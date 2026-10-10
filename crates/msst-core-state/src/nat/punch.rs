//! NAT hole punching — respond to coordinator punch requests.
//!
//! When the Coordinator detects that two peers are behind NATs and need
//! to communicate directly, it sends a `punch_request` to both peers.
//! Each peer then sends UDP packets to the other's known endpoints,
//! which causes the NAT to create a mapping that allows return traffic.
//!
//! ## Flow
//!
//! ```text
//! Coordinator → punch_request { peer_id, endpoints }
//!     │
//!     └─► Peer sends N probe packets to each endpoint
//!         (the packets are small MSST p2p-ping frames)
//! ```
//!
//! The actual P2P path establishment happens after the hole is punched —
//! the path monitor detects the peer's responses and upgrades the path
//! from Relay → Probing → Direct.

use crate::net::msst_packet;
use std::net::SocketAddr;

/// Number of probe packets to send per endpoint during hole punching.
const PUNCH_PROBE_COUNT: usize = 3;

/// Build the UDP packets to send for NAT hole punching.
///
/// Returns a list of `(target_addr, packet_bytes)` pairs.
/// The caller (Core runtime) sends these via the UDP socket.
///
/// The packets are small MSST P2P ping frames — they establish the NAT
/// mapping AND serve as the first path probes.
pub fn build_punch_packets(
    local_device_id: &str,
    peer_device_id: &str,
    peer_endpoints: &[SocketAddr],
    seq_start: u32,
    timestamp_ms: u64,
) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut packets = Vec::new();

    for &endpoint in peer_endpoints {
        for i in 0..PUNCH_PROBE_COUNT {
            let seq = seq_start.wrapping_add(i as u32);
            let pkt = msst_packet::build_p2p_ping(
                local_device_id,
                peer_device_id,
                seq,
                timestamp_ms,
            );
            packets.push((endpoint, pkt));
        }
    }

    packets
}

/// Parse the peer_id and endpoints from a coordinator `punch_request` message.
///
/// Returns `(peer_id, endpoints)` or an error description.
pub fn parse_punch_request(data: &serde_json::Value) -> Result<(String, Vec<SocketAddr>), String> {
    let peer_id = data
        .get("peer_id")
        .and_then(|v| v.as_str())
        .ok_or("missing peer_id")?
        .to_string();

    let endpoints_raw = data
        .get("endpoints")
        .and_then(|v| v.as_array())
        .ok_or("missing endpoints")?;

    let endpoints: Vec<SocketAddr> = endpoints_raw
        .iter()
        .filter_map(|v| v.as_str().and_then(|s| s.parse().ok()))
        .collect();

    if endpoints.is_empty() {
        return Err("no valid endpoints in punch_request".to_string());
    }

    Ok((peer_id, endpoints))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port))
    }

    #[test]
    fn build_punch_packets_count() {
        let endpoints = vec![v4(12345), v4(54321)];
        let pkts = build_punch_packets("device-aabbccdd", "device-11223344", &endpoints, 0, 1000);
        // 3 packets per endpoint × 2 endpoints = 6
        assert_eq!(pkts.len(), 6);
    }

    #[test]
    fn build_punch_packets_target_addresses() {
        let endpoints = vec![v4(12345)];
        let pkts = build_punch_packets("device-aabbccdd", "device-11223344", &endpoints, 0, 1000);
        for (addr, _) in &pkts {
            assert_eq!(*addr, v4(12345));
        }
    }

    #[test]
    fn build_punch_packets_are_p2p_pings() {
        let endpoints = vec![v4(12345)];
        let pkts = build_punch_packets("device-aabbccdd", "device-11223344", &endpoints, 0, 1000);
        for (_, pkt_bytes) in &pkts {
            let pkt = msst_packet::MsstPacket::decode(pkt_bytes).unwrap();
            assert_eq!(pkt.packet_type, msst_packet::TYPE_P2P_PING);
            assert_eq!(pkt.src_id, msst_packet::encode_id("device-aabbccdd"));
            assert_eq!(pkt.dst_id, msst_packet::encode_id("device-11223344"));
            let (seq, ts) = msst_packet::decode_ping_payload(&pkt.payload).unwrap();
            assert!(seq < 3);
            assert_eq!(ts, 1000);
        }
    }

    #[test]
    fn build_punch_packets_seq_increments() {
        let endpoints = vec![v4(12345)];
        let pkts = build_punch_packets("device-aabbccdd", "device-11223344", &endpoints, 100, 1000);
        let seqs: Vec<u32> = pkts
            .iter()
            .map(|(_, bytes)| {
                let pkt = msst_packet::MsstPacket::decode(bytes).unwrap();
                msst_packet::decode_ping_payload(&pkt.payload).unwrap().0
            })
            .collect();
        assert_eq!(seqs, vec![100, 101, 102]);
    }

    #[test]
    fn build_punch_packets_empty_endpoints() {
        let pkts = build_punch_packets("device-aabbccdd", "device-11223344", &[], 0, 1000);
        assert!(pkts.is_empty());
    }

    #[test]
    fn parse_punch_request_valid() {
        let data = serde_json::json!({
            "peer_id": "device-aabbccdd",
            "endpoints": ["1.2.3.4:21031", "5.6.7.8:21031"]
        });
        let (peer_id, endpoints) = parse_punch_request(&data).unwrap();
        assert_eq!(peer_id, "device-aabbccdd");
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].port(), 21031);
    }

    #[test]
    fn parse_punch_request_missing_peer_id() {
        let data = serde_json::json!({ "endpoints": ["1.2.3.4:21031"] });
        assert!(parse_punch_request(&data).is_err());
    }

    #[test]
    fn parse_punch_request_missing_endpoints() {
        let data = serde_json::json!({ "peer_id": "device-aabbccdd" });
        assert!(parse_punch_request(&data).is_err());
    }

    #[test]
    fn parse_punch_request_empty_endpoints() {
        let data = serde_json::json!({
            "peer_id": "device-aabbccdd",
            "endpoints": []
        });
        assert!(parse_punch_request(&data).is_err());
    }

    #[test]
    fn parse_punch_request_invalid_endpoint_format() {
        let data = serde_json::json!({
            "peer_id": "device-aabbccdd",
            "endpoints": ["not-a-valid-address"]
        });
        assert!(parse_punch_request(&data).is_err());
    }
}