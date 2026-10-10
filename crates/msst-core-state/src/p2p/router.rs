//! Packet router — decides relay vs direct for outbound data.
//!
//! Given a destination peer and its current path state, determines:
//! - The target address to send the UDP packet to
//! - Whether to wrap the payload in an MSST data frame
//!
//! This is a pure function — no I/O, no state mutation.

use crate::net::msst_packet;
use crate::net::path::PeerPathMode;
use std::net::SocketAddr;

/// The routing decision for an outbound packet.
#[derive(Debug, Clone)]
pub enum RouteTarget {
    /// Send directly to the peer's P2P endpoint.
    Direct { endpoint: SocketAddr },
    /// Send through a relay server (MSST data frame, relay forwards to peer).
    Relay { relay_addr: SocketAddr },
    /// No route available — packet should be dropped.
    NoRoute,
}

/// Decide where to send an outbound data packet for a peer.
///
/// `peer_path_mode` — the current path mode for this peer.
/// `peer_relay` — the peer's preferred relay address (if known).
/// `own_relay` — our own relay address (fallback).
pub fn route_outbound(
    peer_path_mode: &PeerPathMode,
    peer_relay: Option<SocketAddr>,
    own_relay: Option<SocketAddr>,
) -> RouteTarget {
    match peer_path_mode {
        PeerPathMode::Direct { endpoint } => {
            RouteTarget::Direct { endpoint: *endpoint }
        }
        PeerPathMode::Probing | PeerPathMode::Relay => {
            // Prefer the peer's relay (asymmetric routing), fall back to our own.
            if let Some(relay) = peer_relay {
                RouteTarget::Relay { relay_addr: relay }
            } else if let Some(relay) = own_relay {
                RouteTarget::Relay { relay_addr: relay }
            } else {
                RouteTarget::NoRoute
            }
        }
    }
}

/// Build an MSST data frame for a peer.
///
/// Wraps the raw IP payload in an MSST packet with the correct src/dst IDs.
pub fn build_data_frame(
    local_device_id: &str,
    dst_device_id: &str,
    ip_payload: &[u8],
) -> Vec<u8> {
    msst_packet::build_data(local_device_id, dst_device_id, ip_payload)
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

    fn v4b(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), port))
    }

    #[test]
    fn direct_mode_routes_to_endpoint() {
        let target = route_outbound(
            &PeerPathMode::Direct { endpoint: v4(12345) },
            Some(v4b(21031)),
            Some(v4(21031)),
        );
        match target {
            RouteTarget::Direct { endpoint } => assert_eq!(endpoint, v4(12345)),
            _ => panic!("expected Direct"),
        }
    }

    #[test]
    fn relay_mode_uses_peer_relay() {
        let target = route_outbound(
            &PeerPathMode::Relay,
            Some(v4b(21031)),
            Some(v4(21031)),
        );
        match target {
            RouteTarget::Relay { relay_addr } => assert_eq!(relay_addr, v4b(21031)),
            _ => panic!("expected Relay"),
        }
    }

    #[test]
    fn relay_mode_falls_back_to_own_relay() {
        let target = route_outbound(
            &PeerPathMode::Relay,
            None,
            Some(v4(21031)),
        );
        match target {
            RouteTarget::Relay { relay_addr } => assert_eq!(relay_addr, v4(21031)),
            _ => panic!("expected Relay"),
        }
    }

    #[test]
    fn relay_mode_no_relay_no_route() {
        let target = route_outbound(&PeerPathMode::Relay, None, None);
        assert!(matches!(target, RouteTarget::NoRoute));
    }

    #[test]
    fn probing_mode_uses_relay() {
        let target = route_outbound(
            &PeerPathMode::Probing,
            Some(v4b(21031)),
            Some(v4(21031)),
        );
        match target {
            RouteTarget::Relay { relay_addr } => assert_eq!(relay_addr, v4b(21031)),
            _ => panic!("expected Relay for Probing mode"),
        }
    }

    #[test]
    fn build_data_frame_encodes_correctly() {
        let frame = build_data_frame("device-aabbccdd", "device-11223344", &[1, 2, 3, 4]);
        let pkt = msst_packet::MsstPacket::decode(&frame).unwrap();
        assert_eq!(pkt.packet_type, msst_packet::TYPE_DATA);
        assert_eq!(pkt.src_id, msst_packet::encode_id("device-aabbccdd"));
        assert_eq!(pkt.dst_id, msst_packet::encode_id("device-11223344"));
        assert_eq!(pkt.payload, vec![1, 2, 3, 4]);
    }
}