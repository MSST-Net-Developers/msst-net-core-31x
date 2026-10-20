//! MSST packet codec — the wire format for all MSST-Net traffic.
//!
//! ```text
//! [magic:   4 bytes] "MSST"
//! [version: 1 byte ] currently 1
//! [type:    1 byte ] 0x01=register 0x02=keepalive 0x04=data
//!                    0x05=relay-ping 0x06=p2p-ping 0x07=p2p-pong
//!                    0x08=discovery-register 0x09=discovery-data
//!                    0x0A..0x0C=secure discovery (`sdisc`)
//!                    0x0D=WireGuard message (data-plane encryption)
//! [flags:   1 byte ] 0
//! [src_id:  8 bytes] sender device ID (big-endian u64, lower 32 bits)
//! [dst_id:  8 bytes] destination device ID (zeros for broadcast types)
//! [payload: N bytes]
//! ```
//!
//! Total header length: 23 bytes.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MAGIC: &[u8; 4] = b"MSST";
pub const VERSION: u8 = 1;

pub const TYPE_REGISTER: u8 = 0x01;
pub const TYPE_KEEPALIVE: u8 = 0x02;
pub const TYPE_DATA: u8 = 0x04;
pub const TYPE_RELAY_PING: u8 = 0x05;
pub const TYPE_P2P_PING: u8 = 0x06;
pub const TYPE_P2P_PONG: u8 = 0x07;
pub const TYPE_DISCOVERY_REGISTER: u8 = 0x08;
pub const TYPE_DISCOVERY_DATA: u8 = 0x09;
/// One WireGuard message (see `docs/DATA_PLANE_ENCRYPTION.md`).
pub const TYPE_WG: u8 = 0x0D;

pub const HEADER_LEN: usize = 4 + 1 + 1 + 1 + 8 + 8; // 23
pub const PING_PAYLOAD_LEN: usize = 12; // seq(4) + timestamp_ms(8)

// ---------------------------------------------------------------------------
// MsstPacket
// ---------------------------------------------------------------------------

/// A decoded MSST packet.
#[derive(Debug, Clone, PartialEq)]
pub struct MsstPacket {
    pub version: u8,
    pub packet_type: u8,
    pub flags: u8,
    pub src_id: [u8; 8],
    pub dst_id: [u8; 8],
    pub payload: Vec<u8>,
}

impl MsstPacket {
    /// Encode this packet into bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.payload.len());
        buf.extend_from_slice(MAGIC);
        buf.push(self.version);
        buf.push(self.packet_type);
        buf.push(self.flags);
        buf.extend_from_slice(&self.src_id);
        buf.extend_from_slice(&self.dst_id);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode bytes into a packet.  Returns `None` if too short or magic
    /// doesn't match.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_LEN {
            return None;
        }
        if &data[0..4] != MAGIC {
            return None;
        }
        let mut src_id = [0u8; 8];
        let mut dst_id = [0u8; 8];
        src_id.copy_from_slice(&data[7..15]);
        dst_id.copy_from_slice(&data[15..23]);
        Some(MsstPacket {
            version: data[4],
            packet_type: data[5],
            flags: data[6],
            src_id,
            dst_id,
            payload: data[HEADER_LEN..].to_vec(),
        })
    }

    /// Returns `true` if this is a data packet carrying an IP payload.
    pub fn is_data(&self) -> bool {
        self.packet_type == TYPE_DATA
    }

    /// Returns `true` if this is a P2P ping.
    pub fn is_p2p_ping(&self) -> bool {
        self.packet_type == TYPE_P2P_PING
    }

    /// Returns `true` if this is a P2P pong.
    pub fn is_p2p_pong(&self) -> bool {
        self.packet_type == TYPE_P2P_PONG
    }

    /// Returns the human-readable type name.
    pub fn type_name(&self) -> &'static str {
        match self.packet_type {
            TYPE_REGISTER => "register",
            TYPE_KEEPALIVE => "keepalive",
            TYPE_DATA => "data",
            TYPE_RELAY_PING => "relay-ping",
            TYPE_P2P_PING => "p2p-ping",
            TYPE_P2P_PONG => "p2p-pong",
            TYPE_DISCOVERY_REGISTER => "discovery-register",
            TYPE_DISCOVERY_DATA => "discovery-data",
            TYPE_WG => "wireguard",
            _ => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// ID encoding/decoding
// ---------------------------------------------------------------------------

/// Extract the 8-char hex suffix from a device ID.
pub fn extract_hex(device_id: &str) -> &str {
    device_id
        .strip_prefix("device-")
        .or_else(|| device_id.strip_prefix("dev-"))
        .unwrap_or(device_id)
}

/// Encode a device ID into 8 bytes (big-endian u64).
pub fn encode_id(device_id: &str) -> [u8; 8] {
    let hex = extract_hex(device_id);
    let val = u64::from_str_radix(hex, 16).unwrap_or(0);
    val.to_be_bytes()
}

/// Decode 8 bytes into a device ID string ("device-XXXXXXXX").
pub fn decode_id(bytes: [u8; 8]) -> String {
    let val = u64::from_be_bytes(bytes);
    format!("device-{:08x}", val as u32)
}

/// Returns `true` if the first 4 bytes equal "MSST".
pub fn has_msst_magic(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == MAGIC
}

// ---------------------------------------------------------------------------
// Ping payload (P2P ping/pong)
// ---------------------------------------------------------------------------

/// Encode a ping payload: `[seq: u32 BE][timestamp_ms: u64 BE]`.
pub fn encode_ping_payload(seq: u32, timestamp_ms: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PING_PAYLOAD_LEN);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf
}

/// Decode a ping payload.  Returns `(seq, timestamp_ms)` or `None`.
pub fn decode_ping_payload(data: &[u8]) -> Option<(u32, u64)> {
    if data.len() < PING_PAYLOAD_LEN {
        return None;
    }
    let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let ts = u64::from_be_bytes([
        data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
    ]);
    Some((seq, ts))
}

/// Build a P2P ping packet.
pub fn build_p2p_ping(src_id: &str, dst_id: &str, seq: u32, timestamp_ms: u64) -> Vec<u8> {
    MsstPacket {
        version: VERSION,
        packet_type: TYPE_P2P_PING,
        flags: 0,
        src_id: encode_id(src_id),
        dst_id: encode_id(dst_id),
        payload: encode_ping_payload(seq, timestamp_ms),
    }
    .encode()
}

/// Build a P2P pong packet (echoes the ping payload).
pub fn build_p2p_pong(src_id: &str, dst_id: &str, ping_payload: &[u8]) -> Vec<u8> {
    MsstPacket {
        version: VERSION,
        packet_type: TYPE_P2P_PONG,
        flags: 0,
        src_id: encode_id(src_id),
        dst_id: encode_id(dst_id),
        payload: ping_payload.to_vec(),
    }
    .encode()
}

/// Build a relay keepalive packet.
pub fn build_keepalive(device_id: &str) -> Vec<u8> {
    MsstPacket {
        version: VERSION,
        packet_type: TYPE_KEEPALIVE,
        flags: 0,
        src_id: encode_id(device_id),
        dst_id: [0u8; 8],
        payload: Vec::new(),
    }
    .encode()
}

/// Build a relay registration packet.
pub fn build_register(device_id: &str) -> Vec<u8> {
    MsstPacket {
        version: VERSION,
        packet_type: TYPE_REGISTER,
        flags: 0,
        src_id: encode_id(device_id),
        dst_id: [0u8; 8],
        payload: Vec::new(),
    }
    .encode()
}

/// Build a relay ping packet (for RTT measurement).
pub fn build_relay_ping(device_id: &str) -> Vec<u8> {
    MsstPacket {
        version: VERSION,
        packet_type: TYPE_RELAY_PING,
        flags: 0,
        src_id: encode_id(device_id),
        dst_id: [0u8; 8],
        payload: Vec::new(),
    }
    .encode()
}

/// Build a data packet carrying an IP payload.
pub fn build_data(src_id: &str, dst_id: &str, ip_payload: &[u8]) -> Vec<u8> {
    MsstPacket {
        version: VERSION,
        packet_type: TYPE_DATA,
        flags: 0,
        src_id: encode_id(src_id),
        dst_id: encode_id(dst_id),
        payload: ip_payload.to_vec(),
    }
    .encode()
}

/// Build a `TYPE_WG` frame carrying one WireGuard message.
pub fn build_wg(src_id: &str, dst_id: &str, wg_message: &[u8]) -> Vec<u8> {
    MsstPacket {
        version: VERSION,
        packet_type: TYPE_WG,
        flags: 0,
        src_id: encode_id(src_id),
        dst_id: encode_id(dst_id),
        payload: wg_message.to_vec(),
    }
    .encode()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let pkt = MsstPacket {
            version: VERSION,
            packet_type: TYPE_DATA,
            flags: 0,
            src_id: encode_id("device-aabbccdd"),
            dst_id: encode_id("device-11223344"),
            payload: vec![1, 2, 3, 4],
        };
        let encoded = pkt.encode();
        assert_eq!(encoded.len(), HEADER_LEN + 4);
        let decoded = MsstPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn decode_too_short() {
        assert!(MsstPacket::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn decode_wrong_magic() {
        let mut data = vec![0u8; HEADER_LEN];
        data[0..4].copy_from_slice(b"NOPE");
        assert!(MsstPacket::decode(&data).is_none());
    }

    #[test]
    fn has_msst_magic_works() {
        assert!(has_msst_magic(b"MSSTxxxx"));
        assert!(!has_msst_magic(b"NOPE"));
        assert!(!has_msst_magic(&[1, 2, 3]));
    }

    #[test]
    fn encode_decode_id() {
        let id = "device-aabbccdd";
        let encoded = encode_id(id);
        let decoded = decode_id(encoded);
        assert_eq!(decoded, id);
    }

    #[test]
    fn extract_hex_variants() {
        assert_eq!(extract_hex("device-aabbccdd"), "aabbccdd");
        assert_eq!(extract_hex("dev-aabbccdd"), "aabbccdd");
        assert_eq!(extract_hex("aabbccdd"), "aabbccdd");
    }

    #[test]
    fn ping_payload_round_trip() {
        let payload = encode_ping_payload(42, 1700000000000);
        let (seq, ts) = decode_ping_payload(&payload).unwrap();
        assert_eq!(seq, 42);
        assert_eq!(ts, 1700000000000);
    }

    #[test]
    fn ping_payload_too_short() {
        assert!(decode_ping_payload(&[0u8; 5]).is_none());
    }

    #[test]
    fn build_p2p_ping_packet() {
        let pkt_bytes = build_p2p_ping("device-aabbccdd", "device-11223344", 1, 1000);
        let pkt = MsstPacket::decode(&pkt_bytes).unwrap();
        assert_eq!(pkt.packet_type, TYPE_P2P_PING);
        assert_eq!(pkt.src_id, encode_id("device-aabbccdd"));
        assert_eq!(pkt.dst_id, encode_id("device-11223344"));
        let (seq, ts) = decode_ping_payload(&pkt.payload).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(ts, 1000);
    }

    #[test]
    fn build_keepalive_packet() {
        let pkt_bytes = build_keepalive("device-aabbccdd");
        let pkt = MsstPacket::decode(&pkt_bytes).unwrap();
        assert_eq!(pkt.packet_type, TYPE_KEEPALIVE);
        assert!(pkt.payload.is_empty());
    }

    #[test]
    fn build_data_packet() {
        let ip_data = vec![0x45, 0, 0, 20]; // minimal IPv4 header start
        let pkt_bytes = build_data("device-aabbccdd", "device-11223344", &ip_data);
        let pkt = MsstPacket::decode(&pkt_bytes).unwrap();
        assert_eq!(pkt.packet_type, TYPE_DATA);
        assert_eq!(pkt.payload, ip_data);
    }

    #[test]
    fn type_names() {
        let pkt = MsstPacket {
            version: VERSION,
            packet_type: TYPE_RELAY_PING,
            flags: 0,
            src_id: [0; 8],
            dst_id: [0; 8],
            payload: vec![],
        };
        assert_eq!(pkt.type_name(), "relay-ping");
        assert!(!pkt.is_data());
        assert!(!pkt.is_p2p_ping());
    }
}