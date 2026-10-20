//! In-tunnel relay-path probe — pure codec, no I/O.
//!
//! Measures the round trip peer data really takes when the path is not
//! direct: A → (B's relay) → B → (A's relay) → A.  Plain `0x06` / `0x07`
//! can't: a relay forwards `0x06` only from the address bound to the sender
//! (sreg) and only to devices registered with it, so with two relays one
//! hop always drops it.  `0x0D` frames are forwarded from any source, so the
//! probe travels inside the WireGuard session (`TYPE_WG`) like data.
//!
//! The inner packet is IPv4, protocol [`PROTO`] (253, RFC 3692
//! experimentation), from the sender's virtual IPv4 to the receiver's:
//!
//! ```text
//! payload = "MSRP" ‖ kind (1 ping, 2 pong) ‖ 0 ‖ seq (u32 BE) ‖ sent_ms (u64 BE)   — 18 bytes
//! ```
//!
//! The receiving Core answers a ping itself, through its relay route back
//! to the sender, and never delivers probes to the TUN.  A pong is matched
//! by `seq`; `sent_ms` is the sender's own clock, echoed.

use std::net::Ipv4Addr;

/// IP protocol number of probe packets.
pub const PROTO: u8 = 253;
const MAGIC: &[u8; 4] = b"MSRP";
const IP_HEADER_LEN: usize = 20;
const PAYLOAD_LEN: usize = 18;
const KIND_PING: u8 = 1;
const KIND_PONG: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ping,
    Pong,
}

/// A decoded probe packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub kind: Kind,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub seq: u32,
    pub sent_ms: u64,
}

impl Probe {
    /// The pong answering this ping.
    pub fn pong(&self) -> Probe {
        Probe { kind: Kind::Pong, src: self.dst, dst: self.src, ..*self }
    }

    /// Encode as an IPv4 packet (header checksum included).
    pub fn encode(&self) -> Vec<u8> {
        let total = (IP_HEADER_LEN + PAYLOAD_LEN) as u16;
        let mut p = Vec::with_capacity(total as usize);
        p.extend_from_slice(&[0x45, 0]);
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0x40, 0, 64, PROTO, 0, 0]);
        p.extend_from_slice(&self.src.octets());
        p.extend_from_slice(&self.dst.octets());
        let csum = crate::ippkt::csum_fold(crate::ippkt::csum_add(0, &p));
        p[10..12].copy_from_slice(&csum.to_be_bytes());
        p.extend_from_slice(MAGIC);
        p.push(match self.kind {
            Kind::Ping => KIND_PING,
            Kind::Pong => KIND_PONG,
        });
        p.push(0);
        p.extend_from_slice(&self.seq.to_be_bytes());
        p.extend_from_slice(&self.sent_ms.to_be_bytes());
        p
    }

    /// Decode a probe; `None` for anything else (including other protocol
    /// 253 traffic), which is then handled as ordinary data.
    pub fn decode(pkt: &[u8]) -> Option<Probe> {
        if pkt.len() < IP_HEADER_LEN + PAYLOAD_LEN || pkt[0] != 0x45 || pkt[9] != PROTO {
            return None;
        }
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if total != IP_HEADER_LEN + PAYLOAD_LEN || pkt.len() < total {
            return None;
        }
        let body = &pkt[IP_HEADER_LEN..total];
        if &body[..4] != MAGIC || body[5] != 0 {
            return None;
        }
        let kind = match body[4] {
            KIND_PING => Kind::Ping,
            KIND_PONG => Kind::Pong,
            _ => return None,
        };
        Some(Probe {
            kind,
            src: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
            dst: Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
            seq: u32::from_be_bytes(body[6..10].try_into().unwrap()),
            sent_ms: u64::from_be_bytes(body[10..18].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ping() -> Probe {
        Probe { kind: Kind::Ping, src: Ipv4Addr::new(172, 22, 1, 1), dst: Ipv4Addr::new(172, 22, 2, 2), seq: 7, sent_ms: 1_760_000_000_123 }
    }

    #[test]
    fn round_trip_and_pong() {
        let pkt = ping().encode();
        assert_eq!(pkt.len(), 38);
        assert_eq!(Probe::decode(&pkt), Some(ping()));
        // A valid IPv4 header: it passes boringtun's length check and the
        // runtime's parser, and its checksum verifies.
        assert_eq!(crate::ippkt::csum_fold(crate::ippkt::csum_add(0, &pkt[..20])), 0);
        let parsed = crate::runtime::parse_ip_packet(&pkt).unwrap();
        assert_eq!(parsed.src_ip, std::net::IpAddr::V4(Ipv4Addr::new(172, 22, 1, 1)));

        let pong = ping().pong();
        assert_eq!((pong.kind, pong.src, pong.dst, pong.seq, pong.sent_ms), (Kind::Pong, ping().dst, ping().src, 7, ping().sent_ms));
        assert_eq!(Probe::decode(&pong.encode()), Some(pong));
    }

    #[test]
    fn other_packets_are_not_probes() {
        let good = ping().encode();
        let mut wrong_magic = good.clone();
        wrong_magic[20] = b'X';
        let mut wrong_kind = good.clone();
        wrong_kind[24] = 9;
        let mut udp = good.clone();
        udp[9] = 17;
        for p in [&wrong_magic, &wrong_kind, &udp, &good[..30].to_vec()] {
            assert_eq!(Probe::decode(p), None);
        }
    }
}
