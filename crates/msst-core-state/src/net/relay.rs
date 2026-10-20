//! Relay protocol helpers.
//!
//! Functions for building relay-bound packets (register, keepalive, data
//! forwarding) and for parsing relay responses.  These are pure functions
//! — they don't own sockets or state.

use super::msst_packet::{self, build_keepalive, build_register, build_relay_ping, MsstPacket};
use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// Relay registration
// ---------------------------------------------------------------------------

/// Build the registration packet to send to the relay.
pub fn build_relay_register(device_id: &str) -> Vec<u8> {
    build_register(device_id)
}

// ---------------------------------------------------------------------------
// Relay keepalive
// ---------------------------------------------------------------------------

/// Build a keepalive packet to send to the relay.
pub fn build_relay_keepalive(device_id: &str) -> Vec<u8> {
    build_keepalive(device_id)
}

// ---------------------------------------------------------------------------
// Relay ping (RTT measurement)
// ---------------------------------------------------------------------------

/// Build a relay ping packet for RTT measurement.
pub fn build_relay_rtt_ping(device_id: &str) -> Vec<u8> {
    build_relay_ping(device_id)
}

// ---------------------------------------------------------------------------
// Packet classification helpers
// ---------------------------------------------------------------------------

/// Classify a received UDP datagram.
///
/// MSST packets are decoded; anything else (STUN responses, garbage) is
/// returned raw.
#[derive(Debug, Clone, PartialEq)]
pub enum ReceivedPacket<'a> {
    /// An MSST protocol packet.
    Msst(MsstPacket),
    /// A non-MSST datagram (a STUN response, or unrecognized).
    Raw(&'a [u8]),
}

/// Classify a received UDP datagram.
pub fn classify_packet(data: &[u8]) -> ReceivedPacket<'_> {
    if msst_packet::has_msst_magic(data) {
        match MsstPacket::decode(data) {
            Some(pkt) => ReceivedPacket::Msst(pkt),
            None => ReceivedPacket::Raw(data), // malformed MSST → treat as raw
        }
    } else {
        ReceivedPacket::Raw(data)
    }
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

/// Unmap an IPv4-mapped IPv6 address to plain IPv4.
///
/// On dual-stack sockets, IPv4 peers arrive as `::ffff:x.x.x.x`.
/// This converts them back to plain IPv4 for consistent comparisons.
pub fn unmap_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => addr,
        SocketAddr::V6(a6) => {
            if let Some(v4) = a6.ip().to_ipv4_mapped() {
                SocketAddr::new(std::net::IpAddr::V4(v4), a6.port())
            } else {
                addr
            }
        }
    }
}

/// Map an address for sending on the dual-stack (AF_INET6, V6ONLY=false)
/// socket.
///
/// Windows requires IPv4 destinations as IPv4-mapped IPv6 (`::ffff:a.b.c.d`)
/// on such a socket — a plain sockaddr_in fails with WSAEFAULT (10014).
/// Linux/macOS map in the kernel, so this is a no-op there.  (3.0.x
/// `net::map_send_addr`.)
#[cfg(windows)]
pub fn map_send_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::V6(std::net::SocketAddrV6::new(
            v4.ip().to_ipv6_mapped(),
            v4.port(),
            0,
            0,
        )),
        v6 => v6,
    }
}

#[cfg(not(windows))]
#[inline(always)]
pub fn map_send_addr(addr: SocketAddr) -> SocketAddr {
    addr
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn classify_msst_packet() {
        let pkt = msst_packet::build_wg("device-aabbccdd", "device-11223344", &[1, 2, 3]);
        match classify_packet(&pkt) {
            ReceivedPacket::Msst(p) => {
                assert_eq!(p.packet_type, msst_packet::TYPE_WG);
                assert_eq!(p.payload, vec![1, 2, 3]);
            }
            _ => panic!("expected Msst"),
        }
    }

    #[test]
    fn classify_raw_ip_packet() {
        let data = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        match classify_packet(&data) {
            ReceivedPacket::Raw(d) => assert_eq!(d, &data),
            _ => panic!("expected Raw"),
        }
    }

    #[test]
    fn classify_non_ip_non_msst() {
        let data = [0xFF, 0xFE, 0xFD];
        match classify_packet(&data) {
            ReceivedPacket::Raw(_) => {} // expected
            _ => panic!("expected Raw"),
        }
    }

    #[test]
    fn unmap_ipv4_mapped_v6() {
        let v6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0xC0A8, 0x0101),
            8080,
            0,
            0,
        ));
        let v4 = unmap_addr(v6);
        assert_eq!(v4, SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            8080,
        ));
    }

    #[test]
    fn unmap_plain_v4_unchanged() {
        let v4 = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234);
        assert_eq!(unmap_addr(v4), v4);
    }

    #[test]
    fn unmap_global_v6_unchanged() {
        let v6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));
        assert_eq!(unmap_addr(v6), v6);
    }

}