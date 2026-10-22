//! Which ICMP messages a peer may send us.
//!
//! ICMP from a peer is not subject to the ACL (only echo requests, to the
//! ping setting), so it is limited to what a point-to-point peer can
//! legitimately send: echo requests and replies, and error messages about
//! a packet we sent to that peer.  Redirects, router/neighbour discovery,
//! timestamps and the like are never valid over the tunnel; an error
//! message quoting some other connection of ours (e.g. "fragmentation
//! needed" or "unreachable" for a flow to an Internet host) would let a
//! peer disturb connections it has no part in.

use std::net::IpAddr;

/// The verdict on an ICMP / ICMPv6 message from a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpFromPeer {
    /// An echo request: subject to the ping setting.
    EchoRequest,
    /// Allowed: an echo reply, or an error about a packet we sent to the
    /// peer.
    Allowed,
    /// Dropped.
    Refused,
}

/// Classify the ICMP message starting at `l4` in `pkt`, sent from `peer` to
/// `us` (the packet's checked addresses).
pub fn classify(pkt: &[u8], l4: usize, peer: IpAddr, us: IpAddr) -> IcmpFromPeer {
    let Some(&kind) = pkt.get(l4) else { return IcmpFromPeer::Refused };
    // The quoted packet of an error message starts after the 8-byte header.
    let quoted = pkt.get(l4 + 8..).unwrap_or_default();
    match (peer, kind) {
        (IpAddr::V4(_), 8) | (IpAddr::V6(_), 128) => IcmpFromPeer::EchoRequest,
        (IpAddr::V4(_), 0) | (IpAddr::V6(_), 129) => IcmpFromPeer::Allowed,
        // Destination unreachable, time exceeded, parameter problem;
        // ICMPv6 also packet too big.
        (IpAddr::V4(_), 3 | 11 | 12) | (IpAddr::V6(_), 1..=4) if quotes_our_packet_to(quoted, us, peer) => IcmpFromPeer::Allowed,
        _ => IcmpFromPeer::Refused,
    }
}

/// Whether `quoted` (the original packet an ICMP error quotes) is a packet
/// from `us` to `peer`.
fn quotes_our_packet_to(quoted: &[u8], us: IpAddr, peer: IpAddr) -> bool {
    let (src, dst): (IpAddr, IpAddr) = match (quoted.first().map(|b| b >> 4), us) {
        (Some(4), IpAddr::V4(_)) if quoted.len() >= 20 => (
            <[u8; 4]>::try_from(&quoted[12..16]).unwrap().into(),
            <[u8; 4]>::try_from(&quoted[16..20]).unwrap().into(),
        ),
        (Some(6), IpAddr::V6(_)) if quoted.len() >= 40 => (
            <[u8; 16]>::try_from(&quoted[8..24]).unwrap().into(),
            <[u8; 16]>::try_from(&quoted[24..40]).unwrap().into(),
        ),
        _ => return false,
    };
    src == us && dst == peer
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER4: [u8; 4] = [172, 22, 1, 1];
    const US4: [u8; 4] = [172, 22, 0, 1];

    fn v4(kind: u8, quoted: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0];
        p.extend_from_slice(&PEER4);
        p.extend_from_slice(&US4);
        p.extend_from_slice(&[kind, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(quoted);
        p
    }

    fn quoted4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut q = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0];
        q.extend_from_slice(&src);
        q.extend_from_slice(&dst);
        q.extend_from_slice(&[0x9c, 0x40, 0, 80, 0, 0, 0, 1]); // TCP ports + seq
        q
    }

    fn check(p: &[u8]) -> IcmpFromPeer {
        classify(p, 20, IpAddr::from(PEER4), IpAddr::from(US4))
    }

    #[test]
    fn echo_is_allowed_or_left_to_the_ping_setting() {
        assert_eq!(check(&v4(8, &[])), IcmpFromPeer::EchoRequest);
        assert_eq!(check(&v4(0, &[])), IcmpFromPeer::Allowed);
    }

    #[test]
    fn errors_only_about_our_packets_to_the_peer() {
        for kind in [3, 11, 12] {
            assert_eq!(check(&v4(kind, &quoted4(US4, PEER4))), IcmpFromPeer::Allowed, "type {}", kind);
            // About our connection to an Internet host: refused.
            assert_eq!(check(&v4(kind, &quoted4(US4, [140, 82, 112, 3]))), IcmpFromPeer::Refused);
            // About someone else's packet, or truncated.
            assert_eq!(check(&v4(kind, &quoted4([172, 22, 9, 9], PEER4))), IcmpFromPeer::Refused);
            assert_eq!(check(&v4(kind, &quoted4(US4, PEER4)[..19])), IcmpFromPeer::Refused);
        }
    }

    #[test]
    fn redirects_and_other_types_are_refused() {
        // Redirect, router advertisement/solicitation, timestamp, address mask.
        for kind in [5, 9, 10, 13, 14, 17, 18] {
            assert_eq!(check(&v4(kind, &quoted4(US4, PEER4))), IcmpFromPeer::Refused, "type {}", kind);
        }
        assert_eq!(classify(&v4(0, &[])[..20], 20, IpAddr::from(PEER4), IpAddr::from(US4)), IcmpFromPeer::Refused);
    }

    #[test]
    fn icmpv6_neighbour_discovery_is_refused_errors_checked() {
        let (peer, us): (IpAddr, IpAddr) = ("fd22:2222:2222:2222::b".parse().unwrap(), "fd22:2222:2222:2222::1".parse().unwrap());
        let msg = |kind: u8, q: &[u8]| {
            let mut p = vec![0u8; 40];
            p.extend_from_slice(&[kind, 0, 0, 0, 0, 0, 0, 0]);
            p.extend_from_slice(q);
            p
        };
        let quoted = |src: IpAddr, dst: IpAddr| {
            let mut q = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
            for a in [src, dst] {
                if let IpAddr::V6(a) = a {
                    q.extend_from_slice(&a.octets());
                }
            }
            q.extend_from_slice(&[0; 8]);
            q
        };
        assert_eq!(classify(&msg(128, &[]), 40, peer, us), IcmpFromPeer::EchoRequest);
        assert_eq!(classify(&msg(129, &[]), 40, peer, us), IcmpFromPeer::Allowed);
        assert_eq!(classify(&msg(2, &quoted(us, peer)), 40, peer, us), IcmpFromPeer::Allowed);
        assert_eq!(classify(&msg(2, &quoted(us, "2001:4860::1".parse().unwrap())), 40, peer, us), IcmpFromPeer::Refused);
        for kind in [133, 134, 135, 136, 137, 130, 143] {
            assert_eq!(classify(&msg(kind, &[]), 40, peer, us), IcmpFromPeer::Refused, "type {}", kind);
        }
    }
}
