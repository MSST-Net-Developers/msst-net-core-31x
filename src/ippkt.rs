//! Minimal IPv4/IPv6 + UDP packet helpers (parse, build, checksums).
//!
//! Replaces the `etherparse` uses in 3.0.x for the few packets Core
//! synthesizes itself (TUN DNS replies, rewritten discovery broadcasts).

use std::net::IpAddr;

/// One's-complement sum over `data` (RFC 1071), unfolded.
pub fn csum_add(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    sum
}

/// Fold and complement.
pub fn csum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ip_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// UDP checksum over the pseudo-header + segment (0 is sent as 0xffff).
pub fn udp_checksum(src: &IpAddr, dst: &IpAddr, segment: &[u8]) -> u16 {
    let mut sum = csum_add(0, &ip_bytes(src));
    sum = csum_add(sum, &ip_bytes(dst));
    sum += 17 + segment.len() as u32;
    match csum_fold(csum_add(sum, segment)) {
        0 => 0xffff,
        c => c,
    }
}

/// Borrowed view of a UDP datagram.
pub struct UdpParts<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
    /// Offset of the UDP header in the packet.
    #[cfg_attr(not(test), allow(dead_code))]
    pub udp_offset: usize,
}

/// Parse an IPv4/IPv6 UDP packet (no IPv6 extension headers).
pub fn udp_parts(pkt: &[u8]) -> Option<UdpParts<'_>> {
    let (src, dst, off) = match pkt.first()? >> 4 {
        4 => {
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            if pkt.len() < ihl + 8 || pkt[9] != 17 {
                return None;
            }
            let a: [u8; 4] = pkt[12..16].try_into().ok()?;
            let b: [u8; 4] = pkt[16..20].try_into().ok()?;
            (IpAddr::from(a), IpAddr::from(b), ihl)
        }
        6 => {
            if pkt.len() < 48 || pkt[6] != 17 {
                return None;
            }
            let a: [u8; 16] = pkt[8..24].try_into().ok()?;
            let b: [u8; 16] = pkt[24..40].try_into().ok()?;
            (IpAddr::from(a), IpAddr::from(b), 40)
        }
        _ => return None,
    };
    let udp_len = (u16::from_be_bytes([pkt[off + 4], pkt[off + 5]]) as usize).clamp(8, pkt.len() - off);
    Some(UdpParts {
        src,
        dst,
        src_port: u16::from_be_bytes([pkt[off], pkt[off + 1]]),
        dst_port: u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]),
        payload: &pkt[off + 8..off + udp_len],
        udp_offset: off,
    })
}

/// Build an IP/UDP packet.  `src` and `dst` must be the same family.
pub fn build_udp(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let c = udp_checksum(&src, &dst, &udp);
    udp[6..8].copy_from_slice(&c.to_be_bytes());

    let mut out = Vec::with_capacity(40 + udp_len);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut h = [0u8; 20];
            h[0] = 0x45;
            h[2..4].copy_from_slice(&((20 + udp_len) as u16).to_be_bytes());
            h[8] = 64;
            h[9] = 17;
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            let c = csum_fold(csum_add(0, &h));
            h[10..12].copy_from_slice(&c.to_be_bytes());
            out.extend_from_slice(&h);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&(udp_len as u16).to_be_bytes());
            out.extend_from_slice(&[17, 64]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
        }
        _ => return Vec::new(),
    }
    out.extend_from_slice(&udp);
    out
}

/// Whether the IPv4 header checksum (if v4) and the UDP checksum verify.
#[cfg(test)]
pub fn checksums_valid(pkt: &[u8]) -> bool {
    let Some(u) = udp_parts(pkt) else { return false };
    if pkt[0] >> 4 == 4 && csum_fold(csum_add(0, &pkt[..u.udp_offset])) != 0 {
        return false;
    }
    let seg = &pkt[u.udp_offset..u.udp_offset + 8 + u.payload.len()];
    let mut sum = csum_add(0, &ip_bytes(&u.src));
    sum = csum_add(sum, &ip_bytes(&u.dst));
    sum += 17 + seg.len() as u32;
    csum_fold(csum_add(sum, seg)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_v4_v6() {
        for (s, d) in [
            ("172.22.1.1".parse::<IpAddr>().unwrap(), "172.22.0.1".parse::<IpAddr>().unwrap()),
            ("fd22:2222:2222:2222::b".parse().unwrap(), "fd22:2222:2222:2222::1".parse().unwrap()),
        ] {
            let p = build_udp(s, 1234, d, 53, b"hello");
            assert!(checksums_valid(&p));
            let u = udp_parts(&p).unwrap();
            assert_eq!((u.src, u.src_port, u.dst, u.dst_port, u.payload), (s, 1234, d, 53, &b"hello"[..]));
        }
        assert!(udp_parts(&[0x45, 0, 0]).is_none());
    }
}
