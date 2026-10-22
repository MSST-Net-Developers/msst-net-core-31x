//! Virtual address derivation (unchanged since 3.0.x).
//!
//! Every device's private IPv4 / IPv6 ULA address is derived
//! deterministically from the 8-hex-char suffix of its device ID.  Peers and
//! the coordinator compute the same addresses independently, and devices
//! upgraded from 3.0.x keep theirs, so the derivation MUST NOT change.

use tracing::debug;

/// MSST-Net IPv4 range (172.22.0.0/16).
pub const IPV4_NET: &str = "172.22.0.0/16";
/// MSST-Net IPv6 ULA range.
pub const IPV6_NET: &str = "fd22:2222:2222:2222::/64";

/// Returns true when the OS can route IPv6 traffic to the internet.
///
/// UDP `connect()` to a well-known global IPv6 address makes the kernel do a
/// route lookup (no packet is sent); it fails immediately without a default
/// IPv6 route.  More reliable than checking for any IPv6 interface address.
pub fn ipv6_available() -> bool {
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
    let probe = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
        53,
        0,
        0,
    ));
    UdpSocket::bind("[::]:0")
        .and_then(|s| crate::netsock::protect_std(&s).map(|_| s))
        .and_then(|s| s.connect(probe))
        .is_ok()
}

/// Returns true for addresses in the MSST-Net virtual address space
/// (172.22.0.0/16 and fd22:2222:2222:2222::/64).
pub fn is_msst_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 172 && o[1] == 22
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd22 && s[1] == 0x2222 && s[2] == 0x2222 && s[3] == 0x2222
        }
    }
}

/// Whether a peer may announce `addr` as a direct-path candidate: never
/// loopback, unspecified, multicast, broadcast or link-local (the latter
/// need a scope we don't have), and never port 0.  Private LAN addresses
/// are fine (peers on the same LAN).  Anything else would make us send
/// probes wherever a peer (or the coordinator) points, including this
/// host's own services.
pub fn is_valid_candidate(addr: &std::net::SocketAddr) -> bool {
    use std::net::IpAddr;
    let ok = match addr.ip() {
        IpAddr::V4(a) => !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_broadcast() || a.is_link_local()),
        IpAddr::V6(a) => {
            let link_local = (a.segments()[0] & 0xffc0) == 0xfe80;
            let mapped = a.to_ipv4_mapped().is_some();
            !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || link_local || mapped)
        }
    };
    ok && addr.port() != 0
}

/// Whether `ip` is a public unicast address: what a relay we were told
/// about (a room relay) must resolve to.  Not loopback, private, CGNAT
/// (100.64/10), link-local, unique-local, multicast, broadcast,
/// unspecified, documentation, benchmarking or reserved, and not in
/// MSST-Net's own ranges — otherwise a room creator could have every
/// member send traffic into its own LAN or to its own host.
pub fn is_public_unicast(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    if is_msst_ip(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_loopback() || a.is_private() || a.is_link_local() || a.is_multicast() || a.is_broadcast()
                || a.is_unspecified() || a.is_documentation()
                || o[0] == 0                                   // "this network"
                || (o[0] == 100 && (o[1] & 0xc0) == 64)        // CGNAT 100.64/10
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // IETF protocol assignments
                || (o[0] == 198 && (o[1] & 0xfe) == 18)        // benchmarking 198.18/15
                || o[0] >= 240)                                // reserved
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public_unicast(&IpAddr::V4(v4));
            }
            !(a.is_loopback() || a.is_unspecified() || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00                   // unique local
                || (s[0] & 0xffc0) == 0xfe80                   // link local
                || (s[0] == 0x2001 && s[1] == 0x0db8)          // documentation
                || (s[0] & 0xe000) != 0x2000)                  // outside global unicast 2000::/3
        }
    }
}

/// Extract the 8-char hex suffix from a `device-XXXXXXXX` ID.  Without the
/// prefix the input is returned as-is (best-effort).  3.0.x `dev-` IDs are
/// migrated when the identity is loaded.
pub fn extract_hex(device_id: &str) -> &str {
    device_id.strip_prefix("device-").unwrap_or(device_id)
}

/// Derives IPv4 and IPv6 addresses from the device ID hex string (8 hex chars, no prefix).
///
/// # IPv4 derivation (172.22.0.0/16)
/// Split the 8-char hex string into 4 pairs: a1, b2, c3, d4.
/// x = decimal value of b2
/// y = (decimal value of c3 % 254) + 1
/// Result: 172.22.x.y
///
/// # IPv6 derivation (fd22:2222:2222:2222::/64)
/// Suffix is formed directly from the hex string: fd22:2222:2222:2222::a1b2:c3d4
pub fn derive_ips(device_id_hex: &str) -> (String, String) {
    debug_assert_eq!(
        device_id_hex.len(),
        8,
        "Device ID hex part must be exactly 8 characters"
    );

    let a1 = &device_id_hex[0..2];
    let b2 = &device_id_hex[2..4];
    let c3 = &device_id_hex[4..6];
    let d4 = &device_id_hex[6..8];

    let b2_val = u8::from_str_radix(b2, 16).unwrap_or(0);
    let c3_val = u8::from_str_radix(c3, 16).unwrap_or(0);

    let x = b2_val;
    let y = (c3_val % 254) + 1;

    let ipv4 = format!("172.22.{}.{}", x, y);
    let ipv6 = format!("fd22:2222:2222:2222::{}{}:{}{}", a1, b2, c3, d4);

    debug!("ip: derived {} -> ipv4={} ipv6={}", device_id_hex, ipv4, ipv6);

    (ipv4, ipv6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_addresses() {
        for ok in ["203.0.113.7:21031", "192.168.1.5:21031", "10.0.0.2:5", "[2001:db8::1]:21031", "[fd00::1]:9"] {
            assert!(is_valid_candidate(&ok.parse().unwrap()), "{}", ok);
        }
        for bad in ["127.0.0.1:21031", "0.0.0.0:21031", "224.0.0.1:1", "255.255.255.255:1", "169.254.1.1:1",
                    "[::1]:21031", "[::]:1", "[ff02::1]:1", "[fe80::1]:1", "[::ffff:127.0.0.1]:1", "1.2.3.4:0"] {
            assert!(!is_valid_candidate(&bad.parse().unwrap()), "{}", bad);
        }
    }

    #[test]
    fn public_unicast_addresses() {
        for ok in ["203.0.114.7", "115.159.198.144", "2a0e:6901:410:86:26a3:f0ff:fe49:df02", "2402:4e00:c032:6700::1"] {
            assert!(is_public_unicast(&ok.parse().unwrap()), "{}", ok);
        }
        for bad in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.0.1", "224.0.0.1",
                    "255.255.255.255", "0.0.0.0", "0.1.2.3", "192.0.2.1", "198.18.0.1", "240.0.0.1", "172.22.0.5",
                    "::1", "::", "fd22:2222:2222:2222::5", "fd00::1", "fe80::1", "ff02::1", "2001:db8::1",
                    "::ffff:192.168.1.1", "64:ff9b::1"] {
            assert!(!is_public_unicast(&bad.parse().unwrap()), "{}", bad);
        }
    }

    #[test]
    fn test_derive_ips_example() {
        let (ipv4, ipv6) = derive_ips("a1b2c3d4");
        assert_eq!(ipv4, "172.22.178.196");
        assert_eq!(ipv6, "fd22:2222:2222:2222::a1b2:c3d4");
    }

    #[test]
    fn test_y_never_zero_or_255() {
        let (ipv4, _) = derive_ips("00000000");
        assert!(ipv4.ends_with(".1"));
        let (ipv4, _) = derive_ips("0000fe00");
        assert!(ipv4.ends_with(".1"));
        let (ipv4, _) = derive_ips("0000ff00");
        assert!(ipv4.ends_with(".2"));
    }

    #[test]
    fn msst_ip_ranges() {
        assert!(is_msst_ip(&"172.22.1.2".parse().unwrap()));
        assert!(!is_msst_ip(&"172.23.1.2".parse().unwrap()));
        assert!(is_msst_ip(&"fd22:2222:2222:2222::1".parse().unwrap()));
        assert!(!is_msst_ip(&"fd22:2222:2222:2223::1".parse().unwrap()));
    }

    #[test]
    fn extract_hex_prefixes() {
        assert_eq!(extract_hex("device-a1b2c3d4"), "a1b2c3d4");
        assert_eq!(extract_hex("a1b2c3d4"), "a1b2c3d4");
    }
}
