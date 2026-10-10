//! Virtual address derivation — ported verbatim from 3.0.x `ip.rs`.
//!
//! Every device's private IPv4 / IPv6 ULA address is derived
//! deterministically from the 8-hex-char suffix of its device ID, so the
//! derivation MUST stay bit-for-bit identical to 3.0.x: peers running 3.0.x
//! compute the same addresses for us independently.

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
    UdpSocket::bind("[::]:0").and_then(|s| s.connect(probe)).is_ok()
}

/// Returns true for addresses in the MSST virtual address space
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

/// Extract the 8-char hex suffix from a device ID, handling both the current
/// `device-XXXXXXXX` format and the legacy `dev-XXXXXXXX` format.
/// If neither prefix matches, the input is returned as-is (best-effort).
pub fn extract_hex(device_id: &str) -> &str {
    device_id
        .strip_prefix("device-")
        .or_else(|| device_id.strip_prefix("dev-"))
        .unwrap_or(device_id)
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
        assert_eq!(extract_hex("dev-a1b2c3d4"), "a1b2c3d4");
        assert_eq!(extract_hex("a1b2c3d4"), "a1b2c3d4");
    }
}
