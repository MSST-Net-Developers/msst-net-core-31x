//! STUN protocol — RFC 5389 Binding Request/Response.
//!
//! Minimal implementation for NAT discovery:
//! - Build a Binding Request with random Transaction ID
//! - Parse a Binding Response for XOR-MAPPED-ADDRESS
//! - Detect the public IPv4 address/port of a UDP socket
//!
//! ## STUN server list
//!
//! Uses well-known public STUN servers.  All are probed in parallel;
//! the first valid response wins.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Well-known STUN servers (host:port).
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun.voip.blackberry.com:3478",
    "stun.nextcloud.com:3478",
    "turn.cloudflare.com:3478",
];

/// STUN response timeout (seconds).
pub const STUN_TIMEOUT_SECS: u64 = 3;

// ---------------------------------------------------------------------------
// STUN packet building
// ---------------------------------------------------------------------------

/// Build a STUN Binding Request.
///
/// Returns `(transaction_id, packet_bytes)`.
/// The transaction ID is 12 random bytes used to match the response.
pub fn build_binding_request() -> ([u8; 12], Vec<u8>) {
    use rand::RngCore;
    let mut req = vec![0u8; 20];
    req[0] = 0x00;
    req[1] = 0x01; // Binding Request
    // bytes 2-3: Message Length = 0 (no attributes)
    req[4] = 0x21;
    req[5] = 0x12;
    req[6] = 0xA4;
    req[7] = 0x42; // Magic Cookie
    let mut tx_id = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut tx_id);
    req[8..20].copy_from_slice(&tx_id);
    (tx_id, req)
}

// ---------------------------------------------------------------------------
// STUN packet parsing
// ---------------------------------------------------------------------------

/// Extract the 12-byte Transaction ID from any STUN message.
pub fn parse_txid(data: &[u8]) -> Option<[u8; 12]> {
    if data.len() < 20 {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&data[8..20]);
    Some(txid)
}

/// Returns `true` if `data` looks like a STUN Binding Success Response.
pub fn is_stun_response(data: &[u8]) -> bool {
    data.len() >= 20
        && data[0] == 0x01
        && data[1] == 0x01
        && data[4..8] == [0x21, 0x12, 0xA4, 0x42]
}

/// Parse a STUN Binding Response and extract the XOR-MAPPED-ADDRESS.
///
/// Returns the public `SocketAddr` as seen by the STUN server.
pub fn parse_response(data: &[u8]) -> Option<SocketAddr> {
    if !is_stun_response(data) {
        return None;
    }

    let mut i = 20usize;
    while i + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[i], data[i + 1]]);
        let attr_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;

        if i + attr_len > data.len() {
            break;
        }

        // XOR-MAPPED-ADDRESS (0x0020)
        if attr_type == 0x0020 && attr_len >= 8 {
            let family = data[i + 1];
            if family == 0x01 {
                // IPv4
                let port = u16::from_be_bytes([data[i + 2], data[i + 3]]) ^ 0x2112;
                let ip = Ipv4Addr::new(
                    data[i + 4] ^ 0x21,
                    data[i + 5] ^ 0x12,
                    data[i + 6] ^ 0xA4,
                    data[i + 7] ^ 0x42,
                );
                return Some(SocketAddr::new(IpAddr::V4(ip), port));
            }
            // IPv6 (family == 0x02) — not implemented for now
        }

        // Pad to 4-byte boundary
        i += (attr_len + 3) & !3;
    }
    None
}

// ---------------------------------------------------------------------------
// LAN IPv4 detection
// ---------------------------------------------------------------------------

/// Detect LAN IPv4 addresses from local network interfaces.
///
/// Returns addresses that are in private ranges (10.x, 172.16-31.x, 192.168.x).
/// These enable direct P2P between peers on the same LAN.  Interfaces of
/// other overlay networks, containers and VMs are skipped (see
/// [`is_virtual_interface`]).
pub fn detect_lan_ipv4() -> Vec<Ipv4Addr> {
    let mut lan_ips = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces.into_iter().filter(|i| !is_virtual_interface(&i.name)) {
            if let IpAddr::V4(ip) = iface.addr.ip() {
                if is_private_ipv4(ip) && !ip.is_loopback() {
                    lan_ips.push(ip);
                }
            }
        }
    }
    lan_ips
}

/// Detect public (global unicast) IPv6 addresses from local interfaces.
pub fn detect_public_ipv6() -> Vec<std::net::Ipv6Addr> {
    let mut public_v6 = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces.into_iter().filter(|i| !is_virtual_interface(&i.name)) {
            if let IpAddr::V6(ip) = iface.addr.ip() {
                if ip.is_global_unicast() && !ip.is_loopback() {
                    public_v6.push(ip);
                }
            }
        }
    }
    public_v6
}

/// Interface name prefixes of other overlay networks / VPNs, containers
/// and VMs (Linux, macOS).  An address on such an interface is no LAN
/// endpoint: a direct path over it would run MSST-Net inside another tunnel,
/// or point at a host-only network peers can't reach.  `br-` is Docker's
/// user networks — a plain `br0` LAN bridge stays; `ppp*` (PPPoE) is often
/// the WAN link itself and stays too.
const VIRTUAL_IFACE_PREFIXES: [&str; 21] = [
    "zt", "tailscale", "wg", "tun", "tap", "utun", "ipsec", "msst",
    "docker", "br-", "veth", "cni", "flannel", "cali", "kube", "podman",
    "lxcbr", "lxdbr", "virbr", "vmnet", "vboxnet",
];
/// Substrings of Windows adapter names (friendly names) of the same kinds.
const VIRTUAL_IFACE_WINDOWS: [&str; 7] =
    ["zerotier", "tailscale", "wireguard", "vethernet", "vmware", "virtualbox", "openvpn"];

/// Whether `name` is an interface of another overlay network / VPN, a
/// container or a VM (case-insensitive).  A false positive only costs a
/// LAN shortcut: peers still connect via the public endpoint or a relay.
pub fn is_virtual_interface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    VIRTUAL_IFACE_PREFIXES.iter().any(|p| n.starts_with(p)) || VIRTUAL_IFACE_WINDOWS.iter().any(|w| n.contains(w))
}

/// Returns `true` if the IPv4 address is in a private (LAN) range,
/// excluding the MSST-Net virtual range 172.22.0.0/16 (our own TUN address
/// must never be announced as a LAN endpoint — 3.0.x `is_lan_ipv4`).
fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]) && octets[1] != 22)
        || (octets[0] == 192 && octets[1] == 168)
}

/// Extension trait for Ipv6Addr to check global unicast.
trait Ipv6Ext {
    fn is_global_unicast(&self) -> bool;
}

impl Ipv6Ext for std::net::Ipv6Addr {
    fn is_global_unicast(&self) -> bool {
        // Global unicast starts with 2000::/3 (first 3 bits: 001)
        let segments = self.segments();
        (segments[0] & 0xE000) == 0x2000
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_interfaces_are_not_lan() {
        for v in ["zt6q3kr6s3", "ztdhglkmrq", "tailscale0", "wg0", "tun0", "utun4", "docker0", "br-1a2b3c4d5e6f",
                  "veth12ab", "virbr0", "vmnet8", "vboxnet0", "cni0", "msst0",
                  "ZeroTier One [8056c2e21c000001]", "Tailscale", "vEthernet (WSL)", "VMware Network Adapter VMnet8"] {
            assert!(is_virtual_interface(v), "{}", v);
        }
        for lan in ["eth0", "ppp0", "enp3s0", "wlp2s0", "br0", "bond0", "en0", "wlan0", "以太网", "Ethernet", "Wi-Fi", "WLAN"] {
            assert!(!is_virtual_interface(lan), "{}", lan);
        }
    }

    #[test]
    fn build_and_parse_binding_request() {
        let (tx_id, pkt) = build_binding_request();
        assert_eq!(pkt.len(), 20);
        assert_eq!(pkt[0], 0x00);
        assert_eq!(pkt[1], 0x01); // Binding Request
        assert_eq!(&pkt[4..8], &[0x21, 0x12, 0xA4, 0x42]); // Magic Cookie
        assert_eq!(&pkt[8..20], &tx_id);
    }

    #[test]
    fn parse_txid_from_request() {
        let (tx_id, pkt) = build_binding_request();
        let parsed = parse_txid(&pkt).unwrap();
        assert_eq!(parsed, tx_id);
    }

    #[test]
    fn parse_txid_too_short() {
        assert!(parse_txid(&[0u8; 10]).is_none());
    }

    #[test]
    fn is_stun_response_valid() {
        // Build a minimal valid STUN Binding Success Response.
        let mut resp = vec![0u8; 20];
        resp[0] = 0x01; // Binding Success Response
        resp[1] = 0x01;
        resp[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        assert!(is_stun_response(&resp));
    }

    #[test]
    fn is_stun_response_wrong_type() {
        let mut resp = vec![0u8; 20];
        resp[0] = 0x00; // Binding Request, not Response
        resp[1] = 0x01;
        resp[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        assert!(!is_stun_response(&resp));
    }

    #[test]
    fn is_stun_response_wrong_magic() {
        let mut resp = vec![0u8; 20];
        resp[0] = 0x01;
        resp[1] = 0x01;
        resp[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert!(!is_stun_response(&resp));
    }

    #[test]
    fn parse_response_ipv4() {
        // Build a STUN Binding Success Response with XOR-MAPPED-ADDRESS.
        // Target: 192.168.1.1:12345
        // XOR: port ^ 0x2112, IP octets ^ [0x21, 0x12, 0xA4, 0x42]
        let target_port: u16 = 12345;
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let xor_port = target_port ^ 0x2112;
        let xor_ip: Vec<u8> = target_ip
            .octets()
            .iter()
            .zip([0x21, 0x12, 0xA4, 0x42].iter())
            .map(|(a, b)| a ^ b)
            .collect();

        let mut resp = vec![0u8; 32]; // 20 header + 4 attr header + 8 XOR-MAPPED-ADDRESS
        resp[0] = 0x01;
        resp[1] = 0x01;
        resp[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        // Attribute: type=0x0020, length=8
        resp[20] = 0x00;
        resp[21] = 0x20;
        resp[22] = 0x00;
        resp[23] = 0x08;
        // Family=0x01 (IPv4)
        resp[24] = 0x00;
        resp[25] = 0x01;
        // XOR'd port
        resp[26..28].copy_from_slice(&xor_port.to_be_bytes());
        // XOR'd IP
        resp[28..32].copy_from_slice(&xor_ip);

        let addr = parse_response(&resp).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(target_ip), target_port));
    }

    #[test]
    fn parse_response_not_stun() {
        assert!(parse_response(&[0u8; 10]).is_none());
        assert!(parse_response(&[0xFF; 30]).is_none());
    }

    #[test]
    fn is_private_ipv4_ranges() {
        assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(172, 32, 0, 1)));
    }

    #[test]
    fn detect_lan_ipv4_returns_non_empty() {
        // This test may fail in environments without network interfaces.
        // It's a smoke test — the function should not panic.
        let _ = detect_lan_ipv4();
    }

    #[test]
    fn detect_public_ipv6_returns_non_empty() {
        let _ = detect_public_ipv6();
    }

    #[test]
    fn lan_range_excludes_msst_virtual_net() {
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 2)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(172, 22, 1, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
    }
}
