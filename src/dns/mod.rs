//! Local DNS resolver for MSST-Net (ported from 3.0.x `dns/mod.rs`).
//!
//! Desktop: a UDP server on 127.0.0.1:21053 (Windows: :53) plus system
//! split-DNS so `*.msst.net` queries reach it (`system.rs`).  On Linux in
//! iptables mode, port-53 queries are DNAT'ed to 172.22.0.1:21053, routed
//! into the TUN, and answered by [`intercept_tun_dns`].
//!
//! Resolution:
//! - `*.msst.net` → peer list hostname (local, no network), else the
//!   coordinator's `/dns/resolve`; a known peer's tunnel IPs win over the
//!   coordinator's.  An unknown peer gets a 3 s TTL and an on-demand fetch.
//! - everything else → all upstream resolvers in parallel, first answer wins.
//!
//! Cache: 30 s positive, 10 s negative.  Never answers with a timeout: a
//! parseable query always gets NOERROR / NXDOMAIN / SERVFAIL.

pub mod system;

use crate::state::CoreState;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;
const TTL_POSITIVE: u32 = 30;
const CACHE_TTL_POS: Duration = Duration::from_secs(TTL_POSITIVE as u64);
const CACHE_TTL_NEG: Duration = Duration::from_secs(10);
/// Coordinator answer for a peer we don't know yet: re-check soon.
const CACHE_TTL_UNVERIFIED: Duration = Duration::from_secs(3);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

/// Upstreams, all tried in parallel (Aliyun, Cloudflare, Google).
const UPSTREAM_V6: [&str; 6] = [
    "[2400:3200::1]:53",
    "[2400:3200:baba::1]:53",
    "[2606:4700:4700::1111]:53",
    "[2606:4700:4700::1001]:53",
    "[2001:4860:4860::8888]:53",
    "[2001:4860:4860::8844]:53",
];
const UPSTREAM_V4: [&str; 6] = ["223.5.5.5:53", "223.6.6.6:53", "1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53"];

/// Windows NRPT only supports port 53.
#[cfg(windows)]
pub const DNS_LISTEN_ADDR: &str = "127.0.0.1:53";
#[cfg(not(windows))]
pub const DNS_LISTEN_ADDR: &str = "127.0.0.1:21053";

/// Virtual DNS endpoint reached through the TUN (Linux iptables mode).
pub const TUN_DNS_IP: Ipv4Addr = Ipv4Addr::new(172, 22, 0, 1);
pub const TUN_DNS_IP_V6: Ipv6Addr = Ipv6Addr::new(0xfd22, 0x2222, 0x2222, 0x2222, 0, 0, 0, 1);
/// Port of the TUN-intercepted DNS endpoint.  Android: 53 (VpnService sets
/// 172.22.0.1 as the system DNS server).  Linux iptables mode: 21053, the
/// DNAT target (avoids clashing with resolvers bound to :53).
#[cfg(target_os = "android")]
pub const TUN_DNS_PORT: u16 = 53;
#[cfg(not(target_os = "android"))]
pub const TUN_DNS_PORT: u16 = 21053;

/// Whether DNS queries arriving through the TUN must be answered by Core:
/// always on Android, and on Linux in iptables mode.
pub fn tun_interception_enabled(state: &CoreState) -> bool {
    state.dns.get().is_some() && (cfg!(target_os = "android") || system::using_iptables())
}
/// fwmark on upstream sockets so the iptables DNAT rule exempts them ("MST").
#[cfg(target_os = "linux")]
pub const DNS_UPSTREAM_MARK: u32 = 0x4d5354;

struct CacheEntry {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    not_found: bool,
    expires: Instant,
}

enum MsstResult {
    Found(Vec<IpAddr>),
    NotFound,
    Error,
}

#[derive(Deserialize)]
struct CoordDnsResponse {
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    ipv4: String,
    #[serde(default)]
    ipv6: String,
}

pub struct DnsResolver {
    cache: std::sync::Mutex<HashMap<String, CacheEntry>>,
    state: Weak<CoreState>,
}

impl DnsResolver {
    pub fn new(state: &Arc<CoreState>) -> Arc<Self> {
        Arc::new(DnsResolver { cache: std::sync::Mutex::new(HashMap::new()), state: Arc::downgrade(state) })
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, CacheEntry>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Flush the cache (the network changed).
    pub fn clear_cache(&self) {
        self.cache().clear();
    }

    /// Drop a cached hostname (its peer data changed).
    pub fn invalidate(&self, hostname: &str) {
        self.cache().remove(&hostname.to_ascii_lowercase());
    }

    fn is_msst_domain(name: &str) -> bool {
        name.to_ascii_lowercase().ends_with(".msst.net")
    }

    async fn resolve_msst(&self, name: &str, qtype: u16) -> MsstResult {
        let key = name.to_ascii_lowercase();
        if let Some(e) = self.cache().get(&key).filter(|e| e.expires > Instant::now()) {
            return if e.not_found { MsstResult::NotFound } else { MsstResult::Found(filter_by_qtype(e.ipv4, e.ipv6, qtype)) };
        }
        let Some(state) = self.state.upgrade() else { return MsstResult::Error };

        // Local fast path: peers we know by hostname.
        let local = {
            let net = state.net.read().await;
            net.peer_list.find_by_hostname(&key).map(|p| (v4_of(p.ipv4), v6_of(p.ipv6)))
        };
        if let Some((v4, v6)) = local {
            self.cache().insert(key, CacheEntry { ipv4: v4, ipv6: v6, not_found: false, expires: Instant::now() + CACHE_TTL_POS });
            return MsstResult::Found(filter_by_qtype(v4, v6, qtype));
        }

        let Some(client) = state.coordinator.get() else { return MsstResult::Error };
        let (status, body) = match client.api_request(reqwest::Method::GET, &format!("/dns/resolve?name={}", key), None, None).await {
            Ok(r) => r,
            Err(e) => {
                error!("DNS: coordinator query failed for {}: {}", name, e);
                return MsstResult::Error;
            }
        };
        if status == 404 {
            self.cache().insert(key, CacheEntry { ipv4: None, ipv6: None, not_found: true, expires: Instant::now() + CACHE_TTL_NEG });
            return MsstResult::NotFound;
        }
        let data = match (200..300).contains(&status).then(|| serde_json::from_value::<CoordDnsResponse>(body)) {
            Some(Ok(d)) => d,
            _ => {
                error!("DNS: coordinator returned {} for {}", status, name);
                return MsstResult::Error;
            }
        };

        // Custom record (no device): coordinator IPs are authoritative.
        // Device: prefer the peer list's tunnel IPs; otherwise use the
        // coordinator's with a short TTL and fetch the node.
        let (v4, v6, verified) = if data.device_id.is_empty() {
            (data.ipv4.parse().ok(), data.ipv6.parse().ok(), true)
        } else {
            let known = {
                let net = state.net.read().await;
                net.peer_list.get(&data.device_id).map(|e| (v4_of(e.ipv4), v6_of(e.ipv6)))
            };
            match known {
                Some((a, b)) => (a, b, true),
                None => {
                    crate::nodes::demand(&state, crate::nodes::FetchDemand::ByDevice(data.device_id.clone()));
                    (data.ipv4.parse().ok(), data.ipv6.parse().ok(), false)
                }
            }
        };
        let ttl = if verified { CACHE_TTL_POS } else { CACHE_TTL_UNVERIFIED };
        self.cache().insert(key, CacheEntry { ipv4: v4, ipv6: v6, not_found: false, expires: Instant::now() + ttl });
        MsstResult::Found(filter_by_qtype(v4, v6, qtype))
    }

    /// Answer one raw DNS query.  `None` only for unparseable input.
    pub async fn handle_query(&self, buf: &[u8]) -> Option<Vec<u8>> {
        let q = parse_dns_query(buf)?;
        debug!("DNS: {} qtype={}", q.name, q.qtype);
        if Self::is_msst_domain(&q.name) {
            return Some(match self.resolve_msst(&q.name, q.qtype).await {
                MsstResult::Found(addrs) => build_response(&q, &addrs),
                MsstResult::NotFound => build_rcode(&q, 3),
                MsstResult::Error => build_rcode(&q, 2),
            });
        }
        match forward_to_upstream(buf).await {
            Some(resp) => Some(resp),
            None => {
                warn!("DNS: all upstreams failed for {}, returning SERVFAIL", q.name);
                Some(build_rcode(&q, 2))
            }
        }
    }
}

fn v4_of(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(a) => Some(a),
        _ => None,
    }
}

fn v6_of(ip: IpAddr) -> Option<Ipv6Addr> {
    match ip {
        IpAddr::V6(a) => Some(a),
        _ => None,
    }
}

fn filter_by_qtype(ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>, qtype: u16) -> Vec<IpAddr> {
    let v4 = ipv4.map(IpAddr::V4);
    let v6 = ipv6.map(IpAddr::V6);
    match qtype {
        QTYPE_A => v4.into_iter().collect(),
        QTYPE_AAAA => v6.into_iter().collect(),
        _ => v4.into_iter().chain(v6).collect(),
    }
}

// ── DNS packet codec ──────────────────────────────────────────────────────

struct DnsQuery {
    name: String,
    qtype: u16,
    /// Offset just past the question section in `raw`.
    question_end: usize,
    raw: Vec<u8>,
}

fn parse_dns_query(buf: &[u8]) -> Option<DnsQuery> {
    if buf.len() < 12 || buf[2] & 0x80 != 0 || u16::from_be_bytes([buf[4], buf[5]]) == 0 {
        return None;
    }
    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1;
        labels.push(std::str::from_utf8(buf.get(pos..pos + len)?).ok()?.to_ascii_lowercase());
        pos += len;
    }
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    Some(DnsQuery { name: labels.join("."), qtype, question_end: pos + 4, raw: buf.to_vec() })
}

fn response_header(q: &DnsQuery, rcode: u8, ancount: u8) -> Vec<u8> {
    let mut pkt = q.raw[..q.question_end].to_vec();
    pkt[2] |= 0x80; // QR
    pkt[3] = ((pkt[3] | 0x80) & 0xF0) | rcode; // RA + RCODE
    pkt[6..12].copy_from_slice(&[0, ancount, 0, 0, 0, 0]);
    pkt
}

fn build_response(q: &DnsQuery, addrs: &[IpAddr]) -> Vec<u8> {
    let mut pkt = response_header(q, 0, addrs.len() as u8);
    for addr in addrs {
        pkt.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to question name
        let (qtype, data): (u16, Vec<u8>) = match addr {
            IpAddr::V4(v4) => (QTYPE_A, v4.octets().to_vec()),
            IpAddr::V6(v6) => (QTYPE_AAAA, v6.octets().to_vec()),
        };
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&TTL_POSITIVE.to_be_bytes());
        pkt.extend_from_slice(&(data.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&data);
    }
    pkt
}

/// NXDOMAIN (3) / SERVFAIL (2) with no answers.
fn build_rcode(q: &DnsQuery, rcode: u8) -> Vec<u8> {
    response_header(q, rcode, 0)
}

// ── Upstream forwarding ───────────────────────────────────────────────────

async fn forward_to_upstream(query: &[u8]) -> Option<Vec<u8>> {
    let mut servers: Vec<&str> = Vec::new();
    if crate::ip::ipv6_available() {
        servers.extend_from_slice(&UPSTREAM_V6);
    }
    servers.extend_from_slice(&UPSTREAM_V4);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let query = Arc::new(query.to_vec());
    for addr in servers.iter().filter_map(|s| s.parse::<SocketAddr>().ok()) {
        let (q, tx) = (query.clone(), tx.clone());
        tokio::spawn(async move {
            let Ok(sock) = crate::netsock::udp_socket(crate::netsock::any_for(&addr)).await else { return };
            mark_upstream_socket(&sock);
            if sock.send_to(&q, addr).await.is_err() {
                return;
            }
            let mut buf = vec![0u8; 4096];
            if let Ok(Ok(n)) = tokio::time::timeout(UPSTREAM_TIMEOUT, sock.recv(&mut buf)).await {
                let _ = tx.send(buf[..n].to_vec()).await;
            }
        });
    }
    drop(tx);
    rx.recv().await
}

/// Exempt our upstream queries from the iptables DNAT rule (no loop).
#[cfg(target_os = "linux")]
fn mark_upstream_socket(sock: &UdpSocket) {
    use std::os::fd::AsRawFd;
    let mark = DNS_UPSTREAM_MARK;
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn mark_upstream_socket(_sock: &UdpSocket) {}

// ── Desktop UDP server ────────────────────────────────────────────────────

/// Bind the local resolver and configure system split-DNS for `iface`.
/// Returns `true` if Linux `prefer_split` fell back to iptables.
pub async fn start(resolver: Arc<DnsResolver>, iface: &str, mode: crate::net_settings::LinuxDnsMode) -> (bool, Option<tokio::task::JoinHandle<()>>) {
    match UdpSocket::bind(DNS_LISTEN_ADDR).await {
        Ok(sock) => {
            info!("DNS resolver listening on {}", DNS_LISTEN_ADDR);
            let fell_back = system::configure(iface, mode);
            (fell_back, Some(tokio::spawn(serve_loop(resolver, Arc::new(sock)))))
        }
        Err(e) => {
            error!("DNS: failed to bind {} — *.msst.net names will not resolve: {}", DNS_LISTEN_ADDR, e);
            (false, None)
        }
    }
}

async fn serve_loop(resolver: Arc<DnsResolver>, sock: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, src) = match sock.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(e) => {
                error!("DNS: recv error: {}", e);
                continue;
            }
        };
        let (query, resolver, sock) = (buf[..len].to_vec(), resolver.clone(), sock.clone());
        tokio::spawn(async move {
            if let Some(resp) = resolver.handle_query(&query).await {
                let _ = sock.send_to(&resp, src).await;
            }
        });
    }
}

// ── TUN DNS interception (Linux iptables mode) ────────────────────────────

/// Is `pkt` a UDP query to the virtual DNS endpoint (172.22.0.1 or
/// fd22:2222:2222:2222::1, port 21053)?  Header check only.
pub fn is_tun_dns_query(pkt: &[u8]) -> bool {
    crate::ippkt::udp_parts(pkt).is_some_and(|u| {
        u.dst_port == TUN_DNS_PORT && (u.dst == IpAddr::V4(TUN_DNS_IP) || u.dst == IpAddr::V6(TUN_DNS_IP_V6))
    })
}

/// Resolve a TUN-intercepted query and build the IP/UDP reply to inject
/// back into the TUN.
pub async fn intercept_tun_dns(resolver: &DnsResolver, pkt: &[u8]) -> Option<Vec<u8>> {
    if !is_tun_dns_query(pkt) {
        return None;
    }
    let u = crate::ippkt::udp_parts(pkt)?;
    let resp = resolver.handle_query(u.payload).await?;
    Some(crate::ippkt::build_udp(u.dst, TUN_DNS_PORT, u.src, u.src_port, &resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Query for `name` with `qtype`, id 0x1234.
    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            p.push(l.len() as u8);
            p.extend_from_slice(l.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p
    }

    #[test]
    fn codec_round_trip() {
        let q = parse_dns_query(&query("PC.Bob.ezplay.MSST.net", QTYPE_A)).unwrap();
        assert_eq!(q.name, "pc.bob.ezplay.msst.net");
        let r = build_response(&q, &[IpAddr::V4(Ipv4Addr::new(172, 22, 1, 1))]);
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[2] & 0x80, 0x80); // QR
        assert_eq!(r[3] & 0x0F, 0); // NOERROR
        assert_eq!(r[7], 1); // ANCOUNT
        assert_eq!(&r[r.len() - 4..], &[172, 22, 1, 1]);
        assert_eq!(build_rcode(&q, 3)[3] & 0x0F, 3);
        assert!(parse_dns_query(&[0u8; 5]).is_none());
        let mut resp = query("a.b", 1);
        resp[2] |= 0x80;
        assert!(parse_dns_query(&resp).is_none(), "responses are not queries");
    }

    #[test]
    fn qtype_filtering() {
        let (a, b) = (Some(Ipv4Addr::new(1, 2, 3, 4)), Some(Ipv6Addr::LOCALHOST));
        assert_eq!(filter_by_qtype(a, b, QTYPE_A).len(), 1);
        assert_eq!(filter_by_qtype(a, b, QTYPE_AAAA), vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        assert_eq!(filter_by_qtype(a, b, 255).len(), 2);
        assert!(filter_by_qtype(None, b, QTYPE_A).is_empty());
    }

    #[tokio::test]
    async fn resolves_known_peer_locally_and_coordinator_otherwise() {
        use crate::test_support::{core_state, FakeCoordinator};
        let coord = FakeCoordinator::start(
            |req| match req.path.as_str() {
                "/dns/resolve?name=nas.carol.ezplay.msst.net" => (200, serde_json::json!({"device_id": "device-0000000c", "ipv4": "172.22.3.3", "ipv6": ""})),
                "/dns/resolve?name=www.abjust.msst.net" => (200, serde_json::json!({"device_id": "", "ipv4": "10.1.2.3", "ipv6": ""})),
                _ => (404, serde_json::json!({})),
            },
            |_| vec![],
        ).await;
        let (state, _ipc) = core_state("dns").await;
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        std::mem::forget(rx);
        let _ = state.coordinator.set(Arc::new(crate::coordinator::CoordinatorClient::new(
            crate::coordinator::CoordinatorConfig { coord_url: coord.url.clone() }, tx)));
        state.net.write().await.peer_list.upsert("device-0000000b", "172.22.1.1".parse().unwrap(),
            "fd22:2222:2222:2222::b".parse().unwrap(), None, None, None, Some("pc.bob.ezplay.msst.net"), None, None, false, 0);
        let r = DnsResolver::new(&state);

        let ans = r.handle_query(&query("pc.bob.ezplay.msst.net", QTYPE_A)).await.unwrap();
        assert_eq!(&ans[ans.len() - 4..], &[172, 22, 1, 1]);
        assert!(coord.http_log.lock().unwrap().is_empty(), "known peer resolved locally");

        let ans = r.handle_query(&query("nas.carol.ezplay.msst.net", QTYPE_A)).await.unwrap();
        assert_eq!(&ans[ans.len() - 4..], &[172, 22, 3, 3]);
        let ans = r.handle_query(&query("www.abjust.msst.net", QTYPE_A)).await.unwrap();
        assert_eq!(&ans[ans.len() - 4..], &[10, 1, 2, 3]);
        let ans = r.handle_query(&query("ghost.msst.net", QTYPE_A)).await.unwrap();
        assert_eq!(ans[3] & 0x0F, 3, "NXDOMAIN");
        // Negative answer cached: no second coordinator request.
        let before = coord.http_log.lock().unwrap().len();
        r.handle_query(&query("ghost.msst.net", QTYPE_A)).await.unwrap();
        assert_eq!(coord.http_log.lock().unwrap().len(), before);
    }

    #[tokio::test]
    async fn tun_interception_builds_reply_packet() {
        let (state, _ipc) = crate::test_support::core_state("dns-tun").await;
        state.net.write().await.peer_list.upsert("device-0000000b", "172.22.1.1".parse().unwrap(),
            "fd22:2222:2222:2222::b".parse().unwrap(), None, None, None, Some("pc.bob.ezplay.msst.net"), None, None, false, 0);
        let r = DnsResolver::new(&state);
        let q = query("pc.bob.ezplay.msst.net", QTYPE_A);
        let pkt = crate::ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(172, 22, 9, 9)), 40000, IpAddr::V4(TUN_DNS_IP), TUN_DNS_PORT, &q);
        assert!(is_tun_dns_query(&pkt));
        let reply = intercept_tun_dns(&r, &pkt).await.unwrap();
        let u = crate::ippkt::udp_parts(&reply).unwrap();
        assert_eq!((u.src, u.src_port, u.dst, u.dst_port), (IpAddr::V4(TUN_DNS_IP), TUN_DNS_PORT, IpAddr::V4(Ipv4Addr::new(172, 22, 9, 9)), 40000));
        assert_eq!(&u.payload[u.payload.len() - 4..], &[172, 22, 1, 1]);
        assert!(crate::ippkt::checksums_valid(&reply));
        // Other traffic is not intercepted.
        let other = crate::ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(172, 22, 9, 9)), 1, IpAddr::V4(TUN_DNS_IP), 53, &q);
        assert!(!is_tun_dns_query(&other));
    }
}
