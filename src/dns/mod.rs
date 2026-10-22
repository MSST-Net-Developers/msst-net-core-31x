//! Local DNS resolver for MSST-Net (ported from 3.0.x `dns/mod.rs`).
//!
//! Desktop: a UDP server on 127.0.0.1:21053 (Windows: :53) plus system
//! split-DNS so `*.msst.net` queries reach it (`system.rs`).  On Linux in
//! iptables mode, port-53 queries are DNAT'ed to 172.22.0.1:21053, routed
//! into the TUN, and answered by [`intercept_tun_dns`].
//!
//! Resolution:
//! - `*.msst.net` A / AAAA / ANY → peer list hostname (local, no network),
//!   else the coordinator's `/dns/resolve`; a known peer's tunnel IPs win
//!   over the coordinator's.  An unknown peer gets a 3 s TTL and an
//!   on-demand fetch.
//! - `*.msst.net` TXT / SRV → the user records of custom namespaces, from
//!   the coordinator's `POST /dns/lookup` (its PowerDNS backend, the only
//!   API that returns them).  No record of the type but a CNAME → the
//!   CNAME; a name that exists otherwise → NODATA; else NXDOMAIN.
//! - `*.msst.net`, any other type → NODATA for existing names.
//! - everything else → all upstream resolvers in parallel, first answer wins.
//!   In Linux iptables mode, where every local query is intercepted, the
//!   upstreams are the system's own resolvers (`/etc/resolv.conf`, e.g.
//!   Tailscale's MagicDNS or a company DNS), the public ones only when
//!   those give no answer; otherwise the public ones.
//!
//! Cache: 30 s positive, 10 s negative.  Never answers with a timeout: a
//! parseable query always gets NOERROR / NXDOMAIN / SERVFAIL.  EDNS(0) is
//! honoured up to 1232 bytes (fits the 1280 TUN MTU); a larger answer is
//! truncated with TC set.

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
const QTYPE_CNAME: u16 = 5;
const QTYPE_TXT: u16 = 16;
const QTYPE_AAAA: u16 = 28;
const QTYPE_SRV: u16 = 33;
const QTYPE_OPT: u16 = 41;
const QTYPE_ANY: u16 = 255;
const QCLASS_IN: u16 = 1;
/// Largest UDP answer without EDNS (RFC 1035).
const UDP_MAX_PLAIN: usize = 512;
/// Largest UDP answer with EDNS, and the size we advertise: fits a
/// 1280-byte MTU, so TUN-injected replies need no fragmentation.
const UDP_MAX_EDNS: usize = 1232;
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

enum MsstResult<T> {
    /// The name exists; the answers may be empty (NODATA).
    Found(Vec<T>),
    NotFound,
    Error,
}

/// One answer record (owner: the question name).
#[derive(Debug, Clone, PartialEq)]
struct Answer {
    ttl: u32,
    rdata: Rdata,
}

#[derive(Debug, Clone, PartialEq)]
enum Rdata {
    Addr(IpAddr),
    Cname(String),
    /// Character-strings, each at most 255 bytes.
    Txt(Vec<Vec<u8>>),
    Srv { priority: u16, weight: u16, port: u16, target: String },
}

/// A user record from `POST /dns/lookup` (`{qtype, qname, content, ttl}`).
#[derive(Debug, Clone, Deserialize)]
struct UserRecord {
    qtype: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    ttl: i64,
}

struct RecordsEntry {
    /// Every user record at the name (SOA / NS dropped); empty = none.
    records: Vec<UserRecord>,
    expires: Instant,
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
    /// User records (TXT / SRV / CNAME …) by name.
    records: std::sync::Mutex<HashMap<String, RecordsEntry>>,
    state: Weak<CoreState>,
}

impl DnsResolver {
    pub fn new(state: &Arc<CoreState>) -> Arc<Self> {
        Arc::new(DnsResolver {
            cache: std::sync::Mutex::new(HashMap::new()),
            records: std::sync::Mutex::new(HashMap::new()),
            state: Arc::downgrade(state),
        })
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, CacheEntry>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn records_cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, RecordsEntry>> {
        self.records.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Flush the cache (the network changed).
    pub fn clear_cache(&self) {
        self.cache().clear();
        self.records_cache().clear();
    }

    /// Drop a cached hostname (its peer data changed).
    pub fn invalidate(&self, hostname: &str) {
        let key = hostname.to_ascii_lowercase();
        self.records_cache().remove(&key);
        self.cache().remove(&key);
    }

    fn is_msst_domain(name: &str) -> bool {
        name.to_ascii_lowercase().ends_with(".msst.net")
    }

    async fn resolve_msst(&self, name: &str, qtype: u16) -> MsstResult<IpAddr> {
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

    /// All user records at `name` (cached).  `None`: coordinator error.
    async fn user_records(&self, name: &str) -> Option<Vec<UserRecord>> {
        if let Some(e) = self.records_cache().get(name).filter(|e| e.expires > Instant::now()) {
            return Some(e.records.clone());
        }
        let state = self.state.upgrade()?;
        let client = state.coordinator.get()?;
        let body = serde_json::json!({ "method": "lookup", "parameters": { "qtype": "ANY", "qname": name } });
        let (status, resp) = match client.api_request(reqwest::Method::POST, "/dns/lookup", Some(&body), None).await {
            Ok(r) => r,
            Err(e) => {
                error!("DNS: coordinator record lookup failed for {}: {}", name, e);
                return None;
            }
        };
        if !(200..300).contains(&status) {
            error!("DNS: coordinator returned {} for the records of {}", status, name);
            return None;
        }
        // `result` is the record list, or `false` for a method the backend
        // does not know (treated as no records).
        let records: Vec<UserRecord> = serde_json::from_value::<Vec<UserRecord>>(resp["result"].clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|r| !matches!(r.qtype.to_ascii_uppercase().as_str(), "SOA" | "NS"))
            .collect();
        let ttl = if records.is_empty() { CACHE_TTL_NEG } else { CACHE_TTL_POS };
        self.records_cache().insert(name.to_string(), RecordsEntry { records: records.clone(), expires: Instant::now() + ttl });
        Some(records)
    }

    /// TXT / SRV for a `*.msst.net` name.
    async fn resolve_records(&self, name: &str, qtype: u16) -> MsstResult<Answer> {
        let name = name.to_ascii_lowercase();
        let Some(records) = self.user_records(&name).await else { return MsstResult::Error };
        let of_type = |t: u16| records.iter().filter(move |r| record_type(&r.qtype) == Some(t));
        let answers: Vec<Answer> = of_type(qtype).filter_map(record_answer).collect();
        if !answers.is_empty() {
            return MsstResult::Found(answers);
        }
        // An alias: the client's resolver follows it.
        let cnames: Vec<Answer> = of_type(QTYPE_CNAME).filter_map(record_answer).collect();
        if !cnames.is_empty() {
            return MsstResult::Found(cnames);
        }
        if !records.is_empty() {
            return MsstResult::Found(Vec::new());
        }
        // No user records: the name may still be a device hostname.
        match self.resolve_msst(&name, qtype).await {
            MsstResult::Found(_) => MsstResult::Found(Vec::new()),
            MsstResult::NotFound => MsstResult::NotFound,
            MsstResult::Error => MsstResult::Error,
        }
    }

    /// Answer one raw DNS query.  `None` only for unparseable input.
    pub async fn handle_query(&self, buf: &[u8]) -> Option<Vec<u8>> {
        let q = parse_dns_query(buf)?;
        debug!("DNS: {} qtype={}", q.name, q.qtype);
        if Self::is_msst_domain(&q.name) {
            let result = match q.qtype {
                QTYPE_TXT | QTYPE_SRV => self.resolve_records(&q.name, q.qtype).await,
                _ => match self.resolve_msst(&q.name, q.qtype).await {
                    MsstResult::Found(addrs) => {
                        MsstResult::Found(addrs.into_iter().map(|a| Answer { ttl: TTL_POSITIVE, rdata: Rdata::Addr(a) }).collect())
                    }
                    MsstResult::NotFound => MsstResult::NotFound,
                    MsstResult::Error => MsstResult::Error,
                },
            };
            return Some(match result {
                MsstResult::Found(answers) => build_response(&q, &answers),
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
        QTYPE_ANY => v4.into_iter().chain(v6).collect(),
        // Address records never answer another type (NODATA).
        _ => Vec::new(),
    }
}

// ── User records ──────────────────────────────────────────────────────────

/// The record types we serve from user records.
fn record_type(name: &str) -> Option<u16> {
    match name.to_ascii_uppercase().as_str() {
        "CNAME" => Some(QTYPE_CNAME),
        "TXT" => Some(QTYPE_TXT),
        "SRV" => Some(QTYPE_SRV),
        _ => None,
    }
}

/// A user record as an answer; `None` if its content is unusable (it is
/// stored as entered: the coordinator does not validate SRV or TXT).
fn record_answer(r: &UserRecord) -> Option<Answer> {
    let rdata = match record_type(&r.qtype)? {
        QTYPE_CNAME => Rdata::Cname(r.content.trim().to_string()),
        QTYPE_TXT => Rdata::Txt(txt_strings(&r.content)),
        _ => parse_srv(&r.content)?,
    };
    let ttl = u32::try_from(r.ttl.max(0)).unwrap_or(u32::MAX);
    Some(Answer { ttl, rdata })
}

/// SRV content: `priority weight port target` (as the Controller writes
/// it), or `weight port target` (PowerDNS style, priority 0).
fn parse_srv(content: &str) -> Option<Rdata> {
    let f: Vec<&str> = content.split_whitespace().collect();
    let (priority, rest) = match f.len() {
        4 => (f[0].parse().ok()?, &f[1..]),
        3 => (0, &f[..]),
        _ => return None,
    };
    let target = rest[2].to_string();
    encode_name(&target)?;
    Some(Rdata::Srv { priority, weight: rest[0].parse().ok()?, port: rest[1].parse().ok()?, target })
}

/// TXT content as character-strings.  Content that starts with `"` is a
/// zone-file list (`"a" "b"`, with `\"`, `\\` and `\DDD` escapes);
/// anything else is one text.  Each string is split at 255 bytes.
fn txt_strings(content: &str) -> Vec<Vec<u8>> {
    let content = content.trim();
    let texts = if content.starts_with('"') { parse_quoted(content) } else { None }
        .unwrap_or_else(|| vec![content.as_bytes().to_vec()]);
    let mut out: Vec<Vec<u8>> = texts.iter().flat_map(|t| t.chunks(255).map(<[u8]>::to_vec).collect::<Vec<_>>()).collect();
    if out.is_empty() {
        out.push(Vec::new()); // TXT RDATA has at least one string
    }
    out
}

/// `"a" "b c"` → `["a", "b c"]`; `None` if malformed.
fn parse_quoted(s: &str) -> Option<Vec<Vec<u8>>> {
    let b = s.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b[i] != b'"' {
            return None;
        }
        i += 1;
        let mut cur = Vec::new();
        loop {
            match *b.get(i)? {
                b'"' => break,
                b'\\' => {
                    let digits = b.get(i + 1..i + 4).filter(|d| d.iter().all(u8::is_ascii_digit));
                    if let Some(d) = digits {
                        cur.push(std::str::from_utf8(d).ok()?.parse::<u8>().ok()?);
                        i += 4;
                    } else {
                        cur.push(*b.get(i + 1)?);
                        i += 2;
                    }
                }
                c => {
                    cur.push(c);
                    i += 1;
                }
            }
        }
        out.push(cur);
        i += 1; // closing quote
    }
    Some(out)
}

/// A domain name in wire format (no compression); `None` if invalid.
fn encode_name(name: &str) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.');
    let mut out = Vec::new();
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    (out.len() <= 255).then_some(out)
}

// ── DNS packet codec ──────────────────────────────────────────────────────

struct DnsQuery {
    name: String,
    qtype: u16,
    /// Offset just past the question section in `raw`.
    question_end: usize,
    raw: Vec<u8>,
    /// UDP payload size the client advertised in an EDNS(0) OPT record,
    /// clamped to 512..=1232; `None` without EDNS.
    edns: Option<usize>,
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
    let question_end = pos + 4;
    let arcount = u16::from_be_bytes([buf[10], buf[11]]);
    let edns = if arcount > 0 { opt_udp_size(buf, question_end) } else { None };
    Some(DnsQuery { name: labels.join("."), qtype, question_end, raw: buf.to_vec(), edns })
}

/// The UDP size of an OPT record right after the question (stub resolvers
/// send no answer or authority records, so it is the first additional
/// record): root name, TYPE 41, CLASS = UDP payload size.
fn opt_udp_size(buf: &[u8], pos: usize) -> Option<usize> {
    if buf.get(pos) != Some(&0) || buf.get(pos + 1..pos + 3)? != QTYPE_OPT.to_be_bytes() {
        return None;
    }
    let size = u16::from_be_bytes([*buf.get(pos + 3)?, *buf.get(pos + 4)?]) as usize;
    Some(size.clamp(UDP_MAX_PLAIN, UDP_MAX_EDNS))
}

fn response_header(q: &DnsQuery, rcode: u8) -> Vec<u8> {
    let mut pkt = q.raw[..q.question_end].to_vec();
    pkt[2] = (pkt[2] | 0x80) & !0x02; // QR, TC clear
    pkt[3] = 0x80 | (pkt[3] & 0x10) | rcode; // RA, CD echoed, AD clear (not validated), RCODE
    pkt[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    pkt
}

/// Type and RDATA of an answer; `None` if a name in it can't be encoded.
fn rdata_bytes(rdata: &Rdata) -> Option<(u16, Vec<u8>)> {
    Some(match rdata {
        Rdata::Addr(IpAddr::V4(v4)) => (QTYPE_A, v4.octets().to_vec()),
        Rdata::Addr(IpAddr::V6(v6)) => (QTYPE_AAAA, v6.octets().to_vec()),
        Rdata::Cname(target) => (QTYPE_CNAME, encode_name(target)?),
        Rdata::Txt(strings) => {
            let mut d = Vec::new();
            for s in strings {
                d.push(s.len() as u8);
                d.extend_from_slice(s);
            }
            (QTYPE_TXT, d)
        }
        Rdata::Srv { priority, weight, port, target } => {
            let mut d = [priority.to_be_bytes(), weight.to_be_bytes(), port.to_be_bytes()].concat();
            d.extend_from_slice(&encode_name(target)?);
            (QTYPE_SRV, d)
        }
    })
}

/// NOERROR with `answers` (none = NODATA).  Answers that don't fit the
/// client's UDP size are left out and TC is set.
fn build_response(q: &DnsQuery, answers: &[Answer]) -> Vec<u8> {
    let mut pkt = response_header(q, 0);
    let opt_len = if q.edns.is_some() { 11 } else { 0 };
    let max = q.edns.unwrap_or(UDP_MAX_PLAIN);
    let mut ancount: u16 = 0;
    for a in answers {
        let Some((rtype, data)) = rdata_bytes(&a.rdata) else { continue };
        let Ok(rdlen) = u16::try_from(data.len()) else { continue };
        if pkt.len() + 12 + data.len() + opt_len > max {
            pkt[2] |= 0x02; // TC
            break;
        }
        pkt.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to question name
        pkt.extend_from_slice(&rtype.to_be_bytes());
        pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&a.ttl.to_be_bytes());
        pkt.extend_from_slice(&rdlen.to_be_bytes());
        pkt.extend_from_slice(&data);
        ancount += 1;
    }
    pkt[6..8].copy_from_slice(&ancount.to_be_bytes());
    finish(q, pkt)
}

/// NXDOMAIN (3) / SERVFAIL (2) with no answers.
fn build_rcode(q: &DnsQuery, rcode: u8) -> Vec<u8> {
    finish(q, response_header(q, rcode))
}

/// Answer EDNS with EDNS: our OPT record (UDP size, no options).
fn finish(q: &DnsQuery, mut pkt: Vec<u8>) -> Vec<u8> {
    if q.edns.is_some() {
        pkt.push(0); // root
        pkt.extend_from_slice(&QTYPE_OPT.to_be_bytes());
        pkt.extend_from_slice(&(UDP_MAX_EDNS as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ext-rcode, version, flags, rdlen
        pkt[10..12].copy_from_slice(&1u16.to_be_bytes());
    }
    pkt
}

// ── Upstream forwarding ───────────────────────────────────────────────────

async fn forward_to_upstream(query: &[u8]) -> Option<Vec<u8>> {
    let system = if system::using_iptables() { system_resolvers() } else { Vec::new() };
    if !system.is_empty() {
        if let Some(resp) = query_parallel(query, &system).await {
            return Some(resp);
        }
        debug!("DNS: system resolvers {:?} gave no answer, trying public upstreams", system);
    }
    let mut servers: Vec<&str> = Vec::new();
    if crate::ip::ipv6_available() {
        servers.extend_from_slice(&UPSTREAM_V6);
    }
    servers.extend_from_slice(&UPSTREAM_V4);
    let servers: Vec<SocketAddr> = servers.iter().filter_map(|s| s.parse().ok()).collect();
    query_parallel(query, &servers).await
}

/// Send `query` to every server at once; the first answer wins.
async fn query_parallel(query: &[u8], servers: &[SocketAddr]) -> Option<Vec<u8>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let query = Arc::new(query.to_vec());
    for &addr in servers {
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

/// How long the parsed `/etc/resolv.conf` is reused (other VPNs rewrite
/// it when they come up).
const RESOLV_CONF_TTL: Duration = Duration::from_secs(5);

/// The system's resolvers (`/etc/resolv.conf`), cached briefly.
fn system_resolvers() -> Vec<SocketAddr> {
    static CACHE: std::sync::Mutex<Option<(Instant, Vec<SocketAddr>)>> = std::sync::Mutex::new(None);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, servers)) = cache.as_ref().filter(|(at, _)| at.elapsed() < RESOLV_CONF_TTL) {
        return servers.clone();
    }
    let servers = std::fs::read_to_string("/etc/resolv.conf").map(|t| parse_resolv_conf(&t)).unwrap_or_default();
    *cache = Some((Instant::now(), servers.clone()));
    servers
}

/// `nameserver` lines of a resolv.conf, port 53.  Skipped: MSST-Net's own
/// addresses (the query would come straight back), unspecified addresses
/// and scoped IPv6 (`fe80::1%eth0`).
fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next() == Some("nameserver")).then(|| w.next()).flatten()
        })
        .filter_map(|a| a.parse::<IpAddr>().ok())
        .filter(|ip| !crate::ip::is_msst_ip(ip) && !ip.is_unspecified())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
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

    #[test]
    fn resolv_conf_nameservers() {
        let conf = "# Generated by tailscale\nnameserver 100.100.100.100\nsearch tail1234.ts.net\n\
                    nameserver 127.0.0.53\n  nameserver   2001:db8::53  \nnameserver fe80::1%eth0\n\
                    nameserver 172.22.0.1\nnameserver 0.0.0.0\n#nameserver 9.9.9.9\noptions edns0\nnameserver\n";
        let got: Vec<String> = parse_resolv_conf(conf).iter().map(|a| a.to_string()).collect();
        assert_eq!(got, ["100.100.100.100:53", "127.0.0.53:53", "[2001:db8::53]:53"]);
    }

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

    /// `query` with an EDNS(0) OPT record advertising `size`.
    fn query_edns(name: &str, qtype: u16, size: u16) -> Vec<u8> {
        let mut p = query(name, qtype);
        p[11] = 1; // ARCOUNT
        p.push(0);
        p.extend_from_slice(&QTYPE_OPT.to_be_bytes());
        p.extend_from_slice(&size.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        p
    }

    /// Decoded response: rcode, TC, answers (type, ttl, rdata), ARCOUNT.
    struct Decoded {
        rcode: u8,
        tc: bool,
        answers: Vec<(u16, u32, Vec<u8>)>,
        arcount: u16,
    }

    fn decode(r: &[u8]) -> Decoded {
        let ancount = u16::from_be_bytes([r[6], r[7]]);
        let mut pos = 12;
        while r[pos] != 0 {
            pos += r[pos] as usize + 1;
        }
        pos += 5; // root + qtype + qclass
        let mut answers = Vec::new();
        for _ in 0..ancount {
            assert_eq!(&r[pos..pos + 2], &[0xC0, 0x0C], "owner is the question name");
            let rtype = u16::from_be_bytes([r[pos + 2], r[pos + 3]]);
            let ttl = u32::from_be_bytes(r[pos + 6..pos + 10].try_into().unwrap());
            let len = u16::from_be_bytes([r[pos + 10], r[pos + 11]]) as usize;
            answers.push((rtype, ttl, r[pos + 12..pos + 12 + len].to_vec()));
            pos += 12 + len;
        }
        let arcount = u16::from_be_bytes([r[10], r[11]]);
        if arcount == 1 {
            assert_eq!(&r[pos..pos + 3], &[0, 0, 41], "OPT record");
            pos += 11;
        }
        assert_eq!(pos, r.len(), "no trailing bytes");
        Decoded { rcode: r[3] & 0x0F, tc: r[2] & 0x02 != 0, answers, arcount }
    }

    fn srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Vec<u8> {
        let mut d = [priority.to_be_bytes(), weight.to_be_bytes(), port.to_be_bytes()].concat();
        d.extend_from_slice(&encode_name(target).unwrap());
        d
    }

    fn rec(qtype: &str, content: &str, ttl: i64) -> UserRecord {
        UserRecord { qtype: qtype.into(), content: content.into(), ttl }
    }

    #[test]
    fn codec_round_trip() {
        let q = parse_dns_query(&query("PC.Bob.ezplay.MSST.net", QTYPE_A)).unwrap();
        assert_eq!(q.name, "pc.bob.ezplay.msst.net");
        assert_eq!(q.edns, None);
        let r = build_response(&q, &[Answer { ttl: TTL_POSITIVE, rdata: Rdata::Addr(IpAddr::V4(Ipv4Addr::new(172, 22, 1, 1))) }]);
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[2] & 0x80, 0x80); // QR
        assert_eq!(r[3] & 0x0F, 0); // NOERROR
        assert_eq!(r[7], 1); // ANCOUNT
        assert_eq!(&r[r.len() - 4..], &[172, 22, 1, 1]);
        assert_eq!(build_rcode(&q, 3)[3] & 0x0F, 3);
        // AD set in the query (as dig does) is not echoed: nothing is validated.
        let mut ad = query("pc.bob.ezplay.msst.net", QTYPE_A);
        ad[3] |= 0x20 | 0x10;
        let r = build_rcode(&parse_dns_query(&ad).unwrap(), 0);
        assert_eq!(r[3] & 0x20, 0, "AD clear");
        assert_eq!(r[3] & 0x10, 0x10, "CD echoed");
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
        // Other types get no address records (NODATA), e.g. MX or HTTPS.
        assert!(filter_by_qtype(a, b, 15).is_empty());
        assert!(filter_by_qtype(a, b, 65).is_empty());
    }

    #[test]
    fn txt_content() {
        assert_eq!(txt_strings("v=spf1 -all"), vec![b"v=spf1 -all".to_vec()]);
        assert_eq!(txt_strings("  hello  "), vec![b"hello".to_vec()]);
        assert_eq!(txt_strings(r#""a b" "c""#), vec![b"a b".to_vec(), b"c".to_vec()]);
        assert_eq!(txt_strings(r#""say \"hi\" \\ \065""#), vec![br#"say "hi" \ A"#.to_vec()]);
        // Unterminated quotes: taken literally.
        assert_eq!(txt_strings(r#""oops"#), vec![br#""oops"#.to_vec()]);
        assert_eq!(txt_strings(""), vec![Vec::<u8>::new()]);
        let long = "x".repeat(600);
        let parts = txt_strings(&long);
        assert_eq!(parts.iter().map(Vec::len).collect::<Vec<_>>(), vec![255, 255, 90]);
        // UTF-8 text is carried as bytes.
        assert_eq!(txt_strings("你好"), vec!["你好".as_bytes().to_vec()]);
    }

    #[test]
    fn srv_content() {
        let srv = |p, w, port, t: &str| Some(Rdata::Srv { priority: p, weight: w, port, target: t.into() });
        assert_eq!(parse_srv("0 5 25565 pc.bob.ezplay.msst.net"), srv(0, 5, 25565, "pc.bob.ezplay.msst.net"));
        assert_eq!(parse_srv("  10 0 7777  host.example.com. "), srv(10, 0, 7777, "host.example.com."));
        assert_eq!(parse_srv("5 25565 pc.bob.ezplay.msst.net"), srv(0, 5, 25565, "pc.bob.ezplay.msst.net"));
        for bad in ["", "1 2", "a 5 25565 x.y", "0 5 70000 x.y", "0 5 1 2 3", "0 5 1 bad..name"] {
            assert_eq!(parse_srv(bad), None, "{bad}");
        }
    }

    #[test]
    fn name_encoding() {
        assert_eq!(encode_name("a.bc"), Some(vec![1, b'a', 2, b'b', b'c', 0]));
        assert_eq!(encode_name("a.bc."), encode_name("a.bc"));
        assert_eq!(encode_name("."), Some(vec![0]));
        assert_eq!(encode_name("a..b"), None);
        assert_eq!(encode_name(&"x".repeat(64)), None);
        assert_eq!(encode_name(&vec!["y".repeat(63); 4].join(".")), None, "over 255 bytes");
    }

    #[test]
    fn record_answers() {
        assert_eq!(record_answer(&rec("TXT", "hi", 300)), Some(Answer { ttl: 300, rdata: Rdata::Txt(vec![b"hi".to_vec()]) }));
        assert_eq!(record_answer(&rec("srv", "1 2 3 a.b", -5)).map(|a| a.ttl), Some(0), "type case-insensitive, TTL ≥ 0");
        assert_eq!(record_answer(&rec("SRV", "garbage", 60)), None);
        assert_eq!(record_answer(&rec("A", "1.2.3.4", 60)), None, "address records come from /dns/resolve");
    }

    #[test]
    fn srv_and_txt_wire_format() {
        let q = parse_dns_query(&query("_minecraft._tcp.abjust.msst.net", QTYPE_SRV)).unwrap();
        let r = build_response(&q, &[
            Answer { ttl: 300, rdata: Rdata::Srv { priority: 0, weight: 5, port: 25565, target: "pc.bob.ezplay.msst.net".into() } },
            Answer { ttl: 60, rdata: Rdata::Txt(vec![b"ab".to_vec(), b"c".to_vec()]) },
            Answer { ttl: 60, rdata: Rdata::Cname("bad..name".into()) }, // skipped
        ]);
        let d = decode(&r);
        assert_eq!((d.rcode, d.tc, d.arcount), (0, false, 0));
        assert_eq!(d.answers, vec![
            (QTYPE_SRV, 300, srv_rdata(0, 5, 25565, "pc.bob.ezplay.msst.net")),
            (QTYPE_TXT, 60, vec![2, b'a', b'b', 1, b'c']),
        ]);
        // NODATA: NOERROR without answers.
        let d = decode(&build_response(&q, &[]));
        assert_eq!((d.rcode, d.answers.len()), (0, 0));
    }

    #[test]
    fn edns_and_truncation() {
        let big: Vec<Answer> = (0..20).map(|i| Answer { ttl: 60, rdata: Rdata::Txt(vec![vec![b'a' + i as u8; 100]]) }).collect();

        // Without EDNS: at most 512 bytes, TC set, no OPT.
        let q = parse_dns_query(&query("t.abjust.msst.net", QTYPE_TXT)).unwrap();
        let r = build_response(&q, &big);
        let d = decode(&r);
        assert!(r.len() <= 512 && d.tc && d.arcount == 0);
        assert_eq!(d.answers.len(), 4);

        // EDNS 4096 is capped at 1232; our OPT record is echoed.
        let q = parse_dns_query(&query_edns("t.abjust.msst.net", QTYPE_TXT, 4096)).unwrap();
        assert_eq!(q.edns, Some(1232));
        let r = build_response(&q, &big);
        let d = decode(&r);
        assert!(r.len() <= 1232 && d.tc && d.arcount == 1);
        assert_eq!(d.answers.len(), 10);
        assert_eq!(&r[r.len() - 8..r.len() - 6], &1232u16.to_be_bytes(), "advertised size");

        // Fits: no TC.  An advertised size below 512 counts as 512.
        let q = parse_dns_query(&query_edns("t.abjust.msst.net", QTYPE_TXT, 100)).unwrap();
        assert_eq!(q.edns, Some(512));
        let d = decode(&build_response(&q, &big[..2]));
        assert!(!d.tc && d.answers.len() == 2 && d.arcount == 1);

        // Error answers carry OPT too.
        let d = decode(&build_rcode(&q, 3));
        assert_eq!((d.rcode, d.arcount), (3, 1));
    }

    #[tokio::test]
    async fn txt_and_srv_from_user_records() {
        use crate::test_support::{core_state, FakeCoordinator};
        let soa_ns = |name: &str| vec![
            serde_json::json!({"qtype": "SOA", "qname": name, "content": "ns1. hostmaster. 1 3600 900 604800 300", "ttl": 3600}),
            serde_json::json!({"qtype": "NS", "qname": name, "content": "ns1.", "ttl": 3600}),
        ];
        let coord = FakeCoordinator::start(
            move |req| match (req.method.as_str(), req.path.as_str()) {
                ("POST", "/dns/lookup") => {
                    assert_eq!(req.body["method"], "lookup");
                    assert_eq!(req.body["parameters"]["qtype"], "ANY");
                    let name = req.body["parameters"]["qname"].as_str().unwrap().to_string();
                    let mut result = soa_ns(&name);
                    let extra = match name.as_str() {
                        "_minecraft._tcp.abjust.msst.net" => vec![
                            serde_json::json!({"qtype": "SRV", "qname": name, "content": "0 5 25565 pc.bob.ezplay.msst.net", "ttl": 300}),
                            serde_json::json!({"qtype": "SRV", "qname": name, "content": "not an srv", "ttl": 300}),
                        ],
                        "info.abjust.msst.net" => vec![serde_json::json!({"qtype": "TXT", "qname": name, "content": "hello world", "ttl": 120})],
                        "mc.abjust.msst.net" => vec![serde_json::json!({"qtype": "CNAME", "qname": name, "content": "pc.bob.ezplay.msst.net", "ttl": 300})],
                        "broken.abjust.msst.net" => return (500, serde_json::json!({})),
                        _ => vec![],
                    };
                    result.extend(extra);
                    (200, serde_json::json!({ "result": result }))
                }
                _ => (404, serde_json::json!({})),
            },
            |_| vec![],
        ).await;
        let (state, _ipc) = core_state("dns-records").await;
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        std::mem::forget(rx);
        let _ = state.coordinator.set(Arc::new(crate::coordinator::CoordinatorClient::new(
            crate::coordinator::CoordinatorConfig { coord_url: coord.url.clone() }, tx)));
        state.net.write().await.peer_list.upsert("device-0000000b", "172.22.1.1".parse().unwrap(),
            "fd22:2222:2222:2222::b".parse().unwrap(), None, None, None, Some("pc.bob.ezplay.msst.net"), None, None, false, 0);
        let r = DnsResolver::new(&state);
        let lookups = || coord.http_log.lock().unwrap().iter().filter(|q| q.path == "/dns/lookup").count();

        // SRV: the valid record is answered, the malformed one dropped.
        let d = decode(&r.handle_query(&query("_minecraft._tcp.abjust.msst.net", QTYPE_SRV)).await.unwrap());
        assert_eq!(d.rcode, 0);
        assert_eq!(d.answers, vec![(QTYPE_SRV, 300, srv_rdata(0, 5, 25565, "pc.bob.ezplay.msst.net"))]);
        // Cached: no second lookup.
        let n = lookups();
        r.handle_query(&query("_minecraft._tcp.abjust.msst.net", QTYPE_SRV)).await.unwrap();
        assert_eq!(lookups(), n);

        // TXT.
        let d = decode(&r.handle_query(&query_edns("info.abjust.msst.net", QTYPE_TXT, 1232)).await.unwrap());
        assert_eq!(d.answers, vec![(QTYPE_TXT, 120, [&[11u8][..], b"hello world"].concat())]);
        assert_eq!(d.arcount, 1);

        // A name with records, but none of this type: NODATA.
        let d = decode(&r.handle_query(&query("info.abjust.msst.net", QTYPE_SRV)).await.unwrap());
        assert_eq!((d.rcode, d.answers.len()), (0, 0));

        // An alias: the CNAME is returned for the resolver to follow.
        let d = decode(&r.handle_query(&query("mc.abjust.msst.net", QTYPE_TXT)).await.unwrap());
        assert_eq!(d.answers, vec![(QTYPE_CNAME, 300, encode_name("pc.bob.ezplay.msst.net").unwrap())]);

        // A device hostname has no user records (only SOA/NS come back): NODATA.
        let d = decode(&r.handle_query(&query("pc.bob.ezplay.msst.net", QTYPE_TXT)).await.unwrap());
        assert_eq!((d.rcode, d.answers.len()), (0, 0));
        // … and its address records are unchanged; other types get NODATA.
        let d = decode(&r.handle_query(&query("pc.bob.ezplay.msst.net", QTYPE_A)).await.unwrap());
        assert_eq!(d.answers, vec![(QTYPE_A, TTL_POSITIVE, vec![172, 22, 1, 1])]);
        let d = decode(&r.handle_query(&query("pc.bob.ezplay.msst.net", 15)).await.unwrap());
        assert_eq!((d.rcode, d.answers.len()), (0, 0));

        // Unknown name: NXDOMAIN.
        let d = decode(&r.handle_query(&query("_x._tcp.nobody.msst.net", QTYPE_SRV)).await.unwrap());
        assert_eq!(d.rcode, 3);

        // Coordinator failure: SERVFAIL, and nothing cached.
        let d = decode(&r.handle_query(&query("broken.abjust.msst.net", QTYPE_TXT)).await.unwrap());
        assert_eq!(d.rcode, 2);
        let n = lookups();
        r.handle_query(&query("broken.abjust.msst.net", QTYPE_TXT)).await.unwrap();
        assert_eq!(lookups(), n + 1);

        // clear_cache forgets records.
        r.clear_cache();
        r.handle_query(&query("info.abjust.msst.net", QTYPE_TXT)).await.unwrap();
        assert_eq!(lookups(), n + 2);
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
