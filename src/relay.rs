//! Relay selection, address resolution and RTT tracking.
//!
//! Ported from 3.0.x `net/relay.rs` and the relay-RTT parts of `net/mod.rs`.
//! Packet builders live in `msst_core_state::net::relay`; this module owns
//! the I/O (HTTP `/relays`, UDP probing, DNS) and the RTT bookkeeping.

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use msst_core_state::net::msst_packet::{encode_id, MsstPacket, TYPE_RELAY_PING, VERSION};
use msst_core_state::net::path::RTT_EWMA_ALPHA;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const PING_COUNT: usize = 5;
const PING_TIMEOUT: Duration = Duration::from_millis(2000);
const INTER_PING_DELAY: Duration = Duration::from_millis(100);
/// IPv4 is chosen if its RTT is within 20% of the IPv6 RTT.
const IPV4_PREFER_RATIO: f64 = 1.2;
/// Relay RTT pings older than this are considered lost.
pub const RELAY_PING_STALE: Duration = Duration::from_secs(6);

#[derive(Debug, Deserialize)]
struct RelayEntry {
    addr: String,
    /// The relay's key (base64 X25519), for authenticated registration;
    /// absent for relays without it.
    #[serde(default)]
    pub_key: Option<String>,
    /// Protocol features, e.g. `["sdisc1", "sreg1"]`; absent = none.
    #[serde(default)]
    features: Vec<String>,
}

impl RelayEntry {
    /// The advertised key, if well-formed.  A malformed key is treated as
    /// absent (legacy registration), never as a failure of the relay.
    fn key(&self) -> Option<[u8; 32]> {
        let raw = STANDARD.decode(self.pub_key.as_deref()?).ok()?;
        match raw.try_into() {
            Ok(k) => Some(k),
            Err(_) => {
                warn!("relay: {} advertises a malformed pub_key — no authenticated registration with it", self.addr);
                None
            }
        }
    }

    /// The selection result for this entry, known as `name` and reached
    /// at `target`.
    fn selected(&self, name: &str, target: SocketAddr) -> SelectedRelay {
        let pub_key = self.key();
        let sreg = pub_key.is_some() && self.features.iter().any(|f| f == crate::sreg::FEATURE);
        SelectedRelay::new(name, target, pub_key, sreg)
    }
}

/// The relay chosen by [`select_best_relay`].
#[derive(Debug, Clone, PartialEq)]
pub struct SelectedRelay {
    /// `host:port` as listed by `GET /relays` or configured: a name stays a
    /// name (resolved through [`resolve_addr`]'s cache).
    pub addr: String,
    /// The relay's key from `GET /relays` (pinned for this selection): used
    /// by authenticated registration.
    pub pub_key: Option<[u8; 32]>,
    /// The relays `GET /relays` listed at this selection (as listed; empty
    /// if the list was unavailable): the only relays peers may announce
    /// (`NetState::official_relays`).
    pub listed: Vec<String>,
    /// Register with `0x0E` (sreg v1): the relay lists `sreg1` in its
    /// `features` and has a valid `pub_key`.
    pub sreg: bool,
}

impl SelectedRelay {
    /// Pins `name` to the probed `target` in the resolver cache, so traffic
    /// uses the address (and family) the selection measured.
    fn new(name: &str, target: SocketAddr, pub_key: Option<[u8; 32]>, sreg: bool) -> Self {
        pin_resolved(name, target);
        SelectedRelay { addr: name.to_string(), pub_key, sreg, listed: Vec::new() }
    }
}

#[derive(Debug, Deserialize)]
struct RelaysResponse {
    relays: Vec<RelayEntry>,
}

/// Extract the relay address from a peer's endpoint list.
///
/// Peers include a `relay:<addr>` entry so senders can route data to the
/// peer's own relay (asymmetric routing).
pub fn extract_relay(endpoints: &[String]) -> Option<String> {
    endpoints
        .iter()
        .find_map(|ep| ep.strip_prefix("relay:"))
        .map(str::to_string)
}

async fn fetch_relays(http: &reqwest::Client, coord_url: &str) -> Result<Vec<RelayEntry>> {
    let url = format!("{}/relays", coord_url.trim_end_matches('/'));
    let resp = http.get(&url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "GET /relays returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    Ok(resp.json::<RelaysResponse>().await?.relays)
}

/// A relay from `GET /relays` that advertises a valid key: the key and
/// every address its name resolves to (IPv4-mapped addresses unmapped).
#[derive(Debug, Clone, PartialEq)]
pub struct KnownRelay {
    pub addrs: Vec<SocketAddr>,
    pub pub_key: [u8; 32],
}

/// The relays `GET /relays` lists with a key (an official relay named as a
/// room relay is identified by address).  Relays whose name doesn't
/// resolve are left out.
pub async fn fetch_known_relays(http: &reqwest::Client, coord_url: &str) -> Result<Vec<KnownRelay>> {
    let mut out = Vec::new();
    for e in fetch_relays(http, coord_url).await? {
        let Some(pub_key) = e.key() else { continue };
        let addrs: Vec<SocketAddr> = match e.addr.parse::<SocketAddr>() {
            Ok(sa) => vec![sa],
            Err(_) => match tokio::net::lookup_host(&e.addr).await {
                Ok(it) => it.collect(),
                Err(err) => {
                    debug!("relay: DNS lookup failed for {}: {}", e.addr, err);
                    continue;
                }
            },
        };
        let addrs = addrs.into_iter().map(msst_core_state::net::relay::unmap_addr).collect();
        out.push(KnownRelay { addrs, pub_key });
    }
    Ok(out)
}

/// The relay list entry for a preferred relay reached at `target`: matched
/// by address string, else by resolved address.
/// The listed relay a preferred relay setting names: by its listed name,
/// else by address (a numeric setting, or a name that resolves to a listed
/// relay's address).
async fn entry_for_preferred<'a>(relays: &'a [RelayEntry], pref: &str) -> Option<&'a RelayEntry> {
    if let Some(e) = relays.iter().find(|e| e.addr == pref) {
        return Some(e);
    }
    let target = resolve_addr(pref).await?;
    for e in relays {
        if resolve_addr(&e.addr).await == Some(target) {
            return Some(e);
        }
    }
    None
}

/// Fetch the relay list from the coordinator and return the relay with the
/// lowest average ping RTT (its address as listed, a name stays a name),
/// with the secure-discovery key it advertises.
///
/// A `preferred` relay must be one of the listed (official) relays — the
/// setting supports nothing else — and is then used under its listed name,
/// so peers recognise it (`NetState::official_relays`).  It is probed first
/// and used only if it responds; an unresponsive or unlisted preferred
/// relay falls through to auto-selection (silently pinning to a dead relay
/// would break all relay-routed traffic).  Without the list nothing can be
/// selected.
pub async fn select_best_relay(
    http: &reqwest::Client,
    coord_url: &str,
    device_id: &str,
    preferred: Option<&str>,
) -> Result<SelectedRelay> {
    let src_id = encode_id(device_id);
    let listed = fetch_relays(http, coord_url).await;
    let names: Vec<String> = listed.as_ref().map(|r| r.iter().map(|e| e.addr.clone()).collect()).unwrap_or_default();
    let mut selected = choose_relay(listed, src_id, preferred).await?;
    selected.listed = names;
    Ok(selected)
}

async fn choose_relay(listed: Result<Vec<RelayEntry>>, src_id: [u8; 8], preferred: Option<&str>) -> Result<SelectedRelay> {
    let relays = listed?;
    if let Some(pref) = preferred {
        match entry_for_preferred(&relays, pref).await {
            None => warn!("relay: preferred relay {} is not an official relay — ignored, selecting automatically", pref),
            Some(e) => {
                info!("relay: probing preferred relay {}", e.addr);
                match probe_relay(&e.addr, src_id).await {
                    Some((target, rtt)) => {
                        info!("relay: preferred relay {} reachable at {} ({:.1} ms)", e.addr, target, rtt);
                        return Ok(e.selected(&e.addr, target));
                    }
                    None => warn!("relay: preferred relay {} did not respond — falling back to auto-selection", e.addr),
                }
            }
        }
    }

    if relays.is_empty() {
        anyhow::bail!("coordinator returned an empty relay list");
    }

    let handles: Vec<_> = relays
        .into_iter()
        .map(|relay| {
            tokio::spawn(async move {
                let result = probe_relay(&relay.addr, src_id).await;
                (relay, result)
            })
        })
        .collect();

    let mut best: Option<(SelectedRelay, f64)> = None;
    for h in handles {
        if let Ok((relay, Some((target, rtt)))) = h.await {
            info!("relay: {} ({}) avg RTT {:.1} ms", relay.addr, target, rtt);
            if best.as_ref().is_none_or(|(_, b)| rtt < *b) {
                best = Some((relay.selected(&relay.addr, target), rtt));
            }
        }
    }
    match best {
        None => anyhow::bail!("could not reach any relay server"),
        Some((selected, rtt)) => {
            info!(
                "relay: selected {} ({:.1} ms, registration {})",
                selected.addr,
                rtt,
                if selected.sreg { "sreg1" } else { "legacy" }
            );
            Ok(selected)
        }
    }
}

/// Probe a relay over IPv4 and IPv6 concurrently; return the best working
/// address and its average RTT.  IPv4 wins when within `IPV4_PREFER_RATIO`.
async fn probe_relay(hostname: &str, src_id: [u8; 8]) -> Option<(SocketAddr, f64)> {
    let addrs: Vec<SocketAddr> = if let Ok(sa) = hostname.parse::<SocketAddr>() {
        vec![sa]
    } else {
        match tokio::net::lookup_host(hostname).await {
            Ok(iter) => iter.collect(),
            Err(e) => {
                debug!("relay: DNS lookup failed for {}: {}", hostname, e);
                return None;
            }
        }
    };

    let mut targets: Vec<SocketAddr> = Vec::new();
    if let Some(v4) = addrs.iter().find(|a| a.is_ipv4()) {
        targets.push(*v4);
    }
    if crate::ip::ipv6_available() {
        if let Some(v6) = addrs.iter().find(|a| a.is_ipv6()) {
            targets.push(*v6);
        }
    }
    if targets.is_empty() {
        warn!("relay: no usable addresses for {}", hostname);
        return None;
    }

    let handles: Vec<_> = targets
        .into_iter()
        .map(|t| tokio::spawn(async move { (t, ping_target(t, src_id).await) }))
        .collect();
    let mut results = Vec::new();
    for h in handles {
        if let Ok((t, Some(rtt))) = h.await {
            results.push((t, rtt));
        }
    }
    pick_family(&results)
}

/// Choose between per-family probe results, preferring IPv4 unless IPv6 is
/// clearly (>20%) faster.
fn pick_family(results: &[(SocketAddr, f64)]) -> Option<(SocketAddr, f64)> {
    let mut best: Option<(SocketAddr, f64)> = None;
    for &(target, rtt) in results {
        let better = match best {
            None => true,
            Some((best_addr, best_rtt)) => {
                let prefer_v4 = target.is_ipv4() && best_addr.is_ipv6() && rtt <= best_rtt * IPV4_PREFER_RATIO;
                let keep_v4 = target.is_ipv6() && best_addr.is_ipv4() && best_rtt <= rtt * IPV4_PREFER_RATIO;
                prefer_v4 || (!keep_v4 && rtt < best_rtt)
            }
        };
        if better {
            best = Some((target, rtt));
        }
    }
    best
}

/// Ping `target` `PING_COUNT` times from a throwaway socket; average RTT in
/// ms, or `None` if every ping timed out.
async fn ping_target(target: SocketAddr, src_id: [u8; 8]) -> Option<f64> {
    let sock = match crate::netsock::udp_socket(crate::netsock::any_for(&target)).await {
        Ok(s) => s,
        Err(e) => {
            warn!("relay: failed to create ping socket: {}", e);
            return None;
        }
    };
    let ping = MsstPacket {
        version: VERSION,
        packet_type: TYPE_RELAY_PING,
        flags: 0,
        src_id,
        dst_id: [0u8; 8],
        payload: vec![],
    }
    .encode();

    let mut rtts = Vec::new();
    let mut buf = [0u8; 256];
    for _ in 0..PING_COUNT {
        let start = Instant::now();
        if sock.send_to(&ping, target).await.is_ok() {
            if let Ok(Ok(_)) = tokio::time::timeout(PING_TIMEOUT, sock.recv_from(&mut buf)).await {
                rtts.push(start.elapsed().as_secs_f64() * 1000.0);
            }
        }
        tokio::time::sleep(INTER_PING_DELAY).await;
    }
    (!rtts.is_empty()).then(|| rtts.iter().sum::<f64>() / rtts.len() as f64)
}

/// How long a resolved relay name is used before it is looked up again.
const DNS_TTL: Duration = Duration::from_secs(60);
/// How long a failed lookup is remembered (this runs per packet).
const DNS_NEGATIVE_TTL: Duration = Duration::from_secs(10);

struct Resolved {
    addr: Option<SocketAddr>,
    at: Instant,
    refreshing: bool,
}

/// Relay names (`host:port`) resolved by [`resolve_addr`].
static RESOLVED: LazyLock<Mutex<HashMap<String, Resolved>>> = LazyLock::new(Default::default);

fn resolved_cache() -> std::sync::MutexGuard<'static, HashMap<String, Resolved>> {
    RESOLVED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record that relay `name` was reached at `addr` (relay selection).
pub fn pin_resolved(name: &str, addr: SocketAddr) {
    if name.parse::<SocketAddr>().is_err() {
        resolved_cache().insert(name.to_string(), Resolved { addr: Some(addr), at: Instant::now(), refreshing: false });
    }
}

/// [`resolve_addr`] without a lookup: numeric, or the last resolved
/// address of a name (`None` if it was never resolved).
pub fn cached_addr(addr: &str) -> Option<SocketAddr> {
    match addr.parse::<SocketAddr>() {
        Ok(sa) => Some(sa),
        Err(_) => resolved_cache().get(addr).and_then(|r| r.addr),
    }
}

/// Resolve a relay address string.  Numeric `IP:port` is the fast path; a
/// name is looked up at most every [`DNS_TTL`] (an expired one is still used
/// while it is looked up again in the background), keeping the address
/// family it had, else preferring the family the host can route.
pub async fn resolve_addr(addr: &str) -> Option<SocketAddr> {
    // Fast path: numeric IPv4 needs no probing at all (this runs per packet).
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return (sa.is_ipv4() || crate::ip::ipv6_available()).then_some(sa);
    }
    let prev = {
        let mut cache = resolved_cache();
        match cache.get_mut(addr) {
            Some(r) if r.at.elapsed() < if r.addr.is_some() { DNS_TTL } else { DNS_NEGATIVE_TTL } => return r.addr,
            Some(r) if r.addr.is_some() => {
                if !r.refreshing {
                    r.refreshing = true;
                    let name = addr.to_string();
                    tokio::spawn(async move { refresh_resolved(&name).await });
                }
                return r.addr;
            }
            _ => None,
        }
    };
    refresh_resolved_from(addr, prev).await
}

async fn refresh_resolved(name: &str) -> Option<SocketAddr> {
    let prev = resolved_cache().get(name).and_then(|r| r.addr);
    refresh_resolved_from(name, prev).await
}

/// Look `name` up and cache the result.  A failed lookup keeps a previous
/// address (a DNS hiccup must not cut the relay path).
async fn refresh_resolved_from(name: &str, prev: Option<SocketAddr>) -> Option<SocketAddr> {
    let found = match tokio::net::lookup_host(name).await {
        Ok(it) => pick_resolved(&it.collect::<Vec<_>>(), prev, crate::ip::ipv6_available()),
        Err(e) => {
            debug!("relay: DNS lookup failed for {}: {}", name, e);
            None
        }
    };
    let addr = found.or(prev);
    resolved_cache().insert(name.to_string(), Resolved { addr, at: Instant::now(), refreshing: false });
    addr
}

/// The address to use from a lookup: the previous one if still listed, else
/// one of its family, else the family the host can route.
fn pick_resolved(addrs: &[SocketAddr], prev: Option<SocketAddr>, v6_ok: bool) -> Option<SocketAddr> {
    if let Some(p) = prev {
        if addrs.contains(&p) {
            return Some(p);
        }
        if let Some(a) = addrs.iter().find(|a| a.is_ipv6() == p.is_ipv6()) {
            return Some(*a);
        }
    }
    addrs.iter().find(|a| a.is_ipv6() == v6_ok).or_else(|| addrs.first()).copied()
}

// ---------------------------------------------------------------------------
// Relay RTT tracking
// ---------------------------------------------------------------------------

/// EWMA RTT per relay address plus the relay pings currently in flight.
///
/// The relay echoes a `TYPE_RELAY_PING` datagram back from its own address,
/// so replies are matched by source `SocketAddr`.
#[derive(Debug, Default)]
pub struct RelayRttTracker {
    /// relay address string (as stored in NetState / PeerEntry) → EWMA ms.
    rtt: HashMap<String, f64>,
    /// resolved relay address → (address string, send time).
    in_flight: HashMap<SocketAddr, (String, Instant)>,
}

impl RelayRttTracker {
    /// Record that a ping to `resolved` is about to be sent.  Returns `false`
    /// (send nothing) if a ping to that relay is still outstanding.
    pub fn begin(&mut self, addr: &str, resolved: SocketAddr, now: Instant) -> bool {
        if self.in_flight.contains_key(&resolved) {
            return false;
        }
        self.in_flight.insert(resolved, (addr.to_string(), now));
        true
    }

    /// Match an echoed relay ping.  Returns the relay address and its new EWMA.
    pub fn on_reply(&mut self, src: SocketAddr, now: Instant) -> Option<(String, f64)> {
        let (addr, sent) = self.in_flight.remove(&src)?;
        let sample = now.saturating_duration_since(sent).as_secs_f64() * 1000.0;
        let ewma = match self.rtt.get(&addr) {
            None => sample,
            Some(prev) => RTT_EWMA_ALPHA * sample + (1.0 - RTT_EWMA_ALPHA) * prev,
        };
        self.rtt.insert(addr.clone(), ewma);
        Some((addr, ewma))
    }

    /// Drop pings that were never answered.
    pub fn purge_stale(&mut self, now: Instant) {
        self.in_flight
            .retain(|_, (_, sent)| now.saturating_duration_since(*sent) < RELAY_PING_STALE);
    }

    pub fn get(&self, addr: &str) -> Option<f64> {
        self.rtt.get(addr).copied()
    }

    /// The relay-path RTT baseline for a peer: the RTT to the relay the peer
    /// is registered with, falling back to our own relay's RTT.
    pub fn for_peer(&self, peer_relay: Option<&str>, own_relay: Option<&str>) -> Option<f64> {
        peer_relay.and_then(|a| self.get(a)).or_else(|| own_relay.and_then(|a| self.get(a)))
    }

    pub fn all(&self) -> &HashMap<String, f64> {
        &self.rtt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn resolved_address_keeps_its_family() {
        let (v4, v4b, v6) = (sa("192.0.2.1:7000"), sa("192.0.2.2:7000"), sa("[2001:db8::1]:7000"));
        // Still listed: kept.
        assert_eq!(pick_resolved(&[v6, v4], Some(v4), true), Some(v4));
        // Moved: same family.
        assert_eq!(pick_resolved(&[v6, v4b], Some(v4), true), Some(v4b));
        // First lookup: the family the host can route.
        assert_eq!(pick_resolved(&[v4, v6], None, true), Some(v6));
        assert_eq!(pick_resolved(&[v6, v4], None, false), Some(v4));
        assert_eq!(pick_resolved(&[], Some(v4), true), None);
    }

    #[tokio::test]
    async fn relay_names_are_kept_and_resolved_through_the_cache() {
        // A selected name is pinned to the probed address: no lookup.
        let name = "relay.invalid:7000";
        assert_eq!(cached_addr(name), None);
        let s = SelectedRelay::new(name, sa("192.0.2.9:7000"), None, false);
        assert_eq!(s.addr, name);
        assert_eq!(cached_addr(name), Some(sa("192.0.2.9:7000")));
        assert_eq!(resolve_addr(name).await, Some(sa("192.0.2.9:7000")));
        // Numeric addresses bypass the cache.
        assert_eq!(cached_addr("192.0.2.1:1"), Some(sa("192.0.2.1:1")));
        // A name is looked up once, then served from the cache.
        let local = resolve_addr("localhost:7001").await.expect("localhost resolves");
        assert!(local.ip().is_loopback());
        assert_eq!(cached_addr("localhost:7001"), Some(local));
    }

    #[test]
    fn extract_relay_from_endpoints() {
        let eps = vec!["1.2.3.4:21031".to_string(), "relay:5.6.7.8:7000".to_string()];
        assert_eq!(extract_relay(&eps).as_deref(), Some("5.6.7.8:7000"));
        assert_eq!(extract_relay(&["1.2.3.4:1".to_string()]), None);
    }

    #[test]
    fn family_choice_prefers_ipv4_within_ratio() {
        let v4 = sa("1.2.3.4:7000");
        let v6 = sa("[2001:db8::1]:7000");
        // IPv6 slightly faster (< 20%) → IPv4 still wins, in either order.
        assert_eq!(pick_family(&[(v6, 10.0), (v4, 11.5)]).unwrap().0, v4);
        assert_eq!(pick_family(&[(v4, 11.5), (v6, 10.0)]).unwrap().0, v4);
        // IPv6 clearly faster → IPv6 wins.
        assert_eq!(pick_family(&[(v4, 30.0), (v6, 10.0)]).unwrap().0, v6);
        assert_eq!(pick_family(&[]), None);
    }

    #[tokio::test]
    async fn resolve_numeric_ipv4_fast_path() {
        assert_eq!(resolve_addr("1.2.3.4:7000").await, Some(sa("1.2.3.4:7000")));
    }

    #[test]
    fn rtt_tracker_ewma_and_dedup() {
        let mut t = RelayRttTracker::default();
        let r = sa("5.6.7.8:7000");
        let t0 = Instant::now();
        assert!(t.begin("5.6.7.8:7000", r, t0));
        assert!(!t.begin("5.6.7.8:7000", r, t0)); // still in flight
        let (addr, ewma) = t.on_reply(r, t0 + Duration::from_millis(40)).unwrap();
        assert_eq!(addr, "5.6.7.8:7000");
        assert!((ewma - 40.0).abs() < 0.5);

        assert!(t.begin("5.6.7.8:7000", r, t0));
        let (_, ewma) = t.on_reply(r, t0 + Duration::from_millis(120)).unwrap();
        let expected = RTT_EWMA_ALPHA * 120.0 + (1.0 - RTT_EWMA_ALPHA) * 40.0;
        assert!((ewma - expected).abs() < 0.5);

        // Unknown source → ignored.
        assert!(t.on_reply(sa("9.9.9.9:1"), t0).is_none());
    }

    #[test]
    fn rtt_tracker_purges_stale_and_falls_back() {
        let mut t = RelayRttTracker::default();
        let r = sa("5.6.7.8:7000");
        let t0 = Instant::now();
        t.begin("own", r, t0);
        t.purge_stale(t0 + RELAY_PING_STALE);
        assert!(t.on_reply(r, t0 + RELAY_PING_STALE).is_none());

        t.begin("own", r, t0);
        t.on_reply(r, t0 + Duration::from_millis(20));
        assert!(t.for_peer(Some("peer-relay"), Some("own")).is_some());
        assert!(t.for_peer(Some("peer-relay"), None).is_none());
    }

    #[tokio::test]
    async fn selection_carries_advertised_key() {
        use crate::test_support::{echo_relay, FakeCoordinator};
        use serde_json::json;
        let relay = echo_relay().await;
        let key = STANDARD.encode([5u8; 32]);
        let listed = json!({ "relays": [{ "addr": relay.to_string(), "pub_key": key, "features": ["sdisc1", "sreg1"] }] });
        let coord = FakeCoordinator::start(move |_| (200, listed.clone()), |_| vec![]).await;
        let http = reqwest::Client::new();

        let auto = select_best_relay(&http, &coord.url, "device-11111111", None).await.unwrap();
        assert_eq!(auto, SelectedRelay { addr: relay.to_string(), pub_key: Some([5u8; 32]), sreg: true, listed: vec![relay.to_string()] });
        // Preferred relay: key and features looked up in the same list.
        let pref = select_best_relay(&http, &coord.url, "device-11111111", Some(&relay.to_string())).await.unwrap();
        assert_eq!((pref.pub_key, pref.sreg), (Some([5u8; 32]), true));
    }

    #[tokio::test]
    async fn only_an_official_relay_can_be_preferred() {
        use crate::test_support::{echo_relay, FakeCoordinator};
        use serde_json::json;
        let (official, unlisted) = (echo_relay().await, echo_relay().await);
        let listed = json!({ "relays": [{ "addr": official.to_string(), "pub_key": STANDARD.encode([5u8; 32]) }] });
        let coord = FakeCoordinator::start(move |_| (200, listed.clone()), |_| vec![]).await;
        let http = reqwest::Client::new();
        // Not listed: ignored, the official relay is selected.
        let s = select_best_relay(&http, &coord.url, "device-11111111", Some(&unlisted.to_string())).await.unwrap();
        assert_eq!(s.addr, official.to_string());
        // No list: nothing to verify a preferred relay against.
        let down = FakeCoordinator::start(|_| (503, json!({})), |_| vec![]).await;
        assert!(select_best_relay(&http, &down.url, "device-11111111", Some(&official.to_string())).await.is_err());
    }

    #[test]
    fn malformed_key_is_legacy() {
        let e = |k: Option<&str>| RelayEntry { addr: "r".into(), pub_key: k.map(str::to_string), features: vec!["sreg1".into()] };
        assert_eq!(e(None).key(), None);
        assert_eq!(e(Some("AAAA")).key(), None);
        assert_eq!(e(Some("not base64!")).key(), None);
        assert_eq!(e(Some(&STANDARD.encode([5u8; 32]))).key(), Some([5u8; 32]));
        // sreg needs both the feature and a valid key.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(!e(Some("AAAA")).selected("r:1", addr).sreg);
        assert!(e(Some(&STANDARD.encode([5u8; 32]))).selected("r:1", addr).sreg);
    }

    #[test]
    fn features_are_optional_in_the_relay_list() {
        let key = STANDARD.encode([5u8; 32]);
        let list: RelaysResponse = serde_json::from_value(serde_json::json!({ "relays": [
            { "addr": "a:1", "pub_key": key },
            { "addr": "b:1", "pub_key": key, "features": ["sdisc1"] },
            { "addr": "c:1", "pub_key": key, "features": ["sdisc1", "sreg1"] },
        ] }))
        .unwrap();
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let sreg: Vec<bool> = list.relays.iter().map(|e| e.selected("r:1", addr).sreg).collect();
        assert_eq!(sreg, [false, false, true]);
    }
}
