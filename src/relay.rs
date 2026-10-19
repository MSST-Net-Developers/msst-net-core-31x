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
    /// Secure-discovery key (base64 X25519); absent for relays without
    /// sdisc v1.
    #[serde(default)]
    pub_key: Option<String>,
}

impl RelayEntry {
    /// The advertised key, if well-formed.  A malformed key is treated as
    /// absent (legacy discovery), never as a failure of the relay.
    fn key(&self) -> Option<[u8; 32]> {
        let raw = STANDARD.decode(self.pub_key.as_deref()?).ok()?;
        match raw.try_into() {
            Ok(k) => Some(k),
            Err(_) => {
                warn!("relay: {} advertises a malformed pub_key — using legacy discovery", self.addr);
                None
            }
        }
    }
}

/// The relay chosen by [`select_best_relay`].
#[derive(Debug, Clone, PartialEq)]
pub struct SelectedRelay {
    /// Numeric `IP:port`.
    pub addr: String,
    /// Secure-discovery key from `GET /relays` (pinned for this selection).
    pub pub_key: Option<[u8; 32]>,
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

/// The key the relay list advertises for a preferred relay reached at
/// `target`: matched by address string, else by resolved address.
async fn key_for_preferred(relays: &[RelayEntry], pref: &str, target: SocketAddr) -> Option<[u8; 32]> {
    if let Some(e) = relays.iter().find(|e| e.addr == pref) {
        return e.key();
    }
    for e in relays {
        if resolve_addr(&e.addr).await == Some(target) {
            return e.key();
        }
    }
    None
}

/// Fetch the relay list from the coordinator and return the **numeric
/// IP:port** of the relay with the lowest average ping RTT, with the
/// secure-discovery key it advertises.
///
/// A `preferred` relay is probed first and used only if it responds; an
/// unresponsive preferred relay falls through to auto-selection (silently
/// pinning to a dead relay would break all relay-routed traffic).  Its key
/// comes from the relay list too; if the list is unavailable, or doesn't
/// include it, it is used without one (legacy discovery).
pub async fn select_best_relay(
    http: &reqwest::Client,
    coord_url: &str,
    device_id: &str,
    preferred: Option<&str>,
) -> Result<SelectedRelay> {
    let src_id = encode_id(device_id);
    let listed = fetch_relays(http, coord_url).await;

    if let Some(pref) = preferred {
        info!("relay: probing preferred relay {}", pref);
        match probe_relay(pref, src_id).await {
            Some((target, rtt)) => {
                info!("relay: preferred relay {} reachable at {} ({:.1} ms)", pref, target, rtt);
                let pub_key = match &listed {
                    Ok(relays) => key_for_preferred(relays, pref, target).await,
                    Err(e) => {
                        warn!("relay: relay list unavailable ({}) — preferred relay used without a discovery key", e);
                        None
                    }
                };
                return Ok(SelectedRelay { addr: target.to_string(), pub_key });
            }
            None => warn!(
                "relay: preferred relay {} did not respond — falling back to auto-selection",
                pref
            ),
        }
    }

    let relays = listed?;
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

    let mut best: Option<(SocketAddr, f64, Option<[u8; 32]>)> = None;
    for h in handles {
        if let Ok((relay, Some((target, rtt)))) = h.await {
            info!("relay: {} ({}) avg RTT {:.1} ms", relay.addr, target, rtt);
            if best.is_none_or(|(_, b, _)| rtt < b) {
                best = Some((target, rtt, relay.key()));
            }
        }
    }
    match best {
        None => anyhow::bail!("could not reach any relay server"),
        Some((addr, rtt, pub_key)) => {
            info!(
                "relay: selected {} ({:.1} ms, secure discovery {})",
                addr,
                rtt,
                if pub_key.is_some() { "available" } else { "unavailable" }
            );
            Ok(SelectedRelay { addr: addr.to_string(), pub_key })
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

/// Resolve a relay address string.  Numeric `IP:port` is the fast path; DNS
/// is the fallback, preferring the address family the host can route.
pub async fn resolve_addr(addr: &str) -> Option<SocketAddr> {
    // Fast path: numeric IPv4 needs no probing at all (this runs per packet).
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return (sa.is_ipv4() || crate::ip::ipv6_available()).then_some(sa);
    }
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(addr).await {
        Ok(it) => it.collect(),
        Err(e) => {
            debug!("relay: DNS lookup failed for {}: {}", addr, e);
            return None;
        }
    };
    let v6_ok = crate::ip::ipv6_available();
    addrs
        .iter()
        .find(|a| a.is_ipv6() == v6_ok)
        .or_else(|| addrs.first())
        .copied()
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
        let listed = json!({ "relays": [{ "addr": relay.to_string(), "pub_key": key }] });
        let coord = FakeCoordinator::start(move |_| (200, listed.clone()), |_| vec![]).await;
        let http = reqwest::Client::new();

        let auto = select_best_relay(&http, &coord.url, "device-11111111", None).await.unwrap();
        assert_eq!(auto, SelectedRelay { addr: relay.to_string(), pub_key: Some([5u8; 32]) });
        // Preferred relay: key looked up in the same list.
        let pref = select_best_relay(&http, &coord.url, "device-11111111", Some(&relay.to_string())).await.unwrap();
        assert_eq!(pref.pub_key, Some([5u8; 32]));
    }

    #[tokio::test]
    async fn preferred_relay_not_listed_has_no_key() {
        use crate::test_support::{echo_relay, FakeCoordinator};
        use serde_json::json;
        let relay = echo_relay().await;
        let coord = FakeCoordinator::start(|_| (200, json!({ "relays": [{ "addr": "127.0.0.1:9", "pub_key": STANDARD.encode([5u8; 32]) }] })), |_| vec![]).await;
        let pref = select_best_relay(&reqwest::Client::new(), &coord.url, "device-11111111", Some(&relay.to_string())).await.unwrap();
        assert_eq!(pref, SelectedRelay { addr: relay.to_string(), pub_key: None });
    }

    #[test]
    fn malformed_key_is_legacy() {
        let e = |k: Option<&str>| RelayEntry { addr: "r".into(), pub_key: k.map(str::to_string) };
        assert_eq!(e(None).key(), None);
        assert_eq!(e(Some("AAAA")).key(), None);
        assert_eq!(e(Some("not base64!")).key(), None);
        assert_eq!(e(Some(&STANDARD.encode([5u8; 32]))).key(), Some([5u8; 32]));
    }
}
