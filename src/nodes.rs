//! Peer node knowledge: applying coordinator peer data, and on-demand
//! fetching of nodes we don't know yet (3.0.x `spawn_node_fetcher` /
//! `apply_fetched_nodes`).
//!
//! Fetches are triggered by:
//! - inbound data from an unknown device,
//! - outbound traffic to an unknown MSST address,
//! - rules naming devices/users we don't know,
//! - (re)connecting to the coordinator (own user's devices + rule targets),
//! - node events for rule-referenced devices.
//!
//! Requests are de-duplicated while in flight, and a lookup that found
//! nothing is not repeated for 30 s (negative cache), so a stream of
//! packets cannot turn into a stream of HTTP requests.

use crate::state::CoreState;
use msst_acl_engine::PermissionGroup;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Don't repeat a lookup that found nothing for this long.
pub const NEGATIVE_TTL_SECS: i64 = 30;

/// A request to learn about a node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FetchDemand {
    ByDevice(String),
    ByUser(String),
    ByIp(IpAddr),
}

/// Node data from the coordinator's `/nodes/*` endpoints (3.0.x `NodeInfo`).
#[derive(Debug, Clone, Deserialize)]
pub struct NodeInfo {
    pub device_id: String,
    #[serde(default)]
    pub device_handle: Option<String>,
    #[serde(default)]
    pub device_display_name: Option<String>,
    #[serde(default)]
    pub user_display_name: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub user_handle: Option<String>,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub ipv6: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub is_authenticated: bool,
}

#[derive(Debug, Deserialize)]
struct NodesResponse {
    #[serde(default)]
    nodes: Vec<NodeInfo>,
}

// ---------------------------------------------------------------------------
// Fetch gate (pure)
// ---------------------------------------------------------------------------

/// In-flight de-duplication and negative caching for fetches.
#[derive(Debug, Default)]
pub struct FetchGate {
    pending: HashSet<FetchDemand>,
    negative_until: HashMap<FetchDemand, i64>,
}

impl FetchGate {
    /// Claim `d` for fetching.  `false` if it's in flight or recently failed.
    pub fn try_start(&mut self, d: &FetchDemand, now: i64) -> bool {
        if self.pending.contains(d) || self.negative_until.get(d).is_some_and(|&t| t > now) {
            return false;
        }
        self.negative_until.remove(d);
        self.pending.insert(d.clone());
        true
    }

    /// Release `d`.  `found == false` starts the negative-cache window.
    pub fn finish(&mut self, d: &FetchDemand, found: bool, now: i64) {
        self.pending.remove(d);
        if found {
            self.negative_until.remove(d);
        } else {
            self.negative_until.insert(d.clone(), now + NEGATIVE_TTL_SECS);
        }
    }

    /// Forget a negative result (strong evidence the node exists, e.g. a
    /// coordinator event about it).
    pub fn clear_negative(&mut self, d: &FetchDemand) {
        self.negative_until.remove(d);
    }
}

// ---------------------------------------------------------------------------
// Applying peer data
// ---------------------------------------------------------------------------

/// Peer data from any source (room_state, member_joined, /nodes/*).
#[derive(Debug, Clone, Default)]
pub struct PeerData<'a> {
    pub device_id: &'a str,
    pub ipv4: &'a str,
    pub ipv6: &'a str,
    pub user_id: Option<&'a str>,
    pub device_handle: Option<&'a str>,
    pub user_handle: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub display_name: Option<String>,
    pub user_display_name: Option<String>,
    pub public_key: &'a str,
    pub endpoints: &'a [String],
    pub is_authenticated: bool,
}

/// Upsert one peer into the peer list, scheduler and WireGuard engine.
/// Returns `false` (and changes nothing) if its addresses are invalid.
pub async fn apply_peer(state: &CoreState, p: PeerData<'_>) -> bool {
    let (Ok(ipv4), Ok(ipv6)) = (p.ipv4.parse::<IpAddr>(), p.ipv6.parse::<IpAddr>()) else {
        debug!("nodes: ignoring {} with invalid addresses ({:?}, {:?})", p.device_id, p.ipv4, p.ipv6);
        return false;
    };
    let now = crate::runtime::current_unix();
    let is_new = {
        let mut net = state.net.write().await;
        let is_new = !net.peer_list.contains(p.device_id);
        net.peer_list.upsert(
            p.device_id, ipv4, ipv6, p.user_id, p.device_handle, p.user_handle,
            p.hostname.filter(|h| !h.is_empty()), p.display_name.clone(), p.user_display_name, p.is_authenticated, now,
        );
        if let Some(relay) = crate::relay::extract_relay(p.endpoints) {
            net.peer_list.update_relay(p.device_id, &relay);
        }
        let candidates = crate::endpoints::direct_candidates(p.endpoints);
        if !candidates.is_empty() {
            net.peer_endpoints.insert(p.device_id.to_string(), candidates);
        }
        is_new
    };
    state.scheduler.lock().await.ensure_peer(p.device_id);
    if let (Some(dns), Some(h)) = (state.dns.get(), p.hostname.filter(|h| !h.is_empty())) {
        dns.invalidate(h);
    }
    if !p.public_key.is_empty() {
        if let Err(e) = state.encryption.lock().await.add_peer(p.device_id, p.public_key) {
            warn!("nodes: WG add_peer failed for {}: {}", p.device_id, e);
        }
        state.peers.lock().await.handshakes.register_peer(p.device_id, p.public_key, now);
    }
    if is_new {
        state.emit_ipc_event(msst_ipc_protocol::IpcEvent::NodeAdded {
            device_id: p.device_id.to_string(),
            ipv4: ipv4.to_string(),
            ipv6: ipv6.to_string(),
            hostname: p.hostname.filter(|h| !h.is_empty()).map(str::to_string),
            display_name: p.display_name,
        });
    }
    true
}

async fn apply_nodes(state: &CoreState, nodes: &[NodeInfo]) -> usize {
    let mut n = 0;
    for node in nodes {
        // A fetched node is kept for the communication TTL (3.0.x).
        crate::peer_cache::on_communication(state, &node.device_id).await;
        let ok = apply_peer(state, PeerData {
            device_id: &node.device_id,
            ipv4: &node.ipv4,
            ipv6: &node.ipv6,
            user_id: node.user_id.as_deref(),
            device_handle: node.device_handle.as_deref(),
            user_handle: node.user_handle.as_deref(),
            hostname: Some(&node.hostname),
            display_name: node.device_display_name.clone(),
            user_display_name: node.user_display_name.clone(),
            public_key: &node.public_key,
            endpoints: &node.endpoints,
            is_authenticated: node.is_authenticated,
        })
        .await;
        n += ok as usize;
    }
    n
}

// ---------------------------------------------------------------------------
// Fetcher
// ---------------------------------------------------------------------------

/// Queue a fetch (non-blocking; dropped if the queue is full or the
/// fetcher isn't running — the next trigger will ask again).
pub fn demand(state: &CoreState, d: FetchDemand) {
    if let Some(tx) = state.fetch_tx.get() {
        if tx.try_send(d).is_err() {
            debug!("nodes: fetch queue full, dropping demand");
        }
    }
}

/// Queue fetches for every device/user a rule names that we don't know.
pub async fn demand_rule_targets(state: &CoreState) {
    let wanted: Vec<FetchDemand> = {
        let net = state.net.read().await;
        let mut v = Vec::new();
        for r in &net.acl_rules {
            match &r.permission_group {
                PermissionGroup::Devices { ids } => v.extend(
                    ids.iter()
                        .filter(|i| crate::acl::parse::is_stable_id("device", i) && *i != "*" && !net.peer_list.contains(i))
                        .map(|i| FetchDemand::ByDevice(i.clone())),
                ),
                PermissionGroup::Users { ids } => v.extend(
                    ids.iter()
                        .filter(|i| crate::acl::parse::is_stable_id("user", i) && *i != "*" && net.peer_list.devices_for_user(i).is_empty())
                        .map(|i| FetchDemand::ByUser(i.clone())),
                ),
                PermissionGroup::Space => {}
            }
        }
        v
    };
    for d in wanted {
        demand(state, d);
    }
}

/// Start the fetcher task.
pub fn spawn_fetcher(state: Arc<CoreState>) -> tokio::task::JoinHandle<()> {
    let (tx, mut rx) = mpsc::channel::<FetchDemand>(256);
    let _ = state.fetch_tx.set(tx);
    tokio::spawn(async move {
        info!("nodes: on-demand fetcher started");
        while let Some(d) = rx.recv().await {
            let now = crate::runtime::current_unix();
            // Already known? Nothing to do.
            let known = {
                let net = state.net.read().await;
                match &d {
                    FetchDemand::ByDevice(id) => net.peer_list.contains(id),
                    FetchDemand::ByIp(ip) => net.peer_list.lookup_device_id_by_ip(ip).is_some(),
                    FetchDemand::ByUser(_) => false,
                }
            };
            if known || !state.fetch_gate.lock().unwrap_or_else(|e| e.into_inner()).try_start(&d, now) {
                continue;
            }
            let found = fetch(&state, &d).await;
            state.fetch_gate.lock().unwrap_or_else(|e| e.into_inner()).finish(&d, found, crate::runtime::current_unix());
        }
    })
}

/// Perform one fetch; returns whether the demanded node is now known.
async fn fetch(state: &Arc<CoreState>, d: &FetchDemand) -> bool {
    let Some(client) = state.coordinator.get() else { return false };
    let bearer = state
        .identity
        .read()
        .await
        .as_ref()
        .and_then(|i| i.auth.as_ref())
        .map(|a| a.access_token.clone())
        .filter(|t| !t.is_empty());
    let path = match d {
        FetchDemand::ByDevice(id) => format!("/nodes/by-device?ids={}", id),
        FetchDemand::ByUser(id) => format!("/nodes/by-user/{}", id),
        FetchDemand::ByIp(ip) => format!("/nodes/by-ip?ip={}", ip),
    };
    let nodes = match client.api_get(&path, bearer.as_deref()).await {
        Ok(Some(v)) => serde_json::from_value::<NodesResponse>(v).map(|r| r.nodes).unwrap_or_default(),
        Ok(None) => Vec::new(),
        Err(e) => {
            warn!("nodes: fetch {:?} failed: {}", d, e);
            Vec::new()
        }
    };
    let applied = apply_nodes(state, &nodes).await;
    if applied > 0 {
        info!("nodes: fetched {} node(s) for {:?}", applied, d);
    }
    if is_known(state, d, applied).await {
        return true;
    }
    // By-IP miss: fall back to our own user's devices (3.0.x) — covers
    // same-user devices that share no room and no rule.
    if let FetchDemand::ByIp(_) = d {
        let uid = state.net.read().await.local_user_id.clone();
        if !uid.is_empty() {
            if let Ok(Some(v)) = client.api_get(&format!("/nodes/by-user/{}", uid), bearer.as_deref()).await {
                if let Ok(r) = serde_json::from_value::<NodesResponse>(v) {
                    apply_nodes(state, &r.nodes).await;
                }
            }
            return is_known(state, d, 0).await;
        }
    }
    false
}

async fn is_known(state: &CoreState, d: &FetchDemand, applied: usize) -> bool {
    let net = state.net.read().await;
    match d {
        FetchDemand::ByDevice(id) => net.peer_list.contains(id),
        FetchDemand::ByIp(ip) => net.peer_list.lookup_device_id_by_ip(ip).is_some(),
        FetchDemand::ByUser(_) => applied > 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_dedups_and_negative_caches() {
        let mut g = FetchGate::default();
        let d = FetchDemand::ByDevice("device-0000000b".into());
        assert!(g.try_start(&d, 100));
        assert!(!g.try_start(&d, 100), "in flight");
        g.finish(&d, false, 100);
        assert!(!g.try_start(&d, 100 + NEGATIVE_TTL_SECS - 1), "negative cache");
        assert!(g.try_start(&d, 100 + NEGATIVE_TTL_SECS));
        g.finish(&d, true, 200);
        assert!(g.try_start(&d, 200), "found → no negative entry");
        g.finish(&d, false, 200);
        g.clear_negative(&d);
        assert!(g.try_start(&d, 201));
        // Independent keys.
        assert!(g.try_start(&FetchDemand::ByIp("172.22.1.1".parse().unwrap()), 201));
    }

    #[test]
    fn node_info_parses_3_0_x_shape() {
        let r: NodesResponse = serde_json::from_str(r#"{"nodes":[{"device_id":"device-0000000b","device_handle":"pc",
            "user_id":"user-0000000b","user_handle":"bob","public_key":"","ipv4":"172.22.1.1",
            "ipv6":"fd22:2222:2222:2222::b","hostname":"pc.bob.ezplay.msst.net",
            "endpoints":["1.2.3.4:21031","relay:5.6.7.8:7000"],"status":"online","is_authenticated":true}]}"#).unwrap();
        assert_eq!(r.nodes[0].user_handle.as_deref(), Some("bob"));
        assert_eq!(crate::relay::extract_relay(&r.nodes[0].endpoints).as_deref(), Some("5.6.7.8:7000"));
    }

    /// Fake coordinator: path → body (404 otherwise); counts requests per path.
    async fn fake_coordinator(routes: Vec<(String, String)>) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
                seen2.lock().unwrap().push(path.clone());
                let (status, body) = routes.iter().find(|(p, _)| *p == path).map(|(_, b)| (200, b.clone())).unwrap_or((404, "{}".into()));
                let resp = format!("HTTP/1.1 {} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", status, body.len(), body);
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });
        (url, seen)
    }

    fn node_json(dev: &str, user: &str, v4: &str, hex: &str) -> String {
        format!(r#"{{"device_id":"{dev}","user_id":"{user}","device_handle":"pc","user_handle":"u","ipv4":"{v4}","ipv6":"fd22:2222:2222:2222::{hex}","hostname":"","endpoints":["relay:9.9.9.9:7000"],"public_key":"","is_authenticated":true}}"#)
    }

    async fn state_with_coordinator(url: &str) -> Arc<CoreState> {
        let (ipc_tx, _rx) = mpsc::channel(64);
        std::mem::forget(_rx);
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let state = Arc::new(CoreState::new(ipc_tx, udp, std::env::temp_dir()));
        state.net.write().await.local_user_id = "user-00000001".into();
        let (ev_tx, _ev_rx) = mpsc::channel(4);
        std::mem::forget(_ev_rx);
        let client = crate::coordinator::CoordinatorClient::new(
            crate::coordinator::CoordinatorConfig { coord_url: url.into() }, ev_tx);
        let _ = state.coordinator.set(Arc::new(client));
        spawn_fetcher(state.clone());
        state
    }

    async fn wait_until(state: &CoreState, f: impl Fn(&msst_core_state::peer_list::PeerList) -> bool) -> bool {
        for _ in 0..100 {
            if f(&state.net.read().await.peer_list) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn fetch_by_device_and_negative_cache() {
        let (url, seen) = fake_coordinator(vec![(
            "/nodes/by-device?ids=device-0000000b".into(),
            format!(r#"{{"nodes":[{}]}}"#, node_json("device-0000000b", "user-0000000b", "172.22.1.1", "b")),
        )]).await;
        let state = state_with_coordinator(&url).await;
        demand(&state, FetchDemand::ByDevice("device-0000000b".into()));
        assert!(wait_until(&state, |pl| pl.contains("device-0000000b")).await);
        let net = state.net.read().await;
        assert_eq!(net.peer_list.get("device-0000000b").unwrap().preferred_relay.as_deref(), Some("9.9.9.9:7000"));
        assert_eq!(net.peer_list.resolve_user_handle("u"), Some("user-0000000b"));
        drop(net);

        // Unknown device: one request, then negative-cached.
        for _ in 0..5 {
            demand(&state, FetchDemand::ByDevice("device-0000000c".into()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let n = seen.lock().unwrap().iter().filter(|p| p.contains("device-0000000c")).count();
        assert_eq!(n, 1, "requests: {:?}", seen.lock().unwrap());
    }

    #[tokio::test]
    async fn by_ip_miss_falls_back_to_own_user() {
        let (url, seen) = fake_coordinator(vec![(
            "/nodes/by-user/user-00000001".into(),
            format!(r#"{{"nodes":[{}]}}"#, node_json("device-00000002", "user-00000001", "172.22.5.5", "2")),
        )]).await;
        let state = state_with_coordinator(&url).await;
        let ip: IpAddr = "172.22.5.5".parse().unwrap();
        demand(&state, FetchDemand::ByIp(ip));
        assert!(wait_until(&state, |pl| pl.lookup_device_id_by_ip(&ip) == Some("device-00000002")).await);
        let paths = seen.lock().unwrap().clone();
        assert_eq!(paths, vec!["/nodes/by-ip?ip=172.22.5.5".to_string(), "/nodes/by-user/user-00000001".to_string()]);
    }
}
