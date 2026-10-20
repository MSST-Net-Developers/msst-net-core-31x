//! Own endpoint detection and reporting (3.0.x `net/endpoints.rs`).
//!
//! Detects the endpoints peers can use to reach us directly:
//! - public IPv4:port via STUN on the main UDP socket (the NAT mapping
//!   peers will see),
//! - LAN IPv4 addresses (direct P2P inside one LAN without NAT hairpinning),
//! - public IPv6 addresses.
//!
//! Also `relay:<addr>` so peers can route to our relay, and, while our room
//! relay works, `room-relay:<addr>` (`crate::room_relay`).  With
//! `disable_p2p` only the relays are reported.  Reported via
//! `POST /device/endpoint`.
//!
//! Triggers: after a relay is selected, every 5 minutes (scheduler
//! `DetectEndpoints`), on `RefreshEndpoint`, and when the room relay comes
//! or goes.  Only one detection runs at a time; a request meanwhile makes it
//! run once more.

use crate::state::CoreState;
use msst_core_state::nat::stun;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

/// Endpoint sets kept in history (3.0.x).
const HISTORY_MAX: usize = 10;

/// STUN transactions awaiting a response on the main socket.
pub type StunWaiters = std::sync::Mutex<HashMap<[u8; 12], oneshot::Sender<SocketAddr>>>;

#[derive(Debug, Clone, Serialize)]
pub struct EndpointRecord {
    pub endpoints: Vec<String>,
    pub reported_at: i64,
}

/// The current reported endpoint set and its predecessors.
#[derive(Debug, Default)]
pub struct EndpointHistory {
    pub current: Vec<String>,
    pub history: VecDeque<EndpointRecord>,
}

impl EndpointHistory {
    /// Record a report; a changed set pushes the old one into history.
    /// Returns whether the set changed.
    pub fn record(&mut self, endpoints: Vec<String>, now: i64) -> bool {
        if endpoints == self.current {
            return false;
        }
        if !self.current.is_empty() {
            self.history.push_back(EndpointRecord { endpoints: std::mem::take(&mut self.current), reported_at: now });
            if self.history.len() > HISTORY_MAX {
                self.history.pop_front();
            }
        }
        self.current = endpoints;
        true
    }

    /// `GetEndpoints` view (3.0.x `GET /net/endpoints`).
    pub fn to_view(&self) -> Value {
        json!({ "current": self.current, "history": self.history })
    }
}

/// Route a STUN response from the main socket to the waiting detector.
pub fn on_stun_response(state: &CoreState, data: &[u8]) {
    let (Some(txid), Some(addr)) = (stun::parse_txid(data), stun::parse_response(data)) else { return };
    if let Some(tx) = state.stun_waiters.lock().unwrap_or_else(|e| e.into_inner()).remove(&txid) {
        let _ = tx.send(addr);
    }
}

/// Our public IPv4 endpoint via STUN: all servers in parallel, first answer wins.
async fn detect_public_ipv4(state: &CoreState) -> Option<SocketAddr> {
    let mut receivers = Vec::new();
    for server in stun::STUN_SERVERS {
        let Some(target) = tokio::net::lookup_host(server).await.ok().and_then(|mut it| it.find(|a| a.is_ipv4())) else {
            debug!("STUN: cannot resolve {}", server);
            continue;
        };
        let (txid, req) = stun::build_binding_request();
        let (tx, rx) = oneshot::channel();
        state.stun_waiters.lock().unwrap_or_else(|e| e.into_inner()).insert(txid, tx);
        if state.udp_socket.send_to(&req, msst_core_state::net::relay::map_send_addr(target)).await.is_ok() {
            receivers.push((txid, rx));
        } else {
            state.stun_waiters.lock().unwrap_or_else(|e| e.into_inner()).remove(&txid);
        }
    }
    if receivers.is_empty() {
        warn!("STUN: no server could be queried");
        return None;
    }
    let txids: Vec<[u8; 12]> = receivers.iter().map(|(t, _)| *t).collect();
    let first = futures_util::future::select_ok(receivers.into_iter().map(|(_, rx)| rx));
    let result = tokio::time::timeout(Duration::from_secs(stun::STUN_TIMEOUT_SECS), first).await;
    {
        let mut w = state.stun_waiters.lock().unwrap_or_else(|e| e.into_inner());
        for t in txids {
            w.remove(&t);
        }
    }
    match result {
        Ok(Ok((addr, _))) => Some(msst_core_state::net::relay::unmap_addr(addr)),
        _ => {
            warn!("STUN: no server answered within {}s", stun::STUN_TIMEOUT_SECS);
            None
        }
    }
}

/// Build the endpoint list (pure).
pub fn build_endpoints(
    disable_p2p: bool,
    stun_addr: Option<SocketAddr>,
    lan_v4: &[std::net::Ipv4Addr],
    public_v6: &[std::net::Ipv6Addr],
    port: u16,
    relay: Option<&str>,
    room_relay: Option<&str>,
) -> Vec<String> {
    let mut eps = Vec::new();
    if !disable_p2p {
        eps.extend(stun_addr.map(|a| a.to_string()));
        eps.extend(lan_v4.iter().map(|ip| format!("{}:{}", ip, port)));
        eps.extend(public_v6.iter().map(|ip| format!("[{}]:{}", ip, port)));
    }
    eps.extend(relay.map(|r| format!("relay:{}", r)));
    eps.extend(room_relay.map(|r| format!("{}{}", crate::room_relay::ENDPOINT_PREFIX, r)));
    eps
}

/// Detect and report our endpoints.  A request while a detection runs makes
/// it run once more afterwards (what it reports may be stale already, e.g.
/// the room relay's health changed meanwhile).
pub fn spawn_detect_and_report(state: Arc<CoreState>) {
    state.endpoint_detect_again.store(true, Ordering::SeqCst);
    if state.endpoint_detect_running.swap(true, Ordering::SeqCst) {
        debug!("endpoints: detection already running; it will run again");
        return;
    }
    tokio::spawn(async move {
        loop {
            state.endpoint_detect_again.store(false, Ordering::SeqCst);
            if let Err(e) = detect_and_report(&state).await {
                warn!("endpoints: {}", e);
            }
            state.endpoint_detect_running.store(false, Ordering::SeqCst);
            // A request that came in meanwhile, unless another task took it.
            if !state.endpoint_detect_again.load(Ordering::SeqCst) || state.endpoint_detect_running.swap(true, Ordering::SeqCst) {
                break;
            }
        }
    });
}

async fn detect_and_report(state: &Arc<CoreState>) -> Result<(), String> {
    let disable_p2p = state.net_settings.read().await.disable_p2p;
    let stun_addr = if disable_p2p { None } else { detect_public_ipv4(state).await };
    let port = state.udp_socket.local_addr().map(|a| a.port()).unwrap_or(21031);
    let (device_id, relay, room_relay) = {
        let net = state.net.read().await;
        let room_relay = net.room_relay.as_ref().filter(|r| r.usable_addr().is_some()).map(|r| r.address.clone());
        (net.local_device_id.clone(), net.relay_addr.clone(), room_relay)
    };
    let (lan, v6) = if disable_p2p { (Vec::new(), Vec::new()) } else { (stun::detect_lan_ipv4(), stun::detect_public_ipv6()) };
    let endpoints = build_endpoints(disable_p2p, stun_addr, &lan, &v6, port, relay.as_deref(), room_relay.as_deref());
    if endpoints.is_empty() {
        return Err("no endpoints to report (no public address and no relay)".into());
    }
    let client = state.coordinator.get().ok_or("coordinator client not started")?;
    client
        .api_post("/device/endpoint", &json!({ "deviceId": device_id, "endpoints": endpoints }))
        .await?;
    info!("endpoints: reported {:?}", endpoints);
    let changed = state.endpoint_history.lock().unwrap_or_else(|e| e.into_inner()).record(endpoints, crate::runtime::current_unix());
    if changed {
        state.next_generation();
    }
    Ok(())
}

/// Peer endpoints usable as direct-path candidates (drops `relay:` entries
/// and unparseable ones), IPv6 first (3.0.x `sort_candidates_ipv6_first`).
pub fn direct_candidates(endpoints: &[String]) -> Vec<SocketAddr> {
    let mut v: Vec<SocketAddr> = endpoints.iter().filter_map(|e| e.parse().ok()).collect();
    v.sort_by_key(|a| !a.is_ipv6());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_list_shape() {
        let stun_addr: SocketAddr = "1.2.3.4:40000".parse().unwrap();
        let lan = ["192.168.1.5".parse().unwrap()];
        let v6 = ["2001:db8::5".parse().unwrap()];
        assert_eq!(
            build_endpoints(false, Some(stun_addr), &lan, &v6, 21031, Some("5.6.7.8:7000"), None),
            vec!["1.2.3.4:40000", "192.168.1.5:21031", "[2001:db8::5]:21031", "relay:5.6.7.8:7000"]
        );
        // disable_p2p → relays only; a working room relay is announced.
        assert_eq!(build_endpoints(true, Some(stun_addr), &lan, &v6, 21031, Some("r:1"), Some("9.9.9.9:7000")), vec!["relay:r:1", "room-relay:9.9.9.9:7000"]);
        assert!(build_endpoints(true, None, &[], &[], 21031, None, None).is_empty());
    }

    #[test]
    fn history_keeps_changed_sets_only() {
        let mut h = EndpointHistory::default();
        h.record(vec!["a".into()], 1);
        h.record(vec!["a".into()], 2);
        assert!(h.history.is_empty());
        for i in 0..15 {
            h.record(vec![format!("e{}", i)], 10 + i);
        }
        assert_eq!(h.current, vec!["e14"]);
        assert_eq!(h.history.len(), HISTORY_MAX);
        assert_eq!(h.to_view()["history"][0]["endpoints"][0], "e4"); // a, e0..e13 → last 10
    }

    #[test]
    fn candidates_drop_relay_and_prefer_ipv6() {
        let eps = vec!["1.2.3.4:1".to_string(), "relay:5.6.7.8:7000".to_string(), "[2001:db8::1]:2".to_string(), "bogus".to_string()];
        let c = direct_candidates(&eps);
        assert_eq!(c, vec!["[2001:db8::1]:2".parse::<SocketAddr>().unwrap(), "1.2.3.4:1".parse().unwrap()]);
    }

    #[tokio::test]
    async fn reports_to_coordinator_and_records_history() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (body_tx, body_rx) = oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let mut req = String::new();
            // Read until the JSON body has arrived.
            while !req.contains('}') || !req.ends_with('}') {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 { break; }
                req.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}").await.unwrap();
            let _ = body_tx.send(req);
        });

        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let state = Arc::new(CoreState::new(udp, std::env::temp_dir()));
        {
            let mut net = state.net.write().await;
            net.local_device_id = "device-00000001".into();
            net.relay_addr = Some("5.6.7.8:7000".into());
        }
        // disable_p2p: no STUN / interface probing in the test, relay only.
        state.net_settings.write().await.disable_p2p = true;
        let (ev_tx, _ev_rx) = tokio::sync::mpsc::channel(4);
        let client = crate::coordinator::CoordinatorClient::new(crate::coordinator::CoordinatorConfig { coord_url: url }, ev_tx);
        let _ = state.coordinator.set(Arc::new(client));

        detect_and_report(&state).await.unwrap();
        let req = body_rx.await.unwrap();
        assert!(req.starts_with("POST /device/endpoint "));
        let body: Value = serde_json::from_str(&req[req.find('{').unwrap()..]).unwrap();
        assert_eq!(body, json!({ "deviceId": "device-00000001", "endpoints": ["relay:5.6.7.8:7000"] }));
        assert_eq!(state.endpoint_history.lock().unwrap().current, vec!["relay:5.6.7.8:7000"]);
    }
}
