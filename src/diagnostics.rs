//! Diagnostics: per-peer traffic counters, path view, tracked connections,
//! relay list, and diagnostic ping jobs (3.0.x `api.rs` diagnostics).

use crate::state::CoreState;
use msst_core_state::net::msst_packet;
use msst_core_state::net::path::{PeerPathMode, MAX_PROBE_MISS};
use msst_ipc_protocol::IpcError;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

/// Pings per diagnostic job (3.0.x).
pub const DIAG_PING_COUNT: usize = 10;
const DIAG_PING_TIMEOUT: Duration = Duration::from_secs(2);
const DIAG_PING_GAP: Duration = Duration::from_millis(200);
/// Jobs are forgotten after this long.
const JOB_TTL: Duration = Duration::from_secs(300);

fn err(code: &str, m: impl Into<String>) -> IpcError {
    IpcError { code: code.into(), message: m.into() }
}

// ---------------------------------------------------------------------------
// Traffic counters (hot path: one read lock + one atomic add)
// ---------------------------------------------------------------------------

/// Packets sent to / received from / dropped for one peer.
#[derive(Debug, Default)]
pub struct TrafficStats {
    pub tx: AtomicU64,
    pub rx: AtomicU64,
    pub drop: AtomicU64,
}

pub type TrafficMap = std::sync::RwLock<HashMap<String, Arc<TrafficStats>>>;

/// Counters for `peer` (created on first use).
pub fn traffic(state: &CoreState, peer: &str) -> Arc<TrafficStats> {
    if let Some(s) = state.traffic.read().unwrap_or_else(|e| e.into_inner()).get(peer) {
        return s.clone();
    }
    state.traffic.write().unwrap_or_else(|e| e.into_inner()).entry(peer.to_string()).or_default().clone()
}

/// Reset `peer`'s counters (its path changed, as 3.0.x).
pub fn reset_traffic(state: &CoreState, peer: &str) {
    state.traffic.write().unwrap_or_else(|e| e.into_inner()).insert(peer.to_string(), Arc::default());
}

/// `GetTrafficStats` (3.0.x `GET /net/traffic`).
pub async fn traffic_view(state: &CoreState) -> Value {
    let snapshot: Vec<(String, u64, u64, u64)> = state
        .traffic
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(id, s)| (id.clone(), s.tx.load(Relaxed), s.rx.load(Relaxed), s.drop.load(Relaxed)))
        .collect();
    let net = state.net.read().await;
    let peers: Vec<Value> = snapshot
        .into_iter()
        .map(|(id, tx, rx, drop)| {
            json!({
                "device_id": id,
                "display_name": net.peer_list.get(&id).and_then(|e| e.display_name.clone()),
                "tx": tx, "rx": rx, "drop": drop,
            })
        })
        .collect();
    json!({ "peers": peers })
}

// ---------------------------------------------------------------------------
// Path view
// ---------------------------------------------------------------------------

/// `GetPathView` / `GetPaths` (3.0.x `GET /net/path-view`): per peer, the
/// chosen path and its candidates.
pub async fn path_view(state: &CoreState) -> Value {
    let now = crate::runtime::current_unix();
    let enc_views = state.encryption.lock().await.views(now);
    let sched = state.scheduler.lock().await;
    let net = state.net.read().await;
    let peers: Vec<Value> = sched
        .paths()
        .map(|(id, pp)| {
            let (chosen, candidates) = match &pp.mode {
                PeerPathMode::Relay => {
                    let eps: Vec<Value> = net
                        .peer_endpoints
                        .get(id)
                        .map(|v| v.iter().map(|ep| json!({ "addr": ep.to_string(), "status": "idle" })).collect())
                        .unwrap_or_else(|| vec![json!({ "addr": "relay", "status": "relay" })]);
                    ("relay".to_string(), eps)
                }
                PeerPathMode::Probing => (
                    "probing".to_string(),
                    pp.probe_candidates
                        .iter()
                        .map(|ep| {
                            let failed = pp.probe_miss.get(ep).copied().unwrap_or(0) >= MAX_PROBE_MISS;
                            json!({ "addr": ep.to_string(), "status": if failed { "fail" } else { "probing" } })
                        })
                        .collect(),
                ),
                PeerPathMode::Direct { endpoint } => {
                    let mut c = vec![json!({
                        "addr": endpoint.to_string(),
                        "rtt_ms": pp.rtt_baseline_ms,
                        "loss_rate": pp.loss_rate(),
                        "status": "direct",
                    })];
                    // Background-probed alternatives.
                    c.extend(pp.probe_candidates.iter().map(|ep| {
                        let failed = pp.probe_miss.get(ep).copied().unwrap_or(0) >= MAX_PROBE_MISS;
                        json!({
                            "addr": ep.to_string(),
                            "rtt_ms": pp.probe_rtt_ms.get(ep),
                            "status": if failed { "fail" } else { "probing" },
                        })
                    }));
                    (format!("direct:{}", endpoint), c)
                }
            };
            let mut v = json!({
                "device_id": id,
                "display_name": net.peer_list.get(id).and_then(|e| e.display_name.clone()),
                "chosen": chosen,
                "candidates": candidates,
            });
            // WireGuard session; `no_key`: the coordinator gave no public
            // key, so nothing can be exchanged with this peer.
            let ev = enc_views.get(id);
            v["encryption"] = json!(ev.map_or("no_key", |e| e.state.name()));
            if let Some(t) = ev.and_then(|e| e.last_handshake_at) {
                v["last_handshake_at"] = json!(t);
            }
            // Unreachable peer: when the next probe round may start.
            if pp.probe_failures > 0 {
                v["probe_failures"] = json!(pp.probe_failures);
                v["next_probe_at"] = json!(pp.next_probe_at);
            }
            v
        })
        .collect();
    json!({ "peers": peers })
}

/// `GetConnections`: flows tracked for the "related traffic" fast path.
pub async fn connections_view(state: &CoreState) -> Value {
    let flows: Vec<(std::net::IpAddr, u16, std::net::IpAddr, u16, u8, i64)> = state
        .conn_track
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entries()
        .map(|(k, t)| (k.src_ip, k.src_port, k.dst_ip, k.dst_port, k.proto, t))
        .collect();
    let net = state.net.read().await;
    let conns: Vec<Value> = flows
        .into_iter()
        .map(|(src, sp, dst, dp, proto, last)| {
            json!({
                "proto": match proto { 6 => "tcp", 17 => "udp", _ => "other" },
                "local": std::net::SocketAddr::new(src, sp).to_string(),
                "remote": std::net::SocketAddr::new(dst, dp).to_string(),
                "peer_device_id": net.peer_list.lookup_device_id_by_ip(&dst),
                "last_outbound_unix": last,
            })
        })
        .collect();
    json!({ "connections": conns })
}

/// `GetRelays`: the coordinator's relay list plus our current relay and
/// measured RTTs.
pub async fn relays(state: &CoreState) -> Result<Value, IpcError> {
    let client = state.coordinator.get().ok_or_else(|| err("coordinator_unavailable", "coordinator client not started"))?;
    let (status, mut body) = client
        .api_request(reqwest::Method::GET, "/relays", None, None)
        .await
        .map_err(|e| err("coordinator_unavailable", e))?;
    if !(200..300).contains(&status) {
        return Err(err("coordinator_error", format!("GET /relays returned {}: {}", status, body)));
    }
    let net = state.net.read().await;
    if body.is_object() {
        body["current"] = json!(net.relay_addr);
        body["rtt_ms"] = json!(net.relay_rtt.all());
        // Game discovery (over WireGuard since 3.1.6; `secure_discovery`,
        // the retired relay-based sdisc, is gone).
        body["discovery"] = state.discovery_stats.snapshot();
        // Registration with the current relay (sreg v1 or legacy 0x01/0x02).
        let tx_sreg = state.relay_reg.lock().unwrap_or_else(|e| e.into_inner()).tx_sreg;
        let path_ok = state.relay_path_ok_at.load(std::sync::atomic::Ordering::Relaxed);
        body["registration"] = json!({
            "mode": if net.relay_sreg { "sreg1" } else { "legacy" },
            "tx_sreg": tx_sreg,
            "last_relay_path_ok_at": (path_ok > 0).then_some(path_ok),
        });
        // The room relay (additive): `null` outside a room with one.
        body["room_relay"] = match &net.room_relay {
            Some(r) => {
                let mut v = r.view();
                v["addr"] = json!(r.addr);
                v["tx_sreg"] = json!(state.room_relay_reg.lock().unwrap_or_else(|e| e.into_inner()).tx_sreg);
                v
            }
            None => Value::Null,
        };
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// Diagnostic ping jobs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct PingJob {
    pub target_device_id: String,
    /// Per-ping RTT in ms; `None` = timed out.
    pub results: Vec<Option<f64>>,
    pub done: bool,
    /// The path measured: `direct` or `relay` (protocol 0.4, additive).
    pub path: &'static str,
    #[serde(skip)]
    started: Option<Instant>,
}

pub type PingJobs = std::sync::Mutex<HashMap<String, PingJob>>;

/// In-tunnel diagnostic probes waiting for their pong, by (peer, seq).
pub type ProbeWaiters = std::sync::Mutex<HashMap<(String, u32), tokio::sync::oneshot::Sender<()>>>;

/// The path a diagnostic ping measures: the one the peer's traffic takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiagPath {
    /// P2P ping (`0x06`) to the active direct endpoint, from a fresh socket.
    Direct(std::net::SocketAddr),
    /// A probe inside the WireGuard session over the relay route
    /// (`crate::tunnel_probe`), answered by the peer's Core.
    Relay,
}

/// `StartDiagPing`: ping a peer 10 times (200 ms apart, 2 s timeout) over
/// the path its traffic takes now — its direct endpoint while the path is
/// direct, else through the relays inside the WireGuard session (a
/// handshake is started if needed, so the first ping may include it).
/// 3.0.x always pinged the first announced direct endpoint, which timed out
/// whenever the peer was relayed, and sent direct packets with P2P disabled.
pub async fn start_ping(state: &Arc<CoreState>, device_id: String) -> Result<Value, IpcError> {
    let local_id = state.net.read().await.local_device_id.clone();
    if local_id.is_empty() {
        return Err(err("not_initialized", "identity not loaded"));
    }
    let path = match state.scheduler.lock().await.direct_endpoint(&device_id) {
        Some(ep) => DiagPath::Direct(ep),
        None => DiagPath::Relay,
    };
    let job_id = format!("{:x}", rand::random::<u64>());
    {
        let mut jobs = state.ping_jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.retain(|_, j| j.started.is_some_and(|t| t.elapsed() < JOB_TTL));
        jobs.insert(job_id.clone(), PingJob {
            target_device_id: device_id.clone(),
            results: Vec::new(),
            done: false,
            path: if matches!(path, DiagPath::Direct(_)) { "direct" } else { "relay" },
            started: Some(Instant::now()),
        });
    }
    info!("diagnostics: ping {} started (job {}, {:?})", device_id, job_id, path);
    let (st, id) = (state.clone(), job_id.clone());
    tokio::spawn(async move { run_ping(st, id, local_id, device_id, path).await });
    Ok(json!({ "job_id": job_id }))
}

async fn run_ping(state: Arc<CoreState>, job_id: String, local_id: String, target: String, path: DiagPath) {
    let sock = match path {
        DiagPath::Direct(ep) => crate::netsock::udp_socket(crate::netsock::any_for(&ep)).await.ok(),
        DiagPath::Relay => None,
    };
    for i in 0..DIAG_PING_COUNT {
        let rtt = match path {
            DiagPath::Direct(ep) => match &sock {
                Some(s) => direct_ping(s, ep, &local_id, &target, i as u32).await,
                None => None,
            },
            DiagPath::Relay => tunnel_ping(&state, &target).await,
        };
        if let Some(job) = state.ping_jobs.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&job_id) {
            job.results.push(rtt);
        }
        if i + 1 < DIAG_PING_COUNT {
            tokio::time::sleep(DIAG_PING_GAP).await;
        }
    }
    if let Some(job) = state.ping_jobs.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&job_id) {
        job.done = true;
    }
}

async fn direct_ping(s: &tokio::net::UdpSocket, ep: std::net::SocketAddr, local_id: &str, target: &str, seq: u32) -> Option<f64> {
    let pkt = msst_packet::build_p2p_ping(local_id, target, seq, crate::runtime::current_time_ms());
    let t0 = Instant::now();
    s.send_to(&pkt, ep).await.ok()?;
    let mut buf = [0u8; 512];
    match tokio::time::timeout(DIAG_PING_TIMEOUT, s.recv(&mut buf)).await {
        Ok(Ok(_)) => Some(t0.elapsed().as_secs_f64() * 1000.0),
        _ => None,
    }
}

async fn tunnel_ping(state: &Arc<CoreState>, target: &str) -> Option<f64> {
    // High bit set: never one of the scheduler's relay-path probe numbers.
    let seq = rand::random::<u32>() | 0x8000_0000;
    let key = (target.to_string(), seq);
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.diag_probe_waiters.lock().unwrap_or_else(|e| e.into_inner()).insert(key.clone(), tx);
    let t0 = Instant::now();
    let rtt = if crate::runtime::send_diag_probe(state, target, seq).await {
        tokio::time::timeout(DIAG_PING_TIMEOUT, rx).await.ok().and_then(|r| r.ok()).map(|_| t0.elapsed().as_secs_f64() * 1000.0)
    } else {
        None
    };
    state.diag_probe_waiters.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
    rtt
}

/// A tunnel probe pong arrived from `device_id`: complete the diagnostic
/// ping waiting for it.  Returns whether it was one.
pub fn on_probe_pong(state: &CoreState, device_id: &str, seq: u32) -> bool {
    match state.diag_probe_waiters.lock().unwrap_or_else(|e| e.into_inner()).remove(&(device_id.to_string(), seq)) {
        Some(tx) => {
            let _ = tx.send(());
            true
        }
        None => false,
    }
}

/// `GetDiagPingResult`.
pub fn ping_result(state: &CoreState, job_id: &str) -> Result<Value, IpcError> {
    let jobs = state.ping_jobs.lock().unwrap_or_else(|e| e.into_inner());
    let job = jobs.get(job_id).ok_or_else(|| err("not_found", format!("Ping job '{}' not found", job_id)))?;
    Ok(serde_json::to_value(job).unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::core_state;

    #[tokio::test]
    async fn traffic_counters_and_reset() {
        let (state, _ipc) = core_state("traffic").await;
        traffic(&state, "device-b").tx.fetch_add(3, Relaxed);
        traffic(&state, "device-b").rx.fetch_add(2, Relaxed);
        let v = traffic_view(&state).await;
        assert_eq!(v["peers"][0]["tx"], 3);
        assert_eq!(v["peers"][0]["rx"], 2);
        reset_traffic(&state, "device-b");
        assert_eq!(traffic_view(&state).await["peers"][0]["tx"], 0);
    }

    #[tokio::test]
    async fn diag_ping_direct_against_echoing_peer() {
        let (state, _ipc) = core_state("diagping").await;
        // A "peer" that answers every ping.
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ep = peer.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            while let Ok((n, src)) = peer.recv_from(&mut b).await {
                let _ = peer.send_to(&b[..n], src).await;
            }
        });
        state.ping_jobs.lock().unwrap().insert("j".into(), PingJob {
            target_device_id: "device-b".into(), results: Vec::new(), done: false, path: "direct", started: Some(Instant::now()),
        });
        run_ping(state.clone(), "j".into(), "device-00000001".into(), "device-b".into(), DiagPath::Direct(ep)).await;
        let done = ping_result(&state, "j").unwrap();
        assert_eq!(done["done"], true);
        assert_eq!(done["path"], "direct");
        assert_eq!(done["results"].as_array().unwrap().len(), DIAG_PING_COUNT);
        assert!(done["results"].as_array().unwrap().iter().all(|r| r.is_number()));
        assert_eq!(ping_result(&state, "nope").unwrap_err().code, "not_found");
    }

    #[tokio::test]
    async fn diag_ping_of_a_relayed_peer_goes_through_the_tunnel() {
        let (state, _ipc) = core_state("diagping-relay").await;
        // Not direct: the relay path is measured (no session or relay
        // here, so every ping times out — not the direct candidate).
        state.net.write().await.peer_endpoints.insert("device-b".into(), vec!["127.0.0.1:9".parse().unwrap()]);
        let job = start_ping(&state, "device-b".into()).await.unwrap()["job_id"].as_str().unwrap().to_string();
        assert_eq!(ping_result(&state, &job).unwrap()["path"], "relay");
    }

    #[tokio::test]
    async fn path_view_shapes() {
        let (state, _ipc) = core_state("pathview").await;
        state.scheduler.lock().await.ensure_peer("device-b");
        let v = path_view(&state).await;
        assert_eq!(v["peers"][0]["device_id"], "device-b");
        assert_eq!(v["peers"][0]["chosen"], "relay");
        assert_eq!(v["peers"][0]["candidates"][0]["status"], "relay");
    }
}
