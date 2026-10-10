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
                PeerPathMode::Direct { endpoint } => (
                    format!("direct:{}", endpoint),
                    vec![json!({
                        "addr": endpoint.to_string(),
                        "rtt_ms": pp.rtt_baseline_ms,
                        "loss_rate": pp.loss_rate(),
                        "status": "direct",
                    })],
                ),
            };
            json!({
                "device_id": id,
                "display_name": net.peer_list.get(id).and_then(|e| e.display_name.clone()),
                "chosen": chosen,
                "candidates": candidates,
            })
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
    #[serde(skip)]
    started: Option<Instant>,
}

pub type PingJobs = std::sync::Mutex<HashMap<String, PingJob>>;

/// `StartDiagPing`: ping the peer's first announced direct endpoint 10
/// times (200 ms apart, 2 s timeout) from a fresh socket.  Without a known
/// endpoint every result is a timeout (3.0.x).
pub async fn start_ping(state: &Arc<CoreState>, device_id: String) -> Result<Value, IpcError> {
    let (local_id, endpoint) = {
        let net = state.net.read().await;
        (net.local_device_id.clone(), net.peer_endpoints.get(&device_id).and_then(|v| v.first().copied()))
    };
    if local_id.is_empty() {
        return Err(err("not_initialized", "identity not loaded"));
    }
    let job_id = format!("{:x}", rand::random::<u64>());
    {
        let mut jobs = state.ping_jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.retain(|_, j| j.started.is_some_and(|t| t.elapsed() < JOB_TTL));
        jobs.insert(job_id.clone(), PingJob { target_device_id: device_id.clone(), results: Vec::new(), done: false, started: Some(Instant::now()) });
    }
    info!("diagnostics: ping {} started (job {})", device_id, job_id);
    let (st, id) = (state.clone(), job_id.clone());
    tokio::spawn(async move { run_ping(st, id, local_id, device_id, endpoint).await });
    Ok(json!({ "job_id": job_id }))
}

async fn run_ping(state: Arc<CoreState>, job_id: String, local_id: String, target: String, endpoint: Option<std::net::SocketAddr>) {
    let sock = match endpoint {
        Some(ep) => crate::netsock::udp_socket(crate::netsock::any_for(&ep)).await.ok(),
        None => None,
    };
    let mut buf = [0u8; 512];
    for i in 0..DIAG_PING_COUNT {
        let rtt = match (endpoint, &sock) {
            (Some(ep), Some(s)) => {
                let pkt = msst_packet::build_p2p_ping(&local_id, &target, i as u32, crate::runtime::current_time_ms());
                let t0 = Instant::now();
                match s.send_to(&pkt, ep).await {
                    Ok(_) => match tokio::time::timeout(DIAG_PING_TIMEOUT, s.recv(&mut buf)).await {
                        Ok(Ok(_)) => Some(t0.elapsed().as_secs_f64() * 1000.0),
                        _ => None,
                    },
                    Err(_) => None,
                }
            }
            _ => None,
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
    async fn diag_ping_against_echoing_peer() {
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
        state.net.write().await.peer_endpoints.insert("device-b".into(), vec![ep]);
        let job = start_ping(&state, "device-b".into()).await.unwrap()["job_id"].as_str().unwrap().to_string();
        let mut done = Value::Null;
        for _ in 0..60 {
            done = ping_result(&state, &job).unwrap();
            if done["done"] == true {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(done["done"], true);
        assert_eq!(done["results"].as_array().unwrap().len(), DIAG_PING_COUNT);
        assert!(done["results"].as_array().unwrap().iter().all(|r| r.is_number()));
        assert_eq!(ping_result(&state, "nope").unwrap_err().code, "not_found");
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
