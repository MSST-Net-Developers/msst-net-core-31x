//! Room mode: create / join / leave (3.0.x `api.rs` room handlers).
//!
//! Joining sends `join` (+ `discovery_join`) over the coordinator WS and
//! waits up to 2 s for the room's `room_state` (or a coordinator `error`,
//! e.g. wrong password) so the reply can carry the room name and peers.
//! A timeout is not an error — the room state arrives as an event later.
//! Joined rooms are re-joined on every coordinator reconnect and kept
//! alive by `room_keepalive` (see `coordinator`).

use crate::coordinator::CoordinatorClient;
use crate::state::CoreState;
use msst_ipc_protocol::IpcError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{info, warn};

/// How long a join waits for the room's first `room_state`.
const ROOM_STATE_WAIT: Duration = Duration::from_secs(2);

/// Waiter for the next `room_state` / coordinator `error`.
pub type RoomWaiter = std::sync::Mutex<Option<oneshot::Sender<Result<Value, String>>>>;

fn err(code: &str, message: impl Into<String>) -> IpcError {
    IpcError { code: code.into(), message: message.into() }
}

/// Room passwords travel as hex SHA-256 (3.0.x).
pub fn password_hash(password: &str) -> String {
    Sha256::digest(password.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect()
}

fn client(state: &CoreState) -> Result<Arc<CoordinatorClient>, IpcError> {
    state.coordinator.get().cloned().ok_or_else(|| err("coordinator_unavailable", "coordinator client not started"))
}

/// Complete the pending join (called by the runtime on `room_state`/`error`).
pub fn notify_room_waiter(state: &CoreState, result: Result<Value, String>) {
    if let Some(tx) = state.room_waiter.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = tx.send(result);
    }
}

/// Send `join` and wait briefly for the room state.  Returns the room name
/// (empty if the room state didn't arrive in time).
async fn join_and_wait(state: &CoreState, client: &CoordinatorClient, room_id: &str, password: Option<&str>) -> Result<String, IpcError> {
    let (tx, rx) = oneshot::channel();
    *state.room_waiter.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    client
        .send_join(room_id, password.map(password_hash).as_deref())
        .await
        .map_err(|e| err("coordinator_unavailable", e.to_string()))?;
    match tokio::time::timeout(ROOM_STATE_WAIT, rx).await {
        Ok(Ok(Ok(v))) => Ok(v["room_name"].as_str().unwrap_or("").to_string()),
        Ok(Ok(Err(e))) => Err(err("room_rejected", e)),
        _ => {
            warn!("rooms: timed out waiting for room_state of {}", room_id);
            Ok(String::new())
        }
    }
}

/// Bookkeeping after a successful join.
async fn joined(state: &Arc<CoreState>, client: &CoordinatorClient, room_id: &str, room_name: &str) -> Value {
    state.net.write().await.joined_rooms.insert(room_id.to_string(), room_name.to_string());
    if let Err(e) = client.send_discovery_join(room_id).await {
        warn!("rooms: discovery_join for {} failed: {}", room_id, e);
    }
    crate::endpoints::spawn_detect_and_report(state.clone());
    state.next_generation();
    room_view(state).await
}

pub async fn create_room(state: &Arc<CoreState>, room_name: String, password: Option<String>) -> Result<Value, IpcError> {
    let client = client(state)?;
    // 3.0.x re-selects the relay before creating a room.
    crate::runtime::select_relay_now(state, &client).await.map_err(|e| err("relay_unavailable", e))?;

    let mut body = json!({ "room_name": room_name });
    if let Some(pw) = &password {
        body["password_hash"] = json!(password_hash(pw));
    }
    let (status, resp) = client
        .api_request(reqwest::Method::POST, "/room/create", Some(&body), None)
        .await
        .map_err(|e| err("coordinator_unavailable", e))?;
    if !(200..300).contains(&status) {
        return Err(err("room_create_failed", format!("coordinator returned {}: {}", status, resp)));
    }
    let room_id = resp["room_id"]
        .as_str()
        .ok_or_else(|| err("room_create_failed", "missing room_id in coordinator response"))?
        .to_string();
    info!("rooms: created {} ({})", room_id, room_name);

    // The creator joins without the password (as 3.0.x).
    join_and_wait(state, &client, &room_id, None).await?;
    Ok(joined(state, &client, &room_id, &room_name).await)
}

pub async fn join_room(state: &Arc<CoreState>, room_id: String, password: Option<String>) -> Result<Value, IpcError> {
    let client = client(state)?;
    if state.net.read().await.relay_addr.is_none() {
        crate::runtime::select_relay_now(state, &client).await.map_err(|e| err("relay_unavailable", e))?;
    }
    let room_name = join_and_wait(state, &client, &room_id, password.as_deref()).await?;
    info!("rooms: joined {}", room_id);
    Ok(joined(state, &client, &room_id, &room_name).await)
}

pub async fn leave_room(state: &Arc<CoreState>, room_id: String) -> Result<Value, IpcError> {
    let client = client(state)?;
    client.send_leave(&room_id).await.map_err(|e| err("coordinator_unavailable", e.to_string()))?;
    if let Err(e) = client.send_discovery_leave(&room_id).await {
        warn!("rooms: discovery_leave for {} failed: {}", room_id, e);
    }
    {
        let mut net = state.net.write().await;
        net.joined_rooms.remove(&room_id);
        if net.joined_rooms.is_empty() {
            net.room_peers.clear();
        }
    }
    if state.net.read().await.joined_rooms.is_empty() {
        crate::peer_cache::on_rooms_left(state).await;
    }
    info!("rooms: left {}", room_id);
    emit_room_state(state).await;
    Ok(json!({ "ok": true }))
}

/// Emit `RoomStateChanged` with the same content as `GetSystemState`'s room
/// view (room left → `room_id: null`, no peers but ourselves).
pub async fn emit_room_state(state: &CoreState) {
    let v = room_view(state).await;
    state.next_generation();
    state.emit_ipc_event(msst_ipc_protocol::IpcEvent::RoomStateChanged {
        room_id: v["room_id"].as_str().map(str::to_string),
        room_name: v["room_name"].as_str().map(str::to_string),
        peers: v["peers"].as_array().cloned().unwrap_or_default(),
        relay: v["relay"].as_str().map(str::to_string),
    });
}

/// Current room, relay and visible peers (3.0.x `GET /room/state`).
///
/// In a room only co-members are listed — even before the first room_state
/// arrives — so locally cached nodes aren't exposed as room members.  Our
/// own device is always included.
pub async fn room_view(state: &CoreState) -> Value {
    let net = state.net.read().await;
    let (room_id, room_name) = net
        .joined_rooms
        .iter()
        .next()
        .map(|(id, name)| (Some(id.clone()), Some(name.clone())))
        .unwrap_or((None, None));
    let in_room = !net.joined_rooms.is_empty();
    let mut peers: Vec<Value> = net
        .peer_list
        .device_ids()
        .filter(|id| !in_room || net.room_peers.contains(*id))
        .filter_map(|id| net.peer_list.get(id))
        .map(|e| json!({
            "device_id": e.device_id,
            "ipv4": e.ipv4.to_string(),
            "ipv6": e.ipv6.to_string(),
            "hostname": e.hostname,
            "display_name": e.display_name,
        }))
        .collect();
    let relay = net.relay_addr.clone();
    let local_id = net.local_device_id.clone();
    drop(net);
    if let Some(id) = state.identity.read().await.as_ref() {
        if !peers.iter().any(|p| p["device_id"] == local_id) {
            let (ipv4, ipv6) = id.virtual_ips_canonical();
            peers.push(json!({
                "device_id": id.device.id,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "hostname": Some(&id.device.hostname).filter(|s| !s.is_empty()),
                "display_name": Some(&id.device.display_name).filter(|s| !s.is_empty()),
            }));
        }
    }
    json!({ "room_id": room_id, "room_name": room_name, "relay": relay, "peers": peers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_is_hex_sha256() {
        assert_eq!(password_hash("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    use crate::test_support::{core_state, echo_relay, eventually, FakeCoordinator};

    #[tokio::test]
    async fn create_join_leave_against_fake_coordinator() {
        let relay = echo_relay().await;
        let relays = json!({ "relays": [{ "addr": relay.to_string() }] });
        let coord = FakeCoordinator::start(
            move |req| match req.path.as_str() {
                "/relays" => (200, relays.clone()),
                "/room/create" => (200, json!({ "room_id": "space-1" })),
                _ => (404, json!({})),
            },
            |msg| match (msg["type"].as_str(), msg["data"]["room_id"].as_str()) {
                (Some("join"), Some("space-1")) => vec![json!({ "type": "room_state", "data": {
                    "room_id": "space-1", "room_name": "Test",
                    "peers": [{ "device_id": "device-0000000b", "public_key": "", "ipv4": "172.22.1.1",
                                "ipv6": "fd22:2222:2222:2222::b", "hostname": "pc.bob.ezplay.msst.net",
                                "endpoints": [], "is_authenticated": false }] } })],
                (Some("join"), Some("space-2")) => vec![json!({ "type": "error", "data": { "message": "wrong password" } })],
                _ => vec![],
            },
        ).await;

        let (state, _ipc) = core_state("rooms").await;
        let mut rt = crate::runtime::CoreRuntime::new(state.clone());
        rt.start_coordinator(crate::coordinator::CoordinatorConfig { coord_url: coord.url.clone() }, None);
        assert!(eventually(|| coord.ws_types().contains(&"register".to_string())).await);

        // Create: relay selected, room created over HTTP, joined over WS.
        let out = create_room(&state, "Test".into(), Some("pw".into())).await.unwrap();
        assert_eq!(out["room_id"], "space-1");
        assert_eq!(out["room_name"], "Test");
        assert_eq!(out["relay"], relay.to_string());
        let peers: Vec<&str> = out["peers"].as_array().unwrap().iter().map(|p| p["device_id"].as_str().unwrap()).collect();
        assert!(peers.contains(&"device-0000000b") && peers.contains(&"device-00000001"));
        let create = coord.http_log.lock().unwrap().iter().find(|r| r.path == "/room/create").cloned().unwrap();
        assert_eq!(create.body["password_hash"], password_hash("pw"));
        assert!(eventually(|| coord.ws_types().contains(&"discovery_join".to_string())).await);
        assert!(state.net.read().await.joined_rooms.contains_key("space-1"));

        // Join rejected by the coordinator.
        let e = join_room(&state, "space-2".into(), Some("bad".into())).await.unwrap_err();
        assert_eq!(e.code, "room_rejected");
        assert!(!state.net.read().await.joined_rooms.contains_key("space-2"));
        let join = coord.ws_log.lock().unwrap().iter().rev().find(|m| m["type"] == "join").cloned().unwrap();
        assert_eq!(join["data"]["password_hash"], password_hash("bad"));

        // Leave.
        leave_room(&state, "space-1".into()).await.unwrap();
        assert!(eventually(|| coord.ws_types().ends_with(&["leave".to_string(), "discovery_leave".to_string()])).await);
        let net = state.net.read().await;
        assert!(net.joined_rooms.is_empty() && net.room_peers.is_empty());
        drop(net);
        rt.shutdown().await;
    }
}
