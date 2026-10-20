//! Room mode: create / join / leave (3.0.x `api.rs` room handlers).
//!
//! A device is in at most one room: create / join while in one fails with
//! `already_in_room` (the Coordinator enforces it too).  Room operations
//! are serialized.
//!
//! Room passwords never leave Core: they travel as Argon2id verifiers
//! (`crate::passwords`, `docs/ROOM_RELAY_3.1.md`).  The creator picks a
//! random salt; a joiner fetches it (`GET /room/{id}/password-salt`) and
//! sends the verifier with `join`.
//!
//! Joining sends `join` (+ `discovery_join`) over the coordinator WS and
//! waits up to 2 s for the room's `room_state` (or a coordinator `error`,
//! e.g. wrong password) so the reply can carry the room name and peers.
//! A timeout is not an error — the room state arrives as an event later.
//! Joined rooms are re-joined on every coordinator reconnect, with the
//! room's password verifier (kept in memory), and kept alive by
//! `room_keepalive` (see `coordinator`).

use crate::coordinator::CoordinatorClient;
use crate::passwords;
use crate::state::CoreState;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use msst_ipc_protocol::{errors, IpcError};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{info, warn};

/// How long a join waits for the room's first `room_state`.
const ROOM_STATE_WAIT: Duration = Duration::from_secs(2);

/// A coordinator `error` answering a join.
#[derive(Debug)]
pub struct JoinRefused {
    pub code: Option<String>,
    pub message: String,
}

/// Waiter for the next `room_state` / coordinator `error`.
pub type RoomWaiter = std::sync::Mutex<Option<oneshot::Sender<Result<Value, JoinRefused>>>>;

fn err(code: &str, message: impl Into<String>) -> IpcError {
    IpcError { code: code.into(), message: message.into() }
}

fn client(state: &CoreState) -> Result<Arc<CoordinatorClient>, IpcError> {
    state.coordinator.get().cloned().ok_or_else(|| err(errors::COORDINATOR_UNAVAILABLE, "coordinator client not started"))
}

/// Room IDs as the Coordinator issues them (also safe in a URL path).
fn valid_room_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Fail with `already_in_room` while in a room.
async fn ensure_not_in_room(state: &CoreState) -> Result<(), IpcError> {
    match state.net.read().await.joined_rooms.keys().next() {
        Some(id) => Err(err(errors::ALREADY_IN_ROOM, format!("already in room {}; leave it first", id))),
        None => Ok(()),
    }
}

/// Complete the pending join (called by the runtime on `room_state`/`error`).
pub fn notify_room_waiter(state: &CoreState, result: Result<Value, JoinRefused>) {
    if let Some(tx) = state.room_waiter.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = tx.send(result);
    }
}

/// Send `join` and wait briefly for the room state.  Returns the room name
/// (empty if the room state didn't arrive in time).
async fn join_and_wait(state: &CoreState, client: &CoordinatorClient, room_id: &str, verifier: Option<&str>) -> Result<String, IpcError> {
    let (tx, rx) = oneshot::channel();
    *state.room_waiter.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    client.send_join(room_id, verifier).await.map_err(|e| err(errors::COORDINATOR_UNAVAILABLE, e.to_string()))?;
    crate::ipc::ops::progress("join_sent");
    match tokio::time::timeout(ROOM_STATE_WAIT, rx).await {
        Ok(Ok(Ok(v))) => Ok(v["room_name"].as_str().unwrap_or("").to_string()),
        Ok(Ok(Err(e))) => {
            let code = match e.code.as_deref() {
                Some(errors::ALREADY_IN_ROOM) => errors::ALREADY_IN_ROOM,
                _ => errors::ROOM_REJECTED,
            };
            Err(err(code, e.message))
        }
        _ => {
            warn!("rooms: timed out waiting for room_state of {}", room_id);
            Ok(String::new())
        }
    }
}

/// A room's password salt: `None` when it has no password.
async fn room_password_salt(client: &CoordinatorClient, room_id: &str) -> Result<Option<Vec<u8>>, IpcError> {
    let path = format!("/room/{}/password-salt", room_id);
    let (status, resp) = client
        .api_request(reqwest::Method::GET, &path, None, client.bearer().as_deref())
        .await
        .map_err(|e| err(errors::COORDINATOR_UNAVAILABLE, e))?;
    match status {
        200..=299 => {}
        404 => return Err(err(errors::ROOM_REJECTED, format!("room {} not found", room_id))),
        _ => return Err(err(errors::COORDINATOR_ERROR, format!("{} returned {}: {}", path, status, resp))),
    }
    match &resp["salt"] {
        Value::Null => Ok(None),
        v => v
            .as_str()
            .and_then(|s| STANDARD.decode(s).ok())
            .filter(|salt| (8..=64).contains(&salt.len()))
            .map(Some)
            .ok_or_else(|| err(errors::COORDINATOR_ERROR, format!("{} returned a malformed salt", path))),
    }
}

/// Bookkeeping after a successful join.
async fn joined(state: &Arc<CoreState>, client: &CoordinatorClient, room_id: &str, room_name: &str, verifier: Option<String>) -> Value {
    {
        let mut net = state.net.write().await;
        net.joined_rooms.insert(room_id.to_string(), room_name.to_string());
        match verifier {
            Some(v) => net.room_password_verifiers.insert(room_id.to_string(), v),
            None => net.room_password_verifiers.remove(room_id),
        };
    }
    if let Err(e) = client.send_discovery_join(room_id).await {
        warn!("rooms: discovery_join for {} failed: {}", room_id, e);
    }
    crate::endpoints::spawn_detect_and_report(state.clone());
    state.next_generation();
    room_view(state).await
}

pub async fn create_room(state: &Arc<CoreState>, room_name: String, password: Option<String>) -> Result<Value, IpcError> {
    let _op = state.room_op.lock().await;
    ensure_not_in_room(state).await?;
    let client = client(state)?;
    // 3.0.x re-selects the relay before creating a room.
    crate::runtime::select_relay_now(state, &client).await.map_err(|e| err(errors::RELAY_UNAVAILABLE, e))?;
    crate::ipc::ops::progress("relay_selected");

    let mut body = json!({ "room_name": room_name });
    let mut verifier = None;
    if let Some(pw) = password {
        let salt: [u8; passwords::ROOM_SALT_LEN] = rand::random();
        let v = STANDARD.encode(passwords::verifier_blocking(passwords::ROOM_DOMAIN, pw, salt.to_vec()).await);
        body["password"] = json!({ "salt": STANDARD.encode(salt), "verifier": v });
        verifier = Some(v);
    }
    let (status, resp) = client
        .api_request(reqwest::Method::POST, "/room/create", Some(&body), client.bearer().as_deref())
        .await
        .map_err(|e| err(errors::COORDINATOR_UNAVAILABLE, e))?;
    if !(200..300).contains(&status) {
        return Err(err(errors::ROOM_CREATE_FAILED, format!("coordinator returned {}: {}", status, resp)));
    }
    let room_id = resp["room_id"]
        .as_str()
        .ok_or_else(|| err(errors::ROOM_CREATE_FAILED, "missing room_id in coordinator response"))?
        .to_string();
    info!("rooms: created {} ({})", room_id, room_name);
    crate::ipc::ops::progress("room_created");

    // The creator joins with the password too: the coordinator checks it
    // on every join.
    join_and_wait(state, &client, &room_id, verifier.as_deref()).await?;
    Ok(joined(state, &client, &room_id, &room_name, verifier).await)
}

pub async fn join_room(state: &Arc<CoreState>, room_id: String, password: Option<String>) -> Result<Value, IpcError> {
    let _op = state.room_op.lock().await;
    ensure_not_in_room(state).await?;
    if !valid_room_id(&room_id) {
        return Err(err(errors::ROOM_REJECTED, format!("invalid room ID {:?}", room_id)));
    }
    let client = client(state)?;
    // A password given for a room without one is ignored (as the
    // Coordinator does).
    let verifier = match room_password_salt(&client, &room_id).await? {
        None => None,
        Some(salt) => {
            let pw = password.ok_or_else(|| err(errors::ROOM_PASSWORD_REQUIRED, format!("room {} has a password", room_id)))?;
            Some(STANDARD.encode(passwords::verifier_blocking(passwords::ROOM_DOMAIN, pw, salt).await))
        }
    };
    if state.net.read().await.relay_addr.is_none() {
        crate::runtime::select_relay_now(state, &client).await.map_err(|e| err(errors::RELAY_UNAVAILABLE, e))?;
        crate::ipc::ops::progress("relay_selected");
    }
    let room_name = join_and_wait(state, &client, &room_id, verifier.as_deref()).await?;
    info!("rooms: joined {}", room_id);
    Ok(joined(state, &client, &room_id, &room_name, verifier).await)
}

pub async fn leave_room(state: &Arc<CoreState>, room_id: String) -> Result<Value, IpcError> {
    let _op = state.room_op.lock().await;
    let client = client(state)?;
    client.send_leave(&room_id).await.map_err(|e| err("coordinator_unavailable", e.to_string()))?;
    if let Err(e) = client.send_discovery_leave(&room_id).await {
        warn!("rooms: discovery_leave for {} failed: {}", room_id, e);
    }
    {
        let mut net = state.net.write().await;
        net.joined_rooms.remove(&room_id);
        net.room_password_verifiers.remove(&room_id);
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
    use crate::test_support::{core_state, echo_relay, eventually, FakeCoordinator};

    const SALT2: [u8; 16] = [7; 16];

    fn b64v(pw: &str, salt: &[u8]) -> String {
        STANDARD.encode(passwords::verifier(passwords::ROOM_DOMAIN, pw, salt))
    }

    #[test]
    fn room_ids() {
        assert!(valid_room_id("space-0a1b2c3d") && valid_room_id("a_B-9"));
        for bad in ["", "a/b", "../x", "a b", "?x", &"a".repeat(65)] {
            assert!(!valid_room_id(bad), "{:?}", bad);
        }
    }

    #[tokio::test]
    async fn create_join_leave_against_fake_coordinator() {
        let relay = echo_relay().await;
        let relays = json!({ "relays": [{ "addr": relay.to_string() }] });
        let coord = FakeCoordinator::start(
            move |req| match req.path.as_str() {
                "/relays" => (200, relays.clone()),
                "/room/create" => (200, json!({ "room_id": "space-1" })),
                "/room/space-2/password-salt" => (200, json!({ "salt": STANDARD.encode(SALT2) })),
                "/room/space-4/password-salt" | "/room/space-5/password-salt" => (200, json!({ "salt": null })),
                _ => (404, json!({})),
            },
            |msg| match (msg["type"].as_str(), msg["data"]["room_id"].as_str()) {
                (Some("join"), Some("space-1")) => vec![json!({ "type": "room_state", "data": {
                    "room_id": "space-1", "room_name": "Test",
                    "peers": [{ "device_id": "device-0000000b", "public_key": "", "ipv4": "172.22.1.1",
                                "ipv6": "fd22:2222:2222:2222::b", "hostname": "pc.bob.ezplay.msst.net",
                                "endpoints": [], "is_authenticated": false }] } })],
                (Some("join"), Some("space-2")) => vec![json!({ "type": "error", "data": { "message": "wrong password" } })],
                (Some("join"), Some("space-4")) => vec![json!({ "type": "room_state", "data": { "room_id": "space-4", "room_name": "Open", "peers": [] } })],
                (Some("join"), Some("space-5")) => vec![json!({ "type": "error", "data": { "message": "already in a room", "code": "already_in_room" } })],
                _ => vec![],
            },
        ).await;
        let joins = || coord.ws_log.lock().unwrap().iter().filter(|m| m["type"] == "join").cloned().collect::<Vec<_>>();

        let (state, _ipc) = core_state("rooms").await;
        let mut rt = crate::runtime::CoreRuntime::new(state.clone());
        rt.start_coordinator(crate::coordinator::CoordinatorConfig { coord_url: coord.url.clone() }, None);
        assert!(eventually(|| coord.ws_types().contains(&"register".to_string())).await);

        // Create: relay selected, room created over HTTP with a salted
        // verifier (never the password), joined over WS with the verifier.
        let out = create_room(&state, "Test".into(), Some("pw".into())).await.unwrap();
        assert_eq!(out["room_id"], "space-1");
        assert_eq!(out["room_name"], "Test");
        assert_eq!(out["relay"], relay.to_string());
        let peers: Vec<&str> = out["peers"].as_array().unwrap().iter().map(|p| p["device_id"].as_str().unwrap()).collect();
        assert!(peers.contains(&"device-0000000b") && peers.contains(&"device-00000001"));
        let create = coord.http_log.lock().unwrap().iter().find(|r| r.path == "/room/create").cloned().unwrap();
        assert!(create.body.get("password_hash").is_none() && !create.body.to_string().contains("\"pw\""));
        let salt = STANDARD.decode(create.body["password"]["salt"].as_str().unwrap()).unwrap();
        assert_eq!(salt.len(), passwords::ROOM_SALT_LEN);
        let verifier = b64v("pw", &salt);
        assert_eq!(create.body["password"]["verifier"], verifier);
        assert_eq!(joins()[0]["data"]["password_verifier"], verifier);
        assert!(eventually(|| coord.ws_types().contains(&"discovery_join".to_string())).await);
        {
            // Kept for re-joins after a reconnect.
            let net = state.net.read().await;
            assert!(net.joined_rooms.contains_key("space-1"));
            assert_eq!(net.room_password_verifiers.get("space-1"), Some(&verifier));
        }

        // One room at a time: refused before anything is sent.
        let e = join_room(&state, "space-4".into(), None).await.unwrap_err();
        assert_eq!(e.code, errors::ALREADY_IN_ROOM);
        assert_eq!(create_room(&state, "Other".into(), None).await.unwrap_err().code, errors::ALREADY_IN_ROOM);
        assert_eq!(joins().len(), 1);
        assert_eq!(coord.http_log.lock().unwrap().iter().filter(|r| r.path == "/room/create").count(), 1);

        // Leave.
        leave_room(&state, "space-1".into()).await.unwrap();
        assert!(eventually(|| coord.ws_types().ends_with(&["leave".to_string(), "discovery_leave".to_string()])).await);
        {
            let net = state.net.read().await;
            assert!(net.joined_rooms.is_empty() && net.room_peers.is_empty() && net.room_password_verifiers.is_empty());
        }

        // Password room: no password → refused locally; wrong password →
        // the verifier for the room's salt, refused by the coordinator.
        let e = join_room(&state, "space-2".into(), None).await.unwrap_err();
        assert_eq!(e.code, errors::ROOM_PASSWORD_REQUIRED);
        assert_eq!(joins().len(), 1);
        let e = join_room(&state, "space-2".into(), Some("bad".into())).await.unwrap_err();
        assert_eq!(e.code, errors::ROOM_REJECTED);
        assert_eq!(joins().last().unwrap()["data"]["password_verifier"], b64v("bad", &SALT2));
        assert!(state.net.read().await.joined_rooms.is_empty());

        // Unknown room, malformed ID: refused without a join.
        assert_eq!(join_room(&state, "space-9".into(), None).await.unwrap_err().code, errors::ROOM_REJECTED);
        assert_eq!(join_room(&state, "a/b".into(), None).await.unwrap_err().code, errors::ROOM_REJECTED);
        assert_eq!(joins().len(), 2);

        // The coordinator's own one-room check maps to already_in_room.
        assert_eq!(join_room(&state, "space-5".into(), None).await.unwrap_err().code, errors::ALREADY_IN_ROOM);

        // Room without a password: a given password is ignored.
        let out = join_room(&state, "space-4".into(), Some("unused".into())).await.unwrap();
        assert_eq!(out["room_name"], "Open");
        assert!(joins().last().unwrap()["data"].get("password_verifier").is_none());
        assert!(state.net.read().await.room_password_verifiers.is_empty());
        rt.shutdown().await;
    }
}
