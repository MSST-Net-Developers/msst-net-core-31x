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
//! Joining sends `join` over the coordinator WS and
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
/// Returns whether a join was waiting.
pub fn notify_room_waiter(state: &CoreState, result: Result<Value, JoinRefused>) -> bool {
    match state.room_waiter.lock().unwrap_or_else(|e| e.into_inner()).take() {
        Some(tx) => {
            let _ = tx.send(result);
            true
        }
        None => false,
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
async fn joined(state: &Arc<CoreState>, room_id: &str, room_name: &str, verifier: Option<String>) -> Value {
    {
        let mut net = state.net.write().await;
        net.joined_rooms.insert(room_id.to_string(), room_name.to_string());
        match verifier {
            Some(v) => net.room_password_verifiers.insert(room_id.to_string(), v),
            None => net.room_password_verifiers.remove(room_id),
        };
    }
    crate::endpoints::spawn_detect_and_report(state.clone());
    state.next_generation();
    room_view(state).await
}

/// `CreateRoom.relay` (a connection string, or an official relay's
/// address) → the `relay` object of `POST /room/create`.  The relay is
/// named by its key; a password becomes an Argon2id verifier.
async fn room_relay_request(client: &CoordinatorClient, relay: &str, password: Option<String>) -> Result<Value, IpcError> {
    let (pub_key, has_password) = if crate::room_relay::is_link(relay) {
        let link = crate::room_relay::parse_link(relay).map_err(|e| err(errors::INVALID_RELAY, e))?;
        (link.pub_key, link.password)
    } else {
        let relay = relay.trim();
        let addrs: Vec<std::net::SocketAddr> = match relay.parse::<std::net::SocketAddr>() {
            Ok(a) => vec![a],
            Err(_) => tokio::net::lookup_host(relay).await.map(|it| it.collect()).unwrap_or_default(),
        };
        let addrs: Vec<_> = addrs.into_iter().map(msst_core_state::net::relay::unmap_addr).collect();
        let known = crate::relay::fetch_known_relays(client.http(), client.coord_url())
            .await
            .map_err(|e| err(errors::COORDINATOR_UNAVAILABLE, e.to_string()))?;
        let official = known
            .iter()
            .find(|k| k.addrs.iter().any(|a| addrs.contains(a)))
            .ok_or_else(|| err(errors::INVALID_RELAY, format!("{:?} is not an official relay; use the relay's msst-relay:// link", relay)))?;
        (official.pub_key, false)
    };
    let mut body = json!({ "pub_key": STANDARD.encode(pub_key) });
    match password {
        Some(pw) => {
            let v = passwords::verifier_blocking(passwords::RELAY_DOMAIN, pw, pub_key.to_vec()).await;
            body["password_verifier"] = json!(STANDARD.encode(v));
        }
        None if has_password => return Err(err(errors::RELAY_PASSWORD_REQUIRED, "the relay has a password")),
        None => {}
    }
    Ok(body)
}

/// The IPC error for a refused `POST /room/create`.
fn room_create_error(status: u16, resp: &Value) -> IpcError {
    const PASSED_ON: &[&str] = &[
        errors::INVALID_RELAY,
        errors::RELAY_OFFLINE,
        errors::RELAY_UNSUPPORTED,
        errors::RELAY_PASSWORD_REQUIRED,
        errors::RELAY_PASSWORD_WRONG,
        errors::ROOM_PASSWORD_REQUIRED,
    ];
    let code = resp["code"].as_str().and_then(|c| PASSED_ON.iter().find(|k| **k == c)).copied().unwrap_or(errors::ROOM_CREATE_FAILED);
    err(code, format!("coordinator returned {}: {}", status, resp))
}

pub async fn create_room(
    state: &Arc<CoreState>,
    room_name: String,
    password: Option<String>,
    relay: Option<String>,
    relay_password: Option<String>,
) -> Result<Value, IpcError> {
    let _op = state.room_op.lock().await;
    ensure_not_in_room(state).await?;
    let client = client(state)?;
    let room_relay = match relay.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        Some(r) => Some(room_relay_request(&client, r, relay_password).await?),
        None => None,
    };
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
    if let Some(r) = room_relay {
        body["relay"] = r;
    }
    let (status, resp) = client
        .api_request(reqwest::Method::POST, "/room/create", Some(&body), client.bearer().as_deref())
        .await
        .map_err(|e| err(errors::COORDINATOR_UNAVAILABLE, e))?;
    if !(200..300).contains(&status) {
        return Err(room_create_error(status, &resp));
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
    Ok(joined(state, &room_id, &room_name, verifier).await)
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
    Ok(joined(state, &room_id, &room_name, verifier).await)
}

pub async fn leave_room(state: &Arc<CoreState>, room_id: String) -> Result<Value, IpcError> {
    let _op = state.room_op.lock().await;
    let client = client(state)?;
    client.send_leave(&room_id).await.map_err(|e| err("coordinator_unavailable", e.to_string()))?;
    forget_room(state, &room_id).await;
    info!("rooms: left {}", room_id);
    Ok(json!({ "ok": true }))
}

/// Drop a room from local state (we left it, or the coordinator no longer
/// has it) and report the new room state.  Returns whether we were in it.
async fn forget_room(state: &Arc<CoreState>, room_id: &str) -> bool {
    let (was_in, had_room_relay, none_left) = {
        let mut net = state.net.write().await;
        let was_in = net.joined_rooms.remove(room_id).is_some();
        net.room_password_verifiers.remove(room_id);
        if net.joined_rooms.is_empty() {
            net.room_peers.clear();
        }
        let had_room_relay = net.room_relay.take_if(|r| r.room_id == room_id).is_some();
        (was_in, had_room_relay, net.joined_rooms.is_empty())
    };
    if had_room_relay {
        // Stop announcing `room-relay:`.
        crate::endpoints::spawn_detect_and_report(state.clone());
    }
    if none_left {
        crate::peer_cache::on_rooms_left(state).await;
    }
    crate::inbound::revoke_room_flows(state).await;
    emit_room_state(state).await;
    was_in
}

/// The coordinator answered `room not found` outside a join: a room we are
/// in has expired there (e.g. no member kept it alive while this device
/// was asleep), so our `room_keepalive` or re-join after a reconnect was
/// refused.  The error names no room; a device is in one room at a time,
/// so every joined room is dropped.  Returns the rooms dropped.
pub async fn on_rooms_gone(state: &Arc<CoreState>) -> Vec<String> {
    let rooms: Vec<String> = state.net.read().await.joined_rooms.keys().cloned().collect();
    let mut gone = Vec::new();
    for room_id in rooms {
        if forget_room(state, &room_id).await {
            warn!("rooms: {} no longer exists on the coordinator (expired); left it", room_id);
            gone.push(room_id);
        }
    }
    gone
}

/// The coordinator's message for a room it doesn't have (`hub.go`; it
/// sends no code).
pub const ROOM_NOT_FOUND_MESSAGE: &str = "room not found";

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
        room_relay: Some(v["room_relay"].clone()).filter(|r| !r.is_null()),
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
            // Game discovery with this member: "ok", "unsupported" (an
            // older Core: no discovery either way) or "unknown"; null for
            // ourselves.
            "discovery": (e.device_id != net.local_device_id).then(|| net.discovery_support(&e.device_id).name()),
        }))
        .collect();
    let relay = net.relay_addr.clone();
    let room_relay = net.room_relay.as_ref().filter(|_| in_room).map(|r| r.view());
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
                // Peers see the default name the Coordinator was given.
                "display_name": if id.device.display_name.is_empty() {
                    crate::identity::default_device_display_name(&id.user.id)
                } else {
                    id.device.display_name.clone()
                },
            }));
        }
    }
    json!({ "room_id": room_id, "room_name": room_name, "relay": relay, "room_relay": room_relay, "peers": peers })
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
                                "ipv6": "fd22:2222:2222:2222::b", "hostname": "pc.bob.ezplay.net.msst2031.cn",
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
        let out = create_room(&state, "Test".into(), Some("pw".into()), None, None).await.unwrap();
        assert_eq!(out["room_id"], "space-1");
        assert_eq!(out["room_name"], "Test");
        assert_eq!(out["relay"], relay.to_string());
        let peers: Vec<&str> = out["peers"].as_array().unwrap().iter().map(|p| p["device_id"].as_str().unwrap()).collect();
        assert!(peers.contains(&"device-0000000b") && peers.contains(&"device-00000001"));
        // No device name set: we see the default name peers see.
        let me = out["peers"].as_array().unwrap().iter().find(|p| p["device_id"] == "device-00000001").unwrap();
        let user_id = state.identity.read().await.as_ref().unwrap().user.id.clone();
        assert_eq!(me["display_name"], crate::identity::default_device_display_name(&user_id));
        let create = coord.http_log.lock().unwrap().iter().find(|r| r.path == "/room/create").cloned().unwrap();
        assert!(create.body.get("password_hash").is_none() && !create.body.to_string().contains("\"pw\""));
        let salt = STANDARD.decode(create.body["password"]["salt"].as_str().unwrap()).unwrap();
        assert_eq!(salt.len(), passwords::ROOM_SALT_LEN);
        let verifier = b64v("pw", &salt);
        assert_eq!(create.body["password"]["verifier"], verifier);
        assert_eq!(joins()[0]["data"]["password_verifier"], verifier);
        // No discovery_join any more: it registered for the retired sdisc.
        assert!(!coord.ws_types().iter().any(|t| t.starts_with("discovery_")));
        {
            // Kept for re-joins after a reconnect.
            let net = state.net.read().await;
            assert!(net.joined_rooms.contains_key("space-1"));
            assert_eq!(net.room_password_verifiers.get("space-1"), Some(&verifier));
        }

        // One room at a time: refused before anything is sent.
        let e = join_room(&state, "space-4".into(), None).await.unwrap_err();
        assert_eq!(e.code, errors::ALREADY_IN_ROOM);
        assert_eq!(create_room(&state, "Other".into(), None, None, None).await.unwrap_err().code, errors::ALREADY_IN_ROOM);
        assert_eq!(joins().len(), 1);
        assert_eq!(coord.http_log.lock().unwrap().iter().filter(|r| r.path == "/room/create").count(), 1);

        // Leave.
        leave_room(&state, "space-1".into()).await.unwrap();
        assert!(eventually(|| coord.ws_types().ends_with(&["leave".to_string()])).await);
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

    #[tokio::test]
    async fn create_room_with_a_room_relay() {
        let relay = echo_relay().await;
        let pk = *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([2u8; 32])).as_bytes();
        let relays = json!({ "relays": [{ "addr": relay.to_string(), "pub_key": STANDARD.encode(pk), "features": ["sdisc1", "sreg1"] }] });
        let good = STANDARD.encode(passwords::verifier(passwords::RELAY_DOMAIN, "relay secret", &pk));
        let coord = FakeCoordinator::start(
            move |req| match req.path.as_str() {
                "/relays" => (200, relays.clone()),
                "/room/create" => match req.body["relay"]["password_verifier"].as_str() {
                    Some(v) if v != good => (403, json!({ "error": "wrong relay password", "code": "relay_password_wrong" })),
                    _ if req.body["room_name"] == "offline" => (409, json!({ "error": "relay offline", "code": "relay_offline" })),
                    _ if req.body["room_name"] == "odd" => (400, json!({ "error": "?", "code": "something_new" })),
                    _ => (200, json!({ "room_id": "space-1" })),
                },
                _ => (404, json!({})),
            },
            |msg| match msg["type"].as_str() {
                Some("join") => vec![json!({ "type": "room_state", "data": { "room_id": "space-1", "room_name": "R", "peers": [] } })],
                _ => vec![],
            },
        ).await;
        let creates = || coord.http_log.lock().unwrap().iter().filter(|r| r.path == "/room/create").map(|r| r.body.clone()).collect::<Vec<_>>();
        let (state, _ipc) = core_state("rooms-relay").await;
        let mut rt = crate::runtime::CoreRuntime::new(state.clone());
        rt.start_coordinator(crate::coordinator::CoordinatorConfig { coord_url: coord.url.clone() }, None);
        assert!(eventually(|| coord.ws_types().contains(&"register".to_string())).await);
        let link = "msst-relay://relay.example.com:7000#zo060cy2M-x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk?pw=1";
        let create = |name: &str, relay: Option<&str>, pw: Option<&str>| {
            create_room(&state, name.into(), Some("room pw".into()), relay.map(str::to_string), pw.map(str::to_string))
        };

        // Refused locally, before anything is sent.
        assert_eq!(create("R", Some(link), None).await.unwrap_err().code, errors::RELAY_PASSWORD_REQUIRED);
        assert_eq!(create("R", Some("msst-relay://nope"), None).await.unwrap_err().code, errors::INVALID_RELAY);
        assert_eq!(create("R", Some("192.0.2.1:7000"), None).await.unwrap_err().code, errors::INVALID_RELAY, "not an official relay");
        assert!(creates().is_empty());

        // The coordinator's refusals keep their codes; unknown ones don't.
        assert_eq!(create("R", Some(link), Some("wrong")).await.unwrap_err().code, errors::RELAY_PASSWORD_WRONG);
        assert_eq!(create("offline", Some(link), Some("relay secret")).await.unwrap_err().code, errors::RELAY_OFFLINE);
        assert_eq!(create("odd", Some(link), Some("relay secret")).await.unwrap_err().code, errors::ROOM_CREATE_FAILED);

        // A connection string with its password: the key and a verifier.
        create("R", Some(link), Some("relay secret")).await.unwrap();
        let body = creates().last().cloned().unwrap();
        assert_eq!(body["relay"], json!({ "pub_key": STANDARD.encode(pk), "password_verifier": STANDARD.encode(passwords::verifier(passwords::RELAY_DOMAIN, "relay secret", &pk)) }));
        assert!(!body.to_string().contains("relay secret"));
        leave_room(&state, "space-1".into()).await.unwrap();

        // An official relay by address: its key from GET /relays, no password.
        create("R", Some(&relay.to_string()), None).await.unwrap();
        assert_eq!(creates().last().unwrap()["relay"], json!({ "pub_key": STANDARD.encode(pk) }));
        leave_room(&state, "space-1".into()).await.unwrap();

        // No relay: no `relay` field.
        create("R", None, None).await.unwrap();
        assert!(creates().last().unwrap().get("relay").is_none());
        rt.shutdown().await;
    }
}
