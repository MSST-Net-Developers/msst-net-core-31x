//! Account and identity operations: display names, handles, OIDC device
//! flow, token refresh and re-registration (3.0.x `api.rs` +
//! `coordinator::re_register`).
//!
//! When OIDC is active the coordinator is authoritative for user-level
//! fields (handle / display name come from the token claims), so local
//! edits to them are ignored — device-level fields can always be edited.
//!
//! Tokens never leave Core: responses to the Controller omit
//! `access_token` / `refresh_token`.

use crate::coordinator::CoordinatorClient;
use crate::identity::{self, AuthCredentials};
use crate::state::CoreState;
use msst_ipc_protocol::{IpcError, IpcEvent};
use reqwest::Method;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{info, warn};

fn err(code: &str, message: impl Into<String>) -> IpcError {
    IpcError { code: code.into(), message: message.into() }
}

fn client(state: &CoreState) -> Result<Arc<CoordinatorClient>, IpcError> {
    state.coordinator.get().cloned().ok_or_else(|| err("coordinator_unavailable", "coordinator client not started"))
}

/// Remove credentials from a coordinator response before it goes to the
/// Controller.
fn redact_tokens(mut v: Value) -> Value {
    if let Some(o) = v.as_object_mut() {
        o.remove("access_token");
        o.remove("refresh_token");
        o.remove("id_token");
    }
    v
}

/// Handle syntax (coordinator `validateHandle`: `^[a-z0-9-]+$`).
pub fn validate_handle(h: &str) -> Result<(), &'static str> {
    if h.is_empty() {
        return Err("handle cannot be empty");
    }
    if !h.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err("handle must contain only lowercase letters, digits, and hyphens");
    }
    Ok(())
}

/// Turn an OIDC username into a valid handle (3.0.x `sanitize_handle`,
/// mirrors the coordinator's `sanitizeHandle`).
pub fn sanitize_handle(s: &str) -> String {
    let mut out = String::new();
    for c in s.to_lowercase().chars() {
        match c {
            'a'..='z' | '0'..='9' => out.push(c),
            ' ' | '_' | '.' | '@' | '/' | '-' => out.push('-'),
            _ => {}
        }
    }
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    out.trim_matches('-').to_string()
}

/// Mutate the identity, persist it and keep NetState's copy of the IDs and
/// auth flag in sync.  The mutation is rolled back if saving fails.
async fn update_identity<R>(state: &CoreState, f: impl FnOnce(&mut identity::Identity) -> R) -> Result<R, IpcError> {
    let mut guard = state.identity.write().await;
    let id = guard.as_mut().ok_or_else(|| err("not_initialized", "identity not loaded"))?;
    let before = id.clone();
    let out = f(id);
    if let Err(e) = identity::save(&state.data_dir, id) {
        *id = before;
        return Err(err("persist_failed", format!("failed to save identity: {}", e)));
    }
    let (user_id, authenticated) = (id.user.id.clone(), id.auth.is_some());
    drop(guard);
    {
        let mut net = state.net.write().await;
        net.local_user_id = user_id;
        net.local_authenticated = authenticated;
    }
    if authenticated {
        state.access_auth_required.store(false, std::sync::atomic::Ordering::SeqCst);
    }
    state.next_generation();
    emit_identity_changed(state).await;
    Ok(out)
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// Tell Controllers about the current identity (`IdentityChanged`).
pub async fn emit_identity_changed(state: &CoreState) {
    let Some(ev) = state.identity.read().await.as_ref().map(|id| IpcEvent::IdentityChanged {
        device_id: id.device.id.clone(),
        user_id: id.user.id.clone(),
        device_handle: non_empty(&id.device.handle),
        user_handle: non_empty(&id.user.handle),
        device_display_name: non_empty(&id.device.display_name),
        user_display_name: non_empty(&id.user.display_name),
        device_hostname: non_empty(&id.device.hostname),
        is_authenticated: id.auth.is_some(),
    }) else {
        return;
    };
    state.emit_ipc_event(ev);
}

/// Longest display name accepted, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;

/// Normalize a display name from the Controller: surrounding whitespace is
/// dropped; empty means "unset" (the default is registered instead).
pub fn normalize_display_name(n: &str) -> Result<String, String> {
    let n = n.trim();
    if n.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(format!("display name is longer than {} characters", MAX_DISPLAY_NAME_CHARS));
    }
    if n.chars().any(char::is_control) {
        return Err("display name must not contain control characters".into());
    }
    Ok(n.to_string())
}

/// Normalize a handle from the Controller: empty (after trimming) means
/// "unset" (the device / user ID is registered instead).
pub fn normalize_handle(h: &str) -> Result<String, &'static str> {
    let h = h.trim();
    if !h.is_empty() {
        validate_handle(h)?;
    }
    Ok(h.to_string())
}

/// Push the identity to the coordinator now (`re_register`).  The change is
/// already saved locally; on failure it reaches the coordinator with the
/// next registration (WS reconnect).
async fn sync_identity(state: &Arc<CoreState>, what: &str) -> bool {
    match re_register(state).await {
        Ok(_) => true,
        Err(e) => {
            warn!("account: {} saved locally, coordinator not updated yet: {}", what, e.message);
            false
        }
    }
}

/// `UpdateDisplayName`.  `None` leaves a name unchanged; `""` clears it.
pub async fn update_display_name(state: &Arc<CoreState>, user: Option<String>, device: Option<String>) -> Result<Value, IpcError> {
    if user.is_none() && device.is_none() {
        return Err(err("invalid_request", "At least one name field must be provided"));
    }
    let norm = |n: Option<String>| n.map(|n| normalize_display_name(&n)).transpose().map_err(|e| err("invalid_display_name", e));
    let (user, device) = (norm(user)?, norm(device)?);
    let (u, d, changed) = update_identity(state, |id| {
        let before = (id.user.display_name.clone(), id.device.display_name.clone());
        if id.auth.is_none() {
            if let Some(n) = user {
                id.user.display_name = n;
            }
        }
        if let Some(n) = device {
            id.device.display_name = n;
        }
        let changed = before != (id.user.display_name.clone(), id.device.display_name.clone());
        (id.user.display_name.clone(), id.device.display_name.clone(), changed)
    })
    .await?;
    info!("account: display names — user '{}', device '{}'", u, d);
    let synced = !changed || sync_identity(state, "display name").await;
    Ok(json!({ "ok": true, "user_display_name": non_empty(&u), "device_display_name": non_empty(&d), "synced": synced }))
}

/// `UpdateHandle`.  `None` leaves a handle unchanged; `""` clears it.
pub async fn update_handle(state: &Arc<CoreState>, user: Option<String>, device: Option<String>) -> Result<Value, IpcError> {
    if user.is_none() && device.is_none() {
        return Err(err("invalid_request", "At least one of user_handle or device_handle must be provided"));
    }
    let norm = |name: &str, h: Option<String>| {
        h.map(|h| normalize_handle(&h)).transpose().map_err(|e| err("invalid_handle", format!("{}: {}", name, e)))
    };
    let (user, device) = (norm("user_handle", user)?, norm("device_handle", device)?);
    let (u, d, changed) = update_identity(state, |id| {
        let before = (id.user.handle.clone(), id.device.handle.clone());
        if id.auth.is_none() {
            if let Some(h) = user {
                id.user.handle = h;
            }
        }
        if let Some(h) = device {
            id.device.handle = h;
        }
        let changed = before != (id.user.handle.clone(), id.device.handle.clone());
        (id.user.handle.clone(), id.device.handle.clone(), changed)
    })
    .await?;
    info!("account: handles — user '{}', device '{}'", u, d);
    let synced = !changed || sync_identity(state, "handle").await;
    Ok(json!({ "ok": true, "user_handle": non_empty(&u), "device_handle": non_empty(&d), "synced": synced }))
}

/// `POST /device/register` with the current identity, then adopt the
/// coordinator's conflict-resolved hostname / IPv4.
pub async fn re_register(state: &Arc<CoreState>) -> Result<Value, IpcError> {
    let client = client(state)?;
    let (body, bearer) = {
        let guard = state.identity.read().await;
        let id = guard.as_ref().ok_or_else(|| err("not_initialized", "identity not loaded"))?;
        (
            crate::coordinator::build_register_message(id)["data"].clone(),
            id.auth.as_ref().map(|a| a.access_token.clone()).filter(|t| !t.is_empty()),
        )
    };
    let mut body = body;
    // Cloned so the identity lock isn't held across the HTTP round trip.
    let id = state.identity.read().await.clone().ok_or_else(|| err("not_initialized", "identity not loaded"))?;
    let proof = crate::coordinator::keyproof::obtain(&client, &id).await;
    match proof {
        Ok(p) => crate::coordinator::keyproof::attach(&mut body, p),
        Err(crate::coordinator::keyproof::ProofError::KeyMismatch) => {
            return Err(err(crate::coordinator::keyproof::CODE_KEY_MISMATCH, crate::coordinator::keyproof::mismatch_message(&id.device.id)));
        }
        Err(crate::coordinator::keyproof::ProofError::Other(e)) => warn!("account: no key proof ({}) — registering without one", e),
    }
    let (status, resp) = client
        .api_request(Method::POST, "/device/register", Some(&body), bearer.as_deref())
        .await
        .map_err(|e| err("coordinator_unavailable", e))?;
    if !(200..300).contains(&status) {
        return Err(err("register_failed", format!("coordinator returned {}: {}", status, resp)));
    }
    let hostname = resp["hostname"].as_str().unwrap_or("").to_string();
    let ipv4 = resp["ipv4"].as_str().unwrap_or("").to_string();
    if !hostname.is_empty() || !ipv4.is_empty() {
        update_identity(state, |id| {
            // User-level fields are not part of this response.
            let host = if hostname.is_empty() { id.device.hostname.clone() } else { hostname.clone() };
            crate::coordinator::apply_registered(id, &host, &ipv4, "", "")
        })
        .await?;
    }
    info!("account: device re-registered");
    Ok(json!({ "ok": true }))
}

/// Start the OIDC Device Authorization Grant (`POST /auth/device/start`).
/// The response (session id, verification URL, user code) goes to the
/// Controller, which shows it to the user.
pub async fn auth_start(state: &CoreState) -> Result<Value, IpcError> {
    let client = client(state)?;
    let (status, body) = client
        .api_request(Method::POST, "/auth/device/start", None, None)
        .await
        .map_err(|e| err("coordinator_unavailable", e))?;
    if !(200..300).contains(&status) {
        return Err(err("auth_failed", format!("coordinator returned {}: {}", status, body)));
    }
    Ok(body)
}

/// Poll the device flow (`GET /auth/device/poll`).  `pending: true` while
/// the user hasn't finished; on success the credentials and OIDC profile
/// are stored, the device re-registers, and `pending: false` is returned.
pub async fn auth_poll(state: &Arc<CoreState>, session_id: &str) -> Result<Value, IpcError> {
    let client = client(state)?;
    let (status, body) = client
        .api_request(Method::GET, &format!("/auth/device/poll?session_id={}", session_id), None, None)
        .await
        .map_err(|e| err("coordinator_unavailable", e))?;
    if status == 202 {
        let mut v = redact_tokens(body);
        if !v.is_object() {
            v = json!({});
        }
        v["pending"] = json!(true);
        return Ok(v);
    }
    if !(200..300).contains(&status) {
        return Err(err("auth_failed", format!("auth poll failed ({}): {}", status, body)));
    }

    let s = |k: &str| body[k].as_str().unwrap_or("").to_string();
    let (user_id, access_token) = (s("user_id"), s("access_token"));
    if !user_id.is_empty() && !access_token.is_empty() {
        let (refresh_token, expires_at) = (s("refresh_token"), body["expires_at"].as_i64().unwrap_or(0));
        let (username, display_name) = (s("preferred_username"), s("display_name"));
        update_identity(state, |id| {
            id.user.id = user_id.clone();
            id.auth = Some(AuthCredentials { user_id: user_id.clone(), access_token, refresh_token, expires_at });
            let handle = sanitize_handle(&username);
            if !handle.is_empty() {
                id.user.handle = handle;
            }
            if !display_name.is_empty() {
                id.user.display_name = display_name;
            }
        })
        .await?;
        info!("account: OIDC authentication completed; user_id={}", user_id);
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = re_register(&st).await {
                warn!("account: re-register after OIDC auth failed: {}", e.message);
            }
        });
    }
    let mut v = redact_tokens(body);
    v["pending"] = json!(false);
    Ok(v)
}

/// Refresh the access token now (`POST /auth/token/refresh`).
pub async fn auth_refresh(state: &Arc<CoreState>) -> Result<Value, IpcError> {
    let client = client(state)?;
    let has_refresh = state
        .identity
        .read()
        .await
        .as_ref()
        .and_then(|i| i.auth.as_ref())
        .is_some_and(|a| !a.refresh_token.is_empty());
    if !has_refresh {
        return Err(err("not_authenticated", "No refresh token — authenticate first"));
    }
    if !client.try_refresh_token(state).await {
        return Err(err("auth_failed", "token refresh failed"));
    }
    let expires_at = state.identity.read().await.as_ref().and_then(|i| i.auth.as_ref()).map(|a| a.expires_at);
    Ok(json!({ "ok": true, "expires_at": expires_at }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_rules() {
        assert!(validate_handle("pc-1").is_ok());
        assert!(validate_handle("").is_err());
        assert!(validate_handle("PC").is_err());
        assert!(validate_handle("a.b").is_err());
        assert_eq!(sanitize_handle("John.Doe@Example"), "john-doe-example");
        assert_eq!(sanitize_handle("__a  b__"), "a-b");
        assert_eq!(sanitize_handle("中文"), "");
    }

    #[test]
    fn tokens_are_redacted() {
        let v = redact_tokens(json!({"user_id": "u", "access_token": "a", "refresh_token": "r", "expires_at": 1}));
        assert_eq!(v, json!({"user_id": "u", "expires_at": 1}));
    }

    use crate::test_support::{core_state, eventually, FakeCoordinator};

    /// `identity.json` as written (the test identity's key isn't on disk,
    /// so `load_or_create` would re-derive the device ID).
    fn identity_on_disk(state: &CoreState) -> identity::IdentityFile {
        serde_json::from_str(&std::fs::read_to_string(state.data_dir.join("identity.json")).unwrap()).unwrap()
    }

    async fn with_client(state: &Arc<CoreState>, url: &str) {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        std::mem::forget(rx);
        let c = CoordinatorClient::new(crate::coordinator::CoordinatorConfig { coord_url: url.into() }, tx);
        let _ = state.coordinator.set(Arc::new(c));
    }

    #[tokio::test]
    async fn oidc_device_flow_stores_credentials_and_reregisters() {
        let polls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let p = polls.clone();
        let coord = FakeCoordinator::start(
            move |req| match req.path.as_str() {
                "/auth/device/start" => (200, json!({ "session_id": "s1", "verification_uri": "https://x/verify", "user_code": "ABCD" })),
                "/auth/device/poll?session_id=s1" => {
                    if p.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        (202, json!({ "status": "pending" }))
                    } else {
                        (200, json!({ "user_id": "user-0000abcd", "access_token": "AT", "refresh_token": "RT",
                                      "expires_at": 4102444800i64, "preferred_username": "John.Doe", "display_name": "John" }))
                    }
                }
                "/device/register" => (200, json!({ "hostname": "laptop.john-doe.ezplay.msst.net", "ipv4": "172.22.178.196", "ipv6": "x" })),
                _ => (404, json!({})),
            },
            |_| vec![],
        ).await;
        let (state, _ipc) = core_state("oidc").await;
        with_client(&state, &coord.url).await;

        assert_eq!(auth_start(&state).await.unwrap()["user_code"], "ABCD");
        assert_eq!(auth_poll(&state, "s1").await.unwrap()["pending"], true);
        let done = auth_poll(&state, "s1").await.unwrap();
        assert_eq!(done["pending"], false);
        assert!(done.get("access_token").is_none() && done.get("refresh_token").is_none());

        let id = state.identity.read().await.clone().unwrap();
        assert_eq!(id.user.id, "user-0000abcd");
        assert_eq!(id.user.handle, "john-doe");
        assert_eq!(id.user.display_name, "John");
        assert_eq!(id.auth.as_ref().unwrap().refresh_token, "RT");
        assert!(state.net.read().await.local_authenticated);
        assert_eq!(state.net.read().await.local_user_id, "user-0000abcd");
        // Persisted.
        let on_disk = identity_on_disk(&state);
        assert_eq!(on_disk.auth.unwrap().access_token, "AT");

        // Re-registered with the new token; coordinator hostname adopted.
        assert!(eventually(|| coord.http_log.lock().unwrap().iter().any(|r| r.path == "/device/register")).await);
        let reg = coord.http_log.lock().unwrap().iter().find(|r| r.path == "/device/register").cloned().unwrap();
        assert_eq!(reg.authorization.as_deref(), Some("Bearer AT"));
        assert_eq!(reg.body["user"]["id"], "user-0000abcd");
        assert!(eventually(|| state.identity.try_read().is_ok_and(|g| g.as_ref().unwrap().device.hostname == "laptop.john-doe.ezplay.msst.net")).await);

        // With OIDC active, user-level edits are ignored; device-level apply.
        let out = update_display_name(&state, Some("Other".into()), Some("Laptop".into())).await.unwrap();
        assert_eq!(out["user_display_name"], "John");
        assert_eq!(out["device_display_name"], "Laptop");
    }

    #[tokio::test]
    async fn handle_update_validates_saves_and_reregisters() {
        let coord = FakeCoordinator::start(
            |req| if req.path == "/device/register" { (200, json!({ "hostname": "pc.me.ezplay.msst.net", "ipv4": "172.22.9.9" })) } else { (404, json!({})) },
            |_| vec![],
        ).await;
        let (state, _ipc) = core_state("handles").await;
        with_client(&state, &coord.url).await;

        assert_eq!(update_handle(&state, Some("Bad Handle".into()), None).await.unwrap_err().code, "invalid_handle");
        assert_eq!(update_handle(&state, None, None).await.unwrap_err().code, "invalid_request");

        let out = update_handle(&state, Some("me".into()), Some("pc".into())).await.unwrap();
        assert_eq!((out["user_handle"].as_str(), out["device_handle"].as_str()), (Some("me"), Some("pc")));
        let reg = coord.http_log.lock().unwrap().iter().find(|r| r.path == "/device/register").cloned().unwrap();
        assert_eq!(reg.body["device"]["handle"], "pc");
        // The Coordinator has no keyproof (404): registered without a proof.
        assert!(reg.body["device"].get("key_proof").is_none());
        assert_eq!(reg.body["network"]["hostname"], "pc.me.ezplay.msst.net");
        let id = identity_on_disk(&state);
        assert_eq!(id.device.handle, "pc");
        // Coordinator-assigned IPv4 recorded for next start.
        assert_eq!(id.device.assigned_ipv4.as_deref(), Some("172.22.9.9"));
        assert_eq!(id.device.hostname, "pc.me.ezplay.msst.net");
    }

    #[tokio::test]
    async fn names_and_handles_sync_at_once_and_can_be_cleared() {
        let coord = FakeCoordinator::start(
            |req| if req.path == "/device/register" { (200, json!({ "hostname": req.body["network"]["hostname"], "ipv4": "" })) } else { (404, json!({})) },
            |_| vec![],
        ).await;
        let (state, _ipc) = core_state("clear").await;
        with_client(&state, &coord.url).await;
        let registers = || coord.http_log.lock().unwrap().iter().filter(|r| r.path == "/device/register").map(|r| r.body.clone()).collect::<Vec<_>>();
        let (dev_id, user_id) = {
            let id = state.identity.read().await;
            let id = id.as_ref().unwrap();
            (id.device.id.clone(), id.user.id.clone())
        };

        // A display name change is registered right away.
        let out = update_display_name(&state, None, Some("  Laptop ".into())).await.unwrap();
        assert_eq!((out["device_display_name"].as_str(), out["synced"].as_bool()), (Some("Laptop"), Some(true)));
        assert_eq!(registers().last().unwrap()["meta"]["device_display_name"], "Laptop");

        // Cleared → stored as unset, registered as the default name.
        let out = update_display_name(&state, None, Some(" ".into())).await.unwrap();
        assert!(out["device_display_name"].is_null());
        assert_eq!(identity_on_disk(&state).device.display_name, "");
        assert_eq!(registers().last().unwrap()["meta"]["device_display_name"], format!("用户{}的设备", user_id));

        // Handle set, then cleared → registered as the device ID.
        update_handle(&state, None, Some("pc".into())).await.unwrap();
        assert_eq!(registers().last().unwrap()["device"]["handle"], "pc");
        let out = update_handle(&state, None, Some(String::new())).await.unwrap();
        assert!(out["device_handle"].is_null());
        let last = registers().last().unwrap().clone();
        assert_eq!(last["device"]["handle"], dev_id.as_str());
        assert_eq!(last["network"]["hostname"], format!("{}.{}.ezplay.msst.net", dev_id, user_id));
        assert_eq!(identity_on_disk(&state).device.handle, "");
        assert_eq!(identity_on_disk(&state).device.hostname, format!("{}.{}.ezplay.msst.net", dev_id, user_id));

        // No change → nothing to send.
        let n = registers().len();
        assert_eq!(update_handle(&state, None, Some(String::new())).await.unwrap()["synced"], true);
        assert_eq!(registers().len(), n);
    }

    #[tokio::test]
    async fn display_names_are_validated_and_saved_without_coordinator() {
        let (state, _ipc) = core_state("names-invalid").await;
        let long = "名".repeat(MAX_DISPLAY_NAME_CHARS + 1);
        assert_eq!(update_display_name(&state, None, Some(long)).await.unwrap_err().code, "invalid_display_name");
        assert_eq!(update_display_name(&state, None, Some("a\nb".into())).await.unwrap_err().code, "invalid_display_name");
        assert_eq!(update_handle(&state, None, Some(" PC ".into())).await.unwrap_err().code, "invalid_handle");
        // No coordinator: saved locally, reported as not synced.
        let out = update_display_name(&state, None, Some("名".repeat(MAX_DISPLAY_NAME_CHARS))).await.unwrap();
        assert_eq!(out["synced"], false);
        assert_eq!(identity_on_disk(&state).device.display_name.chars().count(), MAX_DISPLAY_NAME_CHARS);
    }

    #[tokio::test]
    async fn unset_fields_are_null_in_replies() {
        let (state, _ipc) = core_state("account-null").await;
        let out = update_display_name(&state, None, Some("Laptop".into())).await.unwrap();
        assert!(out["user_display_name"].is_null());
        assert_eq!(out["device_display_name"], "Laptop");
    }
}
