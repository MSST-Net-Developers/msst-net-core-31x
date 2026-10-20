//! IPC request handler — routes IpcRequest to IpcResponse.
//!
//! This module contains the dispatch logic for all IPC requests: the
//! permission check (`msst_ipc_protocol::access`), then the business module
//! that serves the request.  Queries only read state.  Commands may do I/O
//! (coordinator calls, relay selection, disk) and, by default, return their
//! final result; sent with `async: true` they run as operations instead
//! (`super::ops`).

use super::Session;
use crate::state::CoreState;
use msst_ipc_protocol::{views, IpcError, IpcRequest, IpcResponse};
use reqwest::Method;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Handle a single IPC request and return a response.
///
/// This is the main dispatch function.  It enforces the permission model
/// (`msst_ipc_protocol::access`), then matches the request type and
/// delegates to the appropriate handler.
pub async fn handle_request(request: IpcRequest, state: &Arc<CoreState>, session: &Session) -> IpcResponse {
    let required = request.required_role();
    if required > session.role {
        debug!("IPC: {:?} needs {}, connection is {}", request.kind(), required.as_str(), session.role.as_str());
        return IpcResponse::Error(IpcError {
            code: "permission_denied".into(),
            message: format!("this connection is {}; the request needs {}", session.role.as_str(), required.as_str()),
        });
    }
    match request {
        // ── Session ────────────────────────────────────────────────────────
        IpcRequest::SetLogStream { enabled } => {
            session.log_stream.store(enabled, std::sync::atomic::Ordering::Relaxed);
            IpcResponse::Ok(serde_json::json!({ "log_stream": enabled }))
        }
        IpcRequest::GetOperation { operation_id } => {
            match state.operations.view(&operation_id, crate::runtime::current_unix()) {
                Some(v) => IpcResponse::ok(&v),
                None => IpcResponse::Error(IpcError {
                    code: "not_found".into(),
                    message: format!("no operation {} (unknown, or finished too long ago)", operation_id),
                }),
            }
        }

        // ── Queries ────────────────────────────────────────────────────────
        IpcRequest::Health => handle_health(state, session).await,
        IpcRequest::GetSystemState => handle_get_system_state(state).await,
        IpcRequest::GetNodes => handle_get_nodes(state).await,
        IpcRequest::GetNode { device_id } => handle_get_node(state, &device_id).await,
        IpcRequest::GetAclRules => IpcResponse::Ok(crate::acl::list_rules(state).await),
        IpcRequest::GetAclGroups => IpcResponse::Ok(crate::acl::list_groups(state).await),
        IpcRequest::GetAccessLog { limit } => IpcResponse::Ok(crate::inbound::access_log(state, limit).await),
        IpcRequest::GetPendingAuth => IpcResponse::Ok(crate::inbound::pending_requests(state).await),
        IpcRequest::GetNetSettings => IpcResponse::Ok(state.net_settings.read().await.to_view()),
        IpcRequest::GetEndpoints => {
            IpcResponse::Ok(state.endpoint_history.lock().unwrap_or_else(|e| e.into_inner()).to_view())
        }
        IpcRequest::GetTrafficStats => IpcResponse::Ok(crate::diagnostics::traffic_view(state).await),
        IpcRequest::GetPathView | IpcRequest::GetPaths => IpcResponse::Ok(crate::diagnostics::path_view(state).await),
        IpcRequest::GetConnections => IpcResponse::Ok(crate::diagnostics::connections_view(state).await),
        IpcRequest::GetLogs { limit } => {
            IpcResponse::Ok(serde_json::json!({ "entries": crate::logcapture::get_logs(limit.map(|l| l as usize)) }))
        }
        IpcRequest::StartDiagPing { device_id } => respond(crate::diagnostics::start_ping(state, device_id).await),
        IpcRequest::GetDiagPingResult { job_id } => respond(crate::diagnostics::ping_result(state, &job_id)),
        IpcRequest::GetServices => IpcResponse::Ok(crate::acl::parse::service_catalog_view()),
        IpcRequest::GetContacts => {
            let entries = state.contacts.lock().unwrap_or_else(|e| e.into_inner()).entries();
            IpcResponse::Ok(serde_json::json!({ "contacts": entries }))
        }
        IpcRequest::GetRelays => respond(crate::diagnostics::relays(state).await),

        // ── Commands ───────────────────────────────────────────────────────
        IpcRequest::CreateRoom { room_name, password, relay, relay_password } => {
            respond(crate::rooms::create_room(state, room_name, password, relay, relay_password).await)
        }
        IpcRequest::JoinRoom { room_id, password } => respond(crate::rooms::join_room(state, room_id, password).await),
        IpcRequest::LeaveRoom { room_id } => respond(crate::rooms::leave_room(state, room_id).await),
        IpcRequest::CreateAclRule { rule } => respond(crate::acl::create_rule(state, rule).await),
        IpcRequest::UpdateAclRule { rule_id, patch } => {
            respond(crate::acl::update_rule(state, &rule_id, patch).await)
        }
        IpcRequest::DeleteAclRule { rule_id } => respond(crate::acl::delete_rule(state, &rule_id).await),
        IpcRequest::ClearAclRules => respond(crate::acl::clear_rules(state).await),
        IpcRequest::CreateAclGroup { group } => respond(crate::acl::create_group(state, group).await),
        IpcRequest::UpdateAclGroup { group_id, patch } => {
            respond(crate::acl::update_group(state, &group_id, patch).await)
        }
        IpcRequest::DeleteAclGroup { group_id } => respond(crate::acl::delete_group(state, &group_id).await),
        IpcRequest::AuthDecision { request_id, decision } => {
            respond(crate::inbound::resolve_auth(state, &request_id, decision).await)
        }
        IpcRequest::SetPingEnabled { enabled } => respond(crate::acl::set_ping_enabled(state, enabled).await),
        IpcRequest::RefreshEndpoint => {
            info!("IPC: endpoint refresh requested");
            crate::endpoints::spawn_detect_and_report(state.clone());
            IpcResponse::Ok(serde_json::json!({ "ok": true }))
        }
        IpcRequest::ReRegister => respond(crate::account::re_register(state).await),
        IpcRequest::ClearLogs => {
            crate::logcapture::clear_logs();
            info!("IPC: logs cleared");
            IpcResponse::Ok(serde_json::json!({ "ok": true }))
        }
        IpcRequest::UpdateDisplayName { user, device } => respond(crate::account::update_display_name(state, user, device).await),
        IpcRequest::UpdateHandle { user, device } => respond(crate::account::update_handle(state, user, device).await),
        IpcRequest::AuthStart => respond(crate::account::auth_start(state).await),
        IpcRequest::AuthPoll { session_id } => respond(crate::account::auth_poll(state, &session_id).await),
        IpcRequest::AuthRefresh => respond(crate::account::auth_refresh(state).await),
        IpcRequest::SetNetSettings { settings } => respond(set_net_settings(state, settings).await),

        IpcRequest::GetDnsDomains => respond(dns_proxy(state, Method::GET, "/dns/domains".into(), None).await),
        IpcRequest::GetDnsRecords { domain } => {
            respond(dns_proxy(state, Method::GET, format!("/dns/domains/{}/records", domain), None).await)
        }
        IpcRequest::DnsRegisterDomain { namespace, reason } => {
            let body = serde_json::json!({ "namespace": namespace, "reason": reason });
            respond(dns_proxy(state, Method::POST, "/dns/domains/register".into(), Some(body)).await)
        }
        IpcRequest::DnsCreateRecord { domain, record } => {
            respond(dns_proxy(state, Method::POST, format!("/dns/domains/{}/records", domain), Some(record)).await)
        }
        IpcRequest::DnsUpdateRecord { domain, record_id, patch } => {
            respond(dns_proxy(state, Method::PUT, format!("/dns/domains/{}/records/{}", domain, record_id), Some(patch)).await)
        }
        IpcRequest::DnsDeleteRecord { domain, record_id } => {
            respond(dns_proxy(state, Method::DELETE, format!("/dns/domains/{}/records/{}", domain, record_id), None).await)
        }

    }
}

fn respond(result: Result<serde_json::Value, IpcError>) -> IpcResponse {
    match result {
        Ok(v) => IpcResponse::Ok(v),
        Err(e) => IpcResponse::Error(e),
    }
}

// ---------------------------------------------------------------------------
// Query handlers
// ---------------------------------------------------------------------------

async fn handle_health(state: &Arc<CoreState>, session: &Session) -> IpcResponse {
    let now = crate::runtime::current_unix();
    let (coordinator, credential, oidc_rejected) = match state.coordinator.get() {
        Some(c) => (c.connection_state().await, c.credential_kind(), c.oidc_rejected()),
        None => (crate::coordinator::ConnectionState::Disconnected, "none", false),
    };
    let net = state.net.read().await;
    let id = state.identity.read().await;
    let id = id.as_ref();
    let auth = id.and_then(|i| i.auth.as_ref());
    // Unset names/handles are null, not "".
    let set = |s: &String| Some(s.clone()).filter(|s| !s.is_empty());
    IpcResponse::ok(&views::Health {
        status: "ok".into(),
        generation: state.generation.current(),
        ipc_role: session.role,
        device_id: id.map(|i| i.device.id.clone()),
        user_id: id.map(|i| i.user.id.clone()),
        device_handle: id.and_then(|i| set(&i.device.handle)),
        user_handle: id.and_then(|i| set(&i.user.handle)),
        user_display_name: id.and_then(|i| set(&i.user.display_name)),
        device_display_name: id.and_then(|i| set(&i.device.display_name)),
        device_hostname: id.and_then(|i| set(&i.device.hostname)),
        // Stored credentials the Coordinator refused don't count.
        is_authenticated: auth.is_some_and(|a| !a.access_token.is_empty() && a.expires_at > now) && !oidc_rejected,
        auth_expires_at: auth.map(|a| a.expires_at),
        ws_connected: coordinator == crate::coordinator::ConnectionState::Connected,
        coordinator_state: format!("{:?}", coordinator),
        coordinator_credential: credential.into(),
        tun_ready: state.tun_attached.load(std::sync::atomic::Ordering::SeqCst),
        access_auth_required: state.access_auth_required.load(std::sync::atomic::Ordering::SeqCst),
        relay: net.relay_addr.clone(),
        peer_count: net.peer_list.len() as u64,
        rule_count: net.acl_rules.len() as u64,
        ping_enabled: net.ping_enabled,
    })
}

async fn handle_get_system_state(state: &Arc<CoreState>) -> IpcResponse {
    // Room view (3.0.x `GET /room/state`) plus the rule count, so a
    // reconnecting Controller can rebuild its main view in one request.
    let mut v = crate::rooms::room_view(state).await;
    let net = state.net.read().await;
    v["device_id"] = serde_json::json!(net.local_device_id);
    v["user_id"] = serde_json::json!(net.local_user_id);
    v["joined_rooms"] = serde_json::json!(net.joined_rooms);
    v["rule_count"] = serde_json::json!(net.acl_rules.len());
    v["generation"] = serde_json::json!(state.generation.current());
    IpcResponse::Ok(v)
}

fn node_summary(e: &msst_core_state::peer_list::PeerEntry) -> views::NodeSummary {
    views::NodeSummary {
        device_id: e.device_id.clone(),
        ipv4: e.ipv4.to_string(),
        ipv6: e.ipv6.to_string(),
        hostname: e.hostname.clone(),
        display_name: e.display_name.clone(),
        user_id: e.user_id.clone(),
        user_handle: e.user_handle.clone(),
        device_handle: e.device_handle.clone(),
        is_authenticated: e.is_authenticated,
    }
}

async fn handle_get_nodes(state: &Arc<CoreState>) -> IpcResponse {
    let net = state.net.read().await;
    let nodes = net.peer_list.device_ids().filter_map(|id| net.peer_list.get(id)).map(node_summary).collect();
    IpcResponse::ok(&views::Nodes { nodes })
}

async fn handle_get_node(state: &Arc<CoreState>, device_id: &str) -> IpcResponse {
    let net = state.net.read().await;
    match net.peer_list.get(device_id) {
        Some(entry) => IpcResponse::ok(&views::NodeDetail { node: node_summary(entry), preferred_relay: entry.preferred_relay.clone() }),
        None => IpcResponse::Error(IpcError {
            code: "not_found".into(),
            message: format!("Peer {} not found", device_id),
        }),
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/// Apply a partial settings update, persist it, and push it to the
/// scheduler.  MTU applies on next start; a new preferred relay on the next
/// relay selection (coordinator reconnect).
async fn set_net_settings(state: &Arc<CoreState>, patch: serde_json::Value) -> Result<serde_json::Value, IpcError> {
    let err = |code: &str, m: String| IpcError { code: code.into(), message: m };
    let view = {
        let mut s = state.net_settings.write().await;
        let mut next = s.clone();
        next.apply_patch(&patch).map_err(|e| err("invalid_settings", e))?;
        next.save(&state.data_dir).map_err(|e| err("persist_failed", format!("failed to save settings: {}", e)))?;
        *s = next;
        info!(
            "IPC: network settings updated: disable_p2p={} lock_path={} preferred_relay={:?} mtu_override={:?} keepalive_secs={:?} linux_dns_mode={:?}",
            s.disable_p2p, s.lock_path, s.preferred_relay, s.mtu_override, s.keepalive_secs, s.linux_dns_mode
        );
        s.to_view()
    };
    state.apply_net_settings().await;
    state.next_generation();
    state.emit_ipc_event(msst_ipc_protocol::IpcEvent::SettingsChanged { scope: "net".into(), settings: view.clone() });
    Ok(view)
}

/// Custom-domain management: forwarded to the coordinator's `/dns/*` API
/// with the user's token (3.0.x DNS proxy).  Requires OIDC authentication.
async fn dns_proxy(
    state: &Arc<CoreState>,
    method: Method,
    path: String,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, IpcError> {
    let err = |code: &str, m: String| IpcError { code: code.into(), message: m };
    let token = state
        .identity
        .read()
        .await
        .as_ref()
        .and_then(|i| i.auth.as_ref())
        .map(|a| a.access_token.clone())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| err("not_authenticated", "请先完成 OIDC 认证".into()))?;
    let client = state.coordinator.get().ok_or_else(|| err("coordinator_unavailable", "coordinator client not started".into()))?;
    let (status, resp) = client
        .api_request(method.clone(), &path, body.as_ref(), Some(&token))
        .await
        .map_err(|e| err("coordinator_unavailable", e))?;
    if (200..300).contains(&status) {
        info!("IPC: DNS {} {} ok", method, path);
        Ok(resp)
    } else {
        warn!("IPC: DNS {} {} returned {}", method, path, status);
        Err(err("coordinator_error", format!("HTTP {}: {}", status, resp)))
    }
}
