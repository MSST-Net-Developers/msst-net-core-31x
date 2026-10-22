//! Protocol contract tests and test vectors (Controller proposal P1).
//!
//! Builds a deterministic Core state, runs every local query through the
//! real IPC handler, captures the events Core emits for typical actions, and
//! compares the resulting frames with
//! `crates/msst-ipc-protocol/tests/vectors/*.json`.
//!
//! Regenerate after an intended change:
//! `UPDATE_VECTORS=1 cargo test -p msst-net-core contract`
//!
//! Volatile values (timestamps, generation, random request IDs) are
//! normalized so the vectors are stable.

use crate::state::CoreState;
use msst_acl_engine::{Action, Direction, FirewallRule, PermissionGroup, Protocol, ProtocolPort};
use msst_core_state::firewall::access_log::{AccessDecision, AccessLogEntry, AccessReason};
use msst_core_state::firewall::auth::AuthKey;
use msst_ipc_protocol::{IpcEvent, IpcMessage, IpcRequest};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("crates/msst-ipc-protocol/tests/vectors")
}

/// Replace values that differ between runs.
fn normalize(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                match k.as_str() {
                    "generation" | "timestamp_ms" | "last_outbound_unix" | "reported_at" if val.is_number() => *val = json!(0),
                    // Event stream positions depend on the fixture's history.
                    "seq" | "event_seq" if val.is_number() => *val = json!(1),
                    "expires_in_secs" if val.is_number() => *val = json!(60),
                    "request_id" if val.is_string() => *val = json!("<request_id>"),
                    _ => normalize(val),
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(normalize),
        _ => {}
    }
}

/// Compare (or, with UPDATE_VECTORS=1, write) one vector file.
fn check(name: &str, mut frames: Value, mismatches: &mut Vec<String>) {
    normalize(&mut frames);
    let path = vectors_dir().join(format!("{}.json", name));
    let text = serde_json::to_string_pretty(&frames).unwrap() + "\n";
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::create_dir_all(vectors_dir()).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(existing) if existing == text => {}
        _ => mismatches.push(name.to_string()),
    }
}

async fn query(state: &Arc<CoreState>, name: &str, request: IpcRequest, mismatches: &mut Vec<String>) {
    let req = IpcMessage::Request { id: "1".into(), body: request.clone(), r#async: false };
    let session = crate::ipc::Session::new(msst_ipc_protocol::Role::Admin);
    let event_seq = Some(state.events.last_seq());
    let resp = IpcMessage::Response { id: "1".into(), body: crate::ipc::handler::handle_request(request, state, &session).await, event_seq };
    check(name, json!({ "request": req, "response": resp }), mismatches);
}

fn drain(rx: &mut crate::state::EventReceiver) -> Vec<IpcEvent> {
    let mut v = Vec::new();
    while let Ok(e) = rx.try_recv() {
        v.push(e);
    }
    v
}

fn event_frame(e: &IpcEvent) -> Value {
    serde_json::to_value(IpcMessage::Event { body: e.clone(), seq: Some(1) }).unwrap()
}

/// The deterministic fixture: one known peer in a room, one rule, one
/// group, one access-log entry, one pending request, a contact, traffic,
/// an endpoint report, a path, and a log line.
async fn fixture(name: &str) -> (Arc<CoreState>, crate::state::EventReceiver) {
    let (state, ipc_rx) = crate::test_support::core_state(name).await;
    crate::nodes::apply_peer(&state, crate::nodes::PeerData {
        device_id: "device-0000000b",
        ipv4: "172.22.1.1",
        ipv6: "fd22:2222:2222:2222::b",
        user_id: Some("user-0000000b"),
        device_handle: Some("pc"),
        user_handle: Some("bob"),
        hostname: Some("pc.bob.ezplay.msst.net"),
        display_name: Some("Bob PC".into()),
        user_display_name: Some("Bob".into()),
        endpoints: &["203.0.113.7:21031".to_string(), "relay:198.51.100.1:7000".to_string()],
        is_authenticated: true,
        ..Default::default()
    })
    .await;
    {
        let mut net = state.net.write().await;
        net.joined_rooms.insert("space-1".into(), "Test room".into());
        net.room_peers.insert("device-0000000b".into());
        net.relay_addr = Some("198.51.100.1:7000".into());
    }
    let rule = FirewallRule {
        id: "00000000000000a1".into(),
        permission_group: PermissionGroup::Devices { ids: vec!["device-0000000b".into()] },
        protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 25565)],
        action: Action::Allow,
        direction: Direction::Inbound,
        expires_at: None,
        enabled: true,
        comment: Some("Minecraft for Bob".into()),
    };
    {
        let mut net = state.net.write().await;
        net.acl_rules.push(rule);
        net.acl_labels.insert("00000000000000a1".into(), [("device-0000000b".to_string(), "pc.bob".to_string())].into());
    }
    state.acl_groups.write().await.push(crate::acl::store::PermissionGroupDef {
        id: "00000000000000g1".into(),
        name: "friends".into(),
        kind: "user".into(),
        member_ids: vec!["user-0000000b".into()],
    });
    {
        let mut fw = state.firewall.lock().await;
        fw.log_access(AccessLogEntry {
            id: "00000000000000l1".into(),
            src_device_id: "device-0000000b".into(),
            service_name: Some("Minecraft Java".into()),
            proto: Protocol::Tcp,
            dst_port: 25565,
            decision: AccessDecision::Allow,
            reason: AccessReason::MatchedRule { rule_id: "00000000000000a1".into(), comment: Some("Minecraft for Bob".into()) },
            timestamp_ms: 1,
            rule_id: Some("00000000000000a1".into()),
            count: 1,
        });
        fw.register_pending_auth(
            AuthKey { src_device_id: "device-0000000b".into(), proto: Protocol::Udp, dst_port: 19132 },
            "device-0000000b".into(),
            "00000000000000l2".into(),
        );
    }
    state.contacts.lock().unwrap().update_room_contact("device-0000000b", Some("user-0000000b"), 1_700_000_000);
    crate::diagnostics::traffic(&state, "device-0000000b").tx.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
    state.endpoint_history.lock().unwrap().record(vec!["203.0.113.1:21031".into(), "relay:198.51.100.1:7000".into()], 1);
    state.conn_track.lock().unwrap().record_outbound(
        "172.22.144.209".parse().unwrap(), 40000, "172.22.1.1".parse().unwrap(), 25565, 6, 1,
    );
    (state, ipc_rx)
}

#[tokio::test]
async fn contract_vectors() {
    let _serial = crate::logcapture::TEST_LOCK.lock().await;
    let (state, mut ipc_rx) = fixture("contract").await;
    drain(&mut ipc_rx);
    crate::logcapture::clear_logs();
    crate::logcapture::record(crate::logcapture::LogEntry {
        level: "info".into(),
        target: "msst_net_core::coordinator".into(),
        message: "coordinator: WebSocket connected".into(),
        timestamp_ms: 1,
    });

    let mut bad = Vec::new();
    // ── Queries (local state only; coordinator proxies are excluded) ──────
    query(&state, "health", IpcRequest::Health, &mut bad).await;
    query(&state, "get_system_state", IpcRequest::GetSystemState, &mut bad).await;
    query(&state, "get_nodes", IpcRequest::GetNodes, &mut bad).await;
    query(&state, "get_node", IpcRequest::GetNode { device_id: "device-0000000b".into() }, &mut bad).await;
    query(&state, "get_node_not_found", IpcRequest::GetNode { device_id: "device-ffffffff".into() }, &mut bad).await;
    query(&state, "get_acl_rules", IpcRequest::GetAclRules, &mut bad).await;
    query(&state, "get_acl_groups", IpcRequest::GetAclGroups, &mut bad).await;
    query(&state, "get_access_log", IpcRequest::GetAccessLog { limit: Some(10) }, &mut bad).await;
    query(&state, "get_pending_auth", IpcRequest::GetPendingAuth, &mut bad).await;
    query(&state, "get_net_settings", IpcRequest::GetNetSettings, &mut bad).await;
    query(&state, "get_endpoints", IpcRequest::GetEndpoints, &mut bad).await;
    query(&state, "get_traffic_stats", IpcRequest::GetTrafficStats, &mut bad).await;
    query(&state, "get_path_view", IpcRequest::GetPathView, &mut bad).await;
    query(&state, "get_connections", IpcRequest::GetConnections, &mut bad).await;
    query(&state, "get_contacts", IpcRequest::GetContacts, &mut bad).await;
    query(&state, "get_services", IpcRequest::GetServices, &mut bad).await;
    query(&state, "get_logs", IpcRequest::GetLogs { limit: Some(1) }, &mut bad).await;

    // ── Events for typical actions ─────────────────────────────────────────
    drain(&mut ipc_rx);
    crate::rooms::emit_room_state(&state).await;
    crate::account::update_display_name(&state, Some("Me".into()), Some("Laptop".into())).await.unwrap();
    crate::acl::set_ping_enabled(&state, true).await.unwrap();
    crate::nodes::apply_peer(&state, crate::nodes::PeerData {
        device_id: "device-0000000b", ipv4: "172.22.1.1", ipv6: "fd22:2222:2222:2222::b",
        hostname: Some("pc.bob.ezplay.msst.net"), display_name: Some("Bob's new PC".into()), is_authenticated: true,
        ..Default::default()
    })
    .await;
    let events: Vec<Value> = drain(&mut ipc_rx).iter().map(event_frame).collect();
    check("events", json!(events), &mut bad);

    // Errors keep their documented codes.
    query(&state, "update_acl_rule_unknown_field", IpcRequest::UpdateAclRule {
        rule_id: "00000000000000a1".into(),
        patch: json!({ "permission_group": { "kind": "space" } }),
    }, &mut bad).await;
    query(&state, "set_net_settings_invalid", IpcRequest::SetNetSettings { settings: json!({ "mtu_override": 70000 }) }, &mut bad).await;

    assert!(bad.is_empty(), "vectors out of date: {:?} — regenerate with UPDATE_VECTORS=1 if the change is intended", bad);
}

#[tokio::test]
async fn every_error_code_is_documented() {
    // Every code used in Core's sources must be listed in `errors::ALL`.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut used = std::collections::BTreeSet::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") && !p.ends_with("contract_tests.rs") {
                let text = std::fs::read_to_string(&p).unwrap();
                for pat in ["err(\"", "ipc_err(\"", "code: \""] {
                    for part in text.split(pat).skip(1) {
                        let code: String = part.chars().take_while(|c| c.is_ascii_lowercase() || *c == '_').collect();
                        if !code.is_empty() && part[code.len()..].starts_with('"') {
                            used.insert(code);
                        }
                    }
                }
            }
        }
    }
    let documented: std::collections::BTreeSet<String> = msst_ipc_protocol::errors::ALL.iter().map(|s| s.to_string()).collect();
    let missing: Vec<_> = used.difference(&documented).collect();
    assert!(missing.is_empty(), "undocumented error codes: {:?}", missing);
}

#[tokio::test]
async fn health_reports_tun_and_auth_state_accurately() {
    let (state, _rx) = crate::test_support::core_state("health").await;
    let h = |state: Arc<CoreState>| async move {
        let session = crate::ipc::Session::new(msst_ipc_protocol::Role::Admin);
        match crate::ipc::handler::handle_request(IpcRequest::Health, &state, &session).await {
            msst_ipc_protocol::IpcResponse::Ok(v) => v,
            e => panic!("{:?}", e),
        }
    };
    let v = h(state.clone()).await;
    assert_eq!(v["tun_ready"], false, "no TUN attached");
    assert!(v["device_handle"].is_null() && v["user_display_name"].is_null(), "unset → null");
    assert_eq!(v["access_auth_required"], false);
    state.access_auth_required.store(true, std::sync::atomic::Ordering::SeqCst);
    state.tun_attached.store(true, std::sync::atomic::Ordering::SeqCst);
    let v = h(state.clone()).await;
    assert_eq!(v["tun_ready"], true);
    assert_eq!(v["access_auth_required"], true);
}

#[tokio::test]
async fn clear_rules_and_eviction_events() {
    let (state, mut rx) = fixture("contract-clear").await;
    drain(&mut rx);
    let g0 = state.generation.current();
    let out = crate::acl::clear_rules(&state).await.unwrap();
    assert_eq!(out["deleted"], 1);
    assert!(state.net.read().await.acl_rules.is_empty());
    assert!(crate::acl::store::load_rules(&state.data_dir).unwrap().is_empty());
    assert!(drain(&mut rx).iter().any(|e| matches!(e, IpcEvent::AclChanged { action, .. } if action == "deleted")));
    assert!(state.generation.current() > g0);

    // A fetched peer with only a communication reason is evicted after 2 h.
    crate::peer_cache::on_communication(&state, "device-0000000b").await;
    state.net.write().await.room_peers.clear();
    let (evicted, _) = state.peers.lock().await.evict_expired(crate::runtime::current_unix() + 3 * 3600);
    assert_eq!(evicted, vec!["device-0000000b".to_string()]);
    // (evict_expired in peer_cache emits NodeRemoved; covered by its path.)
}

#[tokio::test]
async fn ipc_bind_failure_fails_startup() {
    let dir = std::env::temp_dir().join(format!("msst-bindfail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Longer than SUN_LEN (108) → bind fails.
    let sock = dir.join("x".repeat(150));
    let mut config = crate::config::CoreConfig::default();
    config.udp_port = 0;
    let r = crate::core::Core::start(crate::core::CoreOptions { config, data_dir: dir.clone(), ipc_socket: sock, metrics: false, host_routing: false }).await;
    assert!(r.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
