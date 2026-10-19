//! IPC message types.
//!
//! Every frame exchanged over the IPC transport is a JSON-serialized
//! [`IpcMessage`].  The three top-level categories map directly to the
//! semantic model in AGENTS.md §5.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Top-level envelope
// ---------------------------------------------------------------------------

/// The top-level IPC message envelope.
///
/// Every frame is exactly one of these.  The `#[serde(tag = "kind")]` attribute
/// makes the JSON discriminator the `"kind"` field, producing:
///
/// ```json
/// { "kind": "request", "id": "...", "body": { ... } }
/// { "kind": "response", "id": "...", "body": { ... } }
/// { "kind": "event", "body": { ... } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcMessage {
    /// Controller → Core: read state or request an operation.
    Request {
        /// Unique request ID (UUID or monotonic counter).  The response echoes
        /// this ID so the caller can correlate replies.  Since 0.4 responses
        /// may arrive in a different order than the requests were sent.
        id: String,
        body: IpcRequest,
        /// Run a command as a background operation (0.4): Core answers at
        /// once with `{"operation_id"}` and reports the outcome with
        /// `OperationProgress` / `OperationCompleted`.  Ignored for queries.
        #[serde(default, rename = "async", skip_serializing_if = "std::ops::Not::not")]
        r#async: bool,
    },
    /// Core → Controller: reply to a previous request.
    Response {
        /// The request ID this response corresponds to.
        id: String,
        body: IpcResponse,
        /// The `seq` of the last event Core had emitted when it started
        /// handling the request (0.4).  Every state change the response
        /// does not reflect is reported by an event with a larger `seq`;
        /// events with `seq <= event_seq` are already reflected and can be
        /// skipped.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        event_seq: Option<u64>,
    },
    /// Core → Controller: push notification (no request ID needed).
    Event {
        body: IpcEvent,
        /// Position in Core's event stream (0.4): starts at 1 when Core
        /// starts and increases by exactly 1 per event, so a gap means lost
        /// events (re-snapshot).  Absent on log lines (`Diagnostic`
        /// forwarded from the log), which are not part of the state stream.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<u64>,
    },
}

// ---------------------------------------------------------------------------
// Requests  (Controller → Core)
// ---------------------------------------------------------------------------

/// A request from Controller to Core.
///
/// Queries read state without side effects.
/// Commands request a state change; a successful response means the command
/// was **accepted**, not that the operation has completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "params", rename_all = "snake_case")]
pub enum IpcRequest {
    // ── Queries ─────────────────────────────────────────────────────────────
    /// Retrieve the full system state snapshot.
    GetSystemState,
    /// List all known peer nodes.
    GetNodes,
    /// Retrieve a single peer node by device ID.
    GetNode { device_id: String },
    /// List active connections.
    GetConnections,
    /// List peer path states.
    GetPaths,
    /// List firewall rules.
    GetAclRules,
    /// List permission groups.
    GetAclGroups,
    /// Retrieve recent access log entries.
    GetAccessLog { limit: Option<u32> },
    /// Retrieve pending interactive-auth requests.
    GetPendingAuth,
    /// Health / readiness probe.
    Health,
    /// Retrieve current network settings.
    GetNetSettings,
    /// Retrieve current endpoints (STUN, LAN, IPv6).
    GetEndpoints,
    /// Retrieve traffic statistics per peer.
    GetTrafficStats,
    /// Retrieve path view (relay/probing/direct per peer).
    GetPathView,
    /// Retrieve log buffer.
    GetLogs { limit: Option<u32> },
    /// List known DNS domains.
    GetDnsDomains,
    /// List DNS records for a domain.
    GetDnsRecords { domain: String },
    /// List available relay servers.
    GetRelays,
    /// List recent contacts.
    GetContacts,
    /// The well-known service templates rules can use, by category
    /// (3.0.x `GET /firewall/services`).  Added in protocol 0.2.
    GetServices,

    // ── Commands ────────────────────────────────────────────────────────────
    /// Create a room on the coordinator.
    CreateRoom { room_name: String, password: Option<String> },
    /// Join an existing room.
    JoinRoom { room_id: String, password: Option<String> },
    /// Leave a room.
    LeaveRoom { room_id: String },
    /// Create a firewall rule.
    CreateAclRule { rule: serde_json::Value },
    /// Update a firewall rule.
    UpdateAclRule { rule_id: String, patch: serde_json::Value },
    /// Delete a firewall rule.
    DeleteAclRule { rule_id: String },
    /// Delete every firewall rule (3.0.x `DELETE /firewall/rules`).
    /// Response: `{"deleted": <count>}`.  Added in protocol 0.3.
    ClearAclRules,
    /// Create a permission group.
    CreateAclGroup { group: serde_json::Value },
    /// Update a permission group.
    UpdateAclGroup { group_id: String, patch: serde_json::Value },
    /// Delete a permission group.
    DeleteAclGroup { group_id: String },
    /// Resolve an interactive auth request.
    AuthDecision { request_id: String, decision: AuthDecision },
    /// Update display name.
    UpdateDisplayName { user: Option<String>, device: Option<String> },
    /// Update mnemonic handle.
    UpdateHandle { user: Option<String>, device: Option<String> },
    /// Set network settings (partial update).
    SetNetSettings { settings: serde_json::Value },
    /// Toggle ICMP ping response.
    SetPingEnabled { enabled: bool },
    /// Force endpoint re-detection.
    RefreshEndpoint,
    /// Re-register device with coordinator.
    ReRegister,
    /// Start OIDC authentication flow.
    AuthStart,
    /// Poll OIDC authentication status.
    AuthPoll { session_id: String },
    /// Refresh OIDC token.
    AuthRefresh,
    /// Register a custom DNS domain.
    DnsRegisterDomain { namespace: String, reason: String },
    /// Create a DNS record.
    DnsCreateRecord { domain: String, record: serde_json::Value },
    /// Update a DNS record.
    DnsUpdateRecord { domain: String, record_id: String, patch: serde_json::Value },
    /// Delete a DNS record.
    DnsDeleteRecord { domain: String, record_id: String },
    /// Start a diagnostic ping to a peer.
    StartDiagPing { device_id: String },
    /// Get a diagnostic ping result.
    GetDiagPingResult { job_id: String },
    /// Clear log buffer.
    ClearLogs,
    /// State of an operation started with `async: true` (0.4): running,
    /// or its result while it is still remembered (recent operations).
    GetOperation { operation_id: String },
    /// Whether log lines are streamed to this connection as `Diagnostic`
    /// events (0.4).  Affects only the requesting connection; default on.
    SetLogStream { enabled: bool },
}

/// Auth decision variants — matches the 3.0.x `decision` string values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthDecision {
    AllowOnce,
    AlwaysAllow,
    DenyOnce,
    AlwaysDeny,
}

// ---------------------------------------------------------------------------
// Responses  (Core → Controller)
// ---------------------------------------------------------------------------

/// A response from Core to Controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum IpcResponse {
    /// The command/query succeeded.
    Ok(serde_json::Value),
    /// The command/query failed.
    Error(IpcError),
}

/// Structured error returned in [`IpcResponse::Error`].
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("{code}: {message}")]
pub struct IpcError {
    /// Machine-readable error code (e.g. `"not_found"`, `"not_initialized"`).
    pub code: String,
    /// Human-readable description.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Events  (Core → Controller, push)
// ---------------------------------------------------------------------------

/// An unsolicited push event from Core to Controller.
///
/// Events are the primary mechanism for Core to notify Controller of state
/// changes.  Controller should apply events to its local view in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IpcEvent {
    // ── Auth / access control ───────────────────────────────────────────────
    /// An inbound packet needs interactive user approval.
    AccessRequestCreated {
        request_id: String,
        src_device_id: String,
        src_user_id: Option<String>,
        src_device_display_name: Option<String>,
        src_user_display_name: Option<String>,
        proto: String,
        dst_port: u16,
        service_name: Option<String>,
    },
    /// A pending auth request expired.
    AccessRequestTimeout {
        request_id: String,
    },
    /// A pending auth request was answered (`AuthDecision`); `rule_id` is
    /// the rule created from the decision.  Added in protocol 0.3.
    AccessRequestResolved {
        request_id: String,
        decision: AuthDecision,
        rule_id: String,
    },

    // ── Peer lifecycle ──────────────────────────────────────────────────────
    /// A new peer was added to the local peer list.
    NodeAdded {
        device_id: String,
        ipv4: String,
        ipv6: String,
        hostname: Option<String>,
        display_name: Option<String>,
    },
    /// A peer was removed from the local peer list.
    NodeRemoved {
        device_id: String,
    },
    /// A peer's state changed (endpoints, path mode, display name, etc.).
    NodeStateChanged {
        device_id: String,
        change: serde_json::Value,
    },

    // ── Path events ─────────────────────────────────────────────────────────
    /// A peer's path mode changed (relay → probing → direct, etc.).
    PathChanged {
        device_id: String,
        old_mode: String,
        new_mode: String,
    },

    // ── ACL events ──────────────────────────────────────────────────────────
    /// A firewall rule was created, updated, or deleted.
    AclChanged {
        rule_id: String,
        action: String, // "created" | "updated" | "deleted"
    },
    /// A permission group was created, updated, or deleted.
    AclGroupChanged {
        group_id: String,
        action: String,
    },

    // ── Room events ─────────────────────────────────────────────────────────
    /// Room state update (peer list, relay, etc.).
    RoomStateChanged {
        room_id: Option<String>,
        room_name: Option<String>,
        peers: Vec<serde_json::Value>,
        relay: Option<String>,
    },

    // ── Identity / settings ─────────────────────────────────────────────────
    /// The local identity changed (display names, handles, hostname,
    /// assigned IPv4, authentication).  Carries the full new values; `null`
    /// = unset.  Added in protocol 0.3.
    IdentityChanged {
        device_id: String,
        user_id: String,
        device_handle: Option<String>,
        user_handle: Option<String>,
        device_display_name: Option<String>,
        user_display_name: Option<String>,
        device_hostname: Option<String>,
        is_authenticated: bool,
    },
    /// Settings changed.  `scope` = `"net"` (body as `GetNetSettings`) or
    /// `"ping"` (body `{"ping_enabled": bool}`).  Added in protocol 0.3.
    SettingsChanged {
        scope: String,
        settings: serde_json::Value,
    },

    // ── Authentication ──────────────────────────────────────────────────────
    /// The coordinator requires MSST access authentication.
    AccessAuthRequired {
        coordinator_url: String,
    },

    // ── Coordinator connection ──────────────────────────────────────────────
    /// WebSocket connection to coordinator changed state.
    CoordinatorConnectionChanged {
        connected: bool,
    },

    // ── Operations (0.4) ────────────────────────────────────────────────────
    /// Progress of an operation started with `async: true`.  `stage` is a
    /// short machine-readable step name (e.g. `relay_selected`).
    OperationProgress {
        operation_id: String,
        stage: String,
    },
    /// An operation started with `async: true` finished.  `result` is what
    /// the synchronous request would have returned.
    OperationCompleted {
        operation_id: String,
        /// The request's `type`, e.g. `"create_room"`.
        request_type: String,
        result: IpcResponse,
    },

    // ── Diagnostic ──────────────────────────────────────────────────────────
    /// A diagnostic event (log entry, performance metric, etc.).
    Diagnostic {
        level: String,
        target: String,
        message: String,
        timestamp_ms: u64,
    },
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: &IpcMessage) {
        let json = serde_json::to_string(msg).expect("serialize");
        let back: IpcMessage = serde_json::from_str(&json).expect("deserialize");
        // Compare via JSON strings (PartialEq isn't derived on serde_json::Value).
        let json_back = serde_json::to_string(&back).expect("re-serialize");
        assert_eq!(json, json_back, "round-trip mismatch for: {}", json);
    }

    // ── Request round-trips ─────────────────────────────────────────────────

    #[test]
    fn request_get_system_state() {
        roundtrip(&IpcMessage::Request {
            r#async: false,
            id: "req-1".into(),
            body: IpcRequest::GetSystemState,
        });
    }

    #[test]
    fn request_create_room() {
        roundtrip(&IpcMessage::Request {
            r#async: false,
            id: "req-2".into(),
            body: IpcRequest::CreateRoom {
                room_name: "test-room".into(),
                password: Some("secret".into()),
            },
        });
    }

    #[test]
    fn request_auth_decision() {
        roundtrip(&IpcMessage::Request {
            r#async: false,
            id: "req-3".into(),
            body: IpcRequest::AuthDecision {
                request_id: "auth-abc".into(),
                decision: AuthDecision::AlwaysAllow,
            },
        });
    }

    #[test]
    fn request_create_acl_rule() {
        roundtrip(&IpcMessage::Request {
            r#async: false,
            id: "req-4".into(),
            body: IpcRequest::CreateAclRule {
                rule: serde_json::json!({"action": "allow", "proto": "tcp", "port": 25565}),
            },
        });
    }

    // ── Response round-trips ────────────────────────────────────────────────

    #[test]
    fn response_ok() {
        roundtrip(&IpcMessage::Response {
            event_seq: None,
            id: "req-1".into(),
            body: IpcResponse::Ok(serde_json::json!({"status": "ok"})),
        });
    }

    #[test]
    fn response_error() {
        roundtrip(&IpcMessage::Response {
            event_seq: None,
            id: "req-2".into(),
            body: IpcResponse::Error(IpcError {
                code: "not_found".into(),
                message: "Peer not found".into(),
            }),
        });
    }

    // ── Event round-trips ───────────────────────────────────────────────────

    #[test]
    fn event_access_request() {
        roundtrip(&IpcMessage::Event {
            seq: None,
            body: IpcEvent::AccessRequestCreated {
                request_id: "r1".into(),
                src_device_id: "device-aabbccdd".into(),
                src_user_id: Some("usr-11223344".into()),
                src_device_display_name: Some("My PC".into()),
                src_user_display_name: Some("Alice".into()),
                proto: "tcp".into(),
                dst_port: 25565,
                service_name: Some("minecraft-java".into()),
            },
        });
    }

    #[test]
    fn event_node_added() {
        roundtrip(&IpcMessage::Event {
            seq: None,
            body: IpcEvent::NodeAdded {
                device_id: "device-deadbeef".into(),
                ipv4: "172.22.1.2".into(),
                ipv6: "fd22:2222:2222:2222::dead:beef".into(),
                hostname: Some("pc.example.ezplay.msst.net".into()),
                display_name: Some("Example PC".into()),
            },
        });
    }

    #[test]
    fn event_path_changed() {
        roundtrip(&IpcMessage::Event {
            seq: None,
            body: IpcEvent::PathChanged {
                device_id: "device-deadbeef".into(),
                old_mode: "relay".into(),
                new_mode: "direct".into(),
            },
        });
    }

    #[test]
    fn event_diagnostic() {
        roundtrip(&IpcMessage::Event {
            seq: None,
            body: IpcEvent::Diagnostic {
                level: "info".into(),
                target: "net::firewall".into(),
                message: "Allowed inbound TCP:25565".into(),
                timestamp_ms: 1700000000000,
            },
        });
    }

    // ── JSON structure verification ─────────────────────────────────────────

    #[test]
    fn request_json_has_kind_field() {
        let msg = IpcMessage::Request {
            r#async: false,
            id: "test".into(),
            body: IpcRequest::Health,
        };
        let json: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["kind"], "request");
        assert_eq!(json["id"], "test");
        assert_eq!(json["body"]["type"], "health");
    }

    #[test]
    fn response_json_has_kind_field() {
        let msg = IpcMessage::Response {
            event_seq: None,
            id: "test".into(),
            body: IpcResponse::Ok(serde_json::json!(true)),
        };
        let json: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["kind"], "response");
        assert_eq!(json["body"]["status"], "ok");
    }

    #[test]
    fn event_json_has_kind_field() {
        let msg = IpcMessage::Event {
            seq: None,
            body: IpcEvent::NodeRemoved {
                device_id: "device-00000000".into(),
            },
        };
        let json: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["kind"], "event");
        assert_eq!(json["body"]["type"], "node_removed");
    }

    // ── Version tests ───────────────────────────────────────────────────────

    #[test]
    fn version_encoding_roundtrip() {
        use crate::version::{decode_version, make_version};
        let v = make_version(1, 2, 3);
        let (maj, min, pat) = decode_version(v);
        assert_eq!((maj, min, pat), (1, 2, 3));
    }

    #[test]
    fn version_compatibility_same_major() {
        use crate::version::{is_compatible, make_version};
        assert!(is_compatible(make_version(0, 1, 0)));
        assert!(is_compatible(make_version(0, 99, 99)));
    }

    #[test]
    fn version_incompatibility_different_major() {
        use crate::version::{is_compatible, make_version};
        assert!(!is_compatible(make_version(1, 0, 0)));
    }

    // ── 0.4 envelope fields ─────────────────────────────────────────────────

    #[test]
    fn envelope_fields_are_optional_and_omitted_by_default() {
        // 0.3 frames (no async / event_seq / seq) still decode.
        let req: IpcMessage = serde_json::from_str(r#"{"kind":"request","id":"1","body":{"type":"health"}}"#).unwrap();
        assert!(matches!(req, IpcMessage::Request { r#async: false, .. }));
        let resp: IpcMessage = serde_json::from_str(r#"{"kind":"response","id":"1","body":{"status":"ok","data":{}}}"#).unwrap();
        assert!(matches!(resp, IpcMessage::Response { event_seq: None, .. }));
        // Defaults are not serialized, so 0.3 receivers see 0.3 frames.
        let json = serde_json::to_string(&IpcMessage::Request { id: "1".into(), body: IpcRequest::Health, r#async: false }).unwrap();
        assert_eq!(json, r#"{"kind":"request","id":"1","body":{"type":"health"}}"#);
    }

    #[test]
    fn envelope_fields_round_trip() {
        let json = r#"{"kind":"request","id":"1","body":{"type":"leave_room","params":{"room_id":"r"}},"async":true}"#;
        let m: IpcMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(m, IpcMessage::Request { r#async: true, .. }));
        assert_eq!(serde_json::to_string(&m).unwrap(), json);
        roundtrip(&IpcMessage::Response { id: "1".into(), body: IpcResponse::Ok(serde_json::json!({})), event_seq: Some(7) });
        let ev = IpcMessage::Event { body: IpcEvent::CoordinatorConnectionChanged { connected: true }, seq: Some(8) };
        assert!(serde_json::to_string(&ev).unwrap().contains(r#""seq":8"#));
        roundtrip(&ev);
    }

    #[test]
    fn operation_messages_round_trip() {
        roundtrip(&IpcMessage::Request { id: "1".into(), body: IpcRequest::GetOperation { operation_id: "op-1".into() }, r#async: false });
        roundtrip(&IpcMessage::Request { id: "2".into(), body: IpcRequest::SetLogStream { enabled: false }, r#async: false });
        roundtrip(&IpcMessage::Event { body: IpcEvent::OperationProgress { operation_id: "op-1".into(), stage: "relay_selected".into() }, seq: Some(1) });
        roundtrip(&IpcMessage::Event {
            body: IpcEvent::OperationCompleted {
                operation_id: "op-1".into(),
                request_type: "create_room".into(),
                result: IpcResponse::Error(IpcError { code: "relay_unavailable".into(), message: "x".into() }),
            },
            seq: Some(2),
        });
    }
}