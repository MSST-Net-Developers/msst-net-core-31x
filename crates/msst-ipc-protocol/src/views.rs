//! Typed response bodies (protocol 0.4, first batch).
//!
//! `IpcResponse::Ok` still carries JSON, so these types change nothing on
//! the wire; they document the shapes and let Core and Controllers share
//! one definition.  Core builds these responses from the types; the
//! contract vectors are decoded with them (`tests/vectors.rs`).
//!
//! Typed so far: `Health`, `GetNodes`, `GetNode`, the `async` accepted
//! response and `GetOperation`.  The other responses are still free-form
//! JSON (see the vectors) and move here over time.

use crate::{IpcResponse, Role};
use serde::{Deserialize, Serialize};

/// `Health`.  Unset names/handles are `null`, not `""`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Health {
    /// Always `"ok"`.
    pub status: String,
    pub generation: u64,
    /// This connection's permission tier (0.4).
    pub ipc_role: Role,
    pub device_id: Option<String>,
    pub user_id: Option<String>,
    pub device_handle: Option<String>,
    pub user_handle: Option<String>,
    pub user_display_name: Option<String>,
    pub device_display_name: Option<String>,
    pub device_hostname: Option<String>,
    pub is_authenticated: bool,
    pub auth_expires_at: Option<i64>,
    pub ws_connected: bool,
    /// Coordinator connection state, e.g. `"Connected"`, `"AuthRequired"`.
    pub coordinator_state: String,
    /// Credential the Coordinator connection uses: `"oidc"`, `"guest"` (no
    /// valid MSST login: room mode only) or `"none"` (disconnected, or a
    /// Coordinator without guest tokens).
    pub coordinator_credential: String,
    pub tun_ready: bool,
    pub access_auth_required: bool,
    pub relay: Option<String>,
    pub peer_count: u64,
    pub rule_count: u64,
    pub ping_enabled: bool,
}

/// One node in `GetNodes`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeSummary {
    pub device_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub hostname: Option<String>,
    pub display_name: Option<String>,
    pub user_id: Option<String>,
    pub user_handle: Option<String>,
    pub device_handle: Option<String>,
    pub is_authenticated: bool,
}

/// `GetNodes`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Nodes {
    pub nodes: Vec<NodeSummary>,
}

/// `GetNode`: the summary plus the peer's relay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeDetail {
    #[serde(flatten)]
    pub node: NodeSummary,
    pub preferred_relay: Option<String>,
}

/// Response to a command sent with `async: true`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationAccepted {
    pub operation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Running,
    Completed,
}

/// `GetOperation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationView {
    pub operation_id: String,
    /// The request's `type`, e.g. `"create_room"`.
    pub request_type: String,
    pub status: OperationStatus,
    /// Last reported step (`OperationProgress`), while running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// What the synchronous request would have returned, once completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<IpcResponse>,
    /// Unix seconds.
    pub started_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<i64>,
}

impl IpcResponse {
    /// `Ok` with a typed body.
    pub fn ok<T: Serialize>(body: &T) -> Self {
        match serde_json::to_value(body) {
            Ok(v) => IpcResponse::Ok(v),
            Err(e) => IpcResponse::Error(crate::IpcError { code: "invalid_request".into(), message: format!("serialize: {}", e) }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_detail_is_flat() {
        let d = NodeDetail {
            node: NodeSummary {
                device_id: "device-0000000b".into(),
                ipv4: "172.22.1.1".into(),
                ipv6: "fd22::b".into(),
                hostname: None,
                display_name: None,
                user_id: None,
                user_handle: None,
                device_handle: None,
                is_authenticated: true,
            },
            preferred_relay: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["device_id"], "device-0000000b");
        assert!(v["preferred_relay"].is_null() && v.get("node").is_none());
        assert_eq!(serde_json::from_value::<NodeDetail>(v).unwrap(), d);
    }

    #[test]
    fn operation_view_omits_absent_fields() {
        let v = OperationView {
            operation_id: "op-1".into(),
            request_type: "create_room".into(),
            status: OperationStatus::Running,
            stage: None,
            result: None,
            started_at: 1,
            finished_at: None,
        };
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            r#"{"operation_id":"op-1","request_type":"create_room","status":"running","started_at":1}"#
        );
    }
}
