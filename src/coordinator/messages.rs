//! Coordinator WebSocket message types.
//!
//! These types match the Coordinator 3.1.x `hub.go` protocol exactly.
//! Field names and JSON shapes are verified against the Go source.
//!
//! ## Notes
//!
//! - 3.0.x coordinators are not supported.
//! - `room_state_data` does NOT include a `relay` field (removed in 3.1.x
//!   coordinator).  The client should obtain relay info from `/relays`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// The WS message envelope (server → client).
///
/// Matches the Coordinator's `WSMessage` struct:
/// ```go
/// type WSMessage struct {
///     Type   string          `json:"type"`
///     RoomID string          `json:"room_id,omitempty"`
///     Data   json.RawMessage `json:"data,omitempty"`
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsEnvelope {
    #[serde(rename = "type")]
    pub msg_type: String,
    /// Room the message belongs to (top-level in `WSMessage`).
    #[serde(default)]
    pub room_id: Option<String>,
    #[serde(default)]
    pub data: Value,
}

/// The WS message envelope (client → server).
///
/// Matches the Coordinator's `clientMessage` struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub data: Value,
}

// ---------------------------------------------------------------------------
// Server → Client payloads
// ---------------------------------------------------------------------------

/// The `registered` message payload.
///
/// Matches `registeredPayload` in `hub.go`:
/// ```go
/// type registeredPayload struct {
///     Hostname        string `json:"hostname"`
///     IPv4            string `json:"ipv4"`
///     IPv6            string `json:"ipv6"`
///     UserHandle      string `json:"user_handle"`
///     UserDisplayName string `json:"user_display_name"`
/// }
/// ```
///
/// No field is `omitempty`, so all are required (empty when unset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredPayload {
    pub hostname: String,
    pub ipv4: String,
    pub ipv6: String,
    pub user_handle: String,
    pub user_display_name: String,
}

/// The `room_state` message payload.
///
/// Matches `roomStateData` in `hub.go`.
/// Note: the `relay` field is NOT present in 3.1.x coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomStateData {
    pub room_id: String,
    #[serde(default)]
    pub room_name: String,
    #[serde(default)]
    pub peers: Vec<RoomStatePeer>,
}

/// A peer in the `room_state` message.
///
/// Matches `roomStatePeer` in `hub.go`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomStatePeer {
    /// Empty if the coordinator left it out; such peers are dropped.
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub ipv6: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub user_display_name: Option<String>,
    #[serde(default)]
    pub device_display_name: Option<String>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub is_authenticated: bool,
}

/// The `node_added` / `node_updated` message payload.
///
/// Matches `nodeEventPayload` in `hub.go`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEvent {
    pub device_id: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    pub last_seen: i64,
    #[serde(default)]
    pub status: String,
}

/// The `member_joined` / `member_left` message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberEvent {
    /// Falls back to the envelope's `room_id` (`WSMessage.RoomID`).
    #[serde(default)]
    pub room_id: Option<String>,
    pub device_id: String,
}

/// The `member_joined` payload: the new member's full peer data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberJoinedData {
    #[serde(default)]
    pub room_id: Option<String>,
    #[serde(flatten)]
    pub peer: RoomStatePeer,
}

/// The `punch_request` message payload.
///
/// Matches `punchData` in `hub.go`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchRequest {
    pub peer_id: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
}

/// The `error` message payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub message: String,
    /// Machine-readable code (Coordinator keyproof v1; absent before).
    #[serde(default)]
    pub code: Option<String>,
}

// ---------------------------------------------------------------------------
// Client → Server payloads
// ---------------------------------------------------------------------------

/// The `register` message payload.
///
/// Matches `registerData` in `hub.go`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterData {
    pub device: RegisterDevice,
    pub user: RegisterUser,
    pub network: RegisterNetwork,
    pub meta: RegisterMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDevice {
    pub id: String,
    pub handle: String,
    pub pub_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterUser {
    pub id: String,
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterNetwork {
    pub ipv4: String,
    pub ipv6: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMeta {
    pub user_display_name: String,
    pub device_display_name: String,
}

/// The `join` / `leave` / `room_keepalive` message payload.
///
/// Matches `roomActionData` in `hub.go`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomAction {
    pub room_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
}