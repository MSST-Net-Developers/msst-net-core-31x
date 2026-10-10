//! Effect types — side effects that the Core decides but does not execute.
//!
//! The Core's state machine produces `Effect` values.  An *effect executor*
//! (a separate component) translates these into actual OS operations:
//! WireGuard configuration, route table changes, DNS updates, etc.
//!
//! This separation means the Core logic is testable without real network
//! interfaces (AGENTS.md §3.4).

use serde::{Deserialize, Serialize};

/// A side effect that the Core has decided should happen.
///
/// Effects are the output of `(State, Event) → (NewState, Effects)`.
/// The Core never executes them directly — it hands them to an effect
/// executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "params", rename_all = "snake_case")]
pub enum Effect {
    // ── WireGuard ───────────────────────────────────────────────────────────
    /// Add a WireGuard peer session.
    WgAddPeer {
        device_id: String,
        public_key: [u8; 32],
        endpoint: Option<String>,
        allowed_ips: Vec<String>,
    },
    /// Remove a WireGuard peer session.
    WgRemovePeer { device_id: String },
    /// Update a WireGuard peer's endpoint (e.g. after NAT rebinding).
    WgUpdateEndpoint { device_id: String, endpoint: String },

    // ── TUN / routing ───────────────────────────────────────────────────────
    /// Inject a raw IP packet into the TUN interface.
    TunInject { packet: Vec<u8> },
    /// Update the TUN route table (add/remove peer subnet routes).
    RouteUpdate {
        device_id: String,
        ipv4: Option<String>,
        ipv6: Option<String>,
        action: RouteAction,
    },

    // ── Relay ───────────────────────────────────────────────────────────────
    /// Send a UDP packet to a specific address.
    UdpSend { data: Vec<u8>, target: String },
    /// Register with a relay server.
    RelayRegister { address: String },

    // ── Coordinator ─────────────────────────────────────────────────────────
    /// Send a WebSocket message to the coordinator.
    CoordinatorSend { message: serde_json::Value },
    /// Connect/reconnect the coordinator WebSocket.
    CoordinatorConnect,

    // ── STUN / endpoint detection ───────────────────────────────────────────
    /// Trigger STUN endpoint detection.
    DetectEndpoints,
    /// Report endpoints to the coordinator.
    ReportEndpoints { endpoints: Vec<String> },

    // ── DNS ─────────────────────────────────────────────────────────────────
    /// Configure system split-DNS for the TUN interface.
    DnsConfigure { interface: String },
    /// Revert system DNS configuration.
    DnsRevert { interface: String },

    // ── IPC (push to Controller) ────────────────────────────────────────────
    /// Send an IPC event to the Controller.
    IpcNotify { event: crate::effect::IpcNotifyEvent },
}

/// Route table action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Add,
    Remove,
}

/// Simplified IPC event payload for Effect::IpcNotify.
///
/// This is intentionally a subset of `msst_ipc_protocol::IpcEvent` — the
/// Core state crate doesn't depend on the IPC protocol crate.  The effect
/// executor maps these to the full IPC event type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IpcNotifyEvent {
    AccessRequestCreated {
        request_id: String,
        src_device_id: String,
        proto: String,
        dst_port: u16,
    },
    AccessRequestTimeout {
        request_id: String,
    },
    NodeAdded {
        device_id: String,
    },
    NodeRemoved {
        device_id: String,
    },
    PathChanged {
        device_id: String,
        old_mode: String,
        new_mode: String,
    },
    AclChanged {
        rule_id: String,
        action: String,
    },
    RoomStateChanged {
        room_id: Option<String>,
    },
    AccessAuthRequired {
        coordinator_url: String,
    },
    CoordinatorConnectionChanged {
        connected: bool,
    },
}