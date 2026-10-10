//! Peer state with desired/observed separation.
//!
//! The Core maintains two views of each peer:
//!
//! - **Desired** — what *should* be true based on coordinator data, room
//!   membership, and user configuration.
//! - **Observed** — what *is* true based on actual network probes and packet
//!   exchange.
//!
//! The reconciliation loop compares desired vs observed and produces
//! [`Effect`](crate::Effect)s to close the gap.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Desired state  (authoritative: set by coordinator / room / user)
// ---------------------------------------------------------------------------

/// What Core *wants* a peer to be.
///
/// Set by coordinator WebSocket messages (`room_state`, `node_update`, etc.)
/// and by user commands (connect/disconnect).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerDesiredState {
    /// Whether this peer should be reachable at all.
    pub connected: bool,
    /// Whether the peer is currently in a shared room with us.
    pub in_room: bool,
    /// The peer's public key (from coordinator registration).
    pub public_key: Option<[u8; 32]>,
    /// The peer's IPv4 address (from coordinator).
    pub ipv4: Option<String>,
    /// The peer's IPv6 address (from coordinator).
    pub ipv6: Option<String>,
    /// Known endpoints (from coordinator announcements).
    pub endpoints: Vec<String>,
    /// The peer's display name.
    pub display_name: Option<String>,
    /// The peer's user display name.
    pub user_display_name: Option<String>,
    /// The peer's hostname (ezPlay).
    pub hostname: Option<String>,
    /// Whether the peer is authenticated via OIDC.
    pub is_authenticated: bool,
}

impl PeerDesiredState {
    /// A peer that should not be connected (default / removed).
    pub fn disconnected() -> Self {
        PeerDesiredState {
            connected: false,
            in_room: false,
            public_key: None,
            ipv4: None,
            ipv6: None,
            endpoints: Vec::new(),
            display_name: None,
            user_display_name: None,
            hostname: None,
            is_authenticated: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Observed state  (derived: set by network probes and packet exchange)
// ---------------------------------------------------------------------------

/// What Core *actually sees* for a peer.
///
/// Updated by the data plane: packet reception, P2P ping/pong, relay
/// keepalive, WireGuard handshake status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerObservedState {
    /// Whether we have recently received packets from this peer.
    pub reachable: bool,
    /// Current path mode.
    pub path_mode: ObservedPathMode,
    /// The active endpoint (if path mode is Direct).
    pub active_endpoint: Option<String>,
    /// EWMA RTT to this peer in milliseconds (via the active path).
    pub rtt_ms: Option<u64>,
    /// Packet loss rate in the current window (0.0 – 1.0, scaled to 0–1000 for integer representation).
    /// `None` means no data yet.
    pub loss_permille: Option<u16>,
    /// Unix timestamp of the last received packet from this peer.
    pub last_seen_unix: Option<i64>,
}

impl PeerObservedState {
    /// A peer we haven't heard from yet.
    pub fn unknown() -> Self {
        PeerObservedState {
            reachable: false,
            path_mode: ObservedPathMode::Unknown,
            active_endpoint: None,
            rtt_ms: None,
            loss_permille: None,
            last_seen_unix: None,
        }
    }
}

/// Observed path mode — mirrors the 3.0.x `PeerPathMode` but as data, not
/// behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedPathMode {
    /// No path information yet.
    Unknown,
    /// All traffic goes through the relay.
    Relay,
    /// Probing direct endpoints; data still via relay.
    Probing,
    /// Direct P2P connection is active.
    Direct,
}

// ---------------------------------------------------------------------------
// Combined peer state
// ---------------------------------------------------------------------------

/// A single peer's full state: desired + observed + metadata.
///
/// This is the unit of reconciliation: compare `desired` vs `observed` and
/// emit effects to close any gap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    /// Stable identifier (device-XXXXXXXX).
    pub device_id: String,
    /// The user who owns this device (usr-XXXXXXXX).
    pub user_id: Option<String>,
    /// What we want the peer to be.
    pub desired: PeerDesiredState,
    /// What we actually see.
    pub observed: PeerObservedState,
}

impl PeerState {
    /// Returns `true` if the peer's desired and observed states are
    /// consistent (no reconciliation needed).
    pub fn is_reconciled(&self) -> bool {
        // Minimal check: if desired is connected, observed should be reachable.
        // Full reconciliation logic lives in the Core runtime, not here.
        if self.desired.connected {
            self.observed.reachable
        } else {
            !self.observed.reachable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnected_desired_is_reconciled_when_not_reachable() {
        let peer = PeerState {
            device_id: "device-aabbccdd".into(),
            user_id: None,
            desired: PeerDesiredState::disconnected(),
            observed: PeerObservedState::unknown(),
        };
        assert!(peer.is_reconciled());
    }

    #[test]
    fn connected_desired_is_not_reconciled_when_unreachable() {
        let peer = PeerState {
            device_id: "device-aabbccdd".into(),
            user_id: None,
            desired: PeerDesiredState {
                connected: true,
                in_room: true,
                ..PeerDesiredState::disconnected()
            },
            observed: PeerObservedState::unknown(),
        };
        assert!(!peer.is_reconciled());
    }

    #[test]
    fn connected_desired_is_reconciled_when_reachable() {
        let peer = PeerState {
            device_id: "device-aabbccdd".into(),
            user_id: None,
            desired: PeerDesiredState {
                connected: true,
                ..PeerDesiredState::disconnected()
            },
            observed: PeerObservedState {
                reachable: true,
                ..PeerObservedState::unknown()
            },
        };
        assert!(peer.is_reconciled());
    }
}