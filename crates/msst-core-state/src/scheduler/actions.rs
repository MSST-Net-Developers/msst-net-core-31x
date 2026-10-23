//! Scheduler actions — the output of each scheduler tick.
//!
//! The `P2PScheduler` produces these actions.  The Core runtime executes
//! them (UDP sends, IPC events, endpoint reports, etc.).
//!
//! This separation keeps the scheduler pure and testable.

use std::net::SocketAddr;

/// An action the Core runtime should execute.
#[derive(Debug, Clone)]
pub enum SchedulerAction {
    /// Send a UDP packet to the given address (MSST frame or punch).
    UdpSend {
        data: Vec<u8>,
        target: SocketAddr,
    },
    /// A peer's path mode (or direct endpoint) changed.  Modes are
    /// `relay`, `probing` or `direct`; `endpoint` is the direct endpoint;
    /// `reason` is a [`PathChangeReason`](crate::net::path::PathChangeReason)
    /// wire name.
    PathModeChanged {
        peer_id: String,
        old_mode: String,
        new_mode: String,
        endpoint: Option<SocketAddr>,
        reason: Option<&'static str>,
    },
    /// Send relay-path probe `seq` to the peer inside its WireGuard session,
    /// over the relay route; feed the pong to `handle_pong`.
    RelayPathProbe {
        peer_id: String,
        seq: u32,
        sent_ms: u64,
    },
    /// Trigger STUN endpoint detection.
    DetectEndpoints,
    /// Report endpoints to the coordinator.
    ReportEndpoints {
        endpoints: Vec<String>,
    },
    /// Send an IPC event to the Controller.
    IpcEvent {
        event_json: String,
    },
}