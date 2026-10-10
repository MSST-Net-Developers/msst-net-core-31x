//! Core metrics — Prometheus gauges and counters for all subsystems.
//!
//! All metrics are registered in a single `CoreMetrics` struct.
//! The struct is wrapped in `Arc` and shared across all tasks.
//!
//! ## Usage
//!
//! ```ignore
//! let metrics = Arc::new(CoreMetrics::new());
//! metrics.packets_received.with_label_values(&["data"]).inc();
//! metrics.peers_total.set(peer_count as i64);
//! ```

use prometheus::{
    opts, Gauge, GaugeVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Registry,
};

/// All Prometheus metrics for MSST-Net Core.
pub struct CoreMetrics {
    pub registry: Registry,

    // ── Peer state ────────────────────────────────────────────────────────
    pub peers_total: IntGauge,
    pub room_peers_total: IntGauge,
    pub acl_rules_total: IntGauge,

    // ── Packet counters ───────────────────────────────────────────────────
    pub packets_received: IntCounterVec,
    pub packets_sent: IntCounterVec,

    // ── ACL decisions ─────────────────────────────────────────────────────
    pub acl_decisions: IntCounterVec,

    // ── WireGuard ─────────────────────────────────────────────────────────
    pub wg_sessions_total: IntGauge,
    pub wg_handshakes: IntCounterVec,

    // ── Path modes ────────────────────────────────────────────────────────
    pub path_modes: IntGaugeVec,

    // ── IPC ───────────────────────────────────────────────────────────────
    pub ipc_connections: IntGauge,

    // ── Coordinator ───────────────────────────────────────────────────────
    pub coordinator_connected: IntGauge,

    // ── System ────────────────────────────────────────────────────────────
    pub generation: IntGauge,
    pub uptime_seconds: Gauge,
    pub scheduler_tick_duration_ms: Gauge,
}

impl CoreMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        // ── Peer state ────────────────────────────────────────────────────
        let peers_total = IntGauge::with_opts(opts!(
            "msst_core_peers_total",
            "Number of known peers in the peer list"
        )).unwrap();
        let room_peers_total = IntGauge::with_opts(opts!(
            "msst_core_room_peers_total",
            "Number of peers currently in the room"
        )).unwrap();
        let acl_rules_total = IntGauge::with_opts(opts!(
            "msst_core_acl_rules_total",
            "Number of active ACL rules"
        )).unwrap();

        // ── Packet counters ───────────────────────────────────────────────
        let packets_received = IntCounterVec::new(
            opts!("msst_core_packets_received_total", "Total inbound packets")
                .into(),
            &["type"],
        ).unwrap();
        let packets_sent = IntCounterVec::new(
            opts!("msst_core_packets_sent_total", "Total outbound packets")
                .into(),
            &["type"],
        ).unwrap();

        // ── ACL decisions ─────────────────────────────────────────────────
        let acl_decisions = IntCounterVec::new(
            opts!("msst_core_acl_decisions_total", "Total ACL decisions")
                .into(),
            &["decision"],
        ).unwrap();

        // ── WireGuard ─────────────────────────────────────────────────────
        let wg_sessions_total = IntGauge::with_opts(opts!(
            "msst_core_wg_sessions_total",
            "Number of active WireGuard sessions"
        )).unwrap();
        let wg_handshakes = IntCounterVec::new(
            opts!("msst_core_wg_handshakes_total", "WireGuard handshake outcomes")
                .into(),
            &["result"],
        ).unwrap();

        // ── Path modes ────────────────────────────────────────────────────
        let path_modes = IntGaugeVec::new(
            opts!("msst_core_path_modes", "Number of peers per path mode")
                .into(),
            &["mode"],
        ).unwrap();

        // ── IPC ───────────────────────────────────────────────────────────
        let ipc_connections = IntGauge::with_opts(opts!(
            "msst_core_ipc_connections",
            "Number of active IPC client connections"
        )).unwrap();

        // ── Coordinator ───────────────────────────────────────────────────
        let coordinator_connected = IntGauge::with_opts(opts!(
            "msst_core_coordinator_connected",
            "1 if Coordinator WebSocket is connected, 0 otherwise"
        )).unwrap();

        // ── System ────────────────────────────────────────────────────────
        let generation = IntGauge::with_opts(opts!(
            "msst_core_generation",
            "Current generation counter"
        )).unwrap();
        let uptime_seconds = Gauge::with_opts(opts!(
            "msst_core_uptime_seconds",
            "Process uptime in seconds"
        )).unwrap();
        let scheduler_tick_duration_ms = Gauge::with_opts(opts!(
            "msst_core_scheduler_tick_duration_ms",
            "Duration of the last scheduler tick in milliseconds"
        )).unwrap();

        // Register all metrics.
        let r = &registry;
        r.register(Box::new(peers_total.clone())).unwrap();
        r.register(Box::new(room_peers_total.clone())).unwrap();
        r.register(Box::new(acl_rules_total.clone())).unwrap();
        r.register(Box::new(packets_received.clone())).unwrap();
        r.register(Box::new(packets_sent.clone())).unwrap();
        r.register(Box::new(acl_decisions.clone())).unwrap();
        r.register(Box::new(wg_sessions_total.clone())).unwrap();
        r.register(Box::new(wg_handshakes.clone())).unwrap();
        r.register(Box::new(path_modes.clone())).unwrap();
        r.register(Box::new(ipc_connections.clone())).unwrap();
        r.register(Box::new(coordinator_connected.clone())).unwrap();
        r.register(Box::new(generation.clone())).unwrap();
        r.register(Box::new(uptime_seconds.clone())).unwrap();
        r.register(Box::new(scheduler_tick_duration_ms.clone())).unwrap();

        CoreMetrics {
            registry,
            peers_total,
            room_peers_total,
            acl_rules_total,
            packets_received,
            packets_sent,
            acl_decisions,
            wg_sessions_total,
            wg_handshakes,
            path_modes,
            ipc_connections,
            coordinator_connected,
            generation,
            uptime_seconds,
            scheduler_tick_duration_ms,
        }
    }

    /// Record an ACL decision.
    pub fn record_acl_decision(&self, decision: &str) {
        self.acl_decisions.with_label_values(&[decision]).inc();
    }

    /// Record an inbound packet.
    pub fn record_packet_received(&self, packet_type: &str) {
        self.packets_received.with_label_values(&[packet_type]).inc();
    }

    /// Record an outbound packet.
    pub fn record_packet_sent(&self, packet_type: &str) {
        self.packets_sent.with_label_values(&[packet_type]).inc();
    }

    /// Record a WG handshake result.
    pub fn record_wg_handshake(&self, success: bool) {
        let label = if success { "success" } else { "failure" };
        self.wg_handshakes.with_label_values(&[label]).inc();
    }

    /// Update path mode distribution from the scheduler.
    pub fn update_path_modes(&self, relay: i64, probing: i64, direct: i64) {
        self.path_modes.with_label_values(&["relay"]).set(relay);
        self.path_modes.with_label_values(&["probing"]).set(probing);
        self.path_modes.with_label_values(&["direct"]).set(direct);
    }
}

impl Default for CoreMetrics {
    fn default() -> Self {
        Self::new()
    }
}