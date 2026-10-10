//! P2P scheduler — orchestrates the full peer-to-peer lifecycle.
//!
//! This module ties together NAT traversal, path management, and data
//! routing into a single coherent scheduler that the Core runtime drives
//! on a 1-second tick.
//!
//! ## Responsibilities
//!
//! - Maintain per-peer `PeerPath` state machines
//! - Drive the path monitor (probe, keepalive, quality monitoring)
//! - Handle coordinator `punch_request` events
//! - Route outbound data packets (relay vs direct)
//! - Process inbound P2P pings and pongs
//! - Manage STUN endpoint detection schedule
//!
//! ## Design
//!
//! The `P2PScheduler` is a **pure state machine** — it takes inputs and
//! produces `SchedulerAction` values.  The Core runtime executes the
//! actions (UDP sends, IPC events, state updates).
//!
//! This separation means the scheduler is fully testable without real
//! network I/O.

pub mod actions;

use actions::SchedulerAction;
use crate::net::msst_packet;
use crate::net::path::{PeerPath, PeerPathMode};
use crate::nat::punch;
use crate::nat::stun;
use crate::p2p::{probe, router};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// P2PScheduler
// ---------------------------------------------------------------------------

/// The P2P connection scheduler.
///
/// Owns per-peer path state and produces actions for the runtime to execute.
pub struct P2PScheduler {
    /// Per-peer path state machines.
    paths: HashMap<String, PeerPath>,
    /// Local device ID (set during init).
    local_device_id: String,
    /// STUN detection interval (seconds).
    stun_interval_secs: i64,
    /// Last STUN detection timestamp (Unix seconds).
    last_stun_unix: i64,
    /// Keepalive interval (seconds).
    keepalive_secs: i64,
    /// Whether P2P is disabled (relay-only mode).
    disable_p2p: bool,
    /// Whether path mode is locked (no automatic switching).
    lock_path: bool,
    /// Monotonic sequence counter for pings.
    next_seq: u32,
}

impl P2PScheduler {
    pub fn new(local_device_id: String) -> Self {
        P2PScheduler {
            paths: HashMap::new(),
            local_device_id,
            stun_interval_secs: 300, // 5 minutes
            last_stun_unix: 0,
            keepalive_secs: 25,
            disable_p2p: false,
            lock_path: false,
            next_seq: 1,
        }
    }

    // ── Configuration ─────────────────────────────────────────────────────

    pub fn set_disable_p2p(&mut self, disable: bool) {
        self.disable_p2p = disable;
    }

    pub fn set_lock_path(&mut self, lock: bool) {
        self.lock_path = lock;
    }

    pub fn set_keepalive_secs(&mut self, secs: i64) {
        self.keepalive_secs = secs;
    }

    // ── Peer lifecycle ────────────────────────────────────────────────────

    /// Ensure a path entry exists for this peer.
    pub fn ensure_peer(&mut self, device_id: &str) {
        self.paths.entry(device_id.to_string()).or_insert_with(PeerPath::new);
    }

    /// Remove a peer's path state (on eviction or room leave).
    pub fn remove_peer(&mut self, device_id: &str) {
        self.paths.remove(device_id);
    }

    /// Get the current path mode for a peer.
    /// The network changed: let every non-direct path start probing again
    /// right away instead of waiting out its hold timer (3.0.x).
    pub fn clear_hold_timers(&mut self) {
        for pp in self.paths.values_mut() {
            if !pp.mode.is_direct() {
                pp.hold_until = 0;
            }
        }
    }

    /// Full path state of every tracked peer (diagnostics).
    pub fn paths(&self) -> impl Iterator<Item = (&str, &PeerPath)> {
        self.paths.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn path_mode(&self, device_id: &str) -> Option<&PeerPathMode> {
        self.paths.get(device_id).map(|pp| &pp.mode)
    }

    /// Number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.paths.len()
    }

    // ── Path monitor tick (1-second cycle) ────────────────────────────────

    /// Drive the path monitor for all peers.
    ///
    /// Called once per second by the Core runtime.  Returns a list of
    /// actions the runtime should execute (send packets, notify mode
    /// changes, trigger STUN).
    pub fn tick(
        &mut self,
        now_unix: i64,
        now_ms: u64,
        peer_endpoints: &HashMap<String, Vec<SocketAddr>>,
        peer_relays: &HashMap<String, SocketAddr>,
        relay_rtt: &HashMap<String, f64>,
    ) -> Vec<SchedulerAction> {
        let mut actions = Vec::new();

        // ── STUN re-detection ─────────────────────────────────────────────
        if now_unix - self.last_stun_unix >= self.stun_interval_secs {
            self.last_stun_unix = now_unix;
            actions.push(SchedulerAction::DetectEndpoints);
        }

        // ── Per-peer path processing ──────────────────────────────────────
        let peer_ids: Vec<String> = self.paths.keys().cloned().collect();
        for peer_id in peer_ids {
            let candidates = peer_endpoints
                .get(&peer_id)
                .cloned()
                .unwrap_or_default();

            let relay_rtt_ms = peer_relays
                .get(&peer_id)
                .and_then(|r| relay_rtt.get(&r.to_string()).copied());

            let pp = match self.paths.get_mut(&peer_id) {
                Some(p) => p,
                None => continue,
            };

            // Skip peers in Relay mode that have no candidates — nothing to do.
            // Skip peers already in Probing/Direct — probe_tick handles them.
            if matches!(pp.mode, PeerPathMode::Relay) && candidates.is_empty() {
                continue;
            }

            // Network settings (3.0.x semantics):
            // - disable_p2p: never start probing; abandon an ongoing probe.
            // - lock_path: freeze the path — no upgrade, no downgrade
            //   (a direct path keeps sending keepalives).
            match pp.mode {
                PeerPathMode::Relay if self.disable_p2p || self.lock_path => continue,
                PeerPathMode::Probing if self.disable_p2p => {
                    info!("disable_p2p: reverting {} from probing to relay", peer_id);
                    pp.set_relay(now_unix);
                    actions.push(SchedulerAction::PathModeChanged {
                        peer_id: peer_id.clone(),
                        old_mode: "probing".into(),
                        new_mode: "relay".into(),
                    });
                    continue;
                }
                PeerPathMode::Probing if self.lock_path => continue,
                _ => {}
            }
            let locked_snapshot = (self.lock_path && pp.mode.is_direct()).then(|| pp.clone());

            let old_mode = format!("{:?}", pp.mode);

            let probe_actions = probe::probe_tick(
                now_unix,
                now_ms,
                &self.local_device_id,
                &peer_id,
                pp,
                &candidates,
                relay_rtt_ms,
                self.keepalive_secs,
                peer_relays.get(&peer_id).copied(),
            );

            // Locked direct path: keep the keepalive/loss bookkeeping but undo
            // any downgrade decision.
            let probe_actions = match locked_snapshot {
                Some(snapshot) if !pp.mode.is_direct() => {
                    let mut kept = snapshot;
                    kept.loss_window = pp.loss_window.clone();
                    kept.consecutive_no_pong = pp.consecutive_no_pong;
                    *pp = kept;
                    probe_actions
                        .into_iter()
                        .filter(|a| matches!(a, probe::ProbeAction::SendPings { .. }))
                        .collect()
                }
                _ => probe_actions,
            };

            // Convert probe actions to scheduler actions.
            for pa in probe_actions {
                match pa {
                    probe::ProbeAction::SendPings { packets } => {
                        for (addr, pkt) in packets {
                            actions.push(SchedulerAction::UdpSend {
                                data: pkt,
                                target: addr,
                            });
                        }
                    }
                    probe::ProbeAction::ModeChanged { peer_id, old_mode, new_mode } => {
                        info!("P2P: {} mode changed {} → {}", peer_id, old_mode, new_mode);
                        actions.push(SchedulerAction::PathModeChanged {
                            peer_id,
                            old_mode,
                            new_mode,
                        });
                    }
                    probe::ProbeAction::DowngradeToRelay { peer_id } => {
                        warn!("P2P: {} downgraded to relay", peer_id);
                    }
                }
            }
        }

        actions
    }

    // ── Punch request handling ────────────────────────────────────────────

    /// Handle a coordinator `punch_request` event.
    ///
    /// Returns actions to send punch packets and start probing.
    pub fn handle_punch_request(
        &mut self,
        peer_id: &str,
        endpoints: &[SocketAddr],
        now_unix: i64,
        now_ms: u64,
    ) -> Vec<SchedulerAction> {
        let mut actions = Vec::new();

        // Ensure path entry exists.
        self.ensure_peer(peer_id);

        // Start probing (transitions from Relay → Probing, clears pending_pings).
        if let Some(pp) = self.paths.get_mut(peer_id) {
            if !pp.mode.is_direct() && !self.disable_p2p && !self.lock_path {
                pp.start_probing(endpoints.to_vec(), now_unix);
                // Coordinator-triggered probe: upgrade as soon as the
                // criteria are met (3.0.x `trigger_probe`).
                pp.hold_until = 0;
                info!("P2P: started probing {} after punch ({} candidate(s))", peer_id, endpoints.len());
            }
        }

        // Hole-punching packets.  Not tracked as probes: the first packets
        // through a NAT are commonly dropped, and that must not count as
        // probe failures — the regular probe pings follow on the next tick.
        let mut pkts = Vec::new();
        if let Some(pp) = self.paths.get_mut(peer_id) {
            for &endpoint in endpoints {
                for _ in 0..3 {
                    let seq = pp.next_seq;
                    pp.next_seq = pp.next_seq.wrapping_add(1);
                    let pkt = msst_packet::build_p2p_ping(
                        &self.local_device_id, peer_id, seq, now_ms,
                    );
                    pkts.push((endpoint, pkt));
                }
            }
        }

        for (addr, pkt) in pkts {
            actions.push(SchedulerAction::UdpSend { data: pkt, target: addr });
        }

        actions
    }

    // ── Pong processing ───────────────────────────────────────────────────

    /// Process a P2P pong received from a peer.
    ///
    /// Returns actions if the path mode changed.
    pub fn handle_pong(
        &mut self,
        peer_id: &str,
        src: SocketAddr,
        seq: u32,
        rtt_ms: f64,
        relay_rtt_ms: Option<f64>,
        now_unix: i64,
    ) -> Vec<SchedulerAction> {
        let mut actions = Vec::new();

        if let Some(pp) = self.paths.get_mut(peer_id) {
            // A frozen non-direct path must not be upgraded by a late pong.
            if self.lock_path && !pp.mode.is_direct() {
                return actions;
            }
            let old_mode = format!("{:?}", pp.mode);
            let changed = probe::process_pong(
                peer_id, pp, src, seq, rtt_ms, relay_rtt_ms, now_unix,
            );
            if changed {
                let new_mode = format!("{:?}", pp.mode);
                info!("P2P: {} upgraded {} → {}", peer_id, old_mode, new_mode);
                actions.push(SchedulerAction::PathModeChanged {
                    peer_id: peer_id.to_string(),
                    old_mode,
                    new_mode,
                });
            }
        }

        actions
    }

    // ── Outbound routing ──────────────────────────────────────────────────

    /// Route an outbound data packet to the correct destination.
    ///
    /// Returns the target address and the MSST data frame to send.
    /// This is the MSST-framed path (relay or direct without WG).
    pub fn route_outbound(
        &self,
        dst_device_id: &str,
        ip_payload: &[u8],
        peer_relay: Option<SocketAddr>,
        own_relay: Option<SocketAddr>,
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let mode = self.paths.get(dst_device_id).map(|pp| pp.mode.clone());
        let mode = mode.unwrap_or(PeerPathMode::Relay);

        let target = router::route_outbound(&mode, peer_relay, own_relay);

        match target {
            router::RouteTarget::Direct { endpoint } => {
                let frame = router::build_data_frame(&self.local_device_id, dst_device_id, ip_payload);
                Some((endpoint, frame))
            }
            router::RouteTarget::Relay { relay_addr } => {
                let frame = router::build_data_frame(&self.local_device_id, dst_device_id, ip_payload);
                Some((relay_addr, frame))
            }
            router::RouteTarget::NoRoute => None,
        }
    }

    /// Route an outbound packet via WireGuard encryption.
    ///
    /// Returns `Some((endpoint, wg_ciphertext))` if:
    /// - The path is in Direct mode (we have a known endpoint)
    /// - The caller has a WG session for this peer
    ///
    /// Returns `None` if WG direct routing is not available (caller
    /// should fall back to MSST-framed routing).
    pub fn route_outbound_wg(
        &self,
        dst_device_id: &str,
    ) -> Option<SocketAddr> {
        match self.paths.get(dst_device_id).map(|pp| &pp.mode) {
            Some(PeerPathMode::Direct { endpoint }) => Some(*endpoint),
            _ => None,
        }
    }

    // ── STUN response handling ────────────────────────────────────────────

    /// Handle a STUN response (parsed public address).
    ///
    /// Returns an action to report the endpoint to the coordinator.
    pub fn handle_stun_response(
        &self,
        public_addr: SocketAddr,
        lan_ips: &[std::net::Ipv4Addr],
        relay_addr: Option<&str>,
    ) -> Vec<SchedulerAction> {
        let mut endpoints = vec![public_addr.to_string()];

        for ip in lan_ips {
            endpoints.push(format!("{}:{}", ip, 21031));
        }

        if let Some(relay) = relay_addr {
            endpoints.push(format!("relay:{}", relay));
        }

        vec![SchedulerAction::ReportEndpoints { endpoints }]
    }
}

impl PeerPathMode {
    fn is_direct(&self) -> bool {
        matches!(self, PeerPathMode::Direct { .. })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
    }

    fn make_scheduler() -> P2PScheduler {
        P2PScheduler::new("device-aabbccdd".to_string())
    }

    // ── Peer lifecycle ────────────────────────────────────────────────────

    #[test]
    fn new_scheduler_is_empty() {
        let s = make_scheduler();
        assert_eq!(s.peer_count(), 0);
    }

    #[test]
    fn ensure_peer_creates_entry() {
        let mut s = make_scheduler();
        s.ensure_peer("device-11223344");
        assert_eq!(s.peer_count(), 1);
        assert!(s.path_mode("device-11223344").is_some());
    }

    #[test]
    fn ensure_peer_idempotent() {
        let mut s = make_scheduler();
        s.ensure_peer("device-11223344");
        s.ensure_peer("device-11223344");
        assert_eq!(s.peer_count(), 1);
    }

    #[test]
    fn remove_peer() {
        let mut s = make_scheduler();
        s.ensure_peer("device-11223344");
        s.remove_peer("device-11223344");
        assert_eq!(s.peer_count(), 0);
    }

    // ── Punch request ─────────────────────────────────────────────────────

    #[test]
    fn punch_request_creates_path_and_sends() {
        let mut s = make_scheduler();
        let endpoints = vec![v4(1, 2, 3, 4, 21031)];
        let actions = s.handle_punch_request("device-11223344", &endpoints, 1000, 1_000_000);

        // Should have punch packets (3 per endpoint).
        let udp_count = actions.iter().filter(|a| matches!(a, SchedulerAction::UdpSend { .. })).count();
        assert!(udp_count >= 3);

        // Peer should be in Probing mode.
        assert!(matches!(
            s.path_mode("device-11223344"),
            Some(PeerPathMode::Probing)
        ));
    }

    #[test]
    fn punch_request_disabled_p2p_stays_relay() {
        let mut s = make_scheduler();
        s.set_disable_p2p(true);
        let endpoints = vec![v4(1, 2, 3, 4, 21031)];
        let _ = s.handle_punch_request("device-11223344", &endpoints, 1000, 1_000_000);

        assert!(matches!(
            s.path_mode("device-11223344"),
            Some(PeerPathMode::Relay)
        ));
    }

    // ── Tick (path monitor) ───────────────────────────────────────────────

    fn peer_eps() -> HashMap<String, Vec<SocketAddr>> {
        [("device-11223344".to_string(), vec![v4(1, 2, 3, 4, 21031)])].into()
    }

    #[test]
    fn tick_disable_p2p_or_lock_path_never_starts_probing() {
        for (disable, lock) in [(true, false), (false, true)] {
            let mut s = make_scheduler();
            s.set_disable_p2p(disable);
            s.set_lock_path(lock);
            s.ensure_peer("device-11223344");
            let _ = s.tick(1000, 1_000_000, &peer_eps(), &HashMap::new(), &HashMap::new());
            assert!(matches!(s.path_mode("device-11223344"), Some(PeerPathMode::Relay)));
        }
    }

    #[test]
    fn tick_disable_p2p_reverts_probing() {
        let mut s = make_scheduler();
        s.ensure_peer("device-11223344");
        let _ = s.tick(1000, 1_000_000, &peer_eps(), &HashMap::new(), &HashMap::new());
        assert!(matches!(s.path_mode("device-11223344"), Some(PeerPathMode::Probing)));
        s.set_disable_p2p(true);
        let actions = s.tick(1001, 1_001_000, &peer_eps(), &HashMap::new(), &HashMap::new());
        assert!(matches!(s.path_mode("device-11223344"), Some(PeerPathMode::Relay)));
        assert!(actions.iter().any(|a| matches!(a, SchedulerAction::PathModeChanged { new_mode, .. } if new_mode == "relay")));
    }

    #[test]
    fn tick_lock_path_keeps_direct_path_despite_losses() {
        let mut s = make_scheduler();
        s.ensure_peer("device-11223344");
        let ep = v4(1, 2, 3, 4, 21031);
        s.paths.get_mut("device-11223344").unwrap().set_direct(ep, 0);
        s.set_keepalive_secs(1); // 3.0.x default P2P keepalive
        s.set_lock_path(true);
        // Many ticks with no pongs: unlocked this would downgrade.
        let mut sent = 0;
        for i in 0..60i64 {
            let actions = s.tick(1000 + i, 1_000_000 + (i as u64) * 1000, &peer_eps(), &HashMap::new(), &HashMap::new());
            sent += actions.iter().filter(|a| matches!(a, SchedulerAction::UdpSend { .. })).count();
        }
        assert!(matches!(s.path_mode("device-11223344"), Some(PeerPathMode::Direct { .. })));
        assert!(sent > 0, "keepalives still sent");

        // Same scenario unlocked → the direct path is abandoned (downgrade,
        // then re-probing since a candidate exists).
        s.set_lock_path(false);
        let mut downgraded = false;
        for i in 60..120i64 {
            let actions = s.tick(1000 + i, 1_000_000 + (i as u64) * 1000, &peer_eps(), &HashMap::new(), &HashMap::new());
            downgraded |= actions.iter().any(|a| matches!(a, SchedulerAction::PathModeChanged { old_mode, .. } if old_mode == "direct"));
        }
        assert!(downgraded);
        assert!(!matches!(s.path_mode("device-11223344"), Some(PeerPathMode::Direct { .. })));
    }

    #[test]
    fn tick_with_no_peers_returns_stun_only() {
        let mut s = make_scheduler();
        s.last_stun_unix = 0; // force STUN
        let actions = s.tick(300, 300_000, &HashMap::new(), &HashMap::new(), &HashMap::new());
        assert!(actions.iter().any(|a| matches!(a, SchedulerAction::DetectEndpoints)));
    }

    #[test]
    fn tick_starts_probing_for_relay_peer_with_candidates() {
        let mut s = make_scheduler();
        s.ensure_peer("device-11223344");

        let mut endpoints = HashMap::new();
        endpoints.insert("device-11223344".to_string(), vec![v4(1, 2, 3, 4, 21031)]);

        let actions = s.tick(1000, 1_000_000, &endpoints, &HashMap::new(), &HashMap::new());

        // Should transition to Probing and send probe pings.
        assert!(matches!(
            s.path_mode("device-11223344"),
            Some(PeerPathMode::Probing)
        ));
        let udp_count = actions.iter().filter(|a| matches!(a, SchedulerAction::UdpSend { .. })).count();
        assert!(udp_count > 0);
    }

    // ── Outbound routing ──────────────────────────────────────────────────

    #[test]
    fn route_outbound_direct() {
        let mut s = make_scheduler();
        s.ensure_peer("device-11223344");
        // Force direct mode.
        if let Some(pp) = s.paths.get_mut("device-11223344") {
            pp.set_direct(v4(1, 2, 3, 4, 12345), 1000);
        }

        let result = s.route_outbound(
            "device-11223344",
            &[1, 2, 3],
            None,
            Some(v4(5, 6, 7, 8, 21031)),
        );
        let (addr, frame) = result.unwrap();
        assert_eq!(addr, v4(1, 2, 3, 4, 12345));
        let pkt = msst_packet::MsstPacket::decode(&frame).unwrap();
        assert_eq!(pkt.packet_type, msst_packet::TYPE_DATA);
    }

    #[test]
    fn route_outbound_relay() {
        let s = make_scheduler();
        // No path entry → default Relay.
        let result = s.route_outbound(
            "device-11223344",
            &[1, 2, 3],
            Some(v4(5, 6, 7, 8, 21031)),
            None,
        );
        let (addr, _) = result.unwrap();
        assert_eq!(addr, v4(5, 6, 7, 8, 21031));
    }

    #[test]
    fn route_outbound_no_route() {
        let s = make_scheduler();
        let result = s.route_outbound("device-11223344", &[1, 2, 3], None, None);
        assert!(result.is_none());
    }

    // ── STUN ──────────────────────────────────────────────────────────────

    #[test]
    fn handle_stun_response_reports_endpoints() {
        let s = make_scheduler();
        let actions = s.handle_stun_response(
            v4(203, 0, 113, 1, 21031),
            &[Ipv4Addr::new(192, 168, 1, 100)],
            Some("1.2.3.4:21031"),
        );
        match &actions[0] {
            SchedulerAction::ReportEndpoints { endpoints } => {
                assert_eq!(endpoints.len(), 3); // STUN + LAN + relay
                assert!(endpoints.contains(&"203.0.113.1:21031".to_string()));
                assert!(endpoints.contains(&"192.168.1.100:21031".to_string()));
                assert!(endpoints.contains(&"relay:1.2.3.4:21031".to_string()));
            }
            _ => panic!("expected ReportEndpoints"),
        }
    }

    // ── Full lifecycle ────────────────────────────────────────────────────

    #[test]
    fn full_lifecycle_punch_probe_pong_direct() {
        let mut s = make_scheduler();
        let peer = "device-11223344";
        let ep = v4(172, 22, 2, 1, 12345);

        // 1. Punch request → starts probing + sends punch packets.
        let _ = s.handle_punch_request(peer, &[ep], 1000, 1_000_000);
        assert!(matches!(s.path_mode(peer), Some(PeerPathMode::Probing)));

        // 2. Collect enough pongs across multiple ticks to reach MIN_PROBE_OK (5).
        let mut endpoints = HashMap::new();
        endpoints.insert(peer.to_string(), vec![ep]);
        let hold_until = s.paths.get(peer).unwrap().hold_until;
        let after_hold = hold_until + 1;

        // Run ticks and send pongs for each tick's new pings.
        let mut total_ok = 0u32;
        for tick_t in 1001..1010 {
            let actions = s.tick(tick_t, (tick_t * 1000) as u64, &endpoints, &HashMap::new(), &HashMap::new());
            // Extract seqs from sent pings.
            let sent_seqs: Vec<u32> = actions.iter().filter_map(|a| {
                if let SchedulerAction::UdpSend { data, .. } = a {
                    let pkt = msst_packet::MsstPacket::decode(data)?;
                    let (seq, _) = msst_packet::decode_ping_payload(&pkt.payload)?;
                    Some(seq)
                } else {
                    None
                }
            }).collect();
            // Send pongs for all sent pings.
            for seq in &sent_seqs {
                let _ = s.handle_pong(peer, ep, *seq, 15.0, Some(30.0), after_hold);
                total_ok += 1;
            }
            if matches!(s.path_mode(peer), Some(PeerPathMode::Direct { .. })) {
                break;
            }
        }
        assert!(
            matches!(s.path_mode(peer), Some(PeerPathMode::Direct { .. })),
            "expected Direct after {} pongs, got {:?}",
            total_ok,
            s.path_mode(peer)
        );
    }
}