//! Per-peer path state machine.
//!
//! Manages the path selection for each peer:
//!
//! ```text
//! Relay ──(candidates, backoff elapsed)───────────► Probing
//!   ▲  ▲                                                │
//!   │  └──(all fail after hold → backoff)───────────────┤
//!   │                                                   │ (≥5 ok pongs, rtt ≤ relay)
//!   │ (no pong / loss / sustained RTT spike)            ▼
//!   └──────────────────────────────────────────────── Direct ⟲ (better candidate)
//! ```
//!
//! Mode names on the wire (IPC `PathChanged`, path view, metrics) are
//! [`PeerPathMode::name`]: `relay`, `probing`, `direct`.
//!
//! The path state is pure data — the actual probing/keepalive logic lives
//! in the runtime's path monitor loop.  This module provides:
//! - `PeerPathMode` — the current mode
//! - `PeerPath` — per-peer state (mode, probe stats, RTT, loss)
//! - Transition helpers with hold timers and quality thresholds

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

// ── Constants ─────────────────────────────────────────────────────────────

/// Minimum time to remain in any mode after a transition (seconds).
pub const HOLD_DURATION_SECS: i64 = 30;
/// How long to wait for a probe/keepalive pong before counting a miss (ms).
pub const PING_TIMEOUT_MS: u64 = 2000;
/// Consecutive missed pings before abandoning a probe candidate.
pub const MAX_PROBE_MISS: u8 = 3;
/// Consecutive missed keepalives before downgrading from Direct.
pub const MAX_CONSECUTIVE_NO_PONG: u8 = 3;
/// Rolling window size for packet-loss rate calculation.
pub const LOSS_WINDOW_SIZE: usize = 20;
/// Loss rate above this triggers downgrade (after hold expires).
pub const LOSS_RATE_THRESHOLD: f64 = 0.20;
/// RTT spike factor: current > baseline * factor counts as a spike.
pub const RTT_SPIKE_FACTOR: f64 = 3.0;
/// Consecutive spikes before downgrading (one sample is just jitter).
pub const RTT_SPIKE_CONSECUTIVE: u8 = 3;
/// Minimum RTT baseline for spike detection (ms).
pub const RTT_MIN_BASELINE_MS: f64 = 5.0;
/// EWMA smoothing factor for RTT (TCP-style).
pub const RTT_EWMA_ALPHA: f64 = 0.125;
/// Minimum consecutive successful probes before upgrading to Direct.
pub const MIN_PROBE_OK: u32 = 5;
/// P2P RTT must be ≤ this fraction of relay RTT to upgrade.
pub const UPGRADE_RTT_FACTOR: f64 = 1.0;
/// While probing, measure the end-to-end relay path RTT this often (3.0.x).
pub const RELAY_PATH_PROBE_INTERVAL_MS: u64 = 2000;
/// While direct, probe the other candidates this often (3.0.x).
pub const BG_PROBE_INTERVAL_MS: u64 = 5000;
/// Switch to another direct candidate when its RTT is at most this
/// fraction of the active one's.
pub const SWITCH_RTT_FACTOR: f64 = 0.5;
/// After a probe round in which every candidate failed, wait this long
/// before probing again; doubled per further failed round …
pub const PROBE_BACKOFF_BASE_SECS: i64 = 30;
/// … up to this.
pub const PROBE_BACKOFF_MAX_SECS: i64 = 600;

/// Whether `addr` is a private (RFC 1918) LAN address.  A responding LAN
/// candidate is always preferred over the relay (3.0.x `is_lan_endpoint`).
pub fn is_lan_endpoint(addr: SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        std::net::IpAddr::V6(_) => false,
    }
}

// ── PeerPathMode ──────────────────────────────────────────────────────────

/// The current path mode for a peer.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerPathMode {
    /// All traffic goes through the relay server.
    Relay,
    /// Probing direct endpoints; data still via relay.
    Probing,
    /// Direct P2P connection is active.
    Direct { endpoint: SocketAddr },
}

impl PeerPathMode {
    /// The mode's wire name: `relay`, `probing` or `direct`.
    pub fn name(&self) -> &'static str {
        match self {
            PeerPathMode::Relay => "relay",
            PeerPathMode::Probing => "probing",
            PeerPathMode::Direct { .. } => "direct",
        }
    }

    /// The active endpoint in Direct mode.
    pub fn endpoint(&self) -> Option<SocketAddr> {
        match self {
            PeerPathMode::Direct { endpoint } => Some(*endpoint),
            _ => None,
        }
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, PeerPathMode::Direct { .. })
    }
}

// ── PeerPath ──────────────────────────────────────────────────────────────

/// Per-peer path state.
#[derive(Debug, Clone)]
pub struct PeerPath {
    pub mode: PeerPathMode,
    /// No proactive upgrades before this timestamp (Unix seconds).
    pub hold_until: i64,

    // ── Probing state ─────────────────────────────────────────────────────
    /// Candidate endpoints sorted IPv6-first.
    pub probe_candidates: Vec<SocketAddr>,
    /// Per-candidate consecutive successful probe count.
    pub probe_consecutive_ok: HashMap<SocketAddr, u32>,
    /// Per-candidate EWMA RTT (ms).
    pub probe_rtt_ms: HashMap<SocketAddr, f64>,
    /// Per-candidate consecutive miss count.
    pub probe_miss: HashMap<SocketAddr, u8>,
    /// Pending probe pings: seq → (target_addr, sent_at_ms).
    pub pending_pings: HashMap<u32, (SocketAddr, u64)>,

    // ── Direct mode quality monitoring ────────────────────────────────────
    /// Rolling window of recent pong results (true = received, false = lost).
    pub loss_window: VecDeque<bool>,
    /// Consecutive keepalive pongs missed.
    pub consecutive_no_pong: u8,
    /// Consecutive RTT spikes on the active endpoint.
    pub consecutive_spikes: u8,
    /// EWMA RTT baseline (ms) for the active direct path.
    pub rtt_baseline_ms: Option<f64>,
    /// Sequence counter for pings.
    pub next_seq: u32,
    /// Last keepalive sent timestamp (ms).
    pub last_keepalive_sent_ms: u64,
    /// Last background probe sent timestamp (ms).
    pub last_bg_probe_sent_ms: u64,

    // ── Relay-path probing ────────────────────────────────────────────────
    /// Pending relay-path probe pings: seq → sent_at_ms.
    pub relay_path_pending: HashSet<u32>,
    /// EWMA relay-path RTT (us → relay → peer → relay → us).
    pub relay_path_rtt_ms: Option<f64>,
    /// Last relay-path probe sent (ms).
    pub last_relay_path_probe_ms: u64,

    // ── Probe backoff (bounded retries for unreachable peers) ─────────────
    /// Probe rounds in a row in which every candidate failed.
    pub probe_failures: u32,
    /// No new probe round before this timestamp (Unix seconds).
    pub next_probe_at: i64,
    /// The candidates of the last failed round: new ones are probed at once.
    pub failed_candidates: Vec<SocketAddr>,
}

impl PeerPath {
    pub fn new() -> Self {
        PeerPath {
            mode: PeerPathMode::Relay,
            hold_until: 0,
            probe_candidates: Vec::new(),
            probe_consecutive_ok: HashMap::new(),
            probe_rtt_ms: HashMap::new(),
            probe_miss: HashMap::new(),
            pending_pings: HashMap::new(),
            loss_window: VecDeque::new(),
            consecutive_no_pong: 0,
            consecutive_spikes: 0,
            rtt_baseline_ms: None,
            next_seq: 0,
            last_keepalive_sent_ms: 0,
            last_bg_probe_sent_ms: 0,
            relay_path_pending: HashSet::new(),
            relay_path_rtt_ms: None,
            last_relay_path_probe_ms: 0,
            probe_failures: 0,
            next_probe_at: 0,
            failed_candidates: Vec::new(),
        }
    }

    /// Transition to Relay mode: start the hold timer, reset all state
    /// except the probe backoff (3.0.x `set_relay`).
    pub fn set_relay(&mut self, now_unix: i64) {
        self.mode = PeerPathMode::Relay;
        self.hold_until = now_unix + HOLD_DURATION_SECS;
        self.consecutive_no_pong = 0;
        self.consecutive_spikes = 0;
        self.loss_window.clear();
        self.rtt_baseline_ms = None;
        self.pending_pings.clear();
        self.probe_candidates.clear();
        self.probe_consecutive_ok.clear();
        self.probe_rtt_ms.clear();
        self.probe_miss.clear();
        self.relay_path_pending.clear();
        self.relay_path_rtt_ms = None;
    }

    /// Transition to Probing mode with the given candidates.  Does not touch
    /// the hold timer (only the upgrade decision respects it) and keeps the
    /// statistics of candidates seen before (3.0.x `start_probing`).
    pub fn start_probing(&mut self, candidates: Vec<SocketAddr>, _now_unix: i64) {
        self.mode = PeerPathMode::Probing;
        self.probe_consecutive_ok = candidates
            .iter()
            .map(|&ep| (ep, self.probe_consecutive_ok.get(&ep).copied().unwrap_or(0)))
            .collect();
        self.probe_rtt_ms = candidates.iter().filter_map(|&ep| self.probe_rtt_ms.get(&ep).map(|&r| (ep, r))).collect();
        self.probe_miss = candidates.iter().map(|&ep| (ep, 0u8)).collect();
        self.probe_candidates = candidates;
        self.pending_pings.clear();
        self.consecutive_no_pong = 0;
    }

    /// Transition to Direct mode with the active endpoint: start the hold
    /// timer, reset active-path metrics (3.0.x `set_direct`).
    pub fn set_direct(&mut self, endpoint: SocketAddr, now_unix: i64) {
        self.mode = PeerPathMode::Direct { endpoint };
        self.hold_until = now_unix + HOLD_DURATION_SECS;
        self.probe_candidates.retain(|ep| ep != &endpoint);
        self.probe_miss = self.probe_candidates.iter().map(|&ep| (ep, 0u8)).collect();
        self.probe_consecutive_ok.retain(|ep, _| ep != &endpoint);
        self.probe_rtt_ms.retain(|ep, _| ep != &endpoint);
        self.pending_pings.clear();
        self.consecutive_no_pong = 0;
        self.consecutive_spikes = 0;
        self.loss_window.clear();
        self.last_bg_probe_sent_ms = 0;
        self.reset_backoff();
        // Avoid seq collisions with lingering probe pings.
        self.next_seq = self.next_seq.wrapping_add(0x1000);
    }

    /// A probe round failed on every candidate: back off before the next
    /// one (30 s, 60 s, … up to 10 min).
    pub fn note_probe_failure(&mut self, candidates: &[SocketAddr], now_unix: i64) {
        self.probe_failures = self.probe_failures.saturating_add(1);
        let shift = (self.probe_failures - 1).min(16);
        let wait = (PROBE_BACKOFF_BASE_SECS << shift).min(PROBE_BACKOFF_MAX_SECS);
        self.next_probe_at = now_unix + wait;
        self.failed_candidates = candidates.to_vec();
    }

    /// Forget the probe backoff (new information: a working path, new
    /// candidates, a punch request, a network change).
    pub fn reset_backoff(&mut self) {
        self.probe_failures = 0;
        self.next_probe_at = 0;
        self.failed_candidates.clear();
    }

    /// Whether a new probe round may start with these candidates.
    pub fn may_probe(&self, candidates: &[SocketAddr], now_unix: i64) -> bool {
        !candidates.is_empty() && (now_unix >= self.next_probe_at || candidates != self.failed_candidates)
    }

    /// Whether the background-probed `candidate` is clearly better than
    /// the active direct endpoint: a LAN address replacing a non-LAN one,
    /// or at most [`SWITCH_RTT_FACTOR`] of its RTT; either way after
    /// [`MIN_PROBE_OK`] consecutive pongs.
    pub fn should_switch(&self, candidate: SocketAddr) -> bool {
        let Some(active) = self.mode.endpoint() else { return false };
        if candidate == active || self.probe_consecutive_ok.get(&candidate).copied().unwrap_or(0) < MIN_PROBE_OK {
            return false;
        }
        if is_lan_endpoint(candidate) != is_lan_endpoint(active) {
            return is_lan_endpoint(candidate);
        }
        match (self.probe_rtt_ms.get(&candidate), self.rtt_baseline_ms) {
            (Some(&rtt), Some(base)) => rtt <= SWITCH_RTT_FACTOR * base,
            _ => false,
        }
    }

    /// Returns `true` if the hold timer is still active.
    pub fn hold_active(&self, now_unix: i64) -> bool {
        now_unix < self.hold_until
    }

    /// Record a pong result in the loss window.
    pub fn push_loss(&mut self, received: bool) {
        if self.loss_window.len() >= LOSS_WINDOW_SIZE {
            self.loss_window.pop_front();
        }
        self.loss_window.push_back(received);
    }

    /// Calculate the current loss rate (0.0 – 1.0).
    pub fn loss_rate(&self) -> f64 {
        if self.loss_window.is_empty() {
            return 0.0;
        }
        let lost = self.loss_window.iter().filter(|&&r| !r).count();
        lost as f64 / self.loss_window.len() as f64
    }

    /// Update the RTT baseline with a new measurement (EWMA).
    pub fn update_rtt(&mut self, rtt_ms: f64) {
        self.rtt_baseline_ms = Some(match self.rtt_baseline_ms {
            None => rtt_ms,
            Some(prev) => RTT_EWMA_ALPHA * rtt_ms + (1.0 - RTT_EWMA_ALPHA) * prev,
        });
    }

    /// Returns `true` if `rtt_ms` is an RTT spike compared to the baseline.
    pub fn is_rtt_spike(&self, rtt_ms: f64) -> bool {
        if let Some(baseline) = self.rtt_baseline_ms {
            if baseline >= RTT_MIN_BASELINE_MS {
                return rtt_ms > baseline * RTT_SPIKE_FACTOR;
            }
        }
        false
    }

    /// Check if a probe candidate qualifies for upgrade to Direct.
    ///
    /// 3.0.x criteria: at least `MIN_PROBE_OK` consecutive pongs, and
    /// - a LAN candidate always qualifies;
    /// - otherwise P2P RTT ≤ `UPGRADE_RTT_FACTOR` × the full relay path RTT —
    ///   measured end to end (`relay_path_rtt_ms`) or, until measured,
    ///   estimated as 2 × the one-way-to-relay RTT `relay_rtt_ms`;
    /// - with no relay information at all, the pong criterion alone decides.
    pub fn can_upgrade(&self, candidate: SocketAddr, relay_rtt_ms: Option<f64>) -> bool {
        let ok = self.probe_consecutive_ok.get(&candidate).copied().unwrap_or(0);
        if ok < MIN_PROBE_OK {
            return false;
        }
        if is_lan_endpoint(candidate) {
            return true;
        }
        match self.relay_path_rtt_ms.or_else(|| relay_rtt_ms.map(|r| r * 2.0)) {
            Some(relay) => self.probe_rtt_ms.get(&candidate).copied().unwrap_or(f64::MAX) <= UPGRADE_RTT_FACTOR * relay,
            None => true,
        }
    }

    /// Returns `true` if all probe candidates have been abandoned.
    pub fn all_probes_failed(&self) -> bool {
        if self.probe_candidates.is_empty() {
            return true;
        }
        self.probe_candidates.iter().all(|ep| {
            self.probe_miss.get(ep).copied().unwrap_or(0) >= MAX_PROBE_MISS
        })
    }
}

impl Default for PeerPath {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 22, 1, 1), port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0))
    }

    #[test]
    fn new_path_is_relay() {
        let pp = PeerPath::new();
        assert_eq!(pp.mode, PeerPathMode::Relay);
        assert_eq!(pp.loss_rate(), 0.0);
        assert!(!pp.is_rtt_spike(100.0));
    }

    #[test]
    fn relay_to_probing() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345), v6(12345)], 1000);
        assert_eq!(pp.mode, PeerPathMode::Probing);
        assert_eq!(pp.probe_candidates.len(), 2);
        // Starting a probe doesn't arm the hold timer (3.0.x) …
        assert!(!pp.hold_active(1000));
        // … falling back to relay does.
        pp.set_relay(1000);
        assert!(pp.hold_active(1000));
        assert!(!pp.hold_active(1031));
        assert!(pp.probe_candidates.is_empty());
    }

    #[test]
    fn probing_to_direct() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345)], 1000);
        pp.probe_consecutive_ok.insert(v4(12345), MIN_PROBE_OK);
        pp.probe_rtt_ms.insert(v4(12345), 20.0);
        assert!(pp.can_upgrade(v4(12345), Some(30.0)));
        pp.set_direct(v4(12345), 1000);
        assert_eq!(pp.mode, PeerPathMode::Direct { endpoint: v4(12345) });
    }

    #[test]
    fn direct_to_relay_on_no_pong() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.consecutive_no_pong = MAX_CONSECUTIVE_NO_PONG;
        assert!(pp.consecutive_no_pong >= MAX_CONSECUTIVE_NO_PONG);
        pp.set_relay(1010);
        assert_eq!(pp.mode, PeerPathMode::Relay);
    }

    #[test]
    fn loss_rate_calculation() {
        let mut pp = PeerPath::new();
        // 15 received, 5 lost = 25% loss
        for _ in 0..15 {
            pp.push_loss(true);
        }
        for _ in 0..5 {
            pp.push_loss(false);
        }
        assert!((pp.loss_rate() - 0.25).abs() < 0.001);
    }

    #[test]
    fn rtt_spike_detection() {
        let mut pp = PeerPath::new();
        pp.rtt_baseline_ms = Some(20.0);
        assert!(!pp.is_rtt_spike(25.0)); // 25 < 20 * 3.0
        assert!(pp.is_rtt_spike(70.0)); // 70 > 20 * 3.0
    }

    #[test]
    fn rtt_spike_ignored_when_baseline_too_low() {
        let mut pp = PeerPath::new();
        pp.rtt_baseline_ms = Some(2.0); // below RTT_MIN_BASELINE_MS
        assert!(!pp.is_rtt_spike(100.0)); // spike detection disabled
    }

    #[test]
    fn rtt_ewma_update() {
        let mut pp = PeerPath::new();
        pp.update_rtt(100.0);
        assert_eq!(pp.rtt_baseline_ms, Some(100.0));
        pp.update_rtt(200.0);
        // EWMA: 0.125 * 200 + 0.875 * 100 = 25 + 87.5 = 112.5
        let expected = RTT_EWMA_ALPHA * 200.0 + (1.0 - RTT_EWMA_ALPHA) * 100.0;
        assert!((pp.rtt_baseline_ms.unwrap() - expected).abs() < 0.01);
    }

    #[test]
    fn can_upgrade_requires_consecutive_ok() {
        let mut pp = PeerPath::new();
        pp.probe_consecutive_ok.insert(v4(12345), 3); // < MIN_PROBE_OK
        assert!(!pp.can_upgrade(v4(12345), Some(50.0)));
    }

    #[test]
    fn can_upgrade_requires_rtt_competitive() {
        // 3.0.x: compare with the full relay path RTT (measured, or
        // estimated as 2 × the one-way-to-relay RTT).
        let public: SocketAddr = "203.0.113.5:21031".parse().unwrap();
        let mut pp = PeerPath::new();
        pp.probe_consecutive_ok.insert(public, MIN_PROBE_OK);
        pp.probe_rtt_ms.insert(public, 100.0);
        assert!(!pp.can_upgrade(public, Some(40.0))); // 100 > 2 × 40
        assert!(pp.can_upgrade(public, Some(50.0))); // 100 ≤ 2 × 50
        assert!(pp.can_upgrade(public, None)); // no relay information
        // A measured relay path RTT takes precedence over the estimate.
        pp.relay_path_rtt_ms = Some(90.0);
        assert!(!pp.can_upgrade(public, Some(1000.0)));
        // Too few pongs → never.
        pp.probe_consecutive_ok.insert(public, MIN_PROBE_OK - 1);
        assert!(!pp.can_upgrade(public, None));
    }

    #[test]
    fn lan_candidate_always_qualifies() {
        let lan: SocketAddr = "192.168.1.5:21031".parse().unwrap();
        let mut pp = PeerPath::new();
        pp.probe_consecutive_ok.insert(lan, MIN_PROBE_OK);
        pp.probe_rtt_ms.insert(lan, 500.0);
        assert!(pp.can_upgrade(lan, Some(1.0)));
        assert!(is_lan_endpoint(lan));
        assert!(!is_lan_endpoint("8.8.8.8:53".parse().unwrap()));
    }

    #[test]
    fn all_probes_failed_empty() {
        let pp = PeerPath::new();
        assert!(pp.all_probes_failed());
    }

    #[test]
    fn all_probes_failed_mixed() {
        let mut pp = PeerPath::new();
        pp.probe_candidates = vec![v4(1000), v4(2000)];
        pp.probe_miss.insert(v4(1000), MAX_PROBE_MISS); // failed
        pp.probe_miss.insert(v4(2000), 1); // still alive
        assert!(!pp.all_probes_failed());
        pp.probe_miss.insert(v4(2000), MAX_PROBE_MISS);
        assert!(pp.all_probes_failed());
    }

    #[test]
    fn hold_timer() {
        let mut pp = PeerPath::new();
        pp.set_relay(1000);
        assert!(pp.hold_active(1000));
        assert!(pp.hold_active(1029));
        assert!(!pp.hold_active(1030));
        assert!(!pp.hold_active(1031));
    }

    #[test]
    fn default_trait() {
        let pp = PeerPath::default();
        assert_eq!(pp.mode, PeerPathMode::Relay);
    }
}