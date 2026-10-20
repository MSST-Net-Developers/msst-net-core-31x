//! Probe manager — P2P probe sending, tracking, and pong handling.
//!
//! Manages the lifecycle of P2P probes:
//! - Send probe pings to candidate endpoints (with backoff after a round
//!   in which every candidate failed)
//! - Track in-flight probes (seq → target + timestamp)
//! - Process pong responses (update RTT, consecutive_ok, miss counts)
//! - Upgrade (Relay → Probing → Direct), switch to a better direct
//!   candidate, downgrade (Direct → Relay)
//!
//! This module is **data + logic** — it doesn't own the UDP socket.  It
//! only mutates [`PeerPath`]; the caller detects mode changes by comparing
//! the mode before and after, and sends the returned pings.

use crate::net::msst_packet;
use crate::net::path::{self, PeerPath, PeerPathMode, MAX_CONSECUTIVE_NO_PONG, MAX_PROBE_MISS};
use std::collections::HashSet;
use std::net::SocketAddr;

/// Pings to send: (target, packet).
pub type Pings = Vec<(SocketAddr, Vec<u8>)>;

/// Network settings that shape path decisions (3.0.x semantics).
#[derive(Debug, Clone, Copy)]
pub struct PathPolicy {
    /// Direct-path keepalive interval (seconds).
    pub keepalive_secs: i64,
    /// Never start probing; abandon an ongoing probe; no background probes.
    pub disable_p2p: bool,
    /// Freeze the path: no upgrade, no downgrade, no switch (a direct path
    /// keeps its keepalive bookkeeping).
    pub lock_path: bool,
}

impl Default for PathPolicy {
    fn default() -> Self {
        PathPolicy { keepalive_secs: 1, disable_p2p: false, lock_path: false }
    }
}

// ---------------------------------------------------------------------------
// Probe tick — called once per second per peer
// ---------------------------------------------------------------------------

/// What one probe cycle wants sent.
#[derive(Debug, Default)]
pub struct ProbeOut {
    /// P2P pings (`0x06`) to candidate endpoints.
    pub pings: Pings,
    /// A relay-path probe is due with this sequence number.  The runtime
    /// sends it inside the WireGuard session over the relay route (see
    /// `tunnel_probe` in the Core); its pong goes to [`process_pong`].
    pub relay_probe: Option<u32>,
}

/// Process one probe cycle for a peer.
///
/// `candidates` — the peer's announced endpoints (sorted IPv6-first);
/// `relay_path` — a relay route to the peer exists, so the end-to-end
/// relay path can be measured (the upgrade baseline).
#[allow(clippy::too_many_arguments)]
pub fn probe_tick(
    now_unix: i64,
    now_ms: u64,
    local_id: &str,
    peer_id: &str,
    pp: &mut PeerPath,
    candidates: &[SocketAddr],
    relay_path: bool,
    policy: &PathPolicy,
) -> ProbeOut {
    let mut relay_probe = None;
    let pings = tick_pings(now_unix, now_ms, local_id, peer_id, pp, candidates, relay_path, policy, &mut relay_probe);
    ProbeOut { pings, relay_probe }
}

#[allow(clippy::too_many_arguments)]
fn tick_pings(
    now_unix: i64,
    now_ms: u64,
    local_id: &str,
    peer_id: &str,
    pp: &mut PeerPath,
    candidates: &[SocketAddr],
    relay_path: bool,
    policy: &PathPolicy,
    relay_probe: &mut Option<u32>,
) -> Pings {
    let mut pkts = Vec::new();
    let ping = |pp: &mut PeerPath, pkts: &mut Pings, target: SocketAddr| {
        let seq = pp.next_seq;
        pp.next_seq = pp.next_seq.wrapping_add(1);
        pp.pending_pings.insert(seq, (target, now_ms));
        pkts.push((target, msst_packet::build_p2p_ping(local_id, peer_id, seq, now_ms)));
    };

    match pp.mode.clone() {
        PeerPathMode::Relay => {
            if policy.disable_p2p || policy.lock_path || !pp.may_probe(candidates, now_unix) {
                return pkts;
            }
            if candidates != pp.failed_candidates.as_slice() {
                pp.reset_backoff(); // new endpoints: probe them at once
            }
            pp.start_probing(candidates.to_vec(), now_unix);
            // Send the first round of probe pings immediately.
            for &candidate in candidates {
                ping(pp, &mut pkts, candidate);
            }
        }

        PeerPathMode::Probing => {
            if policy.disable_p2p {
                pp.set_relay(now_unix);
                return pkts;
            }
            if policy.lock_path {
                return pkts;
            }
            // Follow the peer's announced endpoints (3.0.x).
            if !candidates.is_empty() && pp.probe_candidates != candidates {
                sync_candidates(pp, candidates.to_vec());
            }
            expire_probes(pp, now_ms, None);

            // Check if all candidates failed (or none are left).
            if pp.all_probes_failed() {
                if pp.hold_active(now_unix) {
                    // During hold: reset counters and keep probing.
                    for miss in pp.probe_miss.values_mut() { *miss = 0; }
                    for ok in pp.probe_consecutive_ok.values_mut() { *ok = 0; }
                } else {
                    let tried = pp.probe_candidates.clone();
                    pp.set_relay(now_unix);
                    pp.note_probe_failure(&tried, now_unix);
                    return pkts;
                }
            }

            // Send probe pings to live candidates.
            let in_flight: HashSet<SocketAddr> = pp.pending_pings.values().map(|(ep, _)| *ep).collect();
            for candidate in pp.probe_candidates.clone() {
                let miss = pp.probe_miss.get(&candidate).copied().unwrap_or(0);
                if miss < MAX_PROBE_MISS && !in_flight.contains(&candidate) {
                    ping(pp, &mut pkts, candidate);
                }
            }
            // Measure the end-to-end relay path (us → peer's relay → peer →
            // our relay → us) as the upgrade baseline.
            if relay_path && now_ms.saturating_sub(pp.last_relay_path_probe_ms) >= path::RELAY_PATH_PROBE_INTERVAL_MS {
                pp.last_relay_path_probe_ms = now_ms;
                pp.relay_path_pending.clear(); // drop a stale in-flight probe
                let seq = pp.next_seq;
                pp.next_seq = pp.next_seq.wrapping_add(1);
                pp.relay_path_pending.insert(seq);
                *relay_probe = Some(seq);
            }
        }

        PeerPathMode::Direct { endpoint } => {
            // Expire timed-out keepalive pings for the active endpoint.
            let expired_active: Vec<u32> = pp.pending_pings.iter()
                .filter(|(_, (addr, sent_ms))| {
                    *addr == endpoint && now_ms.saturating_sub(*sent_ms) > path::PING_TIMEOUT_MS
                })
                .map(|(&seq, _)| seq)
                .collect();
            for seq in expired_active {
                pp.pending_pings.remove(&seq);
                pp.push_loss(false);
                pp.consecutive_no_pong = pp.consecutive_no_pong.saturating_add(1);
            }
            // Background probes to the other candidates.
            expire_probes(pp, now_ms, Some(endpoint));

            if !policy.lock_path {
                // Unreachable: immediate downgrade (bypasses hold).
                if pp.consecutive_no_pong >= MAX_CONSECUTIVE_NO_PONG {
                    pp.set_relay(now_unix);
                    return pkts;
                }
                // High loss rate (after hold expires).
                if !pp.hold_active(now_unix)
                    && pp.loss_rate() > path::LOSS_RATE_THRESHOLD
                    && pp.loss_window.len() >= path::LOSS_WINDOW_SIZE
                {
                    pp.set_relay(now_unix);
                    return pkts;
                }
            }

            // Send keepalive ping if interval elapsed.
            let keepalive_ms = (policy.keepalive_secs.max(1) * 1000) as u64;
            if now_ms.saturating_sub(pp.last_keepalive_sent_ms) >= keepalive_ms {
                pp.last_keepalive_sent_ms = now_ms;
                ping(pp, &mut pkts, endpoint);
            }

            // Background probing (3.0.x): keep measuring the peer's other
            // endpoints so a better one can take over (`process_pong`).
            if !policy.disable_p2p {
                let others: Vec<SocketAddr> = candidates.iter().copied().filter(|&ep| ep != endpoint).collect();
                if pp.probe_candidates != others {
                    sync_candidates(pp, others);
                }
                if !pp.probe_candidates.is_empty()
                    && now_ms.saturating_sub(pp.last_bg_probe_sent_ms) >= path::BG_PROBE_INTERVAL_MS
                {
                    pp.last_bg_probe_sent_ms = now_ms;
                    let in_flight: HashSet<SocketAddr> = pp.pending_pings.values().map(|(ep, _)| *ep).collect();
                    for candidate in pp.probe_candidates.clone() {
                        let miss = pp.probe_miss.get(&candidate).copied().unwrap_or(0);
                        if miss < MAX_PROBE_MISS && !in_flight.contains(&candidate) {
                            ping(pp, &mut pkts, candidate);
                        }
                    }
                }
            }
        }
    }

    pkts
}

/// Replace the probe candidates, keeping the statistics of known ones.
fn sync_candidates(pp: &mut PeerPath, candidates: Vec<SocketAddr>) {
    let old_miss = std::mem::take(&mut pp.probe_miss);
    pp.probe_miss = candidates.iter().map(|&ep| (ep, old_miss.get(&ep).copied().unwrap_or(0))).collect();
    pp.probe_consecutive_ok.retain(|ep, _| candidates.contains(ep));
    pp.probe_rtt_ms.retain(|ep, _| candidates.contains(ep));
    pp.probe_candidates = candidates;
}

/// Expire timed-out probe pings (all but those to `except`, the active
/// endpoint): a miss, and the candidate's success streak is broken.
fn expire_probes(pp: &mut PeerPath, now_ms: u64, except: Option<SocketAddr>) {
    let expired: Vec<u32> = pp.pending_pings.iter()
        .filter(|(_, (addr, sent_ms))| Some(*addr) != except && now_ms.saturating_sub(*sent_ms) > path::PING_TIMEOUT_MS)
        .map(|(&seq, _)| seq)
        .collect();
    for seq in expired {
        if let Some((target, _)) = pp.pending_pings.remove(&seq) {
            let miss = pp.probe_miss.entry(target).or_insert(0);
            *miss = miss.saturating_add(1);
            pp.probe_consecutive_ok.insert(target, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// Pong processing — called when a P2P pong is received
// ---------------------------------------------------------------------------

/// Process a P2P pong received from a peer.
///
/// Updates RTT, consecutive_ok and the loss window, and may upgrade
/// (Probing → Direct), switch the direct endpoint, or downgrade on a
/// sustained RTT spike.  With `lock_path` only statistics change.
pub fn process_pong(
    pp: &mut PeerPath,
    src: SocketAddr,
    seq: u32,
    rtt_ms: f64,
    relay_rtt_ms: Option<f64>,
    now_unix: i64,
    lock_path: bool,
) {
    // Relay-path probe answered (in-tunnel, over the relays): update its RTT.
    if pp.relay_path_pending.remove(&seq) {
        pp.relay_path_rtt_ms = Some(match pp.relay_path_rtt_ms {
            None => rtt_ms,
            Some(p) => path::RTT_EWMA_ALPHA * rtt_ms + (1.0 - path::RTT_EWMA_ALPHA) * p,
        });
        return;
    }

    // Must match a pending ping.
    match pp.pending_pings.remove(&seq) {
        Some((expected, _)) if expected == src => {}
        // NAT hairpinning: the probe to the public address was answered from
        // the LAN address.  Credit src if it is a known candidate; otherwise
        // ignore the pong (the ping stays consumed, as in 3.0.x).
        Some(_) if pp.probe_candidates.contains(&src) => {}
        _ => return,
    }
    let may_change = !lock_path && !pp.hold_active(now_unix);

    match pp.mode.clone() {
        PeerPathMode::Direct { endpoint } if endpoint == src => {
            // Active endpoint: quality monitoring.
            pp.push_loss(true);
            pp.consecutive_no_pong = 0;
            if pp.is_rtt_spike(rtt_ms) {
                // A spike sample is kept out of the baseline; only a
                // sustained spike is a quality signal, and it respects the
                // hold timer (only missing pongs bypass it).
                pp.consecutive_spikes = pp.consecutive_spikes.saturating_add(1);
                if may_change && pp.consecutive_spikes >= path::RTT_SPIKE_CONSECUTIVE {
                    pp.set_relay(now_unix);
                }
            } else {
                pp.consecutive_spikes = 0;
                pp.update_rtt(rtt_ms);
            }
        }

        PeerPathMode::Probing | PeerPathMode::Direct { .. } => {
            // A probe (Probing) or background probe (Direct) answered.
            *pp.probe_consecutive_ok.entry(src).or_insert(0) += 1;
            let ewma = pp.probe_rtt_ms.entry(src).or_insert(rtt_ms);
            *ewma = path::RTT_EWMA_ALPHA * rtt_ms + (1.0 - path::RTT_EWMA_ALPHA) * *ewma;
            pp.probe_miss.insert(src, 0);
            if !may_change {
                return;
            }
            let upgrade = match pp.mode {
                PeerPathMode::Probing => pp.can_upgrade(src, relay_rtt_ms),
                _ => pp.should_switch(src),
            };
            if upgrade {
                let p2p_rtt = pp.probe_rtt_ms.get(&src).copied().unwrap_or(rtt_ms);
                pp.set_direct(src, now_unix);
                pp.rtt_baseline_ms = Some(p2p_rtt);
            }
        }

        PeerPathMode::Relay => {}
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::path::{HOLD_DURATION_SECS, MIN_PROBE_OK, PROBE_BACKOFF_BASE_SECS, PROBE_BACKOFF_MAX_SECS, RTT_SPIKE_CONSECUTIVE};
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 22, 1, 1), port))
    }

    fn v4b(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 22, 2, 1), port))
    }

    fn public(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), port))
    }

    fn lan(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 5), port))
    }

    const P: PathPolicy = PathPolicy { keepalive_secs: 1, disable_p2p: false, lock_path: false };

    fn tick(pp: &mut PeerPath, now: i64, candidates: &[SocketAddr]) -> Pings {
        probe_tick(now, now as u64 * 1000, "local", "peer", pp, candidates, false, &P).pings
    }

    /// Answer the ping `seq` (sent to `to`) from `from`.
    fn pong(pp: &mut PeerPath, to: SocketAddr, from: SocketAddr, rtt: f64, now: i64) {
        let seq = pp.next_seq;
        pp.next_seq += 1;
        pp.pending_pings.insert(seq, (to, 0));
        process_pong(pp, from, seq, rtt, None, now, false);
    }

    /// Let every probe ping time out, `rounds` times.
    fn fail_probes(pp: &mut PeerPath, mut now: i64, candidates: &[SocketAddr], rounds: usize) -> i64 {
        for _ in 0..rounds {
            tick(pp, now, candidates);
            now += 3;
        }
        now
    }

    #[test]
    fn relay_starts_probing_when_candidates_available() {
        let mut pp = PeerPath::new();
        let pings = tick(&mut pp, 1000, &[v4(12345)]);
        assert_eq!(pp.mode, PeerPathMode::Probing);
        assert_eq!(pings.len(), 1, "first round sent at once");
    }

    #[test]
    fn relay_no_candidates_stays_relay() {
        let mut pp = PeerPath::new();
        assert!(tick(&mut pp, 1000, &[]).is_empty());
        assert_eq!(pp.mode, PeerPathMode::Relay);
    }

    #[test]
    fn probing_no_duplicate_pings() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345)], 1000);
        assert_eq!(tick(&mut pp, 1000, &[v4(12345)]).len(), 1);
        // One already in flight.
        assert!(tick(&mut pp, 1001, &[v4(12345)]).is_empty());
    }

    #[test]
    fn failed_probe_rounds_back_off_exponentially() {
        let c = [v4(12345)];
        let mut pp = PeerPath::new();
        tick(&mut pp, 1000, &c);
        // 3 misses (one ping in flight, 2 s timeout) → relay, back off 30 s.
        let now = fail_probes(&mut pp, 1001, &c, MAX_PROBE_MISS as usize + 1);
        assert_eq!(pp.mode, PeerPathMode::Relay);
        assert_eq!((pp.probe_failures, pp.next_probe_at - now + 3), (1, PROBE_BACKOFF_BASE_SECS));
        // No probing during the backoff …
        assert!(tick(&mut pp, now + 10, &c).is_empty());
        assert_eq!(pp.mode, PeerPathMode::Relay);
        // … then one more round; it fails once the hold expires → 60 s.
        let start = pp.next_probe_at;
        tick(&mut pp, start, &c);
        assert_eq!(pp.mode, PeerPathMode::Probing);
        let mut now = start + 1;
        while pp.mode == PeerPathMode::Probing {
            tick(&mut pp, now, &c);
            now += 3;
        }
        assert_eq!(pp.probe_failures, 2);
        assert_eq!(pp.next_probe_at - (now - 3), 2 * PROBE_BACKOFF_BASE_SECS);
        // Capped.
        for _ in 0..10 {
            pp.note_probe_failure(&c, 0);
        }
        assert_eq!(pp.next_probe_at, PROBE_BACKOFF_MAX_SECS);
    }

    #[test]
    fn new_candidates_skip_the_backoff() {
        let mut pp = PeerPath::new();
        pp.note_probe_failure(&[v4(1)], 1000);
        assert!(tick(&mut pp, 1001, &[v4(1)]).is_empty());
        tick(&mut pp, 1001, &[v4(2)]);
        assert_eq!(pp.mode, PeerPathMode::Probing);
        assert_eq!(pp.probe_failures, 0);
    }

    #[test]
    fn upgrade_resets_backoff() {
        let mut pp = PeerPath::new();
        pp.note_probe_failure(&[v4(1)], 0);
        pp.start_probing(vec![v4(12345)], 1000);
        for _ in 0..MIN_PROBE_OK {
            pong(&mut pp, v4(12345), v4(12345), 20.0, 1031);
        }
        assert_eq!(pp.mode, PeerPathMode::Direct { endpoint: v4(12345) });
        assert_eq!((pp.probe_failures, pp.next_probe_at), (0, 0));
    }

    #[test]
    fn pong_upgrades_from_probing() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345)], 1000);
        for i in 0..MIN_PROBE_OK {
            pp.pending_pings.insert(i, (v4(12345), 1_030_000));
            process_pong(&mut pp, v4(12345), i, 20.0, Some(50.0), 1031, false);
            if i < MIN_PROBE_OK - 1 {
                assert_eq!(pp.mode, PeerPathMode::Probing, "not yet at pong {}", i);
            }
        }
        assert_eq!(pp.mode, PeerPathMode::Direct { endpoint: v4(12345) });
    }

    #[test]
    fn direct_sends_keepalive() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.last_keepalive_sent_ms = 0;
        assert_eq!(tick(&mut pp, 1001, &[v4(12345)]).len(), 1);
    }

    #[test]
    fn direct_downgrades_on_consecutive_no_pong() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.consecutive_no_pong = MAX_CONSECUTIVE_NO_PONG - 1;
        pp.pending_pings.insert(99, (v4(12345), 500_000)); // expired
        tick(&mut pp, 1001, &[v4(12345)]);
        assert_eq!(pp.mode, PeerPathMode::Relay);
        assert_eq!(pp.probe_failures, 0, "a downgrade is not a failed probe round");
    }

    #[test]
    fn lock_path_freezes_direct() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.consecutive_no_pong = MAX_CONSECUTIVE_NO_PONG;
        let locked = PathPolicy { lock_path: true, ..P };
        probe_tick(1100, 1_100_000, "local", "peer", &mut pp, &[v4(12345)], false, &locked);
        assert!(pp.mode.is_direct());
        pp.rtt_baseline_ms = Some(10.0);
        for _ in 0..RTT_SPIKE_CONSECUTIVE {
            let seq = pp.next_seq;
            pp.next_seq += 1;
            pp.pending_pings.insert(seq, (v4(12345), 0));
            process_pong(&mut pp, v4(12345), seq, 100.0, None, 1100, true);
        }
        assert!(pp.mode.is_direct());
    }

    #[test]
    fn pong_resets_no_pong_counter_in_direct() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.consecutive_no_pong = 2;
        pong(&mut pp, v4(12345), v4(12345), 15.0, 1000);
        assert_eq!(pp.consecutive_no_pong, 0);
    }

    #[test]
    fn pong_from_wrong_address_rejected() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.pending_pings.insert(42, (v4(12345), 999_000));
        // Pong from an unknown address — ignored (the ping is consumed and
        // will not be mis-counted as a later timeout, as in 3.0.x).
        process_pong(&mut pp, v4b(54321), 42, 15.0, None, 1000, false);
        assert!(!pp.pending_pings.contains_key(&42));
        assert_eq!(pp.loss_window.len(), 0);
    }

    #[test]
    fn relay_path_pong_updates_baseline_only() {
        let mut pp = PeerPath::new();
        pp.relay_path_pending.insert(7);
        process_pong(&mut pp, v4(12345), 7, 80.0, None, 1000, false);
        assert_eq!(pp.relay_path_rtt_ms, Some(80.0));
        assert_eq!(pp.mode, PeerPathMode::Relay);
    }

    #[test]
    fn only_a_sustained_rtt_spike_downgrades() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.rtt_baseline_ms = Some(20.0);
        let after_hold = 1000 + HOLD_DURATION_SECS;
        // Within the hold period: no downgrade, however many spikes.
        for _ in 0..RTT_SPIKE_CONSECUTIVE {
            pong(&mut pp, v4(12345), v4(12345), 100.0, 1001);
        }
        assert!(pp.mode.is_direct());
        // After it: isolated spikes are jitter …
        pp.consecutive_spikes = 0;
        for _ in 0..3 {
            for _ in 1..RTT_SPIKE_CONSECUTIVE {
                pong(&mut pp, v4(12345), v4(12345), 100.0, after_hold);
            }
            pong(&mut pp, v4(12345), v4(12345), 20.0, after_hold);
        }
        assert!(pp.mode.is_direct());
        assert!(pp.rtt_baseline_ms.unwrap() < 21.0, "spikes stay out of the baseline");
        // … a sustained one downgrades.
        for _ in 0..RTT_SPIKE_CONSECUTIVE {
            pong(&mut pp, v4(12345), v4(12345), 100.0, after_hold);
        }
        assert_eq!(pp.mode, PeerPathMode::Relay);
    }

    #[test]
    fn direct_background_probes_and_switches_to_lan() {
        let (active, other) = (public(40000), lan(21031));
        let mut pp = PeerPath::new();
        pp.set_direct(active, 1000);
        pp.rtt_baseline_ms = Some(30.0);
        pp.last_keepalive_sent_ms = u64::MAX / 2; // no keepalive in the way
        let pings = tick(&mut pp, 1001, &[active, other]);
        assert_eq!(pings.iter().map(|(t, _)| *t).collect::<Vec<_>>(), [other], "background probe");
        assert_eq!(pp.probe_candidates, [other]);
        // Answers during the hold only update statistics.
        for _ in 0..MIN_PROBE_OK {
            pong(&mut pp, other, other, 25.0, 1002);
        }
        assert_eq!(pp.mode.endpoint(), Some(active));
        // After it, the LAN candidate takes over.
        pong(&mut pp, other, other, 25.0, 1000 + HOLD_DURATION_SECS);
        assert_eq!(pp.mode.endpoint(), Some(other));
    }

    #[test]
    fn direct_switches_only_to_a_much_faster_candidate() {
        let (active, other) = (public(40000), public(40001));
        let mut pp = PeerPath::new();
        pp.set_direct(active, 0);
        pp.rtt_baseline_ms = Some(30.0);
        pp.probe_candidates = vec![other];
        for _ in 0..MIN_PROBE_OK + 2 {
            pong(&mut pp, other, other, 20.0, 1000);
        }
        assert_eq!(pp.mode.endpoint(), Some(active), "20 ms vs 30 ms is not worth a switch");
        for _ in 0..40 {
            pong(&mut pp, other, other, 10.0, 1000);
        }
        assert_eq!(pp.mode.endpoint(), Some(other));
    }

    #[test]
    fn probing_requests_a_relay_path_probe() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345)], 1000);
        let out = probe_tick(1001, 1_001_000, "local", "peer", &mut pp, &[v4(12345)], true, &P);
        let seq = out.relay_probe.expect("relay-path probe due");
        // Only the candidate gets a 0x06; the relay probe goes in-tunnel.
        assert!(out.pings.iter().all(|(t, _)| *t == v4(12345)));
        assert!(pp.relay_path_pending.contains(&seq));
        // Not again until the interval has passed; never without a relay route.
        assert!(probe_tick(1002, 1_002_000, "local", "peer", &mut pp, &[v4(12345)], true, &P).relay_probe.is_none());
        let mut other = PeerPath::new();
        other.start_probing(vec![v4(12345)], 1000);
        assert!(probe_tick(1001, 1_001_000, "local", "peer", &mut other, &[v4(12345)], false, &P).relay_probe.is_none());
        // Its pong only updates the relay-path RTT.
        process_pong(&mut pp, "198.51.100.1:7000".parse().unwrap(), seq, 80.0, None, 1002, false);
        assert_eq!(pp.relay_path_rtt_ms, Some(80.0));
    }

    #[test]
    fn disable_p2p_reverts_probing_without_backoff() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345)], 1000);
        let off = PathPolicy { disable_p2p: true, ..P };
        probe_tick(1001, 1_001_000, "local", "peer", &mut pp, &[v4(12345)], false, &off);
        assert_eq!((pp.mode.clone(), pp.probe_failures), (PeerPathMode::Relay, 0));
        assert!(probe_tick(1002, 1_002_000, "local", "peer", &mut pp, &[v4(12345)], false, &off).pings.is_empty());
    }
}
