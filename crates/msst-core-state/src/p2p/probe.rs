//! Probe manager — P2P probe sending, tracking, and pong handling.
//!
//! Manages the lifecycle of P2P probes:
//! - Send probe pings to candidate endpoints
//! - Track in-flight probes (seq → target + timestamp)
//! - Process pong responses (update RTT, consecutive_ok, miss counts)
//! - Detect upgrade eligibility (Relay → Probing → Direct)
//! - Detect downgrade necessity (Direct → Relay)
//!
//! This module is **data + logic** — it doesn't own the UDP socket.
//! The caller (Core runtime) reads the probe results and sends packets.

use crate::net::msst_packet;
use crate::net::path::{
    self, PeerPath, PeerPathMode, HOLD_DURATION_SECS, MAX_CONSECUTIVE_NO_PONG,
    MAX_PROBE_MISS, MIN_PROBE_OK, UPGRADE_RTT_FACTOR,
};
use std::collections::HashSet;
use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// ProbeAction — what the caller should do
// ---------------------------------------------------------------------------

/// An action the caller should take after processing a probe cycle.
#[derive(Debug, Clone)]
pub enum ProbeAction {
    /// Send these P2P ping packets to the given addresses.
    SendPings { packets: Vec<(SocketAddr, Vec<u8>)> },
    /// The path mode changed — caller should update state and notify.
    ModeChanged {
        peer_id: String,
        old_mode: String,
        new_mode: String,
    },
    /// Downgrade to relay — path is unreachable.
    DowngradeToRelay { peer_id: String },
}

// ---------------------------------------------------------------------------
// Probe tick — called once per second per peer
// ---------------------------------------------------------------------------

/// Process one probe cycle for a peer.
///
/// Called by the path monitor every second.  Returns a list of actions
/// the caller should execute (send packets, notify mode changes).
///
/// `now_unix` — current Unix timestamp (seconds)
/// `now_ms` — current Unix timestamp (milliseconds, for ping payload)
/// `local_id` — our device ID
/// `peer_id` — the peer's device ID
/// `pp` — the peer's path state (mutable)
/// `candidates` — known endpoints for this peer (sorted IPv6-first)
/// `relay_rtt_ms` — EWMA relay RTT for upgrade comparison (if known)
/// `keepalive_interval_secs` — how often to send keepalive pings
pub fn probe_tick(
    now_unix: i64,
    now_ms: u64,
    local_id: &str,
    peer_id: &str,
    pp: &mut PeerPath,
    candidates: &[SocketAddr],
    relay_rtt_ms: Option<f64>,
    keepalive_interval_secs: i64,
    relay_addr: Option<SocketAddr>,
) -> Vec<ProbeAction> {
    let mut actions = Vec::new();

    match pp.mode.clone() {
        PeerPathMode::Relay => {
            // Start probing if candidates are available.
            if !candidates.is_empty() {
                pp.start_probing(candidates.to_vec(), now_unix);
                actions.push(ProbeAction::ModeChanged {
                    peer_id: peer_id.to_string(),
                    old_mode: "relay".to_string(),
                    new_mode: "probing".to_string(),
                });
                // Also send the first round of probe pings immediately.
                let mut pkts = Vec::new();
                for &candidate in candidates {
                    let seq = pp.next_seq;
                    pp.next_seq = pp.next_seq.wrapping_add(1);
                    pp.pending_pings.insert(seq, (candidate, now_ms));
                    pkts.push((candidate, msst_packet::build_p2p_ping(local_id, peer_id, seq, now_ms)));
                }
                if !pkts.is_empty() {
                    actions.push(ProbeAction::SendPings { packets: pkts });
                }
            }
        }

        PeerPathMode::Probing => {
            // Follow the peer's announced endpoints (3.0.x).
            if !candidates.is_empty() && pp.probe_candidates != candidates {
                let old_miss = std::mem::take(&mut pp.probe_miss);
                pp.probe_candidates = candidates.to_vec();
                pp.probe_miss = candidates.iter().map(|&ep| (ep, old_miss.get(&ep).copied().unwrap_or(0))).collect();
                pp.probe_consecutive_ok.retain(|ep, _| candidates.contains(ep));
                pp.probe_rtt_ms.retain(|ep, _| candidates.contains(ep));
            }

            // Expire timed-out probe pings → increment miss counter.
            let expired: Vec<u32> = pp.pending_pings.iter()
                .filter(|(_, (_, sent_ms))| now_ms.saturating_sub(*sent_ms) > path::PING_TIMEOUT_MS)
                .map(|(&seq, _)| seq)
                .collect();

            for seq in expired {
                if let Some((target, _)) = pp.pending_pings.remove(&seq) {
                    *pp.probe_miss.entry(target).or_insert(0) =
                        pp.probe_miss.get(&target).copied().unwrap_or(0).saturating_add(1);
                    pp.probe_consecutive_ok.insert(target, 0);
                }
            }

            // Check if all candidates failed (or none are left).
            if pp.all_probes_failed() {
                if pp.hold_active(now_unix) {
                    // During hold: reset counters and keep probing.
                    for miss in pp.probe_miss.values_mut() { *miss = 0; }
                    for ok in pp.probe_consecutive_ok.values_mut() { *ok = 0; }
                } else {
                    pp.set_relay(now_unix);
                    actions.push(ProbeAction::DowngradeToRelay {
                        peer_id: peer_id.to_string(),
                    });
                    actions.push(ProbeAction::ModeChanged {
                        peer_id: peer_id.to_string(),
                        old_mode: "probing".to_string(),
                        new_mode: "relay".to_string(),
                    });
                    return actions;
                }
            }

            // Send probe pings to live candidates.
            let in_flight: HashSet<SocketAddr> =
                pp.pending_pings.values().map(|(ep, _)| *ep).collect();

            let mut pkts = Vec::new();
            for &candidate in candidates {
                let miss = pp.probe_miss.get(&candidate).copied().unwrap_or(0);
                if miss >= MAX_PROBE_MISS || in_flight.contains(&candidate) {
                    continue;
                }
                let seq = pp.next_seq;
                pp.next_seq = pp.next_seq.wrapping_add(1);
                pp.pending_pings.insert(seq, (candidate, now_ms));
                pkts.push((candidate, msst_packet::build_p2p_ping(local_id, peer_id, seq, now_ms)));
            }
            // Measure the end-to-end relay path (us → relay → peer → relay →
            // us) as the upgrade baseline: a P2P ping addressed to the peer,
            // sent to its relay (3.0.x).
            if let Some(relay) = relay_addr {
                if now_ms.saturating_sub(pp.last_relay_path_probe_ms) >= path::RELAY_PATH_PROBE_INTERVAL_MS {
                    pp.last_relay_path_probe_ms = now_ms;
                    pp.relay_path_pending.clear(); // drop a stale in-flight probe
                    let seq = pp.next_seq;
                    pp.next_seq = pp.next_seq.wrapping_add(1);
                    pp.relay_path_pending.insert(seq);
                    pkts.push((relay, msst_packet::build_p2p_ping(local_id, peer_id, seq, now_ms)));
                }
            }
            if !pkts.is_empty() {
                actions.push(ProbeAction::SendPings { packets: pkts });
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

            // Check downgrade conditions (after hold expires).
            if !pp.hold_active(now_unix) {
                // High loss rate.
                if pp.loss_rate() > path::LOSS_RATE_THRESHOLD
                    && pp.loss_window.len() >= path::LOSS_WINDOW_SIZE
                {
                    pp.set_relay(now_unix);
                    actions.push(ProbeAction::DowngradeToRelay {
                        peer_id: peer_id.to_string(),
                    });
                    actions.push(ProbeAction::ModeChanged {
                        peer_id: peer_id.to_string(),
                        old_mode: "direct".to_string(),
                        new_mode: "relay".to_string(),
                    });
                    return actions;
                }
            }

            // Unreachable: immediate downgrade (bypasses hold).
            if pp.consecutive_no_pong >= MAX_CONSECUTIVE_NO_PONG {
                pp.set_relay(now_unix);
                actions.push(ProbeAction::DowngradeToRelay {
                    peer_id: peer_id.to_string(),
                });
                actions.push(ProbeAction::ModeChanged {
                    peer_id: peer_id.to_string(),
                    old_mode: "direct".to_string(),
                    new_mode: "relay".to_string(),
                });
                return actions;
            }

            // Send keepalive ping if interval elapsed.
            let keepalive_ms = (keepalive_interval_secs * 1000) as u64;
            if now_ms.saturating_sub(pp.last_keepalive_sent_ms) >= keepalive_ms {
                pp.last_keepalive_sent_ms = now_ms;
                let seq = pp.next_seq;
                pp.next_seq = pp.next_seq.wrapping_add(1);
                pp.pending_pings.insert(seq, (endpoint, now_ms));
                let pkt = msst_packet::build_p2p_ping(local_id, peer_id, seq, now_ms);
                actions.push(ProbeAction::SendPings {
                    packets: vec![(endpoint, pkt)],
                });
            }
        }
    }

    actions
}

// ---------------------------------------------------------------------------
// Pong processing — called when a P2P pong is received
// ---------------------------------------------------------------------------

/// Process a P2P pong received from a peer.
///
/// Updates RTT, consecutive_ok, loss window, and may trigger path upgrade.
/// Returns `true` if the path mode changed.
pub fn process_pong(
    peer_id: &str,
    pp: &mut PeerPath,
    src: SocketAddr,
    seq: u32,
    rtt_ms: f64,
    relay_rtt_ms: Option<f64>,
    now_unix: i64,
) -> bool {
    // Relay-path probe answered (via the relay): update its RTT (3.0.x).
    if pp.relay_path_pending.remove(&seq) {
        pp.relay_path_rtt_ms = Some(match pp.relay_path_rtt_ms {
            None => rtt_ms,
            Some(p) => path::RTT_EWMA_ALPHA * rtt_ms + (1.0 - path::RTT_EWMA_ALPHA) * p,
        });
        return false;
    }

    // Must match a pending ping.
    match pp.pending_pings.remove(&seq) {
        Some((expected, _)) if expected == src => {}
        // NAT hairpinning: the probe to the public address was answered from
        // the LAN address.  Credit src if it is a known candidate; otherwise
        // ignore the pong (the ping stays consumed, as in 3.0.x).
        Some(_) if pp.probe_candidates.contains(&src) => {}
        _ => return false,
    }

    match pp.mode.clone() {
        PeerPathMode::Probing => {
            // Update per-candidate stats.
            *pp.probe_consecutive_ok.entry(src).or_insert(0) += 1;
            let ewma = pp.probe_rtt_ms.entry(src).or_insert(rtt_ms);
            *ewma = path::RTT_EWMA_ALPHA * rtt_ms + (1.0 - path::RTT_EWMA_ALPHA) * *ewma;
            pp.probe_miss.insert(src, 0);

            let ok = pp.probe_consecutive_ok.get(&src).copied().unwrap_or(0);

            // Check upgrade eligibility.
            if !pp.hold_active(now_unix) && pp.can_upgrade(src, relay_rtt_ms) {
                let p2p_rtt = pp.probe_rtt_ms.get(&src).copied().unwrap_or(rtt_ms);
                pp.set_direct(src, now_unix);
                pp.rtt_baseline_ms = Some(p2p_rtt);
                return true;
            }
            false
        }

        PeerPathMode::Direct { endpoint } if endpoint == src => {
            // Active endpoint: quality monitoring.
            pp.push_loss(true);
            pp.consecutive_no_pong = 0;
            let spike = pp.is_rtt_spike(rtt_ms);
            pp.update_rtt(rtt_ms);
            // An RTT spike is a quality signal, so it respects the hold timer
            // (only sustained missing pongs bypass it) — 3.0.x.
            if spike && !pp.hold_active(now_unix) {
                pp.set_relay(now_unix);
                return true;
            }
            false
        }

        PeerPathMode::Direct { .. } => {
            // Background probe pong from non-active candidate.
            *pp.probe_consecutive_ok.entry(src).or_insert(0) += 1;
            let ewma = pp.probe_rtt_ms.entry(src).or_insert(rtt_ms);
            *ewma = path::RTT_EWMA_ALPHA * rtt_ms + (1.0 - path::RTT_EWMA_ALPHA) * *ewma;
            pp.probe_miss.insert(src, 0);
            false
        }

        _ => false,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 22, 1, 1), port))
    }

    fn v4b(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 22, 2, 1), port))
    }

    #[test]
    fn relay_starts_probing_when_candidates_available() {
        let mut pp = PeerPath::new();
        let actions = probe_tick(
            1000, 1_000_000, "local", "peer", &mut pp,
            &[v4(12345)], None, 1, None,
        );
        assert_eq!(pp.mode, PeerPathMode::Probing);
        assert!(actions.iter().any(|a| matches!(a, ProbeAction::ModeChanged { .. })));
    }

    #[test]
    fn relay_no_candidates_stays_relay() {
        let mut pp = PeerPath::new();
        let actions = probe_tick(
            1000, 1_000_000, "local", "peer", &mut pp,
            &[], None, 1, None,
        );
        assert_eq!(pp.mode, PeerPathMode::Relay);
        assert!(actions.is_empty());
    }

    #[test]
    fn probing_sends_pings() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345), v4b(54321)], 1000);
        let actions = probe_tick(
            1000, 1_000_000, "local", "peer", &mut pp,
            &[v4(12345), v4b(54321)], None, 1, None,
        );
        let ping_count: usize = actions.iter().map(|a| match a {
            ProbeAction::SendPings { packets } => packets.len(),
            _ => 0,
        }).sum();
        assert!(ping_count > 0);
    }

    #[test]
    fn probing_no_duplicate_pings() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345)], 1000);
        // First tick sends a ping.
        probe_tick(1000, 1_000_000, "local", "peer", &mut pp, &[v4(12345)], None, 1, None);
        // Second tick should NOT send another ping (one already in flight).
        let actions = probe_tick(1001, 1_001_000, "local", "peer", &mut pp, &[v4(12345)], None, 1, None);
        let ping_count: usize = actions.iter().map(|a| match a {
            ProbeAction::SendPings { packets } => packets.len(),
            _ => 0,
        }).sum();
        assert_eq!(ping_count, 0);
    }

    #[test]
    fn probing_downgrades_after_all_fail() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345)], 1000);
        // Simulate MAX_PROBE_MISS consecutive misses.
        for _ in 0..MAX_PROBE_MISS {
            pp.probe_miss.insert(v4(12345), MAX_PROBE_MISS - 1);
            let _ = probe_tick(1000, 1_000_000, "local", "peer", &mut pp, &[v4(12345)], None, 1, None);
        }
        // Force all misses.
        pp.probe_miss.insert(v4(12345), MAX_PROBE_MISS);
        let actions = probe_tick(1031, 1_031_000, "local", "peer", &mut pp, &[v4(12345)], None, 1, None);
        assert!(actions.iter().any(|a| matches!(a, ProbeAction::DowngradeToRelay { .. })));
        assert_eq!(pp.mode, PeerPathMode::Relay);
    }

    #[test]
    fn direct_sends_keepalive() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.last_keepalive_sent_ms = 0;
        let actions = probe_tick(
            1001, 1_001_000, "local", "peer", &mut pp,
            &[v4(12345)], None, 1, None,
        );
        let ping_count: usize = actions.iter().map(|a| match a {
            ProbeAction::SendPings { packets } => packets.len(),
            _ => 0,
        }).sum();
        assert_eq!(ping_count, 1);
    }

    #[test]
    fn direct_downgrades_on_consecutive_no_pong() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.consecutive_no_pong = MAX_CONSECUTIVE_NO_PONG - 1;
        // One more miss triggers downgrade.
        pp.pending_pings.insert(99, (v4(12345), 500_000)); // expired
        let actions = probe_tick(
            1001, 1_001_000, "local", "peer", &mut pp,
            &[v4(12345)], None, 1, None,
        );
        assert!(actions.iter().any(|a| matches!(a, ProbeAction::DowngradeToRelay { .. })));
        assert_eq!(pp.mode, PeerPathMode::Relay);
    }

    #[test]
    fn pong_upgrades_from_probing() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345)], 1000);
        // Simulate MIN_PROBE_OK successful pongs after hold expires.
        for i in 0..MIN_PROBE_OK {
            pp.pending_pings.insert(i, (v4(12345), 1_030_000));
            let changed = process_pong(
                "peer", &mut pp, v4(12345), i, 20.0, Some(50.0), 1031,
            );
            if i < MIN_PROBE_OK - 1 {
                assert!(!changed, "should not upgrade at pong {}", i);
            }
        }
        assert_eq!(pp.mode, PeerPathMode::Direct { endpoint: v4(12345) });
    }

    #[test]
    fn pong_resets_no_pong_counter_in_direct() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.consecutive_no_pong = 2;
        pp.pending_pings.insert(42, (v4(12345), 999_000));
        process_pong("peer", &mut pp, v4(12345), 42, 15.0, None, 1000);
        assert_eq!(pp.consecutive_no_pong, 0);
    }

    #[test]
    fn pong_from_wrong_address_rejected() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.pending_pings.insert(42, (v4(12345), 999_000));
        // Pong from an unknown address — ignored (the ping is consumed and
        // will not be mis-counted as a later timeout, as in 3.0.x).
        let changed = process_pong("peer", &mut pp, v4b(54321), 42, 15.0, None, 1000);
        assert!(!changed);
        assert!(!pp.pending_pings.contains_key(&42));
        assert_eq!(pp.loss_window.len(), 0);
    }

    #[test]
    fn relay_path_pong_updates_baseline_only() {
        let mut pp = PeerPath::new();
        pp.relay_path_pending.insert(7);
        assert!(!process_pong("peer", &mut pp, v4(12345), 7, 80.0, None, 1000));
        assert_eq!(pp.relay_path_rtt_ms, Some(80.0));
        assert_eq!(pp.mode, PeerPathMode::Relay);
    }

    #[test]
    fn rtt_spike_downgrades_after_hold() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        pp.rtt_baseline_ms = Some(20.0);
        // Within the hold period: no downgrade.
        pp.pending_pings.insert(1, (v4(12345), 0));
        assert!(!process_pong("peer", &mut pp, v4(12345), 1, 100.0, None, 1001));
        assert!(matches!(pp.mode, PeerPathMode::Direct { .. }));
        // After the hold period: a spike (> 3 × baseline) downgrades.
        pp.rtt_baseline_ms = Some(20.0);
        pp.pending_pings.insert(2, (v4(12345), 0));
        assert!(process_pong("peer", &mut pp, v4(12345), 2, 100.0, None, 1000 + HOLD_DURATION_SECS));
        assert_eq!(pp.mode, PeerPathMode::Relay);
    }

    #[test]
    fn probing_sends_relay_path_probe_to_relay() {
        let mut pp = PeerPath::new();
        pp.start_probing(vec![v4(12345)], 1000);
        let relay: SocketAddr = "198.51.100.1:7000".parse().unwrap();
        let actions = probe_tick(1001, 1_001_000, "local", "peer", &mut pp, &[v4(12345)], None, 1, Some(relay));
        let to_relay = actions.iter().any(|a| matches!(a, ProbeAction::SendPings { packets } if packets.iter().any(|(t, _)| *t == relay)));
        assert!(to_relay);
        assert_eq!(pp.relay_path_pending.len(), 1);
    }

    #[test]
    fn pong_unknown_seq_ignored() {
        let mut pp = PeerPath::new();
        pp.set_direct(v4(12345), 1000);
        let changed = process_pong("peer", &mut pp, v4(12345), 999, 15.0, None, 1000);
        assert!(!changed);
    }
}