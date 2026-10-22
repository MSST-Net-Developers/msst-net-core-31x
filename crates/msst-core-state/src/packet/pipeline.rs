//! Inbound packet processing pipeline.
//!
//! This module ties the ACL engine, peer list, and connection tracker into a
//! single `process_inbound()` function that evaluates a parsed packet and
//! returns a `PipelineVerdict`.
//!
//! The pipeline is **pure** — it takes inputs and returns a verdict.  Side
//! effects (TUN injection, IPC notifications, access logging) are the
//! caller's responsibility.

use crate::packet::conn_track::ConnectionTracker;
use crate::packet::parsed::{ParsedPacket, TransportProtocol};
use crate::peer_list::PeerList;
use msst_acl_engine::{
    self as acl, Decision, DecisionReason, Direction, FirewallRule, MatchContext, Protocol,
};

// ---------------------------------------------------------------------------
// PipelineVerdict
// ---------------------------------------------------------------------------

/// The result of processing an inbound packet through the pipeline.
#[derive(Debug, Clone)]
pub enum PipelineVerdict {
    /// Packet should be injected into the TUN (allowed).
    Allow {
        /// The source device that sent this packet.
        src_device_id: String,
        /// The ACL decision (always `Action::Allow`).
        decision: Decision,
    },
    /// Packet should be dropped (denied by ACL).
    Deny {
        src_device_id: String,
        decision: Decision,
    },
    /// No ACL rule matched — interactive auth is needed.
    /// The packet should be queued (UDP) or RST'd (TCP) while waiting.
    NeedAuth {
        src_device_id: String,
        /// The ACL decision (default-deny).
        decision: Decision,
    },
    /// Source IP is not a known peer — drop silently.
    UnknownSource {
        src_ip: std::net::IpAddr,
    },
    /// Packet is a reply to a tracked outbound connection — allow immediately
    /// without ACL evaluation (the "related traffic" fast path).
    Related {
        src_device_id: String,
    },
    /// ICMP packet — allowed by ping policy.
    IcmpAllowed {
        src_device_id: Option<String>,
    },
    /// ICMP echo request — blocked by ping policy.
    IcmpBlocked,
    /// Non-TCP/UDP/ICMP packet — pass through (no ACL applies).
    PassThrough {
        src_device_id: Option<String>,
    },
    /// Dropped by the guest restriction: an unauthenticated party (us or
    /// the sender) may only exchange new traffic with peers it currently
    /// shares a room with.  See [`guest_access_blocked`].
    GuestBlocked {
        src_device_id: String,
    },
}

// ---------------------------------------------------------------------------
// Guest restriction (3.0.x `guest_access_blocked`)
// ---------------------------------------------------------------------------

/// Whether traffic from a peer must be dropped because a guest is involved.
///
/// Symmetric: it doesn't matter whether the guest is the sender or the
/// receiver.  `in_room` is *current* co-membership (no grace period).
pub fn guest_access_blocked(local_authenticated: bool, src_authenticated: bool, in_room: bool) -> bool {
    (!local_authenticated || !src_authenticated) && !in_room
}

/// Apply the guest restriction to a pipeline verdict.
///
/// Applies to everything that was ACL-evaluated (Allow / Deny / NeedAuth)
/// and to ICMP echo requests from known peers.  Related (established)
/// traffic, unknown sources and non-TCP/UDP pass-through are unaffected,
/// exactly as in 3.0.x.
pub fn apply_guest_policy(
    verdict: PipelineVerdict,
    packet: &ParsedPacket,
    peer_list: &PeerList,
    room_peers: &std::collections::HashSet<String>,
    local_authenticated: bool,
) -> PipelineVerdict {
    let src = match &verdict {
        PipelineVerdict::Allow { src_device_id, .. }
        | PipelineVerdict::Deny { src_device_id, .. }
        | PipelineVerdict::NeedAuth { src_device_id, .. } => Some(src_device_id.clone()),
        PipelineVerdict::IcmpAllowed { src_device_id: Some(id) } if packet.is_icmp_echo_request => Some(id.clone()),
        _ => None,
    };
    let Some(src) = src else { return verdict };
    let src_auth = peer_list.get(&src).is_some_and(|e| e.is_authenticated);
    if guest_access_blocked(local_authenticated, src_auth, room_peers.contains(&src)) {
        PipelineVerdict::GuestBlocked { src_device_id: src }
    } else {
        verdict
    }
}

// ---------------------------------------------------------------------------
// ICMP ping policy
// ---------------------------------------------------------------------------

/// Whether ICMP echo-request (ping) is currently enabled.
pub trait PingPolicy {
    fn is_ping_enabled(&self) -> bool;
}

/// A simple static ping policy.
pub struct StaticPingPolicy {
    pub enabled: bool,
}

impl PingPolicy for StaticPingPolicy {
    fn is_ping_enabled(&self) -> bool {
        self.enabled
    }
}

// ---------------------------------------------------------------------------
// process_inbound
// ---------------------------------------------------------------------------

/// Evaluate an inbound packet against the ACL engine, peer list, and
/// connection tracker.
///
/// This is the main entry point for the packet processing pipeline.
/// Returns a [`PipelineVerdict`] that tells the caller what to do with the
/// packet.
///
/// The pipeline does NOT mutate the connection tracker for outbound packets —
/// that happens in the outbound path.  It only reads/refreshes for inbound
/// related-traffic detection.
pub fn process_inbound(
    packet: &ParsedPacket,
    peer_list: &PeerList,
    acl_rules: &[FirewallRule],
    conn_track: &ConnectionTracker,
    local_user_id: &str,
    room_peers: &std::collections::HashSet<String>,
    ping_policy: &dyn PingPolicy,
    now_unix: i64,
) -> PipelineVerdict {
    // ── 1. ICMP handling (no ACL, just ping policy) ───────────────────────
    if packet.proto == TransportProtocol::Icmp {
        let src_device_id = peer_list.lookup_device_id_by_ip(&packet.src_ip)
            .map(|s| s.to_string());

        if packet.is_icmp_echo_request {
            if !ping_policy.is_ping_enabled() {
                return PipelineVerdict::IcmpBlocked;
            }
        }
        return PipelineVerdict::IcmpAllowed { src_device_id };
    }

    // ── 2. Non-TCP/UDP → pass through ─────────────────────────────────────
    let acl_proto = match packet.proto {
        TransportProtocol::Tcp => Protocol::Tcp,
        TransportProtocol::Udp => Protocol::Udp,
        _ => {
            let src_device_id = peer_list.lookup_device_id_by_ip(&packet.src_ip)
                .map(|s| s.to_string());
            return PipelineVerdict::PassThrough { src_device_id };
        }
    };

    // ── 3. Connection tracking fast path ──────────────────────────────────
    let proto_num = packet.proto.number();
    if conn_track.is_related(
        packet.src_ip, packet.src_port,
        packet.dst_ip, packet.dst_port,
        proto_num, now_unix,
    ) {
        let src_device_id = peer_list.lookup_device_id_by_ip(&packet.src_ip)
            .unwrap_or("unknown")
            .to_string();
        return PipelineVerdict::Related { src_device_id };
    }

    // ── 4. Resolve source device ──────────────────────────────────────────
    let src_device_id = match peer_list.lookup_device_id_by_ip(&packet.src_ip) {
        Some(id) => id.to_string(),
        None => return PipelineVerdict::UnknownSource { src_ip: packet.src_ip },
    };

    // ── 5. ACL evaluation ─────────────────────────────────────────────────
    let in_room = room_peers.contains(&src_device_id);
    let ctx = MatchContext::new(
        &src_device_id,
        acl_proto,
        packet.dst_port,
        Direction::Inbound,
        in_room,
        now_unix,
        local_user_id,
    );

    // Device mnemonics in rules (left over from 3.0.x and not yet migrated
    // to IDs) are resolved against the current peer list, as in 3.0.x.
    let resolve_mnemonic = |m: &str| -> Option<String> {
        peer_list.resolve_device_mnemonic(m, local_user_id).map(str::to_string)
    };
    let ctx = ctx.with_mnemonic_resolver(&resolve_mnemonic);

    let resolve_user = |uid: &str| -> Vec<String> {
        peer_list.devices_for_user(uid).into_iter().map(|s| s.to_string()).collect()
    };

    let decision = acl::evaluate(&ctx, acl_rules, resolve_user);

    match decision.action {
        acl::Action::Allow => PipelineVerdict::Allow {
            src_device_id,
            decision,
        },
        acl::Action::Deny => {
            if decision.reason == DecisionReason::DefaultDeny {
                PipelineVerdict::NeedAuth { src_device_id, decision }
            } else {
                PipelineVerdict::Deny { src_device_id, decision }
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::parsed::ParsedPacket;
    use crate::peer_list::PeerList;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};

    const NOW: i64 = 1_700_000_000;
    const LOCAL_USER: &str = "usr-local";
    const DEVICE_A: &str = "device-aabbccdd";
    const DEVICE_B: &str = "device-11223344";

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6() -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    }

    fn make_peer_list() -> PeerList {
        let mut pl = PeerList::new();
        pl.upsert(DEVICE_A, v4(172, 22, 1, 1), v6(), Some("usr-alice"), Some("desktop"), Some("alice"), None, None, None, false, NOW);
        pl.upsert(DEVICE_B, v4(172, 22, 1, 2), v6(), Some("usr-bob"), Some("laptop"), Some("bob"), None, None, None, false, NOW);
        pl
    }

    fn tcp_packet(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> ParsedPacket {
        ParsedPacket {
            src_ip: src,
            dst_ip: dst,
            proto: TransportProtocol::Tcp,
            src_port,
            dst_port,
            is_icmp_echo_request: false,
            fragment: None,
        }
    }

    fn _udp_packet(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> ParsedPacket {
        ParsedPacket {
            src_ip: src,
            dst_ip: dst,
            proto: TransportProtocol::Udp,
            src_port,
            dst_port,
            is_icmp_echo_request: false,
            fragment: None,
        }
    }

    fn icmp_echo(src: IpAddr, dst: IpAddr) -> ParsedPacket {
        ParsedPacket {
            src_ip: src,
            dst_ip: dst,
            proto: TransportProtocol::Icmp,
            src_port: 0,
            dst_port: 0,
            is_icmp_echo_request: true,
            fragment: None,
        }
    }

    fn ping(enabled: bool) -> StaticPingPolicy {
        StaticPingPolicy { enabled }
    }

    fn empty_room() -> HashSet<String> { HashSet::new() }

    // ── Guest restriction ─────────────────────────────────────────────────

    #[test]
    fn guest_rule_truth_table() {
        assert!(!guest_access_blocked(true, true, false));
        assert!(guest_access_blocked(false, true, false));
        assert!(guest_access_blocked(true, false, false));
        assert!(!guest_access_blocked(false, false, true)); // shared room
    }

    fn allow_all_tcp() -> Vec<FirewallRule> {
        vec![FirewallRule {
            id: "all".into(),
            permission_group: acl::PermissionGroup::Devices { ids: vec!["*".into()] },
            protocol_ports: vec![acl::ProtocolPort::wildcard(Protocol::Tcp)],
            action: acl::Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }]
    }

    #[test]
    fn guest_policy_blocks_unauthenticated_outside_room() {
        let pl = make_peer_list(); // peers are unauthenticated
        let ct = ConnectionTracker::new();
        let pkt = tcp_packet(v4(172, 22, 1, 1), v4(172, 22, 0, 1), 5000, 80);
        let v = process_inbound(&pkt, &pl, &allow_all_tcp(), &ct, LOCAL_USER, &empty_room(), &ping(true), NOW);
        assert!(matches!(v, PipelineVerdict::Allow { .. }));
        let v = apply_guest_policy(v, &pkt, &pl, &empty_room(), true);
        assert!(matches!(v, PipelineVerdict::GuestBlocked { ref src_device_id } if src_device_id == DEVICE_A));

        // Same packet while sharing a room: allowed.
        let room: HashSet<String> = [DEVICE_A.to_string()].into();
        let v = process_inbound(&pkt, &pl, &allow_all_tcp(), &ct, LOCAL_USER, &room, &ping(true), NOW);
        assert!(matches!(apply_guest_policy(v, &pkt, &pl, &room, true), PipelineVerdict::Allow { .. }));
    }

    #[test]
    fn guest_policy_allows_authenticated_pair_and_exempts_icmp_reply() {
        let mut pl = make_peer_list();
        pl.upsert(DEVICE_A, v4(172, 22, 1, 1), v6(), Some("usr-alice"), Some("desktop"), Some("alice"), None, None, None, true, NOW);
        let ct = ConnectionTracker::new();
        let pkt = tcp_packet(v4(172, 22, 1, 1), v4(172, 22, 0, 1), 5000, 80);
        let v = process_inbound(&pkt, &pl, &allow_all_tcp(), &ct, LOCAL_USER, &empty_room(), &ping(true), NOW);
        assert!(matches!(apply_guest_policy(v, &pkt, &pl, &empty_room(), true), PipelineVerdict::Allow { .. }));
        // Local device unauthenticated → blocked even though the peer is.
        let v = process_inbound(&pkt, &pl, &allow_all_tcp(), &ct, LOCAL_USER, &empty_room(), &ping(true), NOW);
        assert!(matches!(apply_guest_policy(v, &pkt, &pl, &empty_room(), false), PipelineVerdict::GuestBlocked { .. }));

        // ICMP echo request from a guest outside the room: blocked; non-echo ICMP: not.
        let echo = icmp_echo(v4(172, 22, 1, 2), v4(172, 22, 0, 1));
        let v = process_inbound(&echo, &pl, &[], &ct, LOCAL_USER, &empty_room(), &ping(true), NOW);
        assert!(matches!(apply_guest_policy(v, &echo, &pl, &empty_room(), true), PipelineVerdict::GuestBlocked { .. }));
        let mut reply = echo.clone();
        reply.is_icmp_echo_request = false;
        let v = process_inbound(&reply, &pl, &[], &ct, LOCAL_USER, &empty_room(), &ping(true), NOW);
        assert!(matches!(apply_guest_policy(v, &reply, &pl, &empty_room(), true), PipelineVerdict::IcmpAllowed { .. }));
    }

    #[test]
    fn legacy_device_mnemonic_rule_matches() {
        // 3.0.x-style rule naming the peer by combined mnemonic.
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();
        let mut rules = allow_all_tcp();
        rules[0].permission_group = acl::PermissionGroup::Devices { ids: vec!["desktop.alice".into()] };
        let from_a = tcp_packet(v4(172, 22, 1, 1), v4(172, 22, 0, 1), 5000, 80);
        let from_b = tcp_packet(v4(172, 22, 1, 2), v4(172, 22, 0, 1), 5000, 80);
        assert!(matches!(process_inbound(&from_a, &pl, &rules, &ct, LOCAL_USER, &empty_room(), &ping(true), NOW), PipelineVerdict::Allow { .. }));
        assert!(matches!(process_inbound(&from_b, &pl, &rules, &ct, LOCAL_USER, &empty_room(), &ping(true), NOW), PipelineVerdict::NeedAuth { .. }));
    }

    // ── Unknown source ────────────────────────────────────────────────────

    #[test]
    fn unknown_source_ip_returns_unknown() {
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();
        let pkt = tcp_packet(v4(10, 0, 0, 1), v4(172, 22, 1, 1), 54321, 80);

        let v = process_inbound(&pkt, &pl, &[], &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);
        assert!(matches!(v, PipelineVerdict::UnknownSource { src_ip } if src_ip == v4(10, 0, 0, 1)));
    }

    // ── Connection tracking fast path ─────────────────────────────────────

    #[test]
    fn related_traffic_allows_without_acl() {
        let pl = make_peer_list();
        let mut ct = ConnectionTracker::new();
        // Record outbound: us → DEVICE_A
        ct.record_outbound(v4(172, 22, 1, 100), 12345, v4(172, 22, 1, 1), 80, 6, NOW);

        // Inbound reply from DEVICE_A → us (reverse tuple)
        let pkt = tcp_packet(v4(172, 22, 1, 1), v4(172, 22, 1, 100), 80, 12345);
        let v = process_inbound(&pkt, &pl, &[], &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);
        assert!(matches!(v, PipelineVerdict::Related { .. }));
    }

    // ── ICMP ──────────────────────────────────────────────────────────────

    #[test]
    fn icmp_echo_allowed_when_ping_enabled() {
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();
        let pkt = icmp_echo(v4(172, 22, 1, 1), v4(172, 22, 1, 100));

        let v = process_inbound(&pkt, &pl, &[], &ct, LOCAL_USER, &empty_room(), &ping(true), NOW);
        assert!(matches!(v, PipelineVerdict::IcmpAllowed { .. }));
    }

    #[test]
    fn icmp_echo_blocked_when_ping_disabled() {
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();
        let pkt = icmp_echo(v4(172, 22, 1, 1), v4(172, 22, 1, 100));

        let v = process_inbound(&pkt, &pl, &[], &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);
        assert!(matches!(v, PipelineVerdict::IcmpBlocked));
    }

    // ── ACL allow ─────────────────────────────────────────────────────────

    #[test]
    fn acl_allow_device_rule() {
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();
        let rules = vec![acl::FirewallRule {
            id: "r1".into(),
            permission_group: acl::PermissionGroup::Devices { ids: vec![DEVICE_A.into()] },
            protocol_ports: vec![acl::ProtocolPort::single(acl::Protocol::Tcp, 25565)],
            action: acl::Action::Allow,
            direction: acl::Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: Some("Minecraft".into()),
        }];

        let pkt = tcp_packet(v4(172, 22, 1, 1), v4(172, 22, 1, 100), 54321, 25565);
        let v = process_inbound(&pkt, &pl, &rules, &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);

        match v {
            PipelineVerdict::Allow { src_device_id, decision } => {
                assert_eq!(src_device_id, DEVICE_A);
                assert!(decision.is_allow());
                assert_eq!(decision.matched_rule.as_ref().unwrap().rule_id, "r1");
            }
            other => panic!("expected Allow, got {:?}", other),
        }
    }

    // ── ACL deny (explicit rule) ──────────────────────────────────────────

    #[test]
    fn acl_deny_explicit_rule() {
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();
        let rules = vec![acl::FirewallRule {
            id: "deny-ssh".into(),
            permission_group: acl::PermissionGroup::Devices { ids: vec!["*".into()] },
            protocol_ports: vec![acl::ProtocolPort::single(acl::Protocol::Tcp, 22)],
            action: acl::Action::Deny,
            direction: acl::Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: Some("Block SSH".into()),
        }];

        let pkt = tcp_packet(v4(172, 22, 1, 1), v4(172, 22, 1, 100), 54321, 22);
        let v = process_inbound(&pkt, &pl, &rules, &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);

        match v {
            PipelineVerdict::Deny { src_device_id, decision } => {
                assert_eq!(src_device_id, DEVICE_A);
                assert!(!decision.is_allow());
                assert_eq!(decision.matched_rule.as_ref().unwrap().rule_id, "deny-ssh");
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    // ── ACL need auth (default deny) ──────────────────────────────────────

    #[test]
    fn no_rules_triggers_need_auth() {
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();

        let pkt = tcp_packet(v4(172, 22, 1, 1), v4(172, 22, 1, 100), 54321, 25565);
        let v = process_inbound(&pkt, &pl, &[], &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);

        match v {
            PipelineVerdict::NeedAuth { src_device_id, decision } => {
                assert_eq!(src_device_id, DEVICE_A);
                assert_eq!(decision.reason, DecisionReason::DefaultDeny);
            }
            other => panic!("expected NeedAuth, got {:?}", other),
        }
    }

    // ── User-level rule via PeerList ───────────────────────────────────────

    #[test]
    fn user_level_allow_resolves_via_peer_list() {
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();
        // Allow all of Alice's devices on port 80.
        let rules = vec![acl::FirewallRule {
            id: "alice-web".into(),
            permission_group: acl::PermissionGroup::Users { ids: vec!["usr-alice".into()] },
            protocol_ports: vec![acl::ProtocolPort::single(acl::Protocol::Tcp, 80)],
            action: acl::Action::Allow,
            direction: acl::Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }];

        // DEVICE_A belongs to Alice → allowed.
        let pkt = tcp_packet(v4(172, 22, 1, 1), v4(172, 22, 1, 100), 54321, 80);
        let v = process_inbound(&pkt, &pl, &rules, &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);
        assert!(matches!(v, PipelineVerdict::Allow { .. }));

        // DEVICE_B belongs to Bob → default deny.
        let pkt = tcp_packet(v4(172, 22, 1, 2), v4(172, 22, 1, 100), 54321, 80);
        let v = process_inbound(&pkt, &pl, &rules, &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);
        assert!(matches!(v, PipelineVerdict::NeedAuth { .. }));
    }

    // ── Space-level rule (room peers) ─────────────────────────────────────

    #[test]
    fn space_level_allow_when_in_room() {
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();
        let rules = vec![acl::FirewallRule {
            id: "room-allow".into(),
            permission_group: acl::PermissionGroup::Space,
            protocol_ports: vec![acl::ProtocolPort::single(acl::Protocol::Tcp, 8080)],
            action: acl::Action::Allow,
            direction: acl::Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }];

        // Without room membership → need auth.
        let pkt = tcp_packet(v4(172, 22, 1, 1), v4(172, 22, 1, 100), 54321, 8080);
        let v = process_inbound(&pkt, &pl, &rules, &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);
        assert!(matches!(v, PipelineVerdict::NeedAuth { .. }));

        // With room membership → allow.
        let mut room = HashSet::new();
        room.insert(DEVICE_A.into());
        let v = process_inbound(&pkt, &pl, &rules, &ct, LOCAL_USER, &room, &ping(false), NOW);
        assert!(matches!(v, PipelineVerdict::Allow { .. }));
    }

    // ── Non-TCP/UDP pass through ──────────────────────────────────────────

    #[test]
    fn non_tcp_udp_pass_through() {
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();
        let pkt = ParsedPacket {
            src_ip: v4(172, 22, 1, 1),
            dst_ip: v4(172, 22, 1, 100),
            proto: TransportProtocol::Other(47), // GRE
            src_port: 0,
            dst_port: 0,
            is_icmp_echo_request: false,
            fragment: None,
        };
        let v = process_inbound(&pkt, &pl, &[], &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);
        assert!(matches!(v, PipelineVerdict::PassThrough { .. }));
    }

    // ── End-to-end: priority chain through pipeline ───────────────────────

    #[test]
    fn priority_device_deny_beats_user_allow() {
        let pl = make_peer_list();
        let ct = ConnectionTracker::new();
        let rules = vec![
            // User-level allow for Alice.
            acl::FirewallRule {
                id: "alice-allow".into(),
                permission_group: acl::PermissionGroup::Users { ids: vec!["usr-alice".into()] },
                protocol_ports: vec![acl::ProtocolPort::single(acl::Protocol::Tcp, 80)],
                action: acl::Action::Allow,
                direction: acl::Direction::Inbound,
                expires_at: None,
                enabled: true,
                comment: None,
            },
            // Device-level deny for DEVICE_A specifically.
            acl::FirewallRule {
                id: "device-a-deny".into(),
                permission_group: acl::PermissionGroup::Devices { ids: vec![DEVICE_A.into()] },
                protocol_ports: vec![acl::ProtocolPort::single(acl::Protocol::Tcp, 80)],
                action: acl::Action::Deny,
                direction: acl::Direction::Inbound,
                expires_at: None,
                enabled: true,
                comment: None,
            },
        ];

        let pkt = tcp_packet(v4(172, 22, 1, 1), v4(172, 22, 1, 100), 54321, 80);
        let v = process_inbound(&pkt, &pl, &rules, &ct, LOCAL_USER, &empty_room(), &ping(false), NOW);

        // Device deny should win over user allow.
        match v {
            PipelineVerdict::Deny { decision, .. } => {
                assert_eq!(decision.reason, DecisionReason::DeviceDenyPriority);
                assert_eq!(decision.matched_rule.as_ref().unwrap().rule_id, "device-a-deny");
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }
}