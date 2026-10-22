//! Inbound delivery — the firewall gate in front of the TUN, and the
//! interactive authorization flow (ported from 3.0.x `deliver_inbound` /
//! `trigger_interactive_auth` / `auth_decision`).
//!
//! Every IP packet from a peer (decrypted from its WireGuard session, see
//! [`from_peer_address`]) goes through [`deliver_inbound`].  The only other
//! way into the TUN is verified discovery broadcasts (`crate::discovery`).

use crate::state::CoreState;
use msst_acl_engine::{Action, Direction, FirewallRule, PermissionGroup, Protocol, ProtocolPort, Scope};
use msst_core_state::firewall::access_log::{AccessDecision, AccessLogEntry, AccessReason};
use msst_core_state::firewall::auth::AuthKey;
use msst_core_state::packet::parsed::{ParsedPacket, TransportProtocol};
use msst_core_state::packet::{self, FlowOrigin, LaterFragment, PipelineVerdict, StaticPingPolicy};
use msst_ipc_protocol::{AuthDecision, IpcError, IpcEvent};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// "Once" decisions create a rule that expires after this long (3.0.x).
const ONCE_RULE_TTL_SECS: i64 = 600;
/// Pending requests expire after this long (`Firewall` constant, 3.0.x).
const AUTH_TIMEOUT_SECS: i64 = 60;

fn proto_of(p: &ParsedPacket) -> Option<Protocol> {
    match p.proto {
        TransportProtocol::Tcp => Some(Protocol::Tcp),
        TransportProtocol::Udp => Some(Protocol::Udp),
        _ => None,
    }
}

fn proto_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

/// Whether a packet decrypted from `device_id`'s WireGuard session carries
/// that peer's own virtual address as its source (WireGuard "AllowedIPs").
pub async fn from_peer_address(state: &CoreState, device_id: &str, pkt: &[u8]) -> bool {
    let Some(parsed) = crate::runtime::parse_ip_packet(pkt) else { return false };
    let net = state.net.read().await;
    net.peer_list.get(device_id).is_some_and(|e| e.ipv4 == parsed.src_ip || e.ipv6 == parsed.src_ip)
}

/// The verdict of a fragmented datagram's first fragment, applied to its
/// later fragments (`CoreState::frag_track`).
#[derive(Debug, Clone, PartialEq)]
pub enum FragVerdict {
    Deliver,
    Drop,
    /// Waiting for an interactive decision: queue with the first fragment
    /// (UDP), replayed together on approval.
    QueueForAuth(AuthKey),
}

impl FragVerdict {
    fn of(verdict: &PipelineVerdict, parsed: &ParsedPacket) -> Self {
        match verdict {
            PipelineVerdict::Allow { .. }
            | PipelineVerdict::Related { .. }
            | PipelineVerdict::IcmpAllowed { .. } => FragVerdict::Deliver,
            // TCP is answered with a RST, so its first fragment isn't queued.
            PipelineVerdict::NeedAuth { src_device_id, .. } if parsed.proto == TransportProtocol::Udp => {
                FragVerdict::QueueForAuth(AuthKey { src_device_id: src_device_id.clone(), proto: Protocol::Udp, dst_port: parsed.dst_port })
            }
            _ => FragVerdict::Drop,
        }
    }
}

/// Apply a first fragment's verdict to one of its later fragments.
async fn deliver_fragment(state: &CoreState, tun_tx: &mpsc::Sender<Vec<u8>>, verdict: &FragVerdict, pkt: Vec<u8>) {
    match verdict {
        FragVerdict::Deliver => {
            let _ = tun_tx.send(pkt).await;
        }
        FragVerdict::Drop => {}
        FragVerdict::QueueForAuth(key) => {
            // Queued only while the request is pending (bounded queue).
            state.firewall.lock().await.queue_packet_for_auth(key, pkt);
        }
    }
}

/// Run one inbound IP packet through the firewall and deliver it if allowed.
///
/// A fragmented datagram is evaluated on its first fragment, the only one
/// with the transport header; the later fragments follow that verdict
/// (`msst_core_state::packet::fragment`).
pub async fn deliver_inbound(state: &Arc<CoreState>, tun_tx: &mpsc::Sender<Vec<u8>>, pkt: Vec<u8>) {
    let Some(parsed) = crate::runtime::parse_ip_packet(&pkt) else {
        debug!("inbound: malformed or unevaluable IP packet ({} bytes), dropping", pkt.len());
        return;
    };
    let now = crate::runtime::current_unix();
    let frag_key = packet::FragKey::of(&parsed);

    if let (Some(key), true) = (frag_key, parsed.is_later_fragment()) {
        let later = state.frag_track.lock().unwrap_or_else(|e| e.into_inner()).on_later(key, pkt, now);
        match later {
            LaterFragment::Decided(verdict, pkt) => deliver_fragment(state, tun_tx, &verdict, pkt).await,
            LaterFragment::Held => {}
            LaterFragment::Dropped => debug!("inbound: fragment table full, dropping a fragment from {}", parsed.src_ip),
        }
        return;
    }

    let verdict = {
        let net = state.net.read().await;
        let ping_policy = StaticPingPolicy { enabled: net.ping_enabled };
        let verdict = {
            let conn_track = state.conn_track.lock().unwrap_or_else(|e| e.into_inner());
            packet::pipeline::process_inbound(
                &parsed, &net.peer_list, &net.acl_rules, &conn_track,
                &net.local_user_id, &net.room_peers, &ping_policy, now,
            )
        };
        packet::pipeline::apply_guest_policy(verdict, &parsed, &net.peer_list, &net.room_peers, net.local_authenticated)
    };
    let frag_verdict = frag_key.map(|key| (key, FragVerdict::of(&verdict, &parsed)));

    match verdict {
        PipelineVerdict::Allow { src_device_id, decision } => {
            state.contacts.lock().unwrap_or_else(|e| e.into_inner()).update_communication(&src_device_id, now);
            crate::diagnostics::traffic(state, &src_device_id).rx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some(m) = &decision.matched_rule {
                // Remember what let the flow in, so revoking it ends the flow.
                let origin = FlowOrigin { device_id: src_device_id.clone(), rule_id: m.rule_id.clone(), room_scope: m.scope == Scope::Space };
                record_admitted(state, &parsed, origin, now);
            }
            if let (Some(proto), Some(m)) = (proto_of(&parsed), decision.matched_rule) {
                log_access(state, &src_device_id, proto, parsed.dst_port, AccessDecision::Allow,
                    AccessReason::MatchedRule { rule_id: m.rule_id.clone(), comment: m.comment }, Some(m.rule_id)).await;
            }
            let _ = tun_tx.send(pkt).await;
        }
        PipelineVerdict::Related { .. } | PipelineVerdict::IcmpAllowed { .. } => {
            let _ = tun_tx.send(pkt).await;
        }
        PipelineVerdict::ProtocolBlocked { src_device_id, proto } => {
            if let Some(src) = &src_device_id {
                crate::diagnostics::traffic(state, src).drop.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            debug!("inbound: IP protocol {} from {} blocked (no ACL for it; default deny)", proto,
                src_device_id.as_deref().unwrap_or("unknown source"));
        }
        PipelineVerdict::Deny { src_device_id, decision } => {
            crate::diagnostics::traffic(state, &src_device_id).drop.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!("inbound: denied {}:{} from {}", parsed.proto.number(), parsed.dst_port, src_device_id);
            if let (Some(proto), Some(m)) = (proto_of(&parsed), decision.matched_rule) {
                log_access(state, &src_device_id, proto, parsed.dst_port, AccessDecision::Deny,
                    AccessReason::MatchedRule { rule_id: m.rule_id.clone(), comment: m.comment }, Some(m.rule_id)).await;
            }
        }
        PipelineVerdict::NeedAuth { src_device_id, .. } => {
            crate::diagnostics::traffic(state, &src_device_id).drop.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some(proto) = proto_of(&parsed) {
                on_need_auth(state, src_device_id, proto, &parsed, pkt).await;
            }
        }
        PipelineVerdict::GuestBlocked { src_device_id } => {
            debug!("inbound: dropped packet from {} — guest access requires sharing a room", src_device_id);
        }
        PipelineVerdict::IcmpBlocked => debug!("inbound: ICMP echo request blocked (ping disabled)"),
        PipelineVerdict::UnknownSource { src_ip } => debug!("inbound: packet from unknown IP {}, dropping", src_ip),
    }

    // A first fragment: after it was handled (an auth request now exists),
    // release the later fragments that arrived before it.
    if let Some((key, verdict)) = frag_verdict {
        let held = state.frag_track.lock().unwrap_or_else(|e| e.into_inner()).on_first(key, verdict.clone(), now);
        for p in held {
            deliver_fragment(state, tun_tx, &verdict, p).await;
        }
    }
}

async fn log_access(
    state: &CoreState,
    src: &str,
    proto: Protocol,
    dst_port: u16,
    decision: AccessDecision,
    reason: AccessReason,
    rule_id: Option<String>,
) -> String {
    let mut fw = state.firewall.lock().await;
    let id = fw.new_id();
    fw.log_access(AccessLogEntry {
        id: id.clone(),
        src_device_id: src.to_string(),
        service_name: crate::acl::parse::service_display_name(proto_str(proto), dst_port).map(str::to_string),
        proto,
        dst_port,
        decision,
        reason,
        timestamp_ms: crate::runtime::current_time_ms(),
        rule_id,
        count: 1,
    });
    id
}

/// No rule matched: start (or join) an interactive authorization request.
///
/// TCP is answered with an immediate RST so the remote `connect()` fails
/// fast and can be retried after approval; UDP datagrams are queued and
/// replayed on approval (bounded queue).
async fn on_need_auth(state: &Arc<CoreState>, src: String, proto: Protocol, parsed: &ParsedPacket, pkt: Vec<u8>) {
    let key = AuthKey { src_device_id: src.clone(), proto, dst_port: parsed.dst_port };
    let initial = if proto == Protocol::Tcp {
        if let Some(rst) = build_tcp_rst(&pkt) {
            debug!("inbound: auth needed, sending TCP RST to {} for tcp:{}", src, parsed.dst_port);
            crate::runtime::send_to_peer(&rst, state).await;
        }
        None
    } else {
        Some(pkt)
    };

    {
        let mut fw = state.firewall.lock().await;
        if fw.has_pending_auth(&key) {
            if let Some(p) = initial {
                fw.queue_packet_for_auth(&key, p);
            }
            return;
        }
    }

    if !auth_eligible(state, &src).await {
        debug!("inbound: dropping packet from {} (not own device, recent contact or rule-referenced)", src);
        return;
    }

    let service_name = crate::acl::parse::service_display_name(proto_str(proto), parsed.dst_port).map(str::to_string);
    let request_id = {
        let mut fw = state.firewall.lock().await;
        if fw.has_pending_auth(&key) {
            // Raced with another packet while checking eligibility.
            if let Some(p) = initial {
                fw.queue_packet_for_auth(&key, p);
            }
            return;
        }
        if !fw.auth_capacity(&src) {
            // Too many open prompts (e.g. a port scan): drop without asking.
            debug!("inbound: auth request limit reached, dropping {} → {}:{}", src, proto_str(proto), parsed.dst_port);
            let log_id = fw.new_id();
            fw.log_access(AccessLogEntry {
                id: log_id,
                src_device_id: src.clone(),
                service_name,
                proto,
                dst_port: parsed.dst_port,
                decision: AccessDecision::SilentDeny,
                reason: AccessReason::InteractiveAuthLimit,
                timestamp_ms: crate::runtime::current_time_ms(),
                rule_id: None,
                count: 1,
            });
            return;
        }
        let log_id = fw.new_id();
        fw.log_access(AccessLogEntry {
            id: log_id.clone(),
            src_device_id: src.clone(),
            service_name: service_name.clone(),
            proto,
            dst_port: parsed.dst_port,
            decision: AccessDecision::SilentDeny,
            reason: AccessReason::InteractiveAuth,
            timestamp_ms: crate::runtime::current_time_ms(),
            rule_id: None,
            count: 1,
        });
        let request_id = fw.register_pending_auth(key.clone(), src.clone(), log_id);
        if let Some(p) = initial {
            fw.queue_packet_for_auth(&key, p);
        }
        request_id
    };

    let (src_user_id, src_device_display_name, src_user_display_name) = {
        let net = state.net.read().await;
        let e = net.peer_list.get(&src);
        (e.and_then(|e| e.user_id.clone()), e.and_then(|e| e.display_name.clone()), e.and_then(|e| e.user_display_name.clone()))
    };
    info!("inbound: interactive auth required: {} → {}:{} (request {})", src, proto_str(proto), parsed.dst_port, request_id);
    state.next_generation();
    state.emit_ipc_event(IpcEvent::AccessRequestCreated {
        request_id,
        src_device_id: src,
        src_user_id,
        src_device_display_name,
        src_user_display_name,
        proto: proto_str(proto).into(),
        dst_port: parsed.dst_port,
        service_name,
    });
}

/// Who may trigger an interactive prompt (3.0.x rules):
/// - room mode (we're in a room): any known peer;
/// - large-LAN mode: our own devices, recent contacts, and devices named
///   in one of our rules.  Everyone else is dropped silently.
async fn auth_eligible(state: &CoreState, src: &str) -> bool {
    let now = crate::runtime::current_unix();
    let net = state.net.read().await;
    if !net.joined_rooms.is_empty() {
        return net.peer_list.contains(src);
    }
    let own = !net.local_user_id.is_empty()
        && net.peer_list.get(src).and_then(|e| e.user_id.as_deref()) == Some(net.local_user_id.as_str());
    let referenced = net.acl_rules.iter().any(|r| {
        r.is_active(now) && matches!(&r.permission_group, PermissionGroup::Devices { ids } if ids.iter().any(|i| i == src))
    });
    drop(net);
    own || referenced || state.contacts.lock().unwrap_or_else(|e| e.into_inner()).is_recent_contact(src, now)
}

// ---------------------------------------------------------------------------
// Decisions, timeouts, queries
// ---------------------------------------------------------------------------

/// Apply the user's decision: create the corresponding device-level rule
/// (expiring after 10 min for "once"), finalize the access-log entry and,
/// on allow, deliver the packets queued while waiting.
///
/// The request stays pending (marked as being resolved) until its rule
/// exists, so a failure leaves it answerable.  An expired request is
/// `not_found`, even before the timeout sweep has reported it.
pub async fn resolve_auth(state: &Arc<CoreState>, request_id: &str, decision: AuthDecision) -> Result<Value, IpcError> {
    let now = crate::runtime::current_unix();
    let (action, expires_at, name) = match decision {
        AuthDecision::AllowOnce => (Action::Allow, Some(now + ONCE_RULE_TTL_SECS), "allow_once"),
        AuthDecision::AlwaysAllow => (Action::Allow, None, "always_allow"),
        AuthDecision::DenyOnce => (Action::Deny, Some(now + ONCE_RULE_TTL_SECS), "deny_once"),
        AuthDecision::AlwaysDeny => (Action::Deny, None, "always_deny"),
    };
    let not_found = || IpcError {
        code: "not_found".into(),
        message: format!("Auth request '{}' not found, expired or already resolved", request_id),
    };
    let key = state.firewall.lock().await.begin_resolve_auth(request_id, now).ok_or_else(not_found)?;
    let key = &key;
    let rule = FirewallRule {
        id: crate::acl::parse::new_id(),
        permission_group: PermissionGroup::Devices { ids: vec![key.src_device_id.clone()] },
        protocol_ports: vec![ProtocolPort::single(key.proto, key.dst_port)],
        action: action.clone(),
        direction: Direction::Inbound,
        expires_at,
        enabled: true,
        comment: Some(format!(
            "Auto: {} {} {}:{} (request {})",
            name, key.src_device_id, proto_str(key.proto), key.dst_port, request_id
        )),
    };
    let view = match crate::acl::insert_rule(state, rule.clone()).await {
        Ok(v) => v,
        Err(e) => {
            state.firewall.lock().await.abort_resolve_auth(request_id);
            return Err(e);
        }
    };
    let outcome = {
        let mut fw = state.firewall.lock().await;
        let outcome = fw.resolve_auth(request_id, action.clone(), expires_at.is_none()).ok_or_else(not_found)?;
        fw.access_log.set_rule_id(&outcome.log_entry_id, rule.id.clone());
        outcome
    };
    state.next_generation();
    info!("inbound: auth decision '{}' applied for {} {}:{}", name, key.src_device_id, proto_str(key.proto), key.dst_port);
    state.emit_ipc_event(IpcEvent::AccessRequestResolved {
        request_id: request_id.to_string(),
        decision,
        rule_id: rule.id.clone(),
    });

    if action == Action::Allow && !outcome.queued_packets.is_empty() {
        if let Some(tun_tx) = state.tun_tx.get() {
            let origin = FlowOrigin { device_id: key.src_device_id.clone(), rule_id: rule.id.clone(), room_scope: false };
            for p in outcome.queued_packets {
                if let Some(parsed) = crate::runtime::parse_ip_packet(&p) {
                    record_admitted(state, &parsed, origin.clone(), now);
                }
                let _ = tun_tx.send(p).await;
            }
        }
    }
    Ok(json!({ "ok": true, "rule": view }))
}

/// Record that a rule let a peer-initiated TCP/UDP flow in
/// (`ConnectionTracker::record_inbound_allowed`).
fn record_admitted(state: &CoreState, parsed: &ParsedPacket, origin: FlowOrigin, now: i64) {
    if parsed.is_later_fragment() || !matches!(parsed.proto, TransportProtocol::Tcp | TransportProtocol::Udp) {
        return;
    }
    state.conn_track.lock().unwrap_or_else(|e| e.into_inner()).record_inbound_allowed(
        parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port, parsed.proto.number(), origin, now,
    );
}

/// A permission was revoked: end the peer-initiated flows it admitted, so
/// their next packets are evaluated by the ACL again (an established flow
/// otherwise keeps passing as related traffic once we replied).
pub fn revoke_flows(state: &CoreState, why: &str, matches: impl FnMut(&FlowOrigin) -> bool) {
    let n = state.conn_track.lock().unwrap_or_else(|e| e.into_inner()).revoke(matches);
    if n > 0 {
        info!("inbound: {}: ended {} connection(s) it had admitted", why, n);
    }
}

/// End the flows from devices no longer in a room with us (we left, or
/// they did) that only the room let in: admitted by a room rule, or
/// involving a guest (`packet::pipeline::guest_access_blocked`).
pub async fn revoke_room_flows(state: &CoreState) {
    let net = state.net.read().await;
    let still_allowed = |o: &FlowOrigin| {
        let src_auth = net.peer_list.get(&o.device_id).is_some_and(|e| e.is_authenticated);
        net.room_peers.contains(&o.device_id)
            || (!o.room_scope && !packet::pipeline::guest_access_blocked(net.local_authenticated, src_auth, false))
    };
    revoke_flows(state, "room membership changed", |o| !still_allowed(o));
}

/// Expire unanswered requests (called every second by the scheduler tick).
pub async fn expire_auth_requests(state: &CoreState, now: i64) {
    let timed_out = {
        let mut fw = state.firewall.lock().await;
        let t = fw.collect_timed_out_auth(now);
        fw.resolve_timed_out_auth_log(&t);
        t
    };
    if !timed_out.is_empty() {
        state.next_generation();
    }
    for (key, request_id, _) in timed_out {
        info!("inbound: auth request {} for {} {}:{} timed out", request_id, key.src_device_id, proto_str(key.proto), key.dst_port);
        state.emit_ipc_event(IpcEvent::AccessRequestTimeout { request_id });
    }
}

/// `GetPendingAuth` (3.0.x `GET /firewall/auth`).
pub async fn pending_requests(state: &CoreState) -> Value {
    let now = crate::runtime::current_unix();
    let fw = state.firewall.lock().await;
    let net = state.net.read().await;
    let requests: Vec<Value> = fw
        .pending_auth
        .iter()
        .filter_map(|p| {
            let expires_in = (p.created_at_unix + AUTH_TIMEOUT_SECS - now).max(0);
            if expires_in == 0 {
                return None;
            }
            let peer = net.peer_list.get(&p.key.src_device_id);
            Some(json!({
                "request_id": p.request_id,
                "src_device_id": p.key.src_device_id,
                "src_user_id": peer.and_then(|e| e.user_id.as_deref()),
                "src_device_display_name": peer.and_then(|e| e.display_name.as_deref()),
                "src_user_display_name": peer.and_then(|e| e.user_display_name.as_deref()),
                "proto": proto_str(p.key.proto),
                "dst_port": p.key.dst_port,
                "service_name": crate::acl::parse::service_display_name(proto_str(p.key.proto), p.key.dst_port),
                "expires_in_secs": expires_in,
            }))
        })
        .collect();
    json!({ "requests": requests })
}

/// `GetAccessLog` (newest first; 3.0.x `GET /firewall/access-log`).
pub async fn access_log(state: &CoreState, limit: Option<u32>) -> Value {
    let fw = state.firewall.lock().await;
    let limit = limit.map(|l| l as usize).unwrap_or(usize::MAX);
    let entries: Vec<&AccessLogEntry> = fw.access_log_entries().iter().rev().take(limit).collect();
    json!({ "entries": entries })
}

// ---------------------------------------------------------------------------
// TCP RST synthesis
// ---------------------------------------------------------------------------

fn csum_add(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    sum
}

fn csum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Build the TCP reset answering an inbound TCP segment (RFC 793 3.4):
/// addresses and ports swapped; `seq = SEG.ACK` if the segment has ACK,
/// else `ack = SEG.SEQ + SEG.LEN` with RST|ACK.  The TCP header is located
/// through the IPv6 extension header chain (the reply itself has none).
///
/// `None` — no reset — unless the complete TCP header (data offset
/// included) was found: not for later fragments, malformed header chains,
/// a segment that is itself a RST, or a fragmented segment without ACK
/// (its length is unknown).
pub fn build_tcp_rst(pkt: &[u8]) -> Option<Vec<u8>> {
    let (parsed, off) = crate::runtime::parse_ip_packet_at(pkt)?;
    if parsed.proto != TransportProtocol::Tcp || parsed.is_later_fragment() {
        return None;
    }
    let tcp = pkt.get(off..off + 20)?;
    let header_len = (tcp[12] >> 4) as usize * 4;
    if header_len < 20 || pkt.len() < off + header_len {
        return None;
    }
    let flags = tcp[13];
    if flags & TCP_RST != 0 {
        return None;
    }
    let (seq, ack) = if flags & TCP_ACK != 0 {
        (u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]), None)
    } else {
        if parsed.fragment.is_some() {
            return None;
        }
        let seg_len = (pkt.len() - off - header_len) as u32 + (flags & TCP_SYN != 0) as u32 + (flags & TCP_FIN != 0) as u32;
        (0, Some(u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]).wrapping_add(seg_len)))
    };
    let (src, dst) = (ip_octets(&parsed.src_ip), ip_octets(&parsed.dst_ip));

    let mut t = [0u8; 20];
    t[0..2].copy_from_slice(&tcp[2..4]); // our port = their dst port
    t[2..4].copy_from_slice(&tcp[0..2]);
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.unwrap_or(0).to_be_bytes());
    t[12] = 5 << 4; // data offset
    t[13] = TCP_RST | if ack.is_some() { TCP_ACK } else { 0 };

    // Pseudo-header: src = their dst, dst = their src.
    let mut sum = csum_add(0, &dst);
    sum = csum_add(sum, &src);
    sum += 6 + 20;
    let tcp_csum = csum_fold(csum_add(sum, &t));
    t[16..18].copy_from_slice(&tcp_csum.to_be_bytes());

    let mut out = Vec::with_capacity(60);
    if parsed.src_ip.is_ipv6() {
        out.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, 6, 64]);
        out.extend_from_slice(&dst);
        out.extend_from_slice(&src);
    } else {
        let mut h = [0u8; 20];
        h[0] = 0x45;
        h[2..4].copy_from_slice(&40u16.to_be_bytes());
        h[8] = 64; // TTL
        h[9] = 6;
        h[12..16].copy_from_slice(&dst);
        h[16..20].copy_from_slice(&src);
        let c = csum_fold(csum_add(0, &h));
        h[10..12].copy_from_slice(&c.to_be_bytes());
        out.extend_from_slice(&h);
    }
    out.extend_from_slice(&t);
    Some(out)
}

fn ip_octets(ip: &std::net::IpAddr) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TCP SYN 172.22.1.1:40000 → 172.22.0.1:25565, seq 1000.
    fn syn_v4() -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 172, 22, 1, 1, 172, 22, 0, 1];
        p.extend_from_slice(&[0x9c, 0x40, 0x63, 0xdd, 0, 0, 0x03, 0xe8, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        p
    }

    fn verify_ipv4_header(h: &[u8]) -> bool {
        csum_fold(csum_add(0, &h[..20])) == 0
    }

    fn verify_tcp(src: &[u8], dst: &[u8], tcp: &[u8]) -> bool {
        let mut sum = csum_add(0, src);
        sum = csum_add(sum, dst);
        sum += 6 + tcp.len() as u32;
        csum_fold(csum_add(sum, tcp)) == 0
    }

    #[test]
    fn rst_for_ipv4_syn() {
        let rst = build_tcp_rst(&syn_v4()).unwrap();
        assert_eq!(rst.len(), 40);
        assert!(verify_ipv4_header(&rst));
        assert_eq!(&rst[12..16], &[172, 22, 0, 1]); // from us
        assert_eq!(&rst[16..20], &[172, 22, 1, 1]); // to them
        let tcp = &rst[20..];
        assert_eq!(u16::from_be_bytes([tcp[0], tcp[1]]), 25565);
        assert_eq!(u16::from_be_bytes([tcp[2], tcp[3]]), 40000);
        assert_eq!(u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]), 1001);
        assert_eq!(tcp[13], 0x14);
        assert!(verify_tcp(&rst[12..16], &rst[16..20], tcp));
    }

    #[test]
    fn rst_for_ipv6_syn() {
        let mut p = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
        p.extend_from_slice(&"fd22:2222:2222:2222::b".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"fd22:2222:2222:2222::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&[0x9c, 0x40, 0, 22, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        let rst = build_tcp_rst(&p).unwrap();
        assert_eq!(rst.len(), 60);
        assert_eq!(&rst[8..24], &p[24..40]);
        let tcp = &rst[40..];
        assert_eq!(u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]), 0); // seq wraps
        assert!(verify_tcp(&rst[8..24], &rst[24..40], tcp));
    }

    /// IPv6 fd22::b → fd22::1, next header `next`, then `rest`.
    fn v6(next: u8, rest: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, rest.len() as u8, next, 64];
        p.extend_from_slice(&"fd22:2222:2222:2222::b".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"fd22:2222:2222:2222::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(rest);
        p
    }

    /// TCP header 40000 → 22, seq 1000, ack 5000, `flags`, data offset `doff` words.
    fn tcp_hdr(flags: u8, doff: u8) -> Vec<u8> {
        let mut t = vec![0x9c, 0x40, 0, 22, 0, 0, 0x03, 0xe8, 0, 0, 0x13, 0x88, doff << 4, flags, 0xff, 0xff, 0, 0, 0, 0];
        t.resize(doff.max(5) as usize * 4, 1); // options
        t
    }

    fn rst_fields(rst: &[u8]) -> (u32, u32, u8) {
        let tcp = &rst[rst.len() - 20..];
        (u32::from_be_bytes(tcp[4..8].try_into().unwrap()), u32::from_be_bytes(tcp[8..12].try_into().unwrap()), tcp[13])
    }

    #[test]
    fn rst_through_ipv6_extension_headers() {
        // Destination Options (8) + Hop-by-Hop is first in real chains; here
        // HBH → DestOpts → TCP SYN with a 4-byte option.
        let mut chain = vec![60, 0, 1, 4, 0, 0, 0, 0, 6, 0, 1, 4, 0, 0, 0, 0];
        chain.extend(tcp_hdr(TCP_SYN, 6));
        let rst = build_tcp_rst(&v6(0, &chain)).expect("RST");
        assert_eq!(rst.len(), 60, "plain IPv6 header, no extension headers");
        assert_eq!(&rst[8..24], &"fd22:2222:2222:2222::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        let tcp = &rst[40..];
        assert_eq!((u16::from_be_bytes([tcp[0], tcp[1]]), u16::from_be_bytes([tcp[2], tcp[3]])), (22, 40000));
        assert_eq!(rst_fields(&rst), (0, 1001, TCP_RST | TCP_ACK));
        assert!(verify_tcp(&rst[8..24], &rst[24..40], tcp));
        // Atomic fragment.
        let mut chain = vec![6, 0, 0, 0, 0, 0, 0, 9];
        chain.extend(tcp_hdr(TCP_SYN, 5));
        assert!(build_tcp_rst(&v6(44, &chain)).is_some());
    }

    #[test]
    fn rst_sequence_numbers_follow_rfc_793() {
        // ACK set: seq = SEG.ACK, RST only.
        let mut p = syn_v4();
        p[33] = TCP_ACK | 0x08; // ACK|PSH
        p[28..32].copy_from_slice(&5000u32.to_be_bytes());
        p.extend_from_slice(b"data");
        assert_eq!(rst_fields(&build_tcp_rst(&p).unwrap()), (5000, 0, TCP_RST));
        // No ACK: ack = SEG.SEQ + payload + SYN + FIN.
        let mut p = syn_v4();
        p[33] = TCP_SYN | TCP_FIN;
        p.extend_from_slice(b"abc");
        assert_eq!(rst_fields(&build_tcp_rst(&p).unwrap()), (0, 1000 + 3 + 2, TCP_RST | TCP_ACK));
    }

    #[test]
    fn no_rst_without_a_reliable_tcp_header() {
        // A RST is never answered.
        let mut chain = vec![6, 0, 1, 4, 0, 0, 0, 0];
        chain.extend(tcp_hdr(TCP_RST, 5));
        assert!(build_tcp_rst(&v6(60, &chain)).is_none());
        // Data offset beyond the packet, or below 5 words.
        let mut t = tcp_hdr(TCP_SYN, 8);
        t.truncate(24);
        assert!(build_tcp_rst(&v6(6, &t)).is_none());
        assert!(build_tcp_rst(&v6(6, &tcp_hdr(TCP_SYN, 4))).is_none());
        // Later fragments carry no TCP header.
        let mut later = vec![6, 0, 0, 0x10, 0, 0, 0, 9]; // offset 2
        later.extend(tcp_hdr(TCP_SYN, 5));
        assert!(build_tcp_rst(&v6(44, &later)).is_none());
        let mut v4_later = syn_v4();
        v4_later[6..8].copy_from_slice(&3u16.to_be_bytes());
        assert!(build_tcp_rst(&v4_later).is_none());
        // A fragmented SYN: its length (hence the ack) is unknown.
        let mut first = vec![6, 0, 0, 1, 0, 0, 0, 9]; // offset 0, more
        first.extend(tcp_hdr(TCP_SYN, 5));
        assert!(build_tcp_rst(&v6(44, &first)).is_none());
        // ... but a fragmented segment with ACK has a definite reset.
        let mut first = vec![6, 0, 0, 1, 0, 0, 0, 9];
        first.extend(tcp_hdr(TCP_ACK, 5));
        assert_eq!(rst_fields(&build_tcp_rst(&v6(44, &first)).unwrap()), (5000, 0, TCP_RST));
        // Malformed chain (truncated Destination Options).
        assert!(build_tcp_rst(&v6(60, &[6, 3, 0, 0, 0, 0, 0, 0])).is_none());
    }

    #[test]
    fn rst_rejects_non_tcp() {
        let mut udp = syn_v4();
        udp[9] = 17;
        assert!(build_tcp_rst(&udp).is_none());
        assert!(build_tcp_rst(&[0x45, 0]).is_none());
    }

    // ── Interactive authorization, end to end ────────────────────────────

    struct Harness {
        state: Arc<CoreState>,
        ipc_rx: crate::state::EventReceiver,
        tun_tx: mpsc::Sender<Vec<u8>>,
        tun_rx: mpsc::Receiver<Vec<u8>>,
        relay: tokio::net::UdpSocket,
    }

    /// Local device 172.22.0.1 (authenticated); peer device-0000000b at
    /// 172.22.1.1 (authenticated), reachable via a loopback "relay".
    /// The peer's (device-0000000b) WireGuard key.
    const BOB_SECRET: [u8; 32] = [0xb0; 32];

    async fn harness(name: &str, in_room: bool) -> Harness {
        let dir = std::env::temp_dir().join(format!("msst-inbound-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let state = Arc::new(CoreState::new(udp, dir));
        let ipc_rx = state.subscribe_events();
        let id = crate::identity::Identity {
            user: crate::identity::UserInfo { id: "user-00000001".into(), handle: String::new(), display_name: String::new() },
            device: crate::identity::DeviceInfo {
                id: "device-00000001".into(), handle: String::new(), display_name: String::new(),
                hostname: String::new(), assigned_ipv4: None,
            },
            secret_key: [1u8; 32], public_key: [2u8; 32],
            auth: Some(crate::identity::AuthCredentials::default()),
        };
        state.apply_identity(&id).await;
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        {
            let mut net = state.net.write().await;
            net.peer_list.upsert("device-0000000b", "172.22.1.1".parse().unwrap(), "fd22:2222:2222:2222::b".parse().unwrap(),
                Some("user-0000000b"), Some("pc"), Some("bob"), Some("pc.bob.ezplay.msst.net"), Some("Bob PC".into()), None, true, 0);
            net.peer_list.update_relay("device-0000000b", &relay.local_addr().unwrap().to_string());
            if in_room {
                net.joined_rooms.insert("space-1".into(), "Room".into());
                net.room_peers.insert("device-0000000b".into());
            }
        }
        let bob_pk = crate::test_support::identity_with_key(BOB_SECRET).public_key_base64();
        state.encryption.lock().await.add_peer("device-0000000b", &bob_pk).unwrap();
        let (tun_tx, tun_rx) = mpsc::channel(16);
        let _ = state.tun_tx.set(tun_tx.clone());
        Harness { state, ipc_rx, tun_tx, tun_rx, relay }
    }

    /// UDP 172.22.1.1:5000 → 172.22.0.1:25565.
    fn udp_v4(payload: &[u8]) -> Vec<u8> {
        let len = 28 + payload.len() as u16;
        let mut p = vec![0x45, 0, (len >> 8) as u8, len as u8, 0, 0, 0, 0, 64, 17, 0, 0, 172, 22, 1, 1, 172, 22, 0, 1];
        p.extend_from_slice(&[0x13, 0x88, 0x63, 0xdd, 0, (8 + payload.len()) as u8, 0, 0]);
        p.extend_from_slice(payload);
        p
    }

    fn auth_request_id(rx: &mut crate::state::EventReceiver) -> Option<String> {
        while let Ok(ev) = rx.try_recv() {
            if let IpcEvent::AccessRequestCreated { request_id, src_device_id, dst_port, service_name, src_device_display_name, .. } = ev {
                assert_eq!(src_device_id, "device-0000000b");
                assert_eq!(dst_port, 25565);
                assert_eq!(src_device_display_name.as_deref(), Some("Bob PC"));
                let _ = service_name;
                return Some(request_id);
            }
        }
        None
    }

    #[tokio::test]
    async fn udp_is_queued_then_replayed_on_allow_once() {
        let mut h = harness("udp", true).await;
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"one")).await;
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"two")).await;
        assert!(h.tun_rx.try_recv().is_err(), "nothing delivered before approval");

        let req = auth_request_id(&mut h.ipc_rx).expect("AccessRequestCreated");
        assert!(auth_request_id(&mut h.ipc_rx).is_none(), "one request per (src, proto, port)");
        let pending = pending_requests(&h.state).await;
        assert_eq!(pending["requests"][0]["request_id"], req);
        assert!(pending["requests"][0]["service_name"].is_null()); // only tcp/25565 is named (3.0.x table)

        let out = resolve_auth(&h.state, &req, AuthDecision::AllowOnce).await.unwrap();
        assert_eq!(out["rule"]["permission_group"]["ids"], json!(["device-0000000b"]));
        let mut resolved = false;
        while let Ok(ev) = h.ipc_rx.try_recv() {
            if let IpcEvent::AccessRequestResolved { request_id, rule_id, .. } = ev {
                resolved = request_id == req && rule_id == out["rule"]["id"];
            }
        }
        assert!(resolved, "AccessRequestResolved emitted with the generated rule");
        assert!(out["rule"]["expires_at"].as_i64().unwrap() > crate::runtime::current_unix());
        assert_eq!(h.tun_rx.try_recv().unwrap(), udp_v4(b"one"));
        assert_eq!(h.tun_rx.try_recv().unwrap(), udp_v4(b"two"));

        // The rule now admits further traffic directly.
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"three")).await;
        assert_eq!(h.tun_rx.try_recv().unwrap(), udp_v4(b"three"));
        // Access log: the prompt entry now carries the generated rule.
        let log = access_log(&h.state, None).await;
        let entries = log["entries"].as_array().unwrap();
        assert!(entries.iter().any(|e| e["reason"]["type"] == "interactive_auth" && e["decision"] == "allow"
            && e["rule_id"] == out["rule"]["id"]));
        // Persisted.
        assert_eq!(crate::acl::store::load_rules(&h.state.data_dir).unwrap().len(), 1);
        assert_eq!(resolve_auth(&h.state, &req, AuthDecision::AllowOnce).await.unwrap_err().code, "not_found");
    }

    #[tokio::test]
    async fn deny_discards_queue() {
        let mut h = harness("deny", true).await;
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"x")).await;
        let req = auth_request_id(&mut h.ipc_rx).unwrap();
        let out = resolve_auth(&h.state, &req, AuthDecision::AlwaysDeny).await.unwrap();
        assert_eq!(out["rule"]["action"], "deny");
        assert!(out["rule"]["expires_at"].is_null());
        assert!(h.tun_rx.try_recv().is_err());
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"y")).await;
        assert!(h.tun_rx.try_recv().is_err());
        assert!(auth_request_id(&mut h.ipc_rx).is_none(), "denied by rule, no new prompt");
    }

    #[tokio::test]
    async fn tcp_gets_rst_without_becoming_related() {
        let mut h = harness("tcp", true).await;
        let mut syn = syn_v4();
        syn[12..16].copy_from_slice(&[172, 22, 1, 1]);
        syn[16..20].copy_from_slice(&[172, 22, 0, 1]);
        deliver_inbound(&h.state, &h.tun_tx, syn.clone()).await;
        assert!(auth_request_id(&mut h.ipc_rx).is_some());

        let rst = rst_received_by_peer(&h).await;
        assert_eq!(rst[20 + 13], 0x14);

        // Retrying the SYN must not be admitted via connection tracking.
        deliver_inbound(&h.state, &h.tun_tx, syn).await;
        assert!(h.tun_rx.try_recv().is_err());
    }

    /// The RST Core sent to the peer: via its relay, encrypted — a
    /// handshake initiation first, the RST waiting in the session queue.
    /// Plays the peer: answers the handshake and decrypts what follows.
    async fn rst_received_by_peer(h: &Harness) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(1), h.relay.recv_from(&mut buf)).await.unwrap().unwrap();
        let init = msst_core_state::net::msst_packet::MsstPacket::decode(&buf[..n]).unwrap();
        assert_eq!(init.packet_type, msst_core_state::net::msst_packet::TYPE_WG);
        let mut bob = msst_core_state::encryption::EncryptionEngine::new();
        bob.set_local_keypair(BOB_SECRET);
        bob.add_peer("device-00000001", &h.state.encryption.lock().await.local_public_key_b64().unwrap()).unwrap();
        let resp = bob.inbound("device-00000001", &init.payload, 0).reply.remove(0);
        let flushed = h.state.encryption.lock().await.inbound("device-0000000b", &resp, 0).reply;
        flushed.iter().find_map(|m| bob.inbound("device-00000001", m, 0).packet).expect("RST")
    }

    #[tokio::test]
    async fn ipv6_syn_behind_extension_headers_gets_rst_on_auth() {
        let mut h = harness("tcp6-ext", true).await;
        let mut chain = vec![6, 0, 1, 4, 0, 0, 0, 0];
        chain.extend_from_slice(&syn_to(22)[20..]);
        deliver_inbound(&h.state, &h.tun_tx, ipv6_from_peer(60, &chain)).await;
        assert_eq!(created_ports(&mut h.ipc_rx), [22]);
        let rst = rst_received_by_peer(&h).await;
        assert_eq!(rst[0] >> 4, 6);
        assert_eq!(&rst[24..40], &"fd22:2222:2222:2222::b".parse::<std::net::Ipv6Addr>().unwrap().octets(), "to the peer");
        assert_eq!(rst_fields(&rst), (0, 1001, TCP_RST | TCP_ACK));
        assert!(h.tun_rx.try_recv().is_err());
    }

    /// A TCP SYN from the peer (172.22.1.1) to `port`.
    fn syn_to(port: u16) -> Vec<u8> {
        let mut p = syn_v4();
        p[22..24].copy_from_slice(&port.to_be_bytes());
        p
    }

    fn created_ports(rx: &mut crate::state::EventReceiver) -> Vec<u16> {
        let mut ports = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let IpcEvent::AccessRequestCreated { dst_port, .. } = ev {
                ports.push(dst_port);
            }
        }
        ports
    }

    #[tokio::test]
    async fn a_port_scan_opens_a_bounded_number_of_prompts() {
        let mut h = harness("cap", true).await;
        for port in 1000..1010 {
            deliver_inbound(&h.state, &h.tun_tx, syn_to(port)).await;
        }
        let max = msst_core_state::firewall::MAX_PENDING_AUTH_PER_SOURCE;
        assert_eq!(created_ports(&mut h.ipc_rx), (1000..1000 + max as u16).collect::<Vec<_>>());
        let log = access_log(&h.state, Some(5)).await;
        assert!(log["entries"].as_array().unwrap().iter().any(|e| e["reason"]["type"] == "interactive_auth_limit"), "{}", log);
        // Answering one frees a slot.
        let req = h.state.firewall.lock().await.pending_auth[0].request_id.clone();
        resolve_auth(&h.state, &req, AuthDecision::DenyOnce).await.unwrap();
        deliver_inbound(&h.state, &h.tun_tx, syn_to(2000)).await;
        assert_eq!(created_ports(&mut h.ipc_rx), [2000]);
    }

    #[tokio::test]
    async fn late_answer_is_refused_before_the_sweep() {
        let mut h = harness("late", true).await;
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"x")).await;
        let req = auth_request_id(&mut h.ipc_rx).unwrap();
        h.state.firewall.lock().await.pending_auth[0].created_at_unix -= AUTH_TIMEOUT_SECS;
        assert_eq!(resolve_auth(&h.state, &req, AuthDecision::AllowOnce).await.unwrap_err().code, "not_found");
        assert!(h.state.net.read().await.acl_rules.is_empty(), "no rule from a late answer");
        // The sweep then reports the timeout.
        expire_auth_requests(&h.state, crate::runtime::current_unix()).await;
        assert!(std::iter::from_fn(|| h.ipc_rx.try_recv().ok()).any(|e| matches!(e, IpcEvent::AccessRequestTimeout { request_id } if request_id == req)));
    }

    #[tokio::test]
    async fn failed_rule_creation_leaves_the_request_answerable() {
        let mut h = harness("persist-fail", true).await;
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"x")).await;
        let req = auth_request_id(&mut h.ipc_rx).unwrap();
        // Rules can't be saved: a directory sits where the file goes.
        let blocker = h.state.data_dir.join(crate::acl::store::RULES_FILE);
        std::fs::create_dir_all(blocker.join("x")).unwrap();
        assert_eq!(resolve_auth(&h.state, &req, AuthDecision::AllowOnce).await.unwrap_err().code, "persist_failed");
        assert_eq!(pending_requests(&h.state).await["requests"][0]["request_id"], req.as_str());
        assert!(!std::iter::from_fn(|| h.ipc_rx.try_recv().ok()).any(|e| matches!(e, IpcEvent::AccessRequestResolved { .. })));
        // Fixed: the same request can be answered, and the queued packet goes out.
        std::fs::remove_dir_all(&blocker).unwrap();
        resolve_auth(&h.state, &req, AuthDecision::AllowOnce).await.unwrap();
        assert!(h.tun_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn unanswered_request_times_out() {
        let mut h = harness("timeout", true).await;
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"x")).await;
        let req = auth_request_id(&mut h.ipc_rx).unwrap();
        expire_auth_requests(&h.state, crate::runtime::current_unix() + AUTH_TIMEOUT_SECS).await;
        let mut timed_out = false;
        while let Ok(ev) = h.ipc_rx.try_recv() {
            if let IpcEvent::AccessRequestTimeout { request_id } = ev {
                timed_out = request_id == req;
            }
        }
        assert!(timed_out);
        let log = access_log(&h.state, Some(1)).await;
        assert_eq!(log["entries"][0]["decision"], "silent_deny");
        assert_eq!(log["entries"][0]["reason"]["type"], "interactive_auth_timeout");
        assert_eq!(resolve_auth(&h.state, &req, AuthDecision::AllowOnce).await.unwrap_err().code, "not_found");
    }

    // ── IPv6 extension headers and fragments ─────────────────────────────

    /// IPv6 fd22::b (the peer) → fd22::1 with next header `next`.
    fn ipv6_from_peer(next: u8, rest: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, (rest.len() >> 8) as u8, rest.len() as u8, next, 64];
        p.extend_from_slice(&"fd22:2222:2222:2222::b".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"fd22:2222:2222:2222::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(rest);
        p
    }

    #[tokio::test]
    async fn ipv6_extension_headers_do_not_bypass_the_acl() {
        let mut h = harness("ipv6-ext", true).await;
        let tcp_syn = &syn_to(22)[20..];
        // Destination Options, and an atomic Fragment header, in front of a
        // SYN to a port no rule allows: evaluated like a plain SYN.
        let mut dest_opts = vec![6, 0, 1, 4, 0, 0, 0, 0];
        dest_opts.extend_from_slice(tcp_syn);
        let mut atomic = vec![6, 0, 0, 0, 0, 0, 0, 1];
        atomic.extend_from_slice(tcp_syn);
        for pkt in [ipv6_from_peer(60, &dest_opts), ipv6_from_peer(44, &atomic)] {
            deliver_inbound(&h.state, &h.tun_tx, pkt).await;
            assert!(h.tun_rx.try_recv().is_err(), "not delivered past the default deny");
        }
        assert_eq!(created_ports(&mut h.ipc_rx), [22], "one prompt for tcp/22");

        // With an allow rule it gets through.
        h.state.net.write().await.acl_rules.push(FirewallRule {
            id: "ssh".into(),
            permission_group: PermissionGroup::Devices { ids: vec!["device-0000000b".into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 22)],
            action: Action::Allow, direction: Direction::Inbound, expires_at: None, enabled: true, comment: None,
        });
        deliver_inbound(&h.state, &h.tun_tx, ipv6_from_peer(60, &dest_opts)).await;
        assert!(h.tun_rx.try_recv().is_ok());
    }

    /// IPv4 UDP fragments 172.22.1.1 → 172.22.0.1, id `id`: the first
    /// (UDP header to port 25565 + 8 bytes) and the last (8 bytes at offset 2).
    fn udp_fragments_v4(id: u8) -> (Vec<u8>, Vec<u8>) {
        let frag = |fo: u16, body: &[u8]| {
            let len = 20 + body.len() as u16;
            let mut p = vec![0x45, 0, 0, len as u8, 0, id, (fo >> 8) as u8, fo as u8, 64, 17, 0, 0, 172, 22, 1, 1, 172, 22, 0, 1];
            p.extend_from_slice(body);
            p
        };
        // The later fragment's data would read as ports 22 → 22.
        (frag(0x2000, &[0x13, 0x88, 0x63, 0xdd, 0, 24, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]), frag(2, &[0, 22, 0, 22, 9, 9, 9, 9]))
    }

    fn allow_udp_25565() -> FirewallRule {
        FirewallRule {
            id: "mc".into(),
            permission_group: PermissionGroup::Devices { ids: vec!["device-0000000b".into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Udp, 25565)],
            action: Action::Allow, direction: Direction::Inbound, expires_at: None, enabled: true, comment: None,
        }
    }

    // ── Revoking a permission ends the connections it admitted ───────────

    /// Our reply to `udp_v4`: 172.22.0.1:25565 → 172.22.1.1:5000, recorded
    /// as the outbound path does.
    fn reply(h: &Harness) {
        h.state.conn_track.lock().unwrap().record_outbound(
            "172.22.0.1".parse().unwrap(), 25565, "172.22.1.1".parse().unwrap(), 5000, 17, crate::runtime::current_unix(),
        );
    }

    /// The peer's next packet on the flow reaches the TUN.
    async fn passes(h: &mut Harness) -> bool {
        while h.tun_rx.try_recv().is_ok() {}
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"x")).await;
        h.tun_rx.try_recv().is_ok()
    }

    /// The flow was admitted by `rule` and we replied: it is related now.
    async fn established(h: &mut Harness, rule: FirewallRule) {
        h.state.net.write().await.acl_rules.push(rule);
        assert!(passes(h).await);
        reply(h);
        assert!(passes(h).await);
    }

    #[tokio::test]
    async fn deleting_or_disabling_the_rule_ends_its_connections() {
        let mut h = harness("revoke-delete", false).await;
        established(&mut h, allow_udp_25565()).await;
        crate::acl::delete_rule(&h.state, "mc").await.unwrap();
        assert!(!passes(&mut h).await);
        // Our replies don't make it related again.
        reply(&h);
        assert!(!passes(&mut h).await);

        // Another rule still allows it: it keeps working.
        let mut h = harness("revoke-other", false).await;
        established(&mut h, allow_udp_25565()).await;
        h.state.net.write().await.acl_rules.push(FirewallRule { id: "mc2".into(), ..allow_udp_25565() });
        crate::acl::delete_rule(&h.state, "mc").await.unwrap();
        assert!(passes(&mut h).await);
        reply(&h);
        assert!(passes(&mut h).await);

        let mut h = harness("revoke-disable", false).await;
        established(&mut h, allow_udp_25565()).await;
        crate::acl::update_rule(&h.state, "mc", json!({"comment": "x"})).await.unwrap();
        assert!(passes(&mut h).await, "other edits revoke nothing");
        crate::acl::update_rule(&h.state, "mc", json!({"enabled": false})).await.unwrap();
        assert!(!passes(&mut h).await);
    }

    #[tokio::test]
    async fn an_expired_rule_keeps_its_connections() {
        let mut h = harness("revoke-expire", false).await;
        let now = crate::runtime::current_unix();
        established(&mut h, FirewallRule { expires_at: Some(now + 60), ..allow_udp_25565() }).await;
        crate::acl::expire_rules(&h.state, now + 61).await;
        assert!(h.state.net.read().await.acl_rules.is_empty());
        assert!(passes(&mut h).await);
    }

    #[tokio::test]
    async fn leaving_the_room_ends_what_only_the_room_allowed() {
        let mut h = harness("revoke-room", true).await;
        established(&mut h, FirewallRule { permission_group: PermissionGroup::Space, ..allow_udp_25565() }).await;
        // The peer leaves (member_left): the room rule no longer covers it.
        h.state.net.write().await.room_peers.remove("device-0000000b");
        revoke_room_flows(&h.state).await;
        assert!(!passes(&mut h).await);

        // A device rule between two authenticated devices doesn't depend
        // on the room.
        let mut h = harness("revoke-room-dev", true).await;
        established(&mut h, allow_udp_25565()).await;
        h.state.net.write().await.room_peers.clear();
        revoke_room_flows(&h.state).await;
        assert!(passes(&mut h).await);

        // A guest peer: only the shared room let it in.
        let mut h = harness("revoke-room-guest", true).await;
        h.state.net.write().await.peer_list.upsert("device-0000000b", "172.22.1.1".parse().unwrap(), "fd22:2222:2222:2222::b".parse().unwrap(),
            None, None, None, None, None, None, false, 0);
        established(&mut h, allow_udp_25565()).await;
        h.state.net.write().await.room_peers.clear();
        revoke_room_flows(&h.state).await;
        assert!(!passes(&mut h).await);
    }

    #[tokio::test]
    async fn fragments_follow_their_first_fragment() {
        let mut h = harness("frag-allow", true).await;
        h.state.net.write().await.acl_rules.push(allow_udp_25565());
        let (first, last) = udp_fragments_v4(1);
        deliver_inbound(&h.state, &h.tun_tx, first.clone()).await;
        deliver_inbound(&h.state, &h.tun_tx, last.clone()).await;
        assert_eq!(h.tun_rx.try_recv().unwrap(), first);
        assert_eq!(h.tun_rx.try_recv().unwrap(), last);

        // Out of order: the later fragment waits for its first.
        let (first, last) = udp_fragments_v4(2);
        deliver_inbound(&h.state, &h.tun_tx, last.clone()).await;
        assert!(h.tun_rx.try_recv().is_err());
        deliver_inbound(&h.state, &h.tun_tx, first.clone()).await;
        assert_eq!(h.tun_rx.try_recv().unwrap(), first);
        assert_eq!(h.tun_rx.try_recv().unwrap(), last);
        assert_eq!(created_ports(&mut h.ipc_rx), Vec::<u16>::new(), "no prompts for the fragments' data");
    }

    #[tokio::test]
    async fn fragments_of_a_denied_datagram_are_dropped() {
        let mut h = harness("frag-deny", true).await;
        h.state.net.write().await.acl_rules.push(FirewallRule { action: Action::Deny, ..allow_udp_25565() });
        let (first, last) = udp_fragments_v4(1);
        deliver_inbound(&h.state, &h.tun_tx, last.clone()).await;
        deliver_inbound(&h.state, &h.tun_tx, first).await;
        deliver_inbound(&h.state, &h.tun_tx, last).await;
        assert!(h.tun_rx.try_recv().is_err());
        assert_eq!(h.state.frag_track.lock().unwrap().held_bytes(), 0);
    }

    #[tokio::test]
    async fn fragments_wait_for_the_auth_decision_together() {
        let mut h = harness("frag-auth", true).await;
        let (first, last) = udp_fragments_v4(1);
        deliver_inbound(&h.state, &h.tun_tx, first.clone()).await;
        deliver_inbound(&h.state, &h.tun_tx, last.clone()).await;
        assert!(h.tun_rx.try_recv().is_err());
        let req = auth_request_id(&mut h.ipc_rx).expect("a prompt for udp/25565");
        assert!(auth_request_id(&mut h.ipc_rx).is_none());
        resolve_auth(&h.state, &req, AuthDecision::AllowOnce).await.unwrap();
        assert_eq!(h.tun_rx.try_recv().unwrap(), first);
        assert_eq!(h.tun_rx.try_recv().unwrap(), last);
    }

    #[tokio::test]
    async fn other_ip_protocols_are_not_delivered() {
        let mut h = harness("other-proto", true).await;
        // Even a rule allowing all TCP and UDP from the peer doesn't admit them.
        h.state.net.write().await.acl_rules.push(FirewallRule {
            id: "all".into(),
            permission_group: PermissionGroup::Devices { ids: vec!["device-0000000b".into()] },
            protocol_ports: vec![ProtocolPort::wildcard(Protocol::Tcp), ProtocolPort::wildcard(Protocol::Udp)],
            action: Action::Allow, direction: Direction::Inbound, expires_at: None, enabled: true, comment: None,
        });
        let ip4 = |proto: u8, fo: u16| {
            let mut p = vec![0x45, 0, 0, 32, 0, 3, (fo >> 8) as u8, fo as u8, 64, proto, 0, 0, 172, 22, 1, 1, 172, 22, 0, 1];
            p.extend_from_slice(&[0; 12]);
            p
        };
        for pkt in [ip4(47, 0), ip4(50, 0), ip4(132, 0), ip4(47, 0x2000), ip4(47, 2), ipv6_from_peer(59, &[]), ipv6_from_peer(47, &[0; 8])] {
            deliver_inbound(&h.state, &h.tun_tx, pkt.clone()).await;
            assert!(h.tun_rx.try_recv().is_err(), "{:?}", pkt);
        }
        assert_eq!(created_ports(&mut h.ipc_rx), Vec::<u16>::new(), "no prompts");
        assert!(crate::diagnostics::traffic(&h.state, "device-0000000b").drop.load(std::sync::atomic::Ordering::Relaxed) >= 6);
        // ICMP and allowed UDP still get through.
        let mut ping = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 172, 22, 1, 1, 172, 22, 0, 1];
        ping.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // echo reply
        deliver_inbound(&h.state, &h.tun_tx, ping).await;
        assert!(h.tun_rx.try_recv().is_ok());
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"x")).await;
        assert!(h.tun_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn stranger_in_lan_mode_gets_no_prompt() {
        // Not in a room, not a contact, not our device, not in any rule.
        let mut h = harness("stranger", false).await;
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"x")).await;
        assert!(auth_request_id(&mut h.ipc_rx).is_none());
        assert!(pending_requests(&h.state).await["requests"].as_array().unwrap().is_empty());

        // Once the device is referenced by a rule, it may prompt (for other ports).
        h.state.net.write().await.acl_rules.push(FirewallRule {
            id: "r".into(),
            permission_group: PermissionGroup::Devices { ids: vec!["device-0000000b".into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 22)],
            action: Action::Allow, direction: Direction::Inbound, expires_at: None, enabled: true, comment: None,
        });
        deliver_inbound(&h.state, &h.tun_tx, udp_v4(b"x")).await;
        assert!(auth_request_id(&mut h.ipc_rx).is_some());
    }
}
