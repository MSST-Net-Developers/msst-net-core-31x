//! Inbound delivery — the firewall gate in front of the TUN, and the
//! interactive authorization flow (ported from 3.0.x `deliver_inbound` /
//! `trigger_interactive_auth` / `auth_decision`).
//!
//! Every IP packet that arrives from the network — MSST data frames, raw IP
//! datagrams and WireGuard-decrypted packets alike — goes through
//! [`deliver_inbound`].  Nothing reaches the TUN without passing the
//! pipeline.

use crate::state::CoreState;
use msst_acl_engine::{Action, Direction, FirewallRule, PermissionGroup, Protocol, ProtocolPort};
use msst_core_state::firewall::access_log::{AccessDecision, AccessLogEntry, AccessReason};
use msst_core_state::firewall::auth::AuthKey;
use msst_core_state::packet::parsed::{ParsedPacket, TransportProtocol};
use msst_core_state::packet::{self, PipelineVerdict, StaticPingPolicy};
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

/// Run one inbound IP packet through the firewall and deliver it if allowed.
pub async fn deliver_inbound(state: &Arc<CoreState>, tun_tx: &mpsc::Sender<Vec<u8>>, pkt: Vec<u8>) {
    let Some(parsed) = crate::runtime::parse_ip_packet(&pkt) else { return };
    let now = crate::runtime::current_unix();

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

    match verdict {
        PipelineVerdict::Allow { src_device_id, decision } => {
            state.contacts.lock().unwrap_or_else(|e| e.into_inner()).update_communication(&src_device_id, now);
            crate::diagnostics::traffic(state, &src_device_id).rx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            crate::peer_cache::on_communication(state, &src_device_id).await;
            if let (Some(proto), Some(m)) = (proto_of(&parsed), decision.matched_rule) {
                log_access(state, &src_device_id, proto, parsed.dst_port, AccessDecision::Allow,
                    AccessReason::MatchedRule { rule_id: m.rule_id.clone(), comment: m.comment }, Some(m.rule_id)).await;
            }
            let _ = tun_tx.send(pkt).await;
        }
        PipelineVerdict::Related { .. } | PipelineVerdict::IcmpAllowed { .. } | PipelineVerdict::PassThrough { .. } => {
            let _ = tun_tx.send(pkt).await;
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
pub async fn resolve_auth(state: &Arc<CoreState>, request_id: &str, decision: AuthDecision) -> Result<Value, IpcError> {
    let now = crate::runtime::current_unix();
    let (action, expires_at, name) = match decision {
        AuthDecision::AllowOnce => (Action::Allow, Some(now + ONCE_RULE_TTL_SECS), "allow_once"),
        AuthDecision::AlwaysAllow => (Action::Allow, None, "always_allow"),
        AuthDecision::DenyOnce => (Action::Deny, Some(now + ONCE_RULE_TTL_SECS), "deny_once"),
        AuthDecision::AlwaysDeny => (Action::Deny, None, "always_deny"),
    };
    let outcome = state
        .firewall
        .lock()
        .await
        .resolve_auth(request_id, action.clone(), expires_at.is_none())
        .inspect(|_| {
            state.next_generation();
        })
        .ok_or_else(|| IpcError {
            code: "not_found".into(),
            message: format!("Auth request '{}' not found or already resolved", request_id),
        })?;

    let key = &outcome.key;
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
    let view = crate::acl::insert_rule(state, rule.clone()).await?;
    state.firewall.lock().await.access_log.set_rule_id(&outcome.log_entry_id, rule.id.clone());
    info!("inbound: auth decision '{}' applied for {} {}:{}", name, key.src_device_id, proto_str(key.proto), key.dst_port);
    state.emit_ipc_event(IpcEvent::AccessRequestResolved {
        request_id: request_id.to_string(),
        decision,
        rule_id: rule.id.clone(),
    });

    if action == Action::Allow && !outcome.queued_packets.is_empty() {
        if let Some(tun_tx) = state.tun_tx.get() {
            for p in outcome.queued_packets {
                let _ = tun_tx.send(p).await;
            }
        }
    }
    Ok(json!({ "ok": true, "rule": view }))
}

/// Expire unanswered requests (called from housekeeping).
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

/// Build a TCP RST|ACK answering an inbound TCP segment: addresses and
/// ports swapped, `ack = seq + 1` (3.0.x `build_tcp_rst`).
pub fn build_tcp_rst(pkt: &[u8]) -> Option<Vec<u8>> {
    let (src, dst, tcp, v6) = match pkt.first()? >> 4 {
        4 => {
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            if pkt.len() < ihl + 20 || pkt[9] != 6 {
                return None;
            }
            (&pkt[12..16], &pkt[16..20], &pkt[ihl..], false)
        }
        6 => {
            if pkt.len() < 60 || pkt[6] != 6 {
                return None;
            }
            (&pkt[8..24], &pkt[24..40], &pkt[40..], true)
        }
        _ => return None,
    };
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);

    let mut t = [0u8; 20];
    t[0..2].copy_from_slice(&tcp[2..4]); // our port = their dst port
    t[2..4].copy_from_slice(&tcp[0..2]);
    t[8..12].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
    t[12] = 5 << 4; // data offset
    t[13] = 0x14; // RST | ACK

    // Pseudo-header: src = their dst, dst = their src.
    let mut sum = csum_add(0, dst);
    sum = csum_add(sum, src);
    sum += 6 + 20;
    let tcp_csum = csum_fold(csum_add(sum, &t));
    t[16..18].copy_from_slice(&tcp_csum.to_be_bytes());

    let mut out = Vec::with_capacity(60);
    if v6 {
        out.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, 6, 64]);
        out.extend_from_slice(dst);
        out.extend_from_slice(src);
    } else {
        let mut h = [0u8; 20];
        h[0] = 0x45;
        h[2..4].copy_from_slice(&40u16.to_be_bytes());
        h[8] = 64; // TTL
        h[9] = 6;
        h[12..16].copy_from_slice(dst);
        h[16..20].copy_from_slice(src);
        let c = csum_fold(csum_add(0, &h));
        h[10..12].copy_from_slice(&c.to_be_bytes());
        out.extend_from_slice(&h);
    }
    out.extend_from_slice(&t);
    Some(out)
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

        // The RST went to the peer (via its relay) as an MSST data frame.
        let mut buf = [0u8; 256];
        let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(1), h.relay.recv_from(&mut buf)).await.unwrap().unwrap();
        let frame = msst_core_state::net::msst_packet::MsstPacket::decode(&buf[..n]).unwrap();
        assert_eq!(frame.payload[20 + 13], 0x14);

        // Retrying the SYN must not be admitted via connection tracking.
        deliver_inbound(&h.state, &h.tun_tx, syn).await;
        assert!(h.tun_rx.try_recv().is_err());
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
