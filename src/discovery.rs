//! Game discovery proxy — UDP 21032 (ported from 3.0.x `net/discovery.rs`).
//!
//! Carries IPv4 multicast/broadcast (Minecraft Java LAN 224.0.2.60, mDNS
//! 224.0.0.251, subnet broadcasts) between members of a room so LAN game
//! discovery works over the virtual network.
//!
//! - **Outbound** (only while in a room): discovery packets read from the
//!   TUN — and, on Unix desktops, broadcasts this machine sends on its
//!   physical LAN (rewritten into MSST space) — are de-duplicated,
//!   rate-limited (10/s) and sent to the relay as `TYPE_DISCOVERY_DATA`
//!   with the room ID.
//! - **Inbound**: the relay delivers them as raw IPv4 on UDP 21032 or as
//!   `TYPE_DISCOVERY_DATA` on the main port.  They are injected into the TUN
//!   without ACL evaluation (3.0.x design) — but, unlike 3.0.x, only if the
//!   destination really is a discovery target, so these paths can't be used
//!   to inject unicast traffic past the firewall.
//! - **Registration**: `TYPE_DISCOVERY_REGISTER` from UDP 21032 to the relay
//!   every 25 s so it learns that socket's NAT mapping.
//!
//! ## Secure discovery (sdisc v1, see `crate::sdisc`)
//!
//! Used whenever the current relay advertised a `pub_key` in `GET /relays`
//! (`NetState::relay_pub_key`); otherwise everything above applies as in
//! 3.0.x.  In secure mode:
//!
//! - outbound packets go as authenticated `0x0B`, registration as `0x0A`
//!   (only while in a room: on join, ~1 s later, then every 25 s);
//! - UDP 21032 accepts only `0x0C` from that relay that passes the tag,
//!   recipient and counter checks; bare IPv4 is dropped, and so is
//!   `TYPE_DISCOVERY_DATA` on the main port;
//! - `0x0C` whose original sender the relay could not verify (legacy sender,
//!   relay in `optional` mode) is accepted and counted
//!   (`SdiscStats::rx_unverified_sender`).
//!
//! Every outcome is counted in [`SdiscStats`] (reported by `GetRelays`).
//!
//! Discovery is separate from authorization: a discovered service is still
//! subject to the inbound ACL when connected to.

use crate::ippkt;
use crate::sdisc::{self, DropReason, RegisterSchedule, SdiscKeys};
use crate::state::CoreState;
use msst_core_state::net::msst_packet::{encode_id, MsstPacket, TYPE_DISCOVERY_DATA, TYPE_DISCOVERY_REGISTER, VERSION};
use msst_core_state::net::relay::map_send_addr;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub const DISCOVERY_PORT: u16 = 21032;
const DISCOVERY_MULTICAST: &[Ipv4Addr] = &[Ipv4Addr::new(224, 0, 2, 60), Ipv4Addr::new(224, 0, 0, 251)];
const REGISTER_INTERVAL: Duration = Duration::from_secs(25);
/// Registration loop tick (secure registration needs the 1 s early retry).
const REGISTER_TICK: Duration = Duration::from_secs(1);
/// Minimum interval between warnings about dropped secure packets.
const DROP_WARN_INTERVAL: Duration = Duration::from_secs(60);
const DEDUP_TTL: Duration = Duration::from_secs(3);
const RATE_WINDOW: Duration = Duration::from_secs(1);
const RATE_LIMIT: usize = 10;
/// Broadcast address in MSST space.
const MSST_BROADCAST: Ipv4Addr = Ipv4Addr::new(172, 22, 255, 255);

/// Whether an IPv4 destination is handled by the discovery proxy.
pub fn is_discovery_target(dst: Ipv4Addr) -> bool {
    dst == Ipv4Addr::BROADCAST || dst.octets()[3] == 255 || DISCOVERY_MULTICAST.contains(&dst)
}

/// Whether `data` is an IPv4 packet to a discovery target.
pub fn is_ipv4_discovery_packet(data: &[u8]) -> bool {
    data.len() >= 20 && data[0] >> 4 == 4 && is_discovery_target(Ipv4Addr::new(data[16], data[17], data[18], data[19]))
}

/// Handle an inbound `TYPE_DISCOVERY_DATA` payload
/// (`[room_id_len: 1][room_id][IPv4 packet]`): returns the IPv4 packet to
/// inject, if it is a discovery packet.
pub fn inbound_discovery_payload(payload: &[u8]) -> Option<Vec<u8>> {
    let room_len = *payload.first()? as usize;
    let ip = payload.get(1 + room_len..)?;
    is_ipv4_discovery_packet(ip).then(|| ip.to_vec())
}

/// Build the outbound `TYPE_DISCOVERY_DATA` frame.
pub fn build_discovery_data(device_id: &str, room_id: &str, ip_pkt: &[u8]) -> Vec<u8> {
    let room = &room_id.as_bytes()[..room_id.len().min(255)];
    let mut payload = Vec::with_capacity(1 + room.len() + ip_pkt.len());
    payload.push(room.len() as u8);
    payload.extend_from_slice(room);
    payload.extend_from_slice(ip_pkt);
    MsstPacket { version: VERSION, packet_type: TYPE_DISCOVERY_DATA, flags: 0, src_id: encode_id(device_id), dst_id: [0; 8], payload }.encode()
}

/// Start the proxy.  Returns the sender the outbound path feeds (TUN
/// discovery packets while in a room) and the task handles.  If UDP 21032
/// can't be bound, the sender is a sink.
pub async fn start(state: Arc<CoreState>, tun_tx: mpsc::Sender<Vec<u8>>) -> (mpsc::Sender<Vec<u8>>, Vec<tokio::task::JoinHandle<()>>) {
    let (disc_tx, disc_rx) = mpsc::channel::<Vec<u8>>(256);
    // Dual-stack, like the main socket: the relay may be IPv6.
    let sock = match crate::make_udp_socket(DISCOVERY_PORT) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!("discovery: failed to bind UDP {}: {} — LAN game discovery unavailable", DISCOVERY_PORT, e);
            return (disc_tx, Vec::new());
        }
    };
    info!("discovery: proxy on UDP {}", DISCOVERY_PORT);
    let secure = Arc::new(Mutex::new(SecureSession::default()));
    #[allow(unused_mut)] // only extended on Unix
    let mut handles = vec![
        tokio::spawn(rx_loop(sock.clone(), tun_tx, state.clone(), secure.clone())),
        tokio::spawn(tx_loop(disc_rx, sock.clone(), state.clone(), secure.clone())),
        tokio::spawn(registration_loop(sock, state.clone(), secure)),
    ];
    #[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
    handles.push(tokio::spawn(physical_bcast_loop(disc_tx.clone())));
    (disc_tx, handles)
}

// ---------------------------------------------------------------------------
// Secure discovery session
// ---------------------------------------------------------------------------

/// Secure-discovery counters (atomics: read by `GetRelays` without locks).
#[derive(Debug, Default)]
pub struct SdiscStats {
    pub tx_register: AtomicU64,
    pub tx_data: AtomicU64,
    pub rx_accepted: AtomicU64,
    /// Accepted 0x0C whose original sender the relay did not verify.
    pub rx_unverified_sender: AtomicU64,
    pub drop_not_deliver: AtomicU64,
    pub drop_malformed: AtomicU64,
    pub drop_bad_tag: AtomicU64,
    pub drop_wrong_recipient: AtomicU64,
    pub drop_stale: AtomicU64,
    pub drop_replay: AtomicU64,
    /// Verified, but the payload is not a discovery packet.
    pub drop_not_discovery: AtomicU64,
}

impl SdiscStats {
    fn count_drop(&self, r: DropReason) {
        let c = match r {
            DropReason::NotDeliver => &self.drop_not_deliver,
            DropReason::Malformed => &self.drop_malformed,
            DropReason::BadTag => &self.drop_bad_tag,
            DropReason::WrongRecipient => &self.drop_wrong_recipient,
            DropReason::Stale => &self.drop_stale,
            DropReason::Replay => &self.drop_replay,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        serde_json::json!({
            "tx_register": g(&self.tx_register),
            "tx_data": g(&self.tx_data),
            "rx_accepted": g(&self.rx_accepted),
            "rx_unverified_sender": g(&self.rx_unverified_sender),
            "drop": {
                "not_deliver": g(&self.drop_not_deliver),
                "malformed": g(&self.drop_malformed),
                "bad_tag": g(&self.drop_bad_tag),
                "wrong_recipient": g(&self.drop_wrong_recipient),
                "stale": g(&self.drop_stale),
                "replay": g(&self.drop_replay),
                "not_discovery": g(&self.drop_not_discovery),
            },
        })
    }
}

/// Keys and counters for the current (relay key, device) pair.  Shared by
/// the three loops; guarded by a `std` mutex, never held across `.await`.
#[derive(Default)]
struct SecureSession {
    bound: Option<Bound>,
    /// Shared by 0x0A and 0x0B (they leave the same socket).  Not reset on
    /// relay change: it only has to increase.
    tx_counter: u64,
    last_drop_warn: Option<Instant>,
}

struct Bound {
    relay_pk: [u8; 32],
    device_id: String,
    own_id: u64,
    keys: SdiscKeys,
    /// Last accepted 0x0C counter from this relay.
    rx_last: u64,
}

impl SecureSession {
    /// The bound keys if they match `(relay_pk, device_id)`.
    fn current(&mut self, relay_pk: &[u8; 32], device_id: &str) -> Option<&mut Bound> {
        self.bound.as_mut().filter(|b| &b.relay_pk == relay_pk && b.device_id == device_id)
    }

    fn next_counter(&mut self) -> u64 {
        self.tx_counter = sdisc::next_counter(self.tx_counter, unix_ms());
        self.tx_counter
    }

    /// Rate-limit warnings about dropped packets.
    fn should_warn(&mut self, now: Instant) -> bool {
        if self.last_drop_warn.is_some_and(|t| now.duration_since(t) < DROP_WARN_INTERVAL) {
            return false;
        }
        self.last_drop_warn = Some(now);
        true
    }
}

/// What the loops need to know about the relay, per packet.
struct SecureCtx {
    relay: Option<String>,
    relay_pk: Option<[u8; 32]>,
    room: Option<String>,
    device_id: String,
}

async fn secure_ctx(state: &CoreState) -> SecureCtx {
    let net = state.net.read().await;
    SecureCtx {
        relay: net.relay_addr.clone(),
        relay_pk: net.relay_pub_key,
        room: net.joined_rooms.keys().next().cloned(),
        device_id: net.local_device_id.clone(),
    }
}

/// Make sure the session holds keys for `(relay_pk, device_id)`, deriving
/// them (from the identity key) on first use or after a change.
async fn ensure_keys(state: &CoreState, secure: &Mutex<SecureSession>, relay_pk: &[u8; 32], device_id: &str) -> bool {
    if secure.lock().unwrap().current(relay_pk, device_id).is_some() {
        return true;
    }
    let Some(sk) = state.identity.read().await.as_ref().map(|i| i.secret_key) else { return false };
    let own_id = sdisc::wire_id(device_id);
    let Some(keys) = sdisc::derive_keys(&sk, own_id, relay_pk) else {
        warn!("discovery: relay key is invalid (low-order) — secure discovery unavailable");
        return false;
    };
    info!("discovery: secure discovery (sdisc v1) keys derived for the current relay");
    secure.lock().unwrap().bound = Some(Bound { relay_pk: *relay_pk, device_id: device_id.to_string(), own_id, keys, rx_last: 0 });
    true
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Verify a datagram received on UDP 21032 in secure mode.  Returns the
/// IPv4 discovery packet to inject; updates the replay state and counters.
/// `Err(Some(reason))`: failed verification; `Err(None)`: verified, but not
/// a discovery packet.  Every drop is counted here.
fn accept_secure(session: &mut Bound, stats: &SdiscStats, pkt: &[u8], now_ms: u64) -> Result<Vec<u8>, Option<DropReason>> {
    let d = sdisc::verify_deliver(&session.keys, session.own_id, pkt, now_ms, session.rx_last).map_err(|r| {
        stats.count_drop(r);
        Some(r)
    })?;
    session.rx_last = d.counter;
    if !is_ipv4_discovery_packet(d.ipv4) {
        stats.drop_not_discovery.fetch_add(1, Ordering::Relaxed);
        return Err(None);
    }
    stats.rx_accepted.fetch_add(1, Ordering::Relaxed);
    if !d.sender_verified {
        // Legacy sender (relay in optional mode): accepted by local policy.
        stats.rx_unverified_sender.fetch_add(1, Ordering::Relaxed);
        debug!("discovery: accepted 0x0C from unverified sender {:016x}", d.sender);
    }
    Ok(d.ipv4.to_vec())
}

async fn rx_loop(sock: Arc<UdpSocket>, tun_tx: mpsc::Sender<Vec<u8>>, state: Arc<CoreState>, secure: Arc<Mutex<SecureSession>>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let (len, src) = match sock.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(e) => {
                warn!("discovery: rx error: {}", e);
                continue;
            }
        };
        let ctx = secure_ctx(&state).await;
        let pkt = if let Some(relay_pk) = ctx.relay_pk {
            if !ensure_keys(&state, &secure, &relay_pk, &ctx.device_id).await {
                continue;
            }
            let mut s = secure.lock().unwrap();
            let Some(bound) = s.current(&relay_pk, &ctx.device_id) else { continue };
            match accept_secure(bound, &state.sdisc_stats, &buf[..len], unix_ms()) {
                Ok(ip) => ip,
                Err(None) => continue,
                Err(Some(r)) => {
                    if r == DropReason::Stale && s.should_warn(Instant::now()) {
                        warn!("discovery: dropping secure discovery packets with stale timestamps — is the system clock off by more than {} s?", sdisc::MAX_CLOCK_SKEW_MS / 1000);
                    } else {
                        debug!("discovery: secure mode dropped {} B from {} ({})", len, src, r.as_str());
                    }
                    continue;
                }
            }
        } else {
            if !is_ipv4_discovery_packet(&buf[..len]) {
                debug!("discovery: dropped non-discovery packet ({} B) from {}", len, src);
                continue;
            }
            buf[..len].to_vec()
        };
        if tun_tx.send(pkt).await.is_err() {
            break;
        }
    }
}

/// De-duplication and per-device rate limiting.
#[derive(Default)]
struct TxState {
    dedup: HashMap<[u8; 16], Instant>,
    rate: HashMap<String, VecDeque<Instant>>,
}

impl TxState {
    fn is_duplicate(&mut self, device_id: &str, pkt: &[u8], now: Instant) -> bool {
        let mut h = Sha256::new();
        h.update(device_id.as_bytes());
        h.update(pkt);
        let mut key = [0u8; 16];
        key.copy_from_slice(&h.finalize()[..16]);
        self.dedup.retain(|_, t| now.duration_since(*t) < DEDUP_TTL);
        self.dedup.insert(key, now).is_some()
    }

    fn is_rate_limited(&mut self, device_id: &str, now: Instant) -> bool {
        let q = self.rate.entry(device_id.to_string()).or_default();
        while q.front().is_some_and(|&t| now.duration_since(t) >= RATE_WINDOW) {
            q.pop_front();
        }
        if q.len() >= RATE_LIMIT {
            return true;
        }
        q.push_back(now);
        false
    }
}

async fn tx_loop(mut rx: mpsc::Receiver<Vec<u8>>, sock: Arc<UdpSocket>, state: Arc<CoreState>, secure: Arc<Mutex<SecureSession>>) {
    let mut st = TxState::default();
    while let Some(mut pkt) = rx.recv().await {
        let SecureCtx { relay, relay_pk, room, device_id } = secure_ctx(&state).await;
        let (Some(relay), Some(room)) = (relay, room) else { continue };
        if device_id.is_empty() {
            continue;
        }
        if needs_msst_rewrite(&pkt) {
            let Some(vip) = vpn_ipv4(&state).await else { continue };
            rewrite_for_msst_broadcast(&mut pkt, vip);
        }
        let now = Instant::now();
        if st.is_duplicate(&device_id, &pkt, now) || st.is_rate_limited(&device_id, now) {
            continue;
        }
        let frame = match relay_pk {
            None => build_discovery_data(&device_id, &room, &pkt),
            Some(relay_pk) => {
                if !ensure_keys(&state, &secure, &relay_pk, &device_id).await {
                    continue;
                }
                let mut s = secure.lock().unwrap();
                let counter = s.next_counter();
                let Some(bound) = s.current(&relay_pk, &device_id) else { continue };
                // Never downgraded to 0x09: an invalid room ID just isn't sent.
                let Some(frame) = sdisc::build_client_packet(&bound.keys, bound.own_id, counter, &room, Some(&pkt)) else {
                    debug!("discovery: room ID {:?} not valid for secure discovery", room);
                    continue;
                };
                state.sdisc_stats.tx_data.fetch_add(1, Ordering::Relaxed);
                frame
            }
        };
        let Some(target) = crate::relay::resolve_addr(&relay).await else { continue };
        if let Err(e) = sock.send_to(&frame, map_send_addr(target)).await {
            warn!("discovery: send to relay failed: {}", e);
        }
    }
}

/// Legacy: `TYPE_DISCOVERY_REGISTER` every 25 s whenever a relay is known.
/// Secure: `0x0A` per [`RegisterSchedule`], only while in a room (the relay
/// finds our key through the room's peer list).
async fn registration_loop(sock: Arc<UdpSocket>, state: Arc<CoreState>, secure: Arc<Mutex<SecureSession>>) {
    let mut ticker = tokio::time::interval(REGISTER_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut legacy_next = Instant::now();
    let mut schedule = RegisterSchedule::default();
    let start = Instant::now();
    loop {
        ticker.tick().await;
        let SecureCtx { relay, relay_pk, room, device_id: id } = secure_ctx(&state).await;
        let now_ms = start.elapsed().as_millis() as u64;
        let pkt = match relay_pk {
            None => {
                schedule.poll(None, now_ms);
                let now = Instant::now();
                if relay.is_none() || id.is_empty() || now < legacy_next {
                    continue;
                }
                legacy_next = now + REGISTER_INTERVAL;
                MsstPacket { version: VERSION, packet_type: TYPE_DISCOVERY_REGISTER, flags: 0, src_id: encode_id(&id), dst_id: [0; 8], payload: vec![] }.encode()
            }
            Some(relay_pk) => {
                // Next legacy register goes out immediately if the relay
                // loses its key.
                legacy_next = Instant::now();
                let target = match (&relay, &room) {
                    (Some(r), Some(room)) if !id.is_empty() => Some((r.clone(), room.clone(), relay_pk)),
                    _ => None,
                };
                if !schedule.poll(target, now_ms) || !ensure_keys(&state, &secure, &relay_pk, &id).await {
                    continue;
                }
                let mut s = secure.lock().unwrap();
                let counter = s.next_counter();
                let Some(bound) = s.current(&relay_pk, &id) else { continue };
                let Some(pkt) = sdisc::build_client_packet(&bound.keys, bound.own_id, counter, room.as_deref().unwrap_or(""), None) else { continue };
                state.sdisc_stats.tx_register.fetch_add(1, Ordering::Relaxed);
                pkt
            }
        };
        let Some(relay) = relay else { continue };
        let Some(target) = crate::relay::resolve_addr(&relay).await else { continue };
        if let Err(e) = sock.send_to(&pkt, map_send_addr(target)).await {
            debug!("discovery: register send failed: {}", e);
        }
    }
}

/// Unix desktop: capture UDP broadcasts this machine sends on its physical
/// LAN (raw socket, needs CAP_NET_RAW/root) and forward them.  Broadcasts
/// from other machines are ignored — their own client forwards them.
#[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
async fn physical_bcast_loop(disc_tx: mpsc::Sender<Vec<u8>>) {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::collections::HashSet;
    use std::mem::MaybeUninit;
    use tokio::io::unix::AsyncFd;

    let local_ips: HashSet<Ipv4Addr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.ip() {
            IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
            _ => None,
        })
        .collect();
    if local_ips.is_empty() {
        return;
    }
    let raw = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)).and_then(|s| s.set_nonblocking(true).map(|_| s)) {
        Ok(s) => s,
        Err(e) => {
            warn!("discovery: physical broadcast capture unavailable (needs CAP_NET_RAW/root): {}", e);
            return;
        }
    };
    let Ok(fd) = AsyncFd::new(raw) else { return };
    info!("discovery: physical LAN broadcast capture active");
    let mut buf = vec![MaybeUninit::<u8>::uninit(); 65536];
    loop {
        let Ok(mut guard) = fd.readable().await else { break };
        let len = match guard.try_io(|inner| inner.get_ref().recv_from(&mut buf)) {
            Ok(Ok((n, _))) => n,
            Ok(Err(e)) => {
                warn!("discovery: raw recv error: {}", e);
                break;
            }
            Err(_) => continue,
        };
        // SAFETY: recv_from initialized buf[..len].
        let pkt: Vec<u8> = buf[..len].iter().map(|b| unsafe { b.assume_init() }).collect();
        if !needs_msst_rewrite(&pkt) || !local_ips.contains(&Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])) {
            continue;
        }
        if disc_tx.send(pkt).await.is_err() {
            break;
        }
    }
}

/// IPv4/UDP subnet broadcast outside MSST space (needs rewriting).
fn needs_msst_rewrite(pkt: &[u8]) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
        return false;
    }
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    dst.octets()[3] == 255 && !(dst.octets()[0] == 172 && dst.octets()[1] == 22) && !dst.is_multicast()
}

/// Rewrite src → our VPN IP, dst → 172.22.255.255; fix both checksums.
fn rewrite_for_msst_broadcast(pkt: &mut [u8], vpn_src: Ipv4Addr) {
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt.len() < ihl + 8 {
        return;
    }
    let udp_len = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]) as usize;
    let seg_end = (ihl + udp_len).min(pkt.len());
    pkt[12..16].copy_from_slice(&vpn_src.octets());
    pkt[16..20].copy_from_slice(&MSST_BROADCAST.octets());
    pkt[10..12].copy_from_slice(&[0, 0]);
    let c = ippkt::csum_fold(ippkt::csum_add(0, &pkt[..ihl]));
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
    pkt[ihl + 6..ihl + 8].copy_from_slice(&[0, 0]);
    let c = ippkt::udp_checksum(&IpAddr::V4(vpn_src), &IpAddr::V4(MSST_BROADCAST), &pkt[ihl..seg_end]);
    pkt[ihl + 6..ihl + 8].copy_from_slice(&c.to_be_bytes());
}

async fn vpn_ipv4(state: &CoreState) -> Option<Ipv4Addr> {
    state.identity.read().await.as_ref()?.virtual_ips().0.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_to(dst: Ipv4Addr) -> Vec<u8> {
        ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 4445, IpAddr::V4(dst), 4445, b"[MOTD]x[/MOTD]")
    }

    #[test]
    fn targets() {
        assert!(is_discovery_target(Ipv4Addr::new(224, 0, 2, 60)));
        assert!(is_discovery_target(Ipv4Addr::new(224, 0, 0, 251)));
        assert!(is_discovery_target(Ipv4Addr::new(192, 168, 1, 255)));
        assert!(is_discovery_target(Ipv4Addr::BROADCAST));
        assert!(!is_discovery_target(Ipv4Addr::new(172, 22, 1, 1)));
        assert!(!is_discovery_target(Ipv4Addr::new(224, 0, 0, 1)));
    }

    #[test]
    fn inbound_payload_only_admits_discovery_packets() {
        let mc = udp_to(Ipv4Addr::new(224, 0, 2, 60));
        let frame = build_discovery_data("device-00000001", "space-1", &mc);
        let pkt = MsstPacket::decode(&frame).unwrap();
        assert_eq!(pkt.packet_type, TYPE_DISCOVERY_DATA);
        assert_eq!(inbound_discovery_payload(&pkt.payload).unwrap(), mc);
        // A unicast packet smuggled in the same frame is refused.
        let unicast = udp_to(Ipv4Addr::new(172, 22, 0, 1));
        let frame = build_discovery_data("device-00000001", "space-1", &unicast);
        assert!(inbound_discovery_payload(&MsstPacket::decode(&frame).unwrap().payload).is_none());
        assert!(inbound_discovery_payload(&[5, 1]).is_none());
    }

    #[test]
    fn physical_broadcast_rewrite() {
        let mut p = udp_to(Ipv4Addr::new(192, 168, 1, 255));
        assert!(needs_msst_rewrite(&p));
        rewrite_for_msst_broadcast(&mut p, Ipv4Addr::new(172, 22, 144, 209));
        let u = ippkt::udp_parts(&p).unwrap();
        assert_eq!((u.src, u.dst), (IpAddr::V4(Ipv4Addr::new(172, 22, 144, 209)), IpAddr::V4(MSST_BROADCAST)));
        assert!(ippkt::checksums_valid(&p));
        assert!(!needs_msst_rewrite(&p), "already in MSST space");
        assert!(!needs_msst_rewrite(&udp_to(Ipv4Addr::new(224, 0, 2, 60))));
    }

    #[test]
    fn dedup_and_rate_limit() {
        let mut st = TxState::default();
        let t = Instant::now();
        assert!(!st.is_duplicate("d", b"x", t));
        assert!(st.is_duplicate("d", b"x", t));
        assert!(!st.is_duplicate("d", b"x", t + DEDUP_TTL));
        for _ in 0..RATE_LIMIT {
            assert!(!st.is_rate_limited("d", t));
        }
        assert!(st.is_rate_limited("d", t));
        assert!(!st.is_rate_limited("d", t + RATE_WINDOW));
    }

    // ── Secure mode (sdisc v1) ───────────────────────────────────────────

    use x25519_dalek::{PublicKey, StaticSecret};

    /// Session as both sides of the spec vectors see it: device key 1×32,
    /// relay key 2×32, device-a1b2c3d4.
    fn vector_session() -> (Bound, SdiscKeys) {
        let relay_pk = *PublicKey::from(&StaticSecret::from([2u8; 32])).as_bytes();
        let keys = sdisc::derive_keys(&[1u8; 32], 0xa1b2c3d4, &relay_pk).unwrap();
        (Bound { relay_pk, device_id: "device-a1b2c3d4".into(), own_id: 0xa1b2c3d4, keys: keys.clone(), rx_last: 0 }, keys)
    }

    fn deliver(keys: &SdiscKeys, sender: u64, flags: u8, counter: u64, ip: &[u8]) -> Vec<u8> {
        sdisc::seal_deliver(keys, sender, 0xa1b2c3d4, flags, counter, ip)
    }

    #[test]
    fn secure_rx_accepts_verified_and_counts() {
        let (mut session, keys) = vector_session();
        let stats = SdiscStats::default();
        let now_ms = 1_760_000_000_000u64;
        let mc = udp_to(Ipv4Addr::new(224, 0, 2, 60));

        let p1 = deliver(&keys, 7, sdisc::FLAG_SENDER_VERIFIED, now_ms << 16, &mc);
        assert_eq!(accept_secure(&mut session, &stats, &p1, now_ms).unwrap(), mc);
        // Replayed → dropped; replay state unchanged by it.
        assert_eq!(accept_secure(&mut session, &stats, &p1, now_ms), Err(Some(DropReason::Replay)));
        // Unverified original sender (legacy, relay optional): accepted, counted.
        let p2 = deliver(&keys, 8, 0, (now_ms << 16) + 1, &mc);
        assert_eq!(accept_secure(&mut session, &stats, &p2, now_ms).unwrap(), mc);
        // Verified frame carrying unicast: refused (no ACL bypass).
        let p3 = deliver(&keys, 7, sdisc::FLAG_SENDER_VERIFIED, (now_ms << 16) + 2, &udp_to(Ipv4Addr::new(172, 22, 0, 1)));
        assert_eq!(accept_secure(&mut session, &stats, &p3, now_ms), Err(None));
        // Bare IPv4 (3.0.x delivery) is not accepted in secure mode.
        assert_eq!(accept_secure(&mut session, &stats, &mc, now_ms), Err(Some(DropReason::NotDeliver)));

        let snap = stats.snapshot();
        assert_eq!(snap["rx_accepted"], 2);
        assert_eq!(snap["rx_unverified_sender"], 1);
        assert_eq!(snap["drop"]["replay"], 1);
        assert_eq!(snap["drop"]["not_discovery"], 1);
        assert_eq!(snap["drop"]["not_deliver"], 1);
    }

    #[test]
    fn secure_session_rebinds_on_relay_or_device_change() {
        let (session, _) = vector_session();
        let relay_pk = session.relay_pk;
        let mut s = SecureSession { bound: Some(session), ..Default::default() };
        assert!(s.current(&relay_pk, "device-a1b2c3d4").is_some());
        assert!(s.current(&[9u8; 32], "device-a1b2c3d4").is_none());
        assert!(s.current(&relay_pk, "device-00000001").is_none());
        let a = s.next_counter();
        assert!(s.next_counter() > a);
    }
}
