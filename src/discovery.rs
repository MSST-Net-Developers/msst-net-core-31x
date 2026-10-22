//! Game discovery proxy — UDP 21032.
//!
//! Carries IPv4 multicast/broadcast (Minecraft Java LAN 224.0.2.60, mDNS
//! 224.0.0.251, subnet broadcasts) between members of a room so LAN game
//! discovery works over the virtual network.  It uses secure discovery
//! (sdisc v1, see `crate::sdisc`) only, so it needs relays that advertise a
//! `pub_key` in `GET /relays`.
//!
//! A relay delivers discovery only to room members registered with it, and
//! members may use different relays.  So discovery goes to every relay a
//! room member uses: ours (`NetState::relay_pub_key`) and each member's
//! (its `relay:` endpoint, identified by key through the relay list).  A
//! member whose relay has no key, or isn't listed, gets no discovery.
//!
//! - **Outbound** (only while in a room): discovery packets read from the
//!   TUN — and, on Unix desktops, broadcasts this machine sends on its
//!   physical LAN (rewritten into MSST-Net space) — are de-duplicated,
//!   rate-limited (10/s) and sent to each of those relays as authenticated
//!   `0x0B`.
//! - **Registration**: `0x0A` from UDP 21032 to each of those relays (when
//!   it becomes one, ~1 s later, then every 25 s) so it learns that
//!   socket's NAT mapping.
//! - **Inbound**: UDP 21032 accepts only `0x0C` from one of those relays
//!   that passes the tag, recipient and counter checks and whose original
//!   sender the relay authenticated (flag bit 0) and is in our room.  The
//!   payload must be a discovery datagram ([`discovery_datagram`]: UDP to
//!   MSST-Net's broadcast address on any port — games pick their own — or
//!   to one of [`DISCOVERY_MULTICAST`]); it is rebuilt with the sender's own
//!   virtual address as its source and then injected into the TUN without
//!   ACL evaluation — so this path carries no unicast, no other protocols
//!   and no forged sources.  A packet that arrives through several relays
//!   is injected once, and what is injected is rate-limited per sender
//!   (10/s, like our own outbound discovery) and in total (100/s).
//!
//! Every outcome is counted in [`SdiscStats`] (reported by `GetRelays`).
//!
//! Discovery is separate from authorization: a discovered service is still
//! subject to the inbound ACL when connected to.

use crate::ippkt;
use crate::relay::KnownRelay;
use crate::sdisc::{self, DropReason, RegisterSchedule, SdiscKeys};
use crate::state::CoreState;
use msst_core_state::net::relay::{map_send_addr, unmap_addr};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub const DISCOVERY_PORT: u16 = 21032;
/// Multicast groups carried, each with its protocol's UDP port: Minecraft
/// Java Edition LAN worlds and mDNS.
const DISCOVERY_MULTICAST: &[(Ipv4Addr, u16)] = &[(Ipv4Addr::new(224, 0, 2, 60), 4445), (Ipv4Addr::new(224, 0, 0, 251), 5353)];
/// Registration loop tick (secure registration needs the 1 s early retry).
const REGISTER_TICK: Duration = Duration::from_secs(1);
/// Minimum interval between warnings about dropped secure packets.
const DROP_WARN_INTERVAL: Duration = Duration::from_secs(60);
const DEDUP_TTL: Duration = Duration::from_secs(3);
/// A packet arriving again within this time (through another relay) is
/// dropped.  Shorter than games' re-broadcast interval (Minecraft: 1.5 s).
const RX_DEDUP_TTL: Duration = Duration::from_secs(1);
/// Relays with derived keys kept at most (the set is cleared beyond).
const MAX_BOUND_RELAYS: usize = 16;
/// Relay list (`GET /relays`): refetch for an unknown member relay at most
/// this often, refresh at least this often, give up a request after this.
const RELAY_LIST_RETRY: Duration = Duration::from_secs(60);
const RELAY_LIST_MAX_AGE: Duration = Duration::from_secs(15 * 60);
const RELAY_LIST_TIMEOUT: Duration = Duration::from_secs(5);
const RATE_WINDOW: Duration = Duration::from_secs(1);
/// Discovery packets per sender per [`RATE_WINDOW`], sent and received.
const RATE_LIMIT: usize = 10;
/// Discovery packets injected per [`RATE_WINDOW`] from all senders
/// together: room size is unlimited, so this bounds what reaches the TUN
/// however many senders there are (or a room relay claims there are).
/// Games announce about once a second; this leaves room for ~50 members
/// announcing twice a second.
const RX_GLOBAL_RATE_LIMIT: usize = 100;
/// Broadcast address in MSST-Net space.
const MSST_BROADCAST: Ipv4Addr = Ipv4Addr::new(172, 22, 255, 255);

/// A discovery datagram ([`discovery_datagram`]).
#[derive(Debug, PartialEq, Eq)]
struct DiscoveryDatagram<'a> {
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
}

/// `pkt` as a discovery datagram: a plain IPv4/UDP packet (no options, not
/// fragmented, consistent lengths) to MSST-Net's broadcast address
/// (172.22.255.255, or 255.255.255.255) on any port, or to one of
/// [`DISCOVERY_MULTICAST`] on its port.  Subnet broadcasts of other networks
/// are never carried: in this host's networks they may be unicast
/// addresses.
fn discovery_datagram(pkt: &[u8]) -> Option<DiscoveryDatagram<'_>> {
    if pkt.len() < 28 || pkt[0] != 0x45 || pkt[9] != 17 {
        return None;
    }
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let fragment = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff; // MF + offset
    let udp_len = u16::from_be_bytes([pkt[24], pkt[25]]) as usize;
    if total < 28 || total > pkt.len() || fragment != 0 || udp_len < 8 || 20 + udp_len > total {
        return None;
    }
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let dst_port = u16::from_be_bytes([pkt[22], pkt[23]]);
    if dst != MSST_BROADCAST && dst != Ipv4Addr::BROADCAST && !DISCOVERY_MULTICAST.contains(&(dst, dst_port)) {
        return None;
    }
    Some(DiscoveryDatagram { dst, src_port: u16::from_be_bytes([pkt[20], pkt[21]]), dst_port, payload: &pkt[28..20 + udp_len] })
}

/// The packet to inject for a verified delivery from `sender` (wire ID):
/// rebuilt from `sender`'s own virtual IPv4 address.  `None` unless the
/// sender is a member of our room we know the address of.
fn rebuild_from_sender(net: &crate::state::NetState, sender: u64, pkt: &[u8]) -> Option<Vec<u8>> {
    let d = discovery_datagram(pkt)?;
    let device_id = format!("device-{:08x}", sender);
    if !net.room_peers.contains(&device_id) {
        return None;
    }
    let src = net.peer_list.get(&device_id)?.ipv4;
    src.is_ipv4().then(|| ippkt::build_udp(src, d.src_port, IpAddr::V4(d.dst), d.dst_port, d.payload))
}

/// Whether an IPv4 destination is handled by the discovery proxy.
pub fn is_discovery_target(dst: Ipv4Addr) -> bool {
    dst == Ipv4Addr::BROADCAST || dst.octets()[3] == 255 || DISCOVERY_MULTICAST.iter().any(|&(a, _)| a == dst)
}

/// Whether `data` is an IPv4 packet to a discovery target.
pub fn is_ipv4_discovery_packet(data: &[u8]) -> bool {
    data.len() >= 20 && data[0] >> 4 == 4 && is_discovery_target(Ipv4Addr::new(data[16], data[17], data[18], data[19]))
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
    pub drop_not_deliver: AtomicU64,
    pub drop_malformed: AtomicU64,
    pub drop_bad_tag: AtomicU64,
    pub drop_wrong_recipient: AtomicU64,
    pub drop_stale: AtomicU64,
    pub drop_replay: AtomicU64,
    /// Verified, but the payload is not a discovery packet.
    pub drop_not_discovery: AtomicU64,
    /// Verified, but the relay could not authenticate the original sender.
    pub drop_unverified_sender: AtomicU64,
    /// Verified, but the same packet already arrived through another relay.
    pub drop_duplicate: AtomicU64,
    /// Verified, but its sender exceeded the per-sender rate limit.
    pub drop_rate_limited: AtomicU64,
    /// Relays discovery currently goes to (`IP:port`).
    relays: Mutex<Vec<String>>,
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

    fn set_relays(&self, relays: Vec<String>) {
        *self.relays.lock().unwrap_or_else(|e| e.into_inner()) = relays;
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        serde_json::json!({
            "relays": *self.relays.lock().unwrap_or_else(|e| e.into_inner()),
            "tx_register": g(&self.tx_register),
            "tx_data": g(&self.tx_data),
            "rx_accepted": g(&self.rx_accepted),
            "drop": {
                "not_deliver": g(&self.drop_not_deliver),
                "malformed": g(&self.drop_malformed),
                "bad_tag": g(&self.drop_bad_tag),
                "wrong_recipient": g(&self.drop_wrong_recipient),
                "stale": g(&self.drop_stale),
                "replay": g(&self.drop_replay),
                "not_discovery": g(&self.drop_not_discovery),
                "unverified_sender": g(&self.drop_unverified_sender),
                "duplicate": g(&self.drop_duplicate),
                "rate_limited": g(&self.drop_rate_limited),
            },
        })
    }
}

/// A relay discovery goes to, identified by its key.
#[derive(Debug, Clone, PartialEq)]
struct Target {
    relay_pk: [u8; 32],
    addr: SocketAddr,
}

/// Where discovery goes now (set by the registration loop, used by the
/// outbound loop).
#[derive(Clone)]
struct Route {
    room: String,
    device_id: String,
    targets: Vec<Target>,
}

/// Keys, counters and the current route.  Shared by the three loops;
/// guarded by a `std` mutex, never held across `.await`.
#[derive(Default)]
struct SecureSession {
    /// Per relay key.
    bound: HashMap<[u8; 32], Bound>,
    route: Option<Route>,
    /// Shared by 0x0A and 0x0B to every relay (they leave the same
    /// socket); only has to increase.
    tx_counter: u64,
    /// Recently delivered packets (sender, payload), so a packet that
    /// arrives through several relays is delivered once.
    rx_seen: HashMap<[u8; 16], Instant>,
    /// Rate limits on what is injected: per sender, then all senders
    /// together (the relay limits senders too, but a room relay is run by
    /// whoever created the room).
    rx_rate: RateLimit<u64>,
    rx_global_rate: GlobalRateLimit,
    last_drop_warn: Option<Instant>,
}

struct Bound {
    device_id: String,
    own_id: u64,
    keys: SdiscKeys,
    /// The relay's address we last sent to (tried first on receive).
    addr: Option<SocketAddr>,
    /// Last accepted 0x0C counter from this relay.
    rx_last: u64,
}

impl SecureSession {
    /// The bound keys for `relay_pk` if they are for `device_id`.
    fn current(&mut self, relay_pk: &[u8; 32], device_id: &str) -> Option<&mut Bound> {
        self.bound.get_mut(relay_pk).filter(|b| b.device_id == device_id)
    }

    fn bind(&mut self, relay_pk: [u8; 32], bound: Bound) {
        if self.bound.len() >= MAX_BOUND_RELAYS && !self.bound.contains_key(&relay_pk) {
            self.bound.clear();
        }
        self.bound.insert(relay_pk, bound);
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

    /// Verify a datagram from `src` received on UDP 21032 with the keys of
    /// every relay we are bound to (the one at `src` first) and return the
    /// IPv4 discovery packet to inject; updates replay state and counters.
    /// `Err(Some(reason))`: failed verification; `Err(None)`: verified, but
    /// not a discovery packet, from a sender the relay could not
    /// authenticate, or already delivered — or no relay is bound.  Every
    /// drop is counted here.
    /// A verified delivery: its sender (wire ID) and IPv4 packet.
    fn accept(&mut self, device_id: &str, src: SocketAddr, stats: &SdiscStats, pkt: &[u8], now_ms: u64, now: Instant) -> Result<(u64, Vec<u8>), Option<DropReason>> {
        let mut order: Vec<(bool, [u8; 32])> =
            self.bound.iter().filter(|(_, b)| b.device_id == device_id).map(|(k, b)| (b.addr != Some(src), *k)).collect();
        if order.is_empty() {
            return Err(None);
        }
        order.sort_unstable();
        let mut reason = DropReason::BadTag;
        for (_, k) in order {
            let b = self.bound.get_mut(&k).expect("listed above");
            match sdisc::verify_deliver(&b.keys, b.own_id, pkt, now_ms, b.rx_last) {
                Ok(d) => {
                    b.rx_last = d.counter;
                    return self.deliver(d, stats, now);
                }
                // Another relay's packet: try the next key.
                Err(DropReason::BadTag) => {}
                Err(r) => {
                    reason = r;
                    break;
                }
            }
        }
        stats.count_drop(reason);
        Err(Some(reason))
    }

    fn deliver(&mut self, d: sdisc::Delivery<'_>, stats: &SdiscStats, now: Instant) -> Result<(u64, Vec<u8>), Option<DropReason>> {
        if !d.sender_verified {
            // The relay forwarded a sender it could not authenticate.
            stats.drop_unverified_sender.fetch_add(1, Ordering::Relaxed);
            debug!("discovery: dropped 0x0C from unverified sender {:016x}", d.sender);
            return Err(None);
        }
        if discovery_datagram(d.ipv4).is_none() {
            stats.drop_not_discovery.fetch_add(1, Ordering::Relaxed);
            return Err(None);
        }
        let mut h = Sha256::new();
        h.update(d.sender.to_be_bytes());
        h.update(d.ipv4);
        let mut key = [0u8; 16];
        key.copy_from_slice(&h.finalize()[..16]);
        self.rx_seen.retain(|_, t| now.duration_since(*t) < RX_DEDUP_TTL);
        if self.rx_seen.insert(key, now).is_some() {
            stats.drop_duplicate.fetch_add(1, Ordering::Relaxed);
            return Err(None);
        }
        // After de-duplication: copies via other relays cost nothing.  Per
        // sender first, so a flooding sender's excess doesn't use up the
        // global budget and starve the others.
        if self.rx_rate.exceeded(&d.sender, now) || self.rx_global_rate.0.exceeded(&(), now) {
            stats.drop_rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(None);
        }
        Ok((d.sender, d.ipv4.to_vec()))
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
        warn!("discovery: relay key is invalid (low-order) — no secure discovery through that relay");
        return false;
    };
    info!("discovery: secure discovery (sdisc v1) keys derived for a relay");
    secure.lock().unwrap().bind(*relay_pk, Bound { device_id: device_id.to_string(), own_id, keys, addr: None, rx_last: 0 });
    true
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
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
        let device_id = state.net.read().await.local_device_id.clone();
        let (sender, ip) = {
            let mut s = secure.lock().unwrap();
            match s.accept(&device_id, unmap_addr(src), &state.sdisc_stats, &buf[..len], unix_ms(), Instant::now()) {
                Ok(v) => v,
                Err(None) => continue,
                Err(Some(r)) => {
                    if r == DropReason::Stale && s.should_warn(Instant::now()) {
                        warn!("discovery: dropping secure discovery packets with stale timestamps — is the system clock off by more than {} s?", sdisc::MAX_CLOCK_SKEW_MS / 1000);
                    } else {
                        debug!("discovery: dropped {} B from {} ({})", len, src, r.as_str());
                    }
                    continue;
                }
            }
        };
        // Only a room member's own announcements, from its own address.
        let Some(pkt) = rebuild_from_sender(&*state.net.read().await, sender, &ip) else {
            state.sdisc_stats.drop_unverified_sender.fetch_add(1, Ordering::Relaxed);
            debug!("discovery: dropped 0x0C from {:016x}: not a member of our room", sender);
            continue;
        };
        state.sdisc_stats.rx_accepted.fetch_add(1, Ordering::Relaxed);
        if tun_tx.send(pkt).await.is_err() {
            break;
        }
    }
}

/// De-duplication and per-device rate limiting.
#[derive(Default)]
struct TxState {
    dedup: HashMap<[u8; 16], Instant>,
    rate: RateLimit<String>,
}

/// At most `limit` packets per [`RATE_WINDOW`] per key: [`RATE_LIMIT`] per
/// sender by default, [`RX_GLOBAL_RATE_LIMIT`] for [`GlobalRateLimit`].
struct RateLimit<K> {
    limit: usize,
    sent: HashMap<K, VecDeque<Instant>>,
}

impl<K> Default for RateLimit<K> {
    fn default() -> Self {
        RateLimit { limit: RATE_LIMIT, sent: HashMap::new() }
    }
}

/// [`RX_GLOBAL_RATE_LIMIT`] for all senders together (the one key `()`).
struct GlobalRateLimit(RateLimit<()>);

impl Default for GlobalRateLimit {
    fn default() -> Self {
        GlobalRateLimit(RateLimit { limit: RX_GLOBAL_RATE_LIMIT, sent: HashMap::new() })
    }
}

impl<K: std::hash::Hash + Eq + Clone> RateLimit<K> {
    /// Whether a packet from `key` now exceeds the limit (if not, it counts).
    fn exceeded(&mut self, key: &K, now: Instant) -> bool {
        // Forget idle senders, so the map stays as small as the room.
        self.sent.retain(|_, q| {
            while q.front().is_some_and(|&t| now.duration_since(t) >= RATE_WINDOW) {
                q.pop_front();
            }
            !q.is_empty()
        });
        let q = self.sent.entry(key.clone()).or_default();
        if q.len() >= self.limit {
            return true;
        }
        q.push_back(now);
        false
    }
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
        self.rate.exceeded(&device_id.to_string(), now)
    }
}

async fn tx_loop(mut rx: mpsc::Receiver<Vec<u8>>, sock: Arc<UdpSocket>, state: Arc<CoreState>, secure: Arc<Mutex<SecureSession>>) {
    let mut st = TxState::default();
    while let Some(mut pkt) = rx.recv().await {
        // Set by the registration loop while in a room with a secure relay.
        let Some(route) = secure.lock().unwrap().route.clone() else { continue };
        if needs_msst_rewrite(&pkt) {
            let Some(vip) = vpn_ipv4(&state).await else { continue };
            rewrite_for_msst_broadcast(&mut pkt, vip);
        }
        if discovery_datagram(&pkt).is_none() || is_foreign_member_packet(&pkt, vpn_ipv4(&state).await) {
            continue;
        }
        let now = Instant::now();
        if st.is_duplicate(&route.device_id, &pkt, now) || st.is_rate_limited(&route.device_id, now) {
            continue;
        }
        // The same packet to every relay a room member uses: each relay
        // delivers it to the members registered with it.
        let frames: Vec<(SocketAddr, Vec<u8>)> = {
            let mut s = secure.lock().unwrap();
            let mut out = Vec::with_capacity(route.targets.len());
            for t in &route.targets {
                let counter = s.next_counter();
                let Some(bound) = s.current(&t.relay_pk, &route.device_id) else { continue };
                let Some(frame) = sdisc::build_client_packet(&bound.keys, bound.own_id, counter, &route.room, Some(&pkt)) else {
                    debug!("discovery: room ID {:?} not valid for secure discovery", route.room);
                    break;
                };
                state.sdisc_stats.tx_data.fetch_add(1, Ordering::Relaxed);
                out.push((t.addr, frame));
            }
            out
        };
        for (addr, frame) in frames {
            if let Err(e) = sock.send_to(&frame, map_send_addr(addr)).await {
                warn!("discovery: send to relay {} failed: {}", addr, e);
            }
        }
    }
}

/// The relays discovery goes to: ours (our preferred relay, and the room
/// relay while it works), plus the relay each room member's traffic goes
/// through (`NetState::relay_for_peer`), identified by key through the
/// relay list (and the room relay's key from `room_state`).  Members on a
/// relay we have no key for (not listed, or listed without a key) can't be
/// reached; the second value says whether one was seen, so the list can be
/// refreshed.  Each relay appears once, at an address we can reach.
fn plan_targets(own: Vec<Target>, peer_relays: &[SocketAddr], known: &[KnownRelay], v6_ok: bool) -> (Vec<Target>, bool) {
    let reachable = |a: &SocketAddr| a.is_ipv4() || v6_ok;
    let mut targets: Vec<Target> = Vec::with_capacity(own.len() + peer_relays.len());
    for t in own {
        if !targets.iter().any(|x| x.relay_pk == t.relay_pk) {
            targets.push(t);
        }
    }
    let mut unknown = false;
    for &peer_relay in peer_relays {
        let Some(relay) = known.iter().find(|k| k.addrs.contains(&peer_relay)) else {
            unknown = true;
            continue;
        };
        if targets.iter().any(|t| t.relay_pk == relay.pub_key) {
            continue;
        }
        let addr = if reachable(&peer_relay) { Some(peer_relay) } else { relay.addrs.iter().copied().find(reachable) };
        if let Some(addr) = addr {
            targets.push(Target { relay_pk: relay.pub_key, addr });
        }
    }
    (targets, unknown)
}

/// The relay list as last fetched, for [`plan_targets`].
#[derive(Default)]
struct RelayDirectory {
    relays: Vec<KnownRelay>,
    fetched_at: Option<Instant>,
}

impl RelayDirectory {
    /// Fetch when a member's relay isn't known (at most every
    /// `RELAY_LIST_RETRY`), and refresh every `RELAY_LIST_MAX_AGE`.
    fn due(&self, unknown: bool, now: Instant) -> bool {
        match self.fetched_at {
            None => unknown,
            Some(t) => {
                let age = now.duration_since(t);
                (unknown && age >= RELAY_LIST_RETRY) || age >= RELAY_LIST_MAX_AGE
            }
        }
    }

    async fn refresh(&mut self, state: &CoreState, now: Instant) {
        self.fetched_at = Some(now);
        let Some(client) = state.coordinator.get() else { return };
        match tokio::time::timeout(RELAY_LIST_TIMEOUT, crate::relay::fetch_known_relays(client.http(), client.coord_url())).await {
            Ok(Ok(relays)) => self.relays = relays,
            Ok(Err(e)) => debug!("discovery: relay list unavailable: {}", e),
            Err(_) => debug!("discovery: relay list request timed out"),
        }
    }
}

/// What discovery needs to know about the room, per tick.
struct RoomCtx {
    room: Option<String>,
    device_id: String,
    /// Our relays with keys: the preferred one, and the room relay while it
    /// works (resolved).
    own: Vec<(String, [u8; 32])>,
    /// The room relay while it works.
    room_relay: Option<KnownRelay>,
    peer_relays: Vec<SocketAddr>,
}

async fn room_ctx(state: &CoreState) -> RoomCtx {
    let net = state.net.read().await;
    let mut peer_relays: Vec<SocketAddr> = net
        .room_peers
        .iter()
        // Names resolve through the relay cache (filled by the RTT loop).
        .filter_map(|id| crate::relay::cached_addr(net.relay_for_peer(id)?))
        .map(unmap_addr)
        .collect();
    peer_relays.sort_unstable();
    peer_relays.dedup();
    let room_relay = net.room_relay.as_ref().and_then(|r| {
        let addr = r.usable_addr()?.parse::<SocketAddr>().ok()?;
        Some(KnownRelay { addrs: vec![unmap_addr(addr)], pub_key: r.pub_key })
    });
    let mut own: Vec<(String, [u8; 32])> = net.relay_addr.clone().zip(net.relay_pub_key).into_iter().collect();
    own.extend(room_relay.as_ref().map(|r| (r.addrs[0].to_string(), r.pub_key)));
    RoomCtx {
        room: net.joined_rooms.keys().next().cloned(),
        device_id: net.local_device_id.clone(),
        own,
        room_relay,
        peer_relays,
    }
}

/// Every second: work out the relays discovery goes to (the route), and
/// send `0x0A` to each per its own [`RegisterSchedule`] — only while in a
/// room (the relay finds our key through the room's peer list).
async fn registration_loop(sock: Arc<UdpSocket>, state: Arc<CoreState>, secure: Arc<Mutex<SecureSession>>) {
    let mut ticker = tokio::time::interval(REGISTER_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut schedules: HashMap<[u8; 32], RegisterSchedule<(SocketAddr, String)>> = HashMap::new();
    let mut directory = RelayDirectory::default();
    let mut start = None;
    loop {
        // Scheduled tick time, so a slow relay-list fetch doesn't shift
        // the 1 s retry to the next tick.
        let tick = ticker.tick().await;
        let now_ms = tick.duration_since(*start.get_or_insert(tick)).as_millis() as u64;
        let RoomCtx { room, device_id, own, room_relay, peer_relays } = room_ctx(&state).await;
        let Some(room) = room.filter(|_| !device_id.is_empty()) else {
            schedules.clear();
            secure.lock().unwrap().route = None;
            state.sdisc_stats.set_relays(Vec::new());
            continue;
        };
        let mut own_targets = Vec::with_capacity(own.len());
        for (addr, relay_pk) in own {
            if let Some(a) = crate::relay::resolve_addr(&addr).await {
                own_targets.push(Target { relay_pk, addr: unmap_addr(a) });
            }
        }
        let known = |dir: &RelayDirectory| -> Vec<KnownRelay> { dir.relays.iter().cloned().chain(room_relay.clone()).collect() };
        let v6_ok = crate::ip::ipv6_available();
        let (mut targets, unknown) = plan_targets(own_targets.clone(), &peer_relays, &known(&directory), v6_ok);
        let now = Instant::now();
        if directory.due(unknown, now) {
            directory.refresh(&state, now).await;
            targets = plan_targets(own_targets, &peer_relays, &known(&directory), v6_ok).0;
        }
        let mut usable = Vec::with_capacity(targets.len());
        for t in targets {
            if ensure_keys(&state, &secure, &t.relay_pk, &device_id).await {
                usable.push(t);
            }
        }
        state.sdisc_stats.set_relays(usable.iter().map(|t| t.addr.to_string()).collect());
        schedules.retain(|pk, _| usable.iter().any(|t| &t.relay_pk == pk));

        let mut packets = Vec::new();
        {
            let mut s = secure.lock().unwrap();
            for t in &usable {
                if let Some(b) = s.bound.get_mut(&t.relay_pk) {
                    b.addr = Some(t.addr);
                }
                if !schedules.entry(t.relay_pk).or_default().poll(Some((t.addr, room.clone())), now_ms) {
                    continue;
                }
                let counter = s.next_counter();
                let Some(bound) = s.current(&t.relay_pk, &device_id) else { continue };
                let Some(pkt) = sdisc::build_client_packet(&bound.keys, bound.own_id, counter, &room, None) else { continue };
                state.sdisc_stats.tx_register.fetch_add(1, Ordering::Relaxed);
                packets.push((t.addr, pkt));
            }
            s.route = (!usable.is_empty()).then(|| Route { room: room.clone(), device_id: device_id.clone(), targets: usable });
        }
        for (addr, pkt) in packets {
            if let Err(e) = sock.send_to(&pkt, map_send_addr(addr)).await {
                debug!("discovery: register send to {} failed: {}", addr, e);
            }
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
        if !is_own_physical_broadcast(&pkt, &local_ips) {
            continue;
        }
        if disc_tx.send(pkt).await.is_err() {
            break;
        }
    }
}

/// A packet from another MSST-Net address than ours: another member's
/// broadcast the OS sent back out of the TUN (e.g. Linux with broadcast
/// forwarding on).  Never sent to the room again — that would loop.
fn is_foreign_member_packet(pkt: &[u8], own: Option<Ipv4Addr>) -> bool {
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    src.octets()[..2] == [172, 22] && Some(src) != own
}

/// A broadcast this machine sent on a physical LAN (`physical_bcast_loop`).
/// The raw socket also sees broadcasts injected into the TUN; they are
/// never ours (rebuilt from the room member's address,
/// `rebuild_from_sender`), so a room member's broadcast can't be forwarded
/// back to the room.
fn is_own_physical_broadcast(pkt: &[u8], local_ips: &std::collections::HashSet<Ipv4Addr>) -> bool {
    needs_msst_rewrite(pkt) && local_ips.contains(&Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

/// IPv4/UDP subnet broadcast outside MSST-Net space (needs rewriting).
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
    fn physical_broadcast_rewrite() {
        let mut p = udp_to(Ipv4Addr::new(192, 168, 1, 255));
        assert!(needs_msst_rewrite(&p));
        rewrite_for_msst_broadcast(&mut p, Ipv4Addr::new(172, 22, 144, 209));
        let u = ippkt::udp_parts(&p).unwrap();
        assert_eq!((u.src, u.dst), (IpAddr::V4(Ipv4Addr::new(172, 22, 144, 209)), IpAddr::V4(MSST_BROADCAST)));
        assert!(ippkt::checksums_valid(&p));
        assert!(!needs_msst_rewrite(&p), "already in MSST-Net space");
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

    const DEV: &str = "device-a1b2c3d4";

    fn relay_pk(seed: u8) -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from([seed; 32])).as_bytes()
    }

    fn relay_addr(n: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, n], 7000))
    }

    /// Session as both sides of the spec vectors see it — device key 1×32,
    /// device-a1b2c3d4 — bound to the relays with private keys `seeds`
    /// (2×32 is the spec relay), relay `seed` at 10.0.0.`seed`.  Returns
    /// each relay's keys.
    fn session(seeds: &[u8]) -> (SecureSession, Vec<SdiscKeys>) {
        let mut s = SecureSession::default();
        let mut all = Vec::new();
        for &seed in seeds {
            let keys = sdisc::derive_keys(&[1u8; 32], 0xa1b2c3d4, &relay_pk(seed)).unwrap();
            s.bind(relay_pk(seed), Bound { device_id: DEV.into(), own_id: 0xa1b2c3d4, keys: keys.clone(), addr: Some(relay_addr(seed)), rx_last: 0 });
            all.push(keys);
        }
        (s, all)
    }

    fn deliver(keys: &SdiscKeys, sender: u64, flags: u8, counter: u64, ip: &[u8]) -> Vec<u8> {
        sdisc::seal_deliver(keys, sender, 0xa1b2c3d4, flags, counter, ip)
    }

    #[test]
    fn secure_rx_accepts_verified_and_counts() {
        let (mut s, keys) = session(&[2]);
        let keys = &keys[0];
        let stats = SdiscStats::default();
        let now_ms = 1_760_000_000_000u64;
        let t = Instant::now();
        let src = relay_addr(2);
        let mc = udp_to(Ipv4Addr::new(224, 0, 2, 60));

        let p1 = deliver(keys, 7, sdisc::FLAG_SENDER_VERIFIED, now_ms << 16, &mc);
        assert_eq!(s.accept(DEV, src, &stats, &p1, now_ms, t).unwrap(), (7, mc.clone()));
        // Replayed → dropped; replay state unchanged by it.
        assert_eq!(s.accept(DEV, src, &stats, &p1, now_ms, t), Err(Some(DropReason::Replay)));
        // Original sender not authenticated by the relay: dropped, counted.
        let p2 = deliver(keys, 8, 0, (now_ms << 16) + 1, &mc);
        assert_eq!(s.accept(DEV, src, &stats, &p2, now_ms, t), Err(None));
        // Verified frame carrying unicast: refused (no ACL bypass).
        let p3 = deliver(keys, 7, sdisc::FLAG_SENDER_VERIFIED, (now_ms << 16) + 2, &udp_to(Ipv4Addr::new(172, 22, 0, 1)));
        assert_eq!(s.accept(DEV, src, &stats, &p3, now_ms, t), Err(None));
        // Bare IPv4 is not accepted.
        assert_eq!(s.accept(DEV, src, &stats, &mc, now_ms, t), Err(Some(DropReason::NotDeliver)));
        // Keys of a relay we aren't bound to: bad tag.
        let stranger = sdisc::derive_keys(&[1u8; 32], 0xa1b2c3d4, &relay_pk(9)).unwrap();
        let p4 = deliver(&stranger, 7, sdisc::FLAG_SENDER_VERIFIED, (now_ms << 16) + 3, &mc);
        assert_eq!(s.accept(DEV, src, &stats, &p4, now_ms, t), Err(Some(DropReason::BadTag)));
        // Bound for another device ID (identity changed): nothing to verify with.
        assert_eq!(s.accept("device-00000001", src, &stats, &p1, now_ms, t), Err(None));

        let snap = stats.snapshot();
        assert_eq!(snap["rx_accepted"], 0, "counted when injected (rebuild_from_sender)");
        assert_eq!(snap["drop"]["unverified_sender"], 1);
        assert_eq!(snap["drop"]["replay"], 1);
        assert_eq!(snap["drop"]["not_discovery"], 1);
        assert_eq!(snap["drop"]["not_deliver"], 1);
        assert_eq!(snap["drop"]["bad_tag"], 1);
    }

    #[test]
    fn discovery_is_udp_broadcast_or_known_multicast() {
        let to = |dst: [u8; 4], port: u16| ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(172, 22, 0, 9)), 50000, IpAddr::V4(dst.into()), port, b"x");
        // Broadcasts on any port (games choose their own), the multicast
        // groups on their protocol's port.
        for (dst, port) in [([224, 0, 2, 60], 4445), ([172, 22, 255, 255], 19132), ([255, 255, 255, 255], 19133),
                            ([172, 22, 255, 255], 47624), ([224, 0, 0, 251], 5353)] {
            let p = to(dst, port);
            let d = discovery_datagram(&p).unwrap_or_else(|| panic!("{:?}:{}", dst, port));
            assert_eq!((d.dst, d.src_port, d.dst_port, d.payload), (Ipv4Addr::from(dst), 50000, port, &b"x"[..]));
        }
        // Multicast on another port or group, other networks' broadcast
        // addresses (unicast elsewhere), unicast.
        for (dst, port) in [([224, 0, 2, 60], 5353), ([224, 0, 0, 1], 4445), ([192, 168, 1, 255], 19132),
                            ([172, 22, 1, 255], 19132), ([172, 22, 0, 1], 19132)] {
            assert!(discovery_datagram(&to(dst, port)).is_none(), "{:?}:{}", dst, port);
        }
        let ok = to([224, 0, 2, 60], 4445);
        let mut tcp = ok.clone();
        tcp[9] = 6;
        let mut fragment = ok.clone();
        fragment[6] = 0x20; // MF
        let mut options = ok.clone();
        options[0] = 0x46;
        let mut long_udp = ok.clone();
        long_udp[25] += 1;
        for bad in [tcp, fragment, options, long_udp, ok[..27].to_vec()] {
            assert!(discovery_datagram(&bad).is_none());
        }
    }

    #[test]
    fn injected_packets_come_from_the_room_member_itself() {
        let mut net = crate::state::NetState::new();
        net.peer_list.upsert("device-00000007", "172.22.0.7".parse().unwrap(), "fd22:2222:2222:2222::7".parse().unwrap(),
            None, None, None, None, None, None, false, 0);
        // Claims another source (spoofing another member or a LAN host).
        let p = ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4445, IpAddr::V4(Ipv4Addr::new(224, 0, 2, 60)), 4445, b"[MOTD]x[/MOTD]");
        assert_eq!(rebuild_from_sender(&net, 7, &p), None, "not in our room");
        net.room_peers.insert("device-00000007".into());
        let out = rebuild_from_sender(&net, 7, &p).unwrap();
        let u = ippkt::udp_parts(&out).unwrap();
        assert_eq!((u.src, u.src_port, u.dst_port, u.payload), ("172.22.0.7".parse().unwrap(), 4445, 4445, &b"[MOTD]x[/MOTD]"[..]));
        assert!(ippkt::checksums_valid(&out));
        // Unknown sender, or a non-discovery packet: nothing.
        assert_eq!(rebuild_from_sender(&net, 8, &p), None);
        let unicast = ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(172, 22, 0, 7)), 1, IpAddr::V4(Ipv4Addr::new(172, 22, 0, 1)), 22, b"x");
        assert_eq!(rebuild_from_sender(&net, 7, &unicast), None);
    }

    #[test]
    fn injected_broadcasts_are_not_captured_again() {
        // This machine: LAN 192.168.1.5, MSST-Net 172.22.0.1.
        let local: std::collections::HashSet<Ipv4Addr> = [Ipv4Addr::new(192, 168, 1, 5), Ipv4Addr::new(172, 22, 0, 1)].into();
        let ours = ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 4000, IpAddr::V4(Ipv4Addr::BROADCAST), 4000, b"x");
        assert!(is_own_physical_broadcast(&ours, &local));
        // A member's broadcast claiming our LAN address, as injected: rebuilt
        // from the member's address, so the capture ignores it (before, it
        // went back to the room — a loop).
        let mut net = crate::state::NetState::new();
        net.peer_list.upsert("device-00000007", "172.22.0.7".parse().unwrap(), "fd22:2222:2222:2222::7".parse().unwrap(),
            None, None, None, None, None, None, false, 0);
        net.room_peers.insert("device-00000007".into());
        let injected = rebuild_from_sender(&net, 7, &ours).unwrap();
        assert!(!is_own_physical_broadcast(&injected, &local));
        // MSST-Net's own broadcast address is never captured.
        let msst = ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(172, 22, 0, 1)), 4000, IpAddr::V4(MSST_BROADCAST), 4000, b"x");
        assert!(!is_own_physical_broadcast(&msst, &local));
    }

    #[test]
    fn each_sender_is_rate_limited_on_receive() {
        let (mut s, keys) = session(&[2]);
        let stats = SdiscStats::default();
        let now_ms = 1_760_000_000_000u64;
        let t = Instant::now();
        // Distinct packets (so not duplicates) from one sender.
        let pkt = |sender: u64, c: u64| {
            let ip = ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(172, 22, 0, 7)), c as u16, IpAddr::V4(MSST_BROADCAST), 4000, b"x");
            deliver(&keys[0], sender, sdisc::FLAG_SENDER_VERIFIED, (now_ms << 16) + c, &ip)
        };
        for c in 0..RATE_LIMIT as u64 {
            assert!(s.accept(DEV, relay_addr(2), &stats, &pkt(7, c), now_ms, t).is_ok());
        }
        assert_eq!(s.accept(DEV, relay_addr(2), &stats, &pkt(7, 100), now_ms, t), Err(None));
        assert_eq!(stats.snapshot()["drop"]["rate_limited"], 1);
        // Another sender has its own budget; the window frees the first.
        assert!(s.accept(DEV, relay_addr(2), &stats, &pkt(8, 101), now_ms, t).is_ok());
        assert!(s.accept(DEV, relay_addr(2), &stats, &pkt(7, 102), now_ms, t + RATE_WINDOW).is_ok());
    }

    #[test]
    fn all_senders_together_are_rate_limited_on_receive() {
        let (mut s, keys) = session(&[2]);
        let stats = SdiscStats::default();
        let now_ms = 1_760_000_000_000u64;
        let t = Instant::now();
        let pkt = |sender: u64, c: u64| {
            let ip = ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(172, 22, 0, 7)), c as u16, IpAddr::V4(MSST_BROADCAST), 4000, b"x");
            deliver(&keys[0], sender, sdisc::FLAG_SENDER_VERIFIED, (now_ms << 16) + c, &ip)
        };
        // A flooding sender's excess doesn't count against the others.
        for c in 0..1000 {
            let _ = s.accept(DEV, relay_addr(2), &stats, &pkt(1, c), now_ms, t);
        }
        assert_eq!(stats.snapshot()["drop"]["rate_limited"], 1000 - RATE_LIMIT as u64);
        // Many senders (each within its own limit) share the global budget.
        let mut accepted = RATE_LIMIT;
        let mut c = 1000;
        for sender in 2..200u64 {
            for _ in 0..2 {
                c += 1;
                accepted += s.accept(DEV, relay_addr(2), &stats, &pkt(sender, c), now_ms, t).is_ok() as usize;
            }
        }
        assert_eq!(accepted, RX_GLOBAL_RATE_LIMIT);
        // The next window has a fresh budget.
        assert!(s.accept(DEV, relay_addr(2), &stats, &pkt(500, c + 1), now_ms, t + RATE_WINDOW).is_ok());
    }

    #[test]
    fn another_members_packet_is_never_sent_again() {
        let own = Some(Ipv4Addr::new(172, 22, 0, 1));
        let bcast = |src: [u8; 4]| ippkt::build_udp(IpAddr::V4(src.into()), 4000, IpAddr::V4(MSST_BROADCAST), 4000, b"x");
        assert!(!is_foreign_member_packet(&bcast([172, 22, 0, 1]), own));
        // Injected from member 172.22.0.7, bounced back out of the TUN.
        assert!(is_foreign_member_packet(&bcast([172, 22, 0, 7]), own));
        // A local app bound to another address (the receivers rebuild the
        // source anyway).
        assert!(!is_foreign_member_packet(&bcast([192, 168, 1, 5]), own));
    }

    #[test]
    fn packet_through_two_relays_is_injected_once() {
        let (mut s, keys) = session(&[2, 3]);
        let stats = SdiscStats::default();
        let now_ms = 1_760_000_000_000u64;
        let t = Instant::now();
        let mc = udp_to(Ipv4Addr::new(224, 0, 2, 60));
        let via = |k: usize, c: u64| deliver(&keys[k], 7, sdisc::FLAG_SENDER_VERIFIED, (now_ms << 16) + c, &mc);

        // Each relay's packet verifies, whichever address it came from.
        assert_eq!(s.accept(DEV, relay_addr(3), &stats, &via(1, 0), now_ms, t).unwrap().1, mc);
        assert_eq!(s.accept(DEV, relay_addr(3), &stats, &via(0, 0), now_ms, t), Err(None), "copy via the other relay");
        assert_eq!(stats.snapshot()["drop"]["duplicate"], 1);
        // Separate replay state per relay.
        assert_eq!(s.accept(DEV, relay_addr(2), &stats, &via(0, 0), now_ms, t), Err(Some(DropReason::Replay)));
        // The game's next broadcast (after the window) gets through.
        let later = t + RX_DEDUP_TTL;
        assert_eq!(s.accept(DEV, relay_addr(2), &stats, &via(0, 1), now_ms, later).unwrap().1, mc);
        // Another sender's identical payload is not a duplicate.
        let other = deliver(&keys[0], 8, sdisc::FLAG_SENDER_VERIFIED, (now_ms << 16) + 2, &mc);
        assert_eq!(s.accept(DEV, relay_addr(2), &stats, &other, now_ms, later).unwrap(), (8, mc));
        assert_eq!(stats.snapshot()["drop"]["bad_tag"], 0, "trying the other relay's key is not a drop");
    }

    #[test]
    fn secure_session_rebinds_on_relay_or_device_change() {
        let (mut s, _) = session(&[2]);
        assert!(s.current(&relay_pk(2), DEV).is_some());
        assert!(s.current(&relay_pk(9), DEV).is_none());
        assert!(s.current(&relay_pk(2), "device-00000001").is_none());
        let a = s.next_counter();
        assert!(s.next_counter() > a);
        // Bounded.
        for seed in 10..10 + MAX_BOUND_RELAYS as u8 {
            s.bind([seed; 32], Bound { device_id: DEV.into(), own_id: 1, keys: sdisc::derive_keys(&[1u8; 32], 1, &relay_pk(2)).unwrap(), addr: None, rx_last: 0 });
        }
        assert!(s.bound.len() <= MAX_BOUND_RELAYS);
    }

    #[test]
    fn discovery_goes_to_every_relay_room_members_use() {
        let v6 = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 3], 7000));
        let known = vec![
            KnownRelay { addrs: vec![relay_addr(2)], pub_key: relay_pk(2) },
            KnownRelay { addrs: vec![relay_addr(3), v6], pub_key: relay_pk(3) },
        ];
        let own = vec![Target { relay_pk: relay_pk(2), addr: relay_addr(2) }];
        let t = |seed: u8, addr| Target { relay_pk: relay_pk(seed), addr };

        // Alone in the room, or every member on our relay: ours only.
        assert_eq!(plan_targets(own.clone(), &[], &known, true), (vec![t(2, relay_addr(2))], false));
        assert_eq!(plan_targets(own.clone(), &[relay_addr(2)], &known, true).0, [t(2, relay_addr(2))]);
        // A member on the other relay, reported by its IPv6 address: added
        // once, at an address we can reach.
        assert_eq!(plan_targets(own.clone(), &[v6, relay_addr(3)], &known, true).0, [t(2, relay_addr(2)), t(3, v6)]);
        assert_eq!(plan_targets(own.clone(), &[v6], &known, false).0, [t(2, relay_addr(2)), t(3, relay_addr(3))]);
        // A relay the list doesn't know (or lists without a key): reported.
        assert_eq!(plan_targets(own.clone(), &[relay_addr(4)], &known, true), (vec![t(2, relay_addr(2))], true));
        // Our relay has no key: still reach members on keyed relays.
        assert_eq!(plan_targets(Vec::new(), &[relay_addr(3)], &known, true).0, [t(3, relay_addr(3))]);
        // Our relay and the room relay (5), which every member reports to
        // use, except one that fell back to relay 3.
        let room = KnownRelay { addrs: vec![relay_addr(5)], pub_key: relay_pk(5) };
        let known_room: Vec<KnownRelay> = known.iter().cloned().chain([room]).collect();
        let own_room = vec![t(2, relay_addr(2)), t(5, relay_addr(5)), t(2, relay_addr(2))];
        assert_eq!(
            plan_targets(own_room, &[relay_addr(5), relay_addr(3)], &known_room, true),
            (vec![t(2, relay_addr(2)), t(5, relay_addr(5)), t(3, relay_addr(3))], false)
        );
    }

    #[test]
    fn relay_list_is_fetched_when_needed_and_refreshed() {
        let mut d = RelayDirectory::default();
        let t = Instant::now();
        assert!(!d.due(false, t));
        assert!(d.due(true, t));
        d.fetched_at = Some(t);
        assert!(!d.due(true, t + RELAY_LIST_RETRY - Duration::from_secs(1)));
        assert!(d.due(true, t + RELAY_LIST_RETRY));
        assert!(!d.due(false, t + RELAY_LIST_RETRY));
        assert!(d.due(false, t + RELAY_LIST_MAX_AGE));
    }

    /// Datagrams a fake relay receives within `window`.
    async fn collect(relay: &UdpSocket, window: Duration) -> Vec<Vec<u8>> {
        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        let end = tokio::time::Instant::now() + window;
        while let Ok(Ok((n, _))) = tokio::time::timeout_at(end, relay.recv_from(&mut buf)).await {
            got.push(buf[..n].to_vec());
        }
        got
    }

    /// The real loops: we are on relay 2, a room member on relay 3 (known
    /// only through `GET /relays`); registration and data go to both.
    #[tokio::test]
    async fn loops_reach_room_members_on_another_relay() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let (r2, r3) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (a2, a3) = (r2.local_addr().unwrap(), r3.local_addr().unwrap());
        let relays = serde_json::json!({ "relays": [
            { "addr": a2.to_string(), "pub_key": STANDARD.encode(relay_pk(2)) },
            { "addr": a3.to_string(), "pub_key": STANDARD.encode(relay_pk(3)) },
        ] });
        let coord = crate::test_support::FakeCoordinator::start(
            move |req| if req.path == "/relays" { (200, relays.clone()) } else { (404, serde_json::json!({})) },
            |_| vec![],
        ).await;
        let (state, _ipc) = crate::test_support::core_state("disc-relays").await;
        let (ev_tx, _ev_rx) = mpsc::channel(4);
        let client = crate::coordinator::CoordinatorClient::new(crate::coordinator::CoordinatorConfig { coord_url: coord.url.clone() }, ev_tx);
        let _ = state.coordinator.set(Arc::new(client));
        let endpoints = [format!("relay:{}", a3)];
        assert!(crate::nodes::apply_peer(&state, crate::nodes::PeerData {
            device_id: "device-0000000b", ipv4: "172.22.1.1", ipv6: "fd22:2222:2222:2222::b", endpoints: &endpoints, ..Default::default()
        }).await);
        {
            let mut net = state.net.write().await;
            net.joined_rooms.insert("space-1".into(), "Room".into());
            net.room_peers.insert("device-0000000b".into());
            net.relay_addr = Some(a2.to_string());
            net.relay_pub_key = Some(relay_pk(2));
        }

        let sock = Arc::new(crate::make_udp_socket(0).unwrap());
        let secure = Arc::new(Mutex::new(SecureSession::default()));
        let (tx, rx) = mpsc::channel(4);
        let tasks = [
            tokio::spawn(registration_loop(sock.clone(), state.clone(), secure.clone())),
            tokio::spawn(tx_loop(rx, sock, state.clone(), secure)),
        ];
        let own_id = sdisc::wire_id("device-00000001");
        let keys = |seed| sdisc::derive_keys(&[1u8; 32], own_id, &relay_pk(seed)).unwrap();
        let counter = |p: &[u8]| u64::from_be_bytes(p[23..31].try_into().unwrap());

        // Registration: immediately and about 1 s later, at each relay,
        // under that relay's key.
        let (got2, got3) = tokio::join!(collect(&r2, Duration::from_millis(1600)), collect(&r3, Duration::from_millis(1600)));
        for (seed, got) in [(2, &got2), (3, &got3)] {
            assert_eq!(got.len(), 2, "relay {}: {:?}", seed, got);
            for p in got {
                assert_eq!(*p, sdisc::build_client_packet(&keys(seed), own_id, counter(p), "space-1", None).unwrap());
            }
        }
        let mut relays_used = state.sdisc_stats.snapshot()["relays"].as_array().unwrap().clone();
        relays_used.sort_by_key(|v| v.to_string());
        let mut expected = vec![serde_json::json!(a2.to_string()), serde_json::json!(a3.to_string())];
        expected.sort_by_key(|v| v.to_string());
        assert_eq!(relays_used, expected);

        // A game's broadcast goes to both relays.
        let mc = ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(172, 22, 0, 1)), 4445, IpAddr::V4(Ipv4Addr::new(224, 0, 2, 60)), 4445, b"[MOTD]x[/MOTD]");
        tx.send(mc.clone()).await.unwrap();
        let (got2, got3) = tokio::join!(collect(&r2, Duration::from_millis(300)), collect(&r3, Duration::from_millis(300)));
        for (seed, got) in [(2, &got2), (3, &got3)] {
            assert_eq!(got.len(), 1, "relay {}: {:?}", seed, got);
            assert_eq!(got[0], sdisc::build_client_packet(&keys(seed), own_id, counter(&got[0]), "space-1", Some(&mc)).unwrap());
        }

        // Leaving the room stops everything.
        state.net.write().await.joined_rooms.clear();
        tokio::time::sleep(REGISTER_TICK + Duration::from_millis(200)).await;
        assert_eq!(state.sdisc_stats.snapshot()["relays"], serde_json::json!([]));
        tx.send(mc).await.unwrap();
        assert!(collect(&r3, Duration::from_millis(300)).await.is_empty());
        for t in tasks {
            t.abort();
        }
    }

    /// With a working room relay, discovery registers with it as well as
    /// our relay, and reaches members through the relay their traffic
    /// uses: the room relay if they report it, else their own.
    #[tokio::test]
    async fn room_relay_is_one_of_our_relays() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let (state, _ipc) = crate::test_support::core_state("disc-room-relay").await;
        let room = crate::coordinator::messages::RoomStateRelay {
            address: relay_addr(5).to_string(),
            pub_key: STANDARD.encode(relay_pk(5)),
            features: vec!["sdisc1".into(), "sreg1".into()],
            self_hosted: true,
        };
        let on_room = [format!("relay:{}", relay_addr(3)), format!("room-relay:{}", relay_addr(5))];
        let fell_back = [format!("relay:{}", relay_addr(4))];
        for (dev, v4, v6, eps) in [("device-0000000b", "172.22.1.1", "fd22:2222:2222:2222::b", &on_room[..]), ("device-0000000c", "172.22.1.2", "fd22:2222:2222:2222::c", &fell_back[..])] {
            assert!(crate::nodes::apply_peer(&state, crate::nodes::PeerData { device_id: dev, ipv4: v4, ipv6: v6, endpoints: eps, ..Default::default() }).await);
        }
        {
            let mut net = state.net.write().await;
            net.joined_rooms.insert("space-1".into(), "Room".into());
            net.room_peers.extend(["device-0000000b".to_string(), "device-0000000c".to_string()]);
            net.relay_addr = Some(relay_addr(2).to_string());
            net.relay_pub_key = Some(relay_pk(2));
            net.room_relay = Some(crate::room_relay::RoomRelay::from_room_state("space-1", &room).unwrap());
        }
        let ctx = room_ctx(&state).await;
        // Not working yet: our relay only; members by their preferred relays.
        assert_eq!(ctx.own, [(relay_addr(2).to_string(), relay_pk(2))]);
        assert_eq!(ctx.peer_relays, [relay_addr(3), relay_addr(4)]);

        state.net.write().await.room_relay.as_mut().unwrap().health.reply(Instant::now());
        let ctx = room_ctx(&state).await;
        assert_eq!(ctx.own, [(relay_addr(2).to_string(), relay_pk(2)), (relay_addr(5).to_string(), relay_pk(5))]);
        assert_eq!(ctx.peer_relays, [relay_addr(4), relay_addr(5)], "b through the room relay, c (fell back) through its own");
        assert_eq!(ctx.room_relay, Some(KnownRelay { addrs: vec![relay_addr(5)], pub_key: relay_pk(5) }));
    }
}
