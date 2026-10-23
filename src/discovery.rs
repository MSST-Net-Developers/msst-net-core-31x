//! Game discovery — LAN broadcasts between room members, end to end over
//! WireGuard.
//!
//! Carries IPv4 broadcasts and the discovery multicasts (Minecraft Java LAN
//! 224.0.2.60, mDNS 224.0.0.251) between members of a room so LAN game
//! discovery works over the virtual network.
//!
//! Each discovery datagram is sent to every room member separately, inside
//! its WireGuard session (a [`Message`]: IPv4 protocol 253 from our virtual
//! address to the member's, magic `MSDM`), over the member's current path.
//! The sender is authenticated end to end; relays only forward ciphertext.
//! (Until 3.1.5, discovery went through the relays as sdisc `0x0B`/`0x0C`,
//! where the sender was only the relay's claim — a room relay run by the
//! room's creator could impersonate any member.  It is retired, and never
//! used as a fallback: see `docs/SECURITY_3.1.6.md`.)
//!
//! - **Capability**: we announce [`FEATURE_ENDPOINT`] in our endpoint list
//!   when discovery runs here ([`enabled`]; the embedded Android Core has
//!   none, as in 3.0.x).
//!   Members whose announced endpoints lack it can't take part: they get
//!   nothing and are shown as `discovery: "unsupported"` in the room view
//!   (`NetState::discovery_support`).
//! - **Outbound** (only while in a room): discovery datagrams read from the
//!   TUN — and, on Unix desktops, broadcasts this machine sends on its
//!   physical LAN (rewritten into MSST-Net space) — are held to
//!   [`discovery_datagram`], de-duplicated, rate-limited (10/s) and sent to
//!   each supporting member.
//! - **Inbound** ([`on_tunnel_message`]): only from a member of our room;
//!   the datagram is rebuilt with the member's own virtual address as its
//!   source, must pass [`discovery_datagram`], and is rate-limited per
//!   sender (10/s) and in total (100/s); then it is injected into the TUN
//!   without ACL evaluation.  This is the discovery permission: room
//!   membership and these rules, separate from the inbound ACL.
//!
//! Counters: [`DiscoveryStats`] (`GetRelays.discovery`).  A discovered
//! service is still subject to the inbound ACL when connected to.

use crate::ippkt;
use crate::state::CoreState;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Announced in our endpoint list: we send and accept discovery over
/// WireGuard ([`Message`]).
pub const FEATURE_ENDPOINT: &str = "feature:wgdisc1";
/// Multicast groups carried, each with its protocol's UDP port: Minecraft
/// Java Edition LAN worlds and mDNS.
const DISCOVERY_MULTICAST: &[(Ipv4Addr, u16)] = &[(Ipv4Addr::new(224, 0, 2, 60), 4445), (Ipv4Addr::new(224, 0, 0, 251), 5353)];
/// Outbound de-duplication window.
const DEDUP_TTL: Duration = Duration::from_secs(3);
const RATE_WINDOW: Duration = Duration::from_secs(1);
/// Discovery datagrams per sender per [`RATE_WINDOW`], sent and received.
const RATE_LIMIT: usize = 10;
/// Discovery datagrams injected per [`RATE_WINDOW`] from all senders
/// together: room size is unlimited, so this bounds what reaches the TUN
/// however many members send.  Games announce about once a second; this
/// leaves room for ~50 members announcing twice a second.
const RX_GLOBAL_RATE_LIMIT: usize = 100;
/// Largest UDP payload carried (a message must fit a WireGuard packet).
const MAX_PAYLOAD: usize = 1200;
/// Broadcast address in MSST-Net space.
const MSST_BROADCAST: Ipv4Addr = Ipv4Addr::new(172, 22, 255, 255);

// ---------------------------------------------------------------------------
// Discovery datagrams
// ---------------------------------------------------------------------------

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
/// (172.22.255.255, or 255.255.255.255) on any port — games pick their own
/// — or to one of [`DISCOVERY_MULTICAST`] on its port.  Subnet broadcasts of
/// other networks are never carried: in this host's networks they may be
/// unicast addresses.
fn discovery_datagram(pkt: &[u8]) -> Option<DiscoveryDatagram<'_>> {
    if pkt.len() < 28 || pkt[0] != 0x45 || pkt[9] != 17 {
        return None;
    }
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let fragment = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff; // MF + offset
    let udp_len = u16::from_be_bytes([pkt[24], pkt[25]]) as usize;
    if total < 28 || total > pkt.len() || fragment != 0 || udp_len < 8 || 20 + udp_len > total || udp_len - 8 > MAX_PAYLOAD {
        return None;
    }
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let dst_port = u16::from_be_bytes([pkt[22], pkt[23]]);
    if dst != MSST_BROADCAST && dst != Ipv4Addr::BROADCAST && !DISCOVERY_MULTICAST.contains(&(dst, dst_port)) {
        return None;
    }
    Some(DiscoveryDatagram { dst, src_port: u16::from_be_bytes([pkt[20], pkt[21]]), dst_port, payload: &pkt[28..20 + udp_len] })
}

/// Whether an IPv4 destination is handled by the discovery proxy.
pub fn is_discovery_target(dst: Ipv4Addr) -> bool {
    dst == Ipv4Addr::BROADCAST || dst.octets()[3] == 255 || DISCOVERY_MULTICAST.iter().any(|&(a, _)| a == dst)
}

/// Whether `data` is an IPv4 packet to a discovery target.
pub fn is_ipv4_discovery_packet(data: &[u8]) -> bool {
    data.len() >= 20 && data[0] >> 4 == 4 && is_discovery_target(Ipv4Addr::new(data[16], data[17], data[18], data[19]))
}

// ---------------------------------------------------------------------------
// The in-tunnel message
// ---------------------------------------------------------------------------

const MAGIC: &[u8; 4] = b"MSDM";
const VERSION: u8 = 1;
const IP_HEADER_LEN: usize = 20;
/// magic ‖ version ‖ 0 ‖ dst (4) ‖ src port ‖ dst port
const MESSAGE_HEADER_LEN: usize = 14;

/// A discovery datagram as carried inside a member's WireGuard session:
///
/// ```text
/// IPv4 (protocol 253, from the sender's virtual IPv4 to the recipient's)
/// payload = "MSDM" ‖ version 1 ‖ 0 ‖ dst (4) ‖ src port (2) ‖ dst port (2) ‖ UDP payload
/// ```
///
/// Addressed to the recipient, so it passes the inbound "to us" check like
/// any peer packet.  The relay-path probe shares the protocol number
/// (`crate::tunnel_probe`, magic `MSRP`).  Cores before 3.1.6 drop it as an
/// IP protocol without ACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn encode(&self, src: Ipv4Addr, recipient: Ipv4Addr) -> Vec<u8> {
        let total = (IP_HEADER_LEN + MESSAGE_HEADER_LEN + self.payload.len()) as u16;
        let mut p = Vec::with_capacity(total as usize);
        p.extend_from_slice(&[0x45, 0]);
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0x40, 0, 64, crate::tunnel_probe::PROTO, 0, 0]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&recipient.octets());
        let csum = ippkt::csum_fold(ippkt::csum_add(0, &p));
        p[10..12].copy_from_slice(&csum.to_be_bytes());
        p.extend_from_slice(MAGIC);
        p.extend_from_slice(&[VERSION, 0]);
        p.extend_from_slice(&self.dst.octets());
        p.extend_from_slice(&self.src_port.to_be_bytes());
        p.extend_from_slice(&self.dst_port.to_be_bytes());
        p.extend_from_slice(&self.payload);
        p
    }

    /// Decode; `None` for anything else (including other protocol 253
    /// traffic).
    pub fn decode(pkt: &[u8]) -> Option<Message> {
        if pkt.len() < IP_HEADER_LEN + MESSAGE_HEADER_LEN || pkt[0] != 0x45 || pkt[9] != crate::tunnel_probe::PROTO {
            return None;
        }
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if total < IP_HEADER_LEN + MESSAGE_HEADER_LEN || total > pkt.len() {
            return None;
        }
        let body = &pkt[IP_HEADER_LEN..total];
        if &body[..4] != MAGIC || body[4] != VERSION {
            return None;
        }
        Some(Message {
            dst: Ipv4Addr::new(body[6], body[7], body[8], body[9]),
            src_port: u16::from_be_bytes([body[10], body[11]]),
            dst_port: u16::from_be_bytes([body[12], body[13]]),
            payload: body[MESSAGE_HEADER_LEN..].to_vec(),
        })
    }

    fn of(d: &DiscoveryDatagram<'_>) -> Message {
        Message { dst: d.dst, src_port: d.src_port, dst_port: d.dst_port, payload: d.payload.to_vec() }
    }

    /// The datagram to inject: from `src` (the sender's virtual address),
    /// if it is a discovery datagram.
    fn rebuild(&self, src: Ipv4Addr) -> Option<Vec<u8>> {
        let pkt = ippkt::build_udp(IpAddr::V4(src), self.src_port, IpAddr::V4(self.dst), self.dst_port, &self.payload);
        discovery_datagram(&pkt).is_some().then_some(pkt)
    }
}

/// Whether a room member takes part in discovery over WireGuard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySupport {
    /// It announces [`FEATURE_ENDPOINT`].
    Supported,
    /// Its announced endpoints lack it (Core 3.1.5 or older): it gets no
    /// discovery, and can't send us any.
    Unsupported,
    /// No endpoints from it yet.
    Unknown,
}

impl DiscoverySupport {
    /// Whether an endpoint list announces support.
    pub fn of_endpoints(endpoints: &[String]) -> Self {
        if endpoints.iter().any(|e| e == FEATURE_ENDPOINT) { DiscoverySupport::Supported } else { DiscoverySupport::Unsupported }
    }

    /// Room view name (`discovery` of each member).
    pub fn name(self) -> &'static str {
        match self {
            DiscoverySupport::Supported => "ok",
            DiscoverySupport::Unsupported => "unsupported",
            DiscoverySupport::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Counters and limits
// ---------------------------------------------------------------------------

/// Discovery counters (atomics: read by `GetRelays` without locks).
#[derive(Debug, Default)]
pub struct DiscoveryStats {
    /// Messages sent (one per supporting member per datagram).
    pub tx_messages: AtomicU64,
    /// Datagrams not sent to a member that doesn't support discovery over
    /// WireGuard (announced endpoints without [`FEATURE_ENDPOINT`]).
    pub tx_skipped_unsupported: AtomicU64,
    /// Datagrams injected into the TUN.
    pub rx_accepted: AtomicU64,
    /// From a device that isn't a member of our room.
    pub drop_not_member: AtomicU64,
    /// Not a discovery datagram once rebuilt.
    pub drop_not_discovery: AtomicU64,
    /// Over the per-sender or the total rate limit.
    pub drop_rate_limited: AtomicU64,
}

impl DiscoveryStats {
    pub fn snapshot(&self) -> serde_json::Value {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        serde_json::json!({
            "transport": "wireguard",
            "tx_messages": g(&self.tx_messages),
            "tx_skipped_unsupported": g(&self.tx_skipped_unsupported),
            "rx_accepted": g(&self.rx_accepted),
            "drop": {
                "not_member": g(&self.drop_not_member),
                "not_discovery": g(&self.drop_not_discovery),
                "rate_limited": g(&self.drop_rate_limited),
            },
        })
    }
}

/// At most `limit` datagrams per [`RATE_WINDOW`] per key: [`RATE_LIMIT`]
/// per sender by default, [`RX_GLOBAL_RATE_LIMIT`] for [`GlobalRateLimit`].
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
    /// Whether a datagram from `key` now exceeds the limit (if not, it counts).
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

/// Receive-side limits, independent of the transport (`CoreState`).
#[derive(Default)]
pub struct RxLimits {
    per_sender: RateLimit<String>,
    global: GlobalRateLimit,
}

impl RxLimits {
    /// Per sender first, so a flooding sender's excess doesn't use up the
    /// global budget and starve the others.
    fn exceeded(&mut self, sender: &str, now: Instant) -> bool {
        self.per_sender.exceeded(&sender.to_string(), now) || self.global.0.exceeded(&(), now)
    }
}

// ---------------------------------------------------------------------------
// Inbound
// ---------------------------------------------------------------------------

/// Handle a packet decrypted from `device_id`'s session (already checked to
/// be from its address to ours) if it is a discovery [`Message`].  Returns
/// whether it was one; it is then consumed, injected or dropped.
pub async fn on_tunnel_message(state: &CoreState, tun_tx: &mpsc::Sender<Vec<u8>>, device_id: &str, pkt: &[u8]) -> bool {
    let Some(msg) = Message::decode(pkt) else { return false };
    // Discovery not running here (embedded Core): we don't announce it
    // either, so nothing should arrive.
    if !enabled(state) {
        return true;
    }
    let stats = &state.discovery_stats;
    // The discovery permission: members of our room only.
    let src = {
        let net = state.net.read().await;
        let member = !net.joined_rooms.is_empty() && net.room_peers.contains(device_id);
        match net.peer_list.get(device_id).map(|e| e.ipv4).filter(|_| member) {
            Some(IpAddr::V4(a)) => a,
            _ => {
                stats.drop_not_member.fetch_add(1, Ordering::Relaxed);
                debug!("discovery: dropped a message from {}: not a member of our room", device_id);
                return true;
            }
        }
    };
    let Some(datagram) = msg.rebuild(src) else {
        stats.drop_not_discovery.fetch_add(1, Ordering::Relaxed);
        return true;
    };
    if state.discovery_rx_limits.lock().unwrap_or_else(|e| e.into_inner()).exceeded(device_id, Instant::now()) {
        stats.drop_rate_limited.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    stats.rx_accepted.fetch_add(1, Ordering::Relaxed);
    let _ = tun_tx.send(datagram).await;
    true
}

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

/// Whether discovery runs on this Core ([`start`]; not on the embedded
/// Android Core).  Only then do we announce [`FEATURE_ENDPOINT`].
pub fn enabled(state: &CoreState) -> bool {
    state.discovery_tx.get().is_some()
}

/// Start the outbound side.  Returns the sender the outbound path feeds
/// (TUN discovery packets while in a room) and the task handles.  Inbound
/// messages arrive through the WireGuard path ([`on_tunnel_message`]).
pub async fn start(state: Arc<CoreState>) -> (mpsc::Sender<Vec<u8>>, Vec<tokio::task::JoinHandle<()>>) {
    let (disc_tx, disc_rx) = mpsc::channel::<Vec<u8>>(256);
    info!("discovery: LAN game discovery over WireGuard ({})", FEATURE_ENDPOINT);
    #[allow(unused_mut)] // only extended on Unix
    let mut handles = vec![tokio::spawn(tx_loop(disc_rx, state))];
    #[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
    handles.push(tokio::spawn(physical_bcast_loop(disc_tx.clone())));
    (disc_tx, handles)
}

/// De-duplication and our own rate limit.
#[derive(Default)]
struct TxState {
    dedup: HashMap<[u8; 16], Instant>,
    rate: RateLimit<()>,
}

impl TxState {
    fn is_duplicate(&mut self, pkt: &[u8], now: Instant) -> bool {
        let mut key = [0u8; 16];
        key.copy_from_slice(&Sha256::digest(pkt)[..16]);
        self.dedup.retain(|_, t| now.duration_since(*t) < DEDUP_TTL);
        self.dedup.insert(key, now).is_some()
    }

    fn is_rate_limited(&mut self, now: Instant) -> bool {
        self.rate.exceeded(&(), now)
    }
}

async fn tx_loop(mut rx: mpsc::Receiver<Vec<u8>>, state: Arc<CoreState>) {
    let mut st = TxState::default();
    while let Some(mut pkt) = rx.recv().await {
        let Some(vip) = vpn_ipv4(&state).await else { continue };
        if needs_msst_rewrite(&pkt) {
            rewrite_for_msst_broadcast(&mut pkt, vip);
        }
        if is_foreign_member_packet(&pkt, Some(vip)) {
            continue;
        }
        let Some(d) = discovery_datagram(&pkt) else { continue };
        let now = Instant::now();
        if st.is_duplicate(&pkt, now) || st.is_rate_limited(now) {
            continue;
        }
        let msg = Message::of(&d);
        // Each supporting member gets its own copy, end to end; the others
        // nothing (no fallback through the relays).
        for (member, ipv4, support) in state.net.read().await.discovery_members() {
            match support {
                DiscoverySupport::Supported => {
                    if crate::runtime::send_in_tunnel(&state, &member, &msg.encode(vip, ipv4)).await {
                        state.discovery_stats.tx_messages.fetch_add(1, Ordering::Relaxed);
                    }
                }
                DiscoverySupport::Unsupported => {
                    state.discovery_stats.tx_skipped_unsupported.fetch_add(1, Ordering::Relaxed);
                }
                DiscoverySupport::Unknown => {}
            }
        }
    }
}

/// How often the capture re-reads this machine's networks: they change
/// when it switches networks (Wi-Fi ↔ hotspot), and a stale view would
/// take its own broadcasts for another machine's.
#[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
const LOCAL_NETS_REFRESH: Duration = Duration::from_secs(2);

/// This machine's physical IPv4 networks: its addresses and the broadcast
/// addresses of their subnets (MSST-Net's own range left out).
#[cfg(any(test, all(unix, not(target_os = "android"), not(target_os = "ios"))))]
#[derive(Debug, Default, PartialEq)]
struct LocalNets {
    ips: std::collections::HashSet<Ipv4Addr>,
    broadcasts: std::collections::HashSet<Ipv4Addr>,
}

#[cfg(any(test, all(unix, not(target_os = "android"), not(target_os = "ios"))))]
impl LocalNets {
    #[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
    fn read() -> Self {
        Self::of(if_addrs::get_if_addrs().unwrap_or_default().into_iter().filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(a) => Some((a.ip, a.prefixlen, a.broadcast)),
            _ => None,
        }))
    }

    /// From (address, prefix length, broadcast address) per interface
    /// address; a missing broadcast address is derived from the prefix
    /// (none for /31 and /32).
    fn of(addrs: impl IntoIterator<Item = (Ipv4Addr, u8, Option<Ipv4Addr>)>) -> Self {
        let mut nets = LocalNets::default();
        for (ip, prefix, broadcast) in addrs {
            if ip.is_loopback() || is_msst(ip) {
                continue;
            }
            nets.ips.insert(ip);
            let derived = (prefix < 31).then(|| Ipv4Addr::from(u32::from(ip) | (u32::MAX >> prefix.min(32))));
            nets.broadcasts.extend(broadcast.or(derived).filter(|b| !is_msst(*b) && *b != ip));
        }
        nets
    }

    /// A UDP broadcast this machine sent on one of its physical networks:
    /// from one of its addresses, to 255.255.255.255 or a subnet's
    /// broadcast address (e.g. 172.20.10.15 on an iPhone hotspot's /28).
    /// The raw socket also sees broadcasts injected into the TUN; they are
    /// never ours (rebuilt from the room member's address, [`Message`]), so
    /// a room member's broadcast can't be forwarded back to the room.
    fn is_own_broadcast(&self, pkt: &[u8]) -> bool {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
            return false;
        }
        let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        self.ips.contains(&src) && (dst == Ipv4Addr::BROADCAST || self.broadcasts.contains(&dst))
    }
}

/// In MSST-Net's IPv4 range (172.22.0.0/16).
#[cfg(any(test, all(unix, not(target_os = "android"), not(target_os = "ios"))))]
fn is_msst(ip: Ipv4Addr) -> bool {
    ip.octets()[..2] == [172, 22]
}

/// Unix desktop: capture UDP broadcasts this machine sends on its physical
/// LAN (raw socket, needs CAP_NET_RAW/root) and forward them.  Broadcasts
/// from other machines are ignored — their own client forwards them.
/// Keeps running across network changes, and without any network at first.
#[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
async fn physical_bcast_loop(disc_tx: mpsc::Sender<Vec<u8>>) {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::mem::MaybeUninit;
    use tokio::io::unix::AsyncFd;

    let raw = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)).and_then(|s| s.set_nonblocking(true).map(|_| s)) {
        Ok(s) => s,
        Err(e) => {
            warn!("discovery: physical broadcast capture unavailable (needs CAP_NET_RAW/root): {}", e);
            return;
        }
    };
    let Ok(fd) = AsyncFd::new(raw) else { return };
    info!("discovery: physical LAN broadcast capture active");
    let mut nets = LocalNets::read();
    let mut refresh = tokio::time::interval(LOCAL_NETS_REFRESH);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut recv_failed = false;
    let mut buf = vec![MaybeUninit::<u8>::uninit(); 65536];
    loop {
        let mut guard = tokio::select! {
            _ = refresh.tick() => {
                let now = LocalNets::read();
                if now != nets {
                    debug!("discovery: local networks now {:?} (broadcast {:?})", now.ips, now.broadcasts);
                    nets = now;
                }
                continue;
            }
            g = fd.readable() => match g {
                Ok(g) => g,
                Err(e) => {
                    warn!("discovery: physical broadcast capture stopped: {}", e);
                    return;
                }
            },
        };
        let len = match guard.try_io(|inner| inner.get_ref().recv_from(&mut buf)) {
            Ok(Ok((n, _))) => {
                recv_failed = false;
                n
            }
            Ok(Err(e)) => {
                // E.g. an interface going away: keep capturing.
                if !recv_failed {
                    warn!("discovery: raw recv error: {}", e);
                    recv_failed = true;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            Err(_) => continue,
        };
        // SAFETY: recv_from initialized buf[..len].
        let mut pkt: Vec<u8> = buf[..len].iter().map(|b| unsafe { b.assume_init() }).collect();
        if !nets.is_own_broadcast(&pkt) {
            continue;
        }
        // Any subnet broadcast becomes a limited one, which the outbound
        // path rewrites into MSST-Net space (`rewrite_for_msst_broadcast`
        // recomputes both checksums).
        pkt[16..20].copy_from_slice(&Ipv4Addr::BROADCAST.octets());
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

    fn to(dst: [u8; 4], port: u16) -> Vec<u8> {
        ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(172, 22, 0, 9)), 50000, IpAddr::V4(dst.into()), port, b"x")
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
    fn discovery_is_udp_broadcast_or_known_multicast() {
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
        let huge = ippkt::build_udp(IpAddr::V4(Ipv4Addr::new(172, 22, 0, 9)), 1, IpAddr::V4(MSST_BROADCAST), 2, &[0; MAX_PAYLOAD + 1]);
        for bad in [tcp, fragment, options, long_udp, ok[..27].to_vec(), huge] {
            assert!(discovery_datagram(&bad).is_none());
        }
    }

    #[test]
    fn message_round_trip() {
        let p = to([172, 22, 255, 255], 19132);
        let msg = Message::of(&discovery_datagram(&p).unwrap());
        let (a, b) = (Ipv4Addr::new(172, 22, 0, 9), Ipv4Addr::new(172, 22, 0, 7));
        let wire = msg.encode(a, b);
        assert_eq!(Message::decode(&wire), Some(msg.clone()));
        // A valid IPv4 packet from the sender to the recipient: it passes
        // the inbound "to us" check like any peer packet.
        assert_eq!(ippkt::csum_fold(ippkt::csum_add(0, &wire[..20])), 0);
        let parsed = crate::runtime::parse_ip_packet(&wire).unwrap();
        assert_eq!((parsed.src_ip, parsed.dst_ip), (IpAddr::V4(a), IpAddr::V4(b)));
        // Not a relay-path probe, and a probe is not a message.
        assert_eq!(crate::tunnel_probe::Probe::decode(&wire), None);
        let probe = crate::tunnel_probe::Probe { kind: crate::tunnel_probe::Kind::Ping, src: a, dst: b, seq: 1, sent_ms: 2 };
        assert_eq!(Message::decode(&probe.encode()), None);
        // Other versions, truncated: not decoded.
        let mut v2 = wire.clone();
        v2[24] = 2;
        assert_eq!(Message::decode(&v2), None);
        assert_eq!(Message::decode(&wire[..33]), None);
        // Rebuilt from the sender's address — the source in the message's
        // datagram is never used — and held to the same rules.
        let out = msg.rebuild(Ipv4Addr::new(172, 22, 0, 7)).unwrap();
        let u = ippkt::udp_parts(&out).unwrap();
        assert_eq!((u.src, u.dst, u.src_port, u.dst_port), (IpAddr::V4(b), IpAddr::V4(MSST_BROADCAST), 50000, 19132));
        assert!(ippkt::checksums_valid(&out));
        let unicast = Message { dst: Ipv4Addr::new(192, 168, 1, 10), ..msg };
        assert_eq!(unicast.rebuild(b), None);
    }

    fn udp(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        ippkt::build_udp(IpAddr::V4(src.into()), 4000, IpAddr::V4(dst.into()), 4000, b"x")
    }

    #[test]
    fn injected_broadcasts_are_not_captured_again() {
        // This machine: LAN 192.168.1.5/24, MSST-Net 172.22.0.1/16.
        let local = LocalNets::of([
            (Ipv4Addr::new(192, 168, 1, 5), 24, Some(Ipv4Addr::new(192, 168, 1, 255))),
            (Ipv4Addr::new(172, 22, 0, 1), 16, Some(MSST_BROADCAST)),
        ]);
        let ours = udp([192, 168, 1, 5], [255, 255, 255, 255]);
        assert!(local.is_own_broadcast(&ours));
        // A member's broadcast claiming our LAN address, as injected: rebuilt
        // from the member's address, so the capture ignores it.
        let injected = Message::of(&discovery_datagram(&ours).unwrap()).rebuild(Ipv4Addr::new(172, 22, 0, 7)).unwrap();
        assert!(!local.is_own_broadcast(&injected));
        assert!(!local.is_own_broadcast(&udp([172, 22, 0, 1], [172, 22, 255, 255])));
    }

    #[test]
    fn subnet_broadcasts_follow_the_networks_prefix() {
        // An iPhone hotspot (/28): its broadcast address doesn't end in .255.
        let hotspot = LocalNets::of([(Ipv4Addr::new(172, 20, 10, 2), 28, None)]);
        assert_eq!(hotspot.broadcasts, [Ipv4Addr::new(172, 20, 10, 15)].into());
        assert!(hotspot.is_own_broadcast(&udp([172, 20, 10, 2], [172, 20, 10, 15])));
        // A unicast address ending in .255 in a /16 is not a broadcast.
        let wide = LocalNets::of([(Ipv4Addr::new(10, 0, 1, 5), 16, Some(Ipv4Addr::new(10, 0, 255, 255)))]);
        assert!(!wide.is_own_broadcast(&udp([10, 0, 1, 5], [10, 0, 1, 255])));
        assert!(wide.is_own_broadcast(&udp([10, 0, 1, 5], [10, 0, 255, 255])));
        // No broadcast address on point-to-point /31 and /32.
        assert!(LocalNets::of([(Ipv4Addr::new(10, 1, 1, 1), 32, None), (Ipv4Addr::new(10, 2, 2, 0), 31, None)]).broadcasts.is_empty());
        // Loopback is never a physical network.
        assert_eq!(LocalNets::of([(Ipv4Addr::LOCALHOST, 8, None)]), LocalNets::default());
    }

    #[test]
    fn broadcasts_count_only_from_the_current_networks() {
        // After a switch from Wi-Fi (192.168.222.22) to a hotspot
        // (10.128.12.85), a view taken on Wi-Fi would drop every broadcast
        // the machine now sends; the current one takes them.
        let wifi = LocalNets::of([(Ipv4Addr::new(192, 168, 222, 22), 24, None)]);
        let hotspot = LocalNets::of([(Ipv4Addr::new(10, 128, 12, 85), 24, None)]);
        let sent = udp([10, 128, 12, 85], [255, 255, 255, 255]);
        assert!(!wifi.is_own_broadcast(&sent));
        assert!(hotspot.is_own_broadcast(&sent));
        // Not UDP, not IPv4: never.
        let mut tcp = sent.clone();
        tcp[9] = 6;
        assert!(!hotspot.is_own_broadcast(&tcp));
        assert!(!hotspot.is_own_broadcast(&sent[..19]));
    }

    #[test]
    fn a_captured_subnet_broadcast_is_carried_as_an_msst_broadcast() {
        // The capture makes it a limited broadcast; the outbound path then
        // rewrites it into MSST-Net space, and it is a discovery datagram.
        let mut pkt = udp([172, 20, 10, 2], [172, 20, 10, 15]);
        pkt[16..20].copy_from_slice(&Ipv4Addr::BROADCAST.octets());
        assert!(needs_msst_rewrite(&pkt));
        rewrite_for_msst_broadcast(&mut pkt, Ipv4Addr::new(172, 22, 245, 6));
        assert!(ippkt::checksums_valid(&pkt));
        let d = discovery_datagram(&pkt).unwrap();
        assert_eq!((d.dst, d.dst_port), (MSST_BROADCAST, 4000));
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
    fn outbound_dedup_and_rate_limit() {
        let mut st = TxState::default();
        let t = Instant::now();
        assert!(!st.is_duplicate(b"x", t));
        assert!(st.is_duplicate(b"x", t));
        assert!(!st.is_duplicate(b"x", t + DEDUP_TTL));
        for _ in 0..RATE_LIMIT {
            assert!(!st.is_rate_limited(t));
        }
        assert!(st.is_rate_limited(t));
        assert!(!st.is_rate_limited(t + RATE_WINDOW));
    }

    #[test]
    fn receive_limits_per_sender_then_in_total() {
        let mut l = RxLimits::default();
        let t = Instant::now();
        // One sender: its own limit; a flood doesn't use up the total.
        let accepted = (0..1000).filter(|_| !l.exceeded("device-00000001", t)).count();
        assert_eq!(accepted, RATE_LIMIT);
        // Many senders within their limits share the total.
        let mut total = accepted;
        for n in 2..200 {
            let id = format!("device-{:08x}", n);
            total += (0..2).filter(|_| !l.exceeded(&id, t)).count();
        }
        assert_eq!(total, RX_GLOBAL_RATE_LIMIT);
        // The next window has fresh budgets.
        assert!(!l.exceeded("device-00000001", t + RATE_WINDOW));
    }

    #[test]
    fn members_support_from_their_endpoints() {
        let ok = vec!["relay:r:1".to_string(), FEATURE_ENDPOINT.to_string()];
        assert_eq!(DiscoverySupport::of_endpoints(&ok), DiscoverySupport::Supported);
        assert_eq!(DiscoverySupport::of_endpoints(&["relay:r:1".to_string()]), DiscoverySupport::Unsupported);
        let mut net = crate::state::NetState::new();
        assert_eq!(net.discovery_support("device-00000007"), DiscoverySupport::Unknown);
        net.set_peer_discovery("device-00000007", &ok);
        assert_eq!(net.discovery_support("device-00000007").name(), "ok");
        net.set_peer_discovery("device-00000007", &["relay:r:1".to_string()]);
        assert_eq!(net.discovery_support("device-00000007").name(), "unsupported");
        // The feature entry is not an address or a relay.
        assert!(crate::endpoints::direct_candidates(&ok).is_empty());
        assert_eq!(crate::relay::extract_relay(&[FEATURE_ENDPOINT.to_string()]), None);
    }
}
