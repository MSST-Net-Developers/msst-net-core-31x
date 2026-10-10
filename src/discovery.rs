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
//! Discovery is separate from authorization: a discovered service is still
//! subject to the inbound ACL when connected to.

use crate::ippkt;
use crate::state::CoreState;
use msst_core_state::net::msst_packet::{encode_id, MsstPacket, TYPE_DISCOVERY_DATA, TYPE_DISCOVERY_REGISTER, VERSION};
use msst_core_state::net::relay::map_send_addr;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub const DISCOVERY_PORT: u16 = 21032;
const DISCOVERY_MULTICAST: &[Ipv4Addr] = &[Ipv4Addr::new(224, 0, 2, 60), Ipv4Addr::new(224, 0, 0, 251)];
const REGISTER_INTERVAL: Duration = Duration::from_secs(25);
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
    #[allow(unused_mut)] // only extended on Unix
    let mut handles = vec![
        tokio::spawn(rx_loop(sock.clone(), tun_tx)),
        tokio::spawn(tx_loop(disc_rx, sock.clone(), state.clone())),
        tokio::spawn(registration_loop(sock, state.clone())),
    ];
    #[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
    handles.push(tokio::spawn(physical_bcast_loop(disc_tx.clone())));
    (disc_tx, handles)
}

async fn rx_loop(sock: Arc<UdpSocket>, tun_tx: mpsc::Sender<Vec<u8>>) {
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
        if !is_ipv4_discovery_packet(&buf[..len]) {
            debug!("discovery: dropped non-discovery packet ({} B) from {}", len, src);
            continue;
        }
        if tun_tx.send(buf[..len].to_vec()).await.is_err() {
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

async fn tx_loop(mut rx: mpsc::Receiver<Vec<u8>>, sock: Arc<UdpSocket>, state: Arc<CoreState>) {
    let mut st = TxState::default();
    while let Some(mut pkt) = rx.recv().await {
        let (relay, room, device_id) = {
            let net = state.net.read().await;
            (net.relay_addr.clone(), net.joined_rooms.keys().next().cloned(), net.local_device_id.clone())
        };
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
        let Some(target) = crate::relay::resolve_addr(&relay).await else { continue };
        if let Err(e) = sock.send_to(&build_discovery_data(&device_id, &room, &pkt), map_send_addr(target)).await {
            warn!("discovery: send to relay failed: {}", e);
        }
    }
}

async fn registration_loop(sock: Arc<UdpSocket>, state: Arc<CoreState>) {
    let mut ticker = tokio::time::interval(REGISTER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let (relay, id) = {
            let net = state.net.read().await;
            (net.relay_addr.clone(), net.local_device_id.clone())
        };
        let (Some(relay), false) = (relay, id.is_empty()) else { continue };
        let Some(target) = crate::relay::resolve_addr(&relay).await else { continue };
        let pkt = MsstPacket { version: VERSION, packet_type: TYPE_DISCOVERY_REGISTER, flags: 0, src_id: encode_id(&id), dst_id: [0; 8], payload: vec![] }.encode();
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
}
