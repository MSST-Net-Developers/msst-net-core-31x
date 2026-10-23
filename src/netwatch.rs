//! Network changes: detection on desktops, and the one handler shared with
//! the embedded Core.
//!
//! A switch between networks (Wi-Fi ↔ phone hotspot) changes this
//! machine's addresses, and everything bound to the old ones goes stale at
//! once: the coordinator WebSocket (TCP alone notices only after many
//! minutes — meanwhile the coordinator drops us from our room), the relay's
//! binding for us (until the next keepalive), our announced endpoints
//! (until the 5-minute re-detection: peers can't reach us directly), and
//! paths held back by hold timers and probe backoff.  [`on_network_changed`]
//! renews them all.
//!
//! Desktops: [`watch`] polls the interface addresses.  The embedded
//! (Android) Core is told by the app (`EmbeddedCore::network_changed`); as
//! the app's callbacks also fire when nothing we use changed (at start, a
//! second network coming and going), [`Reported`] lets only an address
//! change reconnect.

use crate::state::CoreState;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// How often the interface addresses are read.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The networks this machine is on: the IPv4 addresses and IPv6 /64
/// prefixes of its physical interfaces.  (An IPv6 privacy address rotating
/// within its prefix is no network change.)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot(BTreeSet<IpAddr>);

impl Snapshot {
    pub fn read() -> Self {
        Self::of(if_addrs::get_if_addrs().unwrap_or_default().into_iter().map(|i| (i.name, i.addr.ip())))
    }

    /// From (interface name, address) pairs.  Loopback and link-local
    /// addresses, MSST-Net's own ranges and the interfaces of VPNs,
    /// containers and VMs are left out.
    pub fn of(addrs: impl IntoIterator<Item = (String, IpAddr)>) -> Self {
        let keys = addrs.into_iter().filter(|(name, _)| !msst_core_state::nat::stun::is_virtual_interface(name)).filter_map(|(_, ip)| match ip {
            IpAddr::V4(a) if a.is_loopback() || a.is_link_local() || a.octets()[..2] == [172, 22] => None,
            IpAddr::V4(a) => Some(IpAddr::V4(a)),
            IpAddr::V6(a) if a.is_loopback() || a.is_unicast_link_local() || a.segments()[..4] == [0xfd22, 0x2222, 0x2222, 0x2222] => None,
            IpAddr::V6(a) => {
                let s = a.segments();
                Some(IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0)))
            }
        });
        Snapshot(keys.collect())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// When a new set of addresses counts as a network change: once it is not
/// empty (mid-switch there is often no address at all) and was seen on two
/// polls in a row (DHCP and IPv6 autoconfiguration settle).  Coming back to
/// the addresses we had is no change.
#[derive(Debug, Default)]
pub struct Watch {
    current: Option<Snapshot>,
    pending: Option<Snapshot>,
}

impl Watch {
    /// Take in a poll; true: the network changed, act now.
    pub fn observe(&mut self, now: Snapshot) -> bool {
        let Some(current) = &self.current else {
            self.current = Some(now);
            return false;
        };
        if &now == current || now.is_empty() {
            self.pending = None;
            return false;
        }
        if self.pending.as_ref() == Some(&now) {
            self.current = self.pending.take();
            return true;
        }
        self.pending = Some(now);
        false
    }
}

/// For network events a platform reports itself (the embedded Core): the
/// addresses as of the last change.
#[derive(Debug, Default)]
pub struct Reported(Option<Snapshot>);

impl Reported {
    pub fn new(now: Snapshot) -> Self {
        Reported(Some(now).filter(|s| !s.is_empty()))
    }

    /// Take in the addresses at a reported event; true: they changed
    /// (none at all is no change — the next event brings the new ones).
    pub fn changed(&mut self, now: Snapshot) -> bool {
        if now.is_empty() || self.0.as_ref() == Some(&now) {
            return false;
        }
        self.0 = Some(now);
        true
    }
}

/// Desktops: watch the interface addresses and handle network changes.
pub async fn watch(state: Arc<CoreState>) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut w = Watch::default();
    loop {
        ticker.tick().await;
        let now = Snapshot::read();
        debug!("network: addresses {:?}", now.0);
        if w.observe(now) {
            on_network_changed(&state, true).await;
        }
    }
}

/// The network changed: flush DNS, re-detect and announce our endpoints,
/// and let every path probe again at once (3.0.x network-change handler);
/// if our addresses changed, also reconnect to the coordinator and register
/// with the relays again from the new address — what was bound to the old
/// one is dead.
pub async fn on_network_changed(state: &Arc<CoreState>, addresses_changed: bool) {
    if addresses_changed {
        info!("network: changed — reconnecting, re-registering with the relays, re-announcing endpoints");
    } else {
        info!("network: event, addresses unchanged — re-announcing endpoints");
    }
    if let Some(dns) = state.dns.get() {
        dns.clear_cache();
    }
    state.scheduler.lock().await.clear_hold_timers();
    if addresses_changed {
        if let Some(client) = state.coordinator.get() {
            client.network_changed();
        }
        crate::runtime::reregister_with_relays(state).await;
    }
    crate::endpoints::spawn_detect_and_report(state.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(addrs: &[(&str, &str)]) -> Snapshot {
        Snapshot::of(addrs.iter().map(|(n, a)| (n.to_string(), a.parse().unwrap())))
    }

    #[test]
    fn snapshot_keeps_physical_networks_only() {
        let s = snap(&[
            ("wlan0", "192.168.222.22"),
            ("wlan0", "2600:381:2012:daba:1abc:2747:f4be:d860"),
            ("wlan0", "fe80::1"),
            ("lo", "127.0.0.1"),
            ("msst0", "172.22.245.6"),
            ("eth0", "169.254.3.4"),
            ("docker0", "172.17.0.1"),
            ("tailscale0", "100.64.0.1"),
        ]);
        assert_eq!(s, snap(&[("wlan0", "192.168.222.22"), ("wlan0", "2600:381:2012:daba::")]));
        // A rotated privacy address in the same /64 is the same network.
        assert_eq!(snap(&[("wlan0", "2600:381:2012:daba::1")]), snap(&[("wlan0", "2600:381:2012:daba::2")]));
        assert!(snap(&[("lo", "::1"), ("msst0", "fd22:2222:2222:2222::1")]).is_empty());
    }

    #[test]
    fn a_switch_counts_once_the_new_addresses_settle() {
        let (wifi, hotspot) = (snap(&[("wlan0", "192.168.222.22")]), snap(&[("wlan0", "10.128.12.85")]));
        let mut w = Watch::default();
        assert!(!w.observe(wifi.clone()), "the first poll is the baseline");
        assert!(!w.observe(wifi.clone()));
        // Wi-Fi → hotspot: addresses gone for a moment, then new ones.
        assert!(!w.observe(Snapshot::default()));
        assert!(!w.observe(hotspot.clone()));
        assert!(w.observe(hotspot.clone()));
        assert!(!w.observe(hotspot.clone()), "acted once");
        // And back.
        assert!(!w.observe(wifi.clone()));
        assert!(w.observe(wifi.clone()));
    }

    #[test]
    fn a_blip_back_to_the_same_network_is_no_change() {
        let wifi = snap(&[("wlan0", "192.168.222.22")]);
        let mut w = Watch::default();
        w.observe(wifi.clone());
        assert!(!w.observe(Snapshot::default()));
        assert!(!w.observe(Snapshot::default()));
        assert!(!w.observe(wifi.clone()));
        assert!(!w.observe(wifi));
        // A one-poll flicker of other addresses neither.
        let mut w = Watch::default();
        w.observe(snap(&[("wlan0", "192.168.222.22")]));
        assert!(!w.observe(snap(&[("wlan0", "10.0.0.2")])));
        assert!(!w.observe(snap(&[("wlan0", "192.168.222.22")])));
        assert!(!w.observe(snap(&[("wlan0", "10.0.0.2")])));
    }

    #[tokio::test]
    async fn a_change_re_registers_and_lets_paths_probe_again() {
        use std::collections::{HashMap, HashSet};
        let (state, _ipc) = crate::test_support::core_state("netwatch").await;
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        state.net.write().await.relay_addr = Some(relay.local_addr().unwrap().to_string());
        // A peer whose only candidate never answered: back on the relay,
        // with a hold and a probe backoff.
        let peer = "device-00000002";
        let candidates: HashMap<String, Vec<std::net::SocketAddr>> = [(peer.to_string(), vec!["203.0.113.7:21031".parse().unwrap()])].into();
        {
            let mut sched = state.scheduler.lock().await;
            sched.ensure_peer(peer);
            let mut t = crate::runtime::current_unix();
            while sched.paths().find(|(id, _)| *id == peer).unwrap().1.probe_failures == 0 {
                sched.tick(t, t as u64 * 1000, &candidates, &HashSet::new(), &HashMap::new());
                t += 3;
            }
        }

        on_network_changed(&state, true).await;

        // Registered with the relay at once (legacy relay: `0x01`) …
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut buf)).await.expect("registration").unwrap();
        assert_eq!(buf[5], msst_core_state::net::msst_packet::TYPE_REGISTER, "{:?}", &buf[..n]);
        // … and the path neither waits for its hold nor its backoff.
        let sched = state.scheduler.lock().await;
        let (_, pp) = sched.paths().find(|(id, _)| *id == peer).unwrap();
        assert!(!pp.hold_active(crate::runtime::current_unix()));
        assert_eq!((pp.probe_failures, pp.next_probe_at), (0, 0));
    }

    #[tokio::test]
    async fn an_event_without_new_addresses_only_refreshes() {
        let (state, _ipc) = crate::test_support::core_state("netwatch-same").await;
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        state.net.write().await.relay_addr = Some(relay.local_addr().unwrap().to_string());
        on_network_changed(&state, false).await;
        let mut buf = [0u8; 64];
        assert!(tokio::time::timeout(Duration::from_millis(300), relay.recv_from(&mut buf)).await.is_err(), "no re-registration");
    }

    #[test]
    fn reported_events_count_only_with_new_addresses() {
        let (wifi, mobile) = (snap(&[("wlan0", "192.168.1.5")]), snap(&[("rmnet0", "10.20.30.40")]));
        // The app's first callback comes for the network we started on.
        let mut r = Reported::new(wifi.clone());
        assert!(!r.changed(wifi.clone()));
        // Mid-switch, no address: not yet; the new network's event is.
        assert!(!r.changed(Snapshot::default()));
        assert!(r.changed(mobile.clone()));
        assert!(!r.changed(mobile));
        assert!(r.changed(wifi));
        // Started without a network: the first one is a change.
        let mut r = Reported::new(Snapshot::default());
        assert!(r.changed(snap(&[("wlan0", "192.168.1.5")])));
    }

    #[test]
    fn the_first_network_after_none_is_a_change() {
        // Started before the network was up (e.g. at boot).
        let mut w = Watch::default();
        assert!(!w.observe(Snapshot::default()));
        let wifi = snap(&[("wlan0", "192.168.222.22")]);
        assert!(!w.observe(wifi.clone()));
        assert!(w.observe(wifi));
    }
}
