//! Fragment verdicts — firewall decisions for fragmented datagrams.
//!
//! Only the first fragment of a datagram carries the transport header, so
//! only it can be evaluated (connection tracking, ACL, interactive auth).
//! Its verdict is recorded here under the reassembly key, and the later
//! fragments of the same datagram follow it: forwarded when the first
//! fragment was, dropped otherwise.  The OS reassembles the fragments
//! behind the TUN, so a datagram is delivered only if its first fragment
//! passed the firewall — a later fragment can never bring a transport
//! header of its own past it.
//!
//! Later fragments that arrive before their first fragment are held (up to
//! a bound) and released with the verdict once it exists.  Everything is
//! bounded and times out; when full, new fragments are dropped (fail
//! closed).
//!
//! Generic over the verdict type `V`; the tracker never inspects it.

use crate::packet::parsed::ParsedPacket;
use std::collections::HashMap;
use std::net::IpAddr;

/// Lifetime of a recorded verdict or held fragments (the Linux IPv4
/// reassembly timeout, `ipfrag_time`).
pub const FRAGMENT_TIMEOUT_SECS: i64 = 30;
/// Datagrams tracked at once (decided or waiting).
pub const MAX_FRAGMENT_ENTRIES: usize = 1024;
/// Later fragments held per datagram while its first fragment is missing.
pub const MAX_HELD_PER_DATAGRAM: usize = 16;
/// Bytes held across all datagrams.
pub const MAX_HELD_BYTES: usize = 1 << 20;

/// Reassembly key: what the OS uses to group fragments.  IPv4 groups by
/// (src, dst, protocol, id); IPv6 by (src, dst, id) — the protocol in a
/// later fragment's Fragment header may be an extension header, so it is
/// left out (0) for IPv6.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct FragKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub proto: u8,
    pub id: u32,
}

impl FragKey {
    /// The key of a fragmented packet; `None` for whole packets.
    pub fn of(p: &ParsedPacket) -> Option<Self> {
        let f = p.fragment?;
        let proto = if p.src_ip.is_ipv4() { p.proto.number() } else { 0 };
        Some(FragKey { src_ip: p.src_ip, dst_ip: p.dst_ip, proto, id: f.id })
    }
}

enum Entry<V> {
    Decided { verdict: V, expires_at: i64 },
    Waiting { held: Vec<Vec<u8>>, expires_at: i64 },
}

impl<V> Entry<V> {
    fn expires_at(&self) -> i64 {
        match self {
            Entry::Decided { expires_at, .. } | Entry::Waiting { expires_at, .. } => *expires_at,
        }
    }
}

/// What to do with a later fragment.
#[derive(Debug, PartialEq)]
pub enum LaterFragment<V> {
    /// The first fragment was decided: apply its verdict to the packet.
    Decided(V, Vec<u8>),
    /// Held until the first fragment arrives.
    Held,
    /// No room to hold it: drop.
    Dropped,
}

/// Verdicts of first fragments and later fragments waiting for one.
pub struct FragmentTracker<V> {
    entries: HashMap<FragKey, Entry<V>>,
    held_bytes: usize,
}

impl<V: Clone> FragmentTracker<V> {
    pub fn new() -> Self {
        FragmentTracker { entries: HashMap::new(), held_bytes: 0 }
    }

    /// Record the verdict of a first fragment.  Returns the later fragments
    /// held for it, to which the caller applies the same verdict.  A
    /// reused id replaces the previous verdict.  When the table is full the
    /// verdict is not recorded and the later fragments are dropped.
    pub fn on_first(&mut self, key: FragKey, verdict: V, now_unix: i64) -> Vec<Vec<u8>> {
        let expires_at = now_unix + FRAGMENT_TIMEOUT_SECS;
        let held = match self.take(&key) {
            Some(Entry::Waiting { held, expires_at: e }) if e > now_unix => held,
            _ => Vec::new(),
        };
        if self.make_room(now_unix) {
            self.entries.insert(key, Entry::Decided { verdict, expires_at });
        }
        held
    }

    /// Classify a later fragment.
    pub fn on_later(&mut self, key: FragKey, pkt: Vec<u8>, now_unix: i64) -> LaterFragment<V> {
        match self.entries.get_mut(&key) {
            Some(Entry::Decided { verdict, expires_at }) if *expires_at > now_unix => {
                return LaterFragment::Decided(verdict.clone(), pkt);
            }
            Some(Entry::Waiting { held, expires_at }) if *expires_at > now_unix => {
                if held.len() >= MAX_HELD_PER_DATAGRAM || self.held_bytes + pkt.len() > MAX_HELD_BYTES {
                    return LaterFragment::Dropped;
                }
                self.held_bytes += pkt.len();
                held.push(pkt);
                return LaterFragment::Held;
            }
            _ => {}
        }
        // No live entry for this datagram yet.
        self.take(&key);
        if self.held_bytes + pkt.len() > MAX_HELD_BYTES || !self.make_room(now_unix) {
            return LaterFragment::Dropped;
        }
        self.held_bytes += pkt.len();
        self.entries.insert(key, Entry::Waiting { held: vec![pkt], expires_at: now_unix + FRAGMENT_TIMEOUT_SECS });
        LaterFragment::Held
    }

    /// Remove expired entries (and the fragments they held).
    pub fn cleanup(&mut self, now_unix: i64) {
        let mut freed = 0;
        self.entries.retain(|_, e| {
            let live = e.expires_at() > now_unix;
            if let (false, Entry::Waiting { held, .. }) = (live, &*e) {
                freed += held.iter().map(Vec::len).sum::<usize>();
            }
            live
        });
        self.held_bytes -= freed;
    }

    /// Remove an entry, releasing the bytes it held.
    fn take(&mut self, key: &FragKey) -> Option<Entry<V>> {
        let e = self.entries.remove(key)?;
        if let Entry::Waiting { held, .. } = &e {
            self.held_bytes -= held.iter().map(Vec::len).sum::<usize>();
        }
        Some(e)
    }

    /// Whether one more entry fits (after dropping expired ones if needed).
    /// The entry for the key being replaced must already be removed.
    fn make_room(&mut self, now_unix: i64) -> bool {
        if self.entries.len() >= MAX_FRAGMENT_ENTRIES {
            self.cleanup(now_unix);
        }
        self.entries.len() < MAX_FRAGMENT_ENTRIES
    }

    /// Datagrams tracked (decided or waiting).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bytes of later fragments currently held.
    pub fn held_bytes(&self) -> usize {
        self.held_bytes
    }
}

impl<V: Clone> Default for FragmentTracker<V> {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::parsed::{Fragment, TransportProtocol};
    use std::net::{Ipv4Addr, Ipv6Addr};

    const NOW: i64 = 1_700_000_000;

    fn key(id: u32) -> FragKey {
        FragKey { src_ip: IpAddr::V4(Ipv4Addr::new(172, 22, 1, 1)), dst_ip: IpAddr::V4(Ipv4Addr::new(172, 22, 0, 1)), proto: 17, id }
    }

    #[test]
    fn later_fragments_follow_the_first() {
        let mut t = FragmentTracker::new();
        assert!(t.on_first(key(1), true, NOW).is_empty());
        assert_eq!(t.on_later(key(1), vec![1], NOW + 1), LaterFragment::Decided(true, vec![1]));
        t.on_first(key(2), false, NOW);
        assert_eq!(t.on_later(key(2), vec![2], NOW), LaterFragment::Decided(false, vec![2]));
        // Ids are per datagram.
        assert_eq!(t.on_later(key(3), vec![3], NOW), LaterFragment::Held);
    }

    #[test]
    fn early_fragments_are_held_until_the_first_arrives() {
        let mut t = FragmentTracker::new();
        assert_eq!(t.on_later(key(1), vec![0; 10], NOW), LaterFragment::Held);
        assert_eq!(t.on_later(key(1), vec![1; 10], NOW), LaterFragment::Held);
        assert_eq!(t.held_bytes(), 20);
        assert_eq!(t.on_first(key(1), "allow", NOW), vec![vec![0; 10], vec![1; 10]]);
        assert_eq!(t.held_bytes(), 0);
        assert_eq!(t.on_later(key(1), vec![2], NOW), LaterFragment::Decided("allow", vec![2]));
    }

    #[test]
    fn held_fragments_are_bounded() {
        let mut t: FragmentTracker<bool> = FragmentTracker::new();
        for _ in 0..MAX_HELD_PER_DATAGRAM {
            assert_eq!(t.on_later(key(1), vec![0], NOW), LaterFragment::Held);
        }
        assert_eq!(t.on_later(key(1), vec![0], NOW), LaterFragment::Dropped);
        // Byte bound across datagrams.
        let big = vec![0; MAX_HELD_BYTES / 2];
        assert_eq!(t.on_later(key(2), big.clone(), NOW), LaterFragment::Held);
        assert_eq!(t.on_later(key(3), big, NOW), LaterFragment::Dropped);
    }

    #[test]
    fn entries_expire() {
        let mut t = FragmentTracker::new();
        t.on_first(key(1), true, NOW);
        t.on_later(key(2), vec![0; 5], NOW);
        // Expired verdicts don't apply; the late fragment waits for a new first.
        assert_eq!(t.on_later(key(1), vec![1], NOW + FRAGMENT_TIMEOUT_SECS), LaterFragment::Held);
        // Expired held fragments aren't released.
        assert!(t.on_first(key(2), true, NOW + FRAGMENT_TIMEOUT_SECS).is_empty());
        t.cleanup(NOW + 2 * FRAGMENT_TIMEOUT_SECS);
        assert!(t.is_empty());
        assert_eq!(t.held_bytes(), 0);
    }

    #[test]
    fn a_full_table_fails_closed() {
        let mut t = FragmentTracker::new();
        for id in 0..MAX_FRAGMENT_ENTRIES as u32 {
            t.on_first(key(id), true, NOW);
        }
        // Not recorded: its later fragments find no verdict and wait.
        t.on_first(key(u32::MAX), true, NOW);
        assert_eq!(t.on_later(key(u32::MAX), vec![0], NOW), LaterFragment::Dropped);
        // Expired entries make room again.
        t.on_first(key(u32::MAX), true, NOW + FRAGMENT_TIMEOUT_SECS);
        assert_eq!(t.on_later(key(u32::MAX), vec![0], NOW + FRAGMENT_TIMEOUT_SECS), LaterFragment::Decided(true, vec![0]));
    }

    #[test]
    fn reassembly_key() {
        let mut p = ParsedPacket {
            src_ip: key(0).src_ip, dst_ip: key(0).dst_ip, proto: TransportProtocol::Udp, src_port: 0, dst_port: 0,
            is_icmp_echo_request: false, fragment: None,
        };
        assert_eq!(FragKey::of(&p), None);
        p.fragment = Some(Fragment { id: 7, offset: 0, more: true });
        assert_eq!(FragKey::of(&p), Some(key(7)));
        // IPv6: the protocol isn't part of the key.
        p.src_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        p.dst_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let first = FragKey::of(&p).unwrap();
        p.proto = TransportProtocol::Other(60);
        assert_eq!(FragKey::of(&p), Some(first));
        assert_eq!(first.proto, 0);
    }
}
