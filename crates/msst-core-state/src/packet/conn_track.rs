//! Connection tracking — the "related traffic" fast path.
//!
//! When the local device sends an outbound packet to a peer, the 5-tuple is
//! recorded here.  If the peer replies (reverse 5-tuple), the inbound packet
//! is allowed immediately without consulting the ACL engine.
//!
//! This mirrors the 3.0.x `ConnTrackMap` but with:
//! - Owned data (no `Instant` — uses Unix timestamps for portability)
//! - Configurable timeouts
//! - Explicit cleanup

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Default UDP flow timeout (30 s, matches typical NAT).
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(30);
/// Default TCP flow timeout (120 s, allows idle game connections).
const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(120);

/// A 5-tuple connection key.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP).
    pub proto: u8,
}

/// Stateful outbound connection tracker.
///
/// Maps outbound 5-tuples to their last-seen timestamp.  Inbound packets
/// that reverse-match a tracked connection are allowed without ACL evaluation.
pub struct ConnectionTracker {
    entries: HashMap<ConnKey, i64>,
    udp_timeout_secs: i64,
    tcp_timeout_secs: i64,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        ConnectionTracker {
            entries: HashMap::new(),
            udp_timeout_secs: DEFAULT_UDP_TIMEOUT.as_secs() as i64,
            tcp_timeout_secs: DEFAULT_TCP_TIMEOUT.as_secs() as i64,
        }
    }

    /// Record an outbound packet's 5-tuple.
    pub fn record_outbound(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        proto: u8,
        now_unix: i64,
    ) {
        let key = ConnKey { src_ip, src_port, dst_ip, dst_port, proto };
        self.entries.insert(key, now_unix);
    }

    /// Check if an inbound packet is a reply to a tracked outbound connection.
    ///
    /// Returns `true` if the reverse 5-tuple exists and hasn't timed out.
    /// The caller should allow such packets immediately (the "related
    /// traffic" fast path).
    ///
    /// Note: this does NOT refresh the timestamp — the entry is refreshed
    /// only when `record_outbound` is called (i.e. when we send another
    /// packet on the same flow).  This prevents the timeout from being
    /// indefinitely extended by passive inbound checks.
    pub fn is_related(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        proto: u8,
        now_unix: i64,
    ) -> bool {
        // The inbound packet's src/dst are the reverse of the outbound.
        let related_key = ConnKey {
            src_ip: dst_ip,
            src_port: dst_port,
            dst_ip: src_ip,
            dst_port: src_port,
            proto,
        };

        let timeout = if proto == 6 { self.tcp_timeout_secs } else { self.udp_timeout_secs };

        if let Some(last_seen) = self.entries.get(&related_key) {
            return now_unix - *last_seen < timeout;
        }
        false
    }

    /// Remove stale entries.  Call periodically (e.g. every 60 s).
    pub fn cleanup(&mut self, now_unix: i64) {
        let udp_timeout = self.udp_timeout_secs;
        let tcp_timeout = self.tcp_timeout_secs;
        self.entries.retain(|key, last_seen| {
            let timeout = if key.proto == 6 { tcp_timeout } else { udp_timeout };
            now_unix - *last_seen < timeout
        });
    }

    /// Number of tracked connections.
    /// Tracked flows with their last-outbound time (diagnostics).
    pub fn entries(&self) -> impl Iterator<Item = (&ConnKey, i64)> {
        self.entries.iter().map(|(k, &t)| (k, t))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ConnectionTracker {
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
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn new_tracker_is_empty() {
        let ct = ConnectionTracker::new();
        assert!(ct.is_empty());
    }

    #[test]
    fn record_then_match() {
        let mut ct = ConnectionTracker::new();
        // Outbound: us:12345 → peer:80 TCP
        ct.record_outbound(ip(172, 22, 1, 1), 12345, ip(172, 22, 2, 1), 80, 6, 1000);
        // Inbound reply: peer:80 → us:12345 TCP (reverse)
        assert!(ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 12345, 6, 1001));
    }

    #[test]
    fn no_match_wrong_proto() {
        let mut ct = ConnectionTracker::new();
        ct.record_outbound(ip(172, 22, 1, 1), 12345, ip(172, 22, 2, 1), 80, 6, 1000);
        assert!(!ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 12345, 17, 1001));
    }

    #[test]
    fn no_match_wrong_ports() {
        let mut ct = ConnectionTracker::new();
        ct.record_outbound(ip(172, 22, 1, 1), 12345, ip(172, 22, 2, 1), 80, 6, 1000);
        assert!(!ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 54321, 6, 1001));
    }

    #[test]
    fn udp_timeout() {
        let mut ct = ConnectionTracker::new();
        ct.record_outbound(ip(172, 22, 1, 1), 12345, ip(172, 22, 2, 1), 80, 17, 1000);
        // Within 30s → match
        assert!(ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 12345, 17, 1029));
        // After 30s → expired
        assert!(!ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 12345, 17, 1031));
    }

    #[test]
    fn tcp_timeout() {
        let mut ct = ConnectionTracker::new();
        ct.record_outbound(ip(172, 22, 1, 1), 12345, ip(172, 22, 2, 1), 80, 6, 1000);
        // Within 120s → match
        assert!(ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 12345, 6, 1119));
        // After 120s → expired
        assert!(!ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 12345, 6, 1121));
    }

    #[test]
    fn cleanup_removes_stale() {
        let mut ct = ConnectionTracker::new();
        ct.record_outbound(ip(172, 22, 1, 1), 1000, ip(172, 22, 2, 1), 80, 17, 1000);
        ct.record_outbound(ip(172, 22, 1, 1), 2000, ip(172, 22, 2, 1), 80, 6, 1000);
        assert_eq!(ct.len(), 2);
        ct.cleanup(1031); // UDP expired, TCP still alive
        assert_eq!(ct.len(), 1);
        ct.cleanup(1121); // TCP also expired
        assert!(ct.is_empty());
    }

    #[test]
    fn refresh_on_outbound_record() {
        let mut ct = ConnectionTracker::new();
        ct.record_outbound(ip(172, 22, 1, 1), 12345, ip(172, 22, 2, 1), 80, 17, 1000);
        // At 1020: still within 30s window.
        assert!(ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 12345, 17, 1020));
        // Re-record outbound refreshes the timestamp.
        ct.record_outbound(ip(172, 22, 1, 1), 12345, ip(172, 22, 2, 1), 80, 17, 1020);
        // Now the entry is alive until 1020 + 30 = 1050.
        assert!(ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 12345, 17, 1049));
        assert!(!ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 12345, 17, 1051));
    }
}