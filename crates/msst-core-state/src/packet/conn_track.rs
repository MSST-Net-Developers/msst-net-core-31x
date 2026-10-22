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
//!
//! Our replies to a flow the *peer* started (let in by a rule) are recorded
//! the same way, so after the first reply the peer's packets take the fast
//! path too.  Such flows remember the rule that admitted them
//! ([`FlowOrigin`]), so revoking that permission — deleting or disabling the
//! rule, leaving the room a room rule depended on — can end them
//! ([`ConnectionTracker::revoke`]): their next packet is evaluated by the
//! ACL again.  A rule that merely expires revokes nothing (an "allow once"
//! keeps the connections it admitted).

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

/// What admitted a peer-initiated flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowOrigin {
    /// The peer that started the flow.
    pub device_id: String,
    /// The ALLOW rule that matched its packets.
    pub rule_id: String,
    /// The rule matched at room scope (`PermissionGroup::Space`).
    pub room_scope: bool,
}

/// Stateful outbound connection tracker.
///
/// Maps outbound 5-tuples to their last-seen timestamp.  Inbound packets
/// that reverse-match a tracked connection are allowed without ACL evaluation.
pub struct ConnectionTracker {
    entries: HashMap<ConnKey, i64>,
    /// Peer-initiated flows, keyed like `entries` (our direction), with
    /// the time they were last seen in either direction.
    origins: HashMap<ConnKey, (FlowOrigin, i64)>,
    /// Revoked flows, with the time they were last seen: our replies on
    /// them don't make the peer's packets related again until the ACL
    /// admits the flow anew (or it goes idle).
    revoked: HashMap<ConnKey, i64>,
    udp_timeout_secs: i64,
    tcp_timeout_secs: i64,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        ConnectionTracker {
            entries: HashMap::new(),
            origins: HashMap::new(),
            revoked: HashMap::new(),
            udp_timeout_secs: DEFAULT_UDP_TIMEOUT.as_secs() as i64,
            tcp_timeout_secs: DEFAULT_TCP_TIMEOUT.as_secs() as i64,
        }
    }

    fn timeout(&self, proto: u8) -> i64 {
        if proto == 6 { self.tcp_timeout_secs } else { self.udp_timeout_secs }
    }

    /// Record an inbound packet the ACL allowed: the flow it belongs to was
    /// started by the peer and admitted by `origin.rule_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_inbound_allowed(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        proto: u8,
        origin: FlowOrigin,
        now_unix: i64,
    ) {
        // Our direction, as `record_outbound` keys our replies.
        let key = ConnKey { src_ip: dst_ip, src_port: dst_port, dst_ip: src_ip, dst_port: src_port, proto };
        self.revoked.remove(&key);
        self.origins.insert(key, (origin, now_unix));
    }

    /// End the tracked peer-initiated flows whose origin matches: their
    /// next inbound packet is evaluated by the ACL again.  Returns how many
    /// flows were ended.
    pub fn revoke(&mut self, mut matches: impl FnMut(&FlowOrigin) -> bool) -> usize {
        let keys: Vec<ConnKey> = self.origins.iter().filter(|(_, (o, _))| matches(o)).map(|(k, _)| k.clone()).collect();
        for k in &keys {
            if let Some((_, seen)) = self.origins.remove(k) {
                self.revoked.insert(k.clone(), seen);
            }
            self.entries.remove(k);
        }
        keys.len()
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
        if let Some(seen) = self.revoked.get_mut(&key) {
            *seen = now_unix;
            return;
        }
        if let Some((_, seen)) = self.origins.get_mut(&key) {
            *seen = now_unix;
        }
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

        let timeout = self.timeout(proto);

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
        self.origins.retain(|key, (_, last_seen)| {
            let timeout = if key.proto == 6 { tcp_timeout } else { udp_timeout };
            now_unix - *last_seen < timeout
        });
        self.revoked.retain(|key, last_seen| {
            let timeout = if key.proto == 6 { tcp_timeout } else { udp_timeout };
            now_unix - *last_seen < timeout
        });
    }

    /// The origin of a tracked peer-initiated flow, by our direction's key
    /// (diagnostics).
    pub fn origin(&self, key: &ConnKey) -> Option<&FlowOrigin> {
        self.origins.get(key).map(|(o, _)| o)
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

    fn origin(device: &str, rule: &str, room_scope: bool) -> FlowOrigin {
        FlowOrigin { device_id: device.into(), rule_id: rule.into(), room_scope }
    }

    /// Peer 172.22.2.1:5555 → us 172.22.1.1:25565 (TCP), allowed by `rule`;
    /// we reply, so its next packets are related.
    fn admitted(ct: &mut ConnectionTracker, peer_port: u16, rule: &str, room_scope: bool) {
        ct.record_inbound_allowed(ip(172, 22, 2, 1), peer_port, ip(172, 22, 1, 1), 25565, 6, origin("device-b", rule, room_scope), 1000);
        ct.record_outbound(ip(172, 22, 1, 1), 25565, ip(172, 22, 2, 1), peer_port, 6, 1000);
        assert!(ct.is_related(ip(172, 22, 2, 1), peer_port, ip(172, 22, 1, 1), 25565, 6, 1001));
    }

    #[test]
    fn revoking_a_rule_ends_the_flows_it_admitted() {
        let mut ct = ConnectionTracker::new();
        admitted(&mut ct, 5555, "r1", false);
        admitted(&mut ct, 6666, "r2", false);
        // A flow we started has no origin and is never revoked.
        ct.record_outbound(ip(172, 22, 1, 1), 40000, ip(172, 22, 2, 1), 80, 6, 1000);

        assert_eq!(ct.revoke(|o| o.rule_id == "r1"), 1);
        assert!(!ct.is_related(ip(172, 22, 2, 1), 5555, ip(172, 22, 1, 1), 25565, 6, 1002));
        assert!(ct.is_related(ip(172, 22, 2, 1), 6666, ip(172, 22, 1, 1), 25565, 6, 1002));
        assert!(ct.is_related(ip(172, 22, 2, 1), 80, ip(172, 22, 1, 1), 40000, 6, 1002));
        assert_eq!(ct.revoke(|o| o.rule_id == "r1"), 0); // already gone

        // Our replies on the revoked flow don't make it related again …
        ct.record_outbound(ip(172, 22, 1, 1), 25565, ip(172, 22, 2, 1), 5555, 6, 1003);
        assert!(!ct.is_related(ip(172, 22, 2, 1), 5555, ip(172, 22, 1, 1), 25565, 6, 1004));
        // … until the ACL admits it again (another rule still allows it).
        ct.record_inbound_allowed(ip(172, 22, 2, 1), 5555, ip(172, 22, 1, 1), 25565, 6, origin("device-b", "r3", false), 1005);
        ct.record_outbound(ip(172, 22, 1, 1), 25565, ip(172, 22, 2, 1), 5555, 6, 1005);
        assert!(ct.is_related(ip(172, 22, 2, 1), 5555, ip(172, 22, 1, 1), 25565, 6, 1006));
    }

    #[test]
    fn a_revoked_flow_is_forgotten_once_idle() {
        let mut ct = ConnectionTracker::new();
        admitted(&mut ct, 5555, "r1", false);
        ct.revoke(|_| true);
        ct.cleanup(1121);
        // Idle past the timeout: a new flow on the same ports is ours.
        ct.record_outbound(ip(172, 22, 1, 1), 25565, ip(172, 22, 2, 1), 5555, 6, 1122);
        assert!(ct.is_related(ip(172, 22, 2, 1), 5555, ip(172, 22, 1, 1), 25565, 6, 1123));
    }

    #[test]
    fn revoking_room_scope_flows_by_device() {
        let mut ct = ConnectionTracker::new();
        admitted(&mut ct, 5555, "space", true);
        admitted(&mut ct, 6666, "dev", false);
        assert_eq!(ct.revoke(|o| o.room_scope && o.device_id == "device-b"), 1);
        assert!(!ct.is_related(ip(172, 22, 2, 1), 5555, ip(172, 22, 1, 1), 25565, 6, 1002));
        assert!(ct.is_related(ip(172, 22, 2, 1), 6666, ip(172, 22, 1, 1), 25565, 6, 1002));
    }

    #[test]
    fn origins_live_as_long_as_the_flow() {
        let mut ct = ConnectionTracker::new();
        admitted(&mut ct, 5555, "r1", false);
        let key = ConnKey { src_ip: ip(172, 22, 1, 1), src_port: 25565, dst_ip: ip(172, 22, 2, 1), dst_port: 5555, proto: 6 };
        // Our replies keep it (and its origin) alive.
        ct.record_outbound(ip(172, 22, 1, 1), 25565, ip(172, 22, 2, 1), 5555, 6, 1100);
        ct.cleanup(1200);
        assert_eq!(ct.origin(&key).map(|o| o.rule_id.as_str()), Some("r1"));
        ct.cleanup(1221);
        assert!(ct.origin(&key).is_none() && ct.is_empty());
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