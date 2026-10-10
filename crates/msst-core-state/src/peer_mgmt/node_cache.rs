//! Node cache — TTL-based peer retention with per-reason expiry.
//!
//! A peer stays in the cache as long as **at least one reason** is active:
//!
//! | Reason           | Set when                         | TTL after cleared   |
//! |------------------|----------------------------------|---------------------|
//! | Room member      | `room_state` with this device    | 20 minutes          |
//! | Rule referenced  | An ACL rule mentions this device  | 24 hours            |
//! | Recent comm      | ACL-allowed packet exchanged     | 2 hours             |
//!
//! When all reasons expire, `drain_expired()` returns the device ID for
//! eviction.

use std::collections::HashMap;
use tracing::debug;

/// Room membership grace period after leaving.
const ROOM_GRACE_SECS: i64 = 20 * 60; // 20 minutes
/// Rule reference grace period after last rule deleted.
const RULE_GRACE_SECS: i64 = 24 * 3600; // 24 hours
/// Communication grace period after last ACL-allowed packet.
const COMM_GRACE_SECS: i64 = 2 * 3600; // 2 hours
/// Threshold for renewing comm_until (avoid tiny extensions).
const COMM_RENEWAL_THRESHOLD_SECS: i64 = 30 * 60; // 30 minutes

// ---------------------------------------------------------------------------
// CacheEntry
// ---------------------------------------------------------------------------

/// Per-device cache entry tracking why we are keeping this node.
#[derive(Debug, Default, Clone)]
pub struct CacheEntry {
    /// True while this device is currently in our room.
    pub in_room: bool,
    /// Expiry for room-member reason after leaving room.
    pub room_until: Option<i64>,
    /// True while at least one active firewall rule references this device.
    pub rule_active: bool,
    /// Expiry for rule-reference reason after all rules expired/were deleted.
    pub rule_until: Option<i64>,
    /// Expiry for recent-communication reason.
    pub comm_until: Option<i64>,
    /// True once we have actually fetched this node's data into the PeerList.
    pub has_data: bool,
}

impl CacheEntry {
    /// Returns `true` if any reason keeps this entry alive at `now_unix`.
    pub fn is_valid(&self, now_unix: i64) -> bool {
        self.in_room
            || self.rule_active
            || self.room_until.is_some_and(|t| t > now_unix)
            || self.rule_until.is_some_and(|t| t > now_unix)
            || self.comm_until.is_some_and(|t| t > now_unix)
    }
}

// ---------------------------------------------------------------------------
// NodeCache
// ---------------------------------------------------------------------------

/// TTL-based node cache mapping device_id → CacheEntry.
pub struct NodeCache {
    entries: HashMap<String, CacheEntry>,
}

impl NodeCache {
    pub fn new() -> Self {
        NodeCache {
            entries: HashMap::new(),
        }
    }

    // ── Room membership ───────────────────────────────────────────────────

    /// Mark a device as currently in our room.
    pub fn mark_room_member(&mut self, device_id: &str) {
        let entry = self.entries.entry(device_id.to_string()).or_default();
        entry.in_room = true;
        entry.room_until = None; // clear any stale grace deadline
    }

    /// Record that a device left the room (starts grace timer).
    pub fn mark_left_room(&mut self, device_id: &str, now_unix: i64) {
        if let Some(entry) = self.entries.get_mut(device_id) {
            entry.in_room = false;
            entry.room_until = Some(now_unix + ROOM_GRACE_SECS);
        }
    }

    /// Clear room membership for all devices (we left the room).
    pub fn clear_all_room_membership(&mut self, now_unix: i64) {
        for entry in self.entries.values_mut() {
            if entry.in_room {
                entry.in_room = false;
                entry.room_until = Some(now_unix + ROOM_GRACE_SECS);
            }
        }
    }

    // ── Rule references ───────────────────────────────────────────────────

    /// Mark a device as referenced by an active firewall rule.
    pub fn mark_rule_active(&mut self, device_id: &str) {
        let entry = self.entries.entry(device_id.to_string()).or_default();
        entry.rule_active = true;
        entry.rule_until = None;
    }

    /// Clear rule-reference mark (all rules referencing this device are gone).
    pub fn clear_rule_active(&mut self, device_id: &str, now_unix: i64) {
        if let Some(entry) = self.entries.get_mut(device_id) {
            entry.rule_active = false;
            entry.rule_until = Some(now_unix + RULE_GRACE_SECS);
        }
    }

    // ── Communication ─────────────────────────────────────────────────────

    /// Extend the communication TTL for a device.
    ///
    /// Only extends if the new deadline would gain more than
    /// `COMM_RENEWAL_THRESHOLD_SECS` over the current one (avoids
    /// tiny extensions on every packet).
    pub fn extend_comm(&mut self, device_id: &str, now_unix: i64) {
        let entry = self.entries.entry(device_id.to_string()).or_default();
        let new_deadline = now_unix + COMM_GRACE_SECS;
        let should_extend = match entry.comm_until {
            Some(current) => new_deadline > current + COMM_RENEWAL_THRESHOLD_SECS,
            None => true,
        };
        if should_extend {
            entry.comm_until = Some(new_deadline);
        }
    }

    // ── Fetch tracking ────────────────────────────────────────────────────

    /// Mark that we have fetched this node's data from the coordinator.
    pub fn mark_fetched(&mut self, device_id: &str) {
        let entry = self.entries.entry(device_id.to_string()).or_default();
        entry.has_data = true;
    }

    /// Returns `true` if we have fetched data for this node.
    pub fn has_data(&self, device_id: &str) -> bool {
        self.entries.get(device_id).map_or(false, |e| e.has_data)
    }

    // ── Eviction ──────────────────────────────────────────────────────────

    /// Returns `true` if this device's cache entry is still valid.
    pub fn is_valid(&self, device_id: &str) -> bool {
        self.entries
            .get(device_id)
            .map_or(false, |e| e.is_valid(now_unix()))
    }

    /// Drain all expired entries and return their device IDs.
    pub fn drain_expired(&mut self, now_unix: i64) -> Vec<String> {
        let expired: Vec<String> = self.entries
            .iter()
            .filter(|(_, e)| !e.is_valid(now_unix))
            .map(|(id, _)| id.clone())
            .collect();

        for id in &expired {
            self.entries.remove(id);
            debug!("node_cache: expired {}", id);
        }
        expired
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // ── Persistence ───────────────────────────────────────────────────────

    /// Snapshot all entries for persistence.
    pub fn snapshot(
        &self,
        peer_list: &crate::peer_list::PeerList,
    ) -> Vec<super::PersistedPeerCacheEntry> {
        self.entries
            .iter()
            .map(|(device_id, entry)| {
                let peer = peer_list.get(device_id).map(|p| super::PersistedPeerData {
                    user_id: p.user_id.clone(),
                    device_handle: p.device_handle.clone(),
                    user_handle: p.user_handle.clone(),
                    hostname: p.hostname.clone(),
                    ipv4: p.ipv4.to_string(),
                    ipv6: p.ipv6.to_string(),
                    display_name: p.display_name.clone(),
                    user_display_name: p.user_display_name.clone(),
                    is_authenticated: p.is_authenticated,
                });
                super::PersistedPeerCacheEntry {
                    device_id: device_id.clone(),
                    cache: super::PersistedCacheEntry {
                        room_until: entry.room_until,
                        rule_active: entry.rule_active,
                        rule_until: entry.rule_until,
                        comm_until: entry.comm_until,
                        has_data: entry.has_data,
                    },
                    peer,
                }
            })
            .collect()
    }

    /// Restore entries from a persisted snapshot.
    pub fn restore(&mut self, entries: Vec<super::PersistedPeerCacheEntry>, now_unix: i64) {
        for persisted in entries {
            let entry = CacheEntry {
                in_room: false,
                room_until: persisted.cache.room_until.filter(|&t| t > now_unix),
                rule_active: persisted.cache.rule_active,
                rule_until: persisted.cache.rule_until.filter(|&t| t > now_unix),
                comm_until: persisted.cache.comm_until.filter(|&t| t > now_unix),
                has_data: persisted.cache.has_data,
            };
            if entry.is_valid(now_unix) {
                self.entries.insert(persisted.device_id, entry);
            }
        }
    }
}

impl Default for NodeCache {
    fn default() -> Self {
        Self::new()
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn new_cache_is_empty() {
        let c = NodeCache::new();
        assert!(c.is_empty());
        assert!(!c.is_valid("device-00000000"));
    }

    #[test]
    fn room_member_is_valid() {
        let mut c = NodeCache::new();
        c.mark_room_member("device-aabbccdd");
        assert!(c.is_valid("device-aabbccdd"));
    }

    #[test]
    fn room_member_grace_after_leave() {
        let mut c = NodeCache::new();
        c.mark_room_member("device-aabbccdd");
        c.mark_left_room("device-aabbccdd", NOW);
        // Still valid during grace period (20 min).
        assert!(c.entries.get("device-aabbccdd").unwrap().is_valid(NOW));
        // Expired after grace.
        assert!(!c.entries.get("device-aabbccdd").unwrap().is_valid(NOW + ROOM_GRACE_SECS + 1));
    }

    #[test]
    fn clear_all_room_membership() {
        let mut c = NodeCache::new();
        c.mark_room_member("dev-1");
        c.mark_room_member("dev-2");
        c.clear_all_room_membership(NOW);
        assert!(!c.entries.get("dev-1").unwrap().in_room);
        assert!(!c.entries.get("dev-2").unwrap().in_room);
        // Still valid during grace.
        assert!(c.entries.get("dev-1").unwrap().is_valid(NOW));
    }

    #[test]
    fn rule_active_is_valid() {
        let mut c = NodeCache::new();
        c.mark_rule_active("device-aabbccdd");
        assert!(c.is_valid("device-aabbccdd"));
        c.clear_rule_active("device-aabbccdd", NOW);
        // Still valid during rule grace (24h).
        assert!(c.entries.get("device-aabbccdd").unwrap().is_valid(NOW));
        // Expired after grace.
        assert!(!c.entries.get("device-aabbccdd").unwrap().is_valid(NOW + RULE_GRACE_SECS + 1));
    }

    #[test]
    fn comm_extension() {
        let mut c = NodeCache::new();
        c.extend_comm("device-aabbccdd", NOW);
        assert!(c.entries.get("device-aabbccdd").unwrap().is_valid(NOW));
        assert!(!c.entries.get("device-aabbccdd").unwrap().is_valid(NOW + COMM_GRACE_SECS + 1));
    }

    #[test]
    fn comm_renewal_threshold() {
        let mut c = NodeCache::new();
        c.extend_comm("device-aabbccdd", NOW);
        let first_deadline = c.entries.get("device-aabbccdd").unwrap().comm_until.unwrap();
        // Tiny extension (less than threshold) should not change the deadline.
        c.extend_comm("device-aabbccdd", NOW + 10);
        assert_eq!(c.entries.get("device-aabbccdd").unwrap().comm_until.unwrap(), first_deadline);
        // Large extension should update.
        c.extend_comm("device-aabbccdd", NOW + COMM_GRACE_SECS);
        assert!(c.entries.get("device-aabbccdd").unwrap().comm_until.unwrap() > first_deadline);
    }

    #[test]
    fn drain_expired_removes_valid_entries() {
        let mut c = NodeCache::new();
        c.mark_room_member("dev-1");
        c.extend_comm("dev-2", NOW);
        // At NOW, both are valid.
        let expired = c.drain_expired(NOW);
        assert!(expired.is_empty());
        // After comm TTL, dev-2 expires.
        let expired = c.drain_expired(NOW + COMM_GRACE_SECS + 1);
        assert_eq!(expired, vec!["dev-2"]);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn multiple_reasons_keep_alive() {
        let mut c = NodeCache::new();
        c.mark_room_member("dev-1");
        c.extend_comm("dev-1", NOW);
        // Leave room — comm still keeps it alive.
        c.mark_left_room("dev-1", NOW);
        assert!(c.entries.get("dev-1").unwrap().is_valid(NOW + ROOM_GRACE_SECS + 1));
        // After comm also expires, it's gone.
        assert!(!c.entries.get("dev-1").unwrap().is_valid(NOW + COMM_GRACE_SECS + 1));
    }

    #[test]
    fn has_data_tracking() {
        let mut c = NodeCache::new();
        assert!(!c.has_data("dev-1"));
        c.mark_fetched("dev-1");
        assert!(c.has_data("dev-1"));
    }

    #[test]
    fn snapshot_and_restore() {
        let mut c = NodeCache::new();
        c.mark_rule_active("dev-1");
        c.mark_rule_active("dev-2");
        c.mark_fetched("dev-1");

        let pl = crate::peer_list::PeerList::new();
        let snapshot = c.snapshot(&pl);
        assert_eq!(snapshot.len(), 2);

        // Restore into a fresh cache.
        let mut c2 = NodeCache::new();
        c2.restore(snapshot, NOW);
        assert_eq!(c2.len(), 2);
        assert!(c2.has_data("dev-1"));
        assert!(c2.is_valid("dev-2"));
    }
}