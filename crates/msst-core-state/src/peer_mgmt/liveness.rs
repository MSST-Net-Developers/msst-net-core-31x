//! Liveness tracker — per-peer "last seen" timestamps.
//!
//! Tracks when we last received any packet from each peer.  Used by the
//! node cache (eviction decisions) and by the peer manager (stale peer
//! detection).
//!
//! This is deliberately separate from the connection tracker (which tracks
//! 5-tuples for the "related traffic" fast path) and from the peer traffic
//! counters (which count packets for statistics).

use std::collections::HashMap;

/// Per-peer liveness entry.
#[derive(Debug, Clone)]
pub struct LivenessEntry {
    /// Unix timestamp (seconds) of the last packet received from this peer.
    pub last_seen_unix: i64,
}

// ---------------------------------------------------------------------------
// LivenessTracker
// ---------------------------------------------------------------------------

/// Tracks per-peer "last seen" timestamps.
pub struct LivenessTracker {
    entries: HashMap<String, LivenessEntry>,
}

impl LivenessTracker {
    pub fn new() -> Self {
        LivenessTracker {
            entries: HashMap::new(),
        }
    }

    /// Record that we saw a packet from this peer at `now_unix`.
    pub fn touch(&mut self, device_id: &str, now_unix: i64) {
        let entry = self.entries.entry(device_id.to_string()).or_insert_with(|| LivenessEntry {
            last_seen_unix: now_unix,
        });
        // Only update if the new timestamp is newer (guards against out-of-order
        // calls from concurrent tasks).
        if now_unix > entry.last_seen_unix {
            entry.last_seen_unix = now_unix;
        }
    }

    /// Get the last-seen timestamp for a peer.
    pub fn last_seen(&self, device_id: &str) -> Option<i64> {
        self.entries.get(device_id).map(|e| e.last_seen_unix)
    }

    /// Returns `true` if we have liveness data for this peer.
    pub fn contains(&self, device_id: &str) -> bool {
        self.entries.contains_key(device_id)
    }

    /// Remove liveness data for a peer.
    pub fn remove(&mut self, device_id: &str) {
        self.entries.remove(device_id);
    }

    /// Remove peers whose `last_seen` is older than `max_age_secs` relative
    /// to `now_unix`.  Returns the removed device IDs.
    pub fn evict_stale(&mut self, now_unix: i64, max_age_secs: i64) -> Vec<String> {
        let stale: Vec<String> = self.entries
            .iter()
            .filter(|(_, e)| now_unix - e.last_seen_unix > max_age_secs)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &stale {
            self.entries.remove(id);
        }
        stale
    }

    /// Number of tracked peers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for LivenessTracker {
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

    #[test]
    fn new_tracker_is_empty() {
        let t = LivenessTracker::new();
        assert!(t.is_empty());
        assert!(!t.contains("dev-1"));
        assert!(t.last_seen("dev-1").is_none());
    }

    #[test]
    fn touch_records_timestamp() {
        let mut t = LivenessTracker::new();
        t.touch("dev-1", 1000);
        assert_eq!(t.last_seen("dev-1"), Some(1000));
        assert!(t.contains("dev-1"));
    }

    #[test]
    fn touch_updates_only_if_newer() {
        let mut t = LivenessTracker::new();
        t.touch("dev-1", 1000);
        t.touch("dev-1", 900); // older — should not update
        assert_eq!(t.last_seen("dev-1"), Some(1000));
        t.touch("dev-1", 1100); // newer — should update
        assert_eq!(t.last_seen("dev-1"), Some(1100));
    }

    #[test]
    fn remove_clears_entry() {
        let mut t = LivenessTracker::new();
        t.touch("dev-1", 1000);
        t.remove("dev-1");
        assert!(!t.contains("dev-1"));
        assert!(t.last_seen("dev-1").is_none());
    }

    #[test]
    fn evict_stale_removes_old_entries() {
        let mut t = LivenessTracker::new();
        t.touch("dev-old", 1000);
        t.touch("dev-new", 2000);
        let evicted = t.evict_stale(2000, 500); // max_age = 500
        assert_eq!(evicted, vec!["dev-old"]);
        assert_eq!(t.len(), 1);
        assert!(t.contains("dev-new"));
    }

    #[test]
    fn evict_stale_no_eviction_if_all_fresh() {
        let mut t = LivenessTracker::new();
        t.touch("dev-1", 1000);
        t.touch("dev-2", 1000);
        let evicted = t.evict_stale(1400, 500);
        assert!(evicted.is_empty());
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn multiple_peers() {
        let mut t = LivenessTracker::new();
        t.touch("dev-a", 100);
        t.touch("dev-b", 200);
        t.touch("dev-c", 300);
        assert_eq!(t.len(), 3);
        assert_eq!(t.last_seen("dev-a"), Some(100));
        assert_eq!(t.last_seen("dev-b"), Some(200));
        assert_eq!(t.last_seen("dev-c"), Some(300));
    }

    #[test]
    fn default_trait_works() {
        let t = LivenessTracker::default();
        assert!(t.is_empty());
    }
}