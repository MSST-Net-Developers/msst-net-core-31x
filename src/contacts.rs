//! Recent-contact tracking (`contacts.json`) — ported from 3.0.x.
//!
//! Remembers devices we shared a room with, and refreshes them when traffic
//! from them passes the firewall.  A contact is "recent" for 7 days.  Used
//! by interactive authorization in large-LAN mode.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info};

pub const FILE: &str = "contacts.json";
/// A contact is recent if either timestamp is within this window.
pub const TTL_SECS: i64 = 7 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContactEntry {
    pub device_id: String,
    pub user_id: Option<String>,
    /// Unix seconds we were last in the same room.
    pub last_room_together: Option<i64>,
    /// Unix seconds traffic from this device last passed the firewall.
    pub last_communicated: Option<i64>,
}

impl ContactEntry {
    fn is_recent(&self, now: i64) -> bool {
        let within = |t: Option<i64>| t.is_some_and(|ts| now - ts < TTL_SECS);
        within(self.last_room_together) || within(self.last_communicated)
    }
}

#[derive(Debug, Default)]
pub struct ContactList {
    entries: HashMap<String, ContactEntry>,
    dirty: bool,
}

impl ContactList {
    /// Record that `device_id` was in a room with us at `now`.
    pub fn update_room_contact(&mut self, device_id: &str, user_id: Option<&str>, now: i64) {
        let entry = self.entries.entry(device_id.to_string()).or_insert_with(|| {
            info!("contacts: added {} via room", device_id);
            ContactEntry { device_id: device_id.to_string(), user_id: None, last_room_together: None, last_communicated: None }
        });
        entry.last_room_together = Some(now);
        if let Some(uid) = user_id {
            entry.user_id = Some(uid.to_string());
        }
        self.dirty = true;
    }

    /// Record allowed traffic from `device_id`.  Only refreshes existing
    /// contacts — raw packets never create one.  Hot path.
    pub fn update_communication(&mut self, device_id: &str, now: i64) {
        if let Some(e) = self.entries.get_mut(device_id) {
            e.last_communicated = Some(now);
            self.dirty = true;
        }
    }

    pub fn is_recent_contact(&self, device_id: &str, now: i64) -> bool {
        self.entries.get(device_id).is_some_and(|e| e.is_recent(now))
    }

    /// Drop entries older than the TTL.
    pub fn prune(&mut self, now: i64) {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.is_recent(now));
        if self.entries.len() != before {
            info!("contacts: pruned {} stale entries", before - self.entries.len());
            self.dirty = true;
        }
    }

    /// Entries sorted by device ID (stable output).
    pub fn entries(&self) -> Vec<ContactEntry> {
        let mut v: Vec<_> = self.entries.values().cloned().collect();
        v.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        v
    }

    /// Serialized file contents if changed since the last call, else `None`.
    pub fn take_dirty_snapshot(&mut self) -> Option<Vec<u8>> {
        if !self.dirty {
            return None;
        }
        self.dirty = false;
        serde_json::to_vec_pretty(&self.entries()).ok()
    }

    pub fn load(dir: &Path) -> Result<Self, String> {
        let path = dir.join(FILE);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path).map_err(|e| format!("read {:?}: {}", path, e))?;
        let entries: Vec<ContactEntry> = serde_json::from_str(&text).map_err(|e| format!("parse {:?}: {}", path, e))?;
        debug!("contacts: loaded {} entries", entries.len());
        Ok(ContactList { entries: entries.into_iter().map(|e| (e.device_id.clone(), e)).collect(), dirty: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn room_contact_then_communication() {
        let mut c = ContactList::default();
        c.update_communication("device-a", NOW); // unknown → ignored
        assert!(!c.is_recent_contact("device-a", NOW));
        c.update_room_contact("device-a", Some("user-a"), NOW - TTL_SECS + 10);
        assert!(c.is_recent_contact("device-a", NOW));
        assert!(!c.is_recent_contact("device-a", NOW + 20));
        c.update_communication("device-a", NOW + 20);
        assert!(c.is_recent_contact("device-a", NOW + 20));
    }

    #[test]
    fn prune_and_dirty_tracking() {
        let mut c = ContactList::default();
        assert!(c.take_dirty_snapshot().is_none());
        c.update_room_contact("old", None, NOW - TTL_SECS - 1);
        c.update_room_contact("new", None, NOW);
        assert!(c.take_dirty_snapshot().is_some());
        assert!(c.take_dirty_snapshot().is_none());
        c.prune(NOW);
        assert_eq!(c.entries().len(), 1);
        assert!(c.take_dirty_snapshot().is_some());
    }

    #[test]
    fn reads_3_0_x_file() {
        let dir = std::env::temp_dir().join(format!("msst-contacts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(FILE), r#"[{"device_id":"device-a","user_id":null,"last_room_together":1700000000,"last_communicated":null}]"#).unwrap();
        let c = ContactList::load(&dir).unwrap();
        assert!(c.is_recent_contact("device-a", NOW));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
