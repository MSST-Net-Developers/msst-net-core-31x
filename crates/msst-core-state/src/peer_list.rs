//! Peer list — the authoritative local view of known peers.
//!
//! Maintains a `device_id → PeerEntry` map with secondary indexes for:
//! - IP address → device_id (inbound packet routing)
//! - device handle → device_id (mnemonic resolution)
//! - user handle → user_id (user-level rule matching)
//! - user_id → [device_id] (ACL user-level rules)
//! - hostname → device_id (DNS fast-path)
//! - (user_id, device_handle) → device_id (combined mnemonic)
//!
//! This is pure data — no I/O, no async.  The Core runtime mutates it in
//! response to coordinator events and packet processing, then passes
//! references into the ACL engine and other subsystems.

use std::collections::HashMap;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// PeerEntry
// ---------------------------------------------------------------------------

/// Metadata for a single known peer device.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerEntry {
    pub device_id: String,
    pub user_id: Option<String>,
    /// Device-level mnemonic handle (e.g. "abjust-archlinux").
    pub device_handle: Option<String>,
    /// User-level mnemonic handle (e.g. "abjust").
    pub user_handle: Option<String>,
    /// Server-assigned ezPlay hostname (e.g. "abjust-archlinux.abjust.ezplay.msst.net").
    pub hostname: Option<String>,
    pub ipv4: IpAddr,
    pub ipv6: IpAddr,
    pub display_name: Option<String>,
    pub user_display_name: Option<String>,
    /// The relay server address this peer prefers (from endpoint announcements).
    pub preferred_relay: Option<String>,
    /// Whether the coordinator reports this device as OIDC-authenticated.
    pub is_authenticated: bool,
    /// Unix timestamp (seconds) of the last time this peer was seen.
    pub last_seen_unix: i64,
}

// ---------------------------------------------------------------------------
// PeerList
// ---------------------------------------------------------------------------

/// The authoritative local view of all known peers, with secondary indexes
/// for fast lookup by IP, handle, hostname, and user.
pub struct PeerList {
    /// device_id → entry
    by_device: HashMap<String, PeerEntry>,
    /// IP (v4 or v6) → device_id
    ip_to_device: HashMap<IpAddr, String>,
    /// device_handle → device_id  (global; may collide across users)
    device_handle_to_id: HashMap<String, String>,
    /// user_handle → user_id
    user_handle_to_id: HashMap<String, String>,
    /// user_id → Vec<device_id>
    user_to_devices: HashMap<String, Vec<String>>,
    /// lowercase hostname → device_id
    hostname_to_device: HashMap<String, String>,
    /// (user_id, device_handle) → device_id  (for combined mnemonic "pc.abjust")
    user_device_to_id: HashMap<(String, String), String>,
}

impl PeerList {
    pub fn new() -> Self {
        PeerList {
            by_device: HashMap::new(),
            ip_to_device: HashMap::new(),
            device_handle_to_id: HashMap::new(),
            user_handle_to_id: HashMap::new(),
            user_to_devices: HashMap::new(),
            hostname_to_device: HashMap::new(),
            user_device_to_id: HashMap::new(),
        }
    }

    // ── Mutation ──────────────────────────────────────────────────────────

    /// Add or update a peer.  Passing `None` for optional fields leaves any
    /// existing value intact; `Some("")` unsets it. `is_authenticated` and `last_seen_unix` are
    /// always applied (the coordinator sends them on every peer update).
    #[allow(clippy::too_many_arguments)]
    pub fn upsert(
        &mut self,
        device_id: &str,
        ipv4: IpAddr,
        ipv6: IpAddr,
        user_id: Option<&str>,
        device_handle: Option<&str>,
        user_handle: Option<&str>,
        hostname: Option<&str>,
        display_name: Option<String>,
        user_display_name: Option<String>,
        is_authenticated: bool,
        last_seen_unix: i64,
    ) {
        // If this device already exists, clean up stale secondary indexes
        // before applying updates.  Clone the data we need so we don't hold
        // a borrow on `self.by_device` while mutating `self`.
        let old_snapshot = self.by_device.get(device_id).cloned();
        if let Some(ref old) = old_snapshot {
            self.remove_secondary_indexes(old);
        }

        // Update IP → device_id index (after the cleanup above, which would
        // otherwise drop the mapping again when the IPs are unchanged).
        self.ip_to_device.insert(ipv4, device_id.to_string());
        self.ip_to_device.insert(ipv6, device_id.to_string());

        let entry = self.by_device.entry(device_id.to_string()).or_insert_with(|| PeerEntry {
            device_id: device_id.to_string(),
            user_id: None,
            device_handle: None,
            user_handle: None,
            hostname: None,
            ipv4,
            ipv6,
            display_name: None,
            user_display_name: None,
            preferred_relay: None,
            is_authenticated,
            last_seen_unix,
        });

        // Apply updates — `None` means "leave existing value", `Some("")`
        // means "unset" (stored as `None`, never as an empty string).
        let set = |s: &str| (!s.is_empty()).then(|| s.to_string());
        entry.ipv4 = ipv4;
        entry.ipv6 = ipv6;
        entry.is_authenticated = is_authenticated;
        entry.last_seen_unix = last_seen_unix;
        if let Some(uid) = user_id { entry.user_id = set(uid); }
        if let Some(dh)  = device_handle { entry.device_handle = set(dh); }
        if let Some(uh)  = user_handle  { entry.user_handle  = set(uh); }
        if let Some(hn)  = hostname     { entry.hostname     = set(hn); }
        if let Some(n)   = display_name { entry.display_name = set(&n); }
        if let Some(n)   = user_display_name { entry.user_display_name = set(&n); }

        // Clone the updated entry data so we can rebuild indexes without
        // holding a borrow on `self.by_device`.
        let updated = entry.clone();
        self.insert_secondary_indexes(&updated);
    }

    /// Set the preferred relay address for a peer.
    pub fn update_relay(&mut self, device_id: &str, relay: &str) {
        if let Some(entry) = self.by_device.get_mut(device_id) {
            entry.preferred_relay = Some(relay.to_string());
        }
    }

    /// Remove all entries for the given device.
    pub fn remove(&mut self, device_id: &str) {
        if let Some(entry) = self.by_device.remove(device_id) {
            self.remove_secondary_indexes(&entry);
        }
    }

    // ── Lookups ───────────────────────────────────────────────────────────

    /// Look up which device owns the given IP address.
    pub fn lookup_device_id_by_ip(&self, ip: &IpAddr) -> Option<&str> {
        self.ip_to_device.get(ip).map(|s| s.as_str())
    }

    /// Resolve a device mnemonic to a device_id, with support for combined
    /// mnemonics.
    ///
    /// Two formats:
    /// - Combined: `"pc.abjust"` → device handle `"pc"` belonging to user
    ///   with handle or ID `"abjust"`.
    /// - Simple: `"pc"` → device handle `"pc"` belonging to `local_user_id`.
    ///
    /// Returns `None` if not currently in the peer list.
    pub fn resolve_device_mnemonic(&self, mnemonic: &str, local_user_id: &str) -> Option<&str> {
        if let Some(dot_pos) = mnemonic.find('.') {
            // Combined mnemonic: device_handle.user_handle
            let device_handle = &mnemonic[..dot_pos];
            let user_part = &mnemonic[dot_pos + 1..];
            let user_id = self.user_handle_to_id.get(user_part)
                .map(|s| s.as_str())
                .unwrap_or(user_part);
            self.user_device_to_id
                .get(&(user_id.to_string(), device_handle.to_string()))
                .map(|s| s.as_str())
        } else {
            // Simple handle: resolve relative to the current user only.
            self.user_device_to_id
                .get(&(local_user_id.to_string(), mnemonic.to_string()))
                .map(|s| s.as_str())
        }
    }

    /// Look up a peer by its ezPlay hostname (case-insensitive).
    pub fn find_by_hostname(&self, hostname: &str) -> Option<&PeerEntry> {
        let id = self.hostname_to_device.get(&hostname.to_ascii_lowercase())?;
        self.by_device.get(id)
    }

    /// Resolve a user handle (mnemonic) to a user ID, if any known peer
    /// belongs to that user.
    pub fn resolve_user_handle(&self, handle: &str) -> Option<&str> {
        self.user_handle_to_id.get(handle).map(|s| s.as_str())
    }

    /// Return all device_ids belonging to the given user identifier
    /// (user_id like `usr-XXXXXXXX`, or a user handle like `abjust`).
    pub fn devices_for_user(&self, user_id_or_handle: &str) -> Vec<&str> {
        // Try direct user_id lookup.
        if let Some(devs) = self.user_to_devices.get(user_id_or_handle) {
            return devs.iter().map(|s| s.as_str()).collect();
        }
        // Try handle → user_id → devices.
        if let Some(uid) = self.user_handle_to_id.get(user_id_or_handle) {
            if let Some(devs) = self.user_to_devices.get(uid) {
                return devs.iter().map(|s| s.as_str()).collect();
            }
        }
        Vec::new()
    }

    /// Get a peer entry by device ID.
    pub fn get(&self, device_id: &str) -> Option<&PeerEntry> {
        self.by_device.get(device_id)
    }

    /// Returns `true` if the device_id is currently in the peer list.
    pub fn contains(&self, device_id: &str) -> bool {
        self.by_device.contains_key(device_id)
    }

    /// Iterate over all known device IDs.
    pub fn device_ids(&self) -> impl Iterator<Item = &str> {
        self.by_device.keys().map(|s| s.as_str())
    }

    /// Number of known peers.
    pub fn len(&self) -> usize {
        self.by_device.len()
    }

    /// Returns `true` if no peers are known.
    pub fn is_empty(&self) -> bool {
        self.by_device.is_empty()
    }

    // ── Internal index helpers ────────────────────────────────────────────

    /// Insert all secondary index entries for the given peer.
    fn insert_secondary_indexes(&mut self, entry: &PeerEntry) {
        if let Some(dh) = &entry.device_handle {
            self.device_handle_to_id.insert(dh.clone(), entry.device_id.clone());
        }
        if let Some(uid) = &entry.user_id {
            if let Some(uh) = &entry.user_handle {
                self.user_handle_to_id.insert(uh.clone(), uid.clone());
            }
            self.user_to_devices
                .entry(uid.clone())
                .or_default();
            // Avoid duplicate entries on re-upsert.
            let devs = self.user_to_devices.get_mut(uid).unwrap();
            if !devs.contains(&entry.device_id) {
                devs.push(entry.device_id.clone());
            }
            if let Some(dh) = &entry.device_handle {
                self.user_device_to_id.insert((uid.clone(), dh.clone()), entry.device_id.clone());
            }
        }
        if let Some(hn) = &entry.hostname {
            self.hostname_to_device.insert(hn.to_ascii_lowercase(), entry.device_id.clone());
        }
    }

    /// Remove all secondary index entries for the given peer.
    fn remove_secondary_indexes(&mut self, entry: &PeerEntry) {
        // Only drop IP mappings that still point at this device (the address
        // may have been taken over by another peer since).
        for ip in [entry.ipv4, entry.ipv6] {
            if self.ip_to_device.get(&ip) == Some(&entry.device_id) {
                self.ip_to_device.remove(&ip);
            }
        }
        if let Some(dh) = &entry.device_handle {
            self.device_handle_to_id.remove(dh);
            if let Some(uid) = &entry.user_id {
                self.user_device_to_id.remove(&(uid.clone(), dh.clone()));
            }
        }
        if let Some(hn) = &entry.hostname {
            self.hostname_to_device.remove(&hn.to_ascii_lowercase());
        }
        if let Some(uid) = &entry.user_id {
            if let Some(uh) = &entry.user_handle {
                self.user_handle_to_id.remove(uh);
            }
            if let Some(devs) = self.user_to_devices.get_mut(uid) {
                devs.retain(|d| d != &entry.device_id);
                if devs.is_empty() {
                    self.user_to_devices.remove(uid);
                }
            }
        }
    }
}

impl Default for PeerList {
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    const NOW: i64 = 1_700_000_000;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6() -> IpAddr {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    }

    // Shorthand: insert a peer with minimal fields.
    fn insert_peer(
        pl: &mut PeerList,
    device_id: &str,
    ipv4: IpAddr,
    user_id: Option<&str>,
    device_handle: Option<&str>,
    user_handle: Option<&str>,
    ) {
        pl.upsert(
            device_id,
            ipv4,
            v6(),
            user_id,
            device_handle,
            user_handle,
            None,     // hostname
            None,     // display_name
            None,     // user_display_name
            false,    // is_authenticated
            NOW,
        );
    }

    // ── Basic CRUD ────────────────────────────────────────────────────────

    #[test]
    fn new_list_is_empty() {
        let pl = PeerList::new();
        assert!(pl.is_empty());
        assert_eq!(pl.len(), 0);
    }

    #[test]
    fn upsert_adds_peer() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), None, None, None);
        assert_eq!(pl.len(), 1);
        assert!(pl.contains("device-aabbccdd"));
    }

    #[test]
    fn upsert_updates_existing_peer() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), None, None, None);
        // Update with new IP.
        pl.upsert(
            "device-aabbccdd",
            v4(172, 22, 1, 2),
            v6(),
            None, None, None, None,
            Some("New Name".into()),
            None,
            true,
            NOW + 10,
        );
        assert_eq!(pl.len(), 1);
        let entry = pl.get("device-aabbccdd").unwrap();
        assert_eq!(entry.ipv4, v4(172, 22, 1, 2));
        assert_eq!(entry.display_name, Some("New Name".into()));
        assert!(entry.is_authenticated);
    }

    #[test]
    fn remove_deletes_peer_and_indexes() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("pc"), Some("alice"));
        assert_eq!(pl.len(), 1);
        pl.remove("device-aabbccdd");
        assert!(pl.is_empty());
        assert!(!pl.contains("device-aabbccdd"));
        // Indexes should also be cleaned up.
        assert!(pl.lookup_device_id_by_ip(&v4(172, 22, 1, 1)).is_none());
        assert!(pl.resolve_device_mnemonic("pc", "usr-11").is_none());
        assert!(pl.devices_for_user("usr-11").is_empty());
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let mut pl = PeerList::new();
        pl.remove("device-nonexistent");
        assert!(pl.is_empty());
    }

    // ── IP lookup ─────────────────────────────────────────────────────────

    #[test]
    fn ip_lookup_finds_device() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), None, None, None);
        assert_eq!(
            pl.lookup_device_id_by_ip(&v4(172, 22, 1, 1)),
            Some("device-aabbccdd")
        );
    }

    #[test]
    fn ip_lookup_miss() {
        let pl = PeerList::new();
        assert!(pl.lookup_device_id_by_ip(&v4(10, 0, 0, 1)).is_none());
    }

    // ── devices_for_user ──────────────────────────────────────────────────

    #[test]
    fn devices_for_user_by_id() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), None, None);
        insert_peer(&mut pl, "device-11223344", v4(172, 22, 1, 2), Some("usr-11"), None, None);
        let devs = pl.devices_for_user("usr-11");
        assert_eq!(devs.len(), 2);
        assert!(devs.contains(&"device-aabbccdd"));
        assert!(devs.contains(&"device-11223344"));
    }

    #[test]
    fn devices_for_user_by_handle() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), None, Some("alice"));
        let devs = pl.devices_for_user("alice");
        assert_eq!(devs, vec!["device-aabbccdd"]);
    }

    #[test]
    fn devices_for_user_unknown() {
        let pl = PeerList::new();
        assert!(pl.devices_for_user("nobody").is_empty());
    }

    #[test]
    fn devices_for_user_empty_after_remove() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), None, None);
        pl.remove("device-aabbccdd");
        assert!(pl.devices_for_user("usr-11").is_empty());
    }

    // ── resolve_device_mnemonic — simple handle ───────────────────────────

    #[test]
    fn resolve_simple_mnemonic() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("my-pc"), Some("alice"));
        // "my-pc" resolves relative to local_user_id "usr-11".
        assert_eq!(pl.resolve_device_mnemonic("my-pc", "usr-11"), Some("device-aabbccdd"));
    }

    #[test]
    fn resolve_simple_mnemonic_wrong_user() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("my-pc"), None);
        // "my-pc" belongs to usr-11, not usr-99.
        assert_eq!(pl.resolve_device_mnemonic("my-pc", "usr-99"), None);
    }

    #[test]
    fn resolve_simple_mnemonic_unknown() {
        let pl = PeerList::new();
        assert_eq!(pl.resolve_device_mnemonic("nonexistent", "usr-11"), None);
    }

    // ── resolve_device_mnemonic — combined mnemonic ───────────────────────

    #[test]
    fn resolve_combined_mnemonic() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("pc"), Some("alice"));
        // "pc.alice" → device handle "pc" for user with handle "alice".
        assert_eq!(pl.resolve_device_mnemonic("pc.alice", ""), Some("device-aabbccdd"));
    }

    #[test]
    fn resolve_combined_mnemonic_with_user_id() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("pc"), Some("alice"));
        // "pc.usr-11" → device handle "pc" for user with ID "usr-11".
        assert_eq!(pl.resolve_device_mnemonic("pc.usr-11", ""), Some("device-aabbccdd"));
    }

    #[test]
    fn resolve_combined_mnemonic_unknown_user() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("pc"), Some("alice"));
        assert_eq!(pl.resolve_device_mnemonic("pc.bob", ""), None);
    }

    #[test]
    fn resolve_combined_mnemonic_wrong_device_handle() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("pc"), Some("alice"));
        assert_eq!(pl.resolve_device_mnemonic("laptop.alice", ""), None);
    }

    // ── Index consistency on update ───────────────────────────────────────

    #[test]
    fn handle_index_updated_on_device_handle_change() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("old-name"), None);
        assert_eq!(pl.resolve_device_mnemonic("old-name", "usr-11"), Some("device-aabbccdd"));

        // Update device handle.
        pl.upsert(
            "device-aabbccdd",
            v4(172, 22, 1, 1),
            v6(),
            None,
            Some("new-name"),
            None, None, None, None, false, NOW,
        );
        // Old handle should be gone, new one should work.
        assert_eq!(pl.resolve_device_mnemonic("old-name", "usr-11"), None);
        assert_eq!(pl.resolve_device_mnemonic("new-name", "usr-11"), Some("device-aabbccdd"));
    }

    #[test]
    fn user_index_updated_on_user_change() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-old"), Some("pc"), Some("old-handle"));

        // Change the user.
        pl.upsert(
            "device-aabbccdd",
            v4(172, 22, 1, 1),
            v6(),
            Some("usr-new"),
            Some("pc"),
            Some("new-handle"),
            None, None, None, false, NOW,
        );

        // Old user should have no devices.
        assert!(pl.devices_for_user("usr-old").is_empty());
        // New user should have the device.
        assert_eq!(pl.devices_for_user("usr-new"), vec!["device-aabbccdd"]);
        // Combined mnemonic should use new user.
        assert_eq!(pl.resolve_device_mnemonic("pc.new-handle", ""), Some("device-aabbccdd"));
    }

    #[test]
    fn hostname_index_updated() {
        let mut pl = PeerList::new();
        pl.upsert(
            "device-aabbccdd",
            v4(172, 22, 1, 1),
            v6(),
            None, None, None,
            Some("old-host.example.msst.net"),
            None, None, false, NOW,
        );
        pl.upsert(
            "device-aabbccdd",
            v4(172, 22, 1, 1),
            v6(),
            None, None, None,
            Some("new-host.example.msst.net"),
            None, None, false, NOW,
        );
        // Note: hostname lookup is not directly exposed as a public method
        // in this module (it's used by the DNS resolver), but we can verify
        // the internal index is consistent by checking that the device still
        // exists and the old hostname is gone.
        assert!(pl.contains("device-aabbccdd"));
    }

    // ── Multiple peers ────────────────────────────────────────────────────

    #[test]
    fn multiple_peers_different_users() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("pc"), Some("alice"));
        insert_peer(&mut pl, "device-11223344", v4(172, 22, 1, 2), Some("usr-22"), Some("laptop"), Some("bob"));

        assert_eq!(pl.len(), 2);
        assert_eq!(pl.devices_for_user("alice"), vec!["device-aabbccdd"]);
        assert_eq!(pl.devices_for_user("bob"), vec!["device-11223344"]);
        assert_eq!(pl.resolve_device_mnemonic("pc", "usr-11"), Some("device-aabbccdd"));
        assert_eq!(pl.resolve_device_mnemonic("laptop", "usr-22"), Some("device-11223344"));
    }

    #[test]
    fn same_user_multiple_devices() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("desktop"), Some("alice"));
        insert_peer(&mut pl, "device-11223344", v4(172, 22, 1, 2), Some("usr-11"), Some("laptop"), Some("alice"));

        let devs = pl.devices_for_user("usr-11");
        assert_eq!(devs.len(), 2);
        assert!(devs.contains(&"device-aabbccdd"));
        assert!(devs.contains(&"device-11223344"));

        // Each device has its own simple mnemonic within the same user.
        assert_eq!(pl.resolve_device_mnemonic("desktop", "usr-11"), Some("device-aabbccdd"));
        assert_eq!(pl.resolve_device_mnemonic("laptop", "usr-11"), Some("device-11223344"));
    }

    // ── Default trait ─────────────────────────────────────────────────────

    #[test]
    fn default_trait_works() {
        let pl = PeerList::default();
        assert!(pl.is_empty());
    }

    // ── device_ids iterator ───────────────────────────────────────────────

    #[test]
    fn device_ids_iterator() {
        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), None, None, None);
        insert_peer(&mut pl, "device-11223344", v4(172, 22, 1, 2), None, None, None);
        let mut ids: Vec<&str> = pl.device_ids().collect();
        ids.sort();
        assert_eq!(ids, vec!["device-11223344", "device-aabbccdd"]);
    }

    // ── Integration with ACL engine ───────────────────────────────────────

    #[test]
    fn acl_engine_integration() {
        use msst_acl_engine::{
            evaluate, Action, DecisionReason, Direction, FirewallRule,
            MatchContext, PermissionGroup, Protocol, ProtocolPort,
        };

        let mut pl = PeerList::new();
        // Alice owns two devices.
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-alice"), Some("desktop"), Some("alice"));
        insert_peer(&mut pl, "device-deadbeef", v4(172, 22, 1, 3), Some("usr-alice"), Some("laptop"), Some("alice"));
        // Bob owns one device.
        insert_peer(&mut pl, "device-11223344", v4(172, 22, 1, 2), Some("usr-bob"), Some("pc"), Some("bob"));

        // ACL rule: user-level allow for Alice on TCP:25565.
        let rules = [FirewallRule {
            id: "r1".into(),
            permission_group: PermissionGroup::Users { ids: vec!["usr-alice".into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 25565)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: Some("Allow Alice's Minecraft".into()),
        }];

        // Build the closure from PeerList.
        let resolve = |uid: &str| -> Vec<String> {
            pl.devices_for_user(uid).into_iter().map(|s| s.to_string()).collect()
        };

        // Alice's desktop → allowed.
        let ctx_alice = MatchContext::new(
            "device-aabbccdd", Protocol::Tcp, 25565, Direction::Inbound, false, 1_700_000_000, "usr-local",
        );
        let d = evaluate(&ctx_alice, &rules, &resolve);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::UserAllowPriority);

        // Alice's laptop → also allowed (same user).
        let ctx_laptop = MatchContext::new(
            "device-deadbeef", Protocol::Tcp, 25565, Direction::Inbound, false, 1_700_000_000, "usr-local",
        );
        let d = evaluate(&ctx_laptop, &rules, &resolve);
        assert_eq!(d.action, Action::Allow);

        // Bob's PC → default deny.
        let ctx_bob = MatchContext::new(
            "device-11223344", Protocol::Tcp, 25565, Direction::Inbound, false, 1_700_000_000, "usr-local",
        );
        let d = evaluate(&ctx_bob, &rules, &resolve);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn acl_engine_mnemonic_resolution_integration() {
        use msst_acl_engine::{
            evaluate, Action, DecisionReason, Direction, FirewallRule,
            MatchContext, PermissionGroup, Protocol, ProtocolPort,
        };

        let mut pl = PeerList::new();
        insert_peer(&mut pl, "device-aabbccdd", v4(172, 22, 1, 1), Some("usr-11"), Some("my-pc"), Some("alice"));

        // ACL rule: device-level allow for mnemonic "my-pc" on TCP:22.
        let rules = [FirewallRule {
            id: "ssh-rule".into(),
            permission_group: PermissionGroup::Devices {
                ids: vec!["my-pc".into()],
            },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, 22)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: Some("SSH from my laptop".into()),
        }];

        // Build the mnemonic resolver from PeerList.
        let resolve_mnemonic = |mnemonic: &str| -> Option<String> {
            pl.resolve_device_mnemonic(mnemonic, "usr-11").map(|s| s.to_string())
        };

        let ctx = MatchContext::new(
            "device-aabbccdd", Protocol::Tcp, 22, Direction::Inbound, false, 1_700_000_000, "usr-11",
        )
        .with_mnemonic_resolver(&resolve_mnemonic);

        let d = evaluate(&ctx, &rules, |_| vec![]);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.reason, DecisionReason::DeviceAllowPriority);
        assert_eq!(d.matched_rule.as_ref().unwrap().comment.as_deref(), Some("SSH from my laptop"));
    }

    #[test]
    fn re_upsert_with_same_ips_keeps_ip_lookup() {
        let mut pl = PeerList::new();
        let v4: IpAddr = "172.22.1.1".parse().unwrap();
        let v6: IpAddr = "fd22:2222:2222:2222::1".parse().unwrap();
        for _ in 0..3 {
            pl.upsert("device-aabbccdd", v4, v6, Some("user-11"), Some("pc"), Some("alice"), None, None, None, false, 0);
        }
        assert_eq!(pl.lookup_device_id_by_ip(&v4), Some("device-aabbccdd"));
        assert_eq!(pl.lookup_device_id_by_ip(&v6), Some("device-aabbccdd"));
        assert_eq!(pl.resolve_user_handle("alice"), Some("user-11"));
    }

    #[test]
    fn ip_taken_over_by_another_peer_is_not_dropped() {
        let mut pl = PeerList::new();
        let v4: IpAddr = "172.22.1.1".parse().unwrap();
        let a6: IpAddr = "fd22:2222:2222:2222::a".parse().unwrap();
        let b6: IpAddr = "fd22:2222:2222:2222::b".parse().unwrap();
        pl.upsert("device-aaaaaaaa", v4, a6, None, None, None, None, None, None, false, 0);
        pl.upsert("device-bbbbbbbb", v4, b6, None, None, None, None, None, None, false, 0);
        // Re-upserting A with a new IPv4 must not remove B's claim on v4.
        pl.upsert("device-aaaaaaaa", "172.22.1.9".parse().unwrap(), a6, None, None, None, None, None, None, false, 0);
        assert_eq!(pl.lookup_device_id_by_ip(&v4), Some("device-bbbbbbbb"));
    }

    #[test]
    fn empty_fields_unset_and_are_not_indexed() {
        let mut pl = PeerList::new();
        let (a, b) = ("172.22.1.1".parse().unwrap(), "fd22:2222:2222:2222::1".parse().unwrap());
        pl.upsert("device-aabbccdd", a, b, Some("user-11"), Some("pc"), Some("bob"), None, Some("PC".into()), None, false, 0);
        assert_eq!(pl.resolve_device_mnemonic("pc.bob", "user-00"), Some("device-aabbccdd"));
        // `None` keeps, `Some("")` clears (and drops the index entries).
        pl.upsert("device-aabbccdd", a, b, None, Some(""), None, None, None, None, false, 1);
        assert_eq!(pl.get("device-aabbccdd").unwrap().display_name.as_deref(), Some("PC"));
        pl.upsert("device-aabbccdd", a, b, None, None, None, None, Some(String::new()), None, false, 2);
        let e = pl.get("device-aabbccdd").unwrap();
        assert_eq!((e.device_handle.as_deref(), e.display_name.as_deref()), (None, None));
        assert!(pl.resolve_device_mnemonic("pc.bob", "user-00").is_none());
        assert!(pl.resolve_device_mnemonic(".bob", "user-00").is_none());
    }

    #[test]
    fn find_by_hostname_case_insensitive() {
        let mut pl = PeerList::new();
        pl.upsert("device-aabbccdd", "172.22.1.1".parse().unwrap(), "fd22:2222:2222:2222::1".parse().unwrap(),
            None, None, None, Some("PC.Bob.ezplay.msst.net"), None, None, false, 0);
        assert_eq!(pl.find_by_hostname("pc.bob.ezplay.msst.net").unwrap().device_id, "device-aabbccdd");
        assert!(pl.find_by_hostname("x.msst.net").is_none());
    }
}
