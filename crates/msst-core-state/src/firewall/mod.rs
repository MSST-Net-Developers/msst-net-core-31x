//! Firewall — the stateful ACL container.
//!
//! This module ties together:
//! - **ACL rules** (`msst_acl_engine`) — pure rule matching
//! - **Interactive auth** (`auth`) — pending requests, packet queuing
//! - **Access log** (`access_log`) — ring buffer with dedup
//! - **Service catalog** (`services`) — well-known protocol/port definitions
//!
//! The `Firewall` struct is the single authority for all firewall state.
//! It does NOT own the `PeerList` or `ConnectionTracker` — those live in
//! `CoreState` and are passed by reference.

pub mod access_log;
pub mod auth;
pub mod services;

use access_log::{AccessLog, AccessLogEntry, AccessDecision, AccessReason};
use auth::{AuthKey, PendingAuth, AuthOutcome};
use msst_acl_engine as acl;
use services::ServiceCatalog;
use std::collections::VecDeque;
use tracing::{debug, info, warn};

/// Maximum number of packets buffered per pending auth request.
const AUTH_QUEUE_MAX_PACKETS: usize = 32;
/// Maximum total bytes buffered per pending auth request.
const AUTH_QUEUE_MAX_BYTES: usize = 256 * 1024;
/// Timeout for interactive auth requests (seconds).
const AUTH_TIMEOUT_SECS: i64 = 60;

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

/// The stateful firewall container.
///
/// Owns the ACL rule list, interactive auth state, access log, and ping
/// policy.  The pure rule matching is delegated to `msst_acl_engine::evaluate`.
pub struct Firewall {
    /// The ACL rules (managed by the API layer).
    pub rules: Vec<acl::FirewallRule>,
    /// Pending interactive auth requests.
    pub pending_auth: Vec<PendingAuth>,
    /// Whether ICMP echo-request (ping) is allowed.
    pub ping_enabled: bool,
    /// Ring buffer of recent access decisions.
    pub access_log: AccessLog,
    /// Well-known service definitions.
    pub services: ServiceCatalog,
    /// Unique ID generator for access log entries and auth requests.
    next_id: u64,
}

impl Firewall {
    pub fn new() -> Self {
        Firewall {
            rules: Vec::new(),
            pending_auth: Vec::new(),
            ping_enabled: false,
            access_log: AccessLog::new(500),
            services: ServiceCatalog::default(),
            next_id: 1,
        }
    }

    /// Generate a unique ID string (16 random hex chars, as 3.0.x).
    ///
    /// Random rather than sequential so a request ID from before a Core
    /// restart can never match a new request.
    fn next_id(&mut self) -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut bytes);
        self.next_id += 1;
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// A fresh unique ID (for access log entries).
    pub fn new_id(&mut self) -> String {
        self.next_id()
    }

    // ── ACL rule management ───────────────────────────────────────────────

    /// Add a rule. Returns the rule ID.
    pub fn add_rule(&mut self, rule: acl::FirewallRule) -> String {
        let id = rule.id.clone();
        self.rules.push(rule);
        info!("firewall: added rule {}", id);
        id
    }

    /// Update a rule's mutable fields (enabled, comment, expires_at).
    /// Returns `true` if found and updated.
    pub fn update_rule(&mut self, rule_id: &str, patch: RulePatch) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            if let Some(enabled) = patch.enabled {
                rule.enabled = enabled;
            }
            if let Some(comment) = patch.comment {
                rule.comment = Some(comment);
            }
            if let Some(expires_at) = patch.expires_at {
                rule.expires_at = Some(expires_at);
            }
            info!("firewall: updated rule {}", rule_id);
            true
        } else {
            warn!("firewall: rule {} not found for update", rule_id);
            false
        }
    }

    /// Delete a rule. Returns `true` if found and removed.
    pub fn delete_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        let removed = self.rules.len() < before;
        if removed {
            info!("firewall: deleted rule {}", rule_id);
        }
        removed
    }

    /// Get a rule by ID.
    pub fn get_rule(&self, rule_id: &str) -> Option<&acl::FirewallRule> {
        self.rules.iter().find(|r| r.id == rule_id)
    }

    /// Remove all expired rules. Returns the IDs of removed rules.
    pub fn cleanup_expired_rules(&mut self, now_unix: i64) -> Vec<String> {
        let expired: Vec<String> = self.rules
            .iter()
            .filter(|r| {
                r.enabled && r.expires_at.is_some_and(|exp| now_unix >= exp)
            })
            .map(|r| r.id.clone())
            .collect();
        self.rules.retain(|r| !expired.contains(&r.id));
        for id in &expired {
            info!("firewall: auto-removed expired rule {}", id);
        }
        expired
    }

    // ── Interactive auth ──────────────────────────────────────────────────

    /// Check if there is already a pending auth request for this key.
    pub fn has_pending_auth(&self, key: &AuthKey) -> bool {
        self.pending_auth.iter().any(|p| p.key == *key)
    }

    /// Register a new pending auth request.
    /// Returns the request ID.
    pub fn register_pending_auth(
        &mut self,
        key: AuthKey,
        src_device_id: String,
        log_entry_id: String,
    ) -> String {
        let request_id = self.next_id();
        info!(
            "firewall: pending auth for {} {:?}:{} (request {})",
            src_device_id, key.proto, key.dst_port, request_id
        );
        self.pending_auth.push(PendingAuth {
            key,
            request_id: request_id.clone(),
            created_at_unix: now_unix_secs(),
            queued_packets: VecDeque::new(),
            queued_bytes: 0,
            log_entry_id,
        });
        request_id
    }

    /// Enqueue a packet for a pending auth request.
    pub fn queue_packet_for_auth(&mut self, key: &AuthKey, packet: Vec<u8>) {
        if let Some(pending) = self.pending_auth.iter_mut().find(|p| p.key == *key) {
            if pending.queued_packets.len() < AUTH_QUEUE_MAX_PACKETS
                && pending.queued_bytes + packet.len() <= AUTH_QUEUE_MAX_BYTES
            {
                pending.queued_bytes += packet.len();
                pending.queued_packets.push_back(packet);
            } else {
                debug!("firewall: auth queue full for {:?}:{}, dropping", key.proto, key.dst_port);
            }
        }
    }

    /// Resolve a pending auth request (user decision).
    /// Returns the outcome if found.
    pub fn resolve_auth(
        &mut self,
        request_id: &str,
        decision: acl::Action,
        permanent: bool,
    ) -> Option<AuthOutcome> {
        let idx = self.pending_auth.iter().position(|p| p.request_id == request_id)?;
        let pending = self.pending_auth.remove(idx);

        info!(
            "firewall: auth resolved for {:?}:{} → {:?} (permanent={})",
            pending.key.proto, pending.key.dst_port, decision, permanent
        );

        // Update the access log entry.
        let log_decision = match decision {
            acl::Action::Allow => AccessDecision::Allow,
            acl::Action::Deny => AccessDecision::Deny,
        };
        self.access_log.update_decision(
            &pending.log_entry_id,
            log_decision.clone(),
            AccessReason::InteractiveAuth,
        );

        Some(AuthOutcome {
            key: pending.key,
            decision,
            permanent,
            queued_packets: pending.queued_packets,
            log_entry_id: pending.log_entry_id,
        })
    }

    /// Collect timed-out auth requests. Returns their request IDs and keys.
    pub fn collect_timed_out_auth(&mut self, now_unix: i64) -> Vec<(AuthKey, String, String)> {
        let timed_out: Vec<_> = self.pending_auth
            .iter()
            .filter(|p| now_unix - p.created_at_unix >= AUTH_TIMEOUT_SECS)
            .map(|p| (p.key.clone(), p.request_id.clone(), p.log_entry_id.clone()))
            .collect();

        for (_, request_id, _) in &timed_out {
            warn!("firewall: auth timed out (request {})", request_id);
        }

        let timeout_ids: Vec<_> = timed_out.iter().map(|(_, id, _)| id.clone()).collect();
        self.pending_auth.retain(|p| !timeout_ids.contains(&p.request_id));

        timed_out
    }

    /// Resolve timed-out auth entries in the access log (silent deny, as 3.0.x).
    pub fn resolve_timed_out_auth_log(&mut self, entries: &[(AuthKey, String, String)]) {
        for (_, _, log_entry_id) in entries {
            self.access_log.update_decision(
                log_entry_id,
                AccessDecision::SilentDeny,
                AccessReason::InteractiveAuthTimeout,
            );
        }
    }

    // ── ICMP ping policy ──────────────────────────────────────────────────

    /// Check if an ICMP echo-request should be allowed.
    pub fn check_icmp(&self, is_echo_request: bool) -> bool {
        if is_echo_request {
            self.ping_enabled
        } else {
            true // non-echo ICMP always allowed
        }
    }

    // ── Access log ────────────────────────────────────────────────────────

    /// Record an access decision in the log.
    pub fn log_access(&mut self, entry: AccessLogEntry) {
        self.access_log.append(entry);
    }

    /// Get recent access log entries.
    pub fn access_log_entries(&self) -> &[AccessLogEntry] {
        self.access_log.entries()
    }
}

impl Default for Firewall {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RulePatch — partial update for rules
// ---------------------------------------------------------------------------

/// Fields that can be updated on an existing rule.
pub struct RulePatch {
    pub enabled: Option<bool>,
    pub comment: Option<String>,
    pub expires_at: Option<i64>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_unix_secs() -> i64 {
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
    use acl::{Action, Direction, FirewallRule, PermissionGroup, Protocol, ProtocolPort};

    const NOW: i64 = 1_700_000_000;

    fn allow_rule(id: &str, port: u16) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            permission_group: PermissionGroup::Devices { ids: vec!["*".into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, port)],
            action: Action::Allow,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }
    }

    fn deny_rule(id: &str, port: u16) -> FirewallRule {
        FirewallRule {
            id: id.into(),
            permission_group: PermissionGroup::Devices { ids: vec!["*".into()] },
            protocol_ports: vec![ProtocolPort::single(Protocol::Tcp, port)],
            action: Action::Deny,
            direction: Direction::Inbound,
            expires_at: None,
            enabled: true,
            comment: None,
        }
    }

    // ── Rule management ───────────────────────────────────────────────────

    #[test]
    fn add_and_get_rule() {
        let mut fw = Firewall::new();
        fw.add_rule(allow_rule("r1", 80));
        assert!(fw.get_rule("r1").is_some());
        assert_eq!(fw.rules.len(), 1);
    }

    #[test]
    fn get_nonexistent_rule() {
        let fw = Firewall::new();
        assert!(fw.get_rule("nonexistent").is_none());
    }

    #[test]
    fn delete_rule() {
        let mut fw = Firewall::new();
        fw.add_rule(allow_rule("r1", 80));
        assert!(fw.delete_rule("r1"));
        assert!(fw.get_rule("r1").is_none());
        assert!(!fw.delete_rule("r1")); // already deleted
    }

    #[test]
    fn update_rule() {
        let mut fw = Firewall::new();
        fw.add_rule(allow_rule("r1", 80));
        assert!(fw.update_rule("r1", RulePatch {
            enabled: Some(false),
            comment: Some("disabled".into()),
            expires_at: None,
        }));
        let rule = fw.get_rule("r1").unwrap();
        assert!(!rule.enabled);
        assert_eq!(rule.comment.as_deref(), Some("disabled"));
    }

    #[test]
    fn update_nonexistent_rule() {
        let mut fw = Firewall::new();
        assert!(!fw.update_rule("nonexistent", RulePatch {
            enabled: Some(false),
            comment: None,
            expires_at: None,
        }));
    }

    #[test]
    fn cleanup_expired_rules() {
        let mut fw = Firewall::new();
        let mut r1 = allow_rule("r1", 80);
        r1.expires_at = Some(NOW - 1); // expired
        let r2 = allow_rule("r2", 443); // no expiry
        fw.add_rule(r1);
        fw.add_rule(r2);

        let expired = fw.cleanup_expired_rules(NOW);
        assert_eq!(expired, vec!["r1"]);
        assert!(fw.get_rule("r1").is_none());
        assert!(fw.get_rule("r2").is_some());
    }

    #[test]
    fn cleanup_does_not_remove_disabled_rules() {
        let mut fw = Firewall::new();
        let mut r1 = allow_rule("r1", 80);
        r1.enabled = false;
        r1.expires_at = Some(NOW - 1);
        fw.add_rule(r1);

        let expired = fw.cleanup_expired_rules(NOW);
        assert!(expired.is_empty()); // disabled rules don't "expire"
    }

    // ── ICMP ping policy ──────────────────────────────────────────────────

    #[test]
    fn ping_disabled_blocks_echo() {
        let fw = Firewall::new(); // ping_enabled defaults to false
        assert!(!fw.check_icmp(true));
    }

    #[test]
    fn ping_enabled_allows_echo() {
        let mut fw = Firewall::new();
        fw.ping_enabled = true;
        assert!(fw.check_icmp(true));
    }

    #[test]
    fn non_echo_icmp_always_allowed() {
        let fw = Firewall::new();
        assert!(fw.check_icmp(false));
    }

    // ── Interactive auth ──────────────────────────────────────────────────

    #[test]
    fn register_and_resolve_auth() {
        let mut fw = Firewall::new();
        let key = AuthKey {
            src_device_id: "device-aabbccdd".into(),
            proto: Protocol::Tcp,
            dst_port: 25565,
        };
        let log_id = fw.next_id();
        let request_id = fw.register_pending_auth(key.clone(), "device-aabbccdd".into(), log_id);
        assert!(fw.has_pending_auth(&key));

        let outcome = fw.resolve_auth(&request_id, Action::Allow, false).unwrap();
        assert_eq!(outcome.key, key);
        assert_eq!(outcome.decision, Action::Allow);
        assert!(!outcome.permanent);
        assert!(!fw.has_pending_auth(&key));
    }

    #[test]
    fn resolve_permanent_auth() {
        let mut fw = Firewall::new();
        let key = AuthKey {
            src_device_id: "device-aabbccdd".into(),
            proto: Protocol::Tcp,
            dst_port: 22,
        };
        let log_id = fw.next_id();
        let request_id = fw.register_pending_auth(key, "device-aabbccdd".into(), log_id);

        let outcome = fw.resolve_auth(&request_id, Action::Allow, true).unwrap();
        assert!(outcome.permanent);
    }

    #[test]
    fn resolve_nonexistent_auth() {
        let mut fw = Firewall::new();
        assert!(fw.resolve_auth("nonexistent", Action::Allow, false).is_none());
    }

    #[test]
    fn queue_packet_for_auth() {
        let mut fw = Firewall::new();
        let key = AuthKey {
            src_device_id: "device-aabbccdd".into(),
            proto: Protocol::Udp,
            dst_port: 25565,
        };
        let log_id = fw.next_id();
        fw.register_pending_auth(key.clone(), "device-aabbccdd".into(), log_id);

        fw.queue_packet_for_auth(&key, vec![1, 2, 3]);
        fw.queue_packet_for_auth(&key, vec![4, 5, 6]);

        // Verify packets are queued.
        let pending = fw.pending_auth.iter().find(|p| p.key == key).unwrap();
        assert_eq!(pending.queued_packets.len(), 2);
        assert_eq!(pending.queued_bytes, 6);
    }

    #[test]
    fn auth_timeout() {
        let mut fw = Firewall::new();
        let key = AuthKey {
            src_device_id: "device-aabbccdd".into(),
            proto: Protocol::Tcp,
            dst_port: 80,
        };
        // Manually create a pending auth with an old timestamp.
        let log_id = fw.next_id();
        fw.register_pending_auth(key.clone(), "device-aabbccdd".into(), log_id);
        // Backdate the created_at.
        fw.pending_auth[0].created_at_unix = NOW - AUTH_TIMEOUT_SECS - 1;

        let timed_out = fw.collect_timed_out_auth(NOW);
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].0, key);
        assert!(!fw.has_pending_auth(&key));
    }

    #[test]
    fn no_timeout_within_window() {
        let mut fw = Firewall::new();
        let key = AuthKey {
            src_device_id: "device-aabbccdd".into(),
            proto: Protocol::Tcp,
            dst_port: 80,
        };
        let log_id = fw.next_id();
        fw.register_pending_auth(key.clone(), "device-aabbccdd".into(), log_id);

        let timed_out = fw.collect_timed_out_auth(NOW);
        assert!(timed_out.is_empty());
        assert!(fw.has_pending_auth(&key));
    }

    // ── Access log ────────────────────────────────────────────────────────

    #[test]
    fn log_access_records_entry() {
        let mut fw = Firewall::new();
        fw.log_access(AccessLogEntry {
            id: "e1".into(),
            src_device_id: "dev-1".into(),
            service_name: None,
            proto: Protocol::Tcp,
            dst_port: 80,
            decision: AccessDecision::Allow,
            reason: AccessReason::MatchedRule {
                rule_id: "r1".into(),
                comment: None,
            },
            timestamp_ms: 1000,
            rule_id: Some("r1".into()),
            count: 1,
        });
        assert_eq!(fw.access_log_entries().len(), 1);
    }

    // ── Service catalog ───────────────────────────────────────────────────

    #[test]
    fn service_catalog_by_name() {
        let fw = Firewall::new();
        assert!(fw.services.by_name("ssh").is_some());
        assert!(fw.services.by_name("minecraft-java").is_some());
        assert!(fw.services.by_name("nonexistent").is_none());
    }

    #[test]
    fn service_catalog_name_by_port() {
        let fw = Firewall::new();
        assert_eq!(fw.services.name_by_port(Protocol::Tcp, 22), Some("ssh"));
        assert_eq!(fw.services.name_by_port(Protocol::Tcp, 25565), Some("minecraft-java"));
        assert!(fw.services.name_by_port(Protocol::Tcp, 12345).is_none());
    }
}