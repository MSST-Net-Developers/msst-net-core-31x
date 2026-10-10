//! Access log — ring buffer of recent ACL decisions with dedup.
//!
//! Records every ALLOW/DENY decision with enough context for the Controller
//! to display to the user.  Identical events within a 30-second window are
//! merged (count incremented) to avoid log flooding.

use msst_acl_engine::Protocol;
use serde::{Deserialize, Serialize};

/// Dedup window: identical events within this many milliseconds are merged.
const DEDUP_WINDOW_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// AccessLogEntry
// ---------------------------------------------------------------------------

/// A single access log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogEntry {
    /// Unique entry ID (hex string).
    pub id: String,
    /// The source device that sent the packet.
    pub src_device_id: String,
    /// Resolved service name (e.g. "minecraft-java"), if any.
    pub service_name: Option<String>,
    /// Transport protocol.
    pub proto: Protocol,
    /// Destination port.
    pub dst_port: u16,
    /// The final decision.
    pub decision: AccessDecision,
    /// Why this decision was made.
    pub reason: AccessReason,
    /// Unix timestamp (milliseconds) of the decision.
    pub timestamp_ms: u64,
    /// The rule that determined the outcome (for revoke/modify).
    pub rule_id: Option<String>,
    /// Number of identical events merged into this entry.
    pub count: u64,
}

// ---------------------------------------------------------------------------
// AccessDecision / AccessReason
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecision {
    Allow,
    Deny,
    /// Silently denied (e.g. pending auth timeout).
    SilentDeny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AccessReason {
    MatchedRule {
        rule_id: String,
        comment: Option<String>,
    },
    InteractiveAuth,
    InteractiveAuthTimeout,
    DefaultDeny,
}

// ---------------------------------------------------------------------------
// AccessLog
// ---------------------------------------------------------------------------

/// Ring buffer of access log entries with dedup.
pub struct AccessLog {
    entries: Vec<AccessLogEntry>,
    max_size: usize,
}

impl AccessLog {
    pub fn new(max_size: usize) -> Self {
        AccessLog {
            entries: Vec::with_capacity(max_size),
            max_size,
        }
    }

    /// Append an entry, merging with a recent identical entry if found.
    pub fn append(&mut self, entry: AccessLogEntry) {
        let threshold = entry.timestamp_ms.saturating_sub(DEDUP_WINDOW_MS);
        // Search the most recent entries (up to 30) for a mergeable match.
        let len = self.entries.len();
        let search_from = len.saturating_sub(30);
        for existing in &mut self.entries[search_from..] {
            if existing.src_device_id == entry.src_device_id
                && existing.proto == entry.proto
                && existing.dst_port == entry.dst_port
                && existing.decision == entry.decision
                && existing.timestamp_ms >= threshold
            {
                existing.timestamp_ms = entry.timestamp_ms;
                existing.count += 1;
                return;
            }
        }
        if self.entries.len() >= self.max_size {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    /// Update an existing entry's decision and reason (used after interactive
    /// auth resolves or times out).
    pub fn update_decision(
        &mut self,
        entry_id: &str,
        decision: AccessDecision,
        reason: AccessReason,
    ) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == entry_id) {
            entry.decision = decision;
            entry.reason = reason;
        }
    }

    /// Record the rule an entry was finally decided by (e.g. the rule
    /// generated from an interactive-auth decision).
    pub fn set_rule_id(&mut self, entry_id: &str, rule_id: String) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == entry_id) {
            entry.rule_id = Some(rule_id);
        }
    }

    /// Get all entries (most recent last).
    pub fn entries(&self) -> &[AccessLogEntry] {
        &self.entries
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: &str, src: &str, proto: Protocol, port: u16, ts: u64) -> AccessLogEntry {
        AccessLogEntry {
            id: id.into(),
            src_device_id: src.into(),
            service_name: None,
            proto,
            dst_port: port,
            decision: AccessDecision::Allow,
            reason: AccessReason::MatchedRule {
                rule_id: "r1".into(),
                comment: None,
            },
            timestamp_ms: ts,
            rule_id: Some("r1".into()),
            count: 1,
        }
    }

    #[test]
    fn new_log_is_empty() {
        let log = AccessLog::new(100);
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn append_adds_entry() {
        let mut log = AccessLog::new(100);
        log.append(make_entry("e1", "dev-1", Protocol::Tcp, 80, 1000));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn dedup_merges_identical_entries() {
        let mut log = AccessLog::new(100);
        log.append(make_entry("e1", "dev-1", Protocol::Tcp, 80, 1000));
        log.append(make_entry("e2", "dev-1", Protocol::Tcp, 80, 5000));
        assert_eq!(log.len(), 1);
        assert_eq!(log.entries()[0].count, 2);
    }

    #[test]
    fn dedup_does_not_merge_different_entries() {
        let mut log = AccessLog::new(100);
        log.append(make_entry("e1", "dev-1", Protocol::Tcp, 80, 1000));
        log.append(make_entry("e2", "dev-1", Protocol::Tcp, 443, 5000));
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn dedup_does_not_merge_outside_window() {
        let mut log = AccessLog::new(100);
        log.append(make_entry("e1", "dev-1", Protocol::Tcp, 80, 1000));
        log.append(make_entry("e2", "dev-1", Protocol::Tcp, 80, 1000 + DEDUP_WINDOW_MS + 1));
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn ring_buffer_evicts_oldest() {
        let mut log = AccessLog::new(3);
        log.append(make_entry("e1", "dev-1", Protocol::Tcp, 80, 1000));
        log.append(make_entry("e2", "dev-1", Protocol::Tcp, 443, 2000));
        log.append(make_entry("e3", "dev-1", Protocol::Udp, 53, 3000));
        log.append(make_entry("e4", "dev-1", Protocol::Udp, 5353, 4000));
        assert_eq!(log.len(), 3);
        // e1 should be evicted.
        assert_eq!(log.entries()[0].id, "e2");
        assert_eq!(log.entries()[2].id, "e4");
    }

    #[test]
    fn update_decision_modifies_entry() {
        let mut log = AccessLog::new(100);
        log.append(make_entry("e1", "dev-1", Protocol::Tcp, 80, 1000));
        log.update_decision("e1", AccessDecision::Deny, AccessReason::InteractiveAuthTimeout);
        assert_eq!(log.entries()[0].decision, AccessDecision::Deny);
    }

    #[test]
    fn update_decision_noop_for_missing_id() {
        let mut log = AccessLog::new(100);
        log.append(make_entry("e1", "dev-1", Protocol::Tcp, 80, 1000));
        log.update_decision("nonexistent", AccessDecision::Deny, AccessReason::DefaultDeny);
        assert_eq!(log.entries()[0].decision, AccessDecision::Allow);
    }

    #[test]
    fn clear_removes_all() {
        let mut log = AccessLog::new(100);
        log.append(make_entry("e1", "dev-1", Protocol::Tcp, 80, 1000));
        log.append(make_entry("e2", "dev-1", Protocol::Tcp, 443, 2000));
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn dedup_different_decision_not_merged() {
        let mut log = AccessLog::new(100);
        log.append(make_entry("e1", "dev-1", Protocol::Tcp, 80, 1000));
        let mut denied = make_entry("e2", "dev-1", Protocol::Tcp, 80, 5000);
        denied.decision = AccessDecision::Deny;
        log.append(denied);
        assert_eq!(log.len(), 2);
    }
}