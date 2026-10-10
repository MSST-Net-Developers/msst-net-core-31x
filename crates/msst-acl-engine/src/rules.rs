//! ACL rule data types.
//!
//! These mirror the 3.0.x `net::firewall` types but are standalone — no
//! dependency on the runtime state machine.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Protocol / port
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A single protocol + port range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolPort {
    pub proto: Protocol,
    /// `start == end` → single port.
    pub start: u16,
    pub end: u16,
}

impl ProtocolPort {
    pub fn single(proto: Protocol, port: u16) -> Self {
        ProtocolPort { proto, start: port, end: port }
    }

    pub fn range(proto: Protocol, start: u16, end: u16) -> Self {
        ProtocolPort { proto, start, end }
    }

    pub fn wildcard(proto: Protocol) -> Self {
        ProtocolPort { proto, start: 1, end: 65535 }
    }

    pub fn matches(&self, proto: Protocol, port: u16) -> bool {
        self.proto == proto && port >= self.start && port <= self.end
    }
}

// ---------------------------------------------------------------------------
// Action / Direction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

// ---------------------------------------------------------------------------
// Scope  (for decision reporting — not part of the rule itself)
// ---------------------------------------------------------------------------

/// The scope at which a rule matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Device,
    User,
    Space,
}

// ---------------------------------------------------------------------------
// PermissionGroup  (principal set)
// ---------------------------------------------------------------------------

/// The resolved principal set in a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum PermissionGroup {
    /// Matches any of the listed device IDs directly.
    Devices { ids: Vec<String> },
    /// Matches any device belonging to any of the listed user IDs.
    Users { ids: Vec<String> },
    /// Matches any device currently in a shared room with the local device.
    Space,
}

// ---------------------------------------------------------------------------
// FirewallRule
// ---------------------------------------------------------------------------

/// A single ACL rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Unique rule ID (hex string).
    pub id: String,
    pub permission_group: PermissionGroup,
    /// After parsing, tcp+udp is already split; each entry is Tcp or Udp only.
    pub protocol_ports: Vec<ProtocolPort>,
    pub action: Action,
    pub direction: Direction,
    /// Unix timestamp (seconds).  `None` = never expires.
    pub expires_at: Option<i64>,
    pub enabled: bool,
    pub comment: Option<String>,
}

impl FirewallRule {
    /// Returns `true` if the rule is currently active (enabled and not expired).
    pub fn is_active(&self, now_unix: i64) -> bool {
        if !self.enabled {
            return false;
        }
        match self.expires_at {
            Some(exp) => now_unix < exp,
            None => true,
        }
    }
}