//! Structured ACL decision — the output of every rule evaluation.
//!
//! Answers: what happened, which rule caused it, and why.

use crate::rules::{Action, Scope};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/// The result of evaluating firewall rules for a single packet.
///
/// Always fully populated — even the default-deny case has a reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    /// The final verdict.
    pub action: Action,
    /// Why this action was chosen.
    pub reason: DecisionReason,
    /// The rule that determined the outcome (None for default-deny).
    pub matched_rule: Option<MatchedRule>,
}

impl Decision {
    pub fn allow(rule: MatchedRule, reason: DecisionReason) -> Self {
        Decision {
            action: Action::Allow,
            reason,
            matched_rule: Some(rule),
        }
    }

    pub fn deny(rule: MatchedRule, reason: DecisionReason) -> Self {
        Decision {
            action: Action::Deny,
            reason,
            matched_rule: Some(rule),
        }
    }

    /// Default deny — no rule matched.
    pub fn default_deny() -> Self {
        Decision {
            action: Action::Deny,
            reason: DecisionReason::DefaultDeny,
            matched_rule: None,
        }
    }

    pub fn is_allow(&self) -> bool {
        self.action == Action::Allow
    }
}

// ---------------------------------------------------------------------------
// MatchedRule
// ---------------------------------------------------------------------------

/// Information about the rule that determined the decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    /// The rule's unique ID.
    pub rule_id: String,
    /// Optional human-readable comment.
    pub comment: Option<String>,
    /// The rule's action (Allow or Deny).
    pub action: Action,
    /// The scope at which this rule matched.
    pub scope: Scope,
}

// ---------------------------------------------------------------------------
// DecisionReason
// ---------------------------------------------------------------------------

/// Why a particular decision was made.
///
/// This is the "explainability" output (AGENTS.md §11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReason {
    /// A device-level DENY rule won (highest priority).
    DeviceDenyPriority,
    /// A device-level ALLOW rule won.
    DeviceAllowPriority,
    /// A user-level DENY rule won.
    UserDenyPriority,
    /// A user-level ALLOW rule won.
    UserAllowPriority,
    /// A space-level DENY rule won.
    SpaceDenyPriority,
    /// A space-level ALLOW rule won.
    SpaceAllowPriority,
    /// No rule matched — default deny policy applies.
    DefaultDeny,
}

impl std::fmt::Display for DecisionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceDenyPriority  => write!(f, "device-level deny rule matched (highest priority)"),
            Self::DeviceAllowPriority => write!(f, "device-level allow rule matched"),
            Self::UserDenyPriority    => write!(f, "user-level deny rule matched"),
            Self::UserAllowPriority   => write!(f, "user-level allow rule matched"),
            Self::SpaceDenyPriority   => write!(f, "space-level deny rule matched"),
            Self::SpaceAllowPriority  => write!(f, "space-level allow rule matched"),
            Self::DefaultDeny         => write!(f, "no rule matched — default deny"),
        }
    }
}