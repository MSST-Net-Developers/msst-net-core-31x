//! Interactive authorization state.
//!
//! When an inbound packet hits no ACL rule, the firewall triggers an
//! interactive auth flow: the Controller shows a prompt to the user, and
//! the packet is queued (UDP) or RST'd (TCP) while waiting.
//!
//! This module defines the data types; the `Firewall` struct in `mod.rs`
//! owns the state and provides the mutation methods.

use msst_acl_engine::Protocol;
use std::collections::VecDeque;

/// The key identifying a pending auth request.
///
/// Two packets from the same source asking for the same proto/port share
/// a single pending auth entry.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AuthKey {
    pub src_device_id: String,
    pub proto: Protocol,
    /// 0 means ICMP / wildcard.
    pub dst_port: u16,
}

/// A pending interactive auth request.
#[derive(Debug)]
pub struct PendingAuth {
    /// The auth key (source + proto + port).
    pub key: AuthKey,
    /// Unique request ID (hex string) sent to the Controller.
    pub request_id: String,
    /// Unix timestamp when the request was created.
    pub created_at_unix: i64,
    /// Packets buffered while waiting for the auth decision.
    pub queued_packets: VecDeque<Vec<u8>>,
    /// Total bytes in queued_packets.
    pub queued_bytes: usize,
    /// ID of the access log entry created when this request was triggered.
    pub log_entry_id: String,
}

/// The outcome of resolving an interactive auth request.
#[derive(Debug)]
pub struct AuthOutcome {
    /// The auth key.
    pub key: AuthKey,
    /// The user's decision (Allow or Deny).
    pub decision: msst_acl_engine::Action,
    /// If `true`, create a permanent ACL rule so this proto/port is always
    /// allowed/denied for this source.
    pub permanent: bool,
    /// Packets that were queued while waiting.
    pub queued_packets: VecDeque<Vec<u8>>,
    /// The access log entry ID to update.
    pub log_entry_id: String,
}

/// Possible decisions the user can make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserDecision {
    AllowOnce,
    AlwaysAllow,
    DenyOnce,
    AlwaysDeny,
}

impl UserDecision {
    /// Convert to (action, permanent).
    pub fn to_action(&self) -> (msst_acl_engine::Action, bool) {
        match self {
            UserDecision::AllowOnce => (msst_acl_engine::Action::Allow, false),
            UserDecision::AlwaysAllow => (msst_acl_engine::Action::Allow, true),
            UserDecision::DenyOnce => (msst_acl_engine::Action::Deny, false),
            UserDecision::AlwaysDeny => (msst_acl_engine::Action::Deny, true),
        }
    }
}