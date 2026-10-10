//! Match context — the packet descriptor passed to the ACL engine.
//!
//! Contains everything the engine needs to evaluate rules against a single
//! packet, but no state machine or I/O.

use crate::rules::{Direction, Protocol};

/// Context for a single ACL evaluation.
///
/// Constructed by the caller (the Core runtime) from the parsed packet header
/// and current peer/room state.  The engine itself is pure — it only reads
/// from this struct.
pub struct MatchContext<'a> {
    /// The source device ID (device-XXXXXXXX).
    pub src_device_id: &'a str,
    /// IP protocol (Tcp or Udp).
    pub proto: Protocol,
    /// Destination port number.
    pub dst_port: u16,
    /// Packet direction (Inbound or Outbound).
    pub direction: Direction,
    /// Whether the source device is currently in a shared room with us.
    pub in_room_with_src: bool,
    /// Current Unix timestamp (seconds) — for rule expiry checks.
    pub now_unix: i64,
    /// Mnemonic resolver: given a device or user mnemonic, return the
    /// resolved device ID.  Returns `None` if the mnemonic cannot be resolved.
    mnemonic_resolver: Option<&'a dyn Fn(&str) -> Option<String>>,
    /// User ID of the local device (for defaulting simple device mnemonics).
    pub local_user_id: &'a str,
}

impl<'a> MatchContext<'a> {
    pub fn new(
        src_device_id: &'a str,
        proto: Protocol,
        dst_port: u16,
        direction: Direction,
        in_room_with_src: bool,
        now_unix: i64,
        local_user_id: &'a str,
    ) -> Self {
        MatchContext {
            src_device_id,
            proto,
            dst_port,
            direction,
            in_room_with_src,
            now_unix,
            mnemonic_resolver: None,
            local_user_id,
        }
    }

    /// Attach a mnemonic resolver (called during rule matching for non-ID
    /// permission group members).
    pub fn with_mnemonic_resolver(
        mut self,
        resolver: &'a dyn Fn(&str) -> Option<String>,
    ) -> Self {
        self.mnemonic_resolver = Some(resolver);
        self
    }

    /// Try to resolve a device mnemonic to a device ID.
    pub fn resolve_device_mnemonic(&self, mnemonic: &str) -> Option<String> {
        self.mnemonic_resolver.and_then(|r| r(mnemonic))
    }
}

/// A resolved principal reference (used in decision reporting).
#[derive(Debug, Clone)]
pub enum PrincipalRef {
    Device { id: String },
    User { id: String },
    Space,
}