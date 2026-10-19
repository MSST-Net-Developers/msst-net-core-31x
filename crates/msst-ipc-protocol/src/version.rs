//! Protocol version tracking.
//!
//! Every [`IpcMessage`] frame implicitly carries the protocol version of the
//! sender.  The receiver checks compatibility at connection time via a
//! version handshake:
//!
//! 1. Core sends a [`version::PROTOCOL_VERSION`] u32 as the first 4 bytes
//!    of the connection (before any JSON frames).
//! 2. Controller reads and compares against its own compiled-in version.
//! 3. If major versions differ, Controller disconnects and reports the
//!    mismatch.
//!
//! Minor version differences are forward-compatible: newer senders may add
//! fields that older receivers ignore (serde's default behavior).

/// Current protocol version.
///
/// Encoding: `(major << 16) | (minor << 8) | patch`
///
/// Bump major when the wire format breaks backward compatibility.
/// Bump minor when new request/response/event types are added (forward-compatible).
/// Bump patch for non-semantic fixes (doc comments, field renames that don't
/// affect JSON).
pub const PROTOCOL_VERSION: u32 = make_version(0, 4, 0);

// History:
// 0.1 — initial 3.1 protocol.
// 0.2 — `GetServices`.
// 0.3 — `ClearAclRules`; events `AccessRequestResolved`, `IdentityChanged`,
//       `SettingsChanged`; documented `generation` and error codes.
// 0.4 — permission model (`access`, `permission_denied`, `Health.ipc_role`).

/// Minimum protocol version this build can speak to.
///
/// Set to the same as `PROTOCOL_VERSION` until the first stable release,
/// then track the oldest compatible version.
pub const MIN_COMPATIBLE_VERSION: u32 = make_version(0, 1, 0);

/// Compile-time version encoder.
pub const fn make_version(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | patch
}

/// Decode a version u32 into (major, minor, patch).
pub const fn decode_version(v: u32) -> (u32, u32, u32) {
    ((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)
}

/// Returns true if `remote_version` is compatible with this build.
pub fn is_compatible(remote_version: u32) -> bool {
    let (remote_major, _, _) = decode_version(remote_version);
    let (local_major, _, _) = decode_version(MIN_COMPATIBLE_VERSION);
    remote_major == local_major
}