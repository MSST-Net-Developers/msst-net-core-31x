//! Error codes carried in [`IpcError::code`](crate::IpcError).
//!
//! `code` is stable and machine-readable; `message` is diagnostic text
//! (may contain raw transport errors) and should not be shown to users
//! verbatim.  Controllers should map unknown codes to a generic message.

/// The request JSON could not be decoded (unknown `type`, wrong params).
pub const INVALID_REQUEST: &str = "invalid_request";
/// Rule request failed validation (principals, ports, services, action…).
pub const INVALID_RULE: &str = "invalid_rule";
/// Patch has an invalid or unknown field (rules, groups).
pub const INVALID_PATCH: &str = "invalid_patch";
/// Permission group failed validation.
pub const INVALID_GROUP: &str = "invalid_group";
/// Network settings failed validation (e.g. MTU outside 1280–1500).
pub const INVALID_SETTINGS: &str = "invalid_settings";
/// Handle is not `^[a-z0-9-]+$`.
pub const INVALID_HANDLE: &str = "invalid_handle";
/// The referenced rule / group / auth request / ping job / node doesn't exist.
pub const NOT_FOUND: &str = "not_found";
/// A mnemonic in a rule matches no known device or user.
pub const MNEMONIC_NOT_FOUND: &str = "mnemonic_not_found";
/// Core's identity is not loaded yet.
pub const NOT_INITIALIZED: &str = "not_initialized";
/// The operation needs OIDC authentication first.
pub const NOT_AUTHENTICATED: &str = "not_authenticated";
/// OIDC device flow / token refresh failed.
pub const AUTH_FAILED: &str = "auth_failed";
/// The coordinator could not be reached (network / not connected).
pub const COORDINATOR_UNAVAILABLE: &str = "coordinator_unavailable";
/// The coordinator answered with an error status.
pub const COORDINATOR_ERROR: &str = "coordinator_error";
/// Device re-registration was refused by the coordinator.
pub const REGISTER_FAILED: &str = "register_failed";
/// No relay could be selected.
pub const RELAY_UNAVAILABLE: &str = "relay_unavailable";
/// The coordinator refused to create the room.
pub const ROOM_CREATE_FAILED: &str = "room_create_failed";
/// The coordinator refused the join (e.g. wrong password).
pub const ROOM_REJECTED: &str = "room_rejected";
/// Core could not save the change to disk (nothing was changed).
pub const PERSIST_FAILED: &str = "persist_failed";

/// Every code above.
pub const ALL: &[&str] = &[
    INVALID_REQUEST, INVALID_RULE, INVALID_PATCH, INVALID_GROUP, INVALID_SETTINGS, INVALID_HANDLE,
    NOT_FOUND, MNEMONIC_NOT_FOUND, NOT_INITIALIZED, NOT_AUTHENTICATED, AUTH_FAILED,
    COORDINATOR_UNAVAILABLE, COORDINATOR_ERROR, REGISTER_FAILED, RELAY_UNAVAILABLE,
    ROOM_CREATE_FAILED, ROOM_REJECTED, PERSIST_FAILED,
];
