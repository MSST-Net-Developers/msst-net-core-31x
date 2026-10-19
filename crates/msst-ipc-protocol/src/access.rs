//! IPC permission model (protocol 0.4).
//!
//! Every connection has a [`Role`], decided by Core from the operating
//! system identity of the connecting process (Unix peer UID, Windows client
//! token) — the protocol carries no credentials.  Two tiers:
//!
//! | Role | May send |
//! |------|----------|
//! | [`Role::Viewer`] | queries; receives every event |
//! | [`Role::Admin`]  | everything, including commands |
//!
//! A request above the connection's role is answered with
//! [`errors::PERMISSION_DENIED`](crate::errors::PERMISSION_DENIED); the
//! connection stays open.  `Health` reports the role as `ipc_role`.
//!
//! Who is an admin (Core's side, for reference): root / LocalSystem, Core's
//! own user, the `sudo` invoker, members of the local group `msst-net`
//! (Linux/macOS) or `MSST-Net Administrators` (Windows), and elevated
//! Administrators on Windows.  Other users that may connect at all
//! (logged-in local users) are viewers.

use crate::IpcRequest;
use serde::{Deserialize, Serialize};

/// The permission tier of an IPC connection.  Ordered: `Viewer < Admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Admin => "admin",
        }
    }
}

/// Whether a request reads state (query), changes it (command), or only
/// affects the requesting connection (session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Query,
    Command,
    Session,
}

impl IpcRequest {
    /// Query, command or session request.  Exhaustive on purpose: a new
    /// request type must be classified before it compiles.
    pub fn kind(&self) -> RequestKind {
        use IpcRequest::*;
        match self {
            GetSystemState | GetNodes | GetNode { .. } | GetConnections | GetPaths | GetAclRules | GetAclGroups
            | GetAccessLog { .. } | GetPendingAuth | Health | GetNetSettings | GetEndpoints | GetTrafficStats
            | GetPathView | GetLogs { .. } | GetDnsDomains | GetDnsRecords { .. } | GetRelays | GetContacts
            | GetServices | GetDiagPingResult { .. } | GetOperation { .. } => RequestKind::Query,

            SetLogStream { .. } => RequestKind::Session,

            CreateRoom { .. } | JoinRoom { .. } | LeaveRoom { .. } | CreateAclRule { .. } | UpdateAclRule { .. }
            | DeleteAclRule { .. } | ClearAclRules | CreateAclGroup { .. } | UpdateAclGroup { .. }
            | DeleteAclGroup { .. } | AuthDecision { .. } | UpdateDisplayName { .. } | UpdateHandle { .. }
            | SetNetSettings { .. } | SetPingEnabled { .. } | RefreshEndpoint | ReRegister | AuthStart
            | AuthPoll { .. } | AuthRefresh | DnsRegisterDomain { .. } | DnsCreateRecord { .. }
            | DnsUpdateRecord { .. } | DnsDeleteRecord { .. } | StartDiagPing { .. } | ClearLogs => RequestKind::Command,
        }
    }

    /// The minimum role allowed to send this request.
    pub fn required_role(&self) -> Role {
        match self.kind() {
            RequestKind::Query | RequestKind::Session => Role::Viewer,
            RequestKind::Command => Role::Admin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_are_viewer_commands_are_admin() {
        assert_eq!(IpcRequest::Health.required_role(), Role::Viewer);
        assert_eq!(IpcRequest::GetAclRules.required_role(), Role::Viewer);
        assert_eq!(IpcRequest::GetDiagPingResult { job_id: "j".into() }.required_role(), Role::Viewer);
        assert_eq!(IpcRequest::SetLogStream { enabled: false }.required_role(), Role::Viewer);
        assert_eq!(IpcRequest::ClearAclRules.required_role(), Role::Admin);
        assert_eq!(IpcRequest::JoinRoom { room_id: "r".into(), password: None }.required_role(), Role::Admin);
        assert_eq!(IpcRequest::StartDiagPing { device_id: "d".into() }.required_role(), Role::Admin);
        assert_eq!(IpcRequest::ClearLogs.required_role(), Role::Admin);
        assert!(Role::Viewer < Role::Admin);
        assert_eq!(serde_json::to_string(&Role::Admin).unwrap(), "\"admin\"");
    }
}
