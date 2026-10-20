//! Which credential the Coordinator connection uses.
//!
//! ```text
//! OIDC access token (identity.auth)
//!   └─ 401 → refresh → retry ─ refused ─► OIDC marked rejected, AccessAuthRequired
//!                                         │
//! guest token (POST /auth/guest/token) ◄──┘   also when never authenticated
//!   └─ 401 (Coordinator restarted: guest tokens are in memory) → new token, retry once
//!   └─ endpoint missing (404/405) → no credential (anonymous)
//! ```
//!
//! The rejection is remembered in memory only, so later reconnects go
//! straight to the guest token; the stored OIDC credentials are kept.  A
//! successful refresh or a new login clears it and reconnects with OIDC
//! (`CoordinatorClient::credentials_changed`).  Guest tokens are never
//! persisted: the Coordinator forgets them on restart anyway.  The same
//! credential is used for the Coordinator's HTTP API.

use serde_json::Value;

/// Request a new guest token this long before the current one expires.
pub const GUEST_RENEW_MARGIN_SECS: i64 = 300;

/// A guest token from `POST /auth/guest/token`.  Debug never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestToken {
    pub token: String,
    /// `guest-<8hex>`, assigned by the Coordinator.
    pub user_id: String,
    pub expires_at: i64,
}

impl std::fmt::Debug for GuestToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestToken").field("user_id", &self.user_id).field("expires_at", &self.expires_at).finish_non_exhaustive()
    }
}

impl GuestToken {
    /// Parse `{token, user_id, expires_at}`; `None` without a token.
    pub fn from_response(v: &Value) -> Option<GuestToken> {
        let token = v["token"].as_str().filter(|t| !t.is_empty())?.to_string();
        Some(GuestToken {
            token,
            user_id: v["user_id"].as_str().unwrap_or("").to_string(),
            expires_at: v["expires_at"].as_i64().unwrap_or(0),
        })
    }

    /// Still good for a new connection at `now`.
    pub fn usable(&self, now: i64) -> bool {
        self.expires_at - GUEST_RENEW_MARGIN_SECS > now
    }
}

/// The credential a connection was opened with.
#[derive(Clone, PartialEq, Eq)]
pub enum Credential {
    Oidc(String),
    Guest(String),
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

impl Credential {
    pub fn token(&self) -> &str {
        match self {
            Credential::Oidc(t) | Credential::Guest(t) => t,
        }
    }

    /// `Health.coordinator_credential` value.
    pub fn kind(&self) -> &'static str {
        match self {
            Credential::Oidc(_) => "oidc",
            Credential::Guest(_) => "guest",
        }
    }
}

/// Outcome of an OIDC token refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresh {
    Refreshed,
    /// No refresh token, or the IdP refused it (HTTP 4xx): the stored
    /// credentials are dead.
    Rejected,
    /// Network error, 5xx or a malformed answer: try again later.
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn guest_token_parsing_and_renewal() {
        let g = GuestToken::from_response(&json!({ "token": "abc", "user_id": "guest-0a1b2c3d", "expires_at": 10_000 })).unwrap();
        assert_eq!((g.user_id.as_str(), g.expires_at), ("guest-0a1b2c3d", 10_000));
        assert!(g.usable(10_000 - GUEST_RENEW_MARGIN_SECS - 1));
        assert!(!g.usable(10_000 - GUEST_RENEW_MARGIN_SECS));
        assert!(GuestToken::from_response(&json!({ "token": "" })).is_none());
        assert!(GuestToken::from_response(&json!({})).is_none());
        // Tokens never reach a log.
        assert!(!format!("{:?}", g).contains("abc"));
        assert_eq!(format!("{:?}", Credential::Guest("abc".into())), "guest");
        assert_eq!(Credential::Oidc("t".into()).token(), "t");
    }
}
