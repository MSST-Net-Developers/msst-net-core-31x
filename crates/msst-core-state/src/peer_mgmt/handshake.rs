//! Handshake and WireGuard session tracking.
//!
//! Tracks per-peer WireGuard session state: whether a session exists,
//! its handshake status, and when it was last active.  The `PeerManager`
//! uses this to decide when to add/remove WG sessions as peers come and go.
//!
//! This module is **data only** — it doesn't touch the actual boringtun
//! library.  The Core runtime reads `HandshakeAction` values and executes
//! them against the real WG implementation.

use std::collections::HashMap;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// The state of a WireGuard session with a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WgSessionState {
    /// No session exists.
    None,
    /// Session created, waiting for handshake.
    Handshaking,
    /// Handshake completed, tunnel is active.
    Established,
    /// Handshake timed out or failed.
    Failed,
}

/// Per-peer WireGuard session metadata.
#[derive(Debug, Clone)]
pub struct WgSession {
    pub device_id: String,
    pub public_key_b64: String,
    pub state: WgSessionState,
    /// Unix timestamp of the last successful handshake or data transfer.
    pub last_active_unix: i64,
    /// Number of consecutive handshake failures.
    pub failure_count: u32,
}

// ---------------------------------------------------------------------------
// HandshakeTracker
// ---------------------------------------------------------------------------

/// Tracks WireGuard session state for all peers.
pub struct HandshakeTracker {
    sessions: HashMap<String, WgSession>,
    /// Maximum consecutive failures before giving up.
    max_failures: u32,
    /// Handshake timeout (seconds).
    handshake_timeout_secs: i64,
}

impl HandshakeTracker {
    pub fn new() -> Self {
        HandshakeTracker {
            sessions: HashMap::new(),
            max_failures: 3,
            handshake_timeout_secs: 10,
        }
    }

    /// Register a new peer for WireGuard tracking.
    /// Returns a `HandshakeAction::AddSession` for the caller to execute.
    pub fn register_peer(
        &mut self,
        device_id: &str,
        public_key_b64: &str,
        now_unix: i64,
    ) -> HandshakeAction {
        info!("wg_tracker: registering peer {}", device_id);
        self.sessions.insert(
            device_id.to_string(),
            WgSession {
                device_id: device_id.to_string(),
                public_key_b64: public_key_b64.to_string(),
                state: WgSessionState::Handshaking,
                last_active_unix: now_unix,
                failure_count: 0,
            },
        );
        HandshakeAction::AddSession {
            device_id: device_id.to_string(),
            public_key_b64: public_key_b64.to_string(),
        }
    }

    /// Remove a peer's WireGuard session.
    /// Returns a `HandshakeAction::RemoveSession` if a session existed.
    pub fn remove_peer(&mut self, device_id: &str) -> Option<HandshakeAction> {
        if self.sessions.remove(device_id).is_some() {
            info!("wg_tracker: removed peer {}", device_id);
            Some(HandshakeAction::RemoveSession {
                device_id: device_id.to_string(),
            })
        } else {
            None
        }
    }

    /// Record that a handshake succeeded for this peer.
    pub fn handshake_completed(&mut self, device_id: &str, now_unix: i64) {
        if let Some(session) = self.sessions.get_mut(device_id) {
            session.state = WgSessionState::Established;
            session.last_active_unix = now_unix;
            session.failure_count = 0;
            debug!("wg_tracker: handshake completed for {}", device_id);
        }
    }

    /// Record that a handshake failed for this peer.
    pub fn handshake_failed(&mut self, device_id: &str, now_unix: i64) -> HandshakeAction {
        if let Some(session) = self.sessions.get_mut(device_id) {
            session.failure_count += 1;
            session.last_active_unix = now_unix;
            if session.failure_count >= self.max_failures {
                session.state = WgSessionState::Failed;
                info!(
                    "wg_tracker: handshake failed for {} ({} failures, giving up)",
                    device_id, session.failure_count
                );
                HandshakeAction::GiveUp {
                    device_id: device_id.to_string(),
                }
            } else {
                session.state = WgSessionState::Handshaking;
                debug!(
                    "wg_tracker: handshake failed for {} (attempt {})",
                    device_id, session.failure_count
                );
                HandshakeAction::RetryHandshake {
                    device_id: device_id.to_string(),
                }
            }
        } else {
            HandshakeAction::None
        }
    }

    /// Record data transfer activity (keeps the session alive).
    pub fn touch_activity(&mut self, device_id: &str, now_unix: i64) {
        if let Some(session) = self.sessions.get_mut(device_id) {
            session.last_active_unix = now_unix;
        }
    }

    /// Get the session state for a peer.
    pub fn state(&self, device_id: &str) -> WgSessionState {
        self.sessions
            .get(device_id)
            .map(|s| s.state.clone())
            .unwrap_or(WgSessionState::None)
    }

    /// Get the public key for a peer (if tracked).
    pub fn public_key(&self, device_id: &str) -> Option<&str> {
        self.sessions
            .get(device_id)
            .map(|s| s.public_key_b64.as_str())
    }

    /// Returns `true` if the peer has an established WG session.
    pub fn is_established(&self, device_id: &str) -> bool {
        self.sessions
            .get(device_id)
            .map_or(false, |s| s.state == WgSessionState::Established)
    }

    /// Check for timed-out handshakes. Returns device IDs that timed out.
    pub fn check_timeouts(&mut self, now_unix: i64) -> Vec<HandshakeAction> {
        let mut actions = Vec::new();
        for (id, session) in &mut self.sessions {
            if session.state == WgSessionState::Handshaking {
                if now_unix - session.last_active_unix > self.handshake_timeout_secs {
                    session.failure_count += 1;
                    session.last_active_unix = now_unix;
                    if session.failure_count >= self.max_failures {
                        session.state = WgSessionState::Failed;
                        info!("wg_tracker: handshake timeout for {} (giving up)", id);
                        actions.push(HandshakeAction::GiveUp {
                            device_id: id.clone(),
                        });
                    } else {
                        debug!("wg_tracker: handshake timeout for {} (retry {})", id, session.failure_count);
                        actions.push(HandshakeAction::RetryHandshake {
                            device_id: id.clone(),
                        });
                    }
                }
            }
        }
        actions
    }

    /// Number of tracked sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl Default for HandshakeTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HandshakeAction — side effects for the runtime to execute
// ---------------------------------------------------------------------------

/// An action the runtime should execute to manage WireGuard sessions.
#[derive(Debug, Clone)]
pub enum HandshakeAction {
    /// No action needed.
    None,
    /// Add a WireGuard session for this peer.
    AddSession {
        device_id: String,
        public_key_b64: String,
    },
    /// Remove a WireGuard session.
    RemoveSession {
        device_id: String,
    },
    /// Retry the handshake.
    RetryHandshake {
        device_id: String,
    },
    /// Give up on this peer's WG session (too many failures).
    GiveUp {
        device_id: String,
    },
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_is_empty() {
        let t = HandshakeTracker::new();
        assert!(t.is_empty());
        assert_eq!(t.state("dev-1"), WgSessionState::None);
    }

    #[test]
    fn register_peer_creates_session() {
        let mut t = HandshakeTracker::new();
        let action = t.register_peer("dev-1", "base64key", 1000);
        assert!(matches!(action, HandshakeAction::AddSession { .. }));
        assert_eq!(t.state("dev-1"), WgSessionState::Handshaking);
        assert_eq!(t.public_key("dev-1"), Some("base64key"));
        assert!(!t.is_established("dev-1"));
    }

    #[test]
    fn handshake_completed() {
        let mut t = HandshakeTracker::new();
        t.register_peer("dev-1", "key", 1000);
        t.handshake_completed("dev-1", 1005);
        assert_eq!(t.state("dev-1"), WgSessionState::Established);
        assert!(t.is_established("dev-1"));
    }

    #[test]
    fn handshake_failed_retries() {
        let mut t = HandshakeTracker::new();
        t.register_peer("dev-1", "key", 1000);

        let action = t.handshake_failed("dev-1", 1001);
        assert!(matches!(action, HandshakeAction::RetryHandshake { .. }));
        assert_eq!(t.state("dev-1"), WgSessionState::Handshaking);
    }

    #[test]
    fn handshake_failed_gives_up_after_max() {
        let mut t = HandshakeTracker::new();
        t.register_peer("dev-1", "key", 1000);

        for i in 1..=3 {
            let action = t.handshake_failed("dev-1", 1000 + i);
            if i < 3 {
                assert!(matches!(action, HandshakeAction::RetryHandshake { .. }));
            } else {
                assert!(matches!(action, HandshakeAction::GiveUp { .. }));
            }
        }
        assert_eq!(t.state("dev-1"), WgSessionState::Failed);
    }

    #[test]
    fn handshake_timeout() {
        let mut t = HandshakeTracker::new();
        t.register_peer("dev-1", "key", 1000);

        // Not timed out yet.
        let actions = t.check_timeouts(1005);
        assert!(actions.is_empty());

        // Timed out after 10 seconds.
        let actions = t.check_timeouts(1011);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], HandshakeAction::RetryHandshake { .. }));
    }

    #[test]
    fn remove_peer() {
        let mut t = HandshakeTracker::new();
        t.register_peer("dev-1", "key", 1000);
        let action = t.remove_peer("dev-1");
        assert!(matches!(action, Some(HandshakeAction::RemoveSession { .. })));
        assert_eq!(t.state("dev-1"), WgSessionState::None);
        assert!(t.is_empty());
    }

    #[test]
    fn remove_nonexistent_peer() {
        let mut t = HandshakeTracker::new();
        assert!(t.remove_peer("dev-1").is_none());
    }

    #[test]
    fn touch_activity() {
        let mut t = HandshakeTracker::new();
        t.register_peer("dev-1", "key", 1000);
        t.handshake_completed("dev-1", 1005);
        t.touch_activity("dev-1", 1010);
        // Session should still be established.
        assert!(t.is_established("dev-1"));
    }

    #[test]
    fn multiple_peers() {
        let mut t = HandshakeTracker::new();
        t.register_peer("dev-1", "key1", 1000);
        t.register_peer("dev-2", "key2", 1000);
        assert_eq!(t.len(), 2);
        t.handshake_completed("dev-1", 1005);
        assert!(t.is_established("dev-1"));
        assert!(!t.is_established("dev-2"));
    }

    #[test]
    fn handshake_completed_resets_failure_count() {
        let mut t = HandshakeTracker::new();
        t.register_peer("dev-1", "key", 1000);
        t.handshake_failed("dev-1", 1001);
        t.handshake_failed("dev-1", 1002);
        t.handshake_completed("dev-1", 1003);
        assert!(t.is_established("dev-1"));
        // Now a failure should restart from 0.
        let action = t.handshake_failed("dev-1", 1004);
        assert!(matches!(action, HandshakeAction::RetryHandshake { .. }));
        // Should still be in Handshaking (not Failed), because count was reset.
        assert_eq!(t.state("dev-1"), WgSessionState::Handshaking);
    }

    #[test]
    fn default_trait() {
        let t = HandshakeTracker::default();
        assert!(t.is_empty());
    }
}