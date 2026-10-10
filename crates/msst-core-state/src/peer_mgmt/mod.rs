//! Peer management — discovery, liveness, and cache lifecycle.
//!
//! This module sits between the coordinator event stream and the `PeerList`.
//! It decides *when* and *why* to add, update, or evict a peer, using:
//!
//! - **Peer events** from the coordinator (`room_state`, `node_update`, etc.)
//! - **Liveness signals** from packet processing (`touch_seen`, `touch_comm`)
//! - **TTL-based cache** with per-reason expiry (room member, rule ref, recent comm)
//!
//! ## Lifecycle
//!
//! ```text
//! Coordinator event ──► PeerManager::apply_event()
//!                         ├─ upsert into PeerList
//!                         ├─ mark reason in NodeCache
//!                         └─ update LivenessTracker
//!
//! Packet received ────► PeerManager::touch_seen()
//!                         └─ refresh liveness
//!
//! Periodic tick ───────► PeerManager::evict_expired()
//!                         └─ remove peers with no active reasons
//! ```

pub mod handshake;
pub mod liveness;
pub mod node_cache;

use crate::peer_list::PeerList;
use handshake::{HandshakeAction, HandshakeTracker};
use liveness::LivenessTracker;
use node_cache::NodeCache;
use std::net::IpAddr;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// PeerEvent — events from the coordinator or packet processing
// ---------------------------------------------------------------------------

/// An event that affects peer state.
///
/// These are the inputs to `PeerManager::apply_event()`.  Each event
/// corresponds to a coordinator WebSocket message or a data-plane signal.
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// A room_state update: the full set of peers in the current room.
    RoomState {
        room_id: String,
        peers: Vec<RoomPeerInfo>,
    },
    /// A peer left the room.
    RoomPeerLeft {
        device_id: String,
    },
    /// We left a room — clear all room membership.
    RoomLeft {
        room_id: String,
    },
    /// A peer's endpoints were updated (coordinator or NAT rebinding).
    EndpointsUpdated {
        device_id: String,
        endpoints: Vec<String>,
    },
    /// A peer's authentication status changed.
    AuthStatusChanged {
        device_id: String,
        is_authenticated: bool,
    },
    /// A coordinator node query returned data for a specific device.
    NodeFetched {
        device_id: String,
        ipv4: String,
        ipv6: String,
        user_id: Option<String>,
        device_handle: Option<String>,
        user_handle: Option<String>,
        hostname: Option<String>,
        display_name: Option<String>,
        user_display_name: Option<String>,
        public_key: Option<String>,
        is_authenticated: bool,
        endpoints: Vec<String>,
    },
}

/// Peer info from a room_state coordinator event.
#[derive(Debug, Clone)]
pub struct RoomPeerInfo {
    pub device_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub hostname: Option<String>,
    pub display_name: Option<String>,
    pub user_display_name: Option<String>,
    pub public_key: Option<String>,
    pub is_authenticated: bool,
    pub endpoints: Vec<String>,
    pub preferred_relay: Option<String>,
}

// ---------------------------------------------------------------------------
// PeerManager
// ---------------------------------------------------------------------------

/// Orchestrates peer lifecycle: discovery, liveness, and eviction.
///
/// Owns a `NodeCache`, `LivenessTracker`, and `HandshakeTracker`.
/// Operates on a `PeerList` (passed by reference) so that state ownership
/// stays clear.
pub struct PeerManager {
    cache: NodeCache,
    liveness: LivenessTracker,
    pub handshakes: HandshakeTracker,
}

impl PeerManager {
    pub fn new() -> Self {
        PeerManager {
            cache: NodeCache::new(),
            liveness: LivenessTracker::new(),
            handshakes: HandshakeTracker::new(),
        }
    }

    // ── Event processing ──────────────────────────────────────────────────

    /// Apply a peer event, updating the PeerList, NodeCache, and
    /// LivenessTracker as needed.
    ///
    /// Returns a list of side effects the caller should execute (e.g.
    /// WireGuard session add, endpoint probe trigger).
    pub fn apply_event(
        &mut self,
        event: &PeerEvent,
        peer_list: &mut PeerList,
        now_unix: i64,
    ) -> Vec<PeerSideEffect> {
        match event {
            PeerEvent::RoomState { room_id: _, peers } => {
                let mut effects = Vec::new();
                for peer in peers {
                    self.upsert_from_room(peer, peer_list, now_unix);
                    if let Some(pk) = &peer.public_key {
                        // Register with handshake tracker.
                        let action = self.handshakes.register_peer(
                            &peer.device_id, pk, now_unix,
                        );
                        if let HandshakeAction::AddSession { device_id, public_key_b64 } = action {
                            effects.push(PeerSideEffect::WgAddPeer {
                                device_id,
                                public_key_b64,
                            });
                        }
                    }
                    if let Some(relay) = &peer.preferred_relay {
                        peer_list.update_relay(&peer.device_id, relay);
                    }
                }
                effects
            }
            PeerEvent::RoomPeerLeft { device_id } => {
                self.cache.mark_left_room(device_id, now_unix);
                // Remove WG session when peer leaves room.
                if let Some(action) = self.handshakes.remove_peer(device_id) {
                    if let HandshakeAction::RemoveSession { device_id } = action {
                        return vec![PeerSideEffect::WgRemovePeer { device_id }];
                    }
                }
                vec![]
            }
            PeerEvent::RoomLeft { room_id: _ } => {
                self.cache.clear_all_room_membership(now_unix);
                vec![]
            }
            PeerEvent::EndpointsUpdated { device_id, endpoints } => {
                let parsed: Vec<std::net::SocketAddr> = endpoints
                    .iter()
                    .filter_map(|ep| ep.parse().ok())
                    .collect();
                if !parsed.is_empty() {
                    // Update endpoints in peer list (additive).
                    // PeerList doesn't have update_endpoints yet — store as effect.
                }
                vec![PeerSideEffect::ProbeEndpoints {
                    device_id: device_id.clone(),
                    endpoints: parsed,
                }]
            }
            PeerEvent::AuthStatusChanged { device_id, is_authenticated } => {
                // Clone the entry data so we don't hold a borrow on peer_list
                // while calling upsert (which needs &mut).
                let snapshot = peer_list.get(device_id).cloned();
                if let Some(entry) = snapshot {
                    peer_list.upsert(
                        device_id,
                        entry.ipv4,
                        entry.ipv6,
                        entry.user_id.as_deref(),
                        entry.device_handle.as_deref(),
                        entry.user_handle.as_deref(),
                        entry.hostname.as_deref(),
                        entry.display_name.clone(),
                        entry.user_display_name.clone(),
                        *is_authenticated,
                        now_unix,
                    );
                }
                vec![]
            }
            PeerEvent::NodeFetched {
                device_id, ipv4, ipv6, user_id, device_handle, user_handle,
                hostname, display_name, user_display_name, public_key,
                is_authenticated, endpoints,
            } => {
                let ipv4_addr: IpAddr = match ipv4.parse() {
                    Ok(a) => a,
                    Err(_) => return vec![],
                };
                let ipv6_addr: IpAddr = match ipv6.parse() {
                    Ok(a) => a,
                    Err(_) => return vec![],
                };
                peer_list.upsert(
                    device_id,
                    ipv4_addr,
                    ipv6_addr,
                    user_id.as_deref(),
                    device_handle.as_deref(),
                    user_handle.as_deref(),
                    hostname.as_deref(),
                    display_name.clone(),
                    user_display_name.clone(),
                    *is_authenticated,
                    now_unix,
                );
                self.cache.mark_fetched(device_id);
                self.liveness.touch(device_id, now_unix);

                let mut effects = vec![];
                if let Some(pk) = public_key {
                    effects.push(PeerSideEffect::WgAddPeer {
                        device_id: device_id.clone(),
                        public_key_b64: pk.clone(),
                    });
                }
                let parsed_eps: Vec<std::net::SocketAddr> = endpoints
                    .iter()
                    .filter_map(|ep| ep.parse().ok())
                    .collect();
                if !parsed_eps.is_empty() {
                    effects.push(PeerSideEffect::ProbeEndpoints {
                        device_id: device_id.clone(),
                        endpoints: parsed_eps,
                    });
                }
                effects
            }
        }
    }

    // ── Liveness signals (from data plane) ────────────────────────────────

    /// Record that we saw a packet from this peer (any traffic).
    pub fn touch_seen(&mut self, device_id: &str, now_unix: i64) {
        self.liveness.touch(device_id, now_unix);
        self.handshakes.touch_activity(device_id, now_unix);
    }

    /// Record that we communicated with this peer (ACL-allowed traffic).
    /// Extends the comm TTL in the node cache.
    pub fn touch_comm(&mut self, device_id: &str, now_unix: i64) {
        self.liveness.touch(device_id, now_unix);
        self.cache.extend_comm(device_id, now_unix);
    }

    /// Mark a device as currently in our room (kept while in the room).
    pub fn mark_room_member(&mut self, device_id: &str) {
        self.cache.mark_room_member(device_id);
    }

    /// A device left our room: start its 20-minute grace period.
    pub fn mark_left_room(&mut self, device_id: &str, now_unix: i64) {
        self.cache.mark_left_room(device_id, now_unix);
    }

    /// We left our rooms: every member starts its grace period.
    pub fn clear_room_membership(&mut self, now_unix: i64) {
        self.cache.clear_all_room_membership(now_unix);
    }

    /// Mark a device as referenced by an active firewall rule.
    pub fn mark_rule_ref(&mut self, device_id: &str) {
        self.cache.mark_rule_active(device_id);
    }

    /// Clear rule-reference mark (when all rules referencing this device are deleted).
    pub fn clear_rule_ref(&mut self, device_id: &str, now_unix: i64) {
        self.cache.clear_rule_active(device_id, now_unix);
    }

    // ── Eviction ──────────────────────────────────────────────────────────

    /// Evict peers whose cache entries have expired (no active reasons).
    /// Returns the list of evicted device IDs.
    ///
    /// Also removes WireGuard sessions for evicted peers and returns the
    /// side effects the caller should execute.
    pub fn evict_expired(&mut self, now_unix: i64) -> (Vec<String>, Vec<PeerSideEffect>) {
        let expired = self.cache.drain_expired(now_unix);
        let mut effects = Vec::new();
        for id in &expired {
            self.liveness.remove(id);
            if let Some(action) = self.handshakes.remove_peer(id) {
                if let HandshakeAction::RemoveSession { device_id } = action {
                    effects.push(PeerSideEffect::WgRemovePeer { device_id });
                }
            }
            info!("peer_mgmt: evicted {}", id);
        }
        (expired, effects)
    }

    /// Check for WireGuard handshake timeouts.
    /// Returns actions the caller should execute (retry or give up).
    pub fn check_handshake_timeouts(&mut self, now_unix: i64) -> Vec<HandshakeAction> {
        self.handshakes.check_timeouts(now_unix)
    }

    // ── Cache persistence ─────────────────────────────────────────────────

    /// Snapshot the cache for persistence.
    pub fn snapshot_for_persist(&self, peer_list: &PeerList) -> Vec<PersistedPeerCacheEntry> {
        self.cache.snapshot(peer_list)
    }

    /// Restore the cache from a persisted snapshot.
    pub fn restore_from_persist(&mut self, entries: Vec<PersistedPeerCacheEntry>, now_unix: i64) {
        self.cache.restore(entries, now_unix);
    }

    // ── Queries ───────────────────────────────────────────────────────────

    /// Is this device tracked in the cache (even if data isn't fetched yet)?
    pub fn is_cached(&self, device_id: &str) -> bool {
        self.cache.is_valid(device_id)
    }

    /// When did we last see this peer? (Unix seconds, or None.)
    pub fn last_seen(&self, device_id: &str) -> Option<i64> {
        self.liveness.last_seen(device_id)
    }

    /// Number of cached peers.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn upsert_from_room(&mut self, peer: &RoomPeerInfo, peer_list: &mut PeerList, now_unix: i64) {
        let ipv4: IpAddr = match peer.ipv4.parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        let ipv6: IpAddr = match peer.ipv6.parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        peer_list.upsert(
            &peer.device_id,
            ipv4,
            ipv6,
            None, // user_id comes from /sync, not room_state
            None,
            None,
            peer.hostname.as_deref(),
            peer.display_name.clone(),
            peer.user_display_name.clone(),
            peer.is_authenticated,
            now_unix,
        );
        self.cache.mark_room_member(&peer.device_id);
        self.liveness.touch(&peer.device_id, now_unix);
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Side effects — returned by apply_event, executed by the caller
// ---------------------------------------------------------------------------

/// A side effect that the peer manager requests the caller to execute.
///
/// These are NOT executed inside the manager — the caller (Core runtime)
/// translates them into actual WireGuard operations, UDP sends, etc.
#[derive(Debug, Clone)]
pub enum PeerSideEffect {
    /// Add a WireGuard peer session.
    WgAddPeer {
        device_id: String,
        public_key_b64: String,
    },
    /// Remove a WireGuard peer session.
    WgRemovePeer {
        device_id: String,
    },
    /// Trigger a P2P endpoint probe for this peer.
    ProbeEndpoints {
        device_id: String,
        endpoints: Vec<std::net::SocketAddr>,
    },
}

// ---------------------------------------------------------------------------
// PersistedPeerCacheEntry — for disk persistence
// ---------------------------------------------------------------------------

/// A cache entry snapshot for persistence to disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedPeerCacheEntry {
    pub device_id: String,
    pub cache: PersistedCacheEntry,
    pub peer: Option<PersistedPeerData>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedCacheEntry {
    pub room_until: Option<i64>,
    pub rule_active: bool,
    pub rule_until: Option<i64>,
    pub comm_until: Option<i64>,
    pub has_data: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedPeerData {
    pub user_id: Option<String>,
    pub device_handle: Option<String>,
    pub user_handle: Option<String>,
    pub hostname: Option<String>,
    pub ipv4: String,
    pub ipv6: String,
    pub display_name: Option<String>,
    pub user_display_name: Option<String>,
    pub is_authenticated: bool,
}