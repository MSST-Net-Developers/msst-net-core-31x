//! Peer retention and persistence (3.0.x `node_cache`).
//!
//! A peer learned from the coordinator is kept while any reason holds:
//! - it is in our room (then 20 min after it/we left),
//! - an active rule names it (then 24 h after the last such rule went away),
//! - it sent us an authenticated WireGuard message / we fetched it (2 h).
//!
//! Housekeeping evicts peers with no reason left.  Peers in the peer list
//! that never got a reason (e.g. learned before this module tracked them)
//! are not evicted.  Our own device (in our user's node list and in room
//! member lists) is never tracked.
//!
//! The cache is saved to `peer_cache.json` every 5 minutes and on shutdown,
//! and restored at startup so known peers are reachable immediately.  (3.0.x
//! used `node_cache.json` in a different format; it is left untouched so a
//! downgrade still works — a lost cache only costs a re-fetch.)

use crate::state::CoreState;
use msst_acl_engine::PermissionGroup;
use msst_core_state::peer_mgmt::PersistedPeerCacheEntry;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, warn};

pub const FILE: &str = "peer_cache.json";

/// Our own device ID: not a peer, never cached.
async fn local_id(state: &CoreState) -> String {
    state.net.read().await.local_device_id.clone()
}

/// Room membership changed: `members` is the room's complete member list.
pub async fn on_room_members(state: &CoreState, members: &[String]) {
    let now = crate::runtime::current_unix();
    let own = local_id(state).await;
    let members: Vec<String> = members.iter().filter(|id| **id != own).cloned().collect();
    let members = members.as_slice();
    let previous: Vec<String> = state.room_cache_members.lock().unwrap_or_else(|e| e.into_inner()).drain().collect();
    let mut peers = state.peers.lock().await;
    for id in previous.iter().filter(|id| !members.contains(id)) {
        peers.mark_left_room(id, now);
    }
    for id in members {
        peers.mark_room_member(id);
    }
    drop(peers);
    state.room_cache_members.lock().unwrap_or_else(|e| e.into_inner()).extend(members.iter().cloned());
}

pub async fn on_member_joined(state: &CoreState, device_id: &str) {
    if device_id == local_id(state).await {
        return;
    }
    state.peers.lock().await.mark_room_member(device_id);
    state.room_cache_members.lock().unwrap_or_else(|e| e.into_inner()).insert(device_id.to_string());
}

pub async fn on_member_left(state: &CoreState, device_id: &str) {
    state.peers.lock().await.mark_left_room(device_id, crate::runtime::current_unix());
    state.room_cache_members.lock().unwrap_or_else(|e| e.into_inner()).remove(device_id);
}

/// We left our last room.
pub async fn on_rooms_left(state: &CoreState) {
    state.peers.lock().await.clear_room_membership(crate::runtime::current_unix());
    state.room_cache_members.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

/// `device_id` sent us an authenticated WireGuard message, or we fetched it.
pub async fn on_communication(state: &CoreState, device_id: &str) {
    if device_id == local_id(state).await {
        return;
    }
    state.peers.lock().await.touch_comm(device_id, crate::runtime::current_unix());
}

/// Recompute which devices active rules reference (called before eviction).
pub async fn sync_rule_refs(state: &CoreState) {
    let now = crate::runtime::current_unix();
    let current: HashSet<String> = state
        .net
        .read()
        .await
        .acl_rules
        .iter()
        .filter(|r| r.is_active(now))
        .flat_map(|r| match &r.permission_group {
            PermissionGroup::Devices { ids } => ids.iter().filter(|i| i.starts_with("device-")).cloned().collect(),
            _ => Vec::new(),
        })
        .collect();
    let previous = std::mem::replace(&mut *state.rule_ref_devices.lock().unwrap_or_else(|e| e.into_inner()), current.clone());
    let mut peers = state.peers.lock().await;
    for id in previous.difference(&current) {
        peers.clear_rule_ref(id, now);
    }
    for id in &current {
        peers.mark_rule_ref(id);
    }
}

/// Evict expired peers from every structure that holds them.
pub async fn evict_expired(state: &CoreState) {
    let now = crate::runtime::current_unix();
    let (evicted, _) = state.peers.lock().await.evict_expired(now);
    for id in &evicted {
        info!("peer_cache: evicted {}", id);
        state.scheduler.lock().await.remove_peer(id);
        state.encryption.lock().await.remove_peer(id);
        {
            let mut net = state.net.write().await;
            net.peer_list.remove(id);
            net.peer_endpoints.remove(id);
            net.peer_discovery.remove(id);
        }
        state.traffic.write().unwrap_or_else(|e| e.into_inner()).remove(id);
        state.next_generation();
        state.emit_ipc_event(msst_ipc_protocol::IpcEvent::NodeRemoved { device_id: id.clone() });
    }
}

/// Save the cache (with peer data) to the data directory.
pub async fn save(state: &CoreState) {
    let entries = {
        let peers = state.peers.lock().await;
        let net = state.net.read().await;
        peers.snapshot_for_persist(&net.peer_list)
    };
    match serde_json::to_vec_pretty(&entries) {
        Ok(bytes) => {
            if let Err(e) = crate::acl::store::write_atomic(&state.data_dir, FILE, &bytes) {
                warn!("peer_cache: save failed: {}", e);
            }
        }
        Err(e) => warn!("peer_cache: serialize failed: {}", e),
    }
}

/// Restore the cache and the peers' data at startup.
pub async fn restore(state: &Arc<CoreState>) {
    let path = state.data_dir.join(FILE);
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let entries: Vec<PersistedPeerCacheEntry> = match serde_json::from_str(&text) {
        Ok(e) => e,
        Err(e) => {
            warn!("peer_cache: ignoring unreadable {:?}: {}", path, e);
            return;
        }
    };
    let now = crate::runtime::current_unix();
    // Older Cores cached our own device too.
    let own = local_id(state).await;
    let entries: Vec<PersistedPeerCacheEntry> = entries.into_iter().filter(|e| e.device_id != own).collect();
    let mut restored = 0;
    for e in &entries {
        let Some(p) = &e.peer else { continue };
        let ok = crate::nodes::apply_peer(state, crate::nodes::PeerData {
            device_id: &e.device_id,
            ipv4: &p.ipv4,
            ipv6: &p.ipv6,
            user_id: p.user_id.as_deref(),
            device_handle: p.device_handle.as_deref(),
            user_handle: p.user_handle.as_deref(),
            hostname: p.hostname.as_deref(),
            display_name: p.display_name.clone(),
            user_display_name: p.user_display_name.clone(),
            is_authenticated: p.is_authenticated,
            ..Default::default()
        })
        .await;
        restored += ok as usize;
    }
    state.peers.lock().await.restore_from_persist(entries, now);
    info!("peer_cache: restored {} peer(s)", restored);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::core_state;

    async fn add_peer(state: &Arc<CoreState>, id: &str, v4: &str) {
        crate::nodes::apply_peer(state, crate::nodes::PeerData { device_id: id, ipv4: v4, ipv6: "fd22:2222:2222:2222::9", ..Default::default() }).await;
    }

    #[tokio::test]
    async fn room_members_survive_until_grace_ends() {
        let (state, _ipc) = core_state("pc-room").await;
        add_peer(&state, "device-0000000b", "172.22.1.1").await;
        on_room_members(&state, &["device-0000000b".into()]).await;
        evict_expired(&state).await;
        assert!(state.net.read().await.peer_list.contains("device-0000000b"));

        // Room state without the peer → grace period, then eviction.
        on_room_members(&state, &[]).await;
        evict_expired(&state).await;
        assert!(state.net.read().await.peer_list.contains("device-0000000b"), "within grace");
        let (evicted, _) = state.peers.lock().await.evict_expired(crate::runtime::current_unix() + 21 * 60);
        assert_eq!(evicted, vec!["device-0000000b".to_string()]);
    }

    #[tokio::test]
    async fn our_own_device_is_never_cached() {
        let (state, _ipc) = core_state("pc-self").await;
        let own = state.net.read().await.local_device_id.clone();
        on_communication(&state, &own).await;
        on_member_joined(&state, &own).await;
        on_room_members(&state, &[own.clone(), "device-0000000b".into()]).await;
        on_room_members(&state, &[]).await;
        // Long after every grace period: nothing of ours to evict.
        let (evicted, _) = state.peers.lock().await.evict_expired(crate::runtime::current_unix() + 25 * 3600);
        assert_eq!(evicted, vec!["device-0000000b".to_string()]);
    }

    #[tokio::test]
    async fn rule_references_keep_peers() {
        let (state, _ipc) = core_state("pc-rule").await;
        add_peer(&state, "device-0000000b", "172.22.1.1").await;
        on_communication(&state, "device-0000000b").await;
        state.net.write().await.acl_rules.push(msst_acl_engine::FirewallRule {
            id: "r".into(),
            permission_group: PermissionGroup::Devices { ids: vec!["device-0000000b".into()] },
            protocol_ports: vec![], action: msst_acl_engine::Action::Allow,
            direction: msst_acl_engine::Direction::Inbound, expires_at: None, enabled: true, comment: None,
        });
        sync_rule_refs(&state).await;
        // Far beyond the 2 h communication TTL: still referenced by a rule.
        let (evicted, _) = state.peers.lock().await.evict_expired(crate::runtime::current_unix() + 3 * 3600);
        assert!(evicted.is_empty());
        state.net.write().await.acl_rules.clear();
        sync_rule_refs(&state).await;
        let (evicted, _) = state.peers.lock().await.evict_expired(crate::runtime::current_unix() + 25 * 3600);
        assert_eq!(evicted.len(), 1);
    }

    #[tokio::test]
    async fn save_and_restore() {
        let (state, _ipc) = core_state("pc-persist").await;
        add_peer(&state, "device-0000000b", "172.22.1.1").await;
        on_communication(&state, "device-0000000b").await;
        save(&state).await;

        let (fresh, _ipc2) = core_state("pc-persist-2").await;
        std::fs::copy(state.data_dir.join(FILE), fresh.data_dir.join(FILE)).unwrap();
        restore(&fresh).await;
        let net = fresh.net.read().await;
        assert_eq!(net.peer_list.lookup_device_id_by_ip(&"172.22.1.1".parse().unwrap()), Some("device-0000000b"));
        drop(net);
        assert_eq!(fresh.peers.lock().await.cache_len(), 1);
    }
}
