//! ACL management — rule/group CRUD, persistence, mnemonic resolution and
//! migration of 3.0.x rules.
//!
//! Core owns the rules: `NetState::acl_rules` is the single list the packet
//! pipeline evaluates.  Every mutation goes through this module, which
//! persists the new state and emits an `AclChanged` / `AclGroupChanged`
//! event.

pub mod parse;
pub mod resolve;
pub mod store;

use crate::state::CoreState;
use msst_acl_engine::FirewallRule;
use msst_ipc_protocol::{IpcError, IpcEvent};
use parse::{RulePatch, RuleRequest};
use resolve::{Kind, LocalIdentity, RemoteResolver, ResolveFailure};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use store::{PermissionGroupDef, StoredRule};
use tracing::{error, info, warn};

fn ipc_err(code: &str, message: impl Into<String>) -> IpcError {
    IpcError { code: code.into(), message: message.into() }
}

// ---------------------------------------------------------------------------
// Coordinator-backed resolver
// ---------------------------------------------------------------------------

/// Resolves mnemonics through the coordinator's REST API.
pub struct CoordResolver {
    http: reqwest::Client,
    coord_url: String,
    bearer: Option<String>,
}

impl CoordResolver {
    /// Build from the running coordinator client, if any.
    pub async fn from_state(state: &CoreState) -> Option<Self> {
        let client = state.coordinator.get()?;
        let bearer = state
            .identity
            .read()
            .await
            .as_ref()
            .and_then(|i| i.auth.as_ref())
            .map(|a| a.access_token.clone())
            .filter(|t| !t.is_empty());
        Some(CoordResolver {
            http: client.http().clone(),
            coord_url: client.coord_url().trim_end_matches('/').to_string(),
            bearer,
        })
    }

    async fn get_json(&self, url: &str) -> Result<Option<Value>, String> {
        let mut req = self.http.get(url).timeout(std::time::Duration::from_secs(10));
        if let Some(t) = &self.bearer {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        resp.json().await.map(Some).map_err(|e| e.to_string())
    }
}

impl RemoteResolver for CoordResolver {
    /// `GET /dns/resolve?name=<hostname>` → `{"device_id": ...}` (as 3.0.x).
    async fn device_id(&self, hostname: &str) -> Result<Option<String>, String> {
        let url = format!("{}/dns/resolve?name={}", self.coord_url, hostname);
        Ok(self.get_json(&url).await?.and_then(|v| v["device_id"].as_str().map(str::to_string)))
    }

    /// `GET /nodes/by-user/<handle>` → `{"nodes": [{"user_id": ...}]}`.
    async fn user_id(&self, handle: &str) -> Result<Option<String>, String> {
        let url = format!("{}/nodes/by-user/{}", self.coord_url, handle);
        Ok(self.get_json(&url).await?.and_then(|v| {
            v["nodes"]
                .as_array()?
                .iter()
                .find_map(|n| n["user_id"].as_str().filter(|s| !s.is_empty()).map(str::to_string))
        }))
    }
}

/// Used when the coordinator client isn't running.
struct NoRemote;

impl RemoteResolver for NoRemote {
    async fn device_id(&self, _: &str) -> Result<Option<String>, String> {
        Err("coordinator client not started".into())
    }
    async fn user_id(&self, _: &str) -> Result<Option<String>, String> {
        Err("coordinator client not started".into())
    }
}

async fn local_identity(state: &CoreState) -> LocalIdentity {
    state
        .identity
        .read()
        .await
        .as_ref()
        .map(|i| LocalIdentity {
            device_id: i.device.id.clone(),
            device_handle: i.device.handle.clone(),
            user_id: i.user.id.clone(),
            user_handle: i.user.handle.clone(),
        })
        .unwrap_or_default()
}

/// Resolve every mnemonic in `rule` (local first, then the coordinator).
/// Returns the rewritten rule and its display map.
async fn resolve_rule(
    state: &CoreState,
    rule: &FirewallRule,
    remote: &impl RemoteResolver,
) -> Result<(FirewallRule, BTreeMap<String, String>), ResolveFailure> {
    let pending = resolve::mnemonics(&rule.permission_group);
    if pending.is_empty() {
        return Ok((rule.clone(), BTreeMap::new()));
    }
    let me = local_identity(state).await;
    let (mut resolved, remaining): (BTreeMap<String, String>, Vec<(Kind, String)>) = {
        let net = state.net.read().await;
        let mut hits = BTreeMap::new();
        let mut rest = Vec::new();
        for (kind, m) in pending {
            match resolve::resolve_locally(kind, &m, &me, &net.peer_list) {
                Some(id) => {
                    hits.insert(m, id);
                }
                None => rest.push((kind, m)),
            }
        }
        (hits, rest)
    };
    resolved.extend(resolve::resolve_remotely(&remaining, &me, remote).await?);
    let (pg, labels) = resolve::apply_resolution(&rule.permission_group, &resolved);
    let mut rule = rule.clone();
    rule.permission_group = pg;
    Ok((rule, labels))
}

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------

async fn snapshot_rules(state: &CoreState) -> Vec<StoredRule> {
    let net = state.net.read().await;
    net.acl_rules
        .iter()
        .map(|r| StoredRule {
            rule: r.clone(),
            principal_mnemonics: net.acl_labels.get(&r.id).cloned().unwrap_or_default(),
        })
        .collect()
}

/// Persist the current rules.  Caller must hold `state.acl_persist`.
async fn persist_rules(state: &CoreState) -> Result<(), IpcError> {
    let rules = snapshot_rules(state).await;
    store::save_rules(&state.data_dir, &rules).map_err(|e| {
        error!("acl: failed to persist rules: {}", e);
        ipc_err("persist_failed", format!("failed to save rules: {}", e))
    })
}

async fn persist_groups(state: &CoreState) -> Result<(), IpcError> {
    let groups = state.acl_groups.read().await.clone();
    store::save_groups(&state.data_dir, &groups).map_err(|e| {
        error!("acl: failed to persist permission groups: {}", e);
        ipc_err("persist_failed", format!("failed to save permission groups: {}", e))
    })
}

/// JSON view of a rule for the Controller: the rule fields plus the display
/// mnemonics and whether it still contains unresolved (3.0.x) mnemonics.
pub fn rule_view(rule: &FirewallRule, labels: Option<&BTreeMap<String, String>>) -> Value {
    let mut v = serde_json::to_value(rule).unwrap_or(Value::Null);
    v["principal_mnemonics"] = json!(labels.cloned().unwrap_or_default());
    v["pending_migration"] = json!(!resolve::mnemonics(&rule.permission_group).is_empty());
    v
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

/// Load rules, groups and the ping setting from the data directory.
///
/// A corrupt rules file is moved aside (never silently overwritten); Core
/// then starts with no rules, i.e. default-deny.
pub async fn load(state: &CoreState) {
    let dir = &state.data_dir;
    let rules = match store::load_rules(dir) {
        Ok(r) => r,
        Err(e) => {
            let aside = dir.join(format!("{}.corrupt-{}", store::RULES_FILE, unix_now()));
            error!("acl: {} — moved to {:?}; starting with no rules (default deny)", e, aside);
            let _ = std::fs::rename(dir.join(store::RULES_FILE), &aside);
            Vec::new()
        }
    };
    let pending = rules.iter().filter(|r| !resolve::mnemonics(&r.rule.permission_group).is_empty()).count();
    {
        let mut net = state.net.write().await;
        net.acl_labels = rules
            .iter()
            .filter(|r| !r.principal_mnemonics.is_empty())
            .map(|r| (r.rule.id.clone(), r.principal_mnemonics.clone()))
            .collect();
        net.acl_rules = rules.into_iter().map(|r| r.rule).collect();
        net.ping_enabled = store::load_ping_enabled(dir);
        info!(
            "acl: loaded {} rule(s) ({} awaiting mnemonic migration); ping {}",
            net.acl_rules.len(),
            pending,
            if net.ping_enabled { "enabled" } else { "disabled" }
        );
    }
    match store::load_groups(dir) {
        Ok(g) => {
            info!("acl: loaded {} permission group(s)", g.len());
            *state.acl_groups.write().await = g;
        }
        Err(e) => warn!("acl: failed to load permission groups: {}", e),
    }
}

/// Try to rewrite mnemonics in loaded 3.0.x rules to IDs.
///
/// Rules that can't be resolved yet stay as they are (still matched by
/// mnemonic, as in 3.0.x) and are retried on the next call.  A rule edited
/// while its resolution was in flight is left alone.
pub async fn migrate_pending(state: &Arc<CoreState>) {
    let candidates: Vec<FirewallRule> = state
        .net
        .read()
        .await
        .acl_rules
        .iter()
        .filter(|r| !resolve::mnemonics(&r.permission_group).is_empty())
        .cloned()
        .collect();
    if candidates.is_empty() {
        return;
    }
    let remote = CoordResolver::from_state(state).await;
    let mut migrated = Vec::new();
    for rule in candidates {
        let result = match &remote {
            Some(r) => resolve_rule(state, &rule, r).await,
            None => resolve_rule(state, &rule, &NoRemote).await,
        };
        match result {
            Ok((new_rule, labels)) => migrated.push((rule, new_rule, labels)),
            Err(e) => warn!("acl: rule {} still awaiting migration: {}", rule.id, e),
        }
    }
    if migrated.is_empty() {
        return;
    }

    let _io = state.acl_persist.lock().await;
    let mut applied = Vec::new();
    {
        let mut net = state.net.write().await;
        for (old, new, labels) in migrated {
            let Some(slot) = net.acl_rules.iter_mut().find(|r| r.id == old.id) else { continue };
            // Unchanged since we read it?  (Compare the principal set only.)
            if serde_json::to_value(&slot.permission_group).ok() != serde_json::to_value(&old.permission_group).ok() {
                continue;
            }
            slot.permission_group = new.permission_group;
            net.acl_labels.entry(old.id.clone()).or_default().extend(labels);
            applied.push(old.id);
        }
    }
    if applied.is_empty() {
        return;
    }
    let _ = persist_rules(state).await;
    state.next_generation();
    for id in applied {
        info!("acl: migrated mnemonics of rule {} to stable IDs", id);
        state.emit_ipc_event(IpcEvent::AclChanged { rule_id: id, action: "updated".into() });
    }
}

// ---------------------------------------------------------------------------
// Rule CRUD
// ---------------------------------------------------------------------------

pub async fn list_rules(state: &CoreState) -> Value {
    let net = state.net.read().await;
    let rules: Vec<Value> = net.acl_rules.iter().map(|r| rule_view(r, net.acl_labels.get(&r.id))).collect();
    json!({ "rules": rules })
}

/// Create a rule from a 3.0.x-shaped `RuleRequest`.  Mnemonics are resolved
/// to IDs before the rule is stored; if any can't be, the rule is rejected.
pub async fn create_rule(state: &Arc<CoreState>, request: Value) -> Result<Value, IpcError> {
    let mut req: RuleRequest =
        serde_json::from_value(request).map_err(|e| ipc_err("invalid_rule", format!("Invalid rule: {}", e)))?;

    if let Some(gid) = req.group_id.clone() {
        if !req.principals.is_empty() {
            return Err(ipc_err("invalid_rule", "Cannot specify both group_id and principals"));
        }
        let groups = state.acl_groups.read().await;
        let group = groups
            .iter()
            .find(|g| g.id == gid)
            .ok_or_else(|| ipc_err("not_found", format!("Permission group '{}' not found", gid)))?;
        req.principals = group
            .member_ids
            .iter()
            .map(|id| parse::RawPrincipal { kind: group.kind.clone(), id: id.clone() })
            .collect();
    }

    let rule = parse::parse_rule(req).map_err(|e| ipc_err("invalid_rule", e))?;
    let (rule, labels) = match CoordResolver::from_state(state).await {
        Some(r) => resolve_rule(state, &rule, &r).await,
        None => resolve_rule(state, &rule, &NoRemote).await,
    }
    .map_err(|e| match e {
        ResolveFailure::NotFound { .. } => ipc_err("mnemonic_not_found", e.to_string()),
        ResolveFailure::Unavailable { .. } => ipc_err("coordinator_unavailable", e.to_string()),
    })?;

    let _io = state.acl_persist.lock().await;
    {
        let mut net = state.net.write().await;
        net.acl_rules.push(rule.clone());
        if !labels.is_empty() {
            net.acl_labels.insert(rule.id.clone(), labels.clone());
        }
    }
    if let Err(e) = persist_rules(state).await {
        // Roll back so memory and disk agree.
        let mut net = state.net.write().await;
        net.acl_rules.retain(|r| r.id != rule.id);
        net.acl_labels.remove(&rule.id);
        return Err(e);
    }
    state.next_generation();
    info!("acl: created rule {} (action={:?}, direction={:?})", rule.id, rule.action, rule.direction);
    state.emit_ipc_event(IpcEvent::AclChanged { rule_id: rule.id.clone(), action: "created".into() });
    crate::nodes::demand_rule_targets(state).await;
    Ok(json!({ "rule": rule_view(&rule, Some(&labels)) }))
}

/// Store a rule generated by Core itself (interactive-auth decisions).
/// Its principals are already stable IDs.
pub async fn insert_rule(state: &Arc<CoreState>, rule: FirewallRule) -> Result<Value, IpcError> {
    let _io = state.acl_persist.lock().await;
    state.net.write().await.acl_rules.push(rule.clone());
    if let Err(e) = persist_rules(state).await {
        state.net.write().await.acl_rules.retain(|r| r.id != rule.id);
        return Err(e);
    }
    state.next_generation();
    state.emit_ipc_event(IpcEvent::AclChanged { rule_id: rule.id.clone(), action: "created".into() });
    Ok(rule_view(&rule, None))
}

/// Delete every rule (3.0.x `DELETE /firewall/rules`).  Returns the count.
pub async fn clear_rules(state: &Arc<CoreState>) -> Result<Value, IpcError> {
    let _io = state.acl_persist.lock().await;
    let (rules, labels) = {
        let mut net = state.net.write().await;
        (std::mem::take(&mut net.acl_rules), std::mem::take(&mut net.acl_labels))
    };
    if let Err(e) = persist_rules(state).await {
        let mut net = state.net.write().await;
        net.acl_rules = rules;
        net.acl_labels = labels;
        return Err(e);
    }
    state.next_generation();
    info!("acl: cleared {} rule(s)", rules.len());
    for r in &rules {
        state.emit_ipc_event(IpcEvent::AclChanged { rule_id: r.id.clone(), action: "deleted".into() });
    }
    Ok(json!({ "deleted": rules.len() }))
}

/// Update `enabled` / `comment` / `expires_at` (3.0.x `PUT /firewall/rules/:id`).
pub async fn update_rule(state: &Arc<CoreState>, rule_id: &str, patch: Value) -> Result<Value, IpcError> {
    let patch: RulePatch = serde_json::from_value(patch).map_err(|e| ipc_err("invalid_patch", e.to_string()))?;
    let _io = state.acl_persist.lock().await;
    let (before, view) = {
        let mut net = state.net.write().await;
        let rule = net
            .acl_rules
            .iter_mut()
            .find(|r| r.id == rule_id)
            .ok_or_else(|| ipc_err("not_found", format!("Rule '{}' not found", rule_id)))?;
        let before = rule.clone();
        if let Some(en) = patch.enabled {
            rule.enabled = en;
        }
        if let Some(c) = patch.comment {
            rule.comment = Some(c);
        }
        if patch.expires_at.is_some() {
            rule.expires_at = patch.expires_at;
        }
        let rule = rule.clone();
        (before, rule_view(&rule, net.acl_labels.get(rule_id)))
    };
    if let Err(e) = persist_rules(state).await {
        if let Some(r) = state.net.write().await.acl_rules.iter_mut().find(|r| r.id == rule_id) {
            *r = before;
        }
        return Err(e);
    }
    state.next_generation();
    info!("acl: updated rule {}", rule_id);
    state.emit_ipc_event(IpcEvent::AclChanged { rule_id: rule_id.into(), action: "updated".into() });
    Ok(json!({ "rule": view }))
}

pub async fn delete_rule(state: &Arc<CoreState>, rule_id: &str) -> Result<Value, IpcError> {
    let _io = state.acl_persist.lock().await;
    let removed = {
        let mut net = state.net.write().await;
        let Some(pos) = net.acl_rules.iter().position(|r| r.id == rule_id) else {
            return Err(ipc_err("not_found", format!("Rule '{}' not found", rule_id)));
        };
        let rule = net.acl_rules.remove(pos);
        let labels = net.acl_labels.remove(rule_id);
        (pos, rule, labels)
    };
    if let Err(e) = persist_rules(state).await {
        let (pos, rule, labels) = removed;
        let mut net = state.net.write().await;
        let pos = pos.min(net.acl_rules.len());
        net.acl_rules.insert(pos, rule);
        if let Some(l) = labels {
            net.acl_labels.insert(rule_id.into(), l);
        }
        return Err(e);
    }
    state.next_generation();
    info!("acl: deleted rule {}", rule_id);
    state.emit_ipc_event(IpcEvent::AclChanged { rule_id: rule_id.into(), action: "deleted".into() });
    Ok(json!({ "ok": true }))
}

/// Remove rules whose `expires_at` has passed (3.0.x removes, not disables).
pub async fn expire_rules(state: &Arc<CoreState>, now: i64) {
    let _io = state.acl_persist.lock().await;
    let expired: Vec<String> = {
        let mut net = state.net.write().await;
        let ids: Vec<String> = net
            .acl_rules
            .iter()
            .filter(|r| r.expires_at.is_some_and(|t| t < now))
            .map(|r| r.id.clone())
            .collect();
        net.acl_rules.retain(|r| !ids.contains(&r.id));
        for id in &ids {
            net.acl_labels.remove(id);
        }
        ids
    };
    if expired.is_empty() {
        return;
    }
    let _ = persist_rules(state).await;
    state.next_generation();
    for id in expired {
        info!("acl: rule {} expired and was removed", id);
        state.emit_ipc_event(IpcEvent::AclChanged { rule_id: id, action: "deleted".into() });
    }
}

// ---------------------------------------------------------------------------
// Permission groups
// ---------------------------------------------------------------------------

pub async fn list_groups(state: &CoreState) -> Value {
    json!({ "groups": *state.acl_groups.read().await })
}

pub async fn create_group(state: &Arc<CoreState>, group: Value) -> Result<Value, IpcError> {
    #[derive(serde::Deserialize)]
    struct Req {
        name: String,
        kind: String,
        #[serde(default)]
        member_ids: Vec<String>,
    }
    let req: Req = serde_json::from_value(group).map_err(|e| ipc_err("invalid_group", e.to_string()))?;
    if req.kind != "user" && req.kind != "device" {
        return Err(ipc_err("invalid_group", "kind must be 'user' or 'device'"));
    }
    if req.name.trim().is_empty() {
        return Err(ipc_err("invalid_group", "name must not be empty"));
    }
    for m in &req.member_ids {
        parse::validate_principal_id(&req.kind, m).map_err(|e| ipc_err("invalid_group", e))?;
    }
    let group = PermissionGroupDef { id: parse::new_id(), name: req.name.trim().into(), kind: req.kind, member_ids: req.member_ids };
    let _io = state.acl_persist.lock().await;
    state.acl_groups.write().await.push(group.clone());
    if let Err(e) = persist_groups(state).await {
        state.acl_groups.write().await.retain(|g| g.id != group.id);
        return Err(e);
    }
    info!("acl: created permission group {} ('{}', kind={})", group.id, group.name, group.kind);
    state.emit_ipc_event(IpcEvent::AclGroupChanged { group_id: group.id.clone(), action: "created".into() });
    Ok(json!({ "group": group }))
}

pub async fn update_group(state: &Arc<CoreState>, group_id: &str, patch: Value) -> Result<Value, IpcError> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Patch {
        name: Option<String>,
        member_ids: Option<Vec<String>>,
    }
    let patch: Patch = serde_json::from_value(patch).map_err(|e| ipc_err("invalid_patch", e.to_string()))?;
    let _io = state.acl_persist.lock().await;
    let (before, after) = {
        let mut groups = state.acl_groups.write().await;
        let g = groups
            .iter_mut()
            .find(|g| g.id == group_id)
            .ok_or_else(|| ipc_err("not_found", format!("Group '{}' not found", group_id)))?;
        let before = g.clone();
        if let Some(name) = patch.name {
            if name.trim().is_empty() {
                return Err(ipc_err("invalid_patch", "name must not be empty"));
            }
            g.name = name.trim().into();
        }
        if let Some(ids) = patch.member_ids {
            for m in &ids {
                parse::validate_principal_id(&g.kind, m).map_err(|e| ipc_err("invalid_patch", e))?;
            }
            g.member_ids = ids;
        }
        (before, g.clone())
    };
    if let Err(e) = persist_groups(state).await {
        if let Some(g) = state.acl_groups.write().await.iter_mut().find(|g| g.id == group_id) {
            *g = before;
        }
        return Err(e);
    }
    state.emit_ipc_event(IpcEvent::AclGroupChanged { group_id: group_id.into(), action: "updated".into() });
    Ok(json!({ "group": after }))
}

pub async fn delete_group(state: &Arc<CoreState>, group_id: &str) -> Result<Value, IpcError> {
    let _io = state.acl_persist.lock().await;
    let removed = {
        let mut groups = state.acl_groups.write().await;
        let pos = groups
            .iter()
            .position(|g| g.id == group_id)
            .ok_or_else(|| ipc_err("not_found", format!("Group '{}' not found", group_id)))?;
        (pos, groups.remove(pos))
    };
    if let Err(e) = persist_groups(state).await {
        let mut groups = state.acl_groups.write().await;
        let pos = removed.0.min(groups.len());
        groups.insert(pos, removed.1);
        return Err(e);
    }
    state.emit_ipc_event(IpcEvent::AclGroupChanged { group_id: group_id.into(), action: "deleted".into() });
    Ok(json!({ "ok": true }))
}

// ---------------------------------------------------------------------------
// Ping
// ---------------------------------------------------------------------------

pub async fn set_ping_enabled(state: &Arc<CoreState>, enabled: bool) -> Result<Value, IpcError> {
    let _io = state.acl_persist.lock().await;
    store::save_ping_enabled(&state.data_dir, enabled)
        .map_err(|e| ipc_err("persist_failed", format!("failed to save ping setting: {}", e)))?;
    state.net.write().await.ping_enabled = enabled;
    state.next_generation();
    state.emit_ipc_event(IpcEvent::SettingsChanged { scope: "ping".into(), settings: json!({ "ping_enabled": enabled }) });
    info!("acl: ping (ICMP echo) {}", if enabled { "enabled" } else { "disabled" });
    Ok(json!({ "ping_enabled": enabled }))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use msst_acl_engine::PermissionGroup;

    async fn test_state(name: &str) -> Arc<CoreState> {
        let dir = std::env::temp_dir().join(format!("msst-acl-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let state = Arc::new(CoreState::new(udp, dir));
        let id = crate::identity::Identity {
            user: crate::identity::UserInfo { id: "user-00000001".into(), handle: "abjust".into(), display_name: String::new() },
            device: crate::identity::DeviceInfo {
                id: "device-00000001".into(), handle: "laptop".into(), display_name: String::new(),
                hostname: String::new(), assigned_ipv4: None,
            },
            secret_key: [1u8; 32], public_key: [2u8; 32], auth: None,
        };
        state.apply_identity(&id).await;
        let ip = |s: &str| s.parse().unwrap();
        state.net.write().await.peer_list.upsert(
            "device-0000000b", ip("172.22.0.11"), ip("fd22:2222:2222:2222::b"),
            Some("user-0000000b"), Some("pc"), Some("bob"), None, None, None, true, 0,
        );
        state
    }

    fn mc_rule(principals: Value) -> Value {
        json!({ "principals": principals, "services": ["minecraft-java"], "action": "allow", "direction": "inbound" })
    }

    fn on_disk(state: &CoreState) -> Vec<StoredRule> {
        store::load_rules(&state.data_dir).unwrap()
    }

    #[tokio::test]
    async fn create_resolves_mnemonics_and_persists_ids() {
        let state = test_state("create").await;
        let out = create_rule(&state, mc_rule(json!([{"kind":"device","id":"pc.bob"},{"kind":"device","id":"laptop"}])))
            .await
            .unwrap();
        assert_eq!(out["rule"]["permission_group"]["ids"], json!(["device-0000000b", "device-00000001"]));
        assert_eq!(out["rule"]["principal_mnemonics"]["device-0000000b"], "pc.bob");
        assert_eq!(out["rule"]["pending_migration"], false);

        let saved = on_disk(&state);
        assert_eq!(saved.len(), 1);
        assert!(matches!(&saved[0].rule.permission_group, PermissionGroup::Devices { ids } if ids[0] == "device-0000000b"));
        assert_eq!(saved[0].principal_mnemonics["device-00000001"], "laptop");

        // User mnemonic too.
        let out = create_rule(&state, mc_rule(json!([{"kind":"user","id":"bob"}]))).await.unwrap();
        assert_eq!(out["rule"]["permission_group"]["ids"], json!(["user-0000000b"]));
        assert_eq!(state.net.read().await.acl_rules.len(), 2);
    }

    #[tokio::test]
    async fn unresolvable_mnemonic_rejects_rule_and_changes_nothing() {
        let state = test_state("reject").await;
        // No coordinator client in this test → unknown mnemonic can't be resolved.
        let err = create_rule(&state, mc_rule(json!([{"kind":"device","id":"nas.carol"}]))).await.unwrap_err();
        assert_eq!(err.code, "coordinator_unavailable");
        assert!(state.net.read().await.acl_rules.is_empty());
        assert!(on_disk(&state).is_empty());

        let err = create_rule(&state, json!({"principals": [], "services": ["ssh"], "action": "allow", "direction": "inbound"}))
            .await
            .unwrap_err();
        assert_eq!(err.code, "invalid_rule");
    }

    #[tokio::test]
    async fn update_delete_and_expiry() {
        let state = test_state("crud").await;
        let id = create_rule(&state, mc_rule(json!([{"kind":"device","id":"device-0000000b"}]))).await.unwrap()["rule"]["id"]
            .as_str().unwrap().to_string();

        let out = update_rule(&state, &id, json!({"enabled": false, "comment": "off", "expires_at": 100})).await.unwrap();
        assert_eq!(out["rule"]["enabled"], false);
        assert_eq!(on_disk(&state)[0].rule.comment.as_deref(), Some("off"));
        assert_eq!(update_rule(&state, "nope", json!({})).await.unwrap_err().code, "not_found");

        expire_rules(&state, 101).await;
        assert!(state.net.read().await.acl_rules.is_empty());
        assert!(on_disk(&state).is_empty());

        let id = create_rule(&state, mc_rule(json!([{"kind":"device","id":"*"}]))).await.unwrap()["rule"]["id"]
            .as_str().unwrap().to_string();
        delete_rule(&state, &id).await.unwrap();
        assert!(on_disk(&state).is_empty());
        assert_eq!(delete_rule(&state, &id).await.unwrap_err().code, "not_found");
    }

    #[tokio::test]
    async fn loads_and_migrates_3_0_x_mnemonic_rules() {
        let state = test_state("migrate").await;
        std::fs::write(state.data_dir.join(store::RULES_FILE), r#"[
          {"id":"r1","permission_group":{"kind":"devices","ids":["pc.bob"]},
           "protocol_ports":[{"proto":"tcp","start":25565,"end":25565}],
           "action":"allow","direction":"inbound","expires_at":null,"enabled":true,"comment":null},
          {"id":"r2","permission_group":{"kind":"devices","ids":["nas.carol"]},
           "protocol_ports":[{"proto":"tcp","start":22,"end":22}],
           "action":"allow","direction":"inbound","expires_at":null,"enabled":true,"comment":null}
        ]"#).unwrap();
        std::fs::write(state.data_dir.join(store::PING_FILE), r#"{"ping_enabled":true}"#).unwrap();
        load(&state).await;
        assert_eq!(state.net.read().await.acl_rules.len(), 2);
        assert!(state.net.read().await.ping_enabled);
        assert_eq!(list_rules(&state).await["rules"][0]["pending_migration"], true);

        migrate_pending(&state).await;
        let rules = list_rules(&state).await;
        // r1: resolvable from the peer list → rewritten to the ID.
        assert_eq!(rules["rules"][0]["permission_group"]["ids"], json!(["device-0000000b"]));
        assert_eq!(rules["rules"][0]["principal_mnemonics"]["device-0000000b"], "pc.bob");
        assert_eq!(rules["rules"][0]["pending_migration"], false);
        // r2: unknown → left as-is, still pending.
        assert_eq!(rules["rules"][1]["permission_group"]["ids"], json!(["nas.carol"]));
        assert_eq!(rules["rules"][1]["pending_migration"], true);
        let saved = on_disk(&state);
        assert!(matches!(&saved[0].rule.permission_group, PermissionGroup::Devices { ids } if ids == &vec!["device-0000000b".to_string()]));
    }

    #[tokio::test]
    async fn corrupt_rules_file_is_moved_aside() {
        let state = test_state("corrupt").await;
        std::fs::write(state.data_dir.join(store::RULES_FILE), "{not json").unwrap();
        load(&state).await;
        assert!(state.net.read().await.acl_rules.is_empty());
        let moved = std::fs::read_dir(&state.data_dir).unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with("firewall_rules.json.corrupt-"));
        assert!(moved);
    }

    #[tokio::test]
    async fn rule_from_group_and_group_crud() {
        let state = test_state("groups").await;
        let g = create_group(&state, json!({"name": "friends", "kind": "user", "member_ids": ["bob"]})).await.unwrap();
        let gid = g["group"]["id"].as_str().unwrap().to_string();
        assert_eq!(store::load_groups(&state.data_dir).unwrap().len(), 1);

        let out = create_rule(&state, json!({"group_id": gid, "services": ["ssh"], "action": "allow", "direction": "inbound"}))
            .await.unwrap();
        assert_eq!(out["rule"]["permission_group"], json!({"kind": "users", "ids": ["user-0000000b"]}));

        // group_id and principals together are rejected.
        let err = create_rule(&state, json!({"group_id": gid, "principals": [{"kind":"user","id":"bob"}],
            "services": ["ssh"], "action": "allow", "direction": "inbound"})).await.unwrap_err();
        assert_eq!(err.code, "invalid_rule");

        update_group(&state, &gid, json!({"name": "pals"})).await.unwrap();
        assert_eq!(store::load_groups(&state.data_dir).unwrap()[0].name, "pals");
        assert_eq!(create_group(&state, json!({"name": "x", "kind": "space"})).await.unwrap_err().code, "invalid_group");
        delete_group(&state, &gid).await.unwrap();
        assert!(store::load_groups(&state.data_dir).unwrap().is_empty());
    }

    #[tokio::test]
    async fn ping_setting_persists() {
        let state = test_state("ping").await;
        set_ping_enabled(&state, true).await.unwrap();
        assert!(store::load_ping_enabled(&state.data_dir));
        assert!(state.net.read().await.ping_enabled);
    }

    /// Minimal HTTP server: path → (status, body).  Records request lines.
    async fn fake_coordinator(routes: Vec<(&'static str, u16, &'static str)>) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let line = req.lines().next().unwrap_or("").to_string();
                seen2.lock().unwrap().push(req.clone());
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let (status, body) = routes.iter().find(|(p, _, _)| *p == path).map(|(_, s, b)| (*s, *b)).unwrap_or((404, "{}"));
                let resp = format!("HTTP/1.1 {} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}", status, body.len(), body);
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });
        (url, seen)
    }

    #[tokio::test]
    async fn coordinator_resolver_endpoints() {
        let (url, seen) = fake_coordinator(vec![
            ("/dns/resolve?name=nas.abjust.ezplay.msst.net", 200, r#"{"device_id":"device-0000000a"}"#),
            ("/nodes/by-user/carol", 200, r#"{"nodes":[{"device_id":"device-0000000c","user_id":"user-0000000c"}]}"#),
            ("/nodes/by-user/broken", 500, "{}"),
        ]).await;
        let r = CoordResolver { http: reqwest::Client::new(), coord_url: url, bearer: Some("tok".into()) };
        assert_eq!(r.device_id("nas.abjust.ezplay.msst.net").await.unwrap().as_deref(), Some("device-0000000a"));
        assert_eq!(r.device_id("ghost.abjust.ezplay.msst.net").await.unwrap(), None); // 404
        assert_eq!(r.user_id("carol").await.unwrap().as_deref(), Some("user-0000000c"));
        assert!(r.user_id("broken").await.is_err()); // 5xx → unavailable, not "not found"
        assert!(seen.lock().unwrap().iter().all(|req| req.to_ascii_lowercase().contains("authorization: bearer tok")));
    }
}
