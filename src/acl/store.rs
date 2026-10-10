//! On-disk persistence for ACL state.
//!
//! File names and JSON shapes are the 3.0.x ones, so an upgraded data
//! directory loads unchanged:
//! - `firewall_rules.json` — `[FirewallRule]`; 3.1.x adds an optional
//!   `principal_mnemonics` map per rule (ignored by 3.0.x).
//! - `permission_groups.json` — `[PermissionGroupDef]`
//! - `ping_settings.json` — `{"ping_enabled": bool}`
//!
//! Writes are atomic (temp file + rename) so a crash never leaves a
//! truncated file behind.

use msst_acl_engine::FirewallRule;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const RULES_FILE: &str = "firewall_rules.json";
pub const GROUPS_FILE: &str = "permission_groups.json";
pub const PING_FILE: &str = "ping_settings.json";

/// A rule as persisted: the 3.0.x rule plus display-only mnemonics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRule {
    #[serde(flatten)]
    pub rule: FirewallRule,
    /// ID → mnemonic as entered when the rule was created.  Display only;
    /// never used for matching.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub principal_mnemonics: BTreeMap<String, String>,
}

/// A named, reusable principal set (3.0.x `PermissionGroupDef`).
///
/// Groups are templates: creating a rule from a group copies (and resolves)
/// its members into the rule; later group edits don't change existing rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PermissionGroupDef {
    pub id: String,
    pub name: String,
    /// `"user"` or `"device"`.
    pub kind: String,
    /// IDs or mnemonics.
    pub member_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PingSettings {
    ping_enabled: bool,
}

/// Write `contents` to `dir/name` atomically.
pub fn write_atomic(dir: &Path, name: &str, contents: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!(".{}.tmp", name));
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, dir.join(name))
}

fn load_json<T: serde::de::DeserializeOwned + Default>(dir: &Path, name: &str) -> Result<T, String> {
    let path = dir.join(name);
    if !path.exists() {
        return Ok(T::default());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("read {:?}: {}", path, e))?;
    serde_json::from_str(&text).map_err(|e| format!("parse {:?}: {}", path, e))
}

pub fn load_rules(dir: &Path) -> Result<Vec<StoredRule>, String> {
    load_json(dir, RULES_FILE)
}

pub fn save_rules(dir: &Path, rules: &[StoredRule]) -> std::io::Result<()> {
    write_atomic(dir, RULES_FILE, serde_json::to_string_pretty(rules)?.as_bytes())
}

pub fn load_groups(dir: &Path) -> Result<Vec<PermissionGroupDef>, String> {
    load_json(dir, GROUPS_FILE)
}

pub fn save_groups(dir: &Path, groups: &[PermissionGroupDef]) -> std::io::Result<()> {
    write_atomic(dir, GROUPS_FILE, serde_json::to_string_pretty(groups)?.as_bytes())
}

/// `false` when the file is missing or unreadable (3.0.x default).
pub fn load_ping_enabled(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join(PING_FILE))
        .ok()
        .and_then(|s| serde_json::from_str::<PingSettings>(&s).ok())
        .is_some_and(|p| p.ping_enabled)
}

pub fn save_ping_enabled(dir: &Path, enabled: bool) -> std::io::Result<()> {
    write_atomic(dir, PING_FILE, serde_json::to_string(&PingSettings { ping_enabled: enabled })?.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn temp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("msst-acl-store-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A `firewall_rules.json` exactly as 3.0.x writes it.
    const RULES_3_0_X: &str = r#"[
      {"id":"a1b2c3d4e5f60718","permission_group":{"kind":"devices","ids":["pc.bob","device-0000000b"]},
       "protocol_ports":[{"proto":"tcp","start":25565,"end":25565}],
       "action":"allow","direction":"inbound","expires_at":null,"enabled":true,"comment":"mc"},
      {"id":"0000000000000002","permission_group":{"kind":"space"},
       "protocol_ports":[{"proto":"udp","start":1,"end":65535}],
       "action":"deny","direction":"inbound","expires_at":1700000000,"enabled":false,"comment":null}
    ]"#;

    #[test]
    fn loads_3_0_x_rules_and_round_trips() {
        let dir = temp_dir("rules");
        std::fs::write(dir.join(RULES_FILE), RULES_3_0_X).unwrap();
        let mut rules = load_rules(&dir).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].principal_mnemonics.is_empty());
        assert_eq!(rules[1].rule.expires_at, Some(1700000000));

        rules[0].principal_mnemonics.insert("device-0000000b".into(), "pc.bob".into());
        save_rules(&dir, &rules).unwrap();
        let text = std::fs::read_to_string(dir.join(RULES_FILE)).unwrap();
        // Rules without mnemonics serialize exactly the 3.0.x fields.
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(v[1].get("principal_mnemonics").is_none());
        assert_eq!(v[0]["principal_mnemonics"]["device-0000000b"], "pc.bob");
        // 3.0.x's FirewallRule (same fields, no deny_unknown_fields) still parses it.
        let as_3_0_x: Vec<FirewallRule> = serde_json::from_str(&text).unwrap();
        assert_eq!(as_3_0_x.len(), 2);
        let back = load_rules(&dir).unwrap();
        assert_eq!(back[0].principal_mnemonics["device-0000000b"], "pc.bob");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_files_are_empty_defaults() {
        let dir = temp_dir("missing");
        assert!(load_rules(&dir).unwrap().is_empty());
        assert!(load_groups(&dir).unwrap().is_empty());
        assert!(!load_ping_enabled(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_rules_file_is_an_error_not_empty() {
        let dir = temp_dir("corrupt");
        std::fs::write(dir.join(RULES_FILE), "[{").unwrap();
        assert!(load_rules(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn groups_and_ping_round_trip() {
        let dir = temp_dir("groups");
        let g = vec![PermissionGroupDef { id: "g1".into(), name: "friends".into(), kind: "user".into(), member_ids: vec!["bob".into()] }];
        save_groups(&dir, &g).unwrap();
        assert_eq!(load_groups(&dir).unwrap(), g);
        save_ping_enabled(&dir, true).unwrap();
        assert!(load_ping_enabled(&dir));
        assert_eq!(std::fs::read_to_string(dir.join(PING_FILE)).unwrap(), r#"{"ping_enabled":true}"#);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
