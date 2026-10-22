//! Persistent network behaviour settings (`net_settings.json`).
//!
//! Ported from 3.0.x `net_settings.rs`; file name, JSON shape and the
//! `SetNetSettings` patch semantics (`null` clears, value sets) are
//! unchanged.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use tracing::warn;

pub const FILE: &str = "net_settings.json";
/// Accepted TUN MTU range: IPv6 requires ≥ 1280; 1500 is the Ethernet MTU.
pub const MTU_RANGE: std::ops::RangeInclusive<u64> = 1280..=1500;

/// Relay keepalive interval when unset.
pub const DEFAULT_RELAY_KEEPALIVE_SECS: u64 = 25;
/// Direct-path (P2P) keepalive ping interval when unset (3.0.x: 1 s).
pub const DEFAULT_P2P_KEEPALIVE_SECS: i64 = 1;

/// Linux DNS configuration strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LinuxDnsMode {
    /// systemd-resolved split DNS, falling back to iptables.
    #[default]
    PreferSplit,
    /// Always iptables DNAT.
    IptablesOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// Never upgrade relay paths to direct; report no P2P endpoints.
    #[serde(default)]
    pub disable_p2p: bool,
    /// Freeze all peer paths (no upgrades or downgrades).
    #[serde(default)]
    pub lock_path: bool,
    /// Use this relay instead of auto-selecting (if it responds).
    #[serde(default)]
    pub preferred_relay: Option<String>,
    /// TUN MTU override; applied on next start.
    #[serde(default)]
    pub mtu_override: Option<u16>,
    /// Relay + P2P keepalive interval (seconds).
    #[serde(default)]
    pub keepalive_secs: Option<u32>,
    #[serde(default)]
    pub linux_dns_mode: LinuxDnsMode,
    /// Linux: Core's own UDP traffic (peers, relays) uses the main routing
    /// table, not another VPN's full tunnel (`crate::routing`).  Applies
    /// immediately.  Default on; absent in older files → on.
    #[serde(default = "default_true")]
    pub bypass_other_vpns: bool,
    /// Linux: other VPNs' own traffic (Tailscale) may not use MSST as a
    /// path (`crate::routing`).  Applies immediately.  Default on; absent
    /// in older files → on.
    #[serde(default = "default_true")]
    pub block_other_vpns_over_msst: bool,
}

fn default_true() -> bool {
    true
}

impl Default for NetworkSettings {
    fn default() -> Self {
        NetworkSettings {
            disable_p2p: false,
            lock_path: false,
            preferred_relay: None,
            mtu_override: None,
            keepalive_secs: None,
            linux_dns_mode: LinuxDnsMode::default(),
            bypass_other_vpns: true,
            block_other_vpns_over_msst: true,
        }
    }
}

impl NetworkSettings {
    /// Load from the data dir; missing or unreadable → defaults (3.0.x).
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(FILE);
        match std::fs::read_to_string(&path) {
            Err(_) => Self::default(),
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                warn!("net_settings: failed to parse {:?}: {}; using defaults", path, e);
                Self::default()
            }),
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        crate::acl::store::write_atomic(dir, FILE, serde_json::to_string_pretty(self)?.as_bytes())
    }

    pub fn relay_keepalive_secs(&self) -> u64 {
        self.keepalive_secs.map(u64::from).unwrap_or(DEFAULT_RELAY_KEEPALIVE_SECS)
    }

    pub fn p2p_keepalive_secs(&self) -> i64 {
        self.keepalive_secs.map(i64::from).unwrap_or(DEFAULT_P2P_KEEPALIVE_SECS)
    }

    /// The JSON shape returned by `GetNetSettings` (3.0.x `GET /net/settings`).
    pub fn to_view(&self) -> Value {
        json!({
            "disable_p2p": self.disable_p2p,
            "lock_path": self.lock_path,
            "preferred_relay": self.preferred_relay,
            "mtu_override": self.mtu_override,
            "keepalive_secs": self.keepalive_secs,
            "linux_dns_mode": self.linux_dns_mode,
            "bypass_other_vpns": self.bypass_other_vpns,
            "block_other_vpns_over_msst": self.block_other_vpns_over_msst,
        })
    }

    /// Apply a partial update (3.0.x `PUT /net/settings`): absent fields are
    /// unchanged, `null` clears an optional field, `keepalive_secs` is
    /// clamped to 5..=30, an unknown `linux_dns_mode` means `prefer_split`.
    pub fn apply_patch(&mut self, patch: &Value) -> Result<(), String> {
        let obj = patch.as_object().ok_or("settings must be a JSON object")?;
        let bool_field = |k: &str| -> Result<Option<bool>, String> {
            match obj.get(k) {
                None => Ok(None),
                Some(v) => v.as_bool().map(Some).ok_or(format!("{} must be a boolean", k)),
            }
        };
        if let Some(v) = bool_field("disable_p2p")? {
            self.disable_p2p = v;
        }
        if let Some(v) = bool_field("lock_path")? {
            self.lock_path = v;
        }
        if let Some(v) = bool_field("bypass_other_vpns")? {
            self.bypass_other_vpns = v;
        }
        if let Some(v) = bool_field("block_other_vpns_over_msst")? {
            self.block_other_vpns_over_msst = v;
        }
        if let Some(v) = obj.get("preferred_relay") {
            self.preferred_relay = v.as_str().map(str::to_string);
        }
        if let Some(v) = obj.get("preferred_relay") {
            if !v.is_null() && !v.is_string() {
                return Err("preferred_relay must be a string or null".into());
            }
        }
        if let Some(v) = obj.get("mtu_override") {
            self.mtu_override = match v {
                Value::Null => None,
                _ => match v.as_u64() {
                    Some(n) if MTU_RANGE.contains(&n) => Some(n as u16),
                    _ => return Err(format!("mtu_override must be null or an integer in {}–{}", MTU_RANGE.start(), MTU_RANGE.end())),
                },
            };
        }
        if let Some(v) = obj.get("keepalive_secs") {
            self.keepalive_secs = match v {
                Value::Null => None,
                _ => Some(v.as_u64().ok_or("keepalive_secs must be null or a positive integer")?.clamp(5, 30) as u32),
            };
        }
        if let Some(v) = obj.get("linux_dns_mode") {
            self.linux_dns_mode = match v.as_str() {
                Some("iptables_only") => LinuxDnsMode::IptablesOnly,
                _ => LinuxDnsMode::PreferSplit,
            };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_3_0_x_file() {
        let s: NetworkSettings = serde_json::from_str(
            r#"{"disable_p2p":true,"lock_path":false,"preferred_relay":"1.2.3.4:7000","mtu_override":1200,"keepalive_secs":10,"linux_dns_mode":"iptables_only"}"#,
        )
        .unwrap();
        assert!(s.disable_p2p);
        assert_eq!(s.mtu_override, Some(1200));
        assert_eq!(s.relay_keepalive_secs(), 10);
        assert_eq!(s.linux_dns_mode, LinuxDnsMode::IptablesOnly);
        assert!(s.bypass_other_vpns, "absent in 3.0.x files: on");
        assert!(s.block_other_vpns_over_msst, "absent in older files: on");
        // Older files without some fields.
        let s: NetworkSettings = serde_json::from_str(r#"{"preferred_relay":null,"mtu_override":null,"keepalive_secs":null}"#).unwrap();
        assert_eq!(s, NetworkSettings::default());
    }

    #[test]
    fn defaults_match_3_0_x() {
        let s = NetworkSettings::default();
        assert_eq!((s.relay_keepalive_secs(), s.p2p_keepalive_secs(), s.mtu_override), (25, 1, None));
    }

    #[test]
    fn patch_semantics() {
        let mut s = NetworkSettings::default();
        s.apply_patch(&json!({"disable_p2p": true, "preferred_relay": "r:1", "keepalive_secs": 99, "mtu_override": 1400})).unwrap();
        // Validation (nothing applied on error — callers patch a copy).
        for bad in [json!({"mtu_override": 70000}), json!({"mtu_override": 1279}), json!({"mtu_override": "1400"}),
                    json!({"keepalive_secs": "x"}), json!({"preferred_relay": 5})] {
            assert!(s.clone().apply_patch(&bad).is_err(), "{}", bad);
        }
        assert!(s.clone().apply_patch(&json!({"mtu_override": 1500})).is_ok());
        assert!(s.disable_p2p);
        assert_eq!(s.preferred_relay.as_deref(), Some("r:1"));
        assert_eq!(s.keepalive_secs, Some(30)); // clamped
        s.apply_patch(&json!({"keepalive_secs": 1})).unwrap();
        assert_eq!(s.keepalive_secs, Some(5));
        // null clears; absent leaves alone.
        s.apply_patch(&json!({"preferred_relay": null, "linux_dns_mode": "iptables_only"})).unwrap();
        assert_eq!(s.preferred_relay, None);
        assert_eq!(s.mtu_override, Some(1400));
        assert_eq!(s.linux_dns_mode, LinuxDnsMode::IptablesOnly);
        s.apply_patch(&json!({"linux_dns_mode": "bogus"})).unwrap();
        assert_eq!(s.linux_dns_mode, LinuxDnsMode::PreferSplit);
        assert!(s.apply_patch(&json!({"lock_path": "yes"})).is_err());
        s.apply_patch(&json!({"bypass_other_vpns": false})).unwrap();
        assert!(!s.bypass_other_vpns);
        assert_eq!(serde_json::from_str::<NetworkSettings>(&serde_json::to_string(&s).unwrap()).unwrap(), s);
        assert!(s.apply_patch(&json!({"bypass_other_vpns": null})).is_err());
        s.apply_patch(&json!({"block_other_vpns_over_msst": false})).unwrap();
        assert!(!s.block_other_vpns_over_msst && !s.bypass_other_vpns, "independent switches");
        assert!(s.apply_patch(&json!({"block_other_vpns_over_msst": "no"})).is_err());
        assert!(s.apply_patch(&json!([1])).is_err());
        assert_eq!(s.to_view()["linux_dns_mode"], "prefer_split");
    }
}
