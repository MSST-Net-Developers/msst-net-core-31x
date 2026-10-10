//! Rule request parsing and validation — ported from 3.0.x `rule_parser.rs`.
//!
//! The request shape (`RuleRequest`) is the one the 3.0.x Controller sent to
//! `POST /firewall/rules`; it is now the `rule` payload of
//! `IpcRequest::CreateAclRule`.  Validation rules are unchanged.
//! Principal mnemonics are accepted here and resolved to IDs afterwards
//! (see `resolve.rs`).

use msst_acl_engine::{Action, Direction, FirewallRule, PermissionGroup, Protocol, ProtocolPort};
use msst_core_state::firewall::services::ServiceCatalog;
use rand::RngCore;
use serde::Deserialize;

/// One principal as sent by the Controller.
#[derive(Debug, Clone, Deserialize)]
pub struct RawPrincipal {
    /// `"user"`, `"device"` or `"space"`.
    pub kind: String,
    /// Mnemonic or ID (`user-XXXXXXXX` / `device-XXXXXXXX`), or `"*"`.
    pub id: String,
}

/// Protocol + port descriptor (mutually exclusive with `services`).
#[derive(Debug, Clone, Deserialize)]
pub struct RawProtocolPort {
    /// `"tcp"`, `"udp"` or `"tcp+udp"`.
    pub proto: String,
    /// `"*"`, `"80"` or `"80-443"`.
    pub port: String,
}

/// A rule creation request.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleRequest {
    #[serde(default)]
    pub principals: Vec<RawPrincipal>,
    /// Take principals from this permission group (exclusive with `principals`).
    pub group_id: Option<String>,
    #[serde(default)]
    pub protocol_ports: Vec<RawProtocolPort>,
    /// Well-known service names (e.g. `["minecraft-java", "ssh"]`).
    #[serde(default)]
    pub services: Vec<String>,
    pub action: String,
    pub direction: String,
    /// Unix seconds; `None` = never expires.
    pub expires_at: Option<i64>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub comment: Option<String>,
}

fn default_enabled() -> bool {
    true
}

/// Partial update (`IpcRequest::UpdateAclRule::patch`), same fields as the
/// 3.0.x `PUT /firewall/rules/:id`.  Any other field is rejected
/// (`invalid_patch`) so a client can't silently lose edits.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePatch {
    pub enabled: Option<bool>,
    pub comment: Option<String>,
    pub expires_at: Option<i64>,
}

/// Whether `id` is a stable ID of the given kind (or the `*` wildcard).
pub fn is_stable_id(kind: &str, id: &str) -> bool {
    if id == "*" {
        return true;
    }
    let hex = match kind {
        "device" => id.strip_prefix("device-"),
        "user" => id.strip_prefix("user-"),
        _ => None,
    };
    hex.is_some_and(|h| h.len() == 8 && h.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Validate one principal ID (3.0.x `validate_principal_id`).
pub fn validate_principal_id(kind: &str, id: &str) -> Result<(), String> {
    if id == "*" {
        return Ok(());
    }
    if kind == "space" {
        return Err(format!("Space principal ID must be '*' (matches all room members), got '{}'", id));
    }
    let is_device = id.starts_with("device-");
    let is_user = id.starts_with("user-");
    if is_device || is_user {
        let hex = if is_device { &id[7..] } else { &id[5..] };
        if hex.len() != 8 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("Invalid ID '{}': expected 8 hex digits after prefix", id));
        }
        if is_device && kind != "device" {
            return Err(format!("ID '{}' looks like a device ID but kind is '{}'", id, kind));
        }
        if is_user && kind != "user" {
            return Err(format!("ID '{}' looks like a user ID but kind is '{}'", id, kind));
        }
        return Ok(());
    }
    if id.is_empty() {
        return Err("Principal ID must not be empty".into());
    }
    let valid_segment = |p: &str| p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if kind == "device" {
        // "pc" (own user's device) or "pc.abjust" (device.user).
        let parts: Vec<&str> = id.splitn(3, '.').collect();
        if parts.len() > 2 {
            return Err(format!("Device mnemonic '{}' must be 'handle' or 'handle.user-handle' (at most one dot)", id));
        }
        for part in parts {
            if part.is_empty() {
                return Err(format!("Device mnemonic '{}' segments must not be empty", id));
            }
            if !valid_segment(part) {
                return Err(format!(
                    "Device mnemonic segment '{}' must contain only lowercase letters, digits, and hyphens",
                    part
                ));
            }
        }
    } else if !valid_segment(id) {
        return Err(format!("Mnemonic ID '{}' must contain only lowercase letters, digits, and hyphens", id));
    }
    Ok(())
}

fn parse_protocol(s: &str) -> Result<Vec<Protocol>, String> {
    match s {
        "tcp" => Ok(vec![Protocol::Tcp]),
        "udp" => Ok(vec![Protocol::Udp]),
        "tcp+udp" => Ok(vec![Protocol::Tcp, Protocol::Udp]),
        other => Err(format!("Unknown protocol '{}'; expected tcp, udp, or tcp+udp", other)),
    }
}

fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    if s == "*" {
        return Ok((1, 65535));
    }
    let parse = |p: &str| p.trim().parse::<u16>().map_err(|_| format!("Invalid port '{}'", p));
    let (start, end) = match s.split_once('-') {
        Some((a, b)) => (parse(a)?, parse(b)?),
        None => {
            let p = parse(s)?;
            (p, p)
        }
    };
    if start == 0 {
        return Err("Port 0 is not valid".into());
    }
    if start > end {
        return Err(format!("Port range start ({}) > end ({})", start, end));
    }
    Ok((start, end))
}

/// Human-readable service name for a protocol/port (3.0.x
/// `rule_parser::service_name_by_port`), used in access-log entries and
/// authorization prompts.
pub fn service_display_name(proto: &str, port: u16) -> Option<&'static str> {
    Some(match (proto, port) {
        ("tcp", 25565) => "Minecraft Java",
        ("udp", 19132) => "Minecraft Bedrock",
        ("tcp", 5123) => "Rusted Warfare",
        ("tcp", 9178) => "MSST纸牌战",
        ("tcp", 7777) => "Terraria",
        ("udp", 34197) => "Factorio",
        ("tcp", 80) => "HTTP",
        ("tcp", 443) => "HTTPS",
        ("udp", 443) => "QUIC",
        ("tcp", 21) => "FTP",
        ("tcp", 990) => "FTPS",
        ("tcp", 2049) => "NFS",
        ("tcp", 445) => "SMB",
        ("tcp", 3306) => "MySQL",
        ("tcp", 5432) => "PostgreSQL",
        ("tcp", 27017) => "MongoDB",
        ("tcp", 6379) => "Redis",
        ("tcp", 1433) => "MSSQL",
        ("tcp", 1521) => "Oracle",
        ("tcp", 22) => "SSH",
        ("tcp", 3389) => "RDP",
        ("udp", 3389) => "RDP (UDP)",
        ("tcp", 5900) => "VNC",
        ("tcp", 25) => "SMTP",
        ("udp", 53) | ("tcp", 53) => "DNS",
        _ => return None,
    })
}

/// The service templates offered to the user, by category (3.0.x
/// `GET /firewall/services`).  Every `id` is accepted in `services`.
pub fn service_catalog_view() -> serde_json::Value {
    serde_json::json!({
        "categories": [
            { "id": "game", "label": "游戏", "services": [
                { "id": "minecraft-java", "name": "Minecraft（MCJE）", "ports": ["tcp/25565"] },
                { "id": "minecraft-bedrock", "name": "Minecraft（MCBE）", "ports": ["udp/19132"] },
                { "id": "rusted-warfare", "name": "铁锈战争", "ports": ["tcp/5123"] },
                { "id": "msst-cardgame", "name": "MSST纸牌战", "ports": ["tcp/9178"] },
                { "id": "terraria", "name": "Terraria", "ports": ["tcp/7777"] },
                { "id": "factorio", "name": "Factorio", "ports": ["udp/34197"] },
            ]},
            { "id": "web", "label": "Web服务", "services": [
                { "id": "http", "name": "HTTP", "ports": ["tcp/80"] },
                { "id": "https", "name": "HTTPS", "ports": ["tcp/443"] },
                { "id": "quic", "name": "HTTP/3（QUIC）", "ports": ["udp/443"] },
            ]},
            { "id": "file", "label": "文件服务", "services": [
                { "id": "ftp", "name": "FTP", "ports": ["tcp/21"] },
                { "id": "ftps", "name": "FTPS", "ports": ["tcp/990"] },
                { "id": "nfs", "name": "NFS", "ports": ["tcp/2049"] },
                { "id": "smb", "name": "SMB/CIFS", "ports": ["tcp/445"] },
            ]},
            { "id": "database", "label": "数据库服务", "services": [
                { "id": "mysql", "name": "MySQL", "ports": ["tcp/3306"] },
                { "id": "postgres", "name": "PostgreSQL", "ports": ["tcp/5432"] },
                { "id": "mongodb", "name": "MongoDB", "ports": ["tcp/27017"] },
                { "id": "redis", "name": "Redis", "ports": ["tcp/6379"] },
                { "id": "mssql", "name": "MSSQL", "ports": ["tcp/1433"] },
                { "id": "oracle", "name": "Oracle DB", "ports": ["tcp/1521"] },
            ]},
            { "id": "remote", "label": "远程访问", "services": [
                { "id": "ssh", "name": "SSH", "ports": ["tcp/22"] },
                { "id": "rdp", "name": "RDP", "ports": ["tcp/3389"] },
                { "id": "rdp-udp", "name": "RDP（UDP）", "ports": ["udp/3389"] },
                { "id": "vnc", "name": "VNC", "ports": ["tcp/5900"] },
            ]},
        ]
    })
}

/// Random 16-hex-char rule/group ID (3.0.x `new_rule_id`).
pub fn new_id() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Parse and validate a request into one rule (principals not yet resolved).
///
/// `tcp+udp` is split and services are expanded, so every
/// `protocol_ports` entry is a single protocol; entries are deduplicated.
pub fn parse_rule(req: RuleRequest) -> Result<FirewallRule, String> {
    if req.principals.is_empty() {
        return Err("principals must not be empty".into());
    }
    let kind = req.principals[0].kind.as_str();
    if !matches!(kind, "user" | "device" | "space") {
        return Err(format!("principal kind must be 'user', 'device', or 'space', got '{}'", kind));
    }
    for p in &req.principals {
        if p.kind != kind {
            return Err(format!("All principals must have the same kind; found both '{}' and '{}'", kind, p.kind));
        }
        validate_principal_id(&p.kind, &p.id)?;
    }
    let ids = || req.principals.iter().map(|p| p.id.clone()).collect();
    let permission_group = match kind {
        "device" => PermissionGroup::Devices { ids: ids() },
        "user" => PermissionGroup::Users { ids: ids() },
        _ => PermissionGroup::Space,
    };

    if req.protocol_ports.is_empty() && req.services.is_empty() {
        return Err("Provide at least one entry in protocol_ports or services".into());
    }
    if !req.protocol_ports.is_empty() && !req.services.is_empty() {
        return Err("Provide either protocol_ports or services, not both".into());
    }
    let mut entries: Vec<(Protocol, u16, u16)> = Vec::new();
    for rpp in &req.protocol_ports {
        let (start, end) = parse_port_range(&rpp.port)?;
        for proto in parse_protocol(&rpp.proto)? {
            entries.push((proto, start, end));
        }
    }
    let catalog = ServiceCatalog::default();
    for svc in &req.services {
        let ports = catalog.resolve(svc).ok_or_else(|| format!("Unknown service name '{}'", svc))?;
        entries.extend(ports.into_iter().map(|pp| (pp.proto, pp.start, pp.end)));
    }
    entries.sort_by_key(|&(p, s, e)| (p as u8, s, e));
    entries.dedup();

    let action = match req.action.as_str() {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        other => return Err(format!("Unknown action '{}'; expected allow or deny", other)),
    };
    let direction = match req.direction.as_str() {
        "inbound" => Direction::Inbound,
        "outbound" => Direction::Outbound,
        other => return Err(format!("Unknown direction '{}'; expected inbound or outbound", other)),
    };

    Ok(FirewallRule {
        id: new_id(),
        permission_group,
        protocol_ports: entries.into_iter().map(|(proto, start, end)| ProtocolPort { proto, start, end }).collect(),
        action,
        direction,
        expires_at: req.expires_at,
        enabled: req.enabled,
        comment: req.comment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn req(v: serde_json::Value) -> RuleRequest {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn parses_multi_device_multi_service_rule() {
        let r = parse_rule(req(json!({
            "principals": [{"kind":"device","id":"device-aabbccdd"},{"kind":"device","id":"pc.abjust"}],
            "services": ["minecraft-java", "dns", "minecraft"],
            "action": "allow", "direction": "inbound"
        })))
        .unwrap();
        assert!(matches!(&r.permission_group, PermissionGroup::Devices { ids } if ids.len() == 2));
        // dns → udp/53 + tcp/53; minecraft alias deduplicated with minecraft-java.
        assert_eq!(r.protocol_ports.len(), 3);
        assert!(r.enabled);
        assert_eq!(r.id.len(), 16);
    }

    #[test]
    fn splits_tcp_udp_and_parses_ranges() {
        let r = parse_rule(req(json!({
            "principals": [{"kind":"user","id":"*"}],
            "protocol_ports": [{"proto":"tcp+udp","port":"5000-5010"},{"proto":"tcp","port":"*"}],
            "action": "deny", "direction": "inbound", "enabled": false
        })))
        .unwrap();
        assert_eq!(r.protocol_ports, vec![
            ProtocolPort::range(Protocol::Tcp, 1, 65535),
            ProtocolPort::range(Protocol::Tcp, 5000, 5010),
            ProtocolPort::range(Protocol::Udp, 5000, 5010),
        ]);
        assert_eq!(r.action, Action::Deny);
        assert!(!r.enabled);
    }

    #[test]
    fn rejects_invalid_requests() {
        let base = |p: serde_json::Value| json!({"principals": p, "services": ["ssh"], "action": "allow", "direction": "inbound"});
        for bad in [
            base(json!([])),
            base(json!([{"kind":"device","id":"x"},{"kind":"user","id":"y"}])),
            base(json!([{"kind":"device","id":"device-xyz"}])),
            base(json!([{"kind":"user","id":"device-aabbccdd"}])),
            base(json!([{"kind":"device","id":"a.b.c"}])),
            base(json!([{"kind":"user","id":"a.b"}])),
            base(json!([{"kind":"space","id":"room1"}])),
            base(json!([{"kind":"Device","id":"x"}])),
        ] {
            assert!(parse_rule(req(bad.clone())).is_err(), "{}", bad);
        }
        let p = json!([{"kind":"device","id":"*"}]);
        for bad in [
            json!({"principals": p, "action": "allow", "direction": "inbound"}),
            json!({"principals": p, "services": ["ssh"], "protocol_ports": [{"proto":"tcp","port":"1"}], "action": "allow", "direction": "inbound"}),
            json!({"principals": p, "services": ["nope"], "action": "allow", "direction": "inbound"}),
            json!({"principals": p, "protocol_ports": [{"proto":"tcp","port":"0"}], "action": "allow", "direction": "inbound"}),
            json!({"principals": p, "protocol_ports": [{"proto":"tcp","port":"9-1"}], "action": "allow", "direction": "inbound"}),
            json!({"principals": p, "protocol_ports": [{"proto":"icmp","port":"1"}], "action": "allow", "direction": "inbound"}),
            json!({"principals": p, "services": ["ssh"], "action": "accept", "direction": "inbound"}),
            json!({"principals": p, "services": ["ssh"], "action": "allow", "direction": "both"}),
        ] {
            assert!(parse_rule(req(bad.clone())).is_err(), "{}", bad);
        }
    }

    #[test]
    fn catalog_ids_are_all_accepted_with_their_ports() {
        let catalog = ServiceCatalog::default();
        for cat in service_catalog_view()["categories"].as_array().unwrap() {
            for svc in cat["services"].as_array().unwrap() {
                let ports = catalog.resolve(svc["id"].as_str().unwrap()).expect("id resolvable");
                let shown: Vec<String> = ports.iter().map(|p| format!("{:?}/{}", p.proto, p.start).to_lowercase()).collect();
                assert_eq!(serde_json::json!(shown), svc["ports"], "{}", svc["id"]);
            }
        }
    }

    #[test]
    fn stable_id_detection() {
        assert!(is_stable_id("device", "device-a1b2c3d4"));
        assert!(is_stable_id("user", "user-a1b2c3d4"));
        assert!(is_stable_id("device", "*"));
        assert!(!is_stable_id("device", "pc"));
        assert!(!is_stable_id("device", "pc.abjust"));
        assert!(!is_stable_id("user", "device-a1b2c3d4"));
    }
}
