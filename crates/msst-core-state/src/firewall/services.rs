//! Well-known service catalog.
//!
//! Maps human-readable service names (e.g. "minecraft-java") to their
//! protocol/port definitions.  Used by the API layer to expand service
//! names in rule creation requests, and by the access log to resolve
//! port numbers back to service names.

use msst_acl_engine::{Protocol, ProtocolPort};

/// A well-known service definition.
#[derive(Debug, Clone)]
pub struct ServiceDef {
    /// Human-readable name (e.g. "minecraft-java").
    pub name: &'static str,
    /// Protocol/port pairs that this service uses.
    pub ports: &'static [(Protocol, u16, u16)],
}

/// The service catalog — a static list of well-known services.
pub struct ServiceCatalog {
    services: &'static [ServiceDef],
}

impl ServiceCatalog {
    /// Look up a service by name (case-insensitive).
    pub fn by_name(&self, name: &str) -> Option<&'static ServiceDef> {
        let lower = name.to_lowercase();
        self.services.iter().find(|s| s.name == lower)
    }

    /// Resolve a service name to protocol-port pairs.
    pub fn resolve(&self, name: &str) -> Option<Vec<ProtocolPort>> {
        let def = self.by_name(name)?;
        Some(
            def.ports
                .iter()
                .map(|&(proto, start, end)| {
                    if start == end {
                        ProtocolPort::single(proto, start)
                    } else {
                        ProtocolPort::range(proto, start, end)
                    }
                })
                .collect(),
        )
    }

    /// Look up the service name for a given protocol and port.
    pub fn name_by_port(&self, proto: Protocol, port: u16) -> Option<&'static str> {
        self.services
            .iter()
            .find(|s| {
                s.ports
                    .iter()
                    .any(|&(p, start, end)| p == proto && port >= start && port <= end)
            })
            .map(|s| s.name)
    }

    /// List all service names.
    pub fn all_names(&self) -> Vec<&'static str> {
        self.services.iter().map(|s| s.name).collect()
    }
}

// ---------------------------------------------------------------------------
// Default catalog
// ---------------------------------------------------------------------------

/// The 3.0.x service catalogue (`rule_parser::known_service`), unchanged:
/// rules created from service names must expand to the same ports.
static SERVICES: &[ServiceDef] = &[
    // ── Games ─────────────────────────────────────────────────────────────
    ServiceDef { name: "minecraft-java",    ports: &[(Protocol::Tcp, 25565, 25565)] },
    ServiceDef { name: "minecraft",         ports: &[(Protocol::Tcp, 25565, 25565)] }, // alias
    ServiceDef { name: "minecraft-bedrock", ports: &[(Protocol::Udp, 19132, 19132)] },
    ServiceDef { name: "rusted-warfare",    ports: &[(Protocol::Tcp, 5123, 5123)] },
    ServiceDef { name: "msst-cardgame",     ports: &[(Protocol::Tcp, 9178, 9178)] },
    ServiceDef { name: "terraria",          ports: &[(Protocol::Tcp, 7777, 7777)] },
    ServiceDef { name: "factorio",          ports: &[(Protocol::Udp, 34197, 34197)] },
    // ── Web ───────────────────────────────────────────────────────────────
    ServiceDef { name: "http",     ports: &[(Protocol::Tcp, 80, 80)] },
    ServiceDef { name: "https",    ports: &[(Protocol::Tcp, 443, 443)] },
    ServiceDef { name: "quic",     ports: &[(Protocol::Udp, 443, 443)] },
    // ── File services ─────────────────────────────────────────────────────
    ServiceDef { name: "ftp",      ports: &[(Protocol::Tcp, 21, 21)] },
    ServiceDef { name: "ftps",     ports: &[(Protocol::Tcp, 990, 990)] },
    ServiceDef { name: "nfs",      ports: &[(Protocol::Tcp, 2049, 2049)] },
    ServiceDef { name: "smb",      ports: &[(Protocol::Tcp, 445, 445)] },
    // ── Databases ─────────────────────────────────────────────────────────
    ServiceDef { name: "mysql",    ports: &[(Protocol::Tcp, 3306, 3306)] },
    ServiceDef { name: "postgres", ports: &[(Protocol::Tcp, 5432, 5432)] },
    ServiceDef { name: "mongodb",  ports: &[(Protocol::Tcp, 27017, 27017)] },
    ServiceDef { name: "redis",    ports: &[(Protocol::Tcp, 6379, 6379)] },
    ServiceDef { name: "mssql",    ports: &[(Protocol::Tcp, 1433, 1433)] },
    ServiceDef { name: "oracle",   ports: &[(Protocol::Tcp, 1521, 1521)] },
    // ── Remote access ─────────────────────────────────────────────────────
    ServiceDef { name: "ssh",      ports: &[(Protocol::Tcp, 22, 22)] },
    ServiceDef { name: "rdp",      ports: &[(Protocol::Tcp, 3389, 3389)] },
    ServiceDef { name: "rdp-udp",  ports: &[(Protocol::Udp, 3389, 3389)] },
    ServiceDef { name: "vnc",      ports: &[(Protocol::Tcp, 5900, 5900)] },
    // ── Other ─────────────────────────────────────────────────────────────
    ServiceDef { name: "smtp",     ports: &[(Protocol::Tcp, 25, 25)] },
    ServiceDef { name: "dns",      ports: &[(Protocol::Udp, 53, 53), (Protocol::Tcp, 53, 53)] },
];

impl Default for ServiceCatalog {
    fn default() -> Self {
        ServiceCatalog { services: SERVICES }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_minecraft() {
        let catalog = ServiceCatalog::default();
        let mc = catalog.by_name("minecraft-java").unwrap();
        assert_eq!(mc.name, "minecraft-java");
        assert_eq!(mc.ports, &[(Protocol::Tcp, 25565, 25565)]);
    }

    #[test]
    fn case_insensitive_lookup() {
        let catalog = ServiceCatalog::default();
        assert!(catalog.by_name("MINECRAFT-JAVA").is_some());
        assert!(catalog.by_name("SSH").is_some());
    }

    #[test]
    fn resolve_service_to_ports() {
        let catalog = ServiceCatalog::default();
        let ports = catalog.resolve("dns").unwrap();
        assert_eq!(ports.len(), 2); // UDP 53 + TCP 53
    }

    #[test]
    fn name_by_port_known() {
        let catalog = ServiceCatalog::default();
        assert_eq!(catalog.name_by_port(Protocol::Tcp, 22), Some("ssh"));
        assert_eq!(catalog.name_by_port(Protocol::Tcp, 25565), Some("minecraft-java"));
    }

    #[test]
    fn name_by_port_unknown() {
        let catalog = ServiceCatalog::default();
        assert!(catalog.name_by_port(Protocol::Tcp, 12345).is_none());
    }

    #[test]
    fn all_names_not_empty() {
        let catalog = ServiceCatalog::default();
        assert!(!catalog.all_names().is_empty());
        assert!(catalog.all_names().contains(&"ssh"));
    }

    #[test]
    fn minecraft_alias() {
        let catalog = ServiceCatalog::default();
        // Both "minecraft" and "minecraft-java" should resolve to the same port.
        let mc1 = catalog.resolve("minecraft").unwrap();
        let mc2 = catalog.resolve("minecraft-java").unwrap();
        assert_eq!(mc1, mc2);
    }
}