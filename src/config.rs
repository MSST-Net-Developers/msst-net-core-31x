//! Configuration — TOML config file + CLI argument overrides.
//!
//! Config file location: `~/.config/msst-net/core.toml` (Linux/macOS)
//! or `%APPDATA%\msst-net\core.toml` (Windows).
//!
//! Every field has a default value.  The config file is auto-created on
//! first run.  CLI arguments override config file values.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// CoreConfig — the full configuration
// ---------------------------------------------------------------------------

/// The complete Core daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreConfig {
    /// Coordinator HTTP(S) base URL.
    pub coordinator_url: String,
    /// UDP port for MSST data plane (default: 21031).
    pub udp_port: u16,
    /// TUN interface name (default: "msst0").
    pub tun_name: String,
    /// TUN interface MTU (default: 1280).
    pub tun_mtu: u16,
    /// Prometheus metrics port (default: 9100).
    pub metrics_port: u16,
    /// IPC socket path override (default: auto-detected).
    pub ipc_socket: Option<String>,
    /// Log level filter (default: "info").
    pub log_level: String,
    /// Data directory for identity, config, and cache files.
    /// Default: `~/.local/share/msst-net` (Linux), `~/Library/msst-net` (macOS).
    pub data_dir: Option<String>,
    /// Whether to run as a background daemon (default: false on TTY).
    pub daemon: bool,
    /// Enable P2P direct connections (default: true).
    pub enable_p2p: bool,
    /// Keepalive interval in seconds (default: 25).
    pub keepalive_secs: Option<u64>,
    /// Custom relay address override (default: auto-select).
    pub preferred_relay: Option<String>,
}

impl Default for CoreConfig {
    fn default() -> Self {
        CoreConfig {
            coordinator_url: "https://coord.msst-net.msst2031.cn".to_string(),
            udp_port: 21031,
            tun_name: "msst0".to_string(),
            tun_mtu: 1280,
            metrics_port: 9100,
            ipc_socket: None,
            log_level: "info".to_string(),
            data_dir: None,
            daemon: false,
            enable_p2p: true,
            keepalive_secs: Some(25),
            preferred_relay: None,
        }
    }
}

impl CoreConfig {
    /// Resolve the data directory, creating it if necessary.
    ///
    /// Without an explicit `data_dir`, a 3.0.x data directory that already
    /// holds an `identity.json` takes precedence over the 3.1.x default, so
    /// upgrading keeps the device's keypair, IDs and virtual IPs.
    pub fn resolve_data_dir(&self) -> PathBuf {
        let dir = if let Some(ref d) = self.data_dir {
            PathBuf::from(d)
        } else if let Some(legacy) = legacy_data_dir().filter(|d| d.join("identity.json").exists()) {
            legacy
        } else if let Some(base) = dirs::data_dir() {
            base.join("msst-net")
        } else {
            PathBuf::from("/var/lib/msst-net")
        };
        std::fs::create_dir_all(&dir).ok();
        dir
    }

    /// Resolve the IPC socket path.
    ///
    /// Priority: `MSST_IPC_SOCKET` env var → `ipc_socket` config → default.
    /// Default (same directories as 3.0.x): `/run/msst-net/ipc.sock` when
    /// running as root (`/var/run/msst-net` on macOS); otherwise
    /// `$XDG_RUNTIME_DIR/msst-net/ipc.sock`, falling back to
    /// `/tmp/msst-net-<uid>/ipc.sock`.
    pub fn resolve_ipc_socket(&self) -> PathBuf {
        if let Ok(p) = std::env::var("MSST_IPC_SOCKET") {
            return PathBuf::from(p);
        }
        // 3.0.x container deployments: the socket goes in this path's directory.
        if let Some(dir) = std::env::var("CORE_SOCKET_PATH").ok().and_then(|p| PathBuf::from(p).parent().map(PathBuf::from)) {
            return dir.join("ipc.sock");
        }
        if let Some(ref s) = self.ipc_socket {
            return PathBuf::from(s);
        }
        #[cfg(unix)]
        {
            let uid = unsafe { libc::geteuid() };
            let dir = if uid == 0 {
                PathBuf::from(if cfg!(target_os = "macos") { "/var/run/msst-net" } else { "/run/msst-net" })
            } else if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
                PathBuf::from(xdg).join("msst-net")
            } else {
                PathBuf::from(format!("/tmp/msst-net-{}", uid))
            };
            dir.join("ipc.sock")
        }
        #[cfg(not(unix))]
        {
            PathBuf::from(r"\\.\pipe\msst-net-ipc")
        }
    }
}

/// `coord_server_url` from a 3.0.x `config.yaml` (a single `key: value`
/// line, optionally quoted).
fn legacy_coordinator_url(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path).ok()?.lines().find_map(|l| {
        let v = l.trim().strip_prefix("coord_server_url:")?.trim().trim_matches(|c| c == '"' || c == '\'');
        (!v.is_empty()).then(|| v.to_string())
    })
}

/// The 3.0.x data directory: `/var/lib/msst` when `CORE_MODE=container`,
/// otherwise `~/MSST-Net`.
fn legacy_data_dir() -> Option<PathBuf> {
    if std::env::var("CORE_MODE").as_deref() == Ok("container") {
        return Some(PathBuf::from("/var/lib/msst"));
    }
    dirs::home_dir().map(|home| home.join("MSST-Net"))
}

// ---------------------------------------------------------------------------
// Config file I/O
// ---------------------------------------------------------------------------

/// Default config file path.
pub fn default_config_path() -> PathBuf {
    if let Some(config_dir) = dirs::config_dir() {
        config_dir.join("msst-net").join("core.toml")
    } else {
        PathBuf::from("/etc/msst-net/core.toml")
    }
}

/// Load config from a TOML file, or create a default one if it doesn't exist.
pub fn load_or_create(path: &std::path::Path) -> anyhow::Result<CoreConfig> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let config: CoreConfig = toml::from_str(&content)?;
        Ok(config)
    } else {
        let mut config = CoreConfig::default();
        // First run after upgrading: keep a custom coordinator from the
        // 3.0.x `config.yaml` (its only setting).
        if let Some(url) = legacy_data_dir().and_then(|d| legacy_coordinator_url(&d.join("config.yaml"))) {
            config.coordinator_url = url;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(&config)?;
        std::fs::write(path, &content)?;
        Ok(config)
    }
}

/// Apply CLI argument overrides to a config.
pub fn apply_cli_overrides(config: &mut CoreConfig, cli: &CliArgs) {
    if let Some(ref url) = cli.coordinator_url {
        config.coordinator_url = url.clone();
    }
    if let Some(port) = cli.udp_port {
        config.udp_port = port;
    }
    if let Some(port) = cli.metrics_port {
        config.metrics_port = port;
    }
    if let Some(ref level) = cli.log_level {
        config.log_level = level.clone();
    }
    if cli.foreground {
        config.daemon = false;
    }
    if cli.daemon {
        config.daemon = true;
    }
}

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

/// Command-line arguments for the Core daemon.
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub config_path: Option<PathBuf>,
    pub coordinator_url: Option<String>,
    pub udp_port: Option<u16>,
    pub metrics_port: Option<u16>,
    pub log_level: Option<String>,
    pub foreground: bool,
    pub daemon: bool,
}

/// Parse command-line arguments.
///
/// Uses a simple manual parser to avoid adding `clap` as a compile-time
/// dependency (it's slow to build).  Falls back to `clap` only if
/// `--help` or `--version` is requested.
pub fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut cli = CliArgs {
        config_path: None,
        coordinator_url: None,
        udp_port: None,
        metrics_port: None,
        log_level: None,
        foreground: false,
        daemon: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                if i + 1 < args.len() {
                    cli.config_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    eprintln!("--config requires a path argument");
                    std::process::exit(1);
                }
            }
            "--coordinator" => {
                if i + 1 < args.len() {
                    cli.coordinator_url = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("--coordinator requires a URL argument");
                    std::process::exit(1);
                }
            }
            "--udp-port" => {
                if i + 1 < args.len() {
                    cli.udp_port = Some(args[i + 1].parse().expect("--udp-port must be a number"));
                    i += 2;
                } else {
                    eprintln!("--udp-port requires a number");
                    std::process::exit(1);
                }
            }
            "--metrics-port" => {
                if i + 1 < args.len() {
                    cli.metrics_port = Some(args[i + 1].parse().expect("--metrics-port must be a number"));
                    i += 2;
                } else {
                    eprintln!("--metrics-port requires a number");
                    std::process::exit(1);
                }
            }
            "--log-level" | "-l" => {
                if i + 1 < args.len() {
                    cli.log_level = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("--log-level requires a level (trace/debug/info/warn/error)");
                    std::process::exit(1);
                }
            }
            "--foreground" | "-f" => {
                cli.foreground = true;
                i += 1;
            }
            "--daemon" | "-d" => {
                cli.daemon = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("msst-net-core {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                eprintln!("Run with --help for usage.");
                std::process::exit(1);
            }
        }
    }

    cli
}

fn print_help() {
    println!(
        r#"MSST-Net Core {version} — privileged networking daemon

USAGE:
    msst-net-core [OPTIONS]

OPTIONS:
    -c, --config <PATH>         Config file path (default: ~/.config/msst-net/core.toml)
    --coordinator <URL>         Coordinator base URL (overrides config)
    --udp-port <PORT>           UDP data plane port (default: 21031)
    --metrics-port <PORT>       Prometheus metrics port (default: 9100)
    -l, --log-level <LEVEL>     Log level: trace, debug, info, warn, error (default: info)
    -f, --foreground            Run in foreground (don't daemonize)
    -d, --daemon                Run as background daemon
    -h, --help                  Print this help
    -V, --version               Print version

ENVIRONMENT VARIABLES:
    MSST_COORD_URL              Coordinator URL (overrides config and --coordinator)
    MSST_UDP_PORT               UDP port (overrides config and --udp-port)
    MSST_METRICS_PORT           Metrics port (overrides config and --metrics-port)
    MSST_IPC_SOCKET             IPC socket path override
    RUST_LOG                    Tracing log filter (overrides --log-level)"#,
        version = env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_3_0_x_coordinator_url() {
        let dir = std::env::temp_dir().join(format!("msst-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.yaml");
        std::fs::write(&p, "coord_server_url: https://coord.example.org\n").unwrap();
        assert_eq!(legacy_coordinator_url(&p).as_deref(), Some("https://coord.example.org"));
        std::fs::write(&p, "coord_server_url: 'http://10.0.0.1:8080'\n").unwrap();
        assert_eq!(legacy_coordinator_url(&p).as_deref(), Some("http://10.0.0.1:8080"));
        assert_eq!(legacy_coordinator_url(&dir.join("missing.yaml")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
