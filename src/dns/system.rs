//! Platform-specific system DNS configuration (ported unchanged from 3.0.x).
//!
//! Routes *.msst.net queries to the local resolver on 127.0.0.1:21053.
//! All functions are best-effort: failures are logged as warnings rather than
//! propagated, because DNS is a convenience feature and the VPN still works
//! if system DNS is not configured.
use std::process::Command;
use tracing::{debug, error, info};
#[cfg(target_os = "macos")]
use tracing::warn;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::net_settings::LinuxDnsMode;
static LINUX_USE_IPTABLES_FLAG: AtomicBool = AtomicBool::new(false);

/// Configure split-DNS for the TUN interface `iface`.
///
/// Returns `true` on Linux when the `PreferSplit` mode fell back to iptables
/// because `resolvectl` was not available.  The caller can persist that
/// fallback by saving `LinuxDnsMode::IptablesOnly` to settings.
pub fn configure(iface: &str, mode: LinuxDnsMode) -> bool {
    if cfg!(target_os = "linux") {
        return configure_linux(iface, mode);
    }
    if cfg!(target_os = "macos") {
        configure_macos();
    } else if cfg!(windows) {
        configure_windows();
    }
    false
}

/// Remove the split-DNS configuration previously added by [`configure`].
/// Called from `shutdown()` on graceful exit (SIGINT/SIGTERM/Ctrl+C).
pub fn unconfigure(iface: &str) {
    if cfg!(target_os = "linux") {
        unconfigure_linux(iface);
    } else if cfg!(target_os = "macos") {
        unconfigure_macos();
    } else if cfg!(windows) {
        unconfigure_windows();
    }
}

/// Whether DNS goes through the iptables DNAT → TUN interception path, so
/// the outbound loop must answer queries to 172.22.0.1:21053.
pub fn using_iptables() -> bool {
    LINUX_USE_IPTABLES_FLAG.load(Ordering::Acquire)
}

// ── Linux: systemd-resolved via resolvectl or iptables ───────────────────────
#[cfg(target_os = "linux")]
fn configure_linux(iface: &str, mode: LinuxDnsMode) -> bool {
    match mode {
        LinuxDnsMode::IptablesOnly => {
            LINUX_USE_IPTABLES_FLAG.store(true, Ordering::Release);
            info!("DNS: iptables-only mode — skipping resolvectl");
            setup_iptables_dns();
            false
        }
        LinuxDnsMode::PreferSplit => {
            // Per-link split DNS: only *.msst.net queries go to our resolver.
            // The ~ prefix marks these as routing domains (not search domains).
            if let Ok(true) = Path::new("/usr/bin/resolvectl").try_exists() {
                info!(
                    "DNS: systemd-resolved configured ({} → {} for .msst.net)",
                    iface, super::DNS_LISTEN_ADDR,
                );
                run("resolvectl", &["dns", iface, super::DNS_LISTEN_ADDR]);
                run("resolvectl", &["domain", iface, "~msst.net"]);
                false
            } else {
                // resolvectl not available — fall back to iptables DNS interception.
                LINUX_USE_IPTABLES_FLAG.store(true, Ordering::Release);
                info!("DNS: resolvectl not found, falling back to iptables TUN DNS interception");
                setup_iptables_dns();
                true
            }
        }
    }
}

/// Install iptables rules that redirect all locally-generated UDP port-53
/// DNS queries to the MSST-Net TUN virtual resolver (172.22.0.1:TUN_DNS_PORT).
///
/// Using TUN_DNS_PORT (21053) rather than 53 as the DNAT target avoids any
/// conflict with system processes that may bind port 53 on the TUN interface.
///
/// Three rules are added (in evaluation order):
/// 1. ACCEPT — traffic already addressed to 172.22.0.1:TUN_DNS_PORT (safety
///    net for direct queries to that address; prevents double-DNAT).
/// 2. RETURN — traffic marked with DNS_UPSTREAM_MARK, used by our own
///    forward_to_upstream() sockets to bypass this redirection and reach
///    real external DNS servers without looping.
/// 3. DNAT  — everything else on port 53 is redirected to 172.22.0.1:TUN_DNS_PORT,
///    which is routed through the TUN and intercepted by tun_rx_loop.
#[cfg(target_os = "linux")]
fn setup_iptables_dns() {
    let tun_port   = super::TUN_DNS_PORT.to_string();
    let dns_target = format!("{}:{}", super::TUN_DNS_IP, super::TUN_DNS_PORT);
    let dns_host   = super::TUN_DNS_IP.to_string();
    let mark_str   = format!("{:#x}", super::DNS_UPSTREAM_MARK);

    // Rule 1: allow traffic already going to the virtual DNS IP:port (prevents double-DNAT).
    run("iptables", &["-t", "nat", "-I", "OUTPUT", "-p", "udp",
                      "-d", &dns_host, "--dport", &tun_port, "-j", "ACCEPT"]);
    // Rule 2: exempt our own upstream DNS sockets (marked) from DNAT.
    run("iptables", &["-t", "nat", "-I", "OUTPUT", "-p", "udp", "--dport", "53",
                      "-m", "mark", "--mark", &mark_str, "-j", "RETURN"]);
    // Rule 3: redirect all other UDP port-53 queries to the TUN virtual resolver.
    run("iptables", &["-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53",
                      "-j", "DNAT", "--to-destination", &dns_target]);
    info!("DNS: iptables DNS redirection rules installed (→ {})", dns_target);
}

#[cfg(target_os = "linux")]
fn unconfigure_linux(iface: &str) {
    if LINUX_USE_IPTABLES_FLAG.load(Ordering::Acquire) {
        let tun_port   = super::TUN_DNS_PORT.to_string();
        let dns_target = format!("{}:{}", super::TUN_DNS_IP, super::TUN_DNS_PORT);
        let dns_host   = super::TUN_DNS_IP.to_string();
        let mark_str   = format!("{:#x}", super::DNS_UPSTREAM_MARK);

        run("iptables", &["-t", "nat", "-D", "OUTPUT", "-p", "udp",
                          "-d", &dns_host, "--dport", &tun_port, "-j", "ACCEPT"]);
        run("iptables", &["-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53",
                          "-m", "mark", "--mark", &mark_str, "-j", "RETURN"]);
        run("iptables", &["-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53",
                          "-j", "DNAT", "--to-destination", &dns_target]);
        info!("DNS: iptables rules reverted");
    } else {
        run("resolvectl", &["revert", iface]);
        info!("DNS: systemd-resolved reverted for {}", iface);
    }
}

// Satisfy the compiler on non-Linux targets.
#[cfg(not(target_os = "linux"))]
fn configure_linux(_iface: &str, _mode: LinuxDnsMode) -> bool { false }
#[cfg(not(target_os = "linux"))]
fn unconfigure_linux(_iface: &str) {}

// ── macOS: /etc/resolver/ ────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn configure_macos() {
    // macOS reads per-domain resolver config from /etc/resolver/<domain>.
    // For *.msst.net we create /etc/resolver/msst.net so all subdomains are routed.
    // The `port` directive tells the resolver to use a non-standard port.
    let content = "nameserver 127.0.0.1\nport 21053\n";
    let path = "/etc/resolver/msst.net";
    match std::fs::write(path, content) {
        Ok(()) => info!("DNS: wrote {}", path),
        Err(e) => error!("DNS: could not write {} (root required?): {}", path, e),
    }
}

#[cfg(target_os = "macos")]
fn unconfigure_macos() {
    let path = "/etc/resolver/msst.net";
    if let Err(e) = std::fs::remove_file(path) {
        warn!("DNS: could not remove {}: {}", path, e);
    }
    info!("DNS: removed /etc/resolver/msst.net");
}

#[cfg(not(target_os = "macos"))]
fn configure_macos() {}
#[cfg(not(target_os = "macos"))]
fn unconfigure_macos() {}

// ── Windows: NRPT via PowerShell ─────────────────────────────────────────────
//
// Windows NRPT only supports port 53; DNS_LISTEN_ADDR is compiled to
// 127.0.0.1:53 on Windows (see dns/mod.rs).  Administrator privileges are
// required for both WinTun and binding port 53, so this is acceptable.

#[cfg(windows)]
fn configure_windows() {
    let cmd = format!(
        "Add-DnsClientNrptRule -Namespace '.msst.net' -NameServers '127.0.0.1' \
-ErrorAction SilentlyContinue"
    );
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &cmd]);
    info!("DNS: NRPT rule added for .msst.net (127.0.0.1:53)");
}

#[cfg(windows)]
fn unconfigure_windows() {
    let cmd = "Get-DnsClientNrptRule | \
Where-Object { $_.Namespace -eq '.msst.net' } | \
Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue".to_string();
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &cmd]);
    info!("DNS: NRPT rule removed for .msst.net");
}

#[cfg(not(windows))]
fn configure_windows() {}
#[cfg(not(windows))]
fn unconfigure_windows() {}

// ── Helper ────────────────────────────────────────────────────────────────────

fn run(prog: &str, args: &[&str]) {
    debug!("DNS config: running `{} {}`", prog, args.join(" "));
    match Command::new(prog).args(args).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => error!(
            "DNS config: `{} {}` failed: {}",
            prog,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => error!("DNS config: could not run `{}`: {}", prog, e),
    }
}
