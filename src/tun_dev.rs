//! TUN device creation and interface configuration.
//!
//! Ported from 3.0.x `net/tun_dev.rs`: assigns the device's derived IPv4 /
//! IPv6 ULA addresses and adds the MSST-Net summary routes plus the
//! multicast routes used by the game discovery proxy.

use anyhow::Result;
use std::process::Command;
use tracing::{error, info, warn};
use tun2::{AbstractDevice, AsyncDevice};

/// Create a TUN interface with `ipv4`/16 and `ipv6`/64 and the MSST routes.
///
/// `name` is ignored on macOS, where the kernel assigns `utunN`.
/// Requires root / Administrator / `CAP_NET_ADMIN`.
/// Returns the device and its actual interface name.
pub fn create_tun(name: &str, ipv4: &str, ipv6: &str, mtu: u16) -> Result<(AsyncDevice, String)> {
    info!("Creating TUN device: ipv4={} ipv6={} mtu={}", ipv4, ipv6, mtu);
    let addr: std::net::Ipv4Addr = ipv4
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid IPv4 address: {}", ipv4))?;

    let mut config = tun2::Configuration::default();
    #[cfg(not(target_os = "macos"))]
    config.tun_name(name);
    #[cfg(target_os = "macos")]
    let _ = name;
    config.mtu(mtu);
    config.up();
    config.address(addr).netmask((255, 255, 0, 0));

    let dev = tun2::create_as_async(&config)?;
    let iface = dev.tun_name()?;
    info!("Created TUN interface {} with IPv4 {}/16", iface, ipv4);

    configure_interface(&iface, ipv6);
    Ok((dev, iface))
}

#[cfg(target_os = "linux")]
fn configure_interface(iface: &str, ipv6: &str) {
    run_cmd("ip", &["-6", "addr", "add", &format!("{}/64", ipv6), "dev", iface]);
    // Ensure the interface is marked UP (tun2 may not set IFF_UP on all kernels).
    run_cmd("ip", &["link", "set", iface, "up"]);
    run_cmd("ip", &["route", "add", crate::ip::IPV4_NET, "dev", iface]);
    run_cmd("ip", &["-6", "route", "add", crate::ip::IPV6_NET, "dev", iface]);
    // Multicast routes for the game discovery proxy.
    run_cmd("ip", &["route", "add", "224.0.2.60/32", "dev", iface]); // MCJE
    run_cmd("ip", &["route", "add", "224.0.0.251/32", "dev", iface]); // mDNS
}

#[cfg(target_os = "macos")]
fn configure_interface(iface: &str, ipv6: &str) {
    run_cmd("ifconfig", &[iface, "inet6", &format!("{}/64", ipv6), "alias"]);
    run_cmd("ifconfig", &[iface, "up"]);
    run_cmd("route", &["add", "-net", crate::ip::IPV4_NET, "-interface", iface]);
    run_cmd("route", &["add", "-inet6", crate::ip::IPV6_NET, "-interface", iface]);
    run_cmd("route", &["add", "-host", "224.0.2.60", "-interface", iface]); // MCJE
    run_cmd("route", &["add", "-host", "224.0.0.251", "-interface", iface]); // mDNS
}

/// Requires the wintun driver (`wintun.dll`) next to the executable or on PATH.
#[cfg(windows)]
fn configure_interface(iface: &str, ipv6: &str) {
    run_cmd("netsh", &["interface", "ipv6", "add", "address", iface, &format!("{}/64", ipv6)]);
    run_cmd("netsh", &["interface", "ipv4", "add", "route", crate::ip::IPV4_NET, iface]);
    run_cmd("netsh", &["interface", "ipv6", "add", "route", crate::ip::IPV6_NET, iface]);
    run_cmd("netsh", &["interface", "ipv4", "add", "route", "224.0.2.60/32", iface]); // MCJE
    run_cmd("netsh", &["interface", "ipv4", "add", "route", "224.0.0.251/32", iface]); // mDNS
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn configure_interface(iface: &str, _ipv6: &str) {
    warn!(
        "Automatic interface configuration is not supported on this platform. \
         TUN device {} may need manual address/route setup.",
        iface
    );
}

fn run_cmd(program: &str, args: &[&str]) {
    match Command::new(program).args(args).output() {
        Ok(out) if out.status.success() => {
            info!("{} {}", program, args.join(" "));
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("File exists") || stderr.contains("already exists") {
                warn!("{} {}: already configured (harmless)", program, args.join(" "));
            } else {
                error!("{} {} failed: {}", program, args.join(" "), stderr.trim());
            }
        }
        Err(e) => error!("Failed to run `{} {}`: {}", program, args.join(" "), e),
    }
}
