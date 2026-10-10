//! MSST-Net Core — the privileged networking daemon.
//!
//! Built as a library so the same Core runs as the desktop daemon
//! (`src/main.rs` → [`main_entry`]) and embedded in the Android app
//! ([`embedded`], driven by a JNI glue crate).  Either way, Controllers talk
//! to it only through the IPC protocol.

mod account;
mod acl;
mod config;
pub mod core;
mod diagnostics;
mod logcapture;
mod peer_cache;
mod discovery;
#[cfg(unix)]
pub mod embedded;
mod dns;
mod ippkt;
mod endpoints;
mod contacts;
mod net_settings;
pub mod netsock;
mod nodes;
mod coordinator;
mod identity;
mod inbound;
mod ip;
mod ipc;
mod observability;
mod relay;
mod rooms;
mod runtime;
mod state;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod contract_tests;
mod tun_dev;
#[cfg(windows)]
mod windows_service_host;

use anyhow::Result;
use config::CoreConfig;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

pub(crate) fn init_logging(config: &CoreConfig) {
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    use tracing_subscriber::util::SubscriberInitExt;

    // Install the ring crypto provider for rustls (must happen before any TLS).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level));

    // The Controller log view gets the same lines as the console.
    let capture_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level));

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(env_filter))
        .with(logcapture::LogLayer.with_filter(capture_filter))
        .init();
}

// ---------------------------------------------------------------------------
// UDP socket
// ---------------------------------------------------------------------------

const SOCKET_BUF_BYTES: usize = 4 * 1024 * 1024;

fn tune_socket_buffers(sock: &socket2::Socket) {
    if let Err(e) = sock.set_recv_buffer_size(SOCKET_BUF_BYTES) {
        tracing::debug!("could not set UDP recv buffer: {}", e);
    }
    if let Err(e) = sock.set_send_buffer_size(SOCKET_BUF_BYTES) {
        tracing::debug!("could not set UDP send buffer: {}", e);
    }
}

pub(crate) fn make_udp_socket(port: u16) -> Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    let try_dual = || -> std::io::Result<tokio::net::UdpSocket> {
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        netsock::protect_socket2(&sock)?;
        sock.set_only_v6(false)?;
        tune_socket_buffers(&sock);
        sock.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
        sock.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(sock))
    };

    match try_dual() {
        Ok(s) => Ok(s),
        Err(e) => {
            warn!("dual-stack UDP socket failed ({}), falling back to IPv4-only", e);
            let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            netsock::protect_socket2(&sock)?;
            tune_socket_buffers(&sock);
            sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
            sock.set_nonblocking(true)?;
            Ok(tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(sock))?)
        }
    }
}

// ---------------------------------------------------------------------------
// TUN device
// ---------------------------------------------------------------------------

fn try_create_tun(config: &CoreConfig, ipv4: &str, ipv6: &str) -> Option<(tun2::AsyncDevice, String)> {
    match tun_dev::create_tun(&config.tun_name, ipv4, ipv6, config.tun_mtu) {
        Ok((dev, iface)) => {
            info!("TUN interface {} up (MTU {})", iface, config.tun_mtu);
            Some((dev, iface))
        }
        Err(e) => {
            warn!("TUN creation failed ({}); running without TUN (relay-only mode)", e);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Shutdown signal
// ---------------------------------------------------------------------------

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to register SIGTERM handler: {} — SIGINT still works", e);
            let _ = tokio::signal::ctrl_c().await;
            info!("received SIGINT, shutting down…");
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("received SIGINT, shutting down…"),
        _ = sigterm.recv() => info!("received SIGTERM, shutting down…"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("received Ctrl+C, shutting down…");
}

// ---------------------------------------------------------------------------
// Daemon mode (Unix only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn maybe_daemonize(config: &CoreConfig) {
    if !config.daemon {
        return;
    }

    // Fork to background.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("fork failed: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }
        if pid > 0 {
            // Parent: print PID and exit.
            println!("msst-net-core daemon started (PID {})", pid);
            std::process::exit(0);
        }
        // Child: create new session and continue.
        libc::setsid();
    }
}

#[cfg(not(unix))]
fn maybe_daemonize(_config: &CoreConfig) {}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/// Load the configuration: file (created on first run) → CLI → env vars.
pub(crate) fn load_config() -> Result<CoreConfig> {
    let cli = config::parse_args();
    let config_path = cli.config_path.clone().unwrap_or_else(config::default_config_path);
    let mut config = config::load_or_create(&config_path)?;
    config::apply_cli_overrides(&mut config, &cli);

    // Env var overrides (highest priority).
    if let Ok(url) = std::env::var("MSST_COORD_URL") {
        config.coordinator_url = url;
    }
    if let Ok(port) = std::env::var("MSST_UDP_PORT") {
        config.udp_port = port.parse().unwrap_or(config.udp_port);
    }
    if let Ok(port) = std::env::var("MSST_METRICS_PORT") {
        config.metrics_port = port.parse().unwrap_or(config.metrics_port);
    }
    Ok(config)
}

pub(crate) fn build_runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread().enable_all().build()?)
}

/// Desktop entry point (the `msst-net-core` binary).
pub fn main_entry() -> Result<()> {
    // Windows: when started by the Service Control Manager, run as a
    // service; launched by hand, run in the console (3.0.x behaviour).
    #[cfg(windows)]
    if let Some(result) = windows_service_host::dispatch() {
        return result;
    }

    let config = load_config()?;
    // Fork before any thread (incl. the tokio runtime) exists.
    maybe_daemonize(&config);
    build_runtime()?.block_on(run(config, wait_for_shutdown_signal()))
}

/// The Core daemon: runs until `shutdown` completes, then shuts down
/// gracefully.
async fn run(config: CoreConfig, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
    init_logging(&config);
    info!("MSST-Net Core {} starting", env!("CARGO_PKG_VERSION"));
    info!("config: coordinator={} udp={} metrics={} log={}",
        config.coordinator_url, config.udp_port, config.metrics_port, config.log_level);

    let data_dir = config.resolve_data_dir();
    let ipc_socket = config.resolve_ipc_socket();
    let mut core = core::Core::start(core::CoreOptions { config, data_dir, ipc_socket, metrics: true }).await?;

    // TUN (optional — without root Core runs relay-only) and, with it, the
    // local DNS resolver and the game discovery proxy (as in 3.0.x).
    let (ipv4, ipv6) = core.virtual_ips().await;
    let tun_iface = match try_create_tun(&core.config, &ipv4, &ipv6) {
        Some((dev, iface)) => {
            core.attach_tun(dev).await;
            core.start_dns_and_discovery(&iface).await;
            Some(iface)
        }
        None => None,
    };

    info!("MSST-Net Core is running — press Ctrl+C to stop");
    shutdown.await;

    // Revert system DNS while the TUN interface still exists.
    if let Some(iface) = &tun_iface {
        dns::system::unconfigure(iface);
    }
    core.shutdown().await;
    info!("MSST-Net Core stopped");
    Ok(())
}
