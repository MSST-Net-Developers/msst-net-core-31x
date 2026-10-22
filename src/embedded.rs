//! Embedded Core — lifecycle API for running Core inside an app process
//! (Android VpnService), driven by a separate JNI glue crate (as in 3.0.x).
//!
//! The app's UI is still a Controller: it talks to this Core over the IPC
//! protocol, on a Unix socket in the app's private directory — there is no
//! Rust-level state/command API here.  This module only covers what the
//! VpnService itself must do:
//!
//! ```text
//! let core = EmbeddedCore::start(data_dir, ipc_socket, None,
//!     Some(Arc::new(|fd| vpn_service.protect(fd))))?;
//! let (v4, v6) = core.virtual_ips();      // → VpnService.Builder addresses
//! core.attach_tun_fd(builder.establish().detachFd())?;
//! core.network_changed();                 // ConnectivityManager callback
//! core.detach_tun();                      // VPN paused (core keeps running)
//! core.attach_tun_fd(new_fd)?;            // VPN resumed
//! core.stop();
//! ```
//!
//! `protect` is `VpnService.protect(fd)`: every socket Core opens (UDP data
//! plane, relay probes, DNS upstream, coordinator WebSocket and — through a
//! loopback SOCKS5 proxy with random credentials — coordinator HTTP) is
//! protected before use, so Core keeps working under "always-on VPN + block
//! connections without VPN".  It must be thread-safe and must not call back
//! into Core.
//!
//! On Android the VpnService routes the MSST-Net ranges and sets 172.22.0.1 as
//! DNS server; Core answers DNS queries arriving through the TUN.  There is
//! no system DNS configuration and no game discovery proxy (3.0.x parity).

#![cfg(unix)]

use crate::config::CoreConfig;
use crate::core::{Core, CoreOptions};
use anyhow::{Context, Result};
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::Once;
use tracing::info;

static LOGGING: Once = Once::new();

/// A running embedded Core.  Methods block on its own tokio runtime, so
/// they must not be called from inside an async context.
pub struct EmbeddedCore {
    runtime: tokio::runtime::Runtime,
    core: Option<Core>,
    ipv4: String,
    ipv6: String,
}

impl EmbeddedCore {
    /// Start Core: identity and state from `data_dir`, IPC on `ipc_socket`.
    /// `coordinator_url` overrides the default coordinator; `protect` is the
    /// `VpnService.protect` callback (installed once per process).
    pub fn start(
        data_dir: &Path,
        ipc_socket: &Path,
        coordinator_url: Option<&str>,
        protect: Option<crate::netsock::Protector>,
    ) -> Result<EmbeddedCore> {
        let mut config = CoreConfig { data_dir: Some(data_dir.to_string_lossy().into_owned()), ..CoreConfig::default() };
        if let Some(url) = coordinator_url {
            config.coordinator_url = url.to_string();
        }
        LOGGING.call_once(|| crate::init_logging(&config));
        std::fs::create_dir_all(data_dir).with_context(|| format!("create {:?}", data_dir))?;
        info!("MSST-Net Core {} starting (embedded)", env!("CARGO_PKG_VERSION"));

        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        if let Some(p) = protect {
            crate::netsock::install_protector(p);
            runtime.block_on(crate::netsock::start_protected_proxy()).context("start protected proxy")?;
        }
        let core = runtime.block_on(Core::start(CoreOptions {
            config,
            data_dir: data_dir.to_path_buf(),
            ipc_socket: ipc_socket.to_path_buf(),
            metrics: false,
            host_routing: false,
        }))?;
        let (ipv4, ipv6) = runtime.block_on(core.virtual_ips());
        // Must be created inside the runtime (it spawns nothing, but keeps
        // the API symmetric with the desktop path).
        runtime.block_on(async { core.enable_tun_dns() });
        Ok(EmbeddedCore { runtime, core: Some(core), ipv4, ipv6 })
    }

    /// The device's virtual IPv4 / IPv6 (for `VpnService.Builder.addAddress`).
    pub fn virtual_ips(&self) -> (String, String) {
        (self.ipv4.clone(), self.ipv6.clone())
    }

    /// Use the VpnService TUN `fd` (ownership passes to Core: detach it from
    /// the `ParcelFileDescriptor` first).  Replaces any attached TUN.
    pub fn attach_tun_fd(&mut self, fd: RawFd) -> Result<()> {
        let core = self.core.as_mut().context("core stopped")?;
        self.runtime.block_on(async {
            let mut cfg = tun2::Configuration::default();
            cfg.raw_fd(fd);
            let dev = tun2::create_as_async(&cfg).context("open TUN fd")?;
            core.attach_tun(dev).await;
            info!("embedded: TUN attached from fd {}", fd);
            Ok(())
        })
    }

    /// Stop using the TUN (VPN paused); the coordinator connection and all
    /// state stay up.
    pub fn detach_tun(&mut self) {
        if let Some(core) = self.core.as_mut() {
            self.runtime.block_on(core.detach_tun());
        }
    }

    /// The device's network changed (Wi-Fi ↔ mobile): flush DNS, restart
    /// path probing promptly and re-announce our endpoints (3.0.x
    /// network-change handler, debounced by the caller).
    pub fn network_changed(&self) {
        let Some(core) = self.core.as_ref() else { return };
        let state = core.state.clone();
        self.runtime.block_on(async move {
            info!("embedded: network changed — re-detecting endpoints");
            if let Some(dns) = state.dns.get() {
                dns.clear_cache();
            }
            state.scheduler.lock().await.clear_hold_timers();
            crate::endpoints::spawn_detect_and_report(state.clone());
        });
    }

    /// Shut Core down and flush its state.
    pub fn stop(mut self) {
        if let Some(core) = self.core.take() {
            self.runtime.block_on(core.shutdown());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full lifecycle with a datagram socketpair standing in for the
    /// VpnService TUN (`tun2` can only wrap raw fds on Android/iOS).
    #[test]
    fn lifecycle_attach_detach_resume() {
        use std::os::unix::net::UnixDatagram;
        let dir = std::env::temp_dir().join(format!("msst-embedded-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = std::env::temp_dir().join(format!("msst-emb-{}.sock", std::process::id()));
        let mut config = CoreConfig { data_dir: Some(dir.to_string_lossy().into_owned()), ..CoreConfig::default() };
        config.udp_port = 0; // ephemeral, unprivileged
        config.coordinator_url = "http://127.0.0.1:9".into();
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let core = runtime
            .block_on(Core::start(CoreOptions { config, data_dir: dir.clone(), ipc_socket: sock, metrics: false, host_routing: false }))
            .unwrap();
        let (ipv4, ipv6) = runtime.block_on(core.virtual_ips());
        runtime.block_on(async { core.enable_tun_dns() });
        let mut emb = EmbeddedCore { runtime, core: Some(core), ipv4, ipv6 };
        let (v4, v6) = emb.virtual_ips();
        assert!(v4.starts_with("172.22.") && v6.starts_with("fd22:2222:2222:2222::"));

        // Attach a fake TUN; a packet Core injects must come out of it.
        let attach = |emb: &mut EmbeddedCore| -> UnixDatagram {
            let (ours, theirs) = UnixDatagram::pair().unwrap();
            ours.set_nonblocking(true).unwrap();
            // The datagram fd is driven through the stream API: read/write on
            // a SOCK_DGRAM socket move one packet each, like a TUN fd.
            let std_stream = unsafe {
                use std::os::fd::{FromRawFd, IntoRawFd};
                std::os::unix::net::UnixStream::from_raw_fd(ours.into_raw_fd())
            };
            let core = emb.core.as_mut().unwrap();
            emb.runtime.block_on(async {
                let io = tokio::net::UnixStream::from_std(std_stream).unwrap();
                let (r, w) = tokio::io::split(io);
                core.attach_tun_io(r, w).await;
            });
            theirs.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            theirs
        };
        let inject = |emb: &EmbeddedCore, pkt: &[u8]| {
            let tx = emb.core.as_ref().unwrap().state.tun_tx.get().unwrap().clone();
            let p = pkt.to_vec();
            emb.runtime.block_on(async move { tx.send(p).await.unwrap() });
        };
        let mut buf = [0u8; 64];

        let tun1 = attach(&mut emb);
        inject(&emb, b"packet-1");
        let n = tun1.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"packet-1");

        emb.network_changed();
        emb.detach_tun();
        inject(&emb, b"dropped-while-paused");

        let tun2 = attach(&mut emb); // resume with a new "fd"
        inject(&emb, b"packet-2");
        // A packet still queued at pause time may be delivered to the new
        // TUN (harmless); new packets must arrive.
        loop {
            let n = tun2.recv(&mut buf).unwrap();
            if &buf[..n] == b"packet-2" {
                break;
            }
            assert_eq!(&buf[..n], b"dropped-while-paused");
        }

        emb.stop();
        assert!(dir.join("identity.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
