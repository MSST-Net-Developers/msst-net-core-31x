//! Core lifecycle shared by the desktop daemon and the embedded (Android)
//! build: start everything that doesn't need a TUN, attach/detach TUN
//! devices, shut down.
//!
//! The TUN plumbing is split so a TUN can be swapped at runtime (Android
//! VpnService pause/resume) without restarting anything else:
//! - a **writer pump** owns the inbound queue for the whole lifetime and
//!   writes to whichever TUN is attached (packets are dropped while none is);
//! - the **outbound loop** owns the outbound queue for the whole lifetime;
//! - each attached TUN gets a **reader task** feeding the outbound queue.

use crate::config::CoreConfig;
use crate::coordinator::CoordinatorConfig;
use crate::ipc::IpcServer;
use crate::runtime::CoreRuntime;
use crate::state::CoreState;
use crate::{acl, contacts, identity, net_settings, observability, peer_cache};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

type TunWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// What a Core instance needs beyond the config file.
pub struct CoreOptions {
    pub config: CoreConfig,
    pub data_dir: PathBuf,
    pub ipc_socket: PathBuf,
    /// Serve Prometheus metrics on `config.metrics_port`.
    pub metrics: bool,
    /// Desktop daemon: manage the host's routing (`crate::routing`) — from
    /// before the first packet or Coordinator connection.  Never for
    /// embedded Core or tests.
    pub host_routing: bool,
}

pub struct Core {
    pub state: Arc<CoreState>,
    pub config: CoreConfig,
    rt: CoreRuntime,
    writer_slot: Arc<Mutex<Option<TunWriter>>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    reader: Option<JoinHandle<()>>,
    background: Vec<JoinHandle<()>>,
}

impl Core {
    /// Load identity and persisted state, open the UDP socket and start
    /// every background task (coordinator, relay, scheduler, IPC, …).
    /// No TUN yet — see [`Core::attach_tun`].
    pub async fn start(opts: CoreOptions) -> Result<Core> {
        let CoreOptions { mut config, data_dir, ipc_socket, metrics, host_routing } = opts;
        info!("data directory: {:?}", data_dir);

        let udp = Arc::new(crate::make_udp_socket(config.udp_port)?);
        info!("UDP socket listening on [::]:{}", config.udp_port);

        let identity = identity::load_or_create(&data_dir)?;
        let (ipv4, ipv6) = identity.virtual_ips();
        info!("user ID:   {}", identity.user.id);
        info!("device ID: {}", identity.device.id);
        info!("IPv4: {}  IPv6: {}", ipv4, ipv6);

        let settings = net_settings::NetworkSettings::load(&data_dir);
        if let Some(mtu) = settings.mtu_override {
            config.tun_mtu = mtu;
        }
        info!(
            "network settings: disable_p2p={} lock_path={} keepalive={:?}s mtu={}",
            settings.disable_p2p, settings.lock_path, settings.keepalive_secs, config.tun_mtu
        );

        let state = Arc::new(CoreState::new(udp.clone(), data_dir.clone()));
        state.apply_identity(&identity).await;
        *state.net_settings.write().await = settings;
        state.apply_net_settings().await;
        if host_routing {
            crate::routing::enable(&state).await;
        }
        acl::load(&state).await;
        peer_cache::restore(&state).await;
        match contacts::ContactList::load(&data_dir) {
            Ok(c) => *state.contacts.lock().unwrap_or_else(|e| e.into_inner()) = c,
            Err(e) => warn!("contacts: {}; starting empty", e),
        }

        // IPC is bound before any task starts: a Core nobody can manage must
        // not start at all (and must not leave tasks behind).
        let server = IpcServer::new(state.clone());
        #[cfg(unix)]
        let listener = IpcServer::bind_unix(&ipc_socket)
            .map_err(|e| anyhow::anyhow!("cannot bind IPC socket {:?}: {}", ipc_socket, e))?;
        #[cfg(windows)]
        let (pipe_name, first_pipe) = {
            let name = ipc_socket.to_string_lossy().into_owned();
            let first = IpcServer::bind_named_pipe(&name)
                .map_err(|e| anyhow::anyhow!("cannot create IPC pipe {}: {}", name, e))?;
            (name, first)
        };

        // TUN plumbing (see module docs).
        let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(1024);
        let writer_slot: Arc<Mutex<Option<TunWriter>>> = Arc::new(Mutex::new(None));
        let _ = state.tun_tx.set(tun_tx.clone());
        let mut background = vec![tokio::spawn(writer_pump(tun_rx, writer_slot.clone()))];

        if metrics {
            let m = Arc::new(observability::metrics::CoreMetrics::new());
            let _ = state.metrics.set(m.clone());
            let port = config.metrics_port;
            background.push(tokio::spawn(async move { observability::start_metrics_server(m, port).await }));
            info!("Prometheus metrics on http://127.0.0.1:{}/metrics", port);
        }

        let mut rt = CoreRuntime::new(state.clone());
        rt.start_outbound(outbound_rx);
        rt.start_fetcher();
        rt.start_relay_tasks();
        rt.start_scheduler_tick();
        rt.start_housekeeping();

        #[cfg(unix)]
        background.push(tokio::spawn(server.serve_unix(listener)));
        #[cfg(windows)]
        background.push(tokio::spawn(server.serve_named_pipe(first_pipe, pipe_name)));

        rt.start_inbound(udp, tun_tx);
        rt.start_coordinator(CoordinatorConfig { coord_url: config.coordinator_url.clone() }, config.preferred_relay.clone());
        info!("coordinator client targeting {}", config.coordinator_url);
        info!("core state initialized, generation: {}", state.generation.current());

        Ok(Core { state, config, rt, writer_slot, outbound_tx, reader: None, background })
    }

    /// The device's virtual IPv4 / IPv6 (for TUN / VpnService setup).
    pub async fn virtual_ips(&self) -> (String, String) {
        self.state.identity.read().await.as_ref().map(|i| i.virtual_ips_canonical()).unwrap_or_default()
    }

    /// Start using `dev` as the TUN (replacing any attached one).
    pub async fn attach_tun(&mut self, dev: tun2::AsyncDevice) {
        let (reader, writer) = tokio::io::split(dev);
        self.attach_tun_io(reader, writer).await;
    }

    /// Attach any packet-oriented reader/writer pair as the TUN (each read
    /// yields one IP packet, each write takes one).
    pub async fn attach_tun_io(
        &mut self,
        mut reader: impl AsyncRead + Send + Unpin + 'static,
        writer: impl AsyncWrite + Send + Unpin + 'static,
    ) {
        self.detach_tun().await;
        *self.writer_slot.lock().await = Some(Box::new(writer));
        self.state.tun_attached.store(true, std::sync::atomic::Ordering::SeqCst);
        let tx = self.outbound_tx.clone();
        self.reader = Some(tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
        }));
        info!("TUN attached");
    }

    /// Stop using the current TUN; everything else keeps running.
    pub async fn detach_tun(&mut self) {
        if let Some(r) = self.reader.take() {
            r.abort();
            let _ = r.await;
        }
        if self.writer_slot.lock().await.take().is_some() {
            self.state.tun_attached.store(false, std::sync::atomic::Ordering::SeqCst);
            info!("TUN detached");
        }
    }

    /// Desktop extras that need the TUN interface: local DNS (+ system
    /// split-DNS) and the game discovery proxy.
    pub async fn start_dns_and_discovery(&mut self, iface: &str) {
        self.rt.start_dns_and_discovery(iface).await;
    }

    /// Embedded (Android) DNS: a resolver answering queries the system sends
    /// into the TUN (no local server, no system configuration).
    pub fn enable_tun_dns(&self) {
        let _ = self.state.dns.set(crate::dns::DnsResolver::new(&self.state));
    }

    /// Stop every task and flush persisted state.
    pub async fn shutdown(mut self) {
        info!("shutting down…");
        self.detach_tun().await;
        self.rt.shutdown().await;
        for h in self.background {
            h.abort();
        }
        self.state.save_contacts();
        peer_cache::save(&self.state).await;
        let net = self.state.net.read().await;
        info!("final state: {} peers, {} rules, relay {:?}", net.peer_list.len(), net.acl_rules.len(), net.relay_addr);
    }
}

/// Write inbound packets to the attached TUN; drop them while none is.
async fn writer_pump(mut rx: mpsc::Receiver<Vec<u8>>, slot: Arc<Mutex<Option<TunWriter>>>) {
    while let Some(pkt) = rx.recv().await {
        let mut guard = slot.lock().await;
        if let Some(w) = guard.as_mut() {
            if let Err(e) = w.write_all(&pkt).await {
                error!("TUN write error: {}", e);
            }
        }
    }
}
