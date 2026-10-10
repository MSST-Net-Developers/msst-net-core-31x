//! Core state — the authoritative state container for MSST-Net Core.
//!
//! This is the 3.1.x replacement for the 3.0.x `AppState` god-object.
//! Instead of 22 fields with 8+ lock types, state is organized into
//! domain-specific containers that can be locked independently.

use msst_core_state::encryption::EncryptionEngine;
use msst_core_state::firewall::Firewall;
use msst_core_state::packet::ConnectionTracker;
use msst_core_state::peer_list::PeerList;
use msst_core_state::peer_mgmt::PeerManager;
use msst_core_state::scheduler::P2PScheduler;
use msst_core_state::Generation;
use msst_acl_engine::FirewallRule;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// NetState — the network-facing state
// ---------------------------------------------------------------------------

/// Network-facing state: peers, ACL rules, connection tracking, room
/// membership.  Protected by a single `RwLock` — readers (packet processing)
/// take a read lock; mutations (coordinator events, API commands) take a
/// write lock.
pub struct NetState {
    /// The authoritative peer list.
    pub peer_list: PeerList,
    /// ACL rules — the single list the packet pipeline evaluates.
    /// Mutated only through `crate::acl`.
    pub acl_rules: Vec<FirewallRule>,
    /// Display-only mnemonics per rule: rule_id → (ID → mnemonic as entered).
    pub acl_labels: HashMap<String, std::collections::BTreeMap<String, String>>,
    /// Whether this device is authenticated (has OIDC credentials).  Used
    /// by the guest restriction on inbound traffic.
    pub local_authenticated: bool,
    /// Device IDs currently in a shared room with us.
    pub room_peers: HashSet<String>,
    /// Rooms this device has joined: room_id → room_name.  Re-joined on
    /// every coordinator (re)connect and kept alive with `room_keepalive`.
    pub joined_rooms: HashMap<String, String>,
    /// Local device ID (set during init).
    pub local_device_id: String,
    /// Local user ID (set during init).
    pub local_user_id: String,
    /// Whether ICMP echo-request (ping) is enabled.
    pub ping_enabled: bool,
    /// The relay server address we're registered with (numeric `IP:port`).
    pub relay_addr: Option<String>,
    /// Peers' announced direct endpoints (P2P candidates), from room
    /// state, node fetches and node events.
    pub peer_endpoints: HashMap<String, Vec<std::net::SocketAddr>>,
    /// Relay RTT measurements (own relay + peers' relays).
    pub relay_rtt: crate::relay::RelayRttTracker,
    /// Coordinator base URL.
    pub coord_url: String,
}

impl NetState {
    pub fn new() -> Self {
        NetState {
            peer_list: PeerList::new(),
            acl_rules: Vec::new(),
            acl_labels: HashMap::new(),
            local_authenticated: false,
            room_peers: HashSet::new(),
            joined_rooms: HashMap::new(),
            local_device_id: String::new(),
            local_user_id: String::new(),
            ping_enabled: false,
            relay_addr: None,
            relay_rtt: crate::relay::RelayRttTracker::default(),
            peer_endpoints: HashMap::new(),
            coord_url: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// CoreState — the top-level state container
// ---------------------------------------------------------------------------

/// The top-level authoritative state for the Core daemon.
///
/// Organized into independently lockable domain containers:
/// - `net` — network-facing state (peers, ACL, rooms)
/// - `firewall` — firewall state (rules, auth, access log)
/// - `peers` — peer management (cache, liveness, handshakes)
/// - `encryption` — WireGuard sessions
/// - `scheduler` — P2P path management and routing
/// - `conn_track` — connection tracking (hot-path, std::sync)
/// - `generation` — mutation counter
pub struct CoreState {
    /// Network-facing state (peers, ACL, rooms).
    pub net: Arc<RwLock<NetState>>,
    /// Firewall — ACL rules, interactive auth, access log.
    pub firewall: tokio::sync::Mutex<Firewall>,
    /// Peer management — cache, liveness, WG handshake tracking.
    pub peers: tokio::sync::Mutex<PeerManager>,
    /// WireGuard encryption engine.
    pub encryption: tokio::sync::Mutex<EncryptionEngine>,
    /// P2P path management and routing.
    pub scheduler: tokio::sync::Mutex<P2PScheduler>,
    /// Connection tracker — hot path, guarded by a `std::sync::Mutex`.
    /// Never hold the guard across an `.await`.
    pub conn_track: std::sync::Mutex<ConnectionTracker>,
    /// Relay-selection epoch.  Bumped each time a selection starts; a
    /// selection whose epoch is no longer current must not apply its result
    /// (an older, slower selection must not overwrite a newer one).
    pub relay_epoch: std::sync::atomic::AtomicU64,
    /// Generation counter — every mutation increments this.
    pub generation: Generation,
    /// IPC event sender — pushed to all connected Controllers.
    pub ipc_event_tx: tokio::sync::mpsc::Sender<msst_ipc_protocol::IpcEvent>,
    /// The main UDP socket (shared for send and receive).
    pub udp_socket: Arc<tokio::net::UdpSocket>,
    /// Local identity (keypair, IDs, auth).  `None` until `apply_identity`.
    pub identity: RwLock<Option<crate::identity::Identity>>,
    /// Data directory (identity, rules, caches).
    pub data_dir: std::path::PathBuf,
    /// Permission groups (rule templates).
    pub acl_groups: RwLock<Vec<crate::acl::store::PermissionGroupDef>>,
    /// Serializes ACL mutations with their persistence, so the files on
    /// disk are written in the same order as the in-memory changes.
    pub acl_persist: tokio::sync::Mutex<()>,
    /// Network behaviour settings (persisted to `net_settings.json`).
    pub net_settings: RwLock<crate::net_settings::NetworkSettings>,
    /// Recent contacts (persisted to `contacts.json`).  Touched on every
    /// allowed inbound packet, hence a `std` mutex; never hold across `.await`.
    pub contacts: std::sync::Mutex<crate::contacts::ContactList>,
    /// On-demand node fetch queue (set when the fetcher starts).
    pub fetch_tx: std::sync::OnceLock<tokio::sync::mpsc::Sender<crate::nodes::FetchDemand>>,
    /// In-flight / negative-cache bookkeeping for node fetches.
    pub fetch_gate: std::sync::Mutex<crate::nodes::FetchGate>,
    /// STUN transactions awaiting a response.
    pub stun_waiters: crate::endpoints::StunWaiters,
    /// Reported endpoint sets (current + history).
    pub endpoint_history: std::sync::Mutex<crate::endpoints::EndpointHistory>,
    /// Whether an endpoint detection is in progress.
    pub endpoint_detect_running: std::sync::atomic::AtomicBool,
    /// Pending room join waiting for the next room_state / error.
    pub room_waiter: crate::rooms::RoomWaiter,
    /// Local DNS resolver (set when the TUN is up).
    pub dns: std::sync::OnceLock<Arc<crate::dns::DnsResolver>>,
    /// Outbound discovery-proxy queue (set when the TUN is up).
    pub discovery_tx: std::sync::OnceLock<tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// Per-peer traffic counters (hot path; `std` lock + atomics).
    pub traffic: crate::diagnostics::TrafficMap,
    /// Diagnostic ping jobs.
    pub ping_jobs: crate::diagnostics::PingJobs,
    /// Room members as last told to the peer cache.
    pub room_cache_members: std::sync::Mutex<HashSet<String>>,
    /// Devices referenced by active rules, as last told to the peer cache.
    pub rule_ref_devices: std::sync::Mutex<HashSet<String>>,
    /// Whether a TUN device is currently attached (`Health.tun_ready`).
    pub tun_attached: std::sync::atomic::AtomicBool,
    /// Access authentication was requested (startup check or HTTP 401) and
    /// hasn't been completed since (`Health.access_auth_required`).
    pub access_auth_required: std::sync::atomic::AtomicBool,
    /// Sender into the TUN writer (always set; packets are dropped while
    /// no TUN is attached).
    pub tun_tx: std::sync::OnceLock<tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// The coordinator client (set once the runtime starts it).
    pub coordinator: std::sync::OnceLock<Arc<crate::coordinator::CoordinatorClient>>,
}

impl CoreState {
    pub fn new(
        ipc_event_tx: tokio::sync::mpsc::Sender<msst_ipc_protocol::IpcEvent>,
        udp_socket: Arc<tokio::net::UdpSocket>,
        data_dir: std::path::PathBuf,
    ) -> Self {
        CoreState {
            net: Arc::new(RwLock::new(NetState::new())),
            firewall: tokio::sync::Mutex::new(Firewall::new()),
            peers: tokio::sync::Mutex::new(PeerManager::new()),
            encryption: tokio::sync::Mutex::new(EncryptionEngine::new()),
            scheduler: tokio::sync::Mutex::new(P2PScheduler::new(String::new())),
            conn_track: std::sync::Mutex::new(ConnectionTracker::new()),
            relay_epoch: std::sync::atomic::AtomicU64::new(0),
            generation: Generation::new(),
            ipc_event_tx,
            udp_socket,
            identity: RwLock::new(None),
            data_dir,
            acl_groups: RwLock::new(Vec::new()),
            acl_persist: tokio::sync::Mutex::new(()),
            net_settings: RwLock::new(crate::net_settings::NetworkSettings::default()),
            contacts: std::sync::Mutex::new(crate::contacts::ContactList::default()),
            coordinator: std::sync::OnceLock::new(),
            tun_tx: std::sync::OnceLock::new(),
            tun_attached: std::sync::atomic::AtomicBool::new(false),
            access_auth_required: std::sync::atomic::AtomicBool::new(false),
            traffic: std::sync::RwLock::new(HashMap::new()),
            ping_jobs: std::sync::Mutex::new(HashMap::new()),
            room_cache_members: std::sync::Mutex::new(HashSet::new()),
            rule_ref_devices: std::sync::Mutex::new(HashSet::new()),
            dns: std::sync::OnceLock::new(),
            discovery_tx: std::sync::OnceLock::new(),
            room_waiter: std::sync::Mutex::new(None),
            stun_waiters: std::sync::Mutex::new(HashMap::new()),
            endpoint_history: std::sync::Mutex::new(Default::default()),
            endpoint_detect_running: std::sync::atomic::AtomicBool::new(false),
            fetch_tx: std::sync::OnceLock::new(),
            fetch_gate: std::sync::Mutex::new(crate::nodes::FetchGate::default()),
        }
    }

    /// Install the local identity into every domain that depends on it:
    /// device/user IDs (NetState), the P2P scheduler, and the WireGuard
    /// keypair.  Must run before any network task starts.
    pub async fn apply_identity(&self, identity: &crate::identity::Identity) {
        {
            let mut net = self.net.write().await;
            net.local_device_id = identity.device.id.clone();
            net.local_user_id = identity.user.id.clone();
            net.local_authenticated = identity.auth.is_some();
        }
        *self.scheduler.lock().await = P2PScheduler::new(identity.device.id.clone());
        self.encryption.lock().await.set_local_keypair(identity.secret_key);
        *self.identity.write().await = Some(identity.clone());
        self.next_generation();
    }

    /// Push the current network settings into the P2P scheduler.
    /// (Relay keepalive and preferred relay are read where they're used.)
    pub async fn apply_net_settings(&self) {
        let s = self.net_settings.read().await.clone();
        let mut sched = self.scheduler.lock().await;
        sched.set_disable_p2p(s.disable_p2p);
        sched.set_lock_path(s.lock_path);
        sched.set_keepalive_secs(s.p2p_keepalive_secs());
    }

    /// Write `contacts.json` if it changed.
    pub fn save_contacts(&self) {
        let snapshot = self.contacts.lock().unwrap_or_else(|e| e.into_inner()).take_dirty_snapshot();
        if let Some(bytes) = snapshot {
            if let Err(e) = crate::acl::store::write_atomic(&self.data_dir, crate::contacts::FILE, &bytes) {
                tracing::warn!("contacts: failed to save: {}", e);
            }
        }
    }

    /// Advance the generation counter and return the new value.
    pub fn next_generation(&self) -> u64 {
        self.generation.advance()
    }

    /// Broadcast an IPC event to all connected Controllers.
    ///
    /// Non-blocking: if the IPC queue is full the event is dropped (and
    /// logged) rather than stalling the caller.
    pub fn emit_ipc_event(&self, event: msst_ipc_protocol::IpcEvent) {
        if let Err(e) = self.ipc_event_tx.try_send(event) {
            tracing::warn!("IPC event dropped: {}", e);
        }
    }
}