//! Core state — the authoritative state container for MSST-Net Core.
//!
//! This is the 3.1.x replacement for the 3.0.x `AppState` god-object.
//! Instead of 22 fields with 8+ lock types, state is organized into
//! domain-specific containers that can be locked independently.

use msst_core_state::encryption::EncryptionEngine;
use msst_core_state::firewall::Firewall;
use msst_core_state::packet::{ConnectionTracker, FragmentTracker};
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
    /// Password verifiers of joined rooms that have one: room_id → base64
    /// Argon2id verifier (`crate::passwords`).  Memory only; sent with
    /// every re-join, because the coordinator checks the password on each
    /// `join`.
    pub room_password_verifiers: HashMap<String, String>,
    /// The room relay of the room we are in (`crate::room_relay`).
    pub room_relay: Option<crate::room_relay::RoomRelay>,
    /// Peers whose endpoints say their room relay works (`room-relay:`).
    pub peers_on_room_relay: HashSet<String>,
    /// Local device ID (set during init).
    pub local_device_id: String,
    /// Local user ID (set during init).
    pub local_user_id: String,
    /// Whether ICMP echo-request (ping) is enabled.
    pub ping_enabled: bool,
    /// The relay server address we're registered with (numeric `IP:port`).
    pub relay_addr: Option<String>,
    /// The key `GET /relays` advertised for `relay_addr` (sdisc v1 and
    /// sreg v1).  `None`: the relay doesn't support them — no game
    /// discovery.  Always set together with `relay_addr`.
    pub relay_pub_key: Option<[u8; 32]>,
    /// Register with `relay_addr` using `0x0E` (sreg v1) instead of
    /// `0x01`/`0x02`.  Always set together with `relay_addr`.
    pub relay_sreg: bool,
    /// Peers' announced direct endpoints (P2P candidates), from room
    /// state, node fetches and node events.
    pub peer_endpoints: HashMap<String, Vec<std::net::SocketAddr>>,
    /// Relay RTT measurements (own relay + peers' relays).
    pub relay_rtt: crate::relay::RelayRttTracker,
    /// Coordinator base URL.
    pub coord_url: String,
}

impl NetState {
    /// The relay frames to a peer go through when the path isn't direct:
    /// the room relay while it works and the peer, a member of our room,
    /// reports being on it too; otherwise the peer's preferred relay.
    /// `None`: unknown (callers fall back to our relay).
    pub fn relay_for_peer(&self, device_id: &str) -> Option<&str> {
        let room_relay = self.room_relay.as_ref().and_then(|r| r.usable_addr());
        if let Some(addr) = room_relay.filter(|_| self.room_peers.contains(device_id) && self.peers_on_room_relay.contains(device_id)) {
            return Some(addr);
        }
        self.peer_list.get(device_id)?.preferred_relay.as_deref()
    }

    /// Record whether a peer's latest endpoint list includes `room-relay:`.
    pub fn set_peer_on_room_relay(&mut self, device_id: &str, on: bool) {
        if on {
            self.peers_on_room_relay.insert(device_id.to_string());
        } else {
            self.peers_on_room_relay.remove(device_id);
        }
    }

    pub fn new() -> Self {
        NetState {
            peer_list: PeerList::new(),
            acl_rules: Vec::new(),
            acl_labels: HashMap::new(),
            local_authenticated: false,
            room_peers: HashSet::new(),
            joined_rooms: HashMap::new(),
            room_password_verifiers: HashMap::new(),
            room_relay: None,
            peers_on_room_relay: HashSet::new(),
            local_device_id: String::new(),
            local_user_id: String::new(),
            ping_enabled: false,
            relay_addr: None,
            relay_pub_key: None,
            relay_sreg: false,
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
/// - `peers` — peer management (cache, liveness)
/// - `encryption` — WireGuard sessions
/// - `scheduler` — P2P path management and routing
/// - `conn_track` — connection tracking (hot-path, std::sync)
/// - `frag_track` — verdicts of fragmented datagrams (hot-path, std::sync)
/// - `generation` — mutation counter
pub struct CoreState {
    /// Network-facing state (peers, ACL, rooms).
    pub net: Arc<RwLock<NetState>>,
    /// Firewall — ACL rules, interactive auth, access log.
    pub firewall: tokio::sync::Mutex<Firewall>,
    /// Peer management — cache and liveness.
    pub peers: tokio::sync::Mutex<PeerManager>,
    /// WireGuard encryption engine.
    pub encryption: tokio::sync::Mutex<EncryptionEngine>,
    /// P2P path management and routing.
    pub scheduler: tokio::sync::Mutex<P2PScheduler>,
    /// Connection tracker — hot path, guarded by a `std::sync::Mutex`.
    /// Never hold the guard across an `.await`.
    pub conn_track: std::sync::Mutex<ConnectionTracker>,
    /// Inbound fragment verdicts (`crate::inbound`) — hot path, guarded by
    /// a `std::sync::Mutex`.  Never hold the guard across an `.await`.
    pub frag_track: std::sync::Mutex<FragmentTracker<crate::inbound::FragVerdict>>,
    /// Host routing problems found by the last route check
    /// (`crate::routing`), sorted.  Shown in `GetSystemState`.
    pub network_warnings: std::sync::Mutex<Vec<crate::routing::NetworkWarning>>,
    /// Relay-selection epoch.  Bumped each time a selection starts; a
    /// selection whose epoch is no longer current must not apply its result
    /// (an older, slower selection must not overwrite a newer one).
    pub relay_epoch: std::sync::atomic::AtomicU64,
    /// Generation counter — every mutation increments this.
    pub generation: Generation,
    /// The IPC event stream — pushed to all connected Controllers.
    pub events: EventBus,
    /// Background operations (`async` commands).
    pub operations: crate::ipc::ops::Operations,
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
    /// Another detection was requested while one was running.
    pub endpoint_detect_again: std::sync::atomic::AtomicBool,
    /// Pending room join waiting for the next room_state / error.
    pub room_waiter: crate::rooms::RoomWaiter,
    /// Serializes create / join / leave (one room at a time, one waiter).
    pub room_op: tokio::sync::Mutex<()>,
    /// Local DNS resolver (set when the TUN is up).
    pub dns: std::sync::OnceLock<Arc<crate::dns::DnsResolver>>,
    /// Prometheus metrics, when enabled (`--metrics`).
    pub metrics: std::sync::OnceLock<Arc<crate::observability::metrics::CoreMetrics>>,
    /// Outbound discovery-proxy queue (set when the TUN is up).
    pub discovery_tx: std::sync::OnceLock<tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// Secure-discovery (sdisc v1) counters.
    pub sdisc_stats: crate::discovery::SdiscStats,
    /// Registration with the current relay (sreg v1 key, counter, schedule).
    pub relay_reg: std::sync::Mutex<crate::sreg::Registration>,
    /// Registration with the room relay (sreg v1; see `crate::room_relay`).
    pub room_relay_reg: std::sync::Mutex<crate::sreg::Registration>,
    /// Unix time a P2P pong last came back through our own relay — proof
    /// that the relay's binding for us works (it only forwards `0x06` from
    /// the bound address).  0 = never.
    pub relay_path_ok_at: std::sync::atomic::AtomicI64,
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
            frag_track: std::sync::Mutex::new(FragmentTracker::new()),
            network_warnings: std::sync::Mutex::new(Vec::new()),
            relay_epoch: std::sync::atomic::AtomicU64::new(0),
            generation: Generation::new(),
            events: EventBus::new(),
            operations: Default::default(),
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
            metrics: std::sync::OnceLock::new(),
            discovery_tx: std::sync::OnceLock::new(),
            sdisc_stats: Default::default(),
            relay_reg: Default::default(),
            room_relay_reg: Default::default(),
            relay_path_ok_at: std::sync::atomic::AtomicI64::new(0),
            room_waiter: std::sync::Mutex::new(None),
            room_op: tokio::sync::Mutex::new(()),
            stun_waiters: std::sync::Mutex::new(HashMap::new()),
            endpoint_history: std::sync::Mutex::new(Default::default()),
            endpoint_detect_running: std::sync::atomic::AtomicBool::new(false),
            endpoint_detect_again: std::sync::atomic::AtomicBool::new(false),
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
        drop(sched);
        crate::routing::set_bypass(self, s.bypass_other_vpns);
    }

    /// Emit `EncryptionChanged` for data-plane encryption state changes.
    pub fn emit_encryption_changes(&self, changes: Vec<msst_core_state::encryption::EncChange>) {
        if changes.is_empty() {
            return;
        }
        self.next_generation();
        for c in changes {
            self.emit_ipc_event(msst_ipc_protocol::IpcEvent::EncryptionChanged {
                device_id: c.device_id,
                old_state: c.old.name().to_string(),
                new_state: c.new.name().to_string(),
            });
        }
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

    /// Broadcast an IPC event to all connected Controllers (see
    /// [`EventBus::emit`]).  Never blocks.
    pub fn emit_ipc_event(&self, event: msst_ipc_protocol::IpcEvent) {
        self.events.emit(event);
    }

    /// Subscribe to the event stream (tests).
    #[cfg(test)]
    pub fn subscribe_events(&self) -> EventReceiver {
        EventReceiver(self.events.subscribe())
    }
}

// ---------------------------------------------------------------------------
// EventBus — Core's single, sequenced event stream
// ---------------------------------------------------------------------------

/// Events buffered per subscriber before it counts as lagging.
const EVENT_BUS_CAPACITY: usize = 1024;

/// An event with its position in the stream.
#[derive(Debug, Clone)]
pub struct SeqEvent {
    pub seq: u64,
    pub event: msst_ipc_protocol::IpcEvent,
}

/// The event stream every IPC connection subscribes to (protocol 0.4).
///
/// `seq` starts at 1 and increases by exactly 1 per event; numbering and
/// sending happen under one lock, so every subscriber receives events in
/// `seq` order.  Emitting never blocks and never drops silently: a
/// subscriber that falls more than [`EVENT_BUS_CAPACITY`] behind gets
/// `Lagged` (the IPC server then disconnects it so it re-snapshots).
pub struct EventBus {
    tx: tokio::sync::broadcast::Sender<SeqEvent>,
    seq: std::sync::Mutex<u64>,
}

impl EventBus {
    pub fn new() -> Self {
        EventBus { tx: tokio::sync::broadcast::channel(EVENT_BUS_CAPACITY).0, seq: std::sync::Mutex::new(0) }
    }

    /// Number and broadcast an event.  Returns its `seq`.
    pub fn emit(&self, event: msst_ipc_protocol::IpcEvent) -> u64 {
        let mut seq = self.seq.lock().unwrap_or_else(|e| e.into_inner());
        *seq += 1;
        // Err = no subscribers (no Controller connected): nothing to do.
        let _ = self.tx.send(SeqEvent { seq: *seq, event });
        *seq
    }

    /// `seq` of the last event emitted (0 if none yet).
    pub fn last_seq(&self) -> u64 {
        *self.seq.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Receive every event emitted from now on.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<SeqEvent> {
        self.tx.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// A test-side subscription yielding bare events.
#[cfg(test)]
pub struct EventReceiver(tokio::sync::broadcast::Receiver<SeqEvent>);

#[cfg(test)]
impl EventReceiver {
    pub fn try_recv(&mut self) -> Result<msst_ipc_protocol::IpcEvent, tokio::sync::broadcast::error::TryRecvError> {
        self.0.try_recv().map(|e| e.event)
    }
}

#[cfg(test)]
mod event_bus_tests {
    use super::*;
    use msst_ipc_protocol::IpcEvent;

    #[test]
    fn seq_is_contiguous_and_ordered() {
        let bus = EventBus::new();
        assert_eq!(bus.emit(IpcEvent::NodeRemoved { device_id: "x".into() }), 1, "no subscriber: still numbered");
        let mut rx = bus.subscribe();
        for _ in 0..3 {
            bus.emit(IpcEvent::CoordinatorConnectionChanged { connected: true });
        }
        assert_eq!(bus.last_seq(), 4);
        let got: Vec<u64> = (0..3).map(|_| rx.try_recv().unwrap().seq).collect();
        assert_eq!(got, [2, 3, 4]);
    }

    #[test]
    fn lagging_subscriber_is_told() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        for _ in 0..EVENT_BUS_CAPACITY + 1 {
            bus.emit(IpcEvent::CoordinatorConnectionChanged { connected: true });
        }
        assert!(matches!(rx.try_recv(), Err(tokio::sync::broadcast::error::TryRecvError::Lagged(1))));
    }
}
