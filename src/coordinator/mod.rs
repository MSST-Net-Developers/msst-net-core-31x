//! Coordinator client — WebSocket connection to the MSST-Net Coordinator.
//!
//! This module implements the client side of the Coordinator protocol:
//! - WebSocket connection with bounded exponential backoff
//! - Device registration on every (re)connect
//! - Re-joining rooms (`join` + `discovery_join`) after a reconnect
//! - Node heartbeat, room keepalive and WS ping, bound to the connection
//! - Bearer-token auth: OIDC (refreshed on HTTP 401), else a guest token
//!   (see `credentials`)
//! - Incoming message parsing (room_state, node events, punch requests)
//!
//! ## Protocol contract
//!
//! Outgoing message shapes are identical to 3.0.x `coordinator.rs`.
//! See `messages.rs` for the incoming JSON shapes.
//!
//! ## Lifecycle
//!
//! ```text
//! run(state) loop:
//!     connect (Authorization: Bearer <OIDC token>)
//!       ├── 401 → refresh token → retry once → else AccessAuthRequired
//!       │         and connect as a guest (Bearer <guest token>)
//!       └── ok  → new per-connection channel
//!                 ├── send register
//!                 ├── re-join rooms in NetState::joined_rooms
//!                 ├── writer task: outgoing queue + ping/heartbeat/keepalive
//!                 └── reader: parse → CoordinatorEvent → runtime
//!     disconnect → drop channel (send() now fails fast) → backoff → retry
//! ```

pub mod credentials;
pub mod keyproof;
pub mod messages;

use crate::identity::{self, Identity};
use crate::state::CoreState;
use futures_util::{SinkExt, StreamExt};
use credentials::{Credential, GuestToken, Refresh};
use messages::*;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify, RwLock};
use tokio::time::MissedTickBehavior;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

/// WS-level ping to keep NAT/proxy state alive.
const WS_PING_INTERVAL: Duration = Duration::from_secs(30);
/// `node_heartbeat` must be sent before the server's 90-second timeout.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
/// `room_keepalive` interval (coordinator room TTL is 2 minutes).
const ROOM_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
/// Reconnect backoff bounds.
const BACKOFF_MIN_SECS: u64 = 1;
const BACKOFF_MAX_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the Coordinator client.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Coordinator HTTP(S) base URL (e.g. "https://coord.msst-net.msst2031.cn").
    pub coord_url: String,
}

// ---------------------------------------------------------------------------
// CoordinatorClient
// ---------------------------------------------------------------------------

/// The Coordinator WebSocket client.
///
/// Holds at most one live connection.  Each connection gets its own outgoing
/// channel; when the connection drops the channel is discarded, so
/// [`CoordinatorClient::send`] fails fast with [`NotConnected`] instead of
/// queueing into a dead connection.
pub struct CoordinatorClient {
    config: CoordinatorConfig,
    http: reqwest::Client,
    /// Outgoing sender of the *current* connection (`None` while disconnected).
    conn_tx: RwLock<Option<mpsc::Sender<String>>>,
    /// Channel for incoming parsed events (consumed by the Core runtime).
    event_tx: mpsc::Sender<CoordinatorEvent>,
    /// Current connection state.
    state: RwLock<ConnectionState>,
    /// The Coordinator refused the stored OIDC credentials and the refresh
    /// token too: connect as a guest until a refresh or a new login.
    oidc_rejected: AtomicBool,
    /// The guest token in use (memory only).
    guest: std::sync::Mutex<Option<GuestToken>>,
    /// The credential of the current connection (`None`: disconnected, or
    /// connected without one).  Also used for the HTTP API.
    credential: std::sync::RwLock<Option<Credential>>,
    /// Drops the current connection so the next one uses new credentials.
    reconnect: Notify,
}

/// The current state of the Coordinator connection.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    /// WS is open and the `register` message has been queued.
    Connected,
    /// The coordinator rejected our credentials and refresh did not help.
    AuthRequired,
}

/// Returned by [`CoordinatorClient::send`] while no connection is live.
#[derive(Debug, Clone, PartialEq)]
pub struct NotConnected;

impl std::fmt::Display for NotConnected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("coordinator WebSocket not connected")
    }
}

impl std::error::Error for NotConnected {}

/// Events received from the Coordinator.
#[derive(Debug, Clone)]
pub enum CoordinatorEvent {
    /// A WS connection was established and `register` was sent.  Emitted on
    /// every (re)connect; the runtime (re)selects and registers a relay.
    Connected,
    /// Registration confirmed — server assigned hostname/IPv4/IPv6.
    Registered {
        hostname: String,
        ipv4: String,
        ipv6: String,
        user_handle: String,
        user_display_name: String,
    },
    /// Room state update (full peer list for a room).
    RoomState {
        room_id: String,
        room_name: String,
        peers: Vec<RoomStatePeer>,
    },
    /// A member joined our room (with the same peer data as `room_state`).
    MemberJoined {
        room_id: String,
        peer: RoomStatePeer,
    },
    /// A member left our room.
    MemberLeft {
        room_id: String,
        device_id: String,
    },
    /// A new node appeared on the network (authenticated devices only).
    NodeAdded {
        device_id: String,
        endpoints: Vec<String>,
        last_seen: i64,
        status: String,
    },
    /// A node's state changed.
    NodeUpdated {
        device_id: String,
        endpoints: Vec<String>,
        last_seen: i64,
        status: String,
    },
    /// NAT traversal punch request.
    PunchRequest {
        peer_id: String,
        endpoints: Vec<String>,
    },
    /// Coordinator sent an error.
    Error {
        message: String,
        /// Machine-readable code, when the Coordinator sends one.
        code: Option<String>,
    },
}

type WsStream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Outcome of a single connection attempt.
enum ConnectOutcome {
    /// Connected, ran until the connection dropped.
    Disconnected,
    /// Could not connect (network / TLS / HTTP error other than 401).
    Failed,
    /// HTTP 401 that token refresh could not fix.
    AuthRequired,
    /// The Coordinator rejected our registration.  Unlike `Disconnected`,
    /// the backoff keeps growing: reconnecting at once would fail the same way.
    RegisterRejected,
    /// The device ID is pinned to another key (`device_key_mismatch`).
    KeyMismatch,
}

impl CoordinatorClient {
    /// Create a new Coordinator client.
    pub fn new(config: CoordinatorConfig, event_tx: mpsc::Sender<CoordinatorEvent>) -> Self {
        CoordinatorClient {
            config,
            http: crate::netsock::http_client(),
            conn_tx: RwLock::new(None),
            event_tx,
            state: RwLock::new(ConnectionState::Disconnected),
            oidc_rejected: AtomicBool::new(false),
            guest: std::sync::Mutex::new(None),
            credential: std::sync::RwLock::new(None),
            reconnect: Notify::new(),
        }
    }

    // ── Credentials ────────────────────────────────────────────────────────

    /// Bearer token for HTTP API calls: the current connection's credential.
    pub fn bearer(&self) -> Option<String> {
        self.credential.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|c| c.token().to_string())
    }

    /// `Health.coordinator_credential`: `oidc`, `guest` or `none`.
    pub fn credential_kind(&self) -> &'static str {
        self.credential.read().unwrap_or_else(|e| e.into_inner()).as_ref().map_or("none", Credential::kind)
    }

    /// Whether the Coordinator refused the stored OIDC credentials.
    pub fn oidc_rejected(&self) -> bool {
        self.oidc_rejected.load(Ordering::SeqCst)
    }

    /// New or refreshed OIDC credentials: use them again, and if the current
    /// connection doesn't, reconnect so the Coordinator sees them.
    pub async fn credentials_changed(&self, core: &Arc<CoreState>) {
        self.oidc_rejected.store(false, Ordering::SeqCst);
        core.net.write().await.local_authenticated = core.identity.read().await.as_ref().is_some_and(|i| i.auth.is_some());
        if !matches!(*self.credential.read().unwrap_or_else(|e| e.into_inner()), Some(Credential::Oidc(_))) {
            info!("coordinator: reconnecting with the new credentials");
            self.reconnect.notify_waiters();
        }
    }

    /// The guest token to connect with: the cached one unless `renew`, else
    /// a new one from `POST /auth/guest/token`.  `Ok(None)`: the Coordinator
    /// doesn't issue guest tokens (connect without a credential).
    async fn guest_token(&self, renew: bool) -> Result<Option<GuestToken>, String> {
        let now = unix_now();
        if !renew {
            if let Some(g) = self.guest.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|g| g.usable(now)) {
                return Ok(Some(g.clone()));
            }
        }
        let (status, body) = self.api_request(reqwest::Method::POST, "/auth/guest/token", None, None).await?;
        if status == 404 || status == 405 {
            info!("coordinator: no guest tokens on this coordinator — connecting without credentials");
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(format!("POST /auth/guest/token returned {}", status));
        }
        let g = GuestToken::from_response(&body).ok_or("POST /auth/guest/token returned no token")?;
        info!("coordinator: guest token issued ({}, expires_at={})", g.user_id, g.expires_at);
        *self.guest.lock().unwrap_or_else(|e| e.into_inner()) = Some(g.clone());
        Ok(Some(g))
    }

    /// Open the WS with the best credential (see `credentials`).
    async fn open_authenticated(&self, core: &Arc<CoreState>, ws_url: &str) -> Result<(WsStream, Option<Credential>), ConnectOutcome> {
        // 1. OIDC, unless the Coordinator already refused it.
        let oidc = || async { core.identity.read().await.as_ref().and_then(access_token) };
        if !self.oidc_rejected() {
            if let Some(token) = oidc().await {
                match self.open_ws(ws_url, Some(&token)).await {
                    Ok(s) => return Ok((s, Some(Credential::Oidc(token)))),
                    Err(e) if !is_auth_required_error(&e) => return Err(self.failed(core, e).await),
                    Err(_) => {}
                }
                info!("coordinator: HTTP 401 — attempting token refresh before re-auth prompt");
                match self.refresh_token(core).await {
                    Refresh::Refreshed => {
                        let token = oidc().await.unwrap_or_default();
                        match self.open_ws(ws_url, Some(&token)).await {
                            Ok(s) => return Ok((s, Some(Credential::Oidc(token)))),
                            Err(e) if !is_auth_required_error(&e) => return Err(self.failed(core, e).await),
                            Err(_) => {}
                        }
                    }
                    // Can't tell whether the credentials are dead: retry later.
                    Refresh::Unavailable => {
                        self.set_state(core, ConnectionState::Disconnected).await;
                        return Err(ConnectOutcome::Failed);
                    }
                    Refresh::Rejected => {}
                }
                warn!("coordinator: MSST access authentication required (token refresh did not resolve 401) — continuing as a guest (room mode only)");
                self.oidc_rejected.store(true, Ordering::SeqCst);
                core.net.write().await.local_authenticated = false;
                self.report_auth_required(core);
            }
        }

        // 2. Guest token; a 401 means the Coordinator forgot it (restart).
        for renew in [false, true] {
            let guest = match self.guest_token(renew).await {
                Ok(g) => g,
                Err(e) => {
                    warn!("coordinator: cannot get a guest token: {}", e);
                    self.set_state(core, ConnectionState::Disconnected).await;
                    return Err(ConnectOutcome::Failed);
                }
            };
            let token = guest.map(|g| g.token);
            match self.open_ws(ws_url, token.as_deref()).await {
                Ok(s) => return Ok((s, token.map(Credential::Guest))),
                Err(e) if !is_auth_required_error(&e) => return Err(self.failed(core, e).await),
                Err(_) if token.is_some() && !renew => info!("coordinator: guest token rejected — requesting a new one"),
                Err(_) => break,
            }
        }
        warn!("coordinator: guest access refused (HTTP 401)");
        self.set_state(core, ConnectionState::AuthRequired).await;
        Err(ConnectOutcome::AuthRequired)
    }

    async fn failed(&self, core: &Arc<CoreState>, e: tokio_tungstenite::tungstenite::Error) -> ConnectOutcome {
        warn!("coordinator: connection failed: {}", e);
        self.set_state(core, ConnectionState::Disconnected).await;
        ConnectOutcome::Failed
    }

    // ── Connection loop ────────────────────────────────────────────────────

    /// Connect to the Coordinator and keep the connection alive.
    ///
    /// Runs indefinitely; reconnects with exponential backoff
    /// (1 s → 30 s, reset after a successful connection).  Spawn as a
    /// background task.
    pub async fn run(&self, core: Arc<CoreState>) {
        self.startup_auth_check(&core).await;

        let mut backoff = BACKOFF_MIN_SECS;
        let mut auth_required_reported = false;
        let mut key_mismatch_reported = false;
        loop {
            match self.connect_once(&core).await {
                ConnectOutcome::Disconnected => {
                    backoff = BACKOFF_MIN_SECS;
                    auth_required_reported = false;
                    key_mismatch_reported = false;
                }
                ConnectOutcome::Failed | ConnectOutcome::RegisterRejected => {}
                ConnectOutcome::KeyMismatch => {
                    // Surface once per streak; retries stay at the backoff
                    // ceiling (an administrator may unpin the ID).
                    if !key_mismatch_reported {
                        let id = core.net.read().await.local_device_id.clone();
                        error!("{}", keyproof::mismatch_message(&id));
                        key_mismatch_reported = true;
                    }
                    backoff = BACKOFF_MAX_SECS;
                }
                ConnectOutcome::AuthRequired => {
                    // Report once per streak so a missing login doesn't spam
                    // the Controller every backoff cycle.
                    if !auth_required_reported {
                        self.report_auth_required(&core);
                        auth_required_reported = true;
                    }
                }
            }
            info!("coordinator: reconnecting in {}s…", backoff);
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = next_backoff(backoff);
        }
    }

    /// At startup, try to silently refresh an expired access token; if the
    /// device is not authenticated afterwards, tell the Controller (3.0.x
    /// `init()` behaviour).
    async fn startup_auth_check(&self, core: &Arc<CoreState>) {
        let now = unix_now();
        let (authenticated, has_refresh) = {
            let id = core.identity.read().await;
            let auth = id.as_ref().and_then(|i| i.auth.as_ref());
            (
                auth.is_some_and(|a| !a.access_token.is_empty() && a.expires_at > now),
                auth.is_some_and(|a| !a.refresh_token.is_empty()),
            )
        };
        if authenticated {
            return;
        }
        let refreshed = if has_refresh {
            info!("access token expired — attempting silent token refresh at startup");
            self.try_refresh_token(core).await
        } else {
            false
        };
        if !refreshed {
            info!("MSST接入认证未完成或凭据已过期，请通过MSST联合认证平台完成接入认证");
            self.report_auth_required(core);
        }
    }

    fn report_auth_required(&self, core: &Arc<CoreState>) {
        core.access_auth_required.store(true, std::sync::atomic::Ordering::SeqCst);
        core.emit_ipc_event(msst_ipc_protocol::IpcEvent::AccessAuthRequired {
            coordinator_url: self.config.coord_url.clone(),
        });
    }

    async fn set_state(&self, core: &Arc<CoreState>, new: ConnectionState) {
        let mut st = self.state.write().await;
        let was_connected = *st == ConnectionState::Connected;
        let now_connected = new == ConnectionState::Connected;
        *st = new;
        drop(st);
        if was_connected != now_connected {
            core.emit_ipc_event(msst_ipc_protocol::IpcEvent::CoordinatorConnectionChanged {
                connected: now_connected,
            });
        }
    }

    async fn connect_once(&self, core: &Arc<CoreState>) -> ConnectOutcome {
        let ws_url = self.ws_url();
        let Some(identity) = core.identity.read().await.clone() else {
            warn!("coordinator: identity not loaded yet");
            return ConnectOutcome::Failed;
        };

        info!("coordinator: connecting to {}", ws_url);
        self.set_state(core, ConnectionState::Connecting).await;

        let (ws_stream, credential) = match self.open_authenticated(core, &ws_url).await {
            Ok(v) => v,
            Err(outcome) => return outcome,
        };
        info!("coordinator: WebSocket connected ({})", credential.as_ref().map_or("no credential", Credential::kind));
        *self.credential.write().unwrap_or_else(|e| e.into_inner()) = credential;

        // Key proof (keyproof v1): one fresh challenge per registration,
        // requested after the WS is open so it can't expire in between.
        let mut register = build_register_message(&identity);
        match keyproof::obtain(self, &identity).await {
            Ok(proof) => keyproof::attach(&mut register["data"], proof),
            Err(keyproof::ProofError::KeyMismatch) => {
                self.set_state(core, ConnectionState::Disconnected).await;
                return ConnectOutcome::KeyMismatch;
            }
            Err(keyproof::ProofError::Other(e)) => {
                warn!("coordinator: no key proof ({}) — registering without one", e);
            }
        }

        // Fresh outgoing channel for this connection.  `register` goes first
        // so the coordinator knows who we are before any other message.
        let (tx, rx) = mpsc::channel::<String>(64);
        let _ = tx.send(register.to_string()).await;
        let rooms: Vec<(String, Option<String>)> = {
            let net = core.net.read().await;
            net.joined_rooms.keys().map(|id| (id.clone(), net.room_password_verifiers.get(id).cloned())).collect()
        };
        for (room_id, pw) in &rooms {
            // The coordinator checks the password on every join, and ties
            // discovery-proxy registration to the WS connection, so
            // `discovery_join` must be resent with `join`.
            let _ = tx.send(join_message(room_id, pw.as_deref()).to_string()).await;
            let _ = tx.send(discovery_join_message(room_id).to_string()).await;
            info!("coordinator: re-joining room {} after (re)connect", room_id);
        }
        *self.conn_tx.write().await = Some(tx);
        self.set_state(core, ConnectionState::Connected).await;
        info!("coordinator: registered (device={}, user={})", identity.device.id, identity.user.id);
        let _ = self.event_tx.send(CoordinatorEvent::Connected).await;

        let (ws_writer, mut ws_reader) = ws_stream.split();
        let writer_task = tokio::spawn(writer_loop(ws_writer, rx, core.clone()));

        let mut outcome = ConnectOutcome::Disconnected;
        loop {
            let msg = tokio::select! {
                m = ws_reader.next() => match m {
                    Some(m) => m,
                    None => break,
                },
                _ = self.reconnect.notified() => break,
            };
            match msg {
                Ok(Message::Text(text)) => match self.parse_incoming(&text) {
                    Ok(Some(CoordinatorEvent::Error { code: Some(code), .. }))
                        if [keyproof::CODE_KEY_MISMATCH, keyproof::CODE_PROOF_INVALID, keyproof::CODE_PROOF_REQUIRED]
                            .contains(&code.as_str()) =>
                    {
                        // Registration refused; the connection is useless.
                        // A proof error is retried with a fresh challenge.
                        warn!("coordinator: registration rejected ({}), reconnecting with backoff", code);
                        outcome = if code == keyproof::CODE_KEY_MISMATCH {
                            ConnectOutcome::KeyMismatch
                        } else {
                            ConnectOutcome::RegisterRejected
                        };
                        break;
                    }
                    Ok(Some(event)) => {
                        if self.event_tx.send(event).await.is_err() {
                            warn!("coordinator: event receiver dropped");
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => warn!("coordinator: {}", e),
                },
                Ok(Message::Close(_)) => {
                    info!("coordinator: server closed connection");
                    break;
                }
                Ok(_) => {} // Ping/Pong handled by tungstenite; Binary ignored.
                Err(e) => {
                    warn!("coordinator: WS read error: {}", e);
                    break;
                }
            }
            if writer_task.is_finished() {
                warn!("coordinator: writer exited, dropping connection");
                break;
            }
        }

        *self.conn_tx.write().await = None;
        *self.credential.write().unwrap_or_else(|e| e.into_inner()) = None;
        writer_task.abort();
        self.set_state(core, ConnectionState::Disconnected).await;
        outcome
    }

    async fn open_ws(&self, ws_url: &str, token: Option<&str>) -> Result<WsStream, tokio_tungstenite::tungstenite::Error> {
        // Connect the TCP stream ourselves so it can be protected from the
        // device's VPN (embedded Core), then do TLS + the WS handshake on it.
        let req = build_ws_request(ws_url, token)?;
        let uri = req.uri().clone();
        let host = uri.host().unwrap_or_default().trim_matches(|c| c == '[' || c == ']').to_string();
        let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("wss") { 443 } else { 80 });
        let tcp = crate::netsock::connect_host(&host, port).await.map_err(tokio_tungstenite::tungstenite::Error::Io)?;
        tokio_tungstenite::client_async_tls(req, tcp).await.map(|(s, _)| s)
    }

    /// Refresh the OIDC access token with the stored refresh token.
    ///
    /// On success the identity is updated and persisted.  Returns `true` if a
    /// fresh access token is now available.
    pub async fn try_refresh_token(&self, core: &Arc<CoreState>) -> bool {
        self.refresh_token(core).await == Refresh::Refreshed
    }

    /// [`try_refresh_token`](Self::try_refresh_token), telling apart a
    /// refresh the IdP refused from one that could not be attempted.
    async fn refresh_token(&self, core: &Arc<CoreState>) -> Refresh {
        let refresh_token = core
            .identity
            .read()
            .await
            .as_ref()
            .and_then(|i| i.auth.as_ref())
            .map(|a| a.refresh_token.clone())
            .filter(|t| !t.is_empty());
        let Some(refresh_token) = refresh_token else {
            debug!("try_refresh_token: no refresh token available");
            return Refresh::Rejected;
        };

        let url = format!("{}/auth/token/refresh", self.config.coord_url.trim_end_matches('/'));
        let resp = match self
            .http
            .post(&url)
            .json(&json!({ "refresh_token": refresh_token }))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("token refresh request failed: {}", e);
                return Refresh::Unavailable;
            }
        };
        if !resp.status().is_success() {
            warn!("token refresh failed (HTTP {})", resp.status());
            return if resp.status().is_client_error() { Refresh::Rejected } else { Refresh::Unavailable };
        }
        let body: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!("token refresh response decode error: {}", e);
                return Refresh::Unavailable;
            }
        };

        let mut guard = core.identity.write().await;
        let Some(id) = guard.as_mut() else { return Refresh::Unavailable };
        if !apply_token_refresh(id, &body) {
            warn!("token refresh response contained no access_token");
            return Refresh::Unavailable;
        }
        if let Err(e) = identity::save(&core.data_dir, id) {
            warn!("failed to persist refreshed token: {}", e);
        }
        core.access_auth_required.store(false, std::sync::atomic::Ordering::SeqCst);
        info!(
            "OIDC token refreshed; expires_at={}",
            id.auth.as_ref().map(|a| a.expires_at).unwrap_or(0)
        );
        drop(guard);
        self.credentials_changed(core).await;
        Refresh::Refreshed
    }

    // ── Outgoing messages ──────────────────────────────────────────────────

    /// Send a raw message on the current connection.
    pub async fn send(&self, msg: &str) -> Result<(), NotConnected> {
        let tx = self.conn_tx.read().await.clone().ok_or(NotConnected)?;
        tx.send(msg.to_string()).await.map_err(|_| NotConnected)
    }

    /// Send a join room message.
    pub async fn send_join(&self, room_id: &str, password_verifier: Option<&str>) -> Result<(), NotConnected> {
        self.send(&join_message(room_id, password_verifier).to_string()).await
    }

    /// Send a leave room message.
    pub async fn send_leave(&self, room_id: &str) -> Result<(), NotConnected> {
        let msg = json!({ "type": "leave", "data": { "room_id": room_id } });
        self.send(&msg.to_string()).await
    }

    /// Send a discovery join.
    pub async fn send_discovery_join(&self, room_id: &str) -> Result<(), NotConnected> {
        self.send(&discovery_join_message(room_id).to_string()).await
    }

    /// Send a discovery leave.
    pub async fn send_discovery_leave(&self, room_id: &str) -> Result<(), NotConnected> {
        let msg = json!({ "type": "discovery_leave", "data": { "room_id": room_id } });
        self.send(&msg.to_string()).await
    }

    /// `GET <coord_url><path>` returning JSON; `Ok(None)` on 404.
    pub async fn api_get(&self, path: &str, bearer: Option<&str>) -> Result<Option<Value>, String> {
        let url = format!("{}{}", self.config.coord_url.trim_end_matches('/'), path);
        let mut req = self.http.get(&url).timeout(Duration::from_secs(10));
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(format!("GET {} → HTTP {}", path, resp.status()));
        }
        resp.json().await.map(Some).map_err(|e| e.to_string())
    }

    /// `POST <coord_url><path>` with a JSON body; errors on non-2xx.
    pub async fn api_post(&self, path: &str, body: &Value) -> Result<(), String> {
        let url = format!("{}{}", self.config.coord_url.trim_end_matches('/'), path);
        let mut req = self.http.post(&url).json(body).timeout(Duration::from_secs(10));
        if let Some(t) = self.bearer() {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("POST {} → HTTP {}: {}", path, status, text));
        }
        Ok(())
    }

    /// Generic coordinator REST call.  Returns the HTTP status and the JSON
    /// body (`Null` when the body is empty or not JSON).  Only transport
    /// failures are `Err`; the caller interprets the status.
    pub async fn api_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        bearer: Option<&str>,
    ) -> Result<(u16, Value), String> {
        let url = format!("{}{}", self.config.coord_url.trim_end_matches('/'), path);
        let mut req = self.http.request(method, &url).timeout(Duration::from_secs(15));
        if let Some(b) = body {
            req = req.json(b);
        }
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    /// HTTP client for coordinator REST calls.
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// Coordinator HTTP(S) base URL.
    pub fn coord_url(&self) -> &str {
        &self.config.coord_url
    }

    /// Get the current connection state.
    pub async fn connection_state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }
}

// ---------------------------------------------------------------------------
// Writer task (outgoing queue + periodic messages)
// ---------------------------------------------------------------------------

/// Drains the connection's outgoing queue and emits the periodic WS ping,
/// `node_heartbeat` and `room_keepalive`.  Exits on the first write error;
/// the reader loop notices and tears the connection down.
async fn writer_loop<S>(mut ws: S, mut rx: mpsc::Receiver<String>, core: Arc<CoreState>)
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    let mut ping = tokio::time::interval(WS_PING_INTERVAL);
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    let mut keepalive = tokio::time::interval(ROOM_KEEPALIVE_INTERVAL);
    for t in [&mut ping, &mut heartbeat, &mut keepalive] {
        t.set_missed_tick_behavior(MissedTickBehavior::Skip);
        t.reset(); // first tick after one full interval, not immediately
    }

    loop {
        let outgoing: Vec<Message> = tokio::select! {
            msg = rx.recv() => match msg {
                Some(m) => vec![Message::Text(m.into())],
                None => break,
            },
            _ = ping.tick() => vec![Message::Ping(Vec::new().into())],
            _ = heartbeat.tick() => vec![Message::Text(heartbeat_message().to_string().into())],
            _ = keepalive.tick() => {
                let rooms: Vec<String> = core.net.read().await.joined_rooms.keys().cloned().collect();
                rooms.iter().map(|r| Message::Text(room_keepalive_message(r).to_string().into())).collect()
            }
        };
        for m in outgoing {
            if let Err(e) = ws.send(m).await {
                error!("coordinator: WS write error: {}", e);
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (message builders, identity reconciliation)
// ---------------------------------------------------------------------------

/// Builds the client-side ezPlay hostname proposal (3.0.x `ip::build_hostname`).
///
/// Format: `<device_label>.<user_label>.ezplay.msst.net`; an empty (or
/// invalid) handle falls back to the full ID.  The server may return a
/// different (conflict-resolved) hostname in `registered`.
pub fn build_hostname(device_handle: &str, device_id: &str, user_handle: &str, user_id: &str) -> String {
    format!("{}.{}.ezplay.msst.net", handle_or_id(device_handle, device_id), handle_or_id(user_handle, user_id))
}

/// The handle to register: unset (or invalid) handles are replaced by the
/// ID, as the coordinator does.
fn handle_or_id<'a>(handle: &'a str, id: &'a str) -> &'a str {
    if crate::account::validate_handle(handle).is_ok() { handle } else { id }
}

/// The `register` message — the 3.0.x shape.  Unset handles are sent as
/// the IDs and an unset device display name as
/// [`default_device_display_name`](crate::identity::default_device_display_name).
pub fn build_register_message(id: &Identity) -> Value {
    let (ipv4, ipv6) = id.virtual_ips();
    let device_handle = handle_or_id(&id.device.handle, &id.device.id);
    let user_handle = handle_or_id(&id.user.handle, &id.user.id);
    let hostname = build_hostname(&id.device.handle, &id.device.id, &id.user.handle, &id.user.id);
    let device_display_name = if id.device.display_name.is_empty() {
        crate::identity::default_device_display_name(&id.user.id)
    } else {
        id.device.display_name.clone()
    };

    json!({
        "type": "register",
        "data": {
            "device": {
                "id": id.device.id,
                "handle": device_handle,
                "pub_key": id.public_key_base64(),
            },
            "user": {
                "id": id.user.id,
                "handle": user_handle,
            },
            "network": {
                "ipv4": ipv4,
                "ipv6": ipv6,
                "hostname": hostname,
            },
            "meta": {
                "user_display_name": id.user.display_name,
                "device_display_name": device_display_name,
            }
        }
    })
}

fn join_message(room_id: &str, password_verifier: Option<&str>) -> Value {
    let mut msg = json!({ "type": "join", "data": { "room_id": room_id } });
    if let Some(v) = password_verifier {
        msg["data"]["password_verifier"] = json!(v);
    }
    msg
}

fn discovery_join_message(room_id: &str) -> Value {
    json!({ "type": "discovery_join", "data": { "room_id": room_id } })
}

fn room_keepalive_message(room_id: &str) -> Value {
    json!({ "type": "room_keepalive", "data": { "room_id": room_id } })
}

fn heartbeat_message() -> Value {
    json!({ "type": "node_heartbeat", "data": {} })
}

/// Non-empty access token of the identity, if any.
fn access_token(id: &Identity) -> Option<String> {
    id.auth.as_ref().map(|a| a.access_token.clone()).filter(|t| !t.is_empty())
}

/// Apply a `/auth/token/refresh` response to the identity.
/// Returns `false` (identity unchanged) if the response has no access token.
fn apply_token_refresh(id: &mut Identity, body: &Value) -> bool {
    let access = body["access_token"].as_str().unwrap_or("");
    if access.is_empty() {
        return false;
    }
    let Some(auth) = id.auth.as_mut() else { return false };
    auth.access_token = access.to_string();
    if let Some(rt) = body["refresh_token"].as_str().filter(|s| !s.is_empty()) {
        auth.refresh_token = rt.to_string();
    }
    auth.expires_at = body["expires_at"].as_i64().unwrap_or(0);
    true
}

/// Reconcile the local identity with a `registered` message (3.0.x
/// `on_registered`).  Returns `true` if anything changed and the identity
/// must be persisted.
///
/// * Hostname: adopted unless empty.
/// * IPv4: a different address is stored as `assigned_ipv4`; the TUN is not
///   reconfigured at runtime — it takes effect on the next start.
/// * User handle / display name: adopted only when OIDC auth is active, so
///   the coordinator's token-derived values win over local edits.
pub fn apply_registered(
    id: &mut Identity,
    hostname: &str,
    ipv4: &str,
    user_handle: &str,
    user_display_name: &str,
) -> bool {
    let mut changed = false;
    // An empty hostname is not an assignment: keep the one we have.
    if !hostname.is_empty() && id.device.hostname != hostname {
        info!("coordinator assigned hostname {} (was {:?})", hostname, id.device.hostname);
        id.device.hostname = hostname.to_string();
        changed = true;
    }
    let (current_ipv4, _) = id.virtual_ips();
    if !ipv4.is_empty() && current_ipv4 != ipv4 {
        info!("coordinator assigned IPv4 {} (current {}); used from next startup", ipv4, current_ipv4);
        id.device.assigned_ipv4 = Some(ipv4.to_string());
        changed = true;
    }
    let oidc_active = id.auth.is_some();
    if oidc_active && !user_handle.is_empty() && id.user.handle != user_handle {
        info!("coordinator assigned user handle {} (OIDC)", user_handle);
        id.user.handle = user_handle.to_string();
        changed = true;
    }
    if oidc_active && !user_display_name.is_empty() && id.user.display_name != user_display_name {
        info!("coordinator assigned user display name {} (OIDC)", user_display_name);
        id.user.display_name = user_display_name.to_string();
        changed = true;
    }
    changed
}

/// Returns true if a tungstenite error is an HTTP 401 from the server.
fn is_auth_required_error(e: &tokio_tungstenite::tungstenite::Error) -> bool {
    matches!(e, tokio_tungstenite::tungstenite::Error::Http(resp)
        if resp.status() == tokio_tungstenite::tungstenite::http::StatusCode::UNAUTHORIZED)
}

/// Build the WS upgrade request, optionally with `Authorization: Bearer`.
///
/// Uses `IntoClientRequest` so tungstenite fills in the mandatory WebSocket
/// headers before we add ours.
fn build_ws_request(
    ws_url: &str,
    token: Option<&str>,
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request, tokio_tungstenite::tungstenite::Error> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::{header::AUTHORIZATION, HeaderValue};
    let mut req = ws_url.into_client_request()?;
    if let Some(token) = token {
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", token)) {
            req.headers_mut().insert(AUTHORIZATION, v);
        }
    }
    Ok(req)
}

fn next_backoff(current: u64) -> u64 {
    (current * 2).min(BACKOFF_MAX_SECS)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl CoordinatorClient {
    /// Parse an incoming WS text message and dispatch it.
    ///
    /// Returns `Ok(Some(event))` if a meaningful event was produced,
    /// `Ok(None)` for ack/control messages, `Err` for parse failures.
    pub fn parse_incoming(&self, text: &str) -> Result<Option<CoordinatorEvent>, String> {
        let envelope: WsEnvelope = serde_json::from_str(text)
            .map_err(|e| format!("invalid WS message: {}", e))?;

        match envelope.msg_type.as_str() {
            "registered" => {
                let data: RegisteredPayload = serde_json::from_value(envelope.data)
                    .map_err(|e| format!("invalid registered payload: {}", e))?;
                Ok(Some(CoordinatorEvent::Registered {
                    hostname: data.hostname,
                    ipv4: data.ipv4,
                    ipv6: data.ipv6,
                    user_handle: data.user_handle,
                    user_display_name: data.user_display_name,
                }))
            }
            "room_state" => {
                let data: RoomStateData = serde_json::from_value(envelope.data)
                    .map_err(|e| format!("invalid room_state payload: {}", e))?;
                // A peer without a device ID can't be addressed: drop it, not
                // the whole room.
                let mut peers = data.peers;
                let before = peers.len();
                peers.retain(|p| !p.device_id.is_empty());
                if peers.len() != before {
                    warn!("coordinator: room_state {} had {} peer(s) without a device ID — ignored", data.room_id, before - peers.len());
                }
                Ok(Some(CoordinatorEvent::RoomState {
                    room_id: data.room_id,
                    room_name: data.room_name,
                    peers,
                }))
            }
            "member_joined" => {
                let data: MemberJoinedData = serde_json::from_value(envelope.data)
                    .map_err(|e| format!("invalid member_joined: {}", e))?;
                if data.peer.device_id.is_empty() {
                    return Err("member_joined without a device_id".into());
                }
                Ok(Some(CoordinatorEvent::MemberJoined {
                    room_id: data.room_id.or(envelope.room_id).unwrap_or_default(),
                    peer: data.peer,
                }))
            }
            "member_left" => {
                let data: MemberEvent = serde_json::from_value(envelope.data)
                    .map_err(|e| format!("invalid member_left: {}", e))?;
                Ok(Some(CoordinatorEvent::MemberLeft {
                    room_id: data.room_id.or(envelope.room_id).unwrap_or_default(),
                    device_id: data.device_id,
                }))
            }
            "node_added" => {
                let data: NodeEvent = serde_json::from_value(envelope.data)
                    .map_err(|e| format!("invalid node_added: {}", e))?;
                Ok(Some(CoordinatorEvent::NodeAdded {
                    device_id: data.device_id,
                    endpoints: data.endpoints,
                    last_seen: data.last_seen,
                    status: data.status,
                }))
            }
            "node_updated" => {
                let data: NodeEvent = serde_json::from_value(envelope.data)
                    .map_err(|e| format!("invalid node_updated: {}", e))?;
                Ok(Some(CoordinatorEvent::NodeUpdated {
                    device_id: data.device_id,
                    endpoints: data.endpoints,
                    last_seen: data.last_seen,
                    status: data.status,
                }))
            }
            "punch_request" => {
                let data: PunchRequest = serde_json::from_value(envelope.data)
                    .map_err(|e| format!("invalid punch_request: {}", e))?;
                Ok(Some(CoordinatorEvent::PunchRequest {
                    peer_id: data.peer_id,
                    endpoints: data.endpoints,
                }))
            }
            "error" => {
                let data: ErrorPayload = serde_json::from_value(envelope.data)
                    .map_err(|e| format!("invalid error payload: {}", e))?;
                warn!("coordinator error: {}", data.message);
                Ok(Some(CoordinatorEvent::Error {
                    message: data.message,
                    code: data.code,
                }))
            }
            other => {
                debug!("coordinator: unhandled message type '{}'", other);
                Ok(None)
            }
        }
    }

    /// Derive the WebSocket URL from the coordinator HTTP(S) base URL.
    pub fn ws_url(&self) -> String {
        let base = if self.config.coord_url.starts_with("https://") {
            self.config.coord_url.replacen("https://", "wss://", 1)
        } else if self.config.coord_url.starts_with("http://") {
            self.config.coord_url.replacen("http://", "ws://", 1)
        } else {
            self.config.coord_url.clone()
        };
        format!("{}/ws", base.trim_end_matches('/'))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client() -> CoordinatorClient {
        let (event_tx, _event_rx) = mpsc::channel(16);
        CoordinatorClient::new(
            CoordinatorConfig {
                coord_url: "https://coord.example.com".to_string(),
            },
            event_tx,
        )
    }

    #[test]
    fn ws_url_https() {
        let client = make_client();
        assert_eq!(client.ws_url(), "wss://coord.example.com/ws");
    }

    #[test]
    fn ws_url_http() {
        let (event_tx, _) = mpsc::channel(16);
        let client = CoordinatorClient::new(
            CoordinatorConfig {
                coord_url: "http://localhost:8080".to_string(),
            },
            event_tx,
        );
        assert_eq!(client.ws_url(), "ws://localhost:8080/ws");
    }

    #[test]
    fn ws_url_trailing_slash() {
        let (event_tx, _) = mpsc::channel(16);
        let client = CoordinatorClient::new(
            CoordinatorConfig {
                coord_url: "https://coord.example.com/".to_string(),
            },
            event_tx,
        );
        assert_eq!(client.ws_url(), "wss://coord.example.com/ws");
    }

    #[test]
    fn parse_registered_message() {
        let client = make_client();
        let json = r#"{"type":"registered","data":{"hostname":"pc.abjust.ezplay.msst.net","ipv4":"172.22.1.1","ipv6":"fd22:2222:2222:2222::aabb:ccdd","user_handle":"abjust","user_display_name":"Abjust"}}"#;
        let event = client.parse_incoming(json).unwrap().unwrap();
        match event {
            CoordinatorEvent::Registered { hostname, ipv4, .. } => {
                assert_eq!(hostname, "pc.abjust.ezplay.msst.net");
                assert_eq!(ipv4, "172.22.1.1");
            }
            _ => panic!("expected Registered"),
        }
    }

    #[test]
    fn parse_room_state_message() {
        let client = make_client();
        let json = r#"{"type":"room_state","data":{"room_id":"space-12345678","room_name":"test","peers":[{"device_id":"device-aabbccdd","public_key":"pk","ipv4":"172.22.1.1","ipv6":"::1","hostname":"h","user_display_name":"U","device_display_name":"D","endpoints":[],"is_authenticated":false}]}}"#;
        let event = client.parse_incoming(json).unwrap().unwrap();
        match event {
            CoordinatorEvent::RoomState { room_id, peers, .. } => {
                assert_eq!(room_id, "space-12345678");
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].device_id, "device-aabbccdd");
            }
            _ => panic!("expected RoomState"),
        }
    }

    #[test]
    fn parse_node_added_message() {
        let client = make_client();
        let json = r#"{"type":"node_added","data":{"device_id":"device-aabbccdd","endpoints":["1.2.3.4:21031"],"last_seen":1700000000,"status":"online"}}"#;
        let event = client.parse_incoming(json).unwrap().unwrap();
        match event {
            CoordinatorEvent::NodeAdded { device_id, status, .. } => {
                assert_eq!(device_id, "device-aabbccdd");
                assert_eq!(status, "online");
            }
            _ => panic!("expected NodeAdded"),
        }
    }

    #[test]
    fn parse_punch_request_message() {
        let client = make_client();
        let json = r#"{"type":"punch_request","data":{"peer_id":"device-11223344","endpoints":["5.6.7.8:21031"]}}"#;
        let event = client.parse_incoming(json).unwrap().unwrap();
        match event {
            CoordinatorEvent::PunchRequest { peer_id, .. } => {
                assert_eq!(peer_id, "device-11223344");
            }
            _ => panic!("expected PunchRequest"),
        }
    }

    #[test]
    fn parse_error_message() {
        let client = make_client();
        let json = r#"{"type":"error","data":{"message":"room not found"}}"#;
        let event = client.parse_incoming(json).unwrap().unwrap();
        match event {
            CoordinatorEvent::Error { message, .. } => {
                assert_eq!(message, "room not found");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn parse_unknown_message_type() {
        let client = make_client();
        let json = r#"{"type":"future_message","data":{}}"#;
        let event = client.parse_incoming(json).unwrap();
        assert!(event.is_none());
    }

    #[test]
    fn parse_malformed_json() {
        let client = make_client();
        assert!(client.parse_incoming("not json").is_err());
    }

    #[test]
    fn parse_registered_requires_all_fields() {
        // A 3.0.x coordinator (no ipv6) is not supported.
        let client = make_client();
        let json = r#"{"type":"registered","data":{"hostname":"pc.abjust.ezplay.msst.net","ipv4":"172.22.1.1","user_handle":"abjust","user_display_name":"Abjust"}}"#;
        assert!(client.parse_incoming(json).is_err());
    }

    #[test]
    fn peers_without_device_id_are_dropped_not_the_room() {
        let c = make_client();
        let json = r#"{"type":"room_state","data":{"room_id":"space-1","room_name":"r","peers":[
            {"ipv4":"172.22.1.2","ipv6":"::2"},{"device_id":"","ipv4":"172.22.1.3","ipv6":"::3"},
            {"device_id":"device-aabbccdd","ipv4":"172.22.1.1","ipv6":"::1"}]}}"#;
        match c.parse_incoming(json).unwrap() {
            Some(CoordinatorEvent::RoomState { peers, .. }) => {
                assert_eq!(peers.iter().map(|p| p.device_id.as_str()).collect::<Vec<_>>(), ["device-aabbccdd"]);
            }
            e => panic!("expected RoomState, got {:?}", e),
        }
        let joined = r#"{"type":"member_joined","room_id":"space-1","data":{"ipv4":"172.22.1.1","ipv6":"::1"}}"#;
        assert!(c.parse_incoming(joined).is_err());
    }

    // ── Pure helpers ─────────────────────────────────────────────────────

    fn test_identity(auth: bool) -> Identity {
        use crate::identity::{AuthCredentials, DeviceInfo, UserInfo};
        Identity {
            user: UserInfo { id: "user-11223344".into(), handle: String::new(), display_name: "U".into() },
            device: DeviceInfo {
                id: "device-a1b2c3d4".into(),
                handle: String::new(),
                display_name: "D".into(),
                hostname: String::new(),
                assigned_ipv4: None,
            },
            secret_key: [1u8; 32],
            public_key: [2u8; 32],
            auth: auth.then(|| AuthCredentials {
                user_id: "user-11223344".into(),
                access_token: "old".into(),
                refresh_token: "rt".into(),
                expires_at: 1,
            }),
        }
    }

    #[test]
    fn register_message_matches_3_0_x_shape() {
        let msg = build_register_message(&test_identity(false));
        assert_eq!(msg["type"], "register");
        let d = &msg["data"];
        assert_eq!(d["device"]["id"], "device-a1b2c3d4");
        // Empty handles fall back to the full IDs.
        assert_eq!(d["device"]["handle"], "device-a1b2c3d4");
        assert_eq!(d["user"]["handle"], "user-11223344");
        assert_eq!(d["device"]["pub_key"], "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=");
        assert_eq!(d["network"]["ipv4"], "172.22.178.196");
        assert_eq!(d["network"]["ipv6"], "fd22:2222:2222:2222::a1b2:c3d4");
        assert_eq!(d["network"]["hostname"], "device-a1b2c3d4.user-11223344.ezplay.msst.net");
        assert_eq!(d["meta"]["user_display_name"], "U");
        assert_eq!(d["meta"]["device_display_name"], "D");
    }

    #[test]
    fn register_message_uses_handles_and_assigned_ipv4() {
        let mut id = test_identity(false);
        id.device.handle = "pc".into();
        id.user.handle = "abjust".into();
        id.device.assigned_ipv4 = Some("172.22.9.9".into());
        let d = &build_register_message(&id)["data"];
        assert_eq!(d["device"]["handle"], "pc");
        assert_eq!(d["network"]["hostname"], "pc.abjust.ezplay.msst.net");
        assert_eq!(d["network"]["ipv4"], "172.22.9.9");
    }

    #[test]
    fn register_message_defaults_unset_device_name_and_handle() {
        let mut id = test_identity(false);
        id.device.display_name.clear();
        let d = &build_register_message(&id)["data"];
        assert_eq!(d["meta"]["device_display_name"], "用户user-11223344的设备");
        assert_eq!(d["device"]["handle"], "device-a1b2c3d4");
        // An invalid handle (e.g. hand-edited identity.json) is not sent.
        id.device.handle = "My PC".into();
        let d = &build_register_message(&id)["data"];
        assert_eq!(d["device"]["handle"], "device-a1b2c3d4");
        assert_eq!(d["network"]["hostname"], "device-a1b2c3d4.user-11223344.ezplay.msst.net");
    }

    #[test]
    fn apply_registered_keeps_hostname_when_none_assigned() {
        let mut id = test_identity(false);
        id.device.hostname = "pc.abjust.ezplay.msst.net".into();
        assert!(!apply_registered(&mut id, "", "", "", ""));
        assert_eq!(id.device.hostname, "pc.abjust.ezplay.msst.net");
    }

    #[test]
    fn periodic_messages_match_3_0_x() {
        assert_eq!(heartbeat_message().to_string(), r#"{"data":{},"type":"node_heartbeat"}"#);
        assert_eq!(room_keepalive_message("r1")["data"]["room_id"], "r1");
        assert_eq!(discovery_join_message("r1")["type"], "discovery_join");
        assert_eq!(join_message("r1", None)["type"], "join");
        assert!(join_message("r1", None)["data"].get("password_verifier").is_none());
        assert_eq!(join_message("r1", Some("v"))["data"]["password_verifier"], "v");
    }

    #[test]
    fn apply_registered_without_oidc_ignores_user_fields() {
        let mut id = test_identity(false);
        assert!(apply_registered(&mut id, "h.example", "172.22.178.196", "abjust", "Abjust"));
        assert_eq!(id.device.hostname, "h.example");
        assert_eq!(id.device.assigned_ipv4, None); // same as derived → no override
        assert_eq!(id.user.handle, "");
        assert_eq!(id.user.display_name, "U");
        // Idempotent.
        assert!(!apply_registered(&mut id, "h.example", "172.22.178.196", "abjust", "Abjust"));
    }

    #[test]
    fn apply_registered_with_oidc_adopts_user_fields_and_ipv4() {
        let mut id = test_identity(true);
        assert!(apply_registered(&mut id, "h", "172.22.1.1", "abjust", "Abjust"));
        assert_eq!(id.device.assigned_ipv4.as_deref(), Some("172.22.1.1"));
        assert_eq!(id.user.handle, "abjust");
        assert_eq!(id.user.display_name, "Abjust");
    }

    #[test]
    fn token_refresh_response_applied() {
        let mut id = test_identity(true);
        assert!(apply_token_refresh(&mut id, &json!({"access_token":"new","expires_at":99})));
        let a = id.auth.as_ref().unwrap();
        assert_eq!((a.access_token.as_str(), a.refresh_token.as_str(), a.expires_at), ("new", "rt", 99));
        assert!(apply_token_refresh(&mut id, &json!({"access_token":"n2","refresh_token":"rt2"})));
        assert_eq!(id.auth.as_ref().unwrap().refresh_token, "rt2");
        // No access token → unchanged.
        assert!(!apply_token_refresh(&mut id, &json!({})));
        assert_eq!(id.auth.as_ref().unwrap().access_token, "n2");
    }

    #[test]
    fn ws_request_carries_bearer_token() {
        let req = build_ws_request("wss://coord.example.com/ws", Some("tok")).unwrap();
        assert_eq!(req.headers()["authorization"], "Bearer tok");
        assert!(req.headers().contains_key("sec-websocket-key"));
        let req = build_ws_request("wss://coord.example.com/ws", None).unwrap();
        assert!(!req.headers().contains_key("authorization"));
    }

    #[test]
    fn backoff_is_bounded() {
        let mut b = BACKOFF_MIN_SECS;
        for _ in 0..10 { b = next_backoff(b); }
        assert_eq!(b, BACKOFF_MAX_SECS);
    }

    #[tokio::test]
    async fn send_fails_fast_when_disconnected() {
        let client = make_client();
        assert_eq!(client.send("x").await, Err(NotConnected));
    }

    /// End-to-end against a local fake coordinator: every connection must
    /// start with `register` followed by the joined rooms, and after the
    /// server drops the connection the client must reconnect and do it again.
    #[tokio::test]
    async fn reconnects_and_reregisters_with_room_rejoin() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let core = Arc::new(CoreState::new(udp, std::env::temp_dir()));
        let mut ipc_rx = core.subscribe_events();
        core.apply_identity(&test_identity(false)).await;
        {
            let mut net = core.net.write().await;
            net.joined_rooms.insert("space-1".into(), "Room".into());
            net.room_password_verifiers.insert("space-1".into(), "pwverifier".into());
        }

        let (event_tx, _event_rx) = mpsc::channel(16);
        let client = Arc::new(CoordinatorClient::new(
            CoordinatorConfig { coord_url: format!("http://127.0.0.1:{}", port) },
            event_tx,
        ));
        let runner = {
            let (client, core) = (client.clone(), core.clone());
            tokio::spawn(async move { client.run(core).await })
        };

        // Acceptor: WebSocket upgrades go to the test; the key-challenge
        // POST is answered like a Coordinator without keyproof (404).
        let (ws_conn_tx, mut ws_conns) = mpsc::channel(4);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut tcp, _)) = listener.accept().await {
                let mut peek = [0u8; 4];
                let n = tcp.peek(&mut peek).await.unwrap_or(0);
                if peek[..n].starts_with(b"GET") {
                    let _ = ws_conn_tx.send(tcp).await;
                } else {
                    let mut req = [0u8; 2048];
                    let _ = tcp.read(&mut req).await;
                    let _ = tcp.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
                }
            }
        });

        for round in 0..2 {
            let tcp = tokio::time::timeout(Duration::from_secs(10), ws_conns.recv())
                .await.expect("client did not (re)connect").unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let mut msgs = Vec::new();
            while msgs.len() < 3 {
                if let Some(Ok(Message::Text(t))) = ws.next().await {
                    msgs.push(serde_json::from_str::<Value>(&t).unwrap());
                }
            }
            let types: Vec<&str> = msgs.iter().map(|v| v["type"].as_str().unwrap()).collect();
            assert_eq!(types, ["register", "join", "discovery_join"], "round {}", round);
            // A password-protected room is re-joined with its password.
            assert_eq!(msgs[1]["data"]["password_verifier"], "pwverifier", "round {}", round);
            if round == 0 {
                // Messages sent while connected go out on the live connection.
                client.send_leave("space-1").await.unwrap();
                let Some(Ok(Message::Text(t))) = ws.next().await else { panic!() };
                assert!(t.contains("\"leave\""));
            }
            drop(ws); // server-side disconnect
        }

        // Connection state transitions were reported over IPC.
        let mut seen = Vec::new();
        while let Ok(ev) = ipc_rx.try_recv() {
            if let msst_ipc_protocol::IpcEvent::CoordinatorConnectionChanged { connected } = ev {
                seen.push(connected);
            }
        }
        assert!(seen.starts_with(&[true, false, true]), "got {:?}", seen);
        runner.abort();
    }

    #[test]
    fn parse_member_events_with_envelope_room_id() {
        let client = make_client();
        // The full peer, and the room in the envelope only.
        let json = r#"{"type":"member_joined","room_id":"space-1","data":{"device_id":"device-aabbccdd","public_key":"pk","ipv4":"172.22.1.1","ipv6":"fd22:2222:2222:2222::aabb:ccdd","hostname":"h","endpoints":["relay:1.2.3.4:7000"],"is_authenticated":true}}"#;
        match client.parse_incoming(json).unwrap().unwrap() {
            CoordinatorEvent::MemberJoined { room_id, peer } => {
                assert_eq!(room_id, "space-1");
                assert_eq!(peer.ipv4, "172.22.1.1");
                assert!(peer.is_authenticated);
            }
            _ => panic!("expected MemberJoined"),
        }
        let json = r#"{"type":"member_left","data":{"device_id":"device-aabbccdd"}}"#;
        assert!(matches!(client.parse_incoming(json).unwrap().unwrap(),
            CoordinatorEvent::MemberLeft { device_id, .. } if device_id == "device-aabbccdd"));
    }

    // ── Credentials: OIDC → guest token ───────────────────────────────────

    use crate::test_support::{core_state, FakeCoordinator};
    use std::collections::HashSet;

    type Allowed = Arc<std::sync::Mutex<HashSet<String>>>;

    fn allow(tokens: &[&str]) -> Allowed {
        Arc::new(std::sync::Mutex::new(tokens.iter().map(|t| t.to_string()).collect()))
    }

    /// A coordinator whose WS accepts the `allowed` bearer tokens (and none
    /// without a token); refresh answers `refresh_status`; each guest token
    /// request gets the next of `guests`.
    async fn auth_coordinator(allowed: Allowed, refresh_status: u16, guests: &[&str]) -> FakeCoordinator {
        let guests: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(guests.iter().rev().map(|g| g.to_string()).collect()));
        FakeCoordinator::start_with_ws_auth(
            move |req| match req.path.as_str() {
                "/auth/token/refresh" => (refresh_status, json!({})),
                "/auth/guest/token" => match guests.lock().unwrap().pop() {
                    Some(g) => (200, json!({ "token": g, "user_id": "guest-0000000a", "expires_at": unix_now() + 86_400 })),
                    None => (404, json!({})),
                },
                _ => (404, json!({})),
            },
            |_| vec![],
            move |t| t.is_some_and(|t| allowed.lock().unwrap().contains(t)),
        )
        .await
    }

    async fn start_client(core: &Arc<CoreState>, url: &str) -> (Arc<CoordinatorClient>, tokio::task::JoinHandle<()>) {
        let (event_tx, mut event_rx) = mpsc::channel(64);
        tokio::spawn(async move { while event_rx.recv().await.is_some() {} });
        let client = Arc::new(CoordinatorClient::new(CoordinatorConfig { coord_url: url.into() }, event_tx));
        let runner = {
            let (client, core) = (client.clone(), core.clone());
            tokio::spawn(async move { client.run(core).await })
        };
        (client, runner)
    }

    async fn set_oidc(core: &Arc<CoreState>, token: &str) {
        let mut id = core.identity.write().await;
        id.as_mut().unwrap().auth = Some(crate::identity::AuthCredentials {
            user_id: "user-00000001".into(),
            access_token: token.into(),
            refresh_token: "rt".into(),
            expires_at: unix_now() + 3600,
        });
        drop(id);
        core.net.write().await.local_authenticated = true;
    }

    async fn wait_for(mut f: impl FnMut() -> bool) {
        for _ in 0..250 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("condition not reached");
    }

    #[tokio::test]
    async fn rejected_oidc_falls_back_to_a_guest_token_and_back_after_login() {
        let allowed = allow(&["g1"]);
        let coord = auth_coordinator(allowed.clone(), 401, &["g1"]).await;
        let (core, _ipc) = core_state("coord-guest").await;
        set_oidc(&core, "stale").await;
        let (client, runner) = start_client(&core, &coord.url).await;

        wait_for(|| client.credential_kind() == "guest").await;
        assert!(client.oidc_rejected());
        assert!(core.access_auth_required.load(Ordering::SeqCst));
        assert!(!core.net.read().await.local_authenticated, "room-mode rules apply");
        let attempts: Vec<(Option<String>, bool)> = coord.ws_auth_log.lock().unwrap().clone();
        // Refused once; the refresh was refused too, so no second try with it.
        assert_eq!(attempts, [(Some("stale".into()), false), (Some("g1".into()), true)]);
        assert!(coord.ws_types().contains(&"register".to_string()));

        // The HTTP API uses the same credential (it used to send none).
        client.api_post("/device/endpoint", &json!({ "deviceId": "device-00000001", "endpoints": [] })).await.ok();
        let ep = coord.http_log.lock().unwrap().iter().rev().find(|r| r.path == "/device/endpoint").cloned().unwrap();
        assert_eq!(ep.authorization.as_deref(), Some("Bearer g1"));

        // Logging in again: reconnect with the new OIDC token at once.
        allowed.lock().unwrap().insert("fresh".into());
        set_oidc(&core, "fresh").await;
        client.credentials_changed(&core).await;
        wait_for(|| client.credential_kind() == "oidc").await;
        assert!(!client.oidc_rejected());
        assert_eq!(coord.ws_accepted_tokens().last().cloned().flatten().as_deref(), Some("fresh"));
        assert_eq!(client.bearer().as_deref(), Some("fresh"));
        runner.abort();
    }

    #[tokio::test]
    async fn forgotten_guest_token_is_replaced() {
        // Never logged in: straight to a guest token.
        let allowed = allow(&["g1"]);
        let coord = auth_coordinator(allowed.clone(), 401, &["g1", "g2"]).await;
        let (core, _ipc) = core_state("coord-guest-renew").await;
        let (client, runner) = start_client(&core, &coord.url).await;
        wait_for(|| client.credential_kind() == "guest").await;
        assert_eq!(client.bearer().as_deref(), Some("g1"));
        assert!(!client.oidc_rejected(), "nothing was rejected");

        // The coordinator restarts (guest tokens are in memory): the cached
        // token is refused once, then a new one is used.
        *allowed.lock().unwrap() = ["g2".to_string()].into();
        client.reconnect.notify_waiters();
        wait_for(|| client.bearer().as_deref() == Some("g2")).await;
        let attempts: Vec<Option<String>> = coord.ws_auth_log.lock().unwrap().iter().map(|(t, _)| t.clone()).collect();
        assert_eq!(attempts, [Some("g1".into()), Some("g1".into()), Some("g2".into())]);
        runner.abort();
    }

    #[tokio::test]
    async fn unavailable_refresh_keeps_the_oidc_credentials() {
        // The IdP is down (5xx): don't give up on the login.
        let coord = auth_coordinator(allow(&[]), 503, &["g1"]).await;
        let (core, _ipc) = core_state("coord-refresh-down").await;
        set_oidc(&core, "stale").await;
        let (client, runner) = start_client(&core, &coord.url).await;
        wait_for(|| coord.http_log.lock().unwrap().iter().any(|r| r.path == "/auth/token/refresh")).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!client.oidc_rejected());
        assert_eq!(client.credential_kind(), "none");
        assert!(!coord.http_log.lock().unwrap().iter().any(|r| r.path == "/auth/guest/token"));
        runner.abort();
    }

    #[tokio::test]
    async fn coordinator_without_guest_tokens_is_joined_without_credentials() {
        let coord = FakeCoordinator::start(|_| (404, json!({})), |_| vec![]).await;
        let (core, _ipc) = core_state("coord-anonymous").await;
        let (client, runner) = start_client(&core, &coord.url).await;
        wait_for(|| coord.ws_types().contains(&"register".to_string())).await;
        assert_eq!(coord.ws_accepted_tokens(), [None]);
        assert_eq!(client.credential_kind(), "none");
        runner.abort();
    }
}
