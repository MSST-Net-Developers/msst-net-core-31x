//! IPC server — the Controller ↔ Core communication layer.
//!
//! Replaces the 3.0.x split design (push-only IPC socket + separate HTTP
//! API) with a unified request/response/event model over one transport.
//!
//! ## Transport
//!
//! - **Linux/macOS**: Unix domain socket (`/run/msst-net/ipc.sock` as root),
//!   access and role from the peer UID (`auth.rs`)
//! - **Windows**: named pipe `\\.\pipe\msst-net-ipc`, access restricted by
//!   its ACL, role from the client's token (`windows_pipe.rs`)
//!
//! Each connection gets a role (viewer / admin, protocol 0.4); the handler
//! refuses requests above it with `permission_denied`.
//!
//! The protocol layer (`serve_client`) is generic over any
//! `AsyncRead + AsyncWrite` stream; transports only accept connections and
//! enforce access control.
//!
//! ## Connection lifecycle
//!
//! ```text
//! accept → authorize peer (Unix: SO_PEERCRED UID → role or refuse)
//!        → version handshake (u32 BE both ways; incompatible → error
//!          frame with id "handshake", then close)
//!        → Windows: role from the impersonated client token
//!        → frames: [len: u32 BE][JSON IpcMessage]
//!             Controller → Core: Request{id}
//!             Core → Controller: Response{id} (same id) | Event
//! ```
//!
//! Each request gets exactly one `Response` with the request's `id`.
//! Events are pushed as they occur.
//!
//! ## Concurrency (0.4)
//!
//! Queries (and session requests) run concurrently, at most
//! `MAX_INFLIGHT_QUERIES` per connection; commands run one at a time in
//! arrival order (`COMMAND_QUEUE` may wait).  So a slow command no longer
//! blocks queries, and responses can arrive out of order — correlate by
//! `id`.  A query sent before an earlier command's response arrived may not
//! see that command's effect yet.  When the connection closes, running
//! queries are aborted; the running command completes, queued ones are
//! dropped.
//!
//! ## Events, `seq` and snapshots (0.4)
//!
//! Every event comes from Core's [`EventBus`](crate::state::EventBus) and
//! carries `seq` (1, 2, 3, … per Core run; no gaps).  Every response
//! carries `event_seq`, the last `seq` emitted before the handler read any
//! state.  A Controller subscribes simply by connecting, then:
//! snapshot → skip events with `seq <= event_seq` → apply the rest
//! (idempotently: an event just above `event_seq` may already be in the
//! snapshot).  A gap in `seq` means events were lost → re-snapshot.
//!
//! A client that falls too far behind on events (its queue is full or it
//! lagged on the bus) is disconnected, so it reconnects and rebuilds its
//! state from a fresh snapshot instead of silently missing events.  Event
//! delivery never blocks Core.

#[cfg(unix)]
pub mod auth;
pub(crate) mod handler;
pub(crate) mod ops;
#[cfg(windows)]
mod windows_pipe;

use crate::state::{CoreState, SeqEvent};
use handler::handle_request;
use msst_ipc_protocol::version::PROTOCOL_VERSION;
use msst_ipc_protocol::access::RequestKind;
use msst_ipc_protocol::{IpcEvent, IpcMessage, IpcRequest, IpcResponse, Role};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, watch, Semaphore};
use tracing::{debug, error, info, warn};

/// Maximum accepted frame size.
const MAX_FRAME_LEN: usize = 1024 * 1024;
/// Time the Controller has to send its version.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Per-client outgoing queue depth (responses + events).
const CLIENT_QUEUE: usize = 256;
/// Queries handled concurrently per connection.
const MAX_INFLIGHT_QUERIES: usize = 16;
/// Commands waiting to run per connection.
const COMMAND_QUEUE: usize = 32;

// ---------------------------------------------------------------------------
// IpcServer
// ---------------------------------------------------------------------------

/// The IPC server — accepts Controller connections; each subscribes to
/// Core's event bus (`CoreState::events`).
pub struct IpcServer {
    /// Shared Core state (passed to request handlers).
    state: Arc<CoreState>,
}

impl IpcServer {
    /// Create a new IPC server.
    pub fn new(state: Arc<CoreState>) -> Self {
        IpcServer { state }
    }

    /// Bind the Unix socket (secure directory, permissions).  Fails if the
    /// socket can't be created — Core must not run unmanageable.
    #[cfg(unix)]
    pub fn bind_unix(socket_path: &std::path::Path) -> std::io::Result<tokio::net::UnixListener> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
            if unsafe { libc::geteuid() } == 0 {
                auth::secure_socket_dir(parent);
            }
        }
        let _ = std::fs::remove_file(socket_path); // stale socket
        let listener = tokio::net::UnixListener::bind(socket_path)?;
        auth::set_socket_permissions(socket_path);
        info!("IPC server listening on {:?}", socket_path);
        Ok(listener)
    }

    /// Serve Controllers on a socket bound by [`IpcServer::bind_unix`].
    #[cfg(unix)]
    pub async fn serve_unix(self, listener: tokio::net::UnixListener) {

        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(e) => {
                    error!("IPC accept error: {}", e);
                    break;
                }
            };
            let uid = match stream.peer_cred() {
                Ok(cred) => cred.uid(),
                Err(e) => {
                    warn!("IPC: cannot read peer credentials, rejecting connection: {}", e);
                    continue;
                }
            };
            let Some(role) = auth::peer_role(uid) else {
                warn!("IPC: rejected connection from unauthorized uid={}", uid);
                continue; // dropping the stream closes it
            };
            let peer = format!("uid={}, role={}", uid, role.as_str());
            info!("IPC client connected ({})", peer);
            let state = self.state.clone();
            let events = self.state.events.subscribe();
            tokio::spawn(async move {
                serve_client(stream, state, events, move |_| Some(role)).await;
                info!("IPC client disconnected ({})", peer);
            });
        }
    }

    /// Create the first named-pipe instance.  Fails if the pipe can't be
    /// created (e.g. the name is taken) — Core must not run unmanageable.
    #[cfg(windows)]
    pub fn bind_named_pipe(pipe_name: &str) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        let server = windows_pipe::create_instance(pipe_name, true)?;
        info!("IPC server listening on {}", pipe_name);
        Ok(server)
    }

    /// Serve Controllers on a pipe created by [`IpcServer::bind_named_pipe`].
    #[cfg(windows)]
    pub async fn serve_named_pipe(self, first: tokio::net::windows::named_pipe::NamedPipeServer, pipe_name: String) {
        let pipe_name = pipe_name.as_str();
        let mut server = first;
        loop {
            if let Err(e) = server.connect().await {
                warn!("IPC: named pipe connect error: {}", e);
                continue;
            }
            // Create the next instance before serving this one, so a client
            // can always connect.
            let next = match windows_pipe::create_instance(pipe_name, false) {
                Ok(s) => s,
                Err(e) => {
                    error!("IPC: cannot create named pipe instance: {}", e);
                    break;
                }
            };
            let connected = std::mem::replace(&mut server, next);
            info!("IPC client connected (named pipe)");
            let state = self.state.clone();
            let events = self.state.events.subscribe();
            tokio::spawn(async move {
                serve_client(connected, state, events, windows_pipe::client_role).await;
                info!("IPC client disconnected (named pipe)");
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Per-client protocol handling (transport-independent)
// ---------------------------------------------------------------------------

/// Per-connection state handlers can see.
#[derive(Debug)]
pub struct Session {
    /// Permission tier, fixed for the connection's lifetime.
    pub role: Role,
    /// Whether log lines are streamed to this connection (`SetLogStream`).
    pub log_stream: AtomicBool,
}

impl Session {
    pub fn new(role: Role) -> Self {
        Session { role, log_stream: AtomicBool::new(true) }
    }
}

/// Serve one Controller connection until it closes.
///
/// `authorize` runs after the version handshake (Windows can only
/// impersonate a pipe client after reading from it) and returns the
/// connection's role, or `None` to refuse it.
pub async fn serve_client<S, A>(mut stream: S, state: Arc<CoreState>, mut events: broadcast::Receiver<SeqEvent>, authorize: A)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A: FnOnce(&S) -> Option<Role>,
{
    // ── Version handshake: both sides send first, then read ──────────────
    if let Err(e) = async {
        stream.write_all(&PROTOCOL_VERSION.to_be_bytes()).await?;
        stream.flush().await
    }
    .await
    {
        warn!("IPC: failed to send version handshake: {}", e);
        return;
    }
    let mut remote = [0u8; 4];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut remote)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            warn!("IPC: failed to read Controller version: {}", e);
            return;
        }
        Err(_) => {
            warn!("IPC: Controller version handshake timed out");
            return;
        }
    }
    let remote = u32::from_be_bytes(remote);
    let (rmaj, rmin, rpat) = msst_ipc_protocol::version::decode_version(remote);
    if !msst_ipc_protocol::version::is_compatible(remote) {
        let (maj, min, pat) = msst_ipc_protocol::version::decode_version(PROTOCOL_VERSION);
        warn!(
            "IPC: incompatible Controller {}.{}.{} (Core {}.{}.{}), closing",
            rmaj, rmin, rpat, maj, min, pat
        );
        // Best effort: say why before closing (0.4).  A Controller of another
        // major version may not understand it; it then just sees EOF.
        let why = IpcMessage::Response {
            id: "handshake".into(),
            body: IpcResponse::Error(msst_ipc_protocol::IpcError {
                code: "incompatible_version".into(),
                message: format!("Core speaks protocol {}.{}.{}; Controller sent {}.{}.{}", maj, min, pat, rmaj, rmin, rpat),
            }),
            event_seq: None,
        };
        if let Ok(json) = serde_json::to_string(&why) {
            let _ = write_frame(&mut stream, &json).await;
        }
        return;
    }
    info!("IPC: Controller protocol {}.{}.{}", rmaj, rmin, rpat);

    let Some(role) = authorize(&stream) else {
        warn!("IPC: connection refused after handshake");
        return;
    };
    let session = Arc::new(Session::new(role));
    let (mut reader, mut writer) = tokio::io::split(stream);

    // ── Single writer: responses and events share one ordered queue ──────
    let (out_tx, mut out_rx) = mpsc::channel::<IpcMessage>(CLIENT_QUEUE);
    // Anything that must end the connection (lagging client, oversized
    // event, write error) flips this.
    let (close_tx, mut close_rx) = watch::channel(false);
    let writer_close = close_tx.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let Some(json) = encode_outgoing(msg) else {
                // An event can't be replaced without a gap: make the client
                // reconnect and re-snapshot.
                let _ = writer_close.send(true);
                break;
            };
            if let Err(e) = write_frame(&mut writer, &json).await {
                debug!("IPC: write failed: {}", e);
                let _ = writer_close.send(true);
                break;
            }
        }
    });

    // ── Event forwarder; closes the connection if the client lags ────────
    let event_out = out_tx.clone();
    let event_task = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(ev) => match event_out.try_send(IpcMessage::Event { body: ev.event, seq: Some(ev.seq) }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        warn!("IPC: client not reading (queue full); disconnecting so it re-snapshots");
                        let _ = close_tx.send(true);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                },
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("IPC: client lagged {} event(s); disconnecting so it re-snapshots", n);
                    let _ = close_tx.send(true);
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // ── Log lines: best effort, never a reason to disconnect ─────────────
    let log_out = out_tx.clone();
    let mut logs = crate::logcapture::subscribe();
    let log_session = session.clone();
    let log_task = tokio::spawn(async move {
        loop {
            match logs.recv().await {
                Ok(_) if !log_session.log_stream.load(Ordering::Relaxed) => continue,
                Ok(e) => {
                    // Leave at least half the queue for responses and state
                    // events; excess log lines are simply not forwarded.
                    if log_out.capacity() < CLIENT_QUEUE / 2 {
                        continue;
                    }
                    let ev = IpcEvent::Diagnostic { level: e.level, target: e.target, message: e.message, timestamp_ms: e.timestamp_ms };
                    if let Err(mpsc::error::TrySendError::Closed(_)) = log_out.try_send(IpcMessage::Event { body: ev, seq: None }) {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // ── Command runner: commands run one at a time, in arrival order ─────
    let closed = Arc::new(AtomicBool::new(false));
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<(String, IpcRequest, bool)>(COMMAND_QUEUE);
    let cmd_task = {
        let (state, session, out, closed) = (state.clone(), session.clone(), out_tx.clone(), closed.clone());
        tokio::spawn(async move {
            while let Some((id, body, run_async)) = cmd_rx.recv().await {
                if closed.load(Ordering::SeqCst) {
                    debug!("IPC: client gone; not starting queued command {}", id);
                    continue;
                }
                if !run_async {
                    let msg = respond(&state, &session, id, body).await;
                    let _ = out.send(msg).await;
                    continue;
                }
                // Background operation: answer "accepted" first, then start
                // it, so its OperationCompleted can't overtake the answer.
                let event_seq = Some(state.events.last_seq());
                let (body, go) = match ops::start(&state, session.clone(), body) {
                    Ok((op, go)) => (IpcResponse::ok(&msst_ipc_protocol::views::OperationAccepted { operation_id: op }), Some(go)),
                    Err(e) => (IpcResponse::Error(e), None),
                };
                let _ = out.send(IpcMessage::Response { id, body, event_seq }).await;
                if let Some(go) = go {
                    let _ = go.send(());
                }
            }
        })
    };
    // Queries run concurrently, at most MAX_INFLIGHT_QUERIES at a time.
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_QUERIES));
    let mut queries = tokio::task::JoinSet::new();

    // ── Request loop ─────────────────────────────────────────────────────
    loop {
        while queries.try_join_next().is_some() {}
        let frame = tokio::select! {
            f = read_frame(&mut reader) => f,
            _ = close_rx.changed() => break,
        };
        let json = match frame {
            Ok(j) => j,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    warn!("IPC read error: {}", e);
                }
                break;
            }
        };
        match serde_json::from_str::<IpcMessage>(&json) {
            Ok(IpcMessage::Request { id, body, r#async }) => {
                if body.kind() == RequestKind::Command {
                    // Backpressure: reading pauses while the queue is full.
                    if cmd_tx.send((id, body, r#async)).await.is_err() {
                        break;
                    }
                    continue;
                }
                let Ok(permit) = inflight.clone().acquire_owned().await else { break };
                let (state, session, out) = (state.clone(), session.clone(), out_tx.clone());
                queries.spawn(async move {
                    let msg = respond(&state, &session, id, body).await;
                    let _ = out.send(msg).await;
                    drop(permit);
                });
            }
            Ok(_) => debug!("IPC: ignoring non-request message from Controller"),
            Err(e) => {
                warn!("IPC: malformed message: {}", e);
                // Answer with a structured error if we can recover the id.
                if let Some(id) = serde_json::from_str::<serde_json::Value>(&json)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|i| i.as_str()).map(str::to_string))
                {
                    let body = msst_ipc_protocol::IpcResponse::Error(msst_ipc_protocol::IpcError {
                        code: "invalid_request".into(),
                        message: e.to_string(),
                    });
                    if out_tx.send(IpcMessage::Response { id, body, event_seq: None }).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    // Queries are read-only: abort them.  The running command finishes
    // (aborting it could leave half-applied state); queued ones are skipped.
    closed.store(true, Ordering::SeqCst);
    queries.abort_all();
    drop(cmd_tx);
    drop(cmd_task);
    event_task.abort();
    log_task.abort();
    drop(out_tx);
    // Let queued responses flush, but don't hang on a stuck peer.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), writer_task).await;
}

/// Serialize an outgoing message within [`MAX_FRAME_LEN`].  An oversized
/// response becomes a `response_too_large` error (same `id`); an oversized
/// event, or one that can't be serialized, gives `None` (close).
fn encode_outgoing(msg: IpcMessage) -> Option<String> {
    let json = match serde_json::to_string(&msg) {
        Ok(j) => j,
        Err(e) => {
            error!("IPC: failed to serialize outgoing message: {}", e);
            return None;
        }
    };
    if json.len() <= MAX_FRAME_LEN {
        return Some(json);
    }
    match msg {
        IpcMessage::Response { id, event_seq, .. } => {
            warn!("IPC: response {} is {} bytes (limit {}); sending an error instead", id, json.len(), MAX_FRAME_LEN);
            let body = IpcResponse::Error(msst_ipc_protocol::IpcError {
                code: "response_too_large".into(),
                message: format!("response is {} bytes; the limit is {}", json.len(), MAX_FRAME_LEN),
            });
            serde_json::to_string(&IpcMessage::Response { id, body, event_seq }).ok()
        }
        _ => {
            warn!("IPC: event of {} bytes exceeds the frame limit; disconnecting so the client re-snapshots", json.len());
            None
        }
    }
}

/// Handle one request and build its response frame.
async fn respond(state: &Arc<CoreState>, session: &Session, id: String, body: IpcRequest) -> IpcMessage {
    // Snapshot point: read before the handler looks at state.
    let event_seq = Some(state.events.last_seq());
    let body = handle_request(body, state, session).await;
    IpcMessage::Response { id, body, event_seq }
}

// ---------------------------------------------------------------------------
// Frame I/O
// ---------------------------------------------------------------------------

/// Read a single length-prefixed JSON frame from the stream.
async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> std::io::Result<String> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {} bytes", len),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    String::from_utf8(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Write a single length-prefixed JSON frame to the stream.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, json: &str) -> std::io::Result<()> {
    writer.write_all(&(json.len() as u32).to_be_bytes()).await?;
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_round_trip() {
        let payload = r#"{"kind":"request","id":"test-1","body":{"type":"health"}}"#;
        let mut buf = Vec::new();
        write_frame(&mut std::io::Cursor::new(&mut buf), payload).await.unwrap();

        let mut reader = std::io::Cursor::new(buf);
        let result = read_frame(&mut reader).await.unwrap();
        assert_eq!(result, payload);
    }

    #[tokio::test]
    async fn frame_too_large() {
        // Write a frame claiming 2MB.
        let mut buf = Vec::new();
        buf.extend_from_slice(&2_000_000u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 100]); // not enough data

        let mut reader = std::io::Cursor::new(buf);
        let result = read_frame(&mut reader).await;
        assert!(result.is_err()); // should fail (too large or not enough data)
    }

    #[tokio::test]
    async fn invalid_utf8_frame() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC, 0xFB]); // invalid UTF-8

        let mut reader = std::io::Cursor::new(buf);
        let result = read_frame(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn multiple_frames() {
        let frames = [
            r#"{"kind":"request","id":"1","body":{"type":"health"}}"#,
            r#"{"kind":"request","id":"2","body":{"type":"get_nodes"}}"#,
            r#"{"kind":"event","body":{"type":"node_added","data":{"device_id":"dev-1","ipv4":"1.2.3.4","ipv6":"::1","hostname":null,"display_name":null}}}"#,
        ];

        let mut buf = Vec::new();
        {
            let mut writer = std::io::Cursor::new(&mut buf);
            for frame in &frames {
                write_frame(&mut writer, frame).await.unwrap();
            }
        }

        let mut reader = std::io::Cursor::new(&buf);
        for expected in &frames {
            let result = read_frame(&mut reader).await.unwrap();
            assert_eq!(&result, expected);
        }
    }

    #[test]
    fn ipc_message_serialization_round_trip() {
        let msg = IpcMessage::Request {
            id: "test-1".into(),
            body: IpcRequest::Health,
            r#async: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: IpcMessage = serde_json::from_str(&json).unwrap();
        match back {
            IpcMessage::Request { id, body, .. } => {
                assert_eq!(id, "test-1");
                assert!(matches!(body, IpcRequest::Health));
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn ipc_response_serialization() {
        let msg = IpcMessage::Response {
            id: "test-1".into(),
            body: IpcResponse::Ok(serde_json::json!({"status": "ok"})),
            event_seq: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: IpcMessage = serde_json::from_str(&json).unwrap();
        match back {
            IpcMessage::Response { id, body, .. } => {
                assert_eq!(id, "test-1");
                assert!(matches!(body, IpcResponse::Ok(_)));
            }
            _ => panic!("expected Response"),
        }
    }

    // ── serve_client over an in-memory duplex stream ─────────────────────

    async fn test_state() -> (Arc<CoreState>, Arc<CoreState>) {
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let state = Arc::new(CoreState::new(udp, std::env::temp_dir()));
        (state.clone(), state)
    }

    /// Connect a fake Controller; returns its stream after the handshake.
    async fn connect(
        state: Arc<CoreState>,
        events: &Arc<CoreState>,
        version: u32,
    ) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        connect_as(state, events, version, Role::Admin).await
    }

    async fn connect_as(
        state: Arc<CoreState>,
        events: &Arc<CoreState>,
        version: u32,
        role: Role,
    ) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(serve_client(server, state, events.events.subscribe(), move |_| Some(role)));
        let mut v = [0u8; 4];
        client.read_exact(&mut v).await.unwrap();
        assert_eq!(u32::from_be_bytes(v), PROTOCOL_VERSION);
        client.write_all(&version.to_be_bytes()).await.unwrap();
        (client, task)
    }

    async fn request(client: &mut tokio::io::DuplexStream, id: &str, body: IpcRequest) {
        let msg = IpcMessage::Request { id: id.into(), body, r#async: false };
        write_frame(client, &serde_json::to_string(&msg).unwrap()).await.unwrap();
    }

    /// Next non-log message (log lines from concurrently running tests may
    /// be interleaved).
    async fn next(client: &mut tokio::io::DuplexStream) -> IpcMessage {
        loop {
            let json = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(client))
                .await.expect("timed out").unwrap();
            let msg: IpcMessage = serde_json::from_str(&json).unwrap();
            if !matches!(msg, IpcMessage::Event { body: IpcEvent::Diagnostic { .. }, .. }) {
                return msg;
            }
        }
    }

    #[tokio::test]
    async fn request_gets_response_with_same_id() {
        let (state, events) = test_state().await;
        let (mut client, _t) = connect(state, &events, PROTOCOL_VERSION).await;
        request(&mut client, "req-1", IpcRequest::Health).await;
        request(&mut client, "req-2", IpcRequest::GetNodes).await;
        // Queries run concurrently: either order.
        let mut ids = Vec::new();
        for _ in 0..2 {
            match next(&mut client).await {
                IpcMessage::Response { id, body: IpcResponse::Ok(v), event_seq } => {
                    assert!(event_seq.is_some());
                    if id == "req-1" {
                        assert_eq!(v["status"], "ok");
                    }
                    ids.push(id);
                }
                other => panic!("expected Response, got {:?}", other),
            }
        }
        ids.sort();
        assert_eq!(ids, ["req-1", "req-2"]);
    }

    /// A coordinator that accepts connections and never answers.
    async fn hanging_coordinator(state: &Arc<CoreState>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let (tx, rx) = mpsc::channel(1);
        std::mem::forget(rx);
        let client = crate::coordinator::CoordinatorClient::new(crate::coordinator::CoordinatorConfig { coord_url: url }, tx);
        let _ = state.coordinator.set(Arc::new(client));
    }

    #[tokio::test]
    async fn slow_command_does_not_block_queries() {
        let (state, events) = test_state().await;
        hanging_coordinator(&state).await;
        let (mut client, _t) = connect(state, &events, PROTOCOL_VERSION).await;
        // CreateRoom first re-selects the relay: GET /relays hangs.
        request(&mut client, "slow", IpcRequest::CreateRoom { room_name: "r".into(), password: None }).await;
        request(&mut client, "health", IpcRequest::Health).await;
        assert!(matches!(next(&mut client).await, IpcMessage::Response { id, .. } if id == "health"));
    }

    #[tokio::test]
    async fn commands_run_in_order() {
        let (state, events) = test_state().await;
        let (mut client, _t) = connect(state.clone(), &events, PROTOCOL_VERSION).await;
        for (i, on) in [true, false, true, false].into_iter().enumerate() {
            request(&mut client, &format!("c{}", i), IpcRequest::SetPingEnabled { enabled: on }).await;
        }
        let mut ids = Vec::new();
        while ids.len() < 4 {
            if let IpcMessage::Response { id, .. } = next(&mut client).await {
                ids.push(id);
            }
        }
        assert_eq!(ids, ["c0", "c1", "c2", "c3"]);
        assert!(!state.net.read().await.ping_enabled);
    }

    #[tokio::test]
    async fn events_carry_contiguous_seq_and_responses_the_snapshot_point() {
        let (state, events) = test_state().await;
        let (mut client, _t) = connect(state.clone(), &events, PROTOCOL_VERSION).await;
        let base = state.events.last_seq();
        state.emit_ipc_event(IpcEvent::NodeRemoved { device_id: "a".into() });
        state.emit_ipc_event(IpcEvent::NodeRemoved { device_id: "b".into() });
        let mut seqs = Vec::new();
        while seqs.len() < 2 {
            if let IpcMessage::Event { seq: Some(seq), body: IpcEvent::NodeRemoved { .. } } = next(&mut client).await {
                seqs.push(seq);
            }
        }
        assert_eq!(seqs, [base + 1, base + 2]);
        request(&mut client, "h", IpcRequest::Health).await;
        match next(&mut client).await {
            IpcMessage::Response { event_seq, .. } => assert_eq!(event_seq, Some(base + 2)),
            other => panic!("{:?}", other),
        }
    }

    #[tokio::test]
    async fn events_are_pushed_as_event_frames() {
        let (state, events) = test_state().await;
        let (mut client, _t) = connect(state, &events, PROTOCOL_VERSION).await;
        events.emit_ipc_event(IpcEvent::CoordinatorConnectionChanged { connected: true });
        assert!(matches!(
            next(&mut client).await,
            IpcMessage::Event { body: IpcEvent::CoordinatorConnectionChanged { connected: true }, .. }
        ));
    }

    #[tokio::test]
    async fn malformed_request_with_id_gets_error_response() {
        let (state, events) = test_state().await;
        let (mut client, _t) = connect(state, &events, PROTOCOL_VERSION).await;
        write_frame(&mut client, r#"{"kind":"request","id":"bad-1","body":{"type":"no_such_request"}}"#)
            .await.unwrap();
        match next(&mut client).await {
            IpcMessage::Response { id, body: IpcResponse::Error(e), .. } => {
                assert_eq!(id, "bad-1");
                assert_eq!(e.code, "invalid_request");
            }
            other => panic!("expected error Response, got {:?}", other),
        }
        // The connection is still usable.
        request(&mut client, "ok-1", IpcRequest::Health).await;
        assert!(matches!(next(&mut client).await, IpcMessage::Response { id, .. } if id == "ok-1"));
    }

    #[tokio::test]
    async fn incompatible_version_is_disconnected() {
        let (state, events) = test_state().await;
        let bad = msst_ipc_protocol::version::make_version(9, 0, 0);
        let (mut client, task) = connect(state, &events, bad).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), task).await.unwrap().unwrap();
        // Core says why, then closes.
        let why: IpcMessage = serde_json::from_str(&read_frame(&mut client).await.unwrap()).unwrap();
        match why {
            IpcMessage::Response { id, body: IpcResponse::Error(e), .. } => {
                assert_eq!(id, "handshake");
                assert_eq!(e.code, "incompatible_version");
            }
            other => panic!("{:?}", other),
        }
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0); // EOF
    }

    #[tokio::test]
    async fn lagging_client_is_disconnected() {
        let (state, events) = test_state().await;
        let (client, task) = connect(state, &events, PROTOCOL_VERSION).await;
        // Never read: the duplex buffer fills, the client queue fills, and the
        // broadcast receiver (capacity 4) lags.
        let big = "x".repeat(16 * 1024);
        for _ in 0..(CLIENT_QUEUE + 64) {
            events.emit_ipc_event(IpcEvent::Diagnostic {
                level: "info".into(), target: "t".into(), message: big.clone(), timestamp_ms: 0,
            });
            tokio::task::yield_now().await;
        }
        tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await.expect("lagging client was not disconnected").unwrap();
        drop(client);
    }

    #[tokio::test]
    async fn log_lines_are_streamed_as_diagnostic_events() {
        let _serial = crate::logcapture::TEST_LOCK.lock().await;
        let (state, events) = test_state().await;
        let (mut client, _t) = connect(state, &events, PROTOCOL_VERSION).await;
        // Make sure the per-client log subscription is live.
        request(&mut client, "r", IpcRequest::Health).await;
        let _ = next(&mut client).await;
        crate::logcapture::record(crate::logcapture::LogEntry {
            level: "info".into(), target: "test".into(), message: "hello-from-core".into(), timestamp_ms: 1,
        });
        let mut seen = false;
        for _ in 0..50 {
            let json = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut client)).await.unwrap().unwrap();
            if json.contains("hello-from-core") {
                seen = true;
                break;
            }
        }
        assert!(seen);
    }

    #[tokio::test]
    async fn viewer_may_query_but_not_command() {
        let (state, events) = test_state().await;
        let (mut client, _t) = connect_as(state, &events, PROTOCOL_VERSION, Role::Viewer).await;
        request(&mut client, "q", IpcRequest::Health).await;
        match next(&mut client).await {
            IpcMessage::Response { id, body: IpcResponse::Ok(v), .. } => {
                assert_eq!(id, "q");
                assert_eq!(v["ipc_role"], "viewer");
            }
            other => panic!("expected Health, got {:?}", other),
        }
        request(&mut client, "c", IpcRequest::ClearAclRules).await;
        match next(&mut client).await {
            IpcMessage::Response { id, body: IpcResponse::Error(e), .. } => {
                assert_eq!(id, "c");
                assert_eq!(e.code, "permission_denied");
            }
            other => panic!("expected permission_denied, got {:?}", other),
        }
        // Session requests are allowed and the connection stays usable.
        request(&mut client, "s", IpcRequest::SetLogStream { enabled: false }).await;
        assert!(matches!(next(&mut client).await, IpcMessage::Response { id, body: IpcResponse::Ok(_), .. } if id == "s"));
    }

    #[tokio::test]
    async fn refused_after_handshake_is_closed() {
        let (state, events) = test_state().await;
        let (mut client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(serve_client(server, state, events.events.subscribe(), |_| None));
        let mut v = [0u8; 4];
        client.read_exact(&mut v).await.unwrap();
        client.write_all(&PROTOCOL_VERSION.to_be_bytes()).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), task).await.unwrap().unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn async_command_answers_first_then_completes() {
        let (state, events) = test_state().await;
        let (mut client, _t) = connect(state.clone(), &events, PROTOCOL_VERSION).await;
        let msg = IpcMessage::Request { id: "a".into(), body: IpcRequest::SetPingEnabled { enabled: true }, r#async: true };
        write_frame(&mut client, &serde_json::to_string(&msg).unwrap()).await.unwrap();
        let op = match next(&mut client).await {
            IpcMessage::Response { id, body: IpcResponse::Ok(v), .. } if id == "a" => v["operation_id"].as_str().unwrap().to_string(),
            other => panic!("expected the accepted response first, got {:?}", other),
        };
        loop {
            if let IpcMessage::Event { body: IpcEvent::OperationCompleted { operation_id, result, .. }, .. } = next(&mut client).await {
                assert_eq!(operation_id, op);
                assert!(matches!(result, IpcResponse::Ok(_)));
                break;
            }
        }
        request(&mut client, "g", IpcRequest::GetOperation { operation_id: op }).await;
        match next(&mut client).await {
            IpcMessage::Response { body: IpcResponse::Ok(v), .. } => assert_eq!(v["status"], "completed"),
            other => panic!("{:?}", other),
        }
        // `async` on a query is ignored: answered normally.
        let msg = IpcMessage::Request { id: "q".into(), body: IpcRequest::Health, r#async: true };
        write_frame(&mut client, &serde_json::to_string(&msg).unwrap()).await.unwrap();
        match next(&mut client).await {
            IpcMessage::Response { id, body: IpcResponse::Ok(v), .. } => assert_eq!((id.as_str(), &v["status"]), ("q", &serde_json::json!("ok"))),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn oversized_outgoing_frames() {
        let big = serde_json::json!({ "x": "y".repeat(MAX_FRAME_LEN) });
        let resp = IpcMessage::Response { id: "r".into(), body: IpcResponse::Ok(big.clone()), event_seq: Some(3) };
        let out: IpcMessage = serde_json::from_str(&encode_outgoing(resp).unwrap()).unwrap();
        match out {
            IpcMessage::Response { id, body: IpcResponse::Error(e), event_seq } => {
                assert_eq!((id.as_str(), e.code.as_str(), event_seq), ("r", "response_too_large", Some(3)));
            }
            other => panic!("{:?}", other),
        }
        let ev = IpcMessage::Event { body: IpcEvent::NodeStateChanged { device_id: "d".into(), change: big }, seq: Some(1) };
        assert!(encode_outgoing(ev).is_none(), "oversized event closes the connection");
        let small = IpcMessage::Event { body: IpcEvent::NodeRemoved { device_id: "d".into() }, seq: Some(2) };
        assert!(encode_outgoing(small).is_some());
    }
}
