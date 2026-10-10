//! IPC server — the Controller ↔ Core communication layer.
//!
//! Replaces the 3.0.x split design (push-only IPC socket + separate HTTP
//! API) with a unified request/response/event model over one transport.
//!
//! ## Transport
//!
//! - **Linux/macOS**: Unix domain socket (`/run/msst-net/ipc.sock` as root),
//!   access checked by peer UID (`auth.rs`)
//! - **Windows**: named pipe `\\.\pipe\msst-net-ipc`, access restricted by
//!   its ACL (`windows_pipe.rs`)
//!
//! The protocol layer (`serve_client`) is generic over any
//! `AsyncRead + AsyncWrite` stream; transports only accept connections and
//! enforce access control.
//!
//! ## Connection lifecycle
//!
//! ```text
//! accept → authorize peer (Unix: SO_PEERCRED UID check)
//!        → version handshake (u32 BE both ways; incompatible → close)
//!        → frames: [len: u32 BE][JSON IpcMessage]
//!             Controller → Core: Request{id}
//!             Core → Controller: Response{id} (same id) | Event
//! ```
//!
//! Requests on one connection are handled in order; each gets exactly one
//! `Response` with the request's `id`.  Events are pushed as they occur.
//! A client that falls too far behind on events (its queue is full or the
//! broadcast channel overflowed) is disconnected, so it reconnects and
//! rebuilds its state from a fresh snapshot instead of silently missing
//! events.  Event delivery never blocks Core.

#[cfg(unix)]
pub mod auth;
mod handler;
#[cfg(windows)]
mod windows_pipe;

use crate::state::CoreState;
use handler::handle_request;
use msst_ipc_protocol::version::PROTOCOL_VERSION;
use msst_ipc_protocol::{IpcEvent, IpcMessage};
#[cfg(test)]
use msst_ipc_protocol::{IpcRequest, IpcResponse};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug, error, info, warn};

/// Maximum accepted frame size.
const MAX_FRAME_LEN: usize = 1024 * 1024;
/// Time the Controller has to send its version.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Per-client outgoing queue depth (responses + events).
const CLIENT_QUEUE: usize = 256;

// ---------------------------------------------------------------------------
// IpcServer
// ---------------------------------------------------------------------------

/// The IPC server — accepts Controller connections and fans events out.
pub struct IpcServer {
    /// Shared Core state (passed to request handlers).
    state: Arc<CoreState>,
    /// Broadcast channel for pushing events to all connected clients.
    event_tx: broadcast::Sender<IpcEvent>,
    /// Events produced by the rest of Core (`CoreState::emit_ipc_event`).
    event_rx: mpsc::Receiver<IpcEvent>,
}

impl IpcServer {
    /// Create a new IPC server.
    pub fn new(
        state: Arc<CoreState>,
        event_rx: mpsc::Receiver<IpcEvent>,
    ) -> (Self, broadcast::Receiver<IpcEvent>) {
        let (event_tx, subscriber) = broadcast::channel(256);
        (IpcServer { state, event_tx, event_rx }, subscriber)
    }

    /// Drain Core's event queue into the broadcast channel.  Runs even when
    /// no Controller is connected, so Core never blocks on IPC.
    fn spawn_event_pump(event_tx: broadcast::Sender<IpcEvent>, mut event_rx: mpsc::Receiver<IpcEvent>) {
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let _ = event_tx.send(event); // Err = no subscribers; fine.
            }
            debug!("IPC event pump exited");
        });
    }

    /// Run the IPC server on a Unix domain socket.
    #[cfg(unix)]
    pub async fn run_unix(self, socket_path: &std::path::Path) {
        if let Some(parent) = socket_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                error!("IPC: cannot create socket directory {:?}: {}", parent, e);
                return;
            }
            if unsafe { libc::geteuid() } == 0 {
                auth::secure_socket_dir(parent);
            }
        }
        let _ = std::fs::remove_file(socket_path); // stale socket

        let listener = match tokio::net::UnixListener::bind(socket_path) {
            Ok(l) => l,
            Err(e) => {
                error!("IPC: cannot bind socket {:?}: {}", socket_path, e);
                return;
            }
        };
        auth::set_socket_permissions(socket_path);
        info!("IPC server listening on {:?}", socket_path);

        Self::spawn_event_pump(self.event_tx.clone(), self.event_rx);

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
            if !auth::is_peer_authorized(uid) {
                warn!("IPC: rejected connection from unauthorized uid={}", uid);
                continue; // dropping the stream closes it
            }
            let peer = format!("uid={}", uid);
            info!("IPC client connected ({})", peer);
            let state = self.state.clone();
            let events = self.event_tx.subscribe();
            tokio::spawn(async move {
                serve_client(stream, state, events).await;
                info!("IPC client disconnected ({})", peer);
            });
        }
    }

    /// Run the IPC server on a Windows named pipe.
    #[cfg(windows)]
    pub async fn run_named_pipe(self, pipe_name: &str) {
        let mut server = match windows_pipe::create_instance(pipe_name, true) {
            Ok(s) => s,
            Err(e) => {
                error!("IPC: cannot create named pipe {} (already in use?): {}", pipe_name, e);
                return;
            }
        };
        info!("IPC server listening on {}", pipe_name);
        Self::spawn_event_pump(self.event_tx.clone(), self.event_rx);
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
            let events = self.event_tx.subscribe();
            tokio::spawn(async move {
                serve_client(connected, state, events).await;
                info!("IPC client disconnected (named pipe)");
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Per-client protocol handling (transport-independent)
// ---------------------------------------------------------------------------

/// Serve one authorized Controller connection until it closes.
pub async fn serve_client<S>(stream: S, state: Arc<CoreState>, mut events: broadcast::Receiver<IpcEvent>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    // ── Version handshake: both sides send first, then read ──────────────
    if let Err(e) = async {
        writer.write_all(&PROTOCOL_VERSION.to_be_bytes()).await?;
        writer.flush().await
    }
    .await
    {
        warn!("IPC: failed to send version handshake: {}", e);
        return;
    }
    let mut remote = [0u8; 4];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut remote)).await {
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
        return;
    }
    info!("IPC: Controller protocol {}.{}.{}", rmaj, rmin, rpat);

    // ── Single writer: responses and events share one ordered queue ──────
    let (out_tx, mut out_rx) = mpsc::channel::<IpcMessage>(CLIENT_QUEUE);
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let json = match serde_json::to_string(&msg) {
                Ok(j) => j,
                Err(e) => {
                    error!("IPC: failed to serialize outgoing message: {}", e);
                    continue;
                }
            };
            if let Err(e) = write_frame(&mut writer, &json).await {
                debug!("IPC: write failed: {}", e);
                break;
            }
        }
    });

    // ── Event forwarder; closes the connection if the client lags ────────
    let (close_tx, mut close_rx) = oneshot::channel::<()>();
    let event_out = out_tx.clone();
    let event_task = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => match event_out.try_send(IpcMessage::Event { body: event }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        warn!("IPC: client not reading (queue full); disconnecting so it re-snapshots");
                        let _ = close_tx.send(());
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                },
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("IPC: client lagged {} event(s); disconnecting so it re-snapshots", n);
                    let _ = close_tx.send(());
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // ── Log lines: best effort, never a reason to disconnect ─────────────
    let log_out = out_tx.clone();
    let mut logs = crate::logcapture::subscribe();
    let log_task = tokio::spawn(async move {
        loop {
            match logs.recv().await {
                Ok(e) => {
                    // Leave at least half the queue for responses and state
                    // events; excess log lines are simply not forwarded.
                    if log_out.capacity() < CLIENT_QUEUE / 2 {
                        continue;
                    }
                    let ev = IpcEvent::Diagnostic { level: e.level, target: e.target, message: e.message, timestamp_ms: e.timestamp_ms };
                    if let Err(mpsc::error::TrySendError::Closed(_)) = log_out.try_send(IpcMessage::Event { body: ev }) {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // ── Request loop ─────────────────────────────────────────────────────
    loop {
        let frame = tokio::select! {
            f = read_frame(&mut reader) => f,
            _ = &mut close_rx => break,
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
            Ok(IpcMessage::Request { id, body }) => {
                let response = handle_request(body, &state).await;
                if out_tx.send(IpcMessage::Response { id, body: response }).await.is_err() {
                    break; // writer gone
                }
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
                    if out_tx.send(IpcMessage::Response { id, body }).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    event_task.abort();
    log_task.abort();
    drop(out_tx);
    // Let queued responses flush, but don't hang on a stuck peer.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), writer_task).await;
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
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: IpcMessage = serde_json::from_str(&json).unwrap();
        match back {
            IpcMessage::Request { id, body } => {
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
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: IpcMessage = serde_json::from_str(&json).unwrap();
        match back {
            IpcMessage::Response { id, body } => {
                assert_eq!(id, "test-1");
                assert!(matches!(body, IpcResponse::Ok(_)));
            }
            _ => panic!("expected Response"),
        }
    }

    // ── serve_client over an in-memory duplex stream ─────────────────────

    async fn test_state() -> (Arc<CoreState>, broadcast::Sender<IpcEvent>) {
        let (ipc_tx, _ipc_rx) = mpsc::channel(8);
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let state = Arc::new(CoreState::new(ipc_tx, udp, std::env::temp_dir()));
        let (event_tx, _) = broadcast::channel(4);
        (state, event_tx)
    }

    /// Connect a fake Controller; returns its stream after the handshake.
    async fn connect(
        state: Arc<CoreState>,
        events: &broadcast::Sender<IpcEvent>,
        version: u32,
    ) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(serve_client(server, state, events.subscribe()));
        let mut v = [0u8; 4];
        client.read_exact(&mut v).await.unwrap();
        assert_eq!(u32::from_be_bytes(v), PROTOCOL_VERSION);
        client.write_all(&version.to_be_bytes()).await.unwrap();
        (client, task)
    }

    async fn request(client: &mut tokio::io::DuplexStream, id: &str, body: IpcRequest) {
        let msg = IpcMessage::Request { id: id.into(), body };
        write_frame(client, &serde_json::to_string(&msg).unwrap()).await.unwrap();
    }

    /// Next non-log message (log lines from concurrently running tests may
    /// be interleaved).
    async fn next(client: &mut tokio::io::DuplexStream) -> IpcMessage {
        loop {
            let json = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(client))
                .await.expect("timed out").unwrap();
            let msg: IpcMessage = serde_json::from_str(&json).unwrap();
            if !matches!(msg, IpcMessage::Event { body: IpcEvent::Diagnostic { .. } }) {
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
        match next(&mut client).await {
            IpcMessage::Response { id, body: IpcResponse::Ok(v) } => {
                assert_eq!(id, "req-1");
                assert_eq!(v["status"], "ok");
            }
            other => panic!("expected Response, got {:?}", other),
        }
        assert!(matches!(next(&mut client).await, IpcMessage::Response { id, .. } if id == "req-2"));
    }

    #[tokio::test]
    async fn events_are_pushed_as_event_frames() {
        let (state, events) = test_state().await;
        let (mut client, _t) = connect(state, &events, PROTOCOL_VERSION).await;
        events.send(IpcEvent::CoordinatorConnectionChanged { connected: true }).unwrap();
        assert!(matches!(
            next(&mut client).await,
            IpcMessage::Event { body: IpcEvent::CoordinatorConnectionChanged { connected: true } }
        ));
    }

    #[tokio::test]
    async fn malformed_request_with_id_gets_error_response() {
        let (state, events) = test_state().await;
        let (mut client, _t) = connect(state, &events, PROTOCOL_VERSION).await;
        write_frame(&mut client, r#"{"kind":"request","id":"bad-1","body":{"type":"no_such_request"}}"#)
            .await.unwrap();
        match next(&mut client).await {
            IpcMessage::Response { id, body: IpcResponse::Error(e) } => {
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
            let _ = events.send(IpcEvent::Diagnostic {
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
}
