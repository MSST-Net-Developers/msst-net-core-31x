//! Test helpers: a fake coordinator (HTTP + WebSocket on one port) and a
//! fake relay.  Test-only.

use crate::state::CoreState;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// A recorded HTTP request.
#[derive(Debug, Clone)]
pub struct HttpReq {
    pub method: String,
    pub path: String,
    pub body: Value,
    pub authorization: Option<String>,
}

type HttpHandler = Arc<dyn Fn(&HttpReq) -> (u16, Value) + Send + Sync>;
/// WS handler: given a client message, returns messages to send back.
type WsHandler = Arc<dyn Fn(&Value) -> Vec<Value> + Send + Sync>;

pub struct FakeCoordinator {
    pub url: String,
    pub http_log: Arc<Mutex<Vec<HttpReq>>>,
    pub ws_log: Arc<Mutex<Vec<Value>>>,
}

impl FakeCoordinator {
    pub async fn start(
        http: impl Fn(&HttpReq) -> (u16, Value) + Send + Sync + 'static,
        ws: impl Fn(&Value) -> Vec<Value> + Send + Sync + 'static,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let http_log = Arc::new(Mutex::new(Vec::new()));
        let ws_log = Arc::new(Mutex::new(Vec::new()));
        let (http, ws): (HttpHandler, WsHandler) = (Arc::new(http), Arc::new(ws));
        let (hl, wl) = (http_log.clone(), ws_log.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (http, ws, hl, wl) = (http.clone(), ws.clone(), hl.clone(), wl.clone());
                tokio::spawn(async move {
                    let mut peek = [0u8; 8];
                    let n = stream.peek(&mut peek).await.unwrap_or(0);
                    if peek[..n].starts_with(b"GET /ws") {
                        serve_ws(stream, ws, wl).await;
                    } else {
                        serve_http(stream, http, hl).await;
                    }
                });
            }
        });
        FakeCoordinator { url, http_log, ws_log }
    }

    pub fn ws_types(&self) -> Vec<String> {
        self.ws_log.lock().unwrap().iter().map(|m| m["type"].as_str().unwrap_or("").to_string()).collect()
    }
}

async fn serve_ws(stream: tokio::net::TcpStream, handler: WsHandler, log: Arc<Mutex<Vec<Value>>>) {
    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else { return };
    while let Some(Ok(msg)) = ws.next().await {
        if let Message::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
            log.lock().unwrap().push(v.clone());
            for reply in handler(&v) {
                if ws.send(Message::Text(reply.to_string().into())).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn serve_http(mut stream: tokio::net::TcpStream, handler: HttpHandler, log: Arc<Mutex<Vec<HttpReq>>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read headers, then the body by content-length.
    let header_end = loop {
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let content_length = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let req = HttpReq {
        method: first.next().unwrap_or("").to_string(),
        path: first.next().unwrap_or("").to_string(),
        body: serde_json::from_slice(&buf[header_end..]).unwrap_or(Value::Null),
        authorization: head
            .lines()
            .find_map(|l| l.to_ascii_lowercase().starts_with("authorization:").then(|| l[14..].trim().to_string())),
    };
    log.lock().unwrap().push(req.clone());
    let (status, body) = handler(&req);
    let body = body.to_string();
    let resp = format!(
        "HTTP/1.1 {} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

/// A UDP relay that echoes every datagram (answers relay RTT probes).
pub async fn echo_relay() -> std::net::SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], src).await;
        }
    });
    addr
}

/// A Core state with an identity, in its own temp data dir.
pub async fn core_state(name: &str) -> (Arc<CoreState>, mpsc::Receiver<msst_ipc_protocol::IpcEvent>) {
    let dir = std::env::temp_dir().join(format!("msst-test-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (ipc_tx, ipc_rx) = mpsc::channel(256);
    let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let state = Arc::new(CoreState::new(ipc_tx, udp, dir));
    let id = crate::identity::Identity {
        user: crate::identity::UserInfo { id: "user-00000001".into(), handle: String::new(), display_name: String::new() },
        device: crate::identity::DeviceInfo {
            id: "device-00000001".into(),
            handle: String::new(),
            display_name: String::new(),
            hostname: String::new(),
            assigned_ipv4: None,
        },
        secret_key: [1u8; 32],
        public_key: [2u8; 32],
        auth: None,
    };
    crate::identity::save(&state.data_dir, &id).unwrap();
    state.apply_identity(&id).await;
    (state, ipc_rx)
}

/// Poll `f` until true (2 s max).
pub async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if f() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    false
}
