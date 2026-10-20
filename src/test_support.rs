//! Test helpers: a fake coordinator (HTTP + WebSocket on one port) and a
//! fake relay.  Test-only.

use crate::state::CoreState;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
/// WS upgrade gate: given the bearer token (if any), accept (else 401).
type WsAuth = Arc<dyn Fn(Option<&str>) -> bool + Send + Sync>;

pub struct FakeCoordinator {
    pub url: String,
    pub http_log: Arc<Mutex<Vec<HttpReq>>>,
    pub ws_log: Arc<Mutex<Vec<Value>>>,
    /// Bearer token of every WS upgrade attempt, and whether it was accepted.
    pub ws_auth_log: Arc<Mutex<Vec<(Option<String>, bool)>>>,
}

impl FakeCoordinator {
    pub async fn start(
        http: impl Fn(&HttpReq) -> (u16, Value) + Send + Sync + 'static,
        ws: impl Fn(&Value) -> Vec<Value> + Send + Sync + 'static,
    ) -> Self {
        Self::start_with_ws_auth(http, ws, |_| true).await
    }

    /// Like [`start`](Self::start), but WS upgrades whose bearer token
    /// `ws_auth` refuses get HTTP 401 (as the Coordinator's `handleWS`).
    pub async fn start_with_ws_auth(
        http: impl Fn(&HttpReq) -> (u16, Value) + Send + Sync + 'static,
        ws: impl Fn(&Value) -> Vec<Value> + Send + Sync + 'static,
        ws_auth: impl Fn(Option<&str>) -> bool + Send + Sync + 'static,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let http_log = Arc::new(Mutex::new(Vec::new()));
        let ws_log = Arc::new(Mutex::new(Vec::new()));
        let ws_auth_log = Arc::new(Mutex::new(Vec::new()));
        let (http, ws, auth): (HttpHandler, WsHandler, WsAuth) = (Arc::new(http), Arc::new(ws), Arc::new(ws_auth));
        let (hl, wl, al) = (http_log.clone(), ws_log.clone(), ws_auth_log.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (http, ws, auth, hl, wl, al) = (http.clone(), ws.clone(), auth.clone(), hl.clone(), wl.clone(), al.clone());
                tokio::spawn(async move {
                    let mut peek = [0u8; 8];
                    let n = stream.peek(&mut peek).await.unwrap_or(0);
                    if peek[..n].starts_with(b"GET /ws") {
                        serve_ws(stream, ws, wl, auth, al).await;
                    } else {
                        serve_http(stream, http, hl).await;
                    }
                });
            }
        });
        FakeCoordinator { url, http_log, ws_log, ws_auth_log }
    }

    /// Bearer tokens of the accepted WS connections, in order.
    pub fn ws_accepted_tokens(&self) -> Vec<Option<String>> {
        self.ws_auth_log.lock().unwrap().iter().filter(|(_, ok)| *ok).map(|(t, _)| t.clone()).collect()
    }

    pub fn ws_types(&self) -> Vec<String> {
        self.ws_log.lock().unwrap().iter().map(|m| m["type"].as_str().unwrap_or("").to_string()).collect()
    }
}

async fn serve_ws(stream: tokio::net::TcpStream, handler: WsHandler, log: Arc<Mutex<Vec<Value>>>, auth: WsAuth, auth_log: Arc<Mutex<Vec<(Option<String>, bool)>>>) {
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    let gate = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let token = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_string);
        let ok = auth(token.as_deref());
        auth_log.lock().unwrap().push((token, ok));
        if ok {
            Ok(resp)
        } else {
            let mut e = ErrorResponse::new(Some("unauthorized".into()));
            *e.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::UNAUTHORIZED;
            Err(e)
        }
    };
    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, gate).await else { return };
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
pub async fn core_state(name: &str) -> (Arc<CoreState>, crate::state::EventReceiver) {
    let dir = std::env::temp_dir().join(format!("msst-test-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let state = Arc::new(CoreState::new(udp, dir));
    let ipc_rx = state.subscribe_events();
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

/// An identity whose IDs and public key are derived from `secret_key`
/// (what the Coordinator accepts).
pub fn identity_with_key(secret_key: [u8; 32]) -> crate::identity::Identity {
    let public_key = *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret_key)).as_bytes();
    crate::identity::Identity {
        user: crate::identity::UserInfo { id: crate::identity::derive_id(&public_key, "user"), handle: String::new(), display_name: String::new() },
        device: crate::identity::DeviceInfo {
            id: crate::identity::derive_id(&public_key, "device"),
            handle: String::new(),
            display_name: String::new(),
            hostname: String::new(),
            assigned_ipv4: None,
        },
        secret_key,
        public_key,
        auth: None,
    }
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
