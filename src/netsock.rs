//! Outbound sockets, with optional protection from the device's own VPN.
//!
//! On Android, Core runs inside the app that owns the VpnService.  With
//! "always-on VPN + block connections without VPN", every socket Core opens
//! must be passed to `VpnService.protect(fd)` first, or its traffic is
//! routed into the VPN (i.e. back into Core) or blocked.  The embedded API
//! installs a *protector* callback; every outbound socket Core creates goes
//! through this module:
//!
//! - UDP: [`udp_socket`] (data plane, discovery, relay probes, DNS upstream,
//!   diagnostic ping) and [`protect_std`] for one-off std sockets;
//! - TCP: [`connect_tcp`] (coordinator WebSocket);
//! - HTTP: [`http_client`] — `reqwest` can't take externally created
//!   sockets, so with a protector it goes through an in-process SOCKS5
//!   proxy on 127.0.0.1 whose upstream connections use [`connect_tcp`].
//!   The proxy requires per-process random credentials so other apps on the
//!   device can't use it to bypass the VPN.
//!
//! Without a protector (desktop) everything behaves like plain sockets and
//! `reqwest` connects directly.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

/// `VpnService.protect`-style callback: protect `fd`, return success.
pub type Protector = Arc<dyn Fn(i32) -> bool + Send + Sync>;

static PROTECTOR: OnceLock<Protector> = OnceLock::new();
static SOCKS: OnceLock<SocksProxy> = OnceLock::new();
/// Desktop: the proxy Coordinator HTTP goes through while
/// `crate::routing` bypasses other VPNs (see [`http_client`]).
static ROUTED: OnceLock<SocksProxy> = OnceLock::new();

/// Install the process-wide protector (embedded Core, once).
pub fn install_protector(p: Protector) {
    if PROTECTOR.set(p).is_err() {
        warn!("netsock: protector already installed");
    }
}

fn global() -> Option<&'static Protector> {
    PROTECTOR.get()
}

fn apply(protector: Option<&Protector>, fd: i32) -> std::io::Result<()> {
    match protector {
        None => Ok(()),
        Some(p) if p(fd) => Ok(()),
        Some(_) => Err(std::io::Error::other("VpnService.protect failed")),
    }
}

#[cfg(unix)]
fn raw_fd<T: std::os::fd::AsRawFd>(s: &T) -> i32 {
    s.as_raw_fd()
}
#[cfg(not(unix))]
fn raw_fd<T>(_s: &T) -> i32 {
    -1
}

/// Protect an already created std socket (e.g. a one-off probe).
pub fn protect_socket2(s: &socket2::Socket) -> std::io::Result<()> {
    apply(global(), raw_fd(s))
}

/// Protect a std UDP socket created elsewhere.
pub fn protect_std(s: &std::net::UdpSocket) -> std::io::Result<()> {
    apply(global(), raw_fd(s))
}

/// Bind an outbound UDP socket (protected) — replacement for
/// `tokio::net::UdpSocket::bind`.
pub async fn udp_socket(bind: SocketAddr) -> std::io::Result<UdpSocket> {
    udp_socket_with(global(), bind)
}

fn udp_socket_with(protector: Option<&Protector>, bind: SocketAddr) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))?;
    apply(protector, raw_fd(&s))?;
    crate::routing::mark_new_socket(&s);
    s.set_nonblocking(true)?;
    s.bind(&bind.into())?;
    UdpSocket::from_std(s.into())
}

/// The wildcard address of `target`'s family, port 0.
pub fn any_for(target: &SocketAddr) -> SocketAddr {
    if target.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() }
}

/// Connect a (protected) TCP stream to the first reachable address.
pub async fn connect_tcp(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    connect_tcp_with(global(), addrs).await
}

async fn connect_tcp_with(protector: Option<&Protector>, addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses");
    for &addr in addrs {
        let sock = if addr.is_ipv6() { tokio::net::TcpSocket::new_v6()? } else { tokio::net::TcpSocket::new_v4()? };
        apply(protector, raw_fd(&sock))?;
        // Before connect(): the route is chosen then.
        crate::routing::mark_new_socket(&sock);
        match sock.connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Resolve `host:port` and connect (protected).
pub async fn connect_host(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    connect_tcp(&addrs).await
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

/// The HTTP client Core uses for the coordinator.  With a protector, it is
/// routed through the authenticated local SOCKS5 proxy.  On the desktop,
/// while `crate::routing` bypasses other VPNs, through the routed proxy
/// (its upstream sockets carry the routing mark) — decided per request, so
/// the setting applies to new connections without a new client.
pub fn http_client() -> reqwest::Client {
    let routed: RoutedProxy = Arc::new(|| {
        crate::routing::bypass_active().then(|| ROUTED.get().map(SocksProxy::url)).flatten()
    });
    http_client_with(SOCKS.get().map(SocksProxy::url), routed)
}

/// Where HTTP goes now: a proxy URL, or `None` for a direct connection.
type RoutedProxy = Arc<dyn Fn() -> Option<String> + Send + Sync>;

fn http_client_with(protected: Option<String>, routed: RoutedProxy) -> reqwest::Client {
    let mut b = reqwest::Client::builder();
    if let Some(url) = protected {
        match reqwest::Proxy::all(url) {
            Ok(proxy) => b = b.proxy(proxy),
            Err(e) => warn!("netsock: invalid proxy url: {}", e),
        }
    } else {
        // Never follow HTTP(S)_PROXY env into a VPN loop.
        b = b.no_proxy().proxy(reqwest::Proxy::custom(move |_| routed()));
    }
    b.build().unwrap_or_else(|e| {
        warn!("netsock: HTTP client build failed ({}), using defaults", e);
        reqwest::Client::new()
    })
}

/// Start the protected SOCKS5 proxy (embedded Core, after
/// [`install_protector`]; needs a tokio runtime).
pub async fn start_protected_proxy() -> std::io::Result<()> {
    let Some(p) = global().cloned() else { return Ok(()) };
    if SOCKS.get().is_some() {
        return Ok(());
    }
    let proxy = SocksProxy::start(Some(p)).await?;
    info!("netsock: protected SOCKS5 proxy on {}", proxy.addr);
    let _ = SOCKS.set(proxy);
    Ok(())
}

/// Start the routed proxy (desktop, `crate::routing::enable`).  Upstream
/// connections go through [`connect_tcp_with`], which marks them.
pub async fn start_routed_proxy() -> std::io::Result<()> {
    if ROUTED.get().is_some() {
        return Ok(());
    }
    let proxy = SocksProxy::start(None).await?;
    debug!("netsock: routed SOCKS5 proxy on {}", proxy.addr);
    let _ = ROUTED.set(proxy);
    Ok(())
}

/// A minimal SOCKS5 server (RFC 1928 CONNECT + RFC 1929 user/password) on
/// loopback, connecting upstream through [`connect_tcp_with`].
pub struct SocksProxy {
    pub addr: SocketAddr,
    user: String,
    pass: String,
    /// Sessions accepted so far.
    pub sessions: Arc<std::sync::atomic::AtomicU64>,
}

impl SocksProxy {
    pub async fn start(protector: Option<Protector>) -> std::io::Result<SocksProxy> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let token = || format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        let (user, pass) = (token(), token());
        let (u, pw) = (user.clone(), pass.clone());
        let sessions = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter = sessions.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (u, pw, prot) = (u.clone(), pw.clone(), protector.clone());
                tokio::spawn(async move {
                    if let Err(e) = socks_session(client, &u, &pw, prot.as_ref()).await {
                        debug!("socks: session ended: {}", e);
                    }
                });
            }
        });
        Ok(SocksProxy { addr, user, pass, sessions })
    }

    /// `socks5h://user:pass@127.0.0.1:port` (proxy-side DNS).
    pub fn url(&self) -> String {
        format!("socks5h://{}:{}@{}", self.user, self.pass, self.addr)
    }
}

/// Constant-time comparison (no early exit on the first differing byte).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn socks_session(mut c: TcpStream, user: &str, pass: &str, protector: Option<&Protector>) -> std::io::Result<()> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    // Greeting: VER, NMETHODS, METHODS — require username/password (0x02).
    let mut hdr = [0u8; 2];
    c.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        return Err(bad("not SOCKS5"));
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    c.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        c.write_all(&[5, 0xFF]).await?;
        return Err(bad("client offers no username/password auth"));
    }
    c.write_all(&[5, 2]).await?;
    // RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD.
    let mut v = [0u8; 2];
    c.read_exact(&mut v).await?;
    let mut u = vec![0u8; v[1] as usize];
    c.read_exact(&mut u).await?;
    let mut pl = [0u8; 1];
    c.read_exact(&mut pl).await?;
    let mut p = vec![0u8; pl[0] as usize];
    c.read_exact(&mut p).await?;
    let ok = ct_eq(&u, user.as_bytes()) & ct_eq(&p, pass.as_bytes());
    c.write_all(&[1, if ok { 0 } else { 1 }]).await?;
    if !ok {
        return Err(bad("bad credentials"));
    }
    // Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT — CONNECT only.
    let mut req = [0u8; 4];
    c.read_exact(&mut req).await?;
    if req[1] != 1 {
        c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?; // command not supported
        return Err(bad("only CONNECT is supported"));
    }
    let target: Vec<SocketAddr> = match req[3] {
        1 => {
            let mut a = [0u8; 6];
            c.read_exact(&mut a).await?;
            vec![SocketAddr::from(([a[0], a[1], a[2], a[3]], u16::from_be_bytes([a[4], a[5]])))]
        }
        4 => {
            let mut a = [0u8; 18];
            c.read_exact(&mut a).await?;
            let ip: [u8; 16] = a[..16].try_into().unwrap();
            vec![SocketAddr::from((ip, u16::from_be_bytes([a[16], a[17]])))]
        }
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await?;
            let mut name = vec![0u8; l[0] as usize + 2];
            c.read_exact(&mut name).await?;
            let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
            let host = String::from_utf8_lossy(&name[..name.len() - 2]).into_owned();
            tokio::net::lookup_host((host.as_str(), port)).await?.collect()
        }
        _ => return Err(bad("bad address type")),
    };
    let mut upstream = match connect_tcp_with(protector, &target).await {
        Ok(s) => s,
        Err(e) => {
            c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?; // connection refused
            return Err(e);
        }
    };
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut c, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn recorder() -> (Protector, Arc<Mutex<Vec<i32>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        (Arc::new(move |fd| {
            s.lock().unwrap().push(fd);
            true
        }), seen)
    }

    #[tokio::test]
    async fn udp_and_tcp_sockets_are_protected_before_use() {
        let (p, seen) = recorder();
        let u = udp_socket_with(Some(&p), "127.0.0.1:0".parse().unwrap()).unwrap();
        assert_eq!(seen.lock().unwrap().as_slice(), &[raw_fd(&u)]);

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let t = connect_tcp_with(Some(&p), &[l.local_addr().unwrap()]).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 2);
        assert_eq!(seen.lock().unwrap()[1], raw_fd(&t));

        // A failing protector fails the socket instead of leaking traffic.
        let deny: Protector = Arc::new(|_| false);
        assert!(udp_socket_with(Some(&deny), "127.0.0.1:0".parse().unwrap()).is_err());
        assert!(connect_tcp_with(Some(&deny), &[l.local_addr().unwrap()]).await.is_err());
    }

    /// Desktop: Coordinator HTTP uses the routed proxy exactly while the
    /// bypass is on, switching per request.
    #[tokio::test]
    async fn http_follows_the_routing_bypass_per_request() {
        let proxy = SocksProxy::start(None).await.unwrap();
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = server.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    let _ = s.read(&mut b).await;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
                });
            }
        });
        let on = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (flag, url) = (on.clone(), proxy.url());
        let client = http_client_with(None, Arc::new(move || flag.load(std::sync::atomic::Ordering::SeqCst).then(|| url.clone())));
        let get = || client.get(format!("http://127.0.0.1:{}/", port)).send();
        let sessions = || proxy.sessions.load(std::sync::atomic::Ordering::SeqCst);

        assert_eq!(get().await.unwrap().text().await.unwrap(), "ok");
        assert_eq!(sessions(), 0, "bypass off: direct, as before");
        on.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(get().await.unwrap().text().await.unwrap(), "ok");
        assert_eq!(sessions(), 1, "bypass on: through the routed proxy");
        on.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(get().await.unwrap().text().await.unwrap(), "ok");
        assert_eq!(sessions(), 1);
    }

    /// HTTP through the proxy: authenticated, upstream connection protected.
    #[tokio::test]
    async fn http_via_protected_socks_proxy() {
        let (p, seen) = recorder();
        let proxy = SocksProxy::start(Some(p)).await.unwrap();
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = server.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
            }
        });

        let client = reqwest::Client::builder().proxy(reqwest::Proxy::all(proxy.url()).unwrap()).build().unwrap();
        let body = client.get(format!("http://localhost:{}/x", addr.port())).send().await.unwrap().text().await.unwrap();
        assert_eq!(body, "ok");
        // Every upstream connection attempt ("localhost" may try ::1 first)
        // was protected.
        assert!(!seen.lock().unwrap().is_empty(), "upstream connection was protected");

        // Wrong credentials are refused.
        let wrong = format!("socks5h://nobody:nothing@{}", proxy.addr);
        let bad = reqwest::Client::builder().proxy(reqwest::Proxy::all(wrong).unwrap()).build().unwrap();
        assert!(bad.get(format!("http://localhost:{}/x", addr.port())).send().await.is_err());
        // No authentication offered → refused.
        let mut raw = TcpStream::connect(proxy.addr).await.unwrap();
        raw.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0u8; 2];
        raw.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 0xFF]);
    }
}
