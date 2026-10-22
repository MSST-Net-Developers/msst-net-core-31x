//! Host routing next to other VPNs (Tailscale, ZeroTier, WireGuard, Clash
//! TUN, Docker networks…).
//!
//! Desktop Core only ([`enable`] is called by the daemon; embedded Core and
//! tests never touch the host's routing).  Linux:
//!
//! - **Virtual ranges pinned to the TUN.**  Table [`ROUTE_TABLE`] holds
//!   `172.22.0.0/16` / `fd22:2222:2222:2222::/64` via the TUN, consulted by
//!   `to <range>` rules at [`PIN_PRIORITY`] — before other VPNs' policy
//!   rules (Tailscale's are at 5210–5270), so an exit node or a broader
//!   subnet route (e.g. `172.16.0.0/12`) can't take MSST traffic.  Only
//!   while no other interface has a route inside (or equal to) the range:
//!   then the range is genuinely shared (e.g. a Docker network on
//!   `172.22.0.0/16`), pinning would break that network, and it is
//!   reported instead.  The main-table routes from `tun_dev` stay as they
//!   are.
//! - **Outer traffic bypass** (`bypass_other_vpns`, default on).  Core's
//!   UDP sockets (data plane, relay probes, STUN) carry [`ROUTE_MARK`], and
//!   a `fwmark` rule at [`BYPASS_PRIORITY`] sends them through the main
//!   table — the physical network — instead of another VPN's full tunnel.
//!   Without a matching route in `main` the lookup falls through to the
//!   next rules as before.  The Coordinator connections (WebSocket and
//!   HTTP, both control plane) are marked the same way: TCP sockets from
//!   `netsock::connect_tcp`, HTTP through the local SOCKS5 proxy whose
//!   upstream connections are marked (`netsock::http_client`; reqwest
//!   can't mark its own sockets).  Only Core's own sockets are affected,
//!   and with the setting off nothing is marked.  DNS upstream sockets keep
//!   their own mark (`dns::DNS_UPSTREAM_MARK`) and so follow the system's
//!   routing.
//!
//! - **Other VPNs kept out of MSST** (`block_other_vpns_over_msst`,
//!   default on).  Tailscale advertises every local address as a candidate
//!   endpoint, MSST's included; between two machines on MSST it then picks
//!   the path through MSST — WireGuard inside WireGuard, fragmented at
//!   MSST's MTU, relayed when MSST is.  tailscaled marks its own sockets
//!   ([`TAILSCALE_BYPASS_MARK`]), so a rule at [`BLOCK_PRIORITY`] makes
//!   exactly those packets to the MSST ranges unreachable: Tailscale's path
//!   probes over MSST fail and it uses its other paths.  Applications'
//!   traffic over Tailscale or MSST is untouched.  (ZeroTier marks nothing;
//!   its `local.conf` `interfacePrefixBlacklist` does the same there.)
//!
//! **Route checks** (Linux, macOS), at TUN setup and every housekeeping
//! tick: the conflicts above and where traffic to an MSST address actually
//! leaves.  Reported as `network_warnings` in `GetSystemState`; a change
//! advances the generation.

// Policy routing is Linux-only; elsewhere only the route check runs.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::state::CoreState;
use serde::Serialize;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Policy routing table holding the TUN routes.
pub const ROUTE_TABLE: u32 = 2222;
/// `fwmark TAILSCALE_BYPASS_MARK to <MSST range> unreachable`: before the
/// pin, which would otherwise route these packets into the TUN.
pub const BLOCK_PRIORITY: u32 = 5199;
/// The mark tailscaled puts on its own (WireGuard, disco) sockets on Linux
/// — its rule 5210 `fwmark 0x80000/0xff0000 lookup main`.
pub const TAILSCALE_BYPASS_MARK: &str = "0x80000/0xff0000";
/// `to <MSST range> lookup ROUTE_TABLE`.
pub const PIN_PRIORITY: u32 = 5200;
/// `fwmark ROUTE_MARK lookup main`.
pub const BYPASS_PRIORITY: u32 = 5201;
// Tailscale's packets meet the block before the pin, and our rules all come
// before Tailscale's own (5210–5270).
const _: () = assert!(BLOCK_PRIORITY < PIN_PRIORITY && PIN_PRIORITY < BYPASS_PRIORITY && BYPASS_PRIORITY < 5210);
/// Mark on Core's UDP sockets while the bypass is on ("MSR"; outside the
/// bits Tailscale's rules match, `0xff0000` = `0x40000`/`0x80000`).
pub const ROUTE_MARK: u32 = 0x4d5352;

/// Something on this host that keeps MSST traffic off the MSST interface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NetworkWarning {
    /// `route_conflict`: another interface has a route inside (or equal to)
    /// an MSST range; `route_hijacked`: traffic to an MSST address leaves
    /// through another interface.
    pub kind: &'static str,
    /// The MSST range concerned.
    pub range: String,
    /// The other interface.
    pub interface: String,
    /// The conflicting route (`route_conflict`), e.g.
    /// `172.22.0.0/16 dev br-1a2b table main`.
    pub route: Option<String>,
}

// ---------------------------------------------------------------------------
// Pure parsing / decisions
// ---------------------------------------------------------------------------

/// An IP prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    /// `a.b.c.d/n`, `addr` (host route) or `default`.
    pub fn parse(s: &str, v6: bool) -> Option<Self> {
        if s == "default" {
            let addr = if v6 { IpAddr::from([0u16; 8]) } else { IpAddr::from([0u8; 4]) };
            return Some(Prefix { addr, len: 0 });
        }
        let (a, l) = s.split_once('/').unwrap_or((s, ""));
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = if l.is_empty() { max } else { l.parse().ok().filter(|&n| n <= max)? };
        Some(Prefix { addr, len })
    }

    fn bits(&self) -> (u128, u8) {
        match self.addr {
            IpAddr::V4(a) => ((u32::from(a) as u128) << 96, self.len),
            IpAddr::V6(a) => (u128::from(a), self.len),
        }
    }

    /// Whether `other` lies inside this prefix (or is equal to it).
    pub fn contains(&self, other: &Prefix) -> bool {
        if self.addr.is_ipv4() != other.addr.is_ipv4() || other.len < self.len {
            return false;
        }
        let ((a, len), (b, _)) = (self.bits(), other.bits());
        let mask = if len == 0 { 0 } else { u128::MAX << (128 - len as u32) };
        a & mask == b & mask
    }
}

/// One route from `ip -o route show table all`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub prefix: Prefix,
    pub dev: String,
    pub table: String,
    /// The prefix as written (`default`, `172.22.0.0/16`, …).
    pub prefix_text: String,
}

/// Parse a route line; `None` for routes without a device and for
/// non-unicast types (`local`, `broadcast`, `multicast`, `throw`, …).
pub fn parse_route(line: &str, v6: bool) -> Option<Route> {
    let mut words = line.split_whitespace().peekable();
    const TYPES: [&str; 10] =
        ["unicast", "local", "broadcast", "multicast", "anycast", "unreachable", "blackhole", "prohibit", "throw", "nat"];
    if let Some(t) = words.peek().copied().filter(|w| TYPES.contains(w)) {
        if t != "unicast" {
            return None;
        }
        words.next();
    }
    let prefix_text = words.next()?;
    let prefix = Prefix::parse(prefix_text, v6)?;
    let rest: Vec<&str> = words.collect();
    let after = |key: &str| rest.windows(2).find(|w| w[0] == key).map(|w| w[1].to_string());
    Some(Route {
        prefix,
        dev: after("dev")?,
        table: after("table").unwrap_or_else(|| "main".into()),
        prefix_text: prefix_text.to_string(),
    })
}

/// Routes of other interfaces inside (or equal to) `range`: the range is
/// shared with another network.  Our own table is ignored.
pub fn conflicts<'a>(routes: &'a [Route], range: &Prefix, tun: &str) -> Vec<&'a Route> {
    let own_table = ROUTE_TABLE.to_string();
    routes.iter().filter(|r| r.dev != tun && r.table != own_table && range.contains(&r.prefix)).collect()
}

/// The device in `ip route get` output (`… dev <name> …`).
pub fn parse_route_get(out: &str) -> Option<String> {
    let w: Vec<&str> = out.split_whitespace().collect();
    w.windows(2).find(|p| p[0] == "dev").map(|p| p[1].to_string())
}

/// The interface in macOS `route -n get` output (`interface: utun4`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_macos_route_get(out: &str) -> Option<String> {
    out.lines().find_map(|l| l.trim().strip_prefix("interface:")).map(|s| s.trim().to_string())
}

/// An address in `range` to look up, other than our own.
fn probe_addr(v6: bool, own: Option<IpAddr>) -> IpAddr {
    let pick = |n: u8| -> IpAddr {
        if v6 { IpAddr::from([0xfd22, 0x2222, 0x2222, 0x2222, 0, 0, 0, n as u16]) } else { IpAddr::from([172, 22, 0, n]) }
    };
    if own == Some(pick(1)) { pick(2) } else { pick(1) }
}

// ---------------------------------------------------------------------------
// Host state (what this process installed)
// ---------------------------------------------------------------------------

struct Host {
    /// The TUN interface and our addresses on it, once up.
    tun: Option<(String, Option<IpAddr>, Option<IpAddr>)>,
    /// Pin installed for [IPv4, IPv6].
    pinned: [bool; 2],
    /// Bypass rules installed.
    bypass: bool,
    /// Rules keeping other VPNs out of MSST installed.
    block_vpns: bool,
}

static HOST: Mutex<Option<Host>> = Mutex::new(None);
/// New Core UDP sockets get [`ROUTE_MARK`] (see [`mark_new_socket`]).
static MARK_SOCKETS: AtomicBool = AtomicBool::new(false);

fn host() -> std::sync::MutexGuard<'static, Option<Host>> {
    HOST.lock().unwrap_or_else(|e| e.into_inner())
}

fn ranges() -> [(Prefix, bool); 2] {
    [
        (Prefix::parse(crate::ip::IPV4_NET, false).expect("valid range"), false),
        (Prefix::parse(crate::ip::IPV6_NET, true).expect("valid range"), true),
    ]
}

/// Take over host routing (desktop daemon): drop rules a previous run left
/// behind, then apply the bypass setting.
pub async fn enable(state: &Arc<CoreState>) {
    *host() = Some(Host { tun: None, pinned: [false; 2], bypass: false, block_vpns: false });
    #[cfg(target_os = "linux")]
    {
        for (range, v6) in ranges() {
            delete_rule(v6, &pin_rule(&range));
            delete_rule(v6, &bypass_rule());
            delete_rule(v6, &block_rule(&range));
            flush_table(v6);
        }
    }
    let settings = state.net_settings.read().await.clone();
    set_bypass(state, settings.bypass_other_vpns);
    set_block_other_vpns(settings.block_other_vpns_over_msst);
    if let Err(e) = crate::netsock::start_routed_proxy().await {
        warn!("routing: no local proxy for Coordinator HTTP ({}); it follows the system routing", e);
    }
}

/// Whether Core's own sockets are being marked (bypass on and managed).
pub fn bypass_active() -> bool {
    MARK_SOCKETS.load(Ordering::Acquire)
}

/// The TUN is up: check (and pin) its routes now.
pub async fn attach_tun(state: &Arc<CoreState>, iface: &str, ipv4: &str, ipv6: &str) {
    {
        let mut h = host();
        let Some(h) = h.as_mut() else { return };
        h.tun = Some((iface.to_string(), ipv4.parse().ok(), ipv6.parse().ok()));
    }
    check(state).await;
}

/// Apply `bypass_other_vpns`.  No-op unless [`enable`]d.
pub fn set_bypass(state: &CoreState, on: bool) {
    let mut guard = host();
    let Some(h) = guard.as_mut() else { return };
    MARK_SOCKETS.store(on, Ordering::Release);
    set_mark(&*state.udp_socket, if on { ROUTE_MARK } else { 0 });
    if on == h.bypass {
        return;
    }
    #[cfg(target_os = "linux")]
    for v6 in [false, true] {
        if on {
            rule(v6, "add", &bypass_rule());
        } else {
            delete_rule(v6, &bypass_rule());
        }
    }
    h.bypass = on;
    info!("routing: outer traffic bypass of other VPNs {}", if on { "on" } else { "off" });
}

/// Apply `block_other_vpns_over_msst`.  No-op unless [`enable`]d.
pub fn set_block_other_vpns(on: bool) {
    let mut guard = host();
    let Some(h) = guard.as_mut() else { return };
    if on == h.block_vpns {
        return;
    }
    #[cfg(target_os = "linux")]
    for (range, v6) in ranges() {
        if on {
            rule(v6, "add", &block_rule(&range));
        } else {
            delete_rule(v6, &block_rule(&range));
        }
    }
    h.block_vpns = on;
    info!("routing: other VPNs (Tailscale) over MSST {}", if on { "blocked" } else { "allowed" });
}

/// Mark a new Core UDP socket while the bypass is on.
pub fn mark_new_socket<S: AsSocketFd>(s: &S) {
    if MARK_SOCKETS.load(Ordering::Acquire) {
        set_mark(s, ROUTE_MARK);
    }
}

/// Remove everything this process installed (shutdown, TUN still up).
pub fn teardown() {
    let Some(h) = host().take() else { return };
    MARK_SOCKETS.store(false, Ordering::Release);
    #[cfg(target_os = "linux")]
    for (i, (range, v6)) in ranges().into_iter().enumerate() {
        if h.bypass {
            delete_rule(v6, &bypass_rule());
        }
        if h.block_vpns {
            delete_rule(v6, &block_rule(&range));
        }
        if h.pinned[i] {
            delete_rule(v6, &pin_rule(&range));
            flush_table(v6);
        }
    }
    let _ = h;
    info!("routing: host routing reverted");
}

/// Re-check routes (housekeeping); publishes `network_warnings`.
pub async fn check(state: &Arc<CoreState>) {
    if host().as_ref().is_none_or(|h| h.tun.is_none()) {
        return;
    }
    let Ok(mut warnings) = tokio::task::spawn_blocking(check_blocking).await else { return };
    warnings.sort();
    let changed = {
        let mut cur = state.network_warnings.lock().unwrap_or_else(|e| e.into_inner());
        if *cur == warnings {
            false
        } else {
            for w in warnings.iter().filter(|w| !cur.contains(w)) {
                warn!("routing: {} for {} via {} {}", w.kind, w.range, w.interface, w.route.as_deref().unwrap_or(""));
            }
            if warnings.is_empty() {
                info!("routing: no more route conflicts");
            }
            *cur = warnings;
            true
        }
    };
    if changed {
        state.next_generation();
    }
}

fn check_blocking() -> Vec<NetworkWarning> {
    let mut guard = host();
    let Some(h) = guard.as_mut() else { return Vec::new() };
    let Some((tun, own4, own6)) = h.tun.clone() else { return Vec::new() };
    let mut warnings = Vec::new();
    for (i, (range, v6)) in ranges().into_iter().enumerate() {
        #[cfg(target_os = "linux")]
        {
            let Some(out) = ip_quiet(v6, &["-o", "route", "show", "table", "all"]) else { continue };
            let routes: Vec<Route> = out.lines().filter_map(|l| parse_route(l, v6)).collect();
            let found = conflicts(&routes, &range, &tun);
            for r in &found {
                warnings.push(NetworkWarning {
                    kind: "route_conflict",
                    range: range_str(v6),
                    interface: r.dev.clone(),
                    route: Some(format!("{} dev {} table {}", r.prefix_text, r.dev, r.table)),
                });
            }
            set_pin(v6, &range, &tun, found.is_empty(), &mut h.pinned[i]);
        }
        let _ = (i, &range);
        let probe = probe_addr(v6, if v6 { own6 } else { own4 });
        if let Some(dev) = route_get(probe).filter(|d| *d != tun) {
            warnings.push(NetworkWarning { kind: "route_hijacked", range: range_str(v6), interface: dev, route: None });
        }
    }
    warnings
}

fn range_str(v6: bool) -> String {
    (if v6 { crate::ip::IPV6_NET } else { crate::ip::IPV4_NET }).to_string()
}

// ---------------------------------------------------------------------------
// Commands (effects)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn pin_rule(range: &Prefix) -> Vec<String> {
    let r = if range.addr.is_ipv4() { crate::ip::IPV4_NET } else { crate::ip::IPV6_NET };
    ["to", r, "lookup", &ROUTE_TABLE.to_string(), "priority", &PIN_PRIORITY.to_string()].map(String::from).to_vec()
}

#[cfg(target_os = "linux")]
fn bypass_rule() -> Vec<String> {
    ["fwmark", &format!("{:#x}", ROUTE_MARK), "lookup", "main", "priority", &BYPASS_PRIORITY.to_string()]
        .map(String::from)
        .to_vec()
}

#[cfg(target_os = "linux")]
fn block_rule(range: &Prefix) -> Vec<String> {
    let r = if range.addr.is_ipv4() { crate::ip::IPV4_NET } else { crate::ip::IPV6_NET };
    ["fwmark", TAILSCALE_BYPASS_MARK, "to", r, "unreachable", "priority", &BLOCK_PRIORITY.to_string()].map(String::from).to_vec()
}

/// Install or remove the pin for one family.
#[cfg(target_os = "linux")]
fn set_pin(v6: bool, range: &Prefix, tun: &str, want: bool, pinned: &mut bool) {
    let table = ROUTE_TABLE.to_string();
    let r = range_str(v6);
    if want && !*pinned {
        if ip(v6, &["route", "replace", &r, "dev", tun, "table", &table]).is_some()
            && rule(v6, "add", &pin_rule(range)).is_some()
        {
            *pinned = true;
            info!("routing: {} pinned to {} (table {}, priority {})", r, tun, table, PIN_PRIORITY);
        }
    } else if !want && *pinned {
        delete_rule(v6, &pin_rule(range));
        flush_table(v6);
        *pinned = false;
        info!("routing: {} unpinned (shared with another interface)", r);
    }
}

/// Remove every route from [`ROUTE_TABLE`].  The kernel drops a table
/// with its last route, and flushing a missing table fails ("FIB table does
/// not exist") — that is the normal case at start (the previous run cleaned
/// up), so only other failures are logged.
#[cfg(target_os = "linux")]
fn flush_table(v6: bool) {
    let mut cmd = std::process::Command::new("ip");
    if v6 {
        cmd.arg("-6");
    }
    match cmd.args(["route", "flush", "table", &ROUTE_TABLE.to_string()]).output() {
        Ok(out) if out.status.success() || table_missing(&String::from_utf8_lossy(&out.stderr)) => {}
        Ok(out) => warn!(
            "routing: `ip {}route flush table {}` failed: {}",
            if v6 { "-6 " } else { "" },
            ROUTE_TABLE,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => warn!("routing: cannot run `ip`: {}", e),
    }
}

/// Whether `ip` stderr says the routing table doesn't exist (empty).
fn table_missing(stderr: &str) -> bool {
    stderr.contains("FIB table does not exist")
}

/// Delete every copy of a rule (left behind by a crash, say).
#[cfg(target_os = "linux")]
fn delete_rule(v6: bool, spec: &[String]) {
    let args: Vec<&str> = ["rule", "del"].into_iter().chain(spec.iter().map(String::as_str)).collect();
    for _ in 0..8 {
        if ip_quiet(v6, &args).is_none() {
            break;
        }
    }
}

/// `ip [-6] rule <verb> <spec>`.
#[cfg(target_os = "linux")]
fn rule(v6: bool, verb: &str, spec: &[String]) -> Option<String> {
    let args: Vec<&str> = ["rule", verb].into_iter().chain(spec.iter().map(String::as_str)).collect();
    ip(v6, &args)
}

/// Run `ip [-6] <args>`; stdout on success, errors logged.
#[cfg(target_os = "linux")]
fn ip<S: AsRef<std::ffi::OsStr> + std::fmt::Debug>(v6: bool, args: &[S]) -> Option<String> {
    let r = ip_quiet(v6, args);
    if r.is_none() {
        warn!("routing: `ip {}{:?}` failed", if v6 { "-6 " } else { "" }, args);
    }
    r
}

#[cfg(target_os = "linux")]
fn ip_quiet<S: AsRef<std::ffi::OsStr>>(v6: bool, args: &[S]) -> Option<String> {
    let mut cmd = std::process::Command::new("ip");
    if v6 {
        cmd.arg("-6");
    }
    let out = cmd.args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The interface traffic to `addr` leaves through.
fn route_get(addr: IpAddr) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        ip_quiet(addr.is_ipv6(), &["route", "get", &addr.to_string()]).and_then(|o| parse_route_get(&o))
    }
    #[cfg(target_os = "macos")]
    {
        let fam = if addr.is_ipv6() { "-inet6" } else { "-inet" };
        let out = std::process::Command::new("route").args(["-n", "get", fam, &addr.to_string()]).output().ok()?;
        out.status.success().then(|| parse_macos_route_get(&String::from_utf8_lossy(&out.stdout))).flatten()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = addr;
        None
    }
}

/// Sockets [`set_mark`] can take.
#[cfg(unix)]
pub trait AsSocketFd: std::os::fd::AsRawFd {}
#[cfg(unix)]
impl<T: std::os::fd::AsRawFd> AsSocketFd for T {}
#[cfg(not(unix))]
pub trait AsSocketFd {}
#[cfg(not(unix))]
impl<T> AsSocketFd for T {}

#[cfg(target_os = "linux")]
fn set_mark<S: AsSocketFd>(s: &S, mark: u32) {
    let rc = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        warn!("routing: SO_MARK failed: {}", std::io::Error::last_os_error());
    }
}

#[cfg(not(target_os = "linux"))]
fn set_mark<S: AsSocketFd>(_s: &S, _mark: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        Prefix::parse(s, s.contains(':')).unwrap()
    }

    #[test]
    fn prefixes() {
        let r4 = p("172.22.0.0/16");
        assert!(r4.contains(&p("172.22.0.0/16")));
        assert!(r4.contains(&p("172.22.5.0/24")));
        assert!(r4.contains(&p("172.22.1.1")));
        assert!(!r4.contains(&p("172.16.0.0/12")), "broader");
        assert!(!r4.contains(&p("172.23.0.0/16")));
        assert!(p("172.16.0.0/12").contains(&r4));
        assert!(Prefix::parse("default", false).unwrap().contains(&r4));
        let r6 = p("fd22:2222:2222:2222::/64");
        assert!(r6.contains(&p("fd22:2222:2222:2222::b")));
        assert!(!r6.contains(&p("fd7a:115c:a1e0::/48")));
        assert!(!r6.contains(&r4) && !r4.contains(&r6));
        assert!(Prefix::parse("10.0.0.0/33", false).is_none());
    }

    #[test]
    fn route_lines() {
        let r = parse_route("172.22.0.0/16 dev br-1a2b proto kernel scope link src 172.22.0.1 linkdown", false).unwrap();
        assert_eq!((r.prefix, r.dev.as_str(), r.table.as_str()), (p("172.22.0.0/16"), "br-1a2b", "main"));
        assert_eq!(r.prefix_text, "172.22.0.0/16");
        let r = parse_route("172.16.0.0/12 dev tailscale0 table 52", false).unwrap();
        assert_eq!((r.dev.as_str(), r.table.as_str()), ("tailscale0", "52"));
        let r = parse_route("default via 192.168.1.1 dev eth0 proto dhcp metric 100", false).unwrap();
        assert_eq!(r.prefix.len, 0);
        let r = parse_route("unicast 172.22.9.0/24 dev zt0 table 7", false).unwrap();
        assert_eq!(r.dev, "zt0");
        for skip in [
            "local 172.22.1.5 dev msst0 table local proto kernel scope host src 172.22.1.5",
            "broadcast 172.22.255.255 dev msst0 table local proto kernel scope link src 172.22.1.5",
            "throw 127.0.0.0/8 table 52",
            "unreachable 10.0.0.0/8 table 5",
            "multicast ff00::/8 dev msst0 table local proto kernel metric 256 pref medium",
        ] {
            assert!(parse_route(skip, skip.contains("ff00")).is_none(), "{}", skip);
        }
        assert!(parse_route("garbage", false).is_none());
    }

    #[test]
    fn conflicts_are_routes_of_other_interfaces_inside_the_range() {
        let routes: Vec<Route> = [
            "172.22.0.0/16 dev msst0 proto kernel scope link src 172.22.1.5",
            "172.22.0.0/16 dev msst0 table 2222",
            "172.16.0.0/12 dev tailscale0 table 52",
            "default dev tailscale0 table 52",
            "172.22.5.0/24 dev br-1a2b proto kernel scope link src 172.22.5.1",
            "10.147.17.0/24 dev ztabc proto kernel scope link",
        ]
        .iter()
        .filter_map(|l| parse_route(l, false))
        .collect();
        let found = conflicts(&routes, &p("172.22.0.0/16"), "msst0");
        assert_eq!(found.iter().map(|r| r.dev.as_str()).collect::<Vec<_>>(), ["br-1a2b"]);
    }

    #[test]
    fn route_get_output() {
        assert_eq!(parse_route_get("172.22.0.1 dev tailscale0 table 52 src 100.64.0.5 uid 0 \n    cache "), Some("tailscale0".into()));
        assert_eq!(parse_route_get("fd22:2222:2222:2222::1 from :: dev msst0 proto kernel src fd22:2222:2222:2222::b metric 256 pref medium"), Some("msst0".into()));
        let mac = "   route to: 172.22.0.1\ndestination: 172.22.0.0\n       mask: 255.255.0.0\n  interface: utun4\n      flags: <UP,DONE,STATIC>\n";
        assert_eq!(parse_macos_route_get(mac), Some("utun4".into()));
        assert_eq!(parse_macos_route_get("route: writing to routing socket: not in table"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rules_in_priority_order() {
        let [(v4, _), (v6, _)] = ranges();
        assert_eq!(block_rule(&v4).join(" "), "fwmark 0x80000/0xff0000 to 172.22.0.0/16 unreachable priority 5199");
        assert_eq!(block_rule(&v6).join(" "), "fwmark 0x80000/0xff0000 to fd22:2222:2222:2222::/64 unreachable priority 5199");
        assert_eq!(pin_rule(&v4).join(" "), "to 172.22.0.0/16 lookup 2222 priority 5200");
        assert_eq!(bypass_rule().join(" "), "fwmark 0x4d5352 lookup main priority 5201");
    }

    #[test]
    fn flushing_a_missing_table_is_not_an_error() {
        // iproute2 7.x on Linux 7.x, table 2222 after a clean shutdown.
        assert!(table_missing("Error: ipv4: FIB table does not exist.\nFlush terminated\n"));
        assert!(table_missing("Error: ipv6: FIB table does not exist.\nFlush terminated\n"));
        assert!(!table_missing("RTNETLINK answers: Operation not permitted\n"));
        assert!(!table_missing(""));
    }

    #[test]
    fn probe_avoids_own_address() {
        assert_eq!(probe_addr(false, Some("172.22.3.4".parse().unwrap())), "172.22.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(probe_addr(false, Some("172.22.0.1".parse().unwrap())), "172.22.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(probe_addr(true, Some("fd22:2222:2222:2222::1".parse().unwrap())), "fd22:2222:2222:2222::2".parse::<IpAddr>().unwrap());
    }
}
