//! Encryption — WireGuard for all peer data (boringtun).
//!
//! See `docs/DATA_PLANE_ENCRYPTION.md`.  Peer data is only ever sent and
//! accepted as WireGuard messages; there is no plaintext fallback.  Each
//! peer with a known public key has a boringtun `Tunn` and a state that
//! makes the session observable:
//!
//! ```text
//!            packet to the peer, or
//!            the peer's handshake
//!   Unknown ─────────────────────────► Handshaking ──session usable──► Encrypted
//!      ▲                                 │      ▲                         │
//!      │                     no session  │      │ packet to the peer /    │ idle: keys
//!      │                     after 15 s  ▼      │ the peer's handshake    │ erased
//!      │                               Failed ──┘                         │
//!      └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! - Outbound packets without a usable session are queued by boringtun and
//!   start a handshake (retransmitted every 5 s for up to 90 s, then the
//!   queue is dropped); the next packet starts a new one.
//! - `Failed` only reports that the last handshake got no answer; traffic
//!   (or the peer's handshake) keeps retrying, bounded by boringtun.
//!
//! The engine does no I/O: it returns WireGuard messages for the runtime to
//! wrap in `TYPE_WG` frames and send over the peer's current path, which is
//! chosen independently (relay or direct).  State changes are collected and
//! taken with [`EncryptionEngine::take_changes`].

use base64::{engine::general_purpose::STANDARD, Engine as _};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use std::collections::HashMap;
use tracing::{debug, info, trace, warn};
use x25519_dalek::{PublicKey, StaticSecret};

/// A handshake that hasn't produced a session after this long is reported
/// as `Failed` (boringtun keeps retrying it).
pub const HANDSHAKE_TIMEOUT_SECS: i64 = 15;

/// Large enough for any UDP datagram plus WireGuard overhead.
const BUF_LEN: usize = 65_536 + 64;
/// boringtun shifts the session index left by 8 bits.
const MAX_INDEX: u32 = 0x00FF_FFFF;

/// Per-peer session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncState {
    Unknown,
    Handshaking,
    Encrypted,
    Failed,
}

impl EncState {
    /// Wire name (path view, IPC events).
    pub fn name(&self) -> &'static str {
        match self {
            EncState::Unknown => "unknown",
            EncState::Handshaking => "handshaking",
            EncState::Encrypted => "encrypted",
            EncState::Failed => "failed",
        }
    }
}

/// What happened to one outbound IP packet.
#[derive(Debug, PartialEq, Eq)]
pub enum Outbound {
    /// Send this WireGuard message (the encrypted packet, or a handshake
    /// initiation while the packet waits in boringtun's queue).
    Send(Vec<u8>),
    /// Queued until the running handshake completes.
    Queued,
    /// No public key for the peer: dropped.
    NoKey,
}

/// Result of one inbound WireGuard message.
#[derive(Debug, Default)]
pub struct Inbound {
    /// WireGuard messages to send back to the peer (`TYPE_WG`).
    pub reply: Vec<Vec<u8>>,
    /// A decrypted IP packet.
    pub packet: Option<Vec<u8>>,
}

/// A peer's session state changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncChange {
    pub device_id: String,
    pub old: EncState,
    pub new: EncState,
}

/// Diagnostics for one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    pub state: EncState,
    /// Unix time the current WireGuard session was established.
    pub last_handshake_at: Option<i64>,
}

struct PeerSession {
    tunn: Tunn,
    peer_public: [u8; 32],
    state: EncState,
    /// When the current handshake attempt started (`Handshaking`).
    handshake_started: i64,
}

impl PeerSession {
    fn usable(&self) -> bool {
        self.tunn.stats().0.is_some()
    }
}

fn transition(changes: &mut Vec<EncChange>, id: &str, s: &mut PeerSession, new: EncState) {
    if s.state != new {
        debug!("encryption: {} {} → {}", id, s.state.name(), new.name());
        changes.push(EncChange { device_id: id.to_string(), old: s.state, new });
        s.state = new;
    }
}

/// A handshake attempt started (by us or the peer) without a usable session.
fn start_handshake(changes: &mut Vec<EncChange>, id: &str, s: &mut PeerSession, now_unix: i64) {
    if s.state != EncState::Handshaking {
        s.handshake_started = now_unix;
        transition(changes, id, s, EncState::Handshaking);
    }
}

/// The WireGuard engine: local key and per-peer sessions.
pub struct EncryptionEngine {
    local_secret: Option<StaticSecret>,
    local_public: Option<PublicKey>,
    sessions: HashMap<String, PeerSession>,
    next_index: u32,
    buf: Vec<u8>,
    changes: Vec<EncChange>,
}

impl EncryptionEngine {
    pub fn new() -> Self {
        EncryptionEngine {
            local_secret: None,
            local_public: None,
            sessions: HashMap::new(),
            next_index: 1,
            buf: vec![0u8; BUF_LEN],
            changes: Vec::new(),
        }
    }

    // ── Key ───────────────────────────────────────────────────────────────

    /// Set the local keypair (the identity key).  Existing sessions are
    /// rebuilt with it.
    pub fn set_local_keypair(&mut self, secret_bytes: [u8; 32]) {
        let secret = StaticSecret::from(secret_bytes);
        self.local_public = Some(PublicKey::from(&secret));
        self.local_secret = Some(secret);
        let ids: Vec<(String, [u8; 32])> = self.sessions.iter().map(|(id, s)| (id.clone(), s.peer_public)).collect();
        for (id, pk) in ids {
            let Some(tunn) = self.new_tunn(pk) else { continue };
            let Self { sessions, changes, .. } = self;
            if let Some(s) = sessions.get_mut(&id) {
                s.tunn = tunn;
                transition(changes, &id, s, EncState::Unknown);
            }
        }
        info!("encryption: local keypair configured");
    }

    pub fn local_public_key_b64(&self) -> Option<String> {
        self.local_public.map(|pk| STANDARD.encode(pk.as_bytes()))
    }

    pub fn local_public_key(&self) -> Option<[u8; 32]> {
        self.local_public.map(|pk| *pk.as_bytes())
    }

    fn new_tunn(&mut self, peer_public: [u8; 32]) -> Option<Tunn> {
        let secret = self.local_secret.clone()?;
        let index = self.next_index;
        self.next_index = self.next_index % MAX_INDEX + 1;
        Some(Tunn::new(secret, PublicKey::from(peer_public), None, None, index, None))
    }

    // ── Peers ─────────────────────────────────────────────────────────────

    /// Add or update a peer's public key (base64 X25519, from the
    /// coordinator).  The same key again is a no-op; a new key starts a
    /// fresh session in `Unknown`.  Returns whether a session was created.
    pub fn add_peer(&mut self, device_id: &str, peer_public_key_b64: &str) -> Result<bool, EncryptionError> {
        if self.local_secret.is_none() {
            return Err(EncryptionError::LocalKeyNotSet);
        }
        let pk: [u8; 32] = STANDARD
            .decode(peer_public_key_b64)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| EncryptionError::InvalidPublicKey(peer_public_key_b64.to_string()))?;
        if self.sessions.get(device_id).is_some_and(|s| s.peer_public == pk) {
            return Ok(false);
        }
        let tunn = self.new_tunn(pk).ok_or(EncryptionError::LocalKeyNotSet)?;
        let fresh = PeerSession { tunn, peer_public: pk, state: EncState::Unknown, handshake_started: 0 };
        let Self { sessions, changes, .. } = self;
        match sessions.get_mut(device_id) {
            Some(s) => {
                debug!("encryption: {} has a new public key", device_id);
                let old = std::mem::replace(s, fresh);
                if old.state != EncState::Unknown {
                    changes.push(EncChange { device_id: device_id.to_string(), old: old.state, new: EncState::Unknown });
                }
            }
            None => {
                debug!("encryption: added peer {}", device_id);
                sessions.insert(device_id.to_string(), fresh);
            }
        }
        Ok(true)
    }

    pub fn remove_peer(&mut self, device_id: &str) {
        if self.sessions.remove(device_id).is_some() {
            debug!("encryption: removed peer {}", device_id);
        }
    }

    pub fn has_peer(&self, device_id: &str) -> bool {
        self.sessions.contains_key(device_id)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn state(&self, device_id: &str) -> Option<EncState> {
        self.sessions.get(device_id).map(|s| s.state)
    }

    pub fn view(&self, device_id: &str, now_unix: i64) -> Option<SessionView> {
        let s = self.sessions.get(device_id)?;
        Some(SessionView { state: s.state, last_handshake_at: s.tunn.stats().0.map(|d| now_unix - d.as_secs() as i64) })
    }

    /// Diagnostics for every peer with a session.
    pub fn views(&self, now_unix: i64) -> HashMap<String, SessionView> {
        self.sessions.keys().filter_map(|id| Some((id.clone(), self.view(id, now_unix)?))).collect()
    }

    /// The changes since the last call.
    pub fn take_changes(&mut self) -> Vec<EncChange> {
        std::mem::take(&mut self.changes)
    }

    // ── Data plane ────────────────────────────────────────────────────────

    /// Encrypt one outbound IP packet for `device_id`.
    pub fn outbound(&mut self, device_id: &str, pkt: &[u8], now_unix: i64) -> Outbound {
        let Self { sessions, buf, changes, .. } = self;
        let Some(s) = sessions.get_mut(device_id) else { return Outbound::NoKey };
        // Without a session boringtun queues the packet and returns a
        // handshake initiation (or `Done` if one is already running).
        let out = match s.tunn.encapsulate(pkt, buf) {
            TunnResult::WriteToNetwork(p) => Outbound::Send(p.to_vec()),
            TunnResult::Err(e) => {
                warn!("encryption: cannot encrypt for {}: {:?}", device_id, e);
                Outbound::Queued
            }
            _ => Outbound::Queued,
        };
        if s.usable() {
            transition(changes, device_id, s, EncState::Encrypted);
        } else {
            start_handshake(changes, device_id, s, now_unix);
        }
        out
    }

    /// Process one WireGuard message (a `TYPE_WG` payload) from `device_id`.
    pub fn inbound(&mut self, device_id: &str, msg: &[u8], now_unix: i64) -> Inbound {
        let mut out = Inbound::default();
        if msg.is_empty() {
            return out;
        }
        let Self { sessions, buf, changes, .. } = self;
        let Some(s) = sessions.get_mut(device_id) else { return out };
        match s.tunn.decapsulate(None, msg, buf) {
            TunnResult::WriteToNetwork(p) => {
                out.reply.push(p.to_vec());
                // Flush packets queued while there was no session.
                while let TunnResult::WriteToNetwork(p) = s.tunn.decapsulate(None, &[], buf) {
                    out.reply.push(p.to_vec());
                }
            }
            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => out.packet = Some(p.to_vec()),
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                trace!("encryption: rejected message from {}: {:?}", device_id, e);
                return out;
            }
        }
        if s.usable() {
            if s.state != EncState::Encrypted {
                info!("encryption: session with {} established", device_id);
            }
            transition(changes, device_id, s, EncState::Encrypted);
        } else {
            // We answered its handshake; usable once its first packet arrives.
            start_handshake(changes, device_id, s, now_unix);
        }
        out
    }

    /// Drive boringtun's timers (retransmit, rekey, keepalive, expiry) and
    /// report unanswered handshakes.  Call about once a second.  Returns
    /// WireGuard messages to send, per peer.
    pub fn tick(&mut self, now_unix: i64) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let Self { sessions, buf, changes, .. } = self;
        for (id, s) in sessions.iter_mut() {
            // Every session, idle ones included: boringtun's clock only
            // advances in `update_timers`, and the next handshake and
            // session are timestamped with it.  Skipping idle peers left
            // the clock stale, so a session established after a long idle
            // period looked old and was erased at the next tick
            // (`REJECT_AFTER_TIME * 3`), and a handshake we started was
            // given up at once (`REKEY_ATTEMPT_TIME`).  An idle session has
            // nothing to send, so this starts no handshakes.
            match s.tunn.update_timers(buf) {
                TunnResult::WriteToNetwork(p) => out.push((id.clone(), p.to_vec())),
                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                    // Idle session erased, or retries given up.  Already
                    // idle or failed: boringtun repeats this until the next
                    // handshake, nothing changed.
                    match s.state {
                        EncState::Encrypted => transition(changes, id, s, EncState::Unknown),
                        EncState::Handshaking => transition(changes, id, s, EncState::Failed),
                        EncState::Unknown | EncState::Failed => {}
                    }
                }
                _ => {}
            }
            if s.state == EncState::Handshaking && !s.usable() && now_unix - s.handshake_started >= HANDSHAKE_TIMEOUT_SECS {
                debug!("encryption: no WireGuard session with {} after {} s", id, HANDSHAKE_TIMEOUT_SECS);
                transition(changes, id, s, EncState::Failed);
            }
        }
        out
    }
}

impl Default for EncryptionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum EncryptionError {
    /// Local keypair not set — call `set_local_keypair` first.
    LocalKeyNotSet,
    /// The peer's public key is invalid (bad base64 or wrong length).
    InvalidPublicKey(String),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalKeyNotSet => write!(f, "local keypair not set"),
            Self::InvalidPublicKey(detail) => write!(f, "invalid public key: {}", detail),
        }
    }
}

impl std::error::Error for EncryptionError {}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_000_000;

    fn engine() -> EncryptionEngine {
        let mut e = EncryptionEngine::new();
        e.set_local_keypair(StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes());
        e
    }

    /// Two engines that know each other as "a" and "b".
    fn pair() -> (EncryptionEngine, EncryptionEngine) {
        let (mut a, mut b) = (engine(), engine());
        a.add_peer("b", &b.local_public_key_b64().unwrap()).unwrap();
        b.add_peer("a", &a.local_public_key_b64().unwrap()).unwrap();
        (a, b)
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let len = 20 + payload.len();
        let mut p = vec![0x45, 0, (len >> 8) as u8, len as u8, 0, 0, 0x40, 0, 64, 17, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(payload);
        p
    }

    fn sent(o: Outbound) -> Vec<u8> {
        match o {
            Outbound::Send(m) => m,
            other => panic!("expected Send, got {:?}", other),
        }
    }

    /// Deliver `to_y` (sent by `x`) and all replies back and forth until both
    /// sides are quiet.  `x_name` / `y_name` are how each is known to the
    /// other.  Returns the packets delivered to `y`.
    fn exchange_named(x: &mut EncryptionEngine, x_name: &str, y: &mut EncryptionEngine, y_name: &str, mut to_y: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut at_y = Vec::new();
        for _ in 0..8 {
            let mut to_x = Vec::new();
            for m in to_y.drain(..) {
                let r = y.inbound(x_name, &m, T0);
                to_x.extend(r.reply);
                at_y.extend(r.packet);
            }
            for m in to_x {
                to_y.extend(x.inbound(y_name, &m, T0).reply);
            }
            if to_y.is_empty() {
                break;
            }
        }
        at_y
    }

    /// `exchange_named` for messages from "a" to "b".
    fn exchange(a: &mut EncryptionEngine, b: &mut EncryptionEngine, to_b: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        exchange_named(a, "a", b, "b", to_b)
    }

    fn established() -> (EncryptionEngine, EncryptionEngine) {
        let (mut a, mut b) = pair();
        let init = sent(a.outbound("b", &ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"hi"), T0));
        exchange(&mut a, &mut b, vec![init]);
        a.take_changes();
        b.take_changes();
        (a, b)
    }

    #[test]
    fn keys_and_peers() {
        let mut e = EncryptionEngine::new();
        assert!(e.local_public_key().is_none());
        let pk = engine().local_public_key_b64().unwrap();
        assert!(matches!(e.add_peer("p", &pk), Err(EncryptionError::LocalKeyNotSet)));

        let mut e = engine();
        assert!(e.add_peer("p", "not-base64!!").is_err());
        assert!(e.add_peer("p", &STANDARD.encode([0u8; 16])).is_err());
        assert!(e.add_peer("p", &pk).unwrap());
        assert!(!e.add_peer("p", &pk).unwrap(), "same key is a no-op");
        assert_eq!(e.state("p"), Some(EncState::Unknown));
        assert_eq!(e.outbound("x", b"pkt", T0), Outbound::NoKey);
        e.remove_peer("p");
        assert!(!e.has_peer("p"));
        assert_eq!(e.session_count(), 0);
    }

    #[test]
    fn first_packets_are_queued_until_the_session_exists() {
        let (mut a, mut b) = pair();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"hello");

        // First packet: a handshake initiation goes out, the packet waits.
        let init = sent(a.outbound("b", &pkt, T0));
        assert_eq!(init[0], 1, "handshake initiation");
        assert_eq!(a.state("b"), Some(EncState::Handshaking));
        // More packets while negotiating: queued, no second initiation.
        let pkt2 = ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"second");
        assert_eq!(a.outbound("b", &pkt2, T0), Outbound::Queued);

        // Handshake round trip; the queued packets arrive encrypted.
        let delivered = exchange(&mut a, &mut b, vec![init]);
        assert_eq!(delivered, [pkt.clone(), pkt2]);
        assert_eq!(a.state("b"), Some(EncState::Encrypted));
        assert_eq!(b.state("a"), Some(EncState::Encrypted));

        // Both ways now.
        let ct = sent(a.outbound("b", &pkt, T0));
        assert_ne!(ct, pkt);
        assert_eq!(b.inbound("a", &ct, T0).packet, Some(pkt));
        let back = ipv4([10, 0, 0, 2], [10, 0, 0, 1], b"reply");
        let ct = sent(b.outbound("a", &back, T0));
        assert_eq!(a.inbound("b", &ct, T0).packet, Some(back));

        let names = |e: &mut EncryptionEngine| -> Vec<(&str, &str)> {
            e.take_changes().iter().map(|c| (c.old.name(), c.new.name())).collect()
        };
        assert_eq!(names(&mut a), [("unknown", "handshaking"), ("handshaking", "encrypted")]);
        assert_eq!(names(&mut b), [("unknown", "handshaking"), ("handshaking", "encrypted")]);
        assert!(a.view("b", T0).unwrap().last_handshake_at.is_some());
    }

    #[test]
    fn unanswered_handshake_is_reported_and_recovers() {
        let (mut a, mut b) = pair();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"x");
        sent(a.outbound("b", &pkt, T0));
        a.tick(T0 + HANDSHAKE_TIMEOUT_SECS - 1);
        assert_eq!(a.state("b"), Some(EncState::Handshaking));
        a.tick(T0 + HANDSHAKE_TIMEOUT_SECS);
        assert_eq!(a.state("b"), Some(EncState::Failed));

        // The peer comes back and initiates: a answers and recovers.
        let init = sent(b.outbound("a", &pkt, T0));
        exchange_named(&mut b, "b", &mut a, "a", vec![init]);
        assert_eq!(a.state("b"), Some(EncState::Encrypted));
        assert_eq!(b.state("a"), Some(EncState::Encrypted));
    }

    #[test]
    fn new_key_starts_over() {
        let (mut a, _b) = established();
        assert_eq!(a.state("b"), Some(EncState::Encrypted));
        let other = engine();
        assert!(a.add_peer("b", &other.local_public_key_b64().unwrap()).unwrap());
        assert_eq!(a.state("b"), Some(EncState::Unknown));
        assert_eq!(a.take_changes(), [EncChange { device_id: "b".into(), old: EncState::Encrypted, new: EncState::Unknown }]);
    }

    #[test]
    fn wrong_peer_cannot_decrypt() {
        let (mut a, mut b) = established();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"secret");
        let ct = sent(a.outbound("b", &pkt, T0));

        // c knows a's key but has no session: nothing comes out.
        let mut c = engine();
        c.add_peer("a", &a.local_public_key_b64().unwrap()).unwrap();
        let r = c.inbound("a", &ct, T0);
        assert!(r.packet.is_none() && r.reply.is_empty());
        assert_eq!(c.state("a"), Some(EncState::Unknown));
        // Garbage is rejected without a state change.
        assert!(b.inbound("a", &[4, 0, 0, 0, 1, 2, 3], T0).packet.is_none());
        assert_eq!(b.state("a"), Some(EncState::Encrypted));
    }

    #[test]
    fn large_packet_round_trip() {
        let (mut a, mut b) = established();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], &[0xAB; 1400]);
        let ct = sent(a.outbound("b", &pkt, T0));
        assert_eq!(ct.len(), pkt.len() + 32);
        assert_eq!(b.inbound("a", &ct, T0).packet, Some(pkt));
    }

    /// A session established after the peers were idle for longer than
    /// boringtun's expiry times survives the next ticks (the timers of idle
    /// sessions are driven too, so boringtun's clock is current).
    #[test]
    fn session_after_long_idle_is_kept() {
        use mock_instant::MockClock;
        use std::time::Duration;

        let (mut a, mut b) = pair();
        // Ten minutes of ticks without traffic: > REJECT_AFTER_TIME * 3
        // (540 s) and > REKEY_ATTEMPT_TIME (90 s).
        let mut now = T0;
        for _ in 0..600 {
            MockClock::advance(Duration::from_secs(1));
            now += 1;
            assert!(a.tick(now).is_empty() && b.tick(now).is_empty(), "idle sessions send nothing");
        }
        assert_eq!((a.state("b"), b.state("a")), (Some(EncState::Unknown), Some(EncState::Unknown)));

        let init = sent(a.outbound("b", &ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"hi"), now));
        assert_eq!(exchange(&mut a, &mut b, vec![init]).len(), 1, "queued packet delivered");
        assert_eq!((a.state("b"), b.state("a")), (Some(EncState::Encrypted), Some(EncState::Encrypted)));

        for _ in 0..5 {
            MockClock::advance(Duration::from_secs(1));
            now += 1;
            for (_, m) in a.tick(now) {
                exchange(&mut a, &mut b, vec![m]);
            }
            for (_, m) in b.tick(now) {
                exchange_named(&mut b, "b", &mut a, "a", vec![m]);
            }
        }
        assert_eq!((a.state("b"), b.state("a")), (Some(EncState::Encrypted), Some(EncState::Encrypted)), "{:?}", a.take_changes());
        let data = sent(a.outbound("b", &ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"still"), now));
        assert_eq!(exchange(&mut a, &mut b, vec![data]).len(), 1, "session still usable");
    }
}
