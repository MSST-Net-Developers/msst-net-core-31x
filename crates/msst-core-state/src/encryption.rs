//! Encryption — negotiated WireGuard for the data plane (boringtun).
//!
//! See `docs/DATA_PLANE_ENCRYPTION.md`.  Each peer has a boringtun `Tunn`
//! and a negotiation state that says what we send to it:
//!
//! ```text
//!               policy ≠ off, first packet to the peer
//!   Unknown ──────────────────────────────────────────► Handshaking ──session usable──► Encrypted
//!      ▲                                                     │
//!      │                                                     │ no session after 15 s
//!      │                                                     ▼
//!      └──── retry due / new key / network change ────── Plaintext (5 min, doubling to 1 h)
//!            / peer sent us WireGuard
//! ```
//!
//! - `Unknown`, `Handshaking`, `Plaintext`: data goes out as plaintext MSST
//!   frames; a handshake is started by outbound traffic when due.
//! - `Encrypted`: data goes out through WireGuard only, and plaintext from
//!   the peer is refused.  This is sticky for the lifetime of the peer's
//!   public key (downgrade protection): an expired session is re-handshaken
//!   by boringtun, never replaced by plaintext.
//!
//! The engine does no I/O: it returns WireGuard messages for the runtime to
//! wrap in `TYPE_WG` frames and send over the peer's current path, which is
//! chosen independently (relay or direct).  State changes are collected and
//! taken with [`EncryptionEngine::take_changes`].

use base64::{engine::general_purpose::STANDARD, Engine as _};
use boringtun::noise::{Tunn, TunnResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, trace};
use x25519_dalek::{PublicKey, StaticSecret};

/// A handshake that hasn't produced a session after this long falls back
/// to plaintext.
pub const HANDSHAKE_TIMEOUT_SECS: i64 = 15;
/// First retry delay after a failed negotiation; doubles per failure.
pub const RETRY_BASE_SECS: i64 = 300;
/// Retry delay cap.
pub const RETRY_MAX_SECS: i64 = 3600;

/// Large enough for any UDP datagram plus WireGuard overhead.
const BUF_LEN: usize = 65_536 + 64;
/// boringtun shifts the session index left by 8 bits.
const MAX_INDEX: u32 = 0x00FF_FFFF;

/// Network setting `data_encryption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionPolicy {
    /// Never initiate or answer handshakes; everything is plaintext.
    Off,
    /// Encrypt with every peer that answers a handshake.
    #[default]
    Prefer,
}

/// Per-peer negotiation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncState {
    Unknown,
    Handshaking,
    Encrypted,
    Plaintext,
}

impl EncState {
    /// Wire name (path view, IPC events).
    pub fn name(&self) -> &'static str {
        match self {
            EncState::Unknown => "unknown",
            EncState::Handshaking => "handshaking",
            EncState::Encrypted => "encrypted",
            EncState::Plaintext => "plaintext",
        }
    }
}

/// What to send for one outbound IP packet.
#[derive(Debug, Default)]
pub struct Outbound {
    /// WireGuard messages, each sent as a `TYPE_WG` frame.
    pub wg: Vec<Vec<u8>>,
    /// Also send the packet itself as a plaintext `TYPE_DATA` frame.
    pub plain: bool,
}

/// Result of one inbound WireGuard message.
#[derive(Debug, Default)]
pub struct Inbound {
    /// WireGuard messages to send back to the peer (`TYPE_WG`).
    pub reply: Vec<Vec<u8>>,
    /// A decrypted IP packet.
    pub packet: Option<Vec<u8>>,
}

/// A peer's negotiation state changed.
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
    /// In `Plaintext`: when a new handshake may start.
    pub next_retry_at: Option<i64>,
}

struct PeerSession {
    tunn: Tunn,
    peer_public: [u8; 32],
    state: EncState,
    /// A session with this key was established: never fall back.
    sticky: bool,
    handshake_started: i64,
    failures: u32,
    retry_at: i64,
}

fn retry_delay(failures: u32) -> i64 {
    let exp = failures.saturating_sub(1).min(16);
    RETRY_BASE_SECS.saturating_mul(1 << exp).min(RETRY_MAX_SECS)
}

fn transition(changes: &mut Vec<EncChange>, id: &str, s: &mut PeerSession, new: EncState) {
    if s.state != new {
        debug!("encryption: {} {} → {}", id, s.state.name(), new.name());
        changes.push(EncChange { device_id: id.to_string(), old: s.state, new });
        s.state = new;
    }
}

/// The WireGuard engine: local key, policy and per-peer sessions.
pub struct EncryptionEngine {
    local_secret: Option<StaticSecret>,
    local_public: Option<PublicKey>,
    policy: EncryptionPolicy,
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
            policy: EncryptionPolicy::default(),
            sessions: HashMap::new(),
            next_index: 1,
            buf: vec![0u8; BUF_LEN],
            changes: Vec::new(),
        }
    }

    // ── Key and policy ────────────────────────────────────────────────────

    /// Set the local keypair (the identity key).  Existing sessions are
    /// rebuilt with it.
    pub fn set_local_keypair(&mut self, secret_bytes: [u8; 32]) {
        let secret = StaticSecret::from(secret_bytes);
        self.local_public = Some(PublicKey::from(&secret));
        self.local_secret = Some(secret);
        self.reset_all();
        info!("encryption: local keypair configured");
    }

    pub fn local_public_key_b64(&self) -> Option<String> {
        self.local_public.map(|pk| STANDARD.encode(pk.as_bytes()))
    }

    pub fn local_public_key(&self) -> Option<[u8; 32]> {
        self.local_public.map(|pk| *pk.as_bytes())
    }

    pub fn policy(&self) -> EncryptionPolicy {
        self.policy
    }

    /// Change the policy.  Every session is rebuilt and sticky marks are
    /// forgotten.
    pub fn set_policy(&mut self, policy: EncryptionPolicy) {
        if self.policy != policy {
            info!("encryption: policy {:?} → {:?}", self.policy, policy);
            self.policy = policy;
            self.reset_all();
        }
    }

    fn new_tunn(&mut self, peer_public: [u8; 32]) -> Option<Tunn> {
        let secret = self.local_secret.clone()?;
        let index = self.next_index;
        self.next_index = self.next_index % MAX_INDEX + 1;
        Some(Tunn::new(secret, PublicKey::from(peer_public), None, None, index, None))
    }

    fn reset_all(&mut self) {
        let ids: Vec<(String, [u8; 32])> = self.sessions.iter().map(|(id, s)| (id.clone(), s.peer_public)).collect();
        for (id, pk) in ids {
            let Some(tunn) = self.new_tunn(pk) else { continue };
            let Self { sessions, changes, .. } = self;
            if let Some(s) = sessions.get_mut(&id) {
                *s = PeerSession { tunn, peer_public: pk, state: s.state, sticky: false, handshake_started: 0, failures: 0, retry_at: 0 };
                transition(changes, &id, s, EncState::Unknown);
            }
        }
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
        let fresh = PeerSession { tunn, peer_public: pk, state: EncState::Unknown, sticky: false, handshake_started: 0, failures: 0, retry_at: 0 };
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
        Some(SessionView {
            state: s.state,
            last_handshake_at: s.tunn.stats().0.map(|d| now_unix - d.as_secs() as i64),
            next_retry_at: (s.state == EncState::Plaintext).then_some(s.retry_at),
        })
    }

    /// Diagnostics for every peer with a session.
    pub fn views(&self, now_unix: i64) -> HashMap<String, SessionView> {
        self.sessions.keys().filter_map(|id| Some((id.clone(), self.view(id, now_unix)?))).collect()
    }

    /// Whether a plaintext `TYPE_DATA` frame from this peer is accepted.
    pub fn accepts_plaintext(&self, device_id: &str) -> bool {
        self.policy == EncryptionPolicy::Off || !self.sessions.get(device_id).is_some_and(|s| s.sticky)
    }

    /// The changes since the last call.
    pub fn take_changes(&mut self) -> Vec<EncChange> {
        std::mem::take(&mut self.changes)
    }

    // ── Data plane ────────────────────────────────────────────────────────

    /// Decide how to send one outbound IP packet to `device_id`.
    pub fn outbound(&mut self, device_id: &str, pkt: &[u8], now_unix: i64) -> Outbound {
        let plain = Outbound { wg: Vec::new(), plain: true };
        if self.policy == EncryptionPolicy::Off {
            return plain;
        }
        let Self { sessions, buf, changes, .. } = self;
        let Some(s) = sessions.get_mut(device_id) else { return plain };
        if s.sticky {
            // Encrypted only.  Without a session boringtun queues the
            // packet and starts a handshake.
            let wg = match s.tunn.encapsulate(pkt, buf) {
                TunnResult::WriteToNetwork(p) => vec![p.to_vec()],
                _ => Vec::new(),
            };
            return Outbound { wg, plain: false };
        }
        let due = match s.state {
            EncState::Unknown => true,
            EncState::Plaintext => now_unix >= s.retry_at,
            _ => false,
        };
        if !due {
            return plain;
        }
        match s.tunn.format_handshake_initiation(buf, true) {
            TunnResult::WriteToNetwork(p) => {
                s.handshake_started = now_unix;
                transition(changes, device_id, s, EncState::Handshaking);
                Outbound { wg: vec![p.to_vec()], plain: true }
            }
            other => {
                debug!("encryption: handshake initiation for {} failed: {:?}", device_id, other);
                plain
            }
        }
    }

    /// Process one WireGuard message (a `TYPE_WG` payload) from `device_id`.
    pub fn inbound(&mut self, device_id: &str, msg: &[u8], now_unix: i64) -> Inbound {
        let mut out = Inbound::default();
        if self.policy == EncryptionPolicy::Off || msg.is_empty() {
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
        // The peer speaks WireGuard: no backoff.
        s.failures = 0;
        s.retry_at = 0;
        if s.tunn.stats().0.is_some() {
            if !s.sticky {
                info!("encryption: session with {} established", device_id);
            }
            s.sticky = true;
            transition(changes, device_id, s, EncState::Encrypted);
        } else if matches!(s.state, EncState::Unknown | EncState::Plaintext) {
            // We answered its handshake; usable once its first packet arrives.
            s.handshake_started = now_unix;
            transition(changes, device_id, s, EncState::Handshaking);
        }
        out
    }

    /// Drive boringtun's timers (retransmit, rekey, keepalive, expiry) and
    /// time out negotiations.  Call about once a second.  Returns
    /// WireGuard messages to send, per peer.
    pub fn tick(&mut self, now_unix: i64) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        if self.policy == EncryptionPolicy::Off {
            return out;
        }
        let Self { sessions, buf, changes, .. } = self;
        for (id, s) in sessions.iter_mut() {
            if !matches!(s.state, EncState::Handshaking | EncState::Encrypted) {
                continue;
            }
            if let TunnResult::WriteToNetwork(p) = s.tunn.update_timers(buf) {
                out.push((id.clone(), p.to_vec()));
            }
            if s.state == EncState::Handshaking && !s.sticky && now_unix - s.handshake_started >= HANDSHAKE_TIMEOUT_SECS {
                s.failures += 1;
                s.retry_at = now_unix + retry_delay(s.failures);
                debug!("encryption: no session with {} ({} failures), plaintext until {}", id, s.failures, s.retry_at);
                transition(changes, id, s, EncState::Plaintext);
            }
        }
        out
    }

    /// Network change: peers on plaintext may negotiate again right away.
    pub fn reset_backoff(&mut self) {
        for s in self.sessions.values_mut() {
            s.failures = 0;
            s.retry_at = 0;
        }
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

    /// Deliver `to_y` (sent by `x`) and all replies back and forth until both
    /// sides are quiet.  `x_name` / `y_name` are how each is known to the other.
    fn exchange_named(x: &mut EncryptionEngine, x_name: &str, y: &mut EncryptionEngine, y_name: &str, mut to_y: Vec<Vec<u8>>) {
        for _ in 0..8 {
            let mut to_x = Vec::new();
            for m in to_y.drain(..) {
                to_x.extend(y.inbound(x_name, &m, T0).reply);
            }
            for m in to_x {
                to_y.extend(x.inbound(y_name, &m, T0).reply);
            }
            if to_y.is_empty() {
                break;
            }
        }
    }

    /// `exchange_named` for messages from "a" to "b".
    fn exchange(a: &mut EncryptionEngine, b: &mut EncryptionEngine, to_b: Vec<Vec<u8>>) {
        exchange_named(a, "a", b, "b", to_b);
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
        e.remove_peer("p");
        assert!(!e.has_peer("p"));
        assert_eq!(e.session_count(), 0);
    }

    #[test]
    fn first_packet_negotiates_then_encrypts() {
        let (mut a, mut b) = pair();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"hello");

        // First packet: plaintext plus a handshake initiation.
        let out = a.outbound("b", &pkt, T0);
        assert!(out.plain);
        assert_eq!(out.wg.len(), 1);
        assert_eq!(a.state("b"), Some(EncState::Handshaking));
        // While negotiating, still plaintext and no second initiation.
        let out2 = a.outbound("b", &pkt, T0);
        assert!(out2.plain && out2.wg.is_empty());

        // Handshake round trip (response, then a's keepalive).
        exchange(&mut a, &mut b, out.wg);
        assert_eq!(a.state("b"), Some(EncState::Encrypted));
        assert_eq!(b.state("a"), Some(EncState::Encrypted));

        // Now encrypted only, both ways.
        let out = a.outbound("b", &pkt, T0);
        assert!(!out.plain);
        assert_eq!(out.wg.len(), 1);
        assert_ne!(out.wg[0], pkt);
        assert_eq!(b.inbound("a", &out.wg[0], T0).packet, Some(pkt.clone()));
        let back = ipv4([10, 0, 0, 2], [10, 0, 0, 1], b"reply");
        let out = b.outbound("a", &back, T0);
        assert!(!out.plain);
        assert_eq!(a.inbound("b", &out.wg[0], T0).packet, Some(back));

        // Plaintext from an encrypted peer is refused.
        assert!(!a.accepts_plaintext("b") && !b.accepts_plaintext("a"));

        let names = |e: &mut EncryptionEngine| -> Vec<(&str, &str)> {
            e.take_changes().iter().map(|c| (c.old.name(), c.new.name())).collect()
        };
        assert_eq!(names(&mut a), [("unknown", "handshaking"), ("handshaking", "encrypted")]);
        assert_eq!(names(&mut b), [("unknown", "handshaking"), ("handshaking", "encrypted")]);
        assert!(a.view("b", T0).unwrap().last_handshake_at.is_some());
    }

    #[test]
    fn unanswered_handshake_falls_back_with_backoff() {
        let (mut a, _b) = pair();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"x");
        assert_eq!(a.outbound("b", &pkt, T0).wg.len(), 1);
        a.tick(T0 + HANDSHAKE_TIMEOUT_SECS - 1);
        assert_eq!(a.state("b"), Some(EncState::Handshaking));
        a.tick(T0 + HANDSHAKE_TIMEOUT_SECS);
        assert_eq!(a.state("b"), Some(EncState::Plaintext));
        let retry = a.view("b", T0).unwrap().next_retry_at.unwrap();
        assert_eq!(retry, T0 + HANDSHAKE_TIMEOUT_SECS + RETRY_BASE_SECS);
        assert!(a.accepts_plaintext("b"));

        // Before the retry: plaintext, no handshake.
        let out = a.outbound("b", &pkt, retry - 1);
        assert!(out.plain && out.wg.is_empty());
        // Due: negotiate again; the next failure waits twice as long.
        assert_eq!(a.outbound("b", &pkt, retry).wg.len(), 1);
        a.tick(retry + HANDSHAKE_TIMEOUT_SECS);
        assert_eq!(a.view("b", 0).unwrap().next_retry_at, Some(retry + HANDSHAKE_TIMEOUT_SECS + 2 * RETRY_BASE_SECS));
        assert_eq!(retry_delay(20), RETRY_MAX_SECS);

        // A network change makes it due immediately.
        a.reset_backoff();
        assert_eq!(a.outbound("b", &pkt, retry + HANDSHAKE_TIMEOUT_SECS + 1).wg.len(), 1);
    }

    #[test]
    fn peer_handshake_ends_plaintext_fallback() {
        let (mut a, mut b) = pair();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"x");
        // a gave up on b earlier.
        a.outbound("b", &pkt, T0);
        a.tick(T0 + HANDSHAKE_TIMEOUT_SECS);
        assert_eq!(a.state("b"), Some(EncState::Plaintext));
        // b initiates: a answers despite its backoff and ends up encrypted.
        let init = b.outbound("a", &pkt, T0).wg;
        exchange_named(&mut b, "b", &mut a, "a", init);
        assert_eq!(a.state("b"), Some(EncState::Encrypted));
        assert_eq!(b.state("a"), Some(EncState::Encrypted));
    }

    #[test]
    fn encrypted_is_sticky_until_the_key_changes() {
        let (mut a, mut b) = pair();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"x");
        let init = a.outbound("b", &pkt, T0).wg;
        exchange(&mut a, &mut b, init);
        assert_eq!(a.state("b"), Some(EncState::Encrypted));

        // Never times out to plaintext, even with nothing coming back.
        a.tick(T0 + 10 * HANDSHAKE_TIMEOUT_SECS);
        assert_eq!(a.state("b"), Some(EncState::Encrypted));
        assert!(!a.outbound("b", &pkt, T0 + 1000).plain);

        // A new key for b (e.g. a new device key): fresh negotiation.
        let other = engine();
        assert!(a.add_peer("b", &other.local_public_key_b64().unwrap()).unwrap());
        assert_eq!(a.state("b"), Some(EncState::Unknown));
        assert!(a.accepts_plaintext("b"));
    }

    #[test]
    fn policy_off_is_plaintext_and_silent() {
        let (mut a, mut b) = pair();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"x");
        b.set_policy(EncryptionPolicy::Off);
        let out = a.outbound("b", &pkt, T0);
        // b ignores the handshake.
        let r = b.inbound("a", &out.wg[0], T0);
        assert!(r.reply.is_empty() && r.packet.is_none());
        let out = b.outbound("a", &pkt, T0);
        assert!(out.plain && out.wg.is_empty());
        assert!(b.accepts_plaintext("a"));
        assert!(b.tick(T0).is_empty());

        // Turning it off after encryption forgets the sticky mark.
        let (mut a, mut b) = pair();
        let init = a.outbound("b", &pkt, T0).wg;
        exchange(&mut a, &mut b, init);
        a.take_changes();
        a.set_policy(EncryptionPolicy::Off);
        assert!(a.accepts_plaintext("b"));
        assert_eq!(a.state("b"), Some(EncState::Unknown));
        assert_eq!(a.take_changes(), [EncChange { device_id: "b".into(), old: EncState::Encrypted, new: EncState::Unknown }]);
    }

    #[test]
    fn wrong_peer_cannot_decrypt() {
        let (mut a, mut b) = pair();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], b"secret");
        let init = a.outbound("b", &pkt, T0).wg;
        exchange(&mut a, &mut b, init);
        let ct = a.outbound("b", &pkt, T0).wg.remove(0);

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
        let (mut a, mut b) = pair();
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], &[0xAB; 1400]);
        let init = a.outbound("b", &pkt, T0).wg;
        exchange(&mut a, &mut b, init);
        let ct = a.outbound("b", &pkt, T0).wg.remove(0);
        assert_eq!(ct.len(), pkt.len() + 32);
        assert_eq!(b.inbound("a", &ct, T0).packet, Some(pkt));
    }
}
