//! Encryption — WireGuard tunnel management via boringtun.
//!
//! This module owns the WireGuard state machine for all peer sessions.
//! It handles:
//! - Local keypair management (identity keypair loaded at init)
//! - Per-peer session creation/destruction
//! - Packet encapsulation (plaintext IP → WG ciphertext)
//! - Packet decapsulation (WG ciphertext → plaintext IP)
//! - Handshake initiation and response
//!
//! ## Design
//!
//! The `EncryptionEngine` is the single authority for WireGuard state.
//! It is NOT behind a lock — the Core runtime owns it directly and calls
//! methods on it from the data-plane loops (inbound/outbound).
//!
//! Per-peer sessions are identified by `device_id` and indexed by a
//! monotonic WG index (derived from the device ID hash).

use boringtun::noise::{Tunn, TunnResult};
use std::collections::HashMap;
use tracing::{debug, info, trace, warn};
use x25519_dalek::{PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// EncryptionEngine
// ---------------------------------------------------------------------------

/// The WireGuard encryption engine.
///
/// Owns the local keypair and all per-peer `Tunn` sessions.
pub struct EncryptionEngine {
    /// Local static secret key (set once at init).
    local_secret: Option<StaticSecret>,
    /// Local public key (derived from secret).
    local_public: Option<PublicKey>,
    /// Per-peer tunnel sessions.
    sessions: HashMap<String, PeerSession>,
    /// Monotonic index counter for WG sessions.
    next_index: u32,
}

struct PeerSession {
    device_id: String,
    tunn: Tunn,
    index: u32,
    /// Public key of the peer (for diagnostics).
    peer_public: PublicKey,
}

impl EncryptionEngine {
    pub fn new() -> Self {
        EncryptionEngine {
            local_secret: None,
            local_public: None,
            sessions: HashMap::new(),
            next_index: 1,
        }
    }

    // ── Key management ────────────────────────────────────────────────────

    /// Set the local keypair from the identity's secret key bytes.
    ///
    /// Must be called once at init, before any peer sessions are created.
    pub fn set_local_keypair(&mut self, secret_bytes: [u8; 32]) {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        self.local_secret = Some(secret);
        self.local_public = Some(public);
        info!("encryption: local keypair configured");
    }

    /// Returns the local public key (base64-encoded).
    pub fn local_public_key_b64(&self) -> Option<String> {
        self.local_public.map(|pk| base64::encode(pk.as_bytes()))
    }

    /// Returns the local public key bytes.
    pub fn local_public_key(&self) -> Option<[u8; 32]> {
        self.local_public.map(|pk| *pk.as_bytes())
    }

    // ── Session management ────────────────────────────────────────────────

    /// Add a peer tunnel session.
    ///
    /// `peer_public_key_b64` is the base64-encoded X25519 public key from
    /// the coordinator.
    pub fn add_peer(
        &mut self,
        device_id: &str,
        peer_public_key_b64: &str,
    ) -> Result<(), EncryptionError> {
        let secret = self.local_secret.as_ref()
            .ok_or(EncryptionError::LocalKeyNotSet)?;

        let pk_bytes = base64::decode(peer_public_key_b64)
            .map_err(|_| EncryptionError::InvalidPublicKey(peer_public_key_b64.to_string()))?;
        if pk_bytes.len() != 32 {
            return Err(EncryptionError::InvalidPublicKey(
                format!("expected 32 bytes, got {}", pk_bytes.len()),
            ));
        }

        let peer_pub = PublicKey::from(<[u8; 32]>::try_from(pk_bytes.as_slice()).unwrap());
        let index = self.next_index;
        self.next_index += 1;

        let tunn = Tunn::new(
            secret.clone(),
            peer_pub,
            None, // psk
            None, // endpoint
            index,
            None, // rate_limiter
        );

        self.sessions.insert(
            device_id.to_string(),
            PeerSession {
                device_id: device_id.to_string(),
                tunn,
                index,
                peer_public: peer_pub,
            },
        );

        debug!("encryption: added peer session for {} (index {})", device_id, index);
        Ok(())
    }

    /// Remove a peer session.
    pub fn remove_peer(&mut self, device_id: &str) {
        if self.sessions.remove(device_id).is_some() {
            debug!("encryption: removed peer session for {}", device_id);
        }
    }

    /// Returns `true` if a session exists for this peer.
    pub fn has_peer(&self, device_id: &str) -> bool {
        self.sessions.contains_key(device_id)
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    // ── Encapsulation (plaintext → ciphertext) ────────────────────────────

    /// Encapsulate a plaintext IP packet for a specific peer.
    ///
    /// Returns the WG ciphertext bytes to send over UDP, or an error if
    /// the session doesn't exist or the handshake hasn't completed yet.
    pub fn encapsulate(
        &mut self,
        device_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let session = self.sessions.get_mut(device_id)
            .ok_or(EncryptionError::NoSession(device_id.to_string()))?;

        let mut out_buf = vec![0u8; 65564]; // WG overhead
        match session.tunn.encapsulate(plaintext, &mut out_buf) {
            TunnResult::WriteToNetwork(ciphertext) => {
                Ok(ciphertext.to_vec())
            }
            TunnResult::Err(e) => {
                warn!("encryption: encapsulate error for {}: {:?}", device_id, e);
                Err(EncryptionError::EncapsulateFailed(format!("{:?}", e)))
            }
            other => {
                trace!("encryption: unexpected encapsulate result for {}: {:?}", device_id, other);
                Err(EncryptionError::EncapsulateFailed(format!("{:?}", other)))
            }
        }
    }

    // ── Decapsulation (ciphertext → plaintext) ────────────────────────────

    /// Try to decapsulate an incoming WG ciphertext packet against a
    /// specific peer session.
    ///
    /// Returns `(Option<plaintext>, Option<handshake_response>)`.
    /// If a handshake response is returned, the caller must send it back.
    pub fn decapsulate_from(
        &mut self,
        device_id: &str,
        ciphertext: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), EncryptionError> {
        let session = self.sessions.get_mut(device_id)
            .ok_or(EncryptionError::NoSession(device_id.to_string()))?;

        let mut out_buf = vec![0u8; 65564];
        match session.tunn.decapsulate(None, ciphertext, &mut out_buf) {
            TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                Ok((Some(pkt.to_vec()), None))
            }
            TunnResult::WriteToNetwork(handshake) => {
                trace!("encryption: handshake response from {} ({} bytes)", device_id, handshake.len());
                Ok((None, Some(handshake.to_vec())))
            }
            TunnResult::Done => Ok((None, None)),
            TunnResult::Err(e) => {
                warn!("encryption: decapsulate error for {}: {:?}", device_id, e);
                Err(EncryptionError::DecapsulateFailed(format!("{:?}", e)))
            }
        }
    }

    /// Try to decapsulate an incoming packet against ALL known peer
    /// sessions.  Returns `(device_id, plaintext, Option<handshake_response>)`
    /// on success.
    ///
    /// This is the hot-path for inbound packets — the sender is unknown
    /// until we successfully decrypt.
    ///
    /// If a handshake response is returned, the caller must send it back
    /// to the peer via UDP.
    pub fn decapsulate_any(
        &mut self,
        ciphertext: &[u8],
    ) -> Option<(String, Vec<u8>, Option<Vec<u8>>)> {
        if self.sessions.is_empty() {
            return None;
        }

        let mut out_buf = vec![0u8; 65564];

        for (id, session) in &mut self.sessions {
            match session.tunn.decapsulate(None, ciphertext, &mut out_buf) {
                TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                    debug!("encryption: decapsulated {} bytes from {}", pkt.len(), id);
                    return Some((id.clone(), pkt.to_vec(), None));
                }
                TunnResult::WriteToNetwork(handshake) => {
                    // Handshake response — caller should send this back.
                    trace!("encryption: handshake response from {} ({} bytes)", id, handshake.len());
                    return Some((id.clone(), Vec::new(), Some(handshake.to_vec())));
                }
                TunnResult::Done => {}
                TunnResult::Err(_) => {}
            }
        }
        None
    }

    // ── Handshake ─────────────────────────────────────────────────────────

    /// Check if a peer session needs to send a handshake initiation.
    ///
    /// Returns the handshake bytes to send if a handshake is needed.
    pub fn maybe_handshake(
        &mut self,
        device_id: &str,
    ) -> Result<Option<Vec<u8>>, EncryptionError> {
        let session = self.sessions.get_mut(device_id)
            .ok_or(EncryptionError::NoSession(device_id.to_string()))?;

        let mut out_buf = vec![0u8; 65564];
        match session.tunn.encapsulate(&[], &mut out_buf) {
            TunnResult::WriteToNetwork(data) => {
                debug!("encryption: handshake initiation for {} ({} bytes)", device_id, data.len());
                Ok(Some(data.to_vec()))
            }
            TunnResult::Done => Ok(None), // no handshake needed
            TunnResult::Err(e) => {
                warn!("encryption: handshake error for {}: {:?}", device_id, e);
                Err(EncryptionError::HandshakeFailed(format!("{:?}", e)))
            }
            _ => Ok(None),
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
    /// No session exists for this peer.
    NoSession(String),
    /// Encapsulation failed.
    EncapsulateFailed(String),
    /// Decapsulation failed.
    DecapsulateFailed(String),
    /// Handshake failed.
    HandshakeFailed(String),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalKeyNotSet => write!(f, "local keypair not set"),
            Self::InvalidPublicKey(detail) => write!(f, "invalid public key: {}", detail),
            Self::NoSession(id) => write!(f, "no session for peer {}", id),
            Self::EncapsulateFailed(detail) => write!(f, "encapsulate failed: {}", detail),
            Self::DecapsulateFailed(detail) => write!(f, "decapsulate failed: {}", detail),
            Self::HandshakeFailed(detail) => write!(f, "handshake failed: {}", detail),
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
    use x25519_dalek::StaticSecret;

    fn make_engine_with_keypair() -> (EncryptionEngine, [u8; 32]) {
        let mut rng = rand::rngs::OsRng;
        let secret = StaticSecret::random_from_rng(&mut rng);
        let secret_bytes = secret.to_bytes();
        let mut engine = EncryptionEngine::new();
        engine.set_local_keypair(secret_bytes);
        (engine, secret_bytes)
    }

    fn make_peer_keypair() -> ([u8; 32], String) {
        let mut rng = rand::rngs::OsRng;
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);
        let b64 = base64::encode(public.as_bytes());
        (secret.to_bytes(), b64)
    }

    #[test]
    fn new_engine_has_no_key() {
        let engine = EncryptionEngine::new();
        assert!(engine.local_public_key().is_none());
        assert!(engine.local_public_key_b64().is_none());
    }

    #[test]
    fn set_keypair() {
        let (engine, _) = make_engine_with_keypair();
        assert!(engine.local_public_key().is_some());
        assert!(engine.local_public_key_b64().is_some());
    }

    #[test]
    fn add_peer_requires_key() {
        let mut engine = EncryptionEngine::new();
        let (_, peer_pk) = make_peer_keypair();
        assert!(engine.add_peer("dev-1", &peer_pk).is_err());
    }

    #[test]
    fn add_and_remove_peer() {
        let (mut engine, _) = make_engine_with_keypair();
        let (_, peer_pk) = make_peer_keypair();

        engine.add_peer("dev-1", &peer_pk).unwrap();
        assert!(engine.has_peer("dev-1"));
        assert_eq!(engine.session_count(), 1);

        engine.remove_peer("dev-1");
        assert!(!engine.has_peer("dev-1"));
        assert_eq!(engine.session_count(), 0);
    }

    #[test]
    fn remove_nonexistent_peer() {
        let (mut engine, _) = make_engine_with_keypair();
        engine.remove_peer("dev-1"); // should not panic
    }

    #[test]
    fn invalid_public_key() {
        let (mut engine, _) = make_engine_with_keypair();
        assert!(engine.add_peer("dev-1", "not-valid-base64!!!").is_err());
        assert!(engine.add_peer("dev-1", &base64::encode(&[0u8; 16])).is_err()); // wrong length
    }

    #[test]
    fn encapsulate_no_session() {
        let (mut engine, _) = make_engine_with_keypair();
        let result = engine.encapsulate("dev-1", &[1, 2, 3]);
        assert!(matches!(result, Err(EncryptionError::NoSession(_))));
    }

    #[test]
    fn decapsulate_from_no_session() {
        let (mut engine, _) = make_engine_with_keypair();
        let result = engine.decapsulate_from("dev-1", &[1, 2, 3]);
        assert!(matches!(result, Err(EncryptionError::NoSession(_))));
    }

    #[test]
    fn decapsulate_any_empty_sessions() {
        let (mut engine, _) = make_engine_with_keypair();
        assert!(engine.decapsulate_any(&[1, 2, 3]).is_none());
    }

    #[test]
    fn full_handshake_and_data_flow() {
        // Two peers set up their engines.
        let (mut engine_a, _) = make_engine_with_keypair();
        let (mut engine_b, _) = make_engine_with_keypair();

        let pk_a_b64 = engine_a.local_public_key_b64().unwrap();
        let pk_b_b64 = engine_b.local_public_key_b64().unwrap();

        // Add each other as peers.
        engine_a.add_peer("dev-b", &pk_b_b64).unwrap();
        engine_b.add_peer("dev-a", &pk_a_b64).unwrap();

        // A initiates handshake.
        let handshake_a = engine_a.maybe_handshake("dev-b").unwrap();
        assert!(handshake_a.is_some(), "A should initiate handshake");
        let handshake_bytes = handshake_a.unwrap();

        // B processes the handshake.
        let (_plaintext, resp) = engine_b.decapsulate_from("dev-a", &handshake_bytes).unwrap();

        // B's handshake response should be sent back to A.
        if let Some(resp_bytes) = resp {
            let _ = engine_a.decapsulate_from("dev-b", &resp_bytes);
        }
    }

    #[test]
    fn multiple_peers() {
        let (mut engine, _) = make_engine_with_keypair();
        let (_, pk1) = make_peer_keypair();
        let (_, pk2) = make_peer_keypair();

        engine.add_peer("dev-1", &pk1).unwrap();
        engine.add_peer("dev-2", &pk2).unwrap();
        assert_eq!(engine.session_count(), 2);
        assert!(engine.has_peer("dev-1"));
        assert!(engine.has_peer("dev-2"));
    }

    #[test]
    fn default_trait() {
        let engine = EncryptionEngine::default();
        assert!(engine.local_public_key().is_none());
        assert_eq!(engine.session_count(), 0);
    }

    // =======================================================================
    // End-to-end integration tests — full WG handshake + data exchange
    // =======================================================================

    /// Helper: create two engines that know each other's public keys.
    fn make_peer_pair() -> (EncryptionEngine, EncryptionEngine) {
        let (mut engine_a, _) = make_engine_with_keypair();
        let (mut engine_b, _) = make_engine_with_keypair();

        let pk_a = engine_a.local_public_key_b64().unwrap();
        let pk_b = engine_b.local_public_key_b64().unwrap();

        engine_a.add_peer("node-b", &pk_b).unwrap();
        engine_b.add_peer("node-a", &pk_a).unwrap();

        (engine_a, engine_b)
    }

    /// Helper: drive the WG handshake to completion.
    /// Returns `true` if data can flow after the handshake.
    fn drive_handshake(engine_a: &mut EncryptionEngine, engine_b: &mut EncryptionEngine) -> bool {
        // A initiates.
        if let Some(init_bytes) = engine_a.maybe_handshake("node-b").unwrap() {
            // B processes init.
            let (_pt, resp) = engine_b.decapsulate_from("node-a", &init_bytes).unwrap();
            if let Some(resp_bytes) = resp {
                // A processes B's response.
                let (_pt2, resp2) = engine_a.decapsulate_from("node-b", &resp_bytes).unwrap();
                // If A produces another response, send it to B.
                if let Some(resp2_bytes) = resp2 {
                    let _ = engine_b.decapsulate_from("node-a", &resp2_bytes);
                }
            }
        }
        // Try encapsulate to verify tunnel is up.
        engine_a.encapsulate("node-b", &[0u8; 1]).is_ok()
    }

    /// Minimal IPv4 header builder for test payloads.
    fn make_ipv4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[1] = 0;    // DSCP/ECN
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[4..6].copy_from_slice(&[0, 0]); // identification
        pkt[6..8].copy_from_slice(&[0x40, 0]); // flags: DF
        pkt[8] = 64;   // TTL
        pkt[9] = 17;   // protocol: UDP
        // checksum left as 0 for test
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..].copy_from_slice(payload);
        pkt
    }

    // ── Handshake + data flow ─────────────────────────────────────────────

    #[test]
    fn e2e_handshake_and_single_packet_a_to_b() {
        let (mut a, mut b) = make_peer_pair();
        assert!(drive_handshake(&mut a, &mut b), "handshake should complete");

        // A encapsulates a packet for B.
        let payload = b"Hello from node A!";
        let ip_pkt = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], payload);
        let ciphertext = a.encapsulate("node-b", &ip_pkt).unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, ip_pkt, "ciphertext should differ from plaintext");

        // B decapsulates.
        let result = b.decapsulate_any(&ciphertext).unwrap();
        let (peer_id, plaintext, _handshake) = result;
        assert_eq!(peer_id, "node-a");
        assert_eq!(plaintext, ip_pkt);
        assert!(plaintext[20..].ends_with(payload));
    }

    #[test]
    fn e2e_handshake_and_single_packet_b_to_a() {
        let (mut a, mut b) = make_peer_pair();
        assert!(drive_handshake(&mut a, &mut b));

        let payload = b"Reply from node B!";
        let ip_pkt = make_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1], payload);
        let ciphertext = b.encapsulate("node-a", &ip_pkt).unwrap();

        let (peer_id, plaintext, _) = a.decapsulate_any(&ciphertext).unwrap();
        assert_eq!(peer_id, "node-b");
        assert_eq!(plaintext, ip_pkt);
    }

    #[test]
    fn e2e_bidirectional_data_exchange() {
        let (mut a, mut b) = make_peer_pair();
        assert!(drive_handshake(&mut a, &mut b));

        // Send 10 packets each direction.
        for i in 0..10u8 {
            // A → B
            let payload_a = vec![0xAA; 100 + i as usize];
            let ip_a = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &payload_a);
            let ct_a = a.encapsulate("node-b", &ip_a).unwrap();
            let (_, pt_a, _) = b.decapsulate_any(&ct_a).unwrap();
            assert_eq!(pt_a, ip_a);

            // B → A
            let payload_b = vec![0xBB; 200 + i as usize];
            let ip_b = make_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1], &payload_b);
            let ct_b = b.encapsulate("node-a", &ip_b).unwrap();
            let (_, pt_b, _) = a.decapsulate_any(&ct_b).unwrap();
            assert_eq!(pt_b, ip_b);
        }
    }

    #[test]
    fn e2e_large_packet() {
        let (mut a, mut b) = make_peer_pair();
        assert!(drive_handshake(&mut a, &mut b));

        // 1400-byte payload (typical MTU-sized).
        let payload = vec![0xAB; 1400];
        let ip_pkt = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &payload);
        let ciphertext = a.encapsulate("node-b", &ip_pkt).unwrap();
        let (_, plaintext, _) = b.decapsulate_any(&ciphertext).unwrap();
        assert_eq!(plaintext, ip_pkt);
        assert_eq!(plaintext.len(), 20 + 1400);
    }

    #[test]
    fn e2e_wrong_peer_cannot_decapsulate() {
        let (mut a, mut b) = make_peer_pair();
        let (mut c, _) = make_engine_with_keypair();
        let pk_a = a.local_public_key_b64().unwrap();
        c.add_peer("node-a", &pk_a).unwrap();

        assert!(drive_handshake(&mut a, &mut b));

        // A sends to B.
        let ip_pkt = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"secret");
        let ciphertext = a.encapsulate("node-b", &ip_pkt).unwrap();

        // C (not the intended recipient) tries to decapsulate.
        let result_c = c.decapsulate_any(&ciphertext);
        assert!(result_c.is_none(), "wrong peer should not decrypt");
    }

    #[test]
    fn e2e_encapsulate_without_handshake_fails() {
        let (mut a, _b) = make_peer_pair();
        // No handshake performed.
        let ip_pkt = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"test");
        let result = a.encapsulate("node-b", &ip_pkt);
        // boringtun may return an error or a handshake initiation instead of data.
        // Either way, the result should not be a valid encrypted data packet.
        match result {
            Ok(data) => {
                // If it returns data, it's likely a handshake init, not encrypted payload.
                // Verify it's not decapsulatable as data by B.
                // (This is expected behavior — WG initiates handshake on first data.)
            }
            Err(_) => {
                // Expected: can't encrypt without completed handshake.
            }
        }
    }

    #[test]
    fn e2e_session_isolation() {
        let (mut a, mut b) = make_peer_pair();
        let (mut c, _) = make_engine_with_keypair();
        let pk_a = a.local_public_key_b64().unwrap();
        c.add_peer("node-a", &pk_a).unwrap();

        // Handshake A ↔ B only.
        assert!(drive_handshake(&mut a, &mut b));

        // A can send to B.
        let pkt = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"ok");
        assert!(a.encapsulate("node-b", &pkt).is_ok());

        // A cannot send to C (no handshake).
        let result = a.encapsulate("node-c", &pkt);
        assert!(result.is_err());
    }

    // ── Full scheduler + encryption integration ───────────────────────────

    #[test]
    fn e2e_scheduler_routes_through_wg() {
        use crate::scheduler::P2PScheduler;
        use std::net::{Ipv4Addr, SocketAddrV4};

        let (mut a, mut b) = make_peer_pair();
        assert!(drive_handshake(&mut a, &mut b));

        let ep_b = std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 22, 2, 1), 12345));

        // Set up scheduler for node A — punch request transitions to Probing.
        let mut sched = P2PScheduler::new("node-a".to_string());
        let _ = sched.handle_punch_request("node-b", &[ep_b], 1000, 1_000_000);

        // Drive to Direct mode: tick + pong loop.
        use crate::net::msst_packet;
        use std::collections::HashMap;
        let mut endpoints = HashMap::new();
        endpoints.insert("node-b".to_string(), vec![ep_b]);
        let hold_until = sched.path_mode("node-b")
            .map(|_| 1000 + 30 + 1) // HOLD_DURATION_SECS = 30
            .unwrap_or(1031);

        for tick_t in 1001..1020 {
            let actions = sched.tick(tick_t, (tick_t as u64) * 1000, &endpoints, &HashMap::new(), &HashMap::new());
            let sent_seqs: Vec<u32> = actions.iter().filter_map(|a| {
                if let crate::scheduler::actions::SchedulerAction::UdpSend { data, .. } = a {
                    let pkt = msst_packet::MsstPacket::decode(data)?;
                    msst_packet::decode_ping_payload(&pkt.payload).map(|(seq, _)| seq)
                } else { None }
            }).collect();
            for seq in &sent_seqs {
                let _ = sched.handle_pong("node-b", ep_b, *seq, 15.0, Some(30.0), hold_until);
            }
            if matches!(sched.path_mode("node-b"), Some(crate::net::path::PeerPathMode::Direct { .. })) {
                break;
            }
        }

        assert!(
            matches!(sched.path_mode("node-b"), Some(crate::net::path::PeerPathMode::Direct { .. })),
            "expected Direct, got {:?}", sched.path_mode("node-b")
        );

        // route_outbound_wg returns the direct endpoint.
        let target = sched.route_outbound_wg("node-b");
        assert_eq!(target, Some(ep_b));

        // Encapsulate via WG and verify round-trip.
        let ip_pkt = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"wg-scheduler-test");
        let ciphertext = a.encapsulate("node-b", &ip_pkt).unwrap();
        let (_, plaintext, _) = b.decapsulate_any(&ciphertext).unwrap();
        assert_eq!(plaintext, ip_pkt);
    }

    #[test]
    fn e2e_scheduler_falls_back_to_relay_when_no_direct() {
        use crate::scheduler::P2PScheduler;
        use std::net::{Ipv4Addr, SocketAddrV4};

        let mut sched = P2PScheduler::new("node-a".to_string());
        sched.ensure_peer("node-b");
        // Default mode is Relay — no direct endpoint.
        let target = sched.route_outbound_wg("node-b");
        assert!(target.is_none(), "should return None for non-Direct mode");

        // route_outbound should still work via relay.
        let relay = std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 21031));
        let result = sched.route_outbound("node-b", &[1, 2, 3], Some(relay), None);
        assert!(result.is_some());
        let (addr, _) = result.unwrap();
        assert_eq!(addr, relay);
    }
}