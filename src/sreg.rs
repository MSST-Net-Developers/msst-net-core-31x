//! Authenticated relay registration (sreg v1) — pure logic, no I/O.
//!
//! Relays that list `"sreg1"` in their `features` (`GET /relays`) and have
//! a `pub_key` accept `0x0E` in place of the unauthenticated `0x01`
//! register / `0x02` keepalive, so nobody without the device key can bind
//! our device ID to another address.  Specification and test vectors: the
//! relay's `REGISTRATION_AUTH.md`.
//!
//! ```text
//! shared = X25519(device_sk, relay_pk)          (all-zero → relay unusable)
//! k_reg  = HKDF-SHA256(shared, salt "msst-sreg-v1",
//!                      info device_id(8 BE) ‖ device_pk ‖ relay_pk, 32)
//! 0x0E   = MSST header (dst_id 0) ‖ counter(8 BE) ‖ tag(16)      — 47 bytes
//! tag    = HMAC-SHA256(k_reg, the 31 bytes before it)[0:16]
//! ```
//!
//! The relay never answers `0x0E`, and a relay that doesn't know our key
//! yet drops the first one while it fetches it from the coordinator, so
//! every (re)registration sends at 0, 1 and 3 s, then at the keepalive
//! interval ([`Registration::due`]).  There is no runtime fallback to
//! `0x01`: `features` comes from the coordinator over HTTPS, while "it
//! doesn't seem to work" can be caused by an attacker.  Never log `k_reg`.

use crate::sdisc::next_counter;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use msst_core_state::net::msst_packet::{MsstPacket, VERSION};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const TYPE_SREG: u8 = 0x0E;
/// The relay feature that means "accepts 0x0E".
pub const FEATURE: &str = "sreg1";
pub const PACKET_LEN: usize = 47;
const LABEL: &[u8] = b"msst-sreg-v1";
const TAG_LEN: usize = 16;
/// Early resends after a (re)registration, in ms after the first packet.
const EARLY_RESENDS_MS: [u64; 2] = [1_000, 3_000];

/// The registration key shared with one relay.  Debug never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct SregKey([u8; 32]);

impl std::fmt::Debug for SregKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SregKey(..)")
    }
}

/// Derive `k_reg`.  `None` for a low-order relay key (all-zero secret).
pub fn derive_key(device_sk: &[u8; 32], device_id: u64, relay_pk: &[u8; 32]) -> Option<SregKey> {
    let secret = StaticSecret::from(*device_sk);
    let device_pk = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(*relay_pk));
    if !shared.was_contributory() {
        return None;
    }
    let mut info = Vec::with_capacity(8 + 32 + 32);
    info.extend_from_slice(&device_id.to_be_bytes());
    info.extend_from_slice(device_pk.as_bytes());
    info.extend_from_slice(relay_pk);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(LABEL), shared.as_bytes()).expand(&info, &mut key).ok()?;
    Some(SregKey(key))
}

/// Build a 0x0E packet (47 bytes).
pub fn build_packet(key: &SregKey, src_id: u64, counter: u64) -> Vec<u8> {
    let mut pkt = MsstPacket {
        version: VERSION,
        packet_type: TYPE_SREG,
        flags: 0,
        src_id: src_id.to_be_bytes(),
        dst_id: [0; 8],
        payload: counter.to_be_bytes().to_vec(),
    }
    .encode();
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key.0).expect("HMAC accepts any key length");
    m.update(&pkt);
    pkt.extend_from_slice(&m.finalize().into_bytes()[..TAG_LEN]);
    debug_assert_eq!(pkt.len(), PACKET_LEN);
    pkt
}

/// Registration state with the current relay: cached key, counter and the
/// send schedule.  Shared by the selection path and the keepalive loop
/// (`std` mutex, never held across `.await`).
#[derive(Debug, Default)]
pub struct Registration {
    /// `(relay_pk, device_id, key)` the key was derived for.
    bound: Option<([u8; 32], u64, SregKey)>,
    counter: u64,
    /// When the current (re)registration started, ms.
    started_ms: Option<u64>,
    /// Early resends already sent.
    early_sent: usize,
    /// Next keepalive, ms.
    next_ms: u64,
    /// 0x0E packets built (`GetRelays.registration.tx_sreg`).
    pub tx_sreg: u64,
}

impl Registration {
    /// A (re)registration starts now: the caller sends the first packet;
    /// [`due`](Self::due) then schedules the rest.  `early`: resend at 1 and
    /// 3 s (sreg, see the module doc); the legacy `0x01` needs no resends.
    pub fn restart(&mut self, now_ms: u64, early: bool) {
        self.started_ms = Some(now_ms);
        self.early_sent = if early { 0 } else { EARLY_RESENDS_MS.len() };
        self.next_ms = 0;
    }

    /// Whether a packet is due now (then it counts as sent).  Before any
    /// [`restart`](Self::restart): plain keepalives every `interval_ms`.
    pub fn due(&mut self, now_ms: u64, interval_ms: u64) -> bool {
        let start = *self.started_ms.get_or_insert(now_ms);
        if let Some(at) = EARLY_RESENDS_MS.get(self.early_sent) {
            if now_ms < start + at {
                return false;
            }
            self.early_sent += 1;
            if self.early_sent == EARLY_RESENDS_MS.len() {
                self.next_ms = now_ms + interval_ms;
            }
            return true;
        }
        if self.next_ms == 0 {
            self.next_ms = start + interval_ms;
        }
        if now_ms < self.next_ms {
            return false;
        }
        self.next_ms = now_ms + interval_ms;
        true
    }

    /// Build the next 0x0E for `(relay_pk, device)`, deriving the key on
    /// first use or after a change.  `None` for a low-order relay key.
    pub fn packet(&mut self, device_sk: &[u8; 32], device_id: u64, relay_pk: &[u8; 32], now_ms: u64) -> Option<Vec<u8>> {
        if !self.bound.as_ref().is_some_and(|(pk, id, _)| pk == relay_pk && *id == device_id) {
            self.bound = Some((*relay_pk, device_id, derive_key(device_sk, device_id, relay_pk)?));
        }
        let (_, _, key) = self.bound.as_ref()?;
        self.counter = next_counter(self.counter, now_ms);
        self.tx_sreg += 1;
        Some(build_packet(key, device_id, self.counter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// `REGISTRATION_AUTH.md` / relay `TestSregVectors`.
    #[test]
    fn spec_vectors() {
        let relay_pk = *PublicKey::from(&StaticSecret::from([2u8; 32])).as_bytes();
        assert_eq!(hex(&relay_pk), "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59");
        assert_eq!(
            hex(PublicKey::from(&StaticSecret::from([1u8; 32])).as_bytes()),
            "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"
        );
        let id = crate::sdisc::wire_id("device-a1b2c3d4");
        assert_eq!(id, 0xa1b2c3d4);
        let key = derive_key(&[1u8; 32], id, &relay_pk).unwrap();
        assert_eq!(hex(&key.0), "600586d9b33a5bcb970b6998524c7974ef368a4d2c48d4cdb649fe194840c2cc");
        let pkt = build_packet(&key, id, 0x0000_0199_0000_0001);
        assert_eq!(pkt.len(), PACKET_LEN);
        assert_eq!(
            hex(&pkt),
            "4d535354010e0000000000a1b2c3d4000000000000000000000199000000019c3ba1a9cf8c539f28c897fba08e581d"
        );
        assert_eq!(format!("{:?}", key), "SregKey(..)");
    }

    #[test]
    fn low_order_relay_key_is_refused() {
        assert!(derive_key(&[1u8; 32], 1, &[0u8; 32]).is_none());
        assert!(Registration::default().packet(&[1u8; 32], 1, &[0u8; 32], 1000).is_none());
    }

    #[test]
    fn counter_increases_within_a_millisecond_and_across_clock_steps_back() {
        let relay_pk = *PublicKey::from(&StaticSecret::from([2u8; 32])).as_bytes();
        let mut r = Registration::default();
        let counter = |p: &[u8]| u64::from_be_bytes(p[23..31].try_into().unwrap());
        let a = counter(&r.packet(&[1u8; 32], 7, &relay_pk, 5_000).unwrap());
        let b = counter(&r.packet(&[1u8; 32], 7, &relay_pk, 5_000).unwrap());
        let c = counter(&r.packet(&[1u8; 32], 7, &relay_pk, 4_000).unwrap());
        assert_eq!(a, 5_000 << 16);
        assert!(a < b && b < c);
        assert_eq!(r.tx_sreg, 3);
        // Another relay: new key, the counter keeps increasing.
        let other = *PublicKey::from(&StaticSecret::from([3u8; 32])).as_bytes();
        let d = r.packet(&[1u8; 32], 7, &other, 4_000).unwrap();
        assert!(counter(&d) > c);
        assert_ne!(d[31..], r.packet(&[1u8; 32], 7, &relay_pk, 4_000).unwrap()[31..]);
    }

    #[test]
    fn schedule_is_0_1_3_then_interval() {
        let mut r = Registration::default();
        let t0 = 100_000;
        r.restart(t0, true); // the caller sent at 0 s
        let sent: Vec<u64> = (0..=60).map(|s| t0 + s * 1000).filter(|&t| r.due(t, 25_000)).map(|t| (t - t0) / 1000).collect();
        assert_eq!(sent, [1, 3, 28, 53]);

        // A re-registration (new relay / reconnect) starts over.
        r.restart(t0 + 61_000, true);
        assert!(!r.due(t0 + 61_500, 25_000));
        assert!(r.due(t0 + 62_000, 25_000));

        // Legacy: no early resends, keepalives at the interval.
        let mut l = Registration::default();
        l.restart(t0, false);
        let sent: Vec<u64> = (0..=60).map(|s| t0 + s * 1000).filter(|&t| l.due(t, 25_000)).map(|t| (t - t0) / 1000).collect();
        assert_eq!(sent, [25, 50]);
    }
}
