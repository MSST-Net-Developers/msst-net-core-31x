//! Secure discovery (sdisc v1) — pure logic, no I/O.
//!
//! Sender authentication for the game-discovery proxy, using the device's
//! X25519 identity key and the relay's static key (advertised as `pub_key`
//! in `GET /relays`).  Specification and test vectors: the relay's
//! `SECURE_DISCOVERY.md`.
//!
//! ```text
//! shared = X25519(device_sk, relay_pk)
//! okm    = HKDF-SHA256(shared, salt "msst-sdisc-v1",
//!                      info device_id(8 BE) ‖ device_pk ‖ relay_pk, 64)
//! k_c2r  = okm[0:32]   k_r2c = okm[32:64]
//! tag    = HMAC-SHA256(key, all packet bytes before the tag)[0:16]
//! ```
//!
//! | Type | Direction | Payload |
//! |------|-----------|---------|
//! | 0x0A register | client → relay | `counter ‖ room_len ‖ room_id ‖ tag` |
//! | 0x0B data     | client → relay | `counter ‖ room_len ‖ room_id ‖ ipv4 ‖ tag` |
//! | 0x0C deliver  | relay → client | `counter ‖ ipv4 ‖ tag` (flags bit 0 = sender verified) |
//!
//! Authentication only: payloads are not encrypted.  Never log keys.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use msst_core_state::net::msst_packet::{MsstPacket, HEADER_LEN, VERSION};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const TYPE_SDISC_REGISTER: u8 = 0x0A;
pub const TYPE_SDISC_DATA: u8 = 0x0B;
pub const TYPE_SDISC_DELIVER: u8 = 0x0C;
/// 0x0C header flag: the relay authenticated the original sender.
pub const FLAG_SENDER_VERIFIED: u8 = 0x01;

const LABEL: &[u8] = b"msst-sdisc-v1";
const COUNTER_LEN: usize = 8;
pub const TAG_LEN: usize = 16;
const COUNTER_SHIFT: u32 = 16;
/// Accepted clock difference between relay and client (relay default for
/// `discovery.auth_max_clock_skew`).
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;

/// Per-relay MAC keys.  Debug is hand-written so keys never reach a log.
#[derive(Clone, PartialEq, Eq)]
pub struct SdiscKeys {
    c2r: [u8; 32],
    r2c: [u8; 32],
}

impl std::fmt::Debug for SdiscKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SdiscKeys(..)")
    }
}

/// The 64-bit wire ID of `device-xxxxxxxx` (big-endian u64 of the 8 hex
/// digits), as carried in MSST headers.
pub fn wire_id(device_id: &str) -> u64 {
    u64::from_be_bytes(msst_core_state::net::msst_packet::encode_id(device_id))
}

/// Derive the keys shared with one relay.  `None` for a low-order relay key
/// (all-zero shared secret).
pub fn derive_keys(device_sk: &[u8; 32], device_id: u64, relay_pk: &[u8; 32]) -> Option<SdiscKeys> {
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
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(LABEL), shared.as_bytes()).expand(&info, &mut okm).ok()?;
    let mut keys = SdiscKeys { c2r: [0; 32], r2c: [0; 32] };
    keys.c2r.copy_from_slice(&okm[..32]);
    keys.r2c.copy_from_slice(&okm[32..]);
    Some(keys)
}

fn mac(key: &[u8; 32]) -> Hmac<Sha256> {
    <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length")
}

/// `room_id` must match `[A-Za-z0-9_-]{1,64}` (the relay drops anything else).
pub fn valid_room_id(room: &str) -> bool {
    (1..=64).contains(&room.len()) && room.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Strictly increasing counter `unix_ms << 16 | seq`.
pub fn next_counter(last: u64, now_ms: u64) -> u64 {
    (last + 1).max(now_ms << COUNTER_SHIFT)
}

/// Build a 0x0A (`ip_pkt == None`) or 0x0B packet, tag included.
/// `None` if `room_id` is invalid.
pub fn build_client_packet(keys: &SdiscKeys, src_id: u64, counter: u64, room_id: &str, ip_pkt: Option<&[u8]>) -> Option<Vec<u8>> {
    if !valid_room_id(room_id) {
        return None;
    }
    let ip = ip_pkt.unwrap_or_default();
    let mut payload = Vec::with_capacity(COUNTER_LEN + 1 + room_id.len() + ip.len() + TAG_LEN);
    payload.extend_from_slice(&counter.to_be_bytes());
    payload.push(room_id.len() as u8);
    payload.extend_from_slice(room_id.as_bytes());
    payload.extend_from_slice(ip);
    let packet_type = if ip_pkt.is_some() { TYPE_SDISC_DATA } else { TYPE_SDISC_REGISTER };
    let mut pkt = MsstPacket { version: VERSION, packet_type, flags: 0, src_id: src_id.to_be_bytes(), dst_id: [0; 8], payload }.encode();
    let mut m = mac(&keys.c2r);
    m.update(&pkt);
    pkt.extend_from_slice(&m.finalize().into_bytes()[..TAG_LEN]);
    Some(pkt)
}

/// A verified 0x0C packet.
#[derive(Debug, PartialEq, Eq)]
pub struct Delivery<'a> {
    /// Original sender (header `src_id`).
    pub sender: u64,
    /// Whether the relay authenticated the original sender.
    pub sender_verified: bool,
    pub counter: u64,
    pub ipv4: &'a [u8],
}

/// Why an inbound packet on the discovery socket was dropped in secure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Not a 0x0C packet (bare IPv4 or any other type).
    NotDeliver,
    Malformed,
    BadTag,
    /// `dst_id` is not this device.
    WrongRecipient,
    /// Counter timestamp outside the clock-skew window.
    Stale,
    /// Counter not greater than the last accepted one.
    Replay,
}

impl DropReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::NotDeliver => "not_deliver",
            DropReason::Malformed => "malformed",
            DropReason::BadTag => "bad_tag",
            DropReason::WrongRecipient => "wrong_recipient",
            DropReason::Stale => "stale",
            DropReason::Replay => "replay",
        }
    }
}

/// Verify a relay → client packet.  Order: type → tag → recipient →
/// freshness → replay, so forged packets never touch `last_counter`.
/// On success the caller stores `Delivery::counter` as the new last counter.
pub fn verify_deliver<'a>(keys: &SdiscKeys, own_id: u64, pkt: &'a [u8], now_ms: u64, last_counter: u64) -> Result<Delivery<'a>, DropReason> {
    if pkt.len() < 6 || &pkt[..4] != b"MSST" || pkt[5] != TYPE_SDISC_DELIVER {
        return Err(DropReason::NotDeliver);
    }
    if pkt[4] != VERSION || pkt.len() < HEADER_LEN + COUNTER_LEN + TAG_LEN {
        return Err(DropReason::Malformed);
    }
    let (msg, tag) = pkt.split_at(pkt.len() - TAG_LEN);
    let mut m = mac(&keys.r2c);
    m.update(msg);
    // Constant-time comparison of the truncated tag.
    m.verify_truncated_left(tag).map_err(|_| DropReason::BadTag)?;
    let header = MsstPacket::decode(msg).ok_or(DropReason::Malformed)?;
    if u64::from_be_bytes(header.dst_id) != own_id {
        return Err(DropReason::WrongRecipient);
    }
    let counter = u64::from_be_bytes(header.payload[..COUNTER_LEN].try_into().unwrap());
    if (counter >> COUNTER_SHIFT).abs_diff(now_ms) > MAX_CLOCK_SKEW_MS {
        return Err(DropReason::Stale);
    }
    if counter <= last_counter {
        return Err(DropReason::Replay);
    }
    Ok(Delivery {
        sender: u64::from_be_bytes(header.src_id),
        sender_verified: header.flags & FLAG_SENDER_VERIFIED != 0,
        counter,
        ipv4: &msg[HEADER_LEN + COUNTER_LEN..],
    })
}

/// Build a 0x0C as the relay does (tests: stands in for the relay).
#[cfg(test)]
pub fn seal_deliver(keys: &SdiscKeys, sender: u64, recipient: u64, flags: u8, counter: u64, ipv4: &[u8]) -> Vec<u8> {
    let mut payload = counter.to_be_bytes().to_vec();
    payload.extend_from_slice(ipv4);
    let mut pkt = MsstPacket { version: VERSION, packet_type: TYPE_SDISC_DELIVER, flags, src_id: sender.to_be_bytes(), dst_id: recipient.to_be_bytes(), payload }.encode();
    let mut m = mac(&keys.r2c);
    m.update(&pkt);
    pkt.extend_from_slice(&m.finalize().into_bytes()[..TAG_LEN]);
    pkt
}

/// When to send 0x0A: on (re)targeting (relay, room or key change), again
/// about 1 s later, then every 25 s — the relay drops the first register
/// while it fetches the room's peer list.
#[derive(Debug)]
pub struct RegisterSchedule<T> {
    target: Option<T>,
    next_at_ms: u64,
}

impl<T> Default for RegisterSchedule<T> {
    fn default() -> Self {
        RegisterSchedule { target: None, next_at_ms: 0 }
    }
}

pub const REGISTER_RETRY_MS: u64 = 1_000;
pub const REGISTER_INTERVAL_MS: u64 = 25_000;

impl<T: PartialEq> RegisterSchedule<T> {
    /// Returns whether a register is due now for `target` (`None` = not in
    /// a room / no secure relay: nothing is sent).
    pub fn poll(&mut self, target: Option<T>, now_ms: u64) -> bool {
        if target.is_none() || target != self.target {
            let due = target.is_some();
            self.target = target;
            self.next_at_ms = now_ms + REGISTER_RETRY_MS;
            return due;
        }
        if now_ms < self.next_at_ms {
            return false;
        }
        self.next_at_ms = now_ms + REGISTER_INTERVAL_MS;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn vector_keys() -> SdiscKeys {
        let relay_pk = *PublicKey::from(&StaticSecret::from([2u8; 32])).as_bytes();
        derive_keys(&[1u8; 32], 0xa1b2c3d4, &relay_pk).unwrap()
    }

    /// Vectors from SECURE_DISCOVERY.md (pinned on the relay by `TestSdiscVectors`).
    #[test]
    fn spec_key_vectors() {
        let relay_pk = PublicKey::from(&StaticSecret::from([2u8; 32]));
        assert_eq!(relay_pk.as_bytes().to_vec(), hex("ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59"));
        let keys = vector_keys();
        assert_eq!(keys.c2r.to_vec(), hex("0eb7f36437a118f7db30875fafb8b74e78d0b7ddf7e2707c3d3360bfc81d8d25"));
        assert_eq!(keys.r2c.to_vec(), hex("b91f9f3c48fabc3672c47973da68bf80af849fe27d473428ca573b84aea6059f"));
        assert_eq!(wire_id("device-a1b2c3d4"), 0xa1b2c3d4);
    }

    fn vector_ip() -> Vec<u8> {
        let mut ip = vec![0x45];
        ip.resize(20, 0);
        ip
    }

    #[test]
    fn spec_data_vector() {
        let pkt = build_client_packet(&vector_keys(), 0xa1b2c3d4, 0x0000019900000001, "space-0a1b2c3d", Some(&vector_ip())).unwrap();
        assert_eq!(
            pkt,
            hex("4d535354010b0000000000a1b2c3d4000000000000000000000199000000010e73706163652d
                 3061316232633364450000000000000000000000000000000000000001345fd3335882d08247
                 1c107a809cf6")
        );
    }

    #[test]
    fn spec_deliver_vector() {
        let pkt = hex(
            "4d535354010c01000000000000000100000000a1b2c3d4000001990000000245000000000000
             0000000000000000000000000014ea364ad6741e5caf670ca30cebf809",
        );
        let now_ms = 0x0000019900000002u64 >> 16;
        let d = verify_deliver(&vector_keys(), 0xa1b2c3d4, &pkt, now_ms, 0).unwrap();
        assert_eq!(d, Delivery { sender: 1, sender_verified: true, counter: 0x0000019900000002, ipv4: &vector_ip() });
        // Same counter again is a replay; a newer one already accepted too.
        assert_eq!(verify_deliver(&vector_keys(), 0xa1b2c3d4, &pkt, now_ms, d.counter), Err(DropReason::Replay));
        // Freshness window.
        assert_eq!(verify_deliver(&vector_keys(), 0xa1b2c3d4, &pkt, now_ms + MAX_CLOCK_SKEW_MS + 1, 0), Err(DropReason::Stale));
        assert!(verify_deliver(&vector_keys(), 0xa1b2c3d4, &pkt, now_ms + MAX_CLOCK_SKEW_MS, 0).is_ok());
        assert_eq!(verify_deliver(&vector_keys(), 0xa1b2c3d5, &pkt, now_ms, 0), Err(DropReason::WrongRecipient));
        // Any flipped bit (header included) breaks the tag.
        for i in 6..pkt.len() {
            let mut bad = pkt.clone();
            bad[i] ^= 0x01;
            assert_eq!(verify_deliver(&vector_keys(), 0xa1b2c3d4, &bad, now_ms, 0), Err(DropReason::BadTag), "byte {}", i);
        }
        // Wrong key.
        let other = derive_keys(&[3u8; 32], 0xa1b2c3d4, &[9u8; 32]).unwrap();
        assert_eq!(verify_deliver(&other, 0xa1b2c3d4, &pkt, now_ms, 0), Err(DropReason::BadTag));
    }

    #[test]
    fn seal_deliver_matches_relay_vector() {
        let pkt = seal_deliver(&vector_keys(), 1, 0xa1b2c3d4, FLAG_SENDER_VERIFIED, 0x0000019900000002, &vector_ip());
        assert_eq!(
            pkt,
            hex("4d535354010c01000000000000000100000000a1b2c3d4000001990000000245000000000000
                 0000000000000000000000000014ea364ad6741e5caf670ca30cebf809")
        );
    }

    #[test]
    fn deliver_rejects_other_shapes() {
        let keys = vector_keys();
        assert_eq!(verify_deliver(&keys, 1, &vector_ip(), 0, 0), Err(DropReason::NotDeliver));
        let mut short = hex("4d535354010c01");
        short.resize(HEADER_LEN + COUNTER_LEN + TAG_LEN - 1, 0);
        assert_eq!(verify_deliver(&keys, 1, &short, 0, 0), Err(DropReason::Malformed));
        let legacy = MsstPacket { version: VERSION, packet_type: 0x09, flags: 0, src_id: [0; 8], dst_id: [0; 8], payload: vec![0; 40] }.encode();
        assert_eq!(verify_deliver(&keys, 1, &legacy, 0, 0), Err(DropReason::NotDeliver));
    }

    #[test]
    fn register_packet_shape() {
        let pkt = build_client_packet(&vector_keys(), 0xa1b2c3d4, 7, "space-1", None).unwrap();
        assert_eq!(pkt[5], TYPE_SDISC_REGISTER);
        assert_eq!(pkt.len(), HEADER_LEN + 8 + 1 + 7 + TAG_LEN);
        assert_eq!(&pkt[HEADER_LEN..HEADER_LEN + 8], &7u64.to_be_bytes());
        assert_eq!(pkt[HEADER_LEN + 8], 7);
        assert!(build_client_packet(&vector_keys(), 1, 1, "bad room", None).is_none());
        assert!(build_client_packet(&vector_keys(), 1, 1, "", None).is_none());
        assert!(build_client_packet(&vector_keys(), 1, 1, &"a".repeat(65), None).is_none());
    }

    #[test]
    fn low_order_relay_key_rejected() {
        assert!(derive_keys(&[1u8; 32], 1, &[0u8; 32]).is_none());
    }

    #[test]
    fn counter_is_monotonic() {
        let c1 = next_counter(0, 1000);
        assert_eq!(c1, 1000 << 16);
        let c2 = next_counter(c1, 1000);
        assert_eq!(c2, c1 + 1);
        // Clock stepping backwards never repeats a counter.
        assert_eq!(next_counter(c2, 500), c2 + 1);
        assert_eq!(next_counter(c2, 2000), 2000 << 16);
    }

    #[test]
    fn register_schedule() {
        let mut s = RegisterSchedule::default();
        assert!(!s.poll(None::<&str>, 0));
        assert!(s.poll(Some("r1"), 0), "on join");
        assert!(!s.poll(Some("r1"), 999));
        assert!(s.poll(Some("r1"), 1000), "early retry");
        assert!(!s.poll(Some("r1"), 25_999));
        assert!(s.poll(Some("r1"), 26_000), "periodic");
        assert!(!s.poll(Some("r1"), 50_999));
        assert!(s.poll(Some("r1"), 51_000));
        // New room / relay: immediately, then the early retry again.
        assert!(s.poll(Some("r2"), 51_500));
        assert!(s.poll(Some("r2"), 52_500));
        // Leaving the room stops registration; rejoining restarts it.
        assert!(!s.poll(None, 53_000));
        assert!(s.poll(Some("r2"), 53_100));
    }
}
