//! Room relay — pure logic, no I/O (`docs/ROOM_RELAY_3.1.md`).
//!
//! A room may name a relay (official or self-hosted) at creation; it never
//! changes.  While its health is `ok`, traffic to room members that report
//! being on it too (`room-relay:` endpoint) goes through it; otherwise
//! through their preferred relays (fallback).  Traffic to anyone else is
//! unaffected.
//!
//! ```text
//!            first reply              3 missed pings in a row (~15 s)
//!  probing ─────────────► ok ─────────────────────────────────────► down
//!     │                    ▲                                         │
//!     │                    └──── replies for 30 s in a row ──────────┘
//!     └── missed ping ───────────────────────────────────────────────► down
//! ```
//!
//! Health is driven by the relay RTT pings (`0x05`, every 5 s): [`Health::tick`]
//! before each round, [`Health::reply`] when the relay echoes one.  It
//! shows that the relay is reachable, not that our registration with it
//! works (sreg has no acknowledgement).

use crate::coordinator::messages::RoomStateRelay;
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::time::{Duration, Instant};

/// Missed pings in a row that make an `ok` relay `down`.
pub const DOWN_AFTER_MISSES: u32 = 3;
/// Uninterrupted replies needed before a `down` relay is used again.
pub const UP_AFTER: Duration = Duration::from_secs(30);
/// Endpoint prefix that says "my room relay works".
pub const ENDPOINT_PREFIX: &str = "room-relay:";
const LINK_SCHEME: &str = "msst-relay://";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Probing,
    Ok,
    Down,
}

impl HealthState {
    pub fn as_str(self) -> &'static str {
        match self {
            HealthState::Probing => "probing",
            HealthState::Ok => "ok",
            HealthState::Down => "down",
        }
    }
}

/// Reachability of the room relay.
#[derive(Debug, Clone)]
pub struct Health {
    state: HealthState,
    /// A ping of the current round is unanswered.
    awaiting: bool,
    misses: u32,
    /// While `down`: start of the current run of replies.
    good_since: Option<Instant>,
}

impl Default for Health {
    fn default() -> Self {
        Health { state: HealthState::Probing, awaiting: false, misses: 0, good_since: None }
    }
}

impl Health {
    pub fn state(&self) -> HealthState {
        self.state
    }

    /// A new ping round starts (whether or not the ping can be sent): the
    /// previous one, if unanswered, counts as missed.  Returns the
    /// transition, if any.
    pub fn tick(&mut self) -> Option<(HealthState, HealthState)> {
        let missed = std::mem::replace(&mut self.awaiting, true);
        if !missed {
            return None;
        }
        self.misses += 1;
        self.good_since = None;
        match self.state {
            HealthState::Probing => self.set(HealthState::Down),
            HealthState::Ok if self.misses >= DOWN_AFTER_MISSES => self.set(HealthState::Down),
            _ => None,
        }
    }

    /// The relay echoed a ping.
    pub fn reply(&mut self, now: Instant) -> Option<(HealthState, HealthState)> {
        self.awaiting = false;
        self.misses = 0;
        match self.state {
            HealthState::Probing => self.set(HealthState::Ok),
            HealthState::Down => {
                let since = *self.good_since.get_or_insert(now);
                if now.duration_since(since) >= UP_AFTER {
                    self.good_since = None;
                    self.set(HealthState::Ok)
                } else {
                    None
                }
            }
            HealthState::Ok => None,
        }
    }

    fn set(&mut self, new: HealthState) -> Option<(HealthState, HealthState)> {
        let old = std::mem::replace(&mut self.state, new);
        (old != new).then_some((old, new))
    }
}

/// The room relay of the room we are in.
#[derive(Debug, Clone)]
pub struct RoomRelay {
    pub room_id: String,
    /// `host:port` as the coordinator gave it.
    pub address: String,
    /// `address` resolved to a numeric `IP:port`; `None` until it resolves.
    pub addr: Option<String>,
    pub pub_key: [u8; 32],
    pub self_hosted: bool,
    pub health: Health,
}

impl RoomRelay {
    /// The room relay from `room_state.relay`.  A room relay must support
    /// authenticated registration (D7).  Secure discovery (`sdisc1`) was
    /// required too until it was retired in 3.1.6 (discovery now goes over
    /// WireGuard, `crate::discovery`).
    pub fn from_room_state(room_id: &str, r: &RoomStateRelay) -> Result<RoomRelay, String> {
        if r.address.is_empty() {
            return Err("no address".into());
        }
        let pub_key = decode_key(&STANDARD, &r.pub_key).ok_or("invalid pub_key")?;
        if !r.features.iter().any(|x| x == crate::sreg::FEATURE) {
            return Err(format!("does not support {}", crate::sreg::FEATURE));
        }
        Ok(RoomRelay {
            room_id: room_id.to_string(),
            address: r.address.clone(),
            addr: r.address.parse::<std::net::SocketAddr>().ok().map(|a| a.to_string()),
            pub_key,
            self_hosted: r.self_hosted,
            health: Health::default(),
        })
    }

    /// Same relay for the same room (the room relay never changes; a
    /// repeated `room_state` must not reset its health).
    pub fn same_as(&self, other: &RoomRelay) -> bool {
        self.room_id == other.room_id && self.pub_key == other.pub_key && self.address == other.address
    }

    /// Usable for room traffic now: healthy, with a resolved address.
    pub fn usable_addr(&self) -> Option<&str> {
        (self.health.state() == HealthState::Ok).then_some(self.addr.as_deref()).flatten()
    }

    /// `room_relay` in the room view (`GetSystemState`, `RoomStateChanged`).
    pub fn view(&self) -> serde_json::Value {
        serde_json::json!({ "address": self.address, "self_hosted": self.self_hosted, "state": self.health.state().as_str() })
    }
}

/// Whether a peer's endpoint list says its room relay works.
pub fn reports_room_relay(endpoints: &[String]) -> bool {
    endpoints.iter().any(|e| e.starts_with(ENDPOINT_PREFIX))
}

/// A relay connection string: `msst-relay://host:port#<base64url key>[?pw=1]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLink {
    pub address: String,
    pub pub_key: [u8; 32],
    /// The relay has a password (the room creator must give it).
    pub password: bool,
}

pub fn is_link(s: &str) -> bool {
    s.trim().to_ascii_lowercase().starts_with(LINK_SCHEME)
}

pub fn parse_link(s: &str) -> Result<RelayLink, String> {
    let s = s.trim();
    if !is_link(s) {
        return Err(format!("not a {} link", LINK_SCHEME));
    }
    let rest = &s[LINK_SCHEME.len()..];
    let (address, frag) = rest.split_once('#').ok_or("missing #<key>")?;
    let (key, query) = match frag.split_once('?') {
        Some((k, q)) => (k, Some(q)),
        None => (frag, None),
    };
    let (host, port) = address.rsplit_once(':').ok_or("address must be host:port")?;
    if host.is_empty() || port.parse::<u16>().map_or(true, |p| p == 0) {
        return Err("address must be host:port".into());
    }
    let pub_key = decode_key(&URL_SAFE_NO_PAD, key).ok_or("invalid key")?;
    let password = query.is_some_and(|q| q.split('&').any(|kv| kv == "pw=1"));
    Ok(RelayLink { address: address.to_string(), pub_key, password })
}

fn decode_key(engine: &impl Engine, s: &str) -> Option<[u8; 32]> {
    engine.decode(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_transitions() {
        let t = Instant::now();
        // probing → ok on the first reply.
        let mut h = Health::default();
        assert_eq!(h.tick(), None);
        assert_eq!(h.reply(t), Some((HealthState::Probing, HealthState::Ok)));
        // ok survives two misses, goes down on the third.
        for _ in 0..DOWN_AFTER_MISSES {
            assert_eq!(h.tick(), None);
        }
        assert_eq!(h.tick(), Some((HealthState::Ok, HealthState::Down)));
        // down → ok only after 30 s of uninterrupted replies.
        assert_eq!(h.reply(t), None);
        h.tick();
        assert_eq!(h.reply(t + Duration::from_secs(20)), None);
        h.tick();
        h.tick(); // missed: the run restarts
        assert_eq!(h.reply(t + Duration::from_secs(40)), None);
        h.tick();
        assert_eq!(h.reply(t + Duration::from_secs(60)), None);
        h.tick();
        assert_eq!(h.reply(t + Duration::from_secs(70)), Some((HealthState::Down, HealthState::Ok)));
        // A first probe that goes unanswered: down at once.
        let mut h = Health::default();
        h.tick();
        assert_eq!(h.tick(), Some((HealthState::Probing, HealthState::Down)));
    }

    fn relay(features: &[&str], key: &str) -> RoomStateRelay {
        RoomStateRelay { address: "relay.example.com:7000".into(), pub_key: key.into(), features: features.iter().map(|s| s.to_string()).collect(), self_hosted: true }
    }

    #[test]
    fn room_state_relay_validation() {
        let key = STANDARD.encode([9u8; 32]);
        let r = RoomRelay::from_room_state("space-1", &relay(&["sdisc1", "sreg1"], &key)).unwrap();
        assert_eq!((r.pub_key, r.addr.as_deref(), r.health.state()), ([9u8; 32], None, HealthState::Probing));
        assert_eq!(r.usable_addr(), None);
        assert_eq!(r.view(), serde_json::json!({ "address": "relay.example.com:7000", "self_hosted": true, "state": "probing" }));
        let numeric = RoomStateRelay { address: "1.2.3.4:7000".into(), ..relay(&["sdisc1", "sreg1"], &key) };
        assert_eq!(RoomRelay::from_room_state("space-1", &numeric).unwrap().addr.as_deref(), Some("1.2.3.4:7000"));
        assert!(RoomRelay::from_room_state("space-1", &relay(&["sdisc1"], &key)).is_err(), "needs sreg1");
        assert!(RoomRelay::from_room_state("space-1", &relay(&["sreg1"], &key)).is_ok(), "sdisc1 no longer needed");
        assert!(RoomRelay::from_room_state("space-1", &relay(&["sdisc1", "sreg1"], "AAAA")).is_err());
        assert!(RoomRelay::from_room_state("space-1", &RoomStateRelay { address: String::new(), ..relay(&["sdisc1", "sreg1"], &key) }).is_err());
    }

    #[test]
    fn links() {
        // The example in ROOM_RELAY_SERVER_3.1.md (key of private 2×32).
        let l = parse_link("msst-relay://relay.example.com:7000#zo060cy2M-x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk").unwrap();
        assert_eq!(l.address, "relay.example.com:7000");
        assert_eq!(l.pub_key, *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([2u8; 32])).as_bytes());
        assert!(!l.password);
        let l = parse_link(" MSST-RELAY://[2001:db8::1]:7000#zo060cy2M-x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk?pw=1 ").unwrap();
        assert_eq!((l.address.as_str(), l.password), ("[2001:db8::1]:7000", true));
        for bad in [
            "relay.example.com:7000",
            "msst-relay://relay.example.com:7000",
            "msst-relay://relay.example.com#zo060cy2M-x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk",
            "msst-relay://relay.example.com:0#zo060cy2M-x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk",
            "msst-relay://:7000#zo060cy2M-x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk",
            "msst-relay://relay.example.com:7000#short",
        ] {
            assert!(parse_link(bad).is_err(), "{}", bad);
        }
    }

    #[test]
    fn room_relay_endpoint() {
        assert!(reports_room_relay(&["1.2.3.4:1".into(), "room-relay:5.6.7.8:7000".into()]));
        assert!(!reports_room_relay(&["relay:5.6.7.8:7000".into()]));
    }
}
