//! Packet router — decides relay vs direct for outbound data.
//!
//! Given a destination peer's path state, determines the address its
//! frames (`TYPE_WG`) are sent to.  Pure — no I/O, no state mutation.

use crate::net::path::PeerPathMode;
use std::net::SocketAddr;

/// The routing decision for an outbound packet.
#[derive(Debug, Clone)]
pub enum RouteTarget {
    /// Send directly to the peer's P2P endpoint.
    Direct { endpoint: SocketAddr },
    /// Send through a relay server (it forwards by `dst_id`).
    Relay { relay_addr: SocketAddr },
    /// No route available — packet should be dropped.
    NoRoute,
}

/// Decide where to send an outbound data packet for a peer.
///
/// `peer_path_mode` — the current path mode for this peer.
/// `peer_relay` — the peer's preferred relay address (if known).
/// `own_relay` — our own relay address (fallback).
pub fn route_outbound(
    peer_path_mode: &PeerPathMode,
    peer_relay: Option<SocketAddr>,
    own_relay: Option<SocketAddr>,
) -> RouteTarget {
    match peer_path_mode {
        PeerPathMode::Direct { endpoint } => {
            RouteTarget::Direct { endpoint: *endpoint }
        }
        PeerPathMode::Probing | PeerPathMode::Relay => {
            // Prefer the peer's relay (asymmetric routing), fall back to our own.
            if let Some(relay) = peer_relay {
                RouteTarget::Relay { relay_addr: relay }
            } else if let Some(relay) = own_relay {
                RouteTarget::Relay { relay_addr: relay }
            } else {
                RouteTarget::NoRoute
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port))
    }

    fn v4b(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), port))
    }

    #[test]
    fn direct_mode_routes_to_endpoint() {
        let target = route_outbound(
            &PeerPathMode::Direct { endpoint: v4(12345) },
            Some(v4b(21031)),
            Some(v4(21031)),
        );
        match target {
            RouteTarget::Direct { endpoint } => assert_eq!(endpoint, v4(12345)),
            _ => panic!("expected Direct"),
        }
    }

    #[test]
    fn relay_mode_uses_peer_relay() {
        let target = route_outbound(
            &PeerPathMode::Relay,
            Some(v4b(21031)),
            Some(v4(21031)),
        );
        match target {
            RouteTarget::Relay { relay_addr } => assert_eq!(relay_addr, v4b(21031)),
            _ => panic!("expected Relay"),
        }
    }

    #[test]
    fn relay_mode_falls_back_to_own_relay() {
        let target = route_outbound(
            &PeerPathMode::Relay,
            None,
            Some(v4(21031)),
        );
        match target {
            RouteTarget::Relay { relay_addr } => assert_eq!(relay_addr, v4(21031)),
            _ => panic!("expected Relay"),
        }
    }

    #[test]
    fn relay_mode_no_relay_no_route() {
        let target = route_outbound(&PeerPathMode::Relay, None, None);
        assert!(matches!(target, RouteTarget::NoRoute));
    }

    #[test]
    fn probing_mode_uses_relay() {
        let target = route_outbound(
            &PeerPathMode::Probing,
            Some(v4b(21031)),
            Some(v4(21031)),
        );
        match target {
            RouteTarget::Relay { relay_addr } => assert_eq!(relay_addr, v4b(21031)),
            _ => panic!("expected Relay for Probing mode"),
        }
    }

}