//! NAT traversal — STUN, endpoint detection, and hole punching.
//!
//! This module handles the network-level NAT traversal:
//! - **STUN** — discover the public IPv4 address/port via STUN servers
//! - **Endpoint detection** — collect STUN + LAN + IPv6 endpoints
//! - **Hole punching** — respond to coordinator `punch_request` by sending
//!   packets to peer endpoints
//!
//! ## Design
//!
//! All functions are async but stateless — they take inputs and return
//! results.  The Core runtime owns the state (endpoint history, STUN
//! transaction map) and calls these functions at appropriate times.

pub mod punch;
pub mod stun;