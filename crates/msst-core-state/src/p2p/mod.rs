//! P2P data channel — direct peer-to-peer communication.
//!
//! This module manages the direct P2P data path after NAT traversal:
//! - **Router** — decides relay vs direct for each outbound packet
//! - **Probe** — sends/monitors P2P probes, handles pong responses
//! - **Path monitor** — drives the state machine (1-second tick)
//!
//! ## Data flow
//!
//! ```text
//! Outbound IP packet
//!     │
//!     ├─ PeerPath mode = Direct? ──► send directly to peer endpoint
//!     ├─ PeerPath mode = Probing? ──► send via relay (data) + probe (direct)
//!     └─ PeerPath mode = Relay?   ──► send via relay
//! ```

pub mod probe;
pub mod router;