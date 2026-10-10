//! Network transport — the MSST data plane.
//!
//! This module handles the wire format and path selection for peer-to-peer
//! and relay-routed traffic.
//!
//! - **`msst_packet`** — MSST packet codec (encode/decode)
//! - **`path`** — per-peer path state machine (relay → probing → direct)
//! - **`relay`** — relay protocol helpers (register, keepalive, ping)

pub mod msst_packet;
pub mod path;
pub mod relay;