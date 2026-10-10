//! # msst-core-state
//!
//! State containers for MSST-Net Core with:
//! - **Generation tracking** — every mutation increments a monotonic counter;
//!   stale async results are discarded if their generation is older than the
//!   current one (AGENTS.md §3.5).
//! - **Desired vs observed state** — the system can reconcile what *should* be
//!   true with what *is* true (AGENTS.md §3.2).
//! - **Explicit state transitions** — `(State, Event) → (NewState, Effects)`
//!   rather than scattered mutations (AGENTS.md §3.3).

pub mod effect;
pub mod encryption;
pub mod firewall;
pub mod generation;
pub mod nat;
pub mod net;
pub mod p2p;
pub mod packet;
pub mod peer;
pub mod peer_list;
pub mod peer_mgmt;
pub mod scheduler;

pub use effect::Effect;
pub use firewall::Firewall;
pub use generation::Generation;
pub use packet::{ConnectionTracker, ParsedPacket, PipelineVerdict, process_inbound};
pub use peer::{PeerDesiredState, PeerObservedState, PeerState};
pub use peer_list::{PeerEntry, PeerList};
pub use peer_mgmt::{PeerManager, PeerEvent, PeerSideEffect};