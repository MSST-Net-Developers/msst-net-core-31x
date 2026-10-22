//! Packet processing pipeline.
//!
//! This module ties together:
//! - **Header parsing** (`parsed`) — raw IP bytes → `ParsedPacket`
//! - **Connection tracking** (`conn_track`) — outbound 5-tuple → inbound fast path
//! - **Fragment verdicts** (`fragment`) — later fragments follow their first fragment
//! - **ACL pipeline** (`pipeline`) — parsed packet → `PipelineVerdict`
//!
//! The pipeline is pure: it takes inputs and returns a verdict.  The Core
//! runtime translates verdicts into side effects (TUN injection, IPC
//! notifications, access logging).

pub mod conn_track;
pub mod fragment;
pub mod parsed;
pub mod pipeline;

pub use conn_track::{ConnKey, ConnectionTracker, FlowOrigin};
pub use fragment::{FragKey, FragmentTracker, LaterFragment};
pub use parsed::{ParsedPacket, TransportProtocol};
pub use pipeline::{PipelineVerdict, PingPolicy, StaticPingPolicy, process_inbound};