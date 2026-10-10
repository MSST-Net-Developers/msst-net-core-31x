//! # msst-ipc-protocol
//!
//! Transport-agnostic IPC message definitions for MSST-Net Core ↔ Controller.
//!
//! This crate defines **what** flows between Core and Controller.
//! It does **not** define **how** (Unix socket, named pipe, TCP, etc.).
//!
//! ## Semantic model (from AGENTS.md §5)
//!
//! | Category  | Direction          | Purpose                           |
//! |-----------|--------------------|-----------------------------------|
//! | Query     | Controller → Core  | Read current state (idempotent)   |
//! | Command   | Controller → Core  | Request a state change            |
//! | Response  | Core → Controller  | Reply to a query or command       |
//! | Event     | Core → Controller  | Push notification (subscription)  |
//!
//! ## Wire format
//!
//! Every IPC frame is a JSON-serialized [`IpcMessage`] preceded by a 4-byte
//! big-endian length prefix.  The length prefix allows the transport layer to
//! frame messages without scanning for newlines.
//!
//! ```text
//! [length: u32 BE] [JSON payload: `length` bytes]
//! ```

pub mod message;
pub mod version;

pub use message::{IpcMessage, IpcRequest, IpcResponse, IpcEvent, IpcError, AuthDecision};
pub use version::PROTOCOL_VERSION;