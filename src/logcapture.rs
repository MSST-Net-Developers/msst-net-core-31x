//! In-memory log capture for the Controller (3.0.x `IpcLogLayer`).
//!
//! A `tracing` layer keeps the last 2000 log lines in a ring buffer
//! (`GetLogs` / `ClearLogs`) and broadcasts each line to connected
//! Controllers as an `IpcEvent::Diagnostic`.  Log lines use their own
//! channel, separate from Core's state events: a Controller that can't keep
//! up just misses log lines (it is never disconnected for that), and nothing
//! the IPC layer logs about it can loop back into the log stream.

use serde::Serialize;
use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::{LazyLock, Mutex, OnceLock};
use tokio::sync::broadcast;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

const LOG_BUFFER_MAX: usize = 2000;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LogEntry {
    pub level: String,
    pub target: String,
    pub message: String,
    pub timestamp_ms: u64,
}

static LOG_BUFFER: LazyLock<Mutex<VecDeque<LogEntry>>> = LazyLock::new(|| Mutex::new(VecDeque::new()));
static LOG_TX: OnceLock<broadcast::Sender<LogEntry>> = OnceLock::new();

thread_local! {
    static IN_LAYER: Cell<bool> = const { Cell::new(false) };
}

fn sender() -> &'static broadcast::Sender<LogEntry> {
    LOG_TX.get_or_init(|| broadcast::channel(1024).0)
}

/// Subscribe to live log lines.
pub fn subscribe() -> broadcast::Receiver<LogEntry> {
    sender().subscribe()
}

/// The newest `limit` buffered lines (all when `None`), oldest first.
pub fn get_logs(limit: Option<usize>) -> Vec<LogEntry> {
    let buf = LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner());
    let skip = limit.map(|l| buf.len().saturating_sub(l)).unwrap_or(0);
    buf.iter().skip(skip).cloned().collect()
}

pub fn clear_logs() {
    LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

pub(crate) fn record(entry: LogEntry) {
    {
        let mut buf = LOG_BUFFER.lock().unwrap_or_else(|e| e.into_inner());
        if buf.len() >= LOG_BUFFER_MAX {
            buf.pop_front();
        }
        buf.push_back(entry.clone());
    }
    let _ = sender().send(entry);
}

/// The capture layer.  Install with the same level filter as the console.
pub struct LogLayer;

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        }
    }
}

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if IN_LAYER.with(|f| f.replace(true)) {
            return; // re-entrant (something below logged) — drop
        }
        let meta = event.metadata();
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        record(LogEntry {
            level: meta.level().to_string().to_lowercase(),
            target: meta.target().to_string(),
            message: visitor.0,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        });
        IN_LAYER.with(|f| f.set(false));
    }
}

/// Serializes tests that use the global log buffer / channel.
#[cfg(test)]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_limit_and_clear() {
        let _serial = TEST_LOCK.blocking_lock();
        clear_logs();
        let mut rx = subscribe();
        for i in 0..(LOG_BUFFER_MAX + 5) {
            record(LogEntry { level: "info".into(), target: "t".into(), message: format!("m{}", i), timestamp_ms: 0 });
        }
        let all = get_logs(None);
        assert!(all.len() <= LOG_BUFFER_MAX);
        assert_eq!(all.last().unwrap().message, format!("m{}", LOG_BUFFER_MAX + 4));
        assert_eq!(get_logs(Some(2)).len(), 2);
        // Lines were broadcast (the receiver has lagged past the channel capacity).
        assert!(!matches!(rx.try_recv(), Err(broadcast::error::TryRecvError::Empty)));
        clear_logs();
        assert!(get_logs(None).is_empty());
    }
}
