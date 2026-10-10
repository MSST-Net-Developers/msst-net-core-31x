//! Task handle — a cancellable background task wrapper.
//!
//! Every background task spawned by the Core runtime returns a `TaskHandle`.
//! The handle owns the `JoinHandle` and provides a clean `cancel()` method
//! for graceful shutdown.
//!
//! This replaces the raw `AbortHandle` pattern from 3.0.x with a safer API
//! that also captures the task name for diagnostics.

use tokio::task::JoinHandle;

/// A cancellable background task.
pub struct TaskHandle {
    /// Human-readable task name (for logging and diagnostics).
    pub name: &'static str,
    handle: JoinHandle<()>,
}

impl TaskHandle {
    /// Wrap a `JoinHandle` with a task name.
    pub fn new(name: &'static str, handle: JoinHandle<()>) -> Self {
        TaskHandle { name, handle }
    }

    /// Cancel this task.  Sends a cooperative cancellation signal and then
    /// aborts the task if it doesn't stop within `timeout`.
    ///
    /// Returns `true` if the task was still running (and was cancelled),
    /// `false` if it had already finished.
    pub async fn cancel(self) -> bool {
        self.handle.abort();
        match self.handle.await {
            Ok(()) => false, // task finished naturally before abort
            Err(e) if e.is_cancelled() => true,
            Err(e) => {
                tracing::warn!("task '{}' panicked: {}", self.name, e);
                true
            }
        }
    }

    /// Returns `true` if the task has finished (either naturally or via abort).
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

/// Cancel a set of tasks in reverse spawn order (LIFO).
/// Logs each cancellation.
pub async fn cancel_all(tasks: Vec<TaskHandle>) {
    for task in tasks.into_iter().rev() {
        let name = task.name;
        if task.cancel().await {
            tracing::debug!("cancelled task: {}", name);
        } else {
            tracing::debug!("task already finished: {}", name);
        }
    }
}