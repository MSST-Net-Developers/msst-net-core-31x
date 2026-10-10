//! Generation counter for preventing stale async results from overwriting
//! newer state (AGENTS.md §3.5).
//!
//! Every state mutation increments the generation.  Async operations capture
//! the generation at dispatch time and compare it at completion time.
//! If the generation has advanced, the result is discarded.
//!
//! # Example
//!
//! ```rust
//! use msst_core_state::Generation;
//!
//! let counter = Generation::new();
//! let dispatched_at = counter.current();  // e.g. 42
//!
//! // ... async operation happens ...
//!
//! // Meanwhile, another operation advanced the generation to 43.
//! counter.advance();
//!
//! // The old operation completes.
//! if counter.is_current(dispatched_at) {
//!     // Apply result — generation hasn't changed.
//! } else {
//!     // Discard result — state has moved on.
//! }
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

/// A monotonic generation counter.
///
/// Thread-safe; cheap to clone (it's an `Arc<AtomicU64>` internally).
#[derive(Debug)]
pub struct Generation {
    inner: AtomicU64,
}

impl Generation {
    /// Create a new generation counter starting at 1.
    pub fn new() -> Self {
        Generation {
            inner: AtomicU64::new(1),
        }
    }

    /// Read the current generation value.
    pub fn current(&self) -> u64 {
        self.inner.load(Ordering::Acquire)
    }

    /// Advance the generation by 1 and return the **new** value.
    pub fn advance(&self) -> u64 {
        self.inner.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Returns `true` if `snapshot` matches the current generation.
    ///
    /// Use this to check whether an async result is still valid:
    /// ```ignore
    /// let gen_at_dispatch = gen.current();
    /// // ... async work ...
    /// if gen.is_current(gen_at_dispatch) { apply(result); }
    /// ```
    pub fn is_current(&self, snapshot: u64) -> bool {
        self.inner.load(Ordering::Acquire) == snapshot
    }
}

impl Default for Generation {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Generation {
    fn clone(&self) -> Self {
        Generation {
            inner: AtomicU64::new(self.current()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_one() {
        let g = Generation::new();
        assert_eq!(g.current(), 1);
    }

    #[test]
    fn advance_increments() {
        let g = Generation::new();
        assert_eq!(g.advance(), 2);
        assert_eq!(g.advance(), 3);
        assert_eq!(g.current(), 3);
    }

    #[test]
    fn is_current_matches() {
        let g = Generation::new();
        let snap = g.current();
        assert!(g.is_current(snap));
    }

    #[test]
    fn is_current_stale_after_advance() {
        let g = Generation::new();
        let snap = g.current();
        g.advance();
        assert!(!g.is_current(snap));
    }

    #[test]
    fn clone_preserves_value() {
        let g = Generation::new();
        g.advance();
        let cloned = g.clone();
        assert_eq!(cloned.current(), g.current());
    }
}