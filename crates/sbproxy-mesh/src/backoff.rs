//! Exponential backoff primitive for gossip retries.
//!
//! Provides a small, allocation-free helper that the gossip loop (and any
//! future mesh caller that retries against a peer) can use to space out
//! attempts. The schedule doubles on each failure, capped at a maximum, so
//! a dead peer is not hammered.
//!
//! The helper is deliberately separate from the gossip loop so it can be
//! unit-tested in isolation and reused by downstream distributed components
//! (rate-limit sync, CRDT replication) as the mesh crate grows.
//!
//! # Example
//!
//! ```ignore
//! use sbproxy_mesh::backoff::ExponentialBackoff;
//! use std::time::Duration;
//!
//! let mut backoff = ExponentialBackoff::new(
//!     Duration::from_millis(100),
//!     Duration::from_secs(10),
//! );
//! for _ in 0..5 {
//!     let delay = backoff.next_delay();
//!     // sleep(delay).await; attempt_rpc();
//!     # let _ = delay;
//! }
//! backoff.reset(); // on success
//! ```

use std::time::Duration;

use crate::metrics;

/// Exponential backoff schedule with a hard cap. Each call to
/// [`Self::next_delay`] doubles the previous delay until the cap is reached; on
/// [`Self::reset`], the schedule starts over at `initial`.
///
/// The struct is `Send + Sync`-free (`Copy`-like semantics) and does not
/// allocate, so it is safe to embed in per-peer state maps.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Initial delay emitted by the first call to `next_delay`.
    initial: Duration,
    /// Hard cap: delays never exceed this.
    max: Duration,
    /// Current delay. `None` until the first call to `next_delay`.
    current: Option<Duration>,
}

impl ExponentialBackoff {
    /// Build a new schedule. `initial` must be non-zero; `max` must be
    /// greater than or equal to `initial`. Both constraints are silently
    /// clamped rather than panicked because backoff is a non-critical
    /// helper and a bogus config shouldn't crash the process.
    pub fn new(initial: Duration, max: Duration) -> Self {
        let initial = if initial.is_zero() {
            Duration::from_millis(1)
        } else {
            initial
        };
        let max = if max < initial { initial } else { max };
        Self {
            initial,
            max,
            current: None,
        }
    }

    /// A sensible default for gossip retries: 100ms initial, 10s cap.
    pub fn gossip_default() -> Self {
        Self::new(Duration::from_millis(100), Duration::from_secs(10))
    }

    /// Emit the next delay. The first call returns `initial`; subsequent
    /// calls double the previous delay, capped at `max`.
    pub fn next_delay(&mut self) -> Duration {
        let next = match self.current {
            None => self.initial,
            Some(d) => {
                // Saturating multiply: if doubling overflows we stay at
                // the cap. `checked_mul` keeps this allocation-free.
                let doubled = d.checked_mul(2).unwrap_or(self.max);
                if doubled > self.max {
                    self.max
                } else {
                    doubled
                }
            }
        };
        self.current = Some(next);
        next
    }

    /// Reset the schedule. Called on a successful attempt so the next
    /// failure starts at `initial` again.
    pub fn reset(&mut self) {
        self.current = None;
    }

    /// Return the most recently emitted delay, or `None` if `next_delay`
    /// has never been called.
    pub fn current(&self) -> Option<Duration> {
        self.current
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::gossip_default()
    }
}

/// Record a gossip retry against `target` in the Prometheus counter.
///
/// Provided as a standalone function (rather than a method on
/// `ExponentialBackoff`) because the backoff schedule is independent of
/// the retry observation: a caller may retry without backing off (e.g.
/// different error categories) or back off without retrying.
pub fn observe_gossip_retry(target: &str) {
    metrics::MESH_GOSSIP_RETRY
        .with_label_values(&[target])
        .inc();
    tracing::debug!(target = target, "mesh gossip retry");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_returns_initial() {
        let mut b = ExponentialBackoff::new(Duration::from_millis(50), Duration::from_secs(5));
        assert_eq!(b.next_delay(), Duration::from_millis(50));
    }

    #[test]
    fn doubles_each_call() {
        let mut b = ExponentialBackoff::new(Duration::from_millis(100), Duration::from_secs(10));
        assert_eq!(b.next_delay(), Duration::from_millis(100));
        assert_eq!(b.next_delay(), Duration::from_millis(200));
        assert_eq!(b.next_delay(), Duration::from_millis(400));
        assert_eq!(b.next_delay(), Duration::from_millis(800));
        assert_eq!(b.next_delay(), Duration::from_millis(1600));
    }

    #[test]
    fn caps_at_max() {
        let mut b = ExponentialBackoff::new(Duration::from_millis(100), Duration::from_millis(500));
        assert_eq!(b.next_delay(), Duration::from_millis(100));
        assert_eq!(b.next_delay(), Duration::from_millis(200));
        assert_eq!(b.next_delay(), Duration::from_millis(400));
        assert_eq!(b.next_delay(), Duration::from_millis(500)); // capped
        assert_eq!(b.next_delay(), Duration::from_millis(500)); // still capped
        assert_eq!(b.next_delay(), Duration::from_millis(500));
    }

    #[test]
    fn reset_starts_over() {
        let mut b = ExponentialBackoff::new(Duration::from_millis(100), Duration::from_secs(10));
        b.next_delay();
        b.next_delay();
        b.next_delay();
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_millis(100));
    }

    #[test]
    fn default_is_gossip_default() {
        let mut b = ExponentialBackoff::default();
        assert_eq!(b.next_delay(), Duration::from_millis(100));
    }

    #[test]
    fn zero_initial_is_clamped_to_one_ms() {
        let mut b = ExponentialBackoff::new(Duration::ZERO, Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_millis(1));
    }

    #[test]
    fn max_lower_than_initial_is_clamped() {
        let mut b = ExponentialBackoff::new(Duration::from_millis(500), Duration::from_millis(100));
        // max should have been clamped up to 500, so the first delay is 500
        // and subsequent delays stay at 500.
        assert_eq!(b.next_delay(), Duration::from_millis(500));
        assert_eq!(b.next_delay(), Duration::from_millis(500));
    }

    #[test]
    fn current_tracks_last_delay() {
        let mut b = ExponentialBackoff::new(Duration::from_millis(10), Duration::from_secs(1));
        assert_eq!(b.current(), None);
        b.next_delay();
        assert_eq!(b.current(), Some(Duration::from_millis(10)));
        b.next_delay();
        assert_eq!(b.current(), Some(Duration::from_millis(20)));
    }

    #[test]
    fn observe_gossip_retry_increments_counter() {
        let target = "backoff-test-target:7946";
        let before = metrics::MESH_GOSSIP_RETRY
            .with_label_values(&[target])
            .get();
        observe_gossip_retry(target);
        observe_gossip_retry(target);
        let after = metrics::MESH_GOSSIP_RETRY
            .with_label_values(&[target])
            .get();
        assert_eq!(after, before + 2);
    }
}
