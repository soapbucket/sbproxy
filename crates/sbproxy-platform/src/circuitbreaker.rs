//! Circuit breaker for protecting upstream services from cascading failures.
//!
//! Uses atomic operations for lock-free state management. The breaker transitions
//! through Closed -> Open -> HalfOpen -> Closed (or back to Open on probe failure).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// --- State Constants ---

const STATE_CLOSED: u32 = 0;
const STATE_OPEN: u32 = 1;
const STATE_HALF_OPEN: u32 = 2;

/// Represents the current state of a circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation. All requests are allowed.
    Closed,
    /// Failing. All requests are rejected until the open duration elapses.
    Open,
    /// Testing recovery. A limited number of probe requests are allowed.
    HalfOpen,
}

/// A lock-free circuit breaker that protects upstream services from cascading failures.
///
/// State transitions:
/// - Closed: count failures. When failures >= threshold, transition to Open.
/// - Open: reject all requests. After open_duration, transition to HalfOpen.
/// - HalfOpen: allow probe requests. On success, increment success_count;
///   if successes >= success_threshold, transition to Closed. On failure, return to Open.
pub struct CircuitBreaker {
    failure_count: AtomicU32,
    success_count: AtomicU32,
    state: AtomicU32,
    failure_threshold: u32,
    success_threshold: u32,
    open_duration_ms: u64,
    last_failure_time: AtomicU64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    ///
    /// - `failure_threshold`: number of consecutive failures before opening the circuit.
    /// - `success_threshold`: number of successes in HalfOpen state to close the circuit.
    /// - `open_duration`: how long the circuit stays open before transitioning to HalfOpen.
    pub fn new(failure_threshold: u32, success_threshold: u32, open_duration: Duration) -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            state: AtomicU32::new(STATE_CLOSED),
            failure_threshold,
            success_threshold,
            open_duration_ms: open_duration.as_millis() as u64,
            last_failure_time: AtomicU64::new(0),
        }
    }

    /// Returns the current circuit state, performing the Open -> HalfOpen
    /// transition if the open duration has elapsed.
    pub fn state(&self) -> CircuitState {
        let raw = self.state.load(Ordering::Acquire);
        if raw == STATE_OPEN && self.open_duration_elapsed() {
            // Attempt transition to HalfOpen. If another thread already did it, that is fine.
            let _ = self.state.compare_exchange(
                STATE_OPEN,
                STATE_HALF_OPEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            if self.state.load(Ordering::Acquire) == STATE_HALF_OPEN {
                self.success_count.store(0, Ordering::Release);
            }
            return CircuitState::HalfOpen;
        }
        Self::decode_state(raw)
    }

    /// Returns true if the request should be allowed through.
    ///
    /// - Closed: always allows.
    /// - Open: rejects unless the open duration has elapsed (triggers HalfOpen transition).
    /// - HalfOpen: allows probe requests.
    pub fn allow_request(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request.
    ///
    /// In Closed state, resets the failure counter.
    /// In HalfOpen state, increments success count and closes the circuit once the
    /// success threshold is reached.
    pub fn record_success(&self) {
        let current = self.state.load(Ordering::Acquire);
        match current {
            STATE_CLOSED => {
                self.failure_count.store(0, Ordering::Release);
            }
            STATE_HALF_OPEN => {
                let prev = self.success_count.fetch_add(1, Ordering::AcqRel);
                if prev + 1 >= self.success_threshold {
                    self.transition_to_closed();
                }
            }
            _ => {}
        }
    }

    /// Record a failed request.
    ///
    /// In Closed state, increments failure count and opens the circuit if the
    /// threshold is reached. In HalfOpen state, immediately transitions back to Open.
    pub fn record_failure(&self) {
        self.last_failure_time
            .store(Self::now_millis(), Ordering::Release);

        let current = self.state.load(Ordering::Acquire);
        match current {
            STATE_CLOSED => {
                let prev = self.failure_count.fetch_add(1, Ordering::AcqRel);
                if prev + 1 >= self.failure_threshold {
                    self.transition_to_open();
                }
            }
            STATE_HALF_OPEN => {
                self.transition_to_open();
            }
            _ => {}
        }
    }

    /// Reset the circuit breaker to Closed state with zeroed counters.
    pub fn reset(&self) {
        self.failure_count.store(0, Ordering::Release);
        self.success_count.store(0, Ordering::Release);
        self.last_failure_time.store(0, Ordering::Release);
        self.state.store(STATE_CLOSED, Ordering::Release);
    }

    // --- Internal Helpers ---

    fn transition_to_open(&self) {
        self.state.store(STATE_OPEN, Ordering::Release);
        self.success_count.store(0, Ordering::Release);
    }

    fn transition_to_closed(&self) {
        self.failure_count.store(0, Ordering::Release);
        self.success_count.store(0, Ordering::Release);
        self.state.store(STATE_CLOSED, Ordering::Release);
    }

    fn open_duration_elapsed(&self) -> bool {
        let last = self.last_failure_time.load(Ordering::Acquire);
        if last == 0 {
            return false;
        }
        let now = Self::now_millis();
        now.saturating_sub(last) >= self.open_duration_ms
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn decode_state(raw: u32) -> CircuitState {
        match raw {
            STATE_CLOSED => CircuitState::Closed,
            STATE_OPEN => CircuitState::Open,
            STATE_HALF_OPEN => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn starts_closed() {
        let cb = CircuitBreaker::new(3, 2, Duration::from_secs(5));
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn transitions_to_open_on_failures() {
        let cb = CircuitBreaker::new(3, 2, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn open_rejects_requests_before_timeout() {
        let cb = CircuitBreaker::new(2, 1, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn open_transitions_to_half_open_after_timeout() {
        let cb = CircuitBreaker::new(2, 1, Duration::from_millis(0));
        cb.record_failure();
        cb.record_failure();

        // open_duration is 0ms, so it should immediately transition to HalfOpen.
        // (With 0ms timeout, we may never observe Open from state().)
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        assert!(cb.allow_request());
    }

    #[test]
    fn half_open_closes_on_success_threshold() {
        let cb = CircuitBreaker::new(2, 2, Duration::from_millis(0));
        cb.record_failure();
        cb.record_failure();

        // Force HalfOpen by checking state (0ms open_duration).
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn half_open_reopens_on_failure() {
        // Use a long open_duration so we can observe the Open state after HalfOpen failure.
        let cb = CircuitBreaker::new(2, 2, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Manually force HalfOpen by setting state directly.
        cb.state.store(2, Ordering::Release); // STATE_HALF_OPEN
        cb.success_count.store(0, Ordering::Release);
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Failure in HalfOpen should transition back to Open.
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn success_in_closed_resets_failure_count() {
        let cb = CircuitBreaker::new(3, 1, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        // Failure count reset, so one more failure should not trip the breaker.
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn reset_restores_closed() {
        let cb = CircuitBreaker::new(2, 1, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }
}
