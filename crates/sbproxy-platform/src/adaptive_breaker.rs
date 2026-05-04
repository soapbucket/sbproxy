//! Adaptive circuit breaker with dynamic threshold tuning.
//!
//! Unlike the fixed-threshold [`CircuitBreaker`][super::CircuitBreaker], this
//! breaker adjusts its error-rate threshold over time based on observed
//! traffic. If errors remain elevated after the circuit closes, the threshold
//! is lowered so the circuit trips again more quickly. If the service recovers
//! cleanly, the threshold drifts back towards the initial value.
//!
//! The adaptation uses a simple exponential moving average (EMA):
//!
//! ```text
//! threshold_new = threshold_old + learning_rate * (target - threshold_old)
//! ```
//!
//! where `target` is either `0.0` (errors are spiking, push threshold down
//! towards zero so the breaker trips sooner) or `initial_threshold` (service
//! is healthy, relax back to the default).

use super::CircuitState;

// --- Adaptive Breaker ---

/// An adaptive circuit breaker that tunes its error-rate threshold based on
/// recent traffic history.
pub struct AdaptiveBreaker {
    /// Initial (and maximum relaxed) error-rate threshold.
    initial_threshold: f64,
    /// Current dynamic threshold (0.0 - 1.0).
    threshold: f64,
    /// Learning rate for EMA-based threshold adjustment (0.0 - 1.0).
    learning_rate: f64,
    /// Current circuit state.
    state: CircuitState,
    /// Minimum number of requests required before the error rate is evaluated.
    min_samples: u64,
    /// Total requests recorded.
    total_requests: u64,
    /// Total errors recorded.
    total_errors: u64,
}

impl AdaptiveBreaker {
    /// Create a new adaptive circuit breaker.
    ///
    /// - `initial_threshold`: starting error-rate threshold (e.g. `0.5` for 50%).
    /// - `learning_rate`: how quickly the threshold adapts (e.g. `0.1`).
    /// - `min_samples`: minimum requests before the breaker evaluates error rate.
    pub fn new(initial_threshold: f64, learning_rate: f64, min_samples: u64) -> Self {
        Self {
            initial_threshold,
            threshold: initial_threshold,
            learning_rate,
            state: CircuitState::Closed,
            min_samples,
            total_requests: 0,
            total_errors: 0,
        }
    }

    /// Record a successful request.
    pub fn record_success(&mut self) {
        self.total_requests += 1;
        self.update_error_rate();
        // When enough samples have been seen and the error rate is below
        // threshold, ensure the circuit stays or moves to Closed.
        if self.total_requests >= self.min_samples {
            let current_rate = self.error_rate();
            if current_rate < self.threshold {
                if self.state == CircuitState::HalfOpen {
                    self.state = CircuitState::Closed;
                }
                // Healthy traffic: relax threshold back towards initial value.
                self.adapt_threshold();
            }
        }
    }

    /// Record a failed request.
    pub fn record_failure(&mut self) {
        self.total_requests += 1;
        self.total_errors += 1;
        self.update_error_rate();
        if self.total_requests >= self.min_samples {
            let current_rate = self.error_rate();
            if current_rate >= self.threshold {
                self.state = CircuitState::Open;
                // Errors are elevated: tighten threshold so next trip is faster.
                self.adapt_threshold();
            }
        }
    }

    /// Returns `true` when the circuit is open (requests should be rejected).
    pub fn is_open(&self) -> bool {
        self.state == CircuitState::Open
    }

    /// Returns the current circuit state.
    pub fn state(&self) -> &CircuitState {
        &self.state
    }

    /// Returns the current dynamic threshold.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Returns the current error rate (0.0 - 1.0).
    pub fn error_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.total_errors as f64 / self.total_requests as f64
    }

    // --- Internal ---

    fn update_error_rate(&mut self) {
        // Recalculate the rolling error rate; stored implicitly via counters.
        // No additional state needed - error_rate() computes it on demand.
    }

    /// Adjust threshold using EMA:
    /// - When error rate is high, push threshold down (circuit trips sooner).
    /// - When error rate is low, relax threshold back up (circuit is lenient).
    fn adapt_threshold(&mut self) {
        let current_rate = self.error_rate();
        let target = if current_rate >= self.threshold {
            // Errors spiking: pull threshold towards 0 (more sensitive).
            0.0
        } else {
            // Healthy: relax threshold back towards initial_threshold.
            self.initial_threshold
        };
        self.threshold += self.learning_rate * (target - self.threshold);
        // Clamp to [0.0, initial_threshold] so we never become more permissive
        // than the original config or go negative.
        self.threshold = self.threshold.clamp(0.0, self.initial_threshold);
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_closed() {
        let ab = AdaptiveBreaker::new(0.5, 0.1, 5);
        assert_eq!(ab.state(), &CircuitState::Closed);
        assert!(!ab.is_open());
    }

    #[test]
    fn opens_on_high_error_rate() {
        // threshold=0.5, min_samples=4 - the 4th request is also a failure.
        let mut ab = AdaptiveBreaker::new(0.5, 0.1, 4);
        // 4 failures out of 4 requests = 100% error rate > 50% threshold.
        ab.record_failure();
        ab.record_failure();
        ab.record_failure();
        ab.record_failure();
        assert!(
            ab.is_open(),
            "should open when error rate exceeds threshold"
        );
    }

    #[test]
    fn stays_closed_below_min_samples() {
        let mut ab = AdaptiveBreaker::new(0.5, 0.1, 10);
        // Even with 100% errors, should not open before min_samples.
        for _ in 0..5 {
            ab.record_failure();
        }
        assert!(!ab.is_open(), "should not open before min_samples reached");
    }

    #[test]
    fn stays_closed_below_threshold() {
        let mut ab = AdaptiveBreaker::new(0.5, 0.1, 4);
        // 1 failure out of 4 = 25% < 50% threshold.
        ab.record_failure();
        ab.record_success();
        ab.record_success();
        ab.record_success();
        assert!(!ab.is_open(), "should remain closed below threshold");
    }

    #[test]
    fn threshold_decreases_on_sustained_errors() {
        let mut ab = AdaptiveBreaker::new(0.5, 0.2, 2);
        let initial = ab.threshold();
        // Force errors to trigger adaptation.
        ab.record_failure();
        ab.record_failure();
        assert!(
            ab.threshold() < initial,
            "threshold should decrease on high error rate; was {initial}, now {}",
            ab.threshold()
        );
    }

    #[test]
    fn threshold_relaxes_on_recovery() {
        let mut ab = AdaptiveBreaker::new(0.5, 0.2, 2);
        // First: push threshold down with errors.
        ab.record_failure();
        ab.record_failure();
        let after_errors = ab.threshold();
        // Reset counters manually to simulate a new window with clean traffic.
        ab.total_requests = 0;
        ab.total_errors = 0;
        ab.state = CircuitState::Closed;
        // Now healthy traffic: threshold should drift back up.
        ab.record_success();
        ab.record_success();
        assert!(
            ab.threshold() >= after_errors,
            "threshold should relax on recovery; was {after_errors}, now {}",
            ab.threshold()
        );
    }

    #[test]
    fn error_rate_calculation() {
        let mut ab = AdaptiveBreaker::new(0.5, 0.1, 1);
        ab.record_failure();
        ab.record_success();
        // 1 error / 2 total = 0.5
        let rate = ab.error_rate();
        assert!(
            (rate - 0.5).abs() < f64::EPSILON,
            "expected 0.5 error rate, got {rate}"
        );
    }

    #[test]
    fn threshold_clamped_to_initial_max() {
        let mut ab = AdaptiveBreaker::new(0.5, 1.0, 1); // learning_rate=1.0 for max effect
                                                        // Trigger healthy adaptation: target = initial_threshold = 0.5.
        ab.record_success();
        ab.record_success();
        assert!(
            ab.threshold() <= 0.5,
            "threshold must not exceed initial_threshold"
        );
    }
}
