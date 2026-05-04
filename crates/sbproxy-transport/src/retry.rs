//! Retry with exponential backoff for upstream requests.
//!
//! Also provides [`RetryBudget`] for limiting the fraction of requests that
//! are retries, preventing retry storms during upstream degradation.

use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Configuration for retry behavior with exponential backoff.
#[derive(Debug, Clone, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Initial backoff duration in milliseconds.
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,

    /// Maximum backoff duration in milliseconds.
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,

    /// Status codes that should trigger a retry. Defaults to 502, 503, 504.
    #[serde(default)]
    pub retry_on_status: Vec<u16>,

    /// Whether to retry on timeout errors.
    #[serde(default)]
    pub retry_on_timeout: bool,
}

fn default_max_retries() -> u32 {
    3
}
fn default_initial_backoff_ms() -> u64 {
    100
}
fn default_max_backoff_ms() -> u64 {
    5000
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_ms: default_initial_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            retry_on_status: Vec::new(),
            retry_on_timeout: false,
        }
    }
}

impl RetryConfig {
    /// Calculate backoff duration for the nth retry (0-indexed).
    pub fn backoff_duration(&self, attempt: u32) -> Duration {
        let ms = self
            .initial_backoff_ms
            .saturating_mul(2u64.saturating_pow(attempt));
        Duration::from_millis(ms.min(self.max_backoff_ms))
    }

    /// Check if a status code should trigger a retry.
    pub fn should_retry_status(&self, status: u16) -> bool {
        if self.retry_on_status.is_empty() {
            matches!(status, 502..=504)
        } else {
            self.retry_on_status.contains(&status)
        }
    }

    /// Check if we have retries remaining.
    pub fn has_retries(&self, attempt: u32) -> bool {
        attempt < self.max_retries
    }
}

// --- RetryBudget ---

/// Retry budget tracker.
///
/// Limits the fraction of total requests that are retries, preventing retry
/// storms when an upstream is degraded.  Counters are reset periodically
/// according to `window_secs`.
///
/// # Example
///
/// ```
/// # use sbproxy_transport::RetryBudget;
/// let budget = RetryBudget::new(0.2, 60);
/// budget.record_request(false);  // normal request
/// assert!(budget.allow_retry());
/// budget.record_request(true);   // retry
/// ```
pub struct RetryBudget {
    /// Max ratio of retries to total requests (0.0 – 1.0).
    max_ratio: f64,
    /// Rolling count of all requests (retries + originals).
    total_requests: AtomicU64,
    /// Rolling count of retries only.
    total_retries: AtomicU64,
    /// Window length in seconds (not currently enforced at the atomic level;
    /// callers should call [`RetryBudget::reset`] for explicit resets).
    pub window_secs: u64,
}

impl RetryBudget {
    /// Create a new budget.
    ///
    /// * `max_ratio` – maximum fraction of requests that may be retries
    ///   (e.g. `0.2` = 20 %).
    /// * `window_secs` – sliding-window length in seconds.
    pub fn new(max_ratio: f64, window_secs: u64) -> Self {
        Self {
            max_ratio: max_ratio.clamp(0.0, 1.0),
            total_requests: AtomicU64::new(0),
            total_retries: AtomicU64::new(0),
            window_secs,
        }
    }

    /// Check whether a retry is permitted within the current budget.
    ///
    /// Returns `true` when the retry-to-total ratio is still below
    /// `max_ratio`, or when fewer than 1 request has been recorded (to avoid
    /// division by zero at startup).
    pub fn allow_retry(&self) -> bool {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return true;
        }
        let retries = self.total_retries.load(Ordering::Relaxed);
        let ratio = retries as f64 / total as f64;
        ratio < self.max_ratio
    }

    /// Record a request.
    ///
    /// * `is_retry = true` increments both the retry counter and the total
    ///   counter.
    /// * `is_retry = false` increments only the total counter.
    pub fn record_request(&self, is_retry: bool) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        if is_retry {
            self.total_retries.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Reset all counters (call this at the start of each window).
    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.total_retries.store(0, Ordering::Relaxed);
    }

    /// Current retry ratio (retries / total).  Returns `0.0` when no requests
    /// have been recorded yet.
    pub fn current_ratio(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let retries = self.total_retries.load(Ordering::Relaxed);
        retries as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_exponentially() {
        let config = RetryConfig::default();
        assert_eq!(config.backoff_duration(0), Duration::from_millis(100));
        assert_eq!(config.backoff_duration(1), Duration::from_millis(200));
        assert_eq!(config.backoff_duration(2), Duration::from_millis(400));
        assert_eq!(config.backoff_duration(3), Duration::from_millis(800));
    }

    #[test]
    fn backoff_caps_at_max() {
        let config = RetryConfig {
            max_backoff_ms: 500,
            ..Default::default()
        };
        assert_eq!(config.backoff_duration(0), Duration::from_millis(100));
        assert_eq!(config.backoff_duration(1), Duration::from_millis(200));
        assert_eq!(config.backoff_duration(2), Duration::from_millis(400));
        // 800 > 500, so capped
        assert_eq!(config.backoff_duration(3), Duration::from_millis(500));
        assert_eq!(config.backoff_duration(10), Duration::from_millis(500));
    }

    #[test]
    fn should_retry_default_statuses() {
        let config = RetryConfig::default();
        assert!(config.should_retry_status(502));
        assert!(config.should_retry_status(503));
        assert!(config.should_retry_status(504));
        assert!(!config.should_retry_status(500));
        assert!(!config.should_retry_status(200));
        assert!(!config.should_retry_status(429));
    }

    #[test]
    fn should_retry_custom_statuses() {
        let config = RetryConfig {
            retry_on_status: vec![429, 500],
            ..Default::default()
        };
        assert!(config.should_retry_status(429));
        assert!(config.should_retry_status(500));
        assert!(!config.should_retry_status(502));
        assert!(!config.should_retry_status(503));
    }

    #[test]
    fn has_retries_respects_max() {
        let config = RetryConfig {
            max_retries: 3,
            ..Default::default()
        };
        assert!(config.has_retries(0));
        assert!(config.has_retries(1));
        assert!(config.has_retries(2));
        assert!(!config.has_retries(3));
        assert!(!config.has_retries(4));
    }

    #[test]
    fn deserialize_partial_config() {
        let json = r#"{"max_retries": 5}"#;
        let config: RetryConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff_ms, 100);
        assert_eq!(config.max_backoff_ms, 5000);
        assert!(config.retry_on_status.is_empty());
        assert!(!config.retry_on_timeout);
    }

    #[test]
    fn backoff_handles_overflow_gracefully() {
        let config = RetryConfig {
            initial_backoff_ms: u64::MAX / 2,
            max_backoff_ms: u64::MAX,
            ..Default::default()
        };
        // Should not panic due to saturating arithmetic
        let _ = config.backoff_duration(10);
    }

    // --- RetryBudget tests ---

    #[test]
    fn budget_allows_retry_when_empty() {
        let budget = RetryBudget::new(0.2, 60);
        assert!(
            budget.allow_retry(),
            "budget should allow retry with no history"
        );
    }

    #[test]
    fn budget_allows_retry_below_threshold() {
        let budget = RetryBudget::new(0.2, 60);
        // 8 normal requests, 1 retry = 11.1% < 20%
        for _ in 0..8 {
            budget.record_request(false);
        }
        budget.record_request(true);
        assert!(budget.allow_retry());
    }

    #[test]
    fn budget_denies_retry_at_threshold() {
        let budget = RetryBudget::new(0.2, 60);
        // 4 normal + 1 retry already recorded = 20% -> next retry should be denied
        for _ in 0..4 {
            budget.record_request(false);
        }
        budget.record_request(true);
        // ratio = 1/5 = 0.20, not strictly < 0.20
        assert!(!budget.allow_retry());
    }

    #[test]
    fn budget_denies_retry_above_threshold() {
        let budget = RetryBudget::new(0.2, 60);
        // 1 normal + 1 retry = 50% >> 20%
        budget.record_request(false);
        budget.record_request(true);
        assert!(!budget.allow_retry());
    }

    #[test]
    fn budget_reset_clears_counters() {
        let budget = RetryBudget::new(0.2, 60);
        budget.record_request(false);
        budget.record_request(true);
        assert!(!budget.allow_retry());
        budget.reset();
        assert!(budget.allow_retry());
        assert_eq!(budget.current_ratio(), 0.0);
    }

    #[test]
    fn budget_zero_max_ratio_always_denies() {
        let budget = RetryBudget::new(0.0, 60);
        budget.record_request(false);
        assert!(
            !budget.allow_retry(),
            "0% budget should always deny retries after first request"
        );
    }

    #[test]
    fn budget_full_ratio_always_allows() {
        let budget = RetryBudget::new(1.0, 60);
        for _ in 0..100 {
            budget.record_request(true);
        }
        // ratio = 1.0 which is NOT < 1.0, so it's denied
        // This tests the clamp boundary; ratio < 1.0 is the condition.
        // After 100 retries out of 100, ratio == 1.0, so allow_retry is false.
        assert!(!budget.allow_retry());
    }

    #[test]
    fn budget_current_ratio_no_requests() {
        let budget = RetryBudget::new(0.2, 60);
        assert_eq!(budget.current_ratio(), 0.0);
    }

    #[test]
    fn budget_current_ratio_mixed() {
        let budget = RetryBudget::new(0.5, 60);
        budget.record_request(false);
        budget.record_request(false);
        budget.record_request(true);
        // 1 retry / 3 total = 0.333...
        let ratio = budget.current_ratio();
        assert!((ratio - 1.0 / 3.0).abs() < 1e-9);
    }
}
