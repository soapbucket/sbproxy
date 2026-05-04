//! Outlier detection for upstream health management.
//!
//! Tracks error rates per upstream endpoint in a sliding window.  When an
//! endpoint exceeds the configured error threshold it is *ejected* from the
//! active pool.  A configurable cooldown passes before the endpoint is
//! re-admitted so that traffic can probe whether it has recovered.
//!
//! # Example
//!
//! ```
//! # use sbproxy_platform::outlier::{OutlierDetector, OutlierDetectorConfig};
//! let cfg = OutlierDetectorConfig {
//!     threshold: 0.5,
//!     window_secs: 60,
//!     min_requests: 5,
//!     ejection_duration_secs: 30,
//! };
//! let detector = OutlierDetector::new(cfg);
//!
//! detector.record_success("host-a:8080");
//! detector.record_failure("host-b:8080");
//! ```

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// --- OutlierDetectorConfig ---

/// Configuration for the [`OutlierDetector`].
pub struct OutlierDetectorConfig {
    /// Error rate threshold for ejection (0.0 – 1.0).
    ///
    /// An endpoint is ejected when `failures / (successes + failures) >= threshold`.
    /// Default: 0.5 (50 %).
    pub threshold: f64,

    /// Duration of the sliding measurement window, in seconds.
    ///
    /// Counters are reset after this interval so that recovered endpoints
    /// are eventually re-evaluated with a clean slate.  Default: 60 s.
    pub window_secs: u64,

    /// Minimum number of requests that must have been observed in the window
    /// before ejection is considered.  Prevents false positives on endpoints
    /// that have received very little traffic.  Default: 5.
    pub min_requests: u32,

    /// How long an ejected endpoint stays out of the pool before being
    /// re-admitted and probed again.  Default: 30 s.
    pub ejection_duration_secs: u64,
}

impl Default for OutlierDetectorConfig {
    fn default() -> Self {
        Self {
            threshold: 0.5,
            window_secs: 60,
            min_requests: 5,
            ejection_duration_secs: 30,
        }
    }
}

// --- EndpointStats ---

/// Per-endpoint counters for a single measurement window.
struct EndpointStats {
    successes: u32,
    failures: u32,
    /// Start of the current window.
    window_start: Instant,
}

impl EndpointStats {
    fn new() -> Self {
        Self {
            successes: 0,
            failures: 0,
            window_start: Instant::now(),
        }
    }

    fn total(&self) -> u32 {
        self.successes + self.failures
    }

    fn error_rate(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        self.failures as f64 / total as f64
    }
}

// --- OutlierDetector ---

/// Detects and ejects misbehaving upstream endpoints.
///
/// All methods are thread-safe via an internal `Mutex`.
pub struct OutlierDetector {
    config: OutlierDetectorConfig,
    /// endpoint_id → per-window statistics.
    stats: Mutex<HashMap<String, EndpointStats>>,
    /// endpoint_id → earliest time at which re-admission is allowed.
    ejected: Mutex<HashMap<String, Instant>>,
}

impl OutlierDetector {
    /// Create a new detector with the given configuration.
    pub fn new(config: OutlierDetectorConfig) -> Self {
        Self {
            config,
            stats: Mutex::new(HashMap::new()),
            ejected: Mutex::new(HashMap::new()),
        }
    }

    /// Record a successful request to `endpoint`.
    pub fn record_success(&self, endpoint: &str) {
        self.with_stats_mut(endpoint, |stats| {
            stats.successes = stats.successes.saturating_add(1);
        });
    }

    /// Record a failed request to `endpoint`.
    pub fn record_failure(&self, endpoint: &str) {
        self.with_stats_mut(endpoint, |stats| {
            stats.failures = stats.failures.saturating_add(1);
        });
    }

    /// Returns `true` when `endpoint` is currently ejected.
    ///
    /// Expired ejections are removed lazily on this call.
    pub fn is_ejected(&self, endpoint: &str) -> bool {
        let mut ejected = self.ejected.lock().unwrap();
        match ejected.get(endpoint) {
            None => false,
            Some(&re_admit_at) => {
                if Instant::now() >= re_admit_at {
                    // Ejection period has passed; re-admit the endpoint.
                    ejected.remove(endpoint);
                    false
                } else {
                    true
                }
            }
        }
    }

    /// Evaluate all endpoints and eject any that exceed the error threshold.
    ///
    /// Returns the IDs of newly ejected endpoints.
    pub fn check_ejections(&self) -> Vec<String> {
        let window = Duration::from_secs(self.config.window_secs);
        let now = Instant::now();
        let mut newly_ejected = Vec::new();

        let mut stats_map = self.stats.lock().unwrap();
        let mut ejected_map = self.ejected.lock().unwrap();

        for (endpoint, stats) in stats_map.iter_mut() {
            // --- Reset window if expired ---
            if now.duration_since(stats.window_start) >= window {
                *stats = EndpointStats::new();
                continue;
            }

            // --- Skip if already ejected ---
            if ejected_map.contains_key(endpoint.as_str()) {
                continue;
            }

            // --- Check threshold ---
            if stats.total() < self.config.min_requests {
                continue;
            }

            if stats.error_rate() >= self.config.threshold {
                let re_admit_at = now + Duration::from_secs(self.config.ejection_duration_secs);
                ejected_map.insert(endpoint.clone(), re_admit_at);
                newly_ejected.push(endpoint.clone());
            }
        }

        newly_ejected
    }

    /// Re-admit endpoints whose ejection period has expired.
    ///
    /// Returns the IDs of endpoints that were re-admitted.
    pub fn check_readmissions(&self) -> Vec<String> {
        let now = Instant::now();
        let mut ejected_map = self.ejected.lock().unwrap();

        let readmitted: Vec<String> = ejected_map
            .iter()
            .filter_map(|(endpoint, &re_admit_at)| {
                if now >= re_admit_at {
                    Some(endpoint.clone())
                } else {
                    None
                }
            })
            .collect();

        for endpoint in &readmitted {
            ejected_map.remove(endpoint);
        }

        readmitted
    }

    // --- Internal helpers ---

    /// Apply `f` to the [`EndpointStats`] for `endpoint`, resetting the window
    /// if it has expired.
    fn with_stats_mut(&self, endpoint: &str, f: impl FnOnce(&mut EndpointStats)) {
        let window = Duration::from_secs(self.config.window_secs);
        let mut stats_map = self.stats.lock().unwrap();
        let stats = stats_map
            .entry(endpoint.to_string())
            .or_insert_with(EndpointStats::new);

        // Reset if window expired.
        if Instant::now().duration_since(stats.window_start) >= window {
            *stats = EndpointStats::new();
        }

        f(stats);
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn default_config() -> OutlierDetectorConfig {
        OutlierDetectorConfig {
            threshold: 0.5,
            window_secs: 60,
            min_requests: 5,
            ejection_duration_secs: 30,
        }
    }

    #[test]
    fn new_endpoint_is_not_ejected() {
        let detector = OutlierDetector::new(default_config());
        assert!(!detector.is_ejected("host-a:8080"));
    }

    #[test]
    fn healthy_endpoint_not_ejected() {
        let detector = OutlierDetector::new(default_config());
        for _ in 0..10 {
            detector.record_success("host-a");
        }
        let ejected = detector.check_ejections();
        assert!(ejected.is_empty());
        assert!(!detector.is_ejected("host-a"));
    }

    #[test]
    fn endpoint_ejected_when_threshold_exceeded() {
        let detector = OutlierDetector::new(default_config());
        // 5 requests, all failures -> 100% error rate > 50% threshold
        for _ in 0..5 {
            detector.record_failure("bad-host");
        }
        let ejected = detector.check_ejections();
        assert!(ejected.contains(&"bad-host".to_string()));
        assert!(detector.is_ejected("bad-host"));
    }

    #[test]
    fn below_min_requests_not_ejected() {
        let cfg = OutlierDetectorConfig {
            min_requests: 10,
            ..default_config()
        };
        let detector = OutlierDetector::new(cfg);
        // Only 4 failures, but min_requests = 10
        for _ in 0..4 {
            detector.record_failure("maybe-bad");
        }
        let ejected = detector.check_ejections();
        assert!(ejected.is_empty(), "should not eject below min_requests");
    }

    #[test]
    fn exactly_at_threshold_triggers_ejection() {
        let cfg = OutlierDetectorConfig {
            threshold: 0.5,
            min_requests: 2,
            ..default_config()
        };
        let detector = OutlierDetector::new(cfg);
        // 1 success + 1 failure = 50% error rate = threshold -> eject
        detector.record_success("borderline");
        detector.record_failure("borderline");
        let ejected = detector.check_ejections();
        assert!(ejected.contains(&"borderline".to_string()));
    }

    #[test]
    fn readmission_after_ejection_period() {
        let cfg = OutlierDetectorConfig {
            ejection_duration_secs: 0, // immediate re-admission
            min_requests: 1,
            threshold: 0.5,
            window_secs: 60,
        };
        let detector = OutlierDetector::new(cfg);
        detector.record_failure("flaky");
        let ejected = detector.check_ejections();
        assert!(ejected.contains(&"flaky".to_string()));

        // With ejection_duration_secs = 0 the re-admit time is already past.
        let readmitted = detector.check_readmissions();
        assert!(readmitted.contains(&"flaky".to_string()));
        assert!(!detector.is_ejected("flaky"));
    }

    #[test]
    fn multiple_endpoints_independent() {
        let detector = OutlierDetector::new(default_config());
        for _ in 0..5 {
            detector.record_failure("bad");
            detector.record_success("good");
            detector.record_success("good");
        }
        let ejected = detector.check_ejections();
        assert!(ejected.contains(&"bad".to_string()));
        assert!(!ejected.contains(&"good".to_string()));
        assert!(!detector.is_ejected("good"));
    }

    #[test]
    fn is_ejected_returns_false_after_re_admit_time() {
        // Manually insert an expired ejection and verify is_ejected re-admits.
        let detector = OutlierDetector::new(default_config());
        {
            let mut ejected_map = detector.ejected.lock().unwrap();
            // Set re-admit time 1 second in the past.
            ejected_map.insert(
                "expired-host".to_string(),
                Instant::now() - Duration::from_secs(1),
            );
        }
        assert!(
            !detector.is_ejected("expired-host"),
            "expired ejection should be re-admitted lazily"
        );
    }

    #[test]
    fn check_ejections_does_not_double_eject() {
        let detector = OutlierDetector::new(default_config());
        for _ in 0..5 {
            detector.record_failure("repeat");
        }
        let first = detector.check_ejections();
        assert_eq!(first.len(), 1);
        let second = detector.check_ejections();
        assert!(
            second.is_empty(),
            "already-ejected endpoint should not appear again"
        );
    }

    #[test]
    fn record_success_and_failure_saturation() {
        // Ensure saturating arithmetic prevents u32 overflow.
        let detector = OutlierDetector::new(default_config());
        {
            let mut stats_map = detector.stats.lock().unwrap();
            let stats = stats_map
                .entry("overflow-test".to_string())
                .or_insert_with(EndpointStats::new);
            stats.successes = u32::MAX;
            stats.failures = u32::MAX;
        }
        // Should not panic.
        detector.record_success("overflow-test");
        detector.record_failure("overflow-test");
    }
}
