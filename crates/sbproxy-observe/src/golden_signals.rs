//! Automatic golden signals per origin: latency, traffic, errors, saturation.
//!
//! The four golden signals (latency, traffic, error rate, saturation) are
//! described in the Google SRE book and provide a concise health picture
//! for any service.  This module computes them from raw counters and
//! exposes a simple `is_healthy` predicate.

// --- GoldenSignals ---

/// Computed golden signals for a single proxy origin over a measurement window.
#[derive(Debug, Clone, PartialEq)]
pub struct GoldenSignals {
    /// Name of the origin (e.g. hostname or config ID).
    pub origin: String,
    /// 99th-percentile request latency in milliseconds.
    pub latency_p99_ms: f64,
    /// Request throughput in requests per second.
    pub request_rate: f64,
    /// Error rate as a fraction (0.0 = no errors, 1.0 = all errors).
    pub error_rate: f64,
    /// Saturation as a fraction of active vs. max connections (0.0 – 1.0).
    pub saturation: f64,
}

impl GoldenSignals {
    /// Compute golden signals from raw counters.
    ///
    /// # Parameters
    /// - `origin`       - Name/ID of the upstream origin.
    /// - `requests`     - Total number of requests observed in the window.
    /// - `errors`       - Number of those requests that resulted in errors.
    /// - `p99_ms`       - 99th-percentile latency for the window in milliseconds.
    /// - `active`       - Current number of active (in-flight) connections.
    /// - `max`          - Maximum allowed concurrent connections (capacity).
    /// - `window_secs`  - Duration of the measurement window in seconds.
    pub fn compute(
        origin: &str,
        requests: u64,
        errors: u64,
        p99_ms: f64,
        active: u64,
        max: u64,
        window_secs: f64,
    ) -> Self {
        let request_rate = if window_secs > 0.0 {
            requests as f64 / window_secs
        } else {
            0.0
        };

        let error_rate = if requests > 0 {
            errors as f64 / requests as f64
        } else {
            0.0
        };

        let saturation = if max > 0 {
            (active as f64 / max as f64).min(1.0)
        } else {
            0.0
        };

        Self {
            origin: origin.to_string(),
            latency_p99_ms: p99_ms,
            request_rate,
            error_rate,
            saturation,
        }
    }

    /// Returns `true` when the origin is considered healthy.
    ///
    /// An origin is healthy when:
    /// - `error_rate` does not exceed `max_error_rate`, and
    /// - `latency_p99_ms` does not exceed `max_latency_ms`.
    pub fn is_healthy(&self, max_error_rate: f64, max_latency_ms: f64) -> bool {
        self.error_rate <= max_error_rate && self.latency_p99_ms <= max_latency_ms
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- compute tests ---

    #[test]
    fn compute_basic_healthy_origin() {
        let gs = GoldenSignals::compute("api.example.com", 1000, 5, 45.0, 10, 100, 60.0);
        assert_eq!(gs.origin, "api.example.com");
        assert!((gs.request_rate - 1000.0 / 60.0).abs() < 0.001);
        assert!((gs.error_rate - 0.005).abs() < 0.0001);
        assert!((gs.saturation - 0.10).abs() < 0.0001);
        assert_eq!(gs.latency_p99_ms, 45.0);
    }

    #[test]
    fn compute_zero_requests_gives_zero_error_rate() {
        let gs = GoldenSignals::compute("origin", 0, 0, 0.0, 0, 100, 60.0);
        assert_eq!(gs.error_rate, 0.0);
        assert_eq!(gs.request_rate, 0.0);
    }

    #[test]
    fn compute_all_errors() {
        let gs = GoldenSignals::compute("origin", 100, 100, 500.0, 50, 100, 10.0);
        assert!((gs.error_rate - 1.0).abs() < 0.0001);
    }

    #[test]
    fn compute_request_rate_with_zero_window() {
        let gs = GoldenSignals::compute("origin", 1000, 0, 0.0, 0, 100, 0.0);
        assert_eq!(gs.request_rate, 0.0, "zero window should give zero rate");
    }

    #[test]
    fn compute_saturation_capped_at_one() {
        // active > max would give > 1.0 without clamping.
        let gs = GoldenSignals::compute("origin", 0, 0, 0.0, 200, 100, 60.0);
        assert!(
            gs.saturation <= 1.0,
            "saturation must not exceed 1.0, got {}",
            gs.saturation
        );
    }

    #[test]
    fn compute_saturation_zero_when_max_is_zero() {
        let gs = GoldenSignals::compute("origin", 0, 0, 0.0, 50, 0, 60.0);
        assert_eq!(gs.saturation, 0.0, "saturation should be 0 when max=0");
    }

    #[test]
    fn compute_full_saturation() {
        let gs = GoldenSignals::compute("origin", 0, 0, 0.0, 100, 100, 60.0);
        assert!((gs.saturation - 1.0).abs() < 0.0001);
    }

    #[test]
    fn compute_partial_saturation() {
        let gs = GoldenSignals::compute("origin", 0, 0, 0.0, 25, 100, 60.0);
        assert!((gs.saturation - 0.25).abs() < 0.0001);
    }

    // --- is_healthy tests ---

    #[test]
    fn is_healthy_when_within_limits() {
        let gs = GoldenSignals::compute("origin", 1000, 10, 150.0, 20, 100, 60.0);
        // error_rate = 0.01 (1%), latency = 150ms
        assert!(gs.is_healthy(0.05, 200.0), "should be healthy");
    }

    #[test]
    fn is_unhealthy_when_error_rate_exceeds_limit() {
        let gs = GoldenSignals::compute("origin", 100, 10, 50.0, 5, 100, 60.0);
        // error_rate = 0.10 (10%)
        assert!(
            !gs.is_healthy(0.05, 200.0),
            "10% errors should be unhealthy"
        );
    }

    #[test]
    fn is_unhealthy_when_latency_exceeds_limit() {
        let gs = GoldenSignals::compute("origin", 100, 0, 500.0, 5, 100, 60.0);
        assert!(!gs.is_healthy(0.05, 200.0), "500ms p99 should be unhealthy");
    }

    #[test]
    fn is_unhealthy_when_both_limits_exceeded() {
        let gs = GoldenSignals::compute("origin", 100, 20, 800.0, 90, 100, 60.0);
        assert!(!gs.is_healthy(0.05, 200.0));
    }

    #[test]
    fn is_healthy_at_exact_limits() {
        // Exactly at the threshold should be considered healthy (<=).
        let gs = GoldenSignals {
            origin: "test".to_string(),
            latency_p99_ms: 200.0,
            request_rate: 10.0,
            error_rate: 0.05,
            saturation: 0.5,
        };
        assert!(gs.is_healthy(0.05, 200.0));
    }

    #[test]
    fn is_healthy_zero_traffic_no_errors() {
        let gs = GoldenSignals::compute("idle-origin", 0, 0, 0.0, 0, 100, 60.0);
        assert!(gs.is_healthy(0.01, 100.0), "idle origin should be healthy");
    }

    #[test]
    fn compute_request_rate_per_second() {
        // 3000 requests over 30 seconds = 100 req/s
        let gs = GoldenSignals::compute("origin", 3000, 0, 0.0, 0, 100, 30.0);
        assert!((gs.request_rate - 100.0).abs() < 0.001);
    }
}
