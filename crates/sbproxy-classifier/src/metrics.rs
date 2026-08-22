//! Prometheus metrics for this sidecar's own `/metrics` endpoint.
//!
//! New for this port (the enterprise crate registered its own metrics
//! through `metrics` + `metrics-exporter-prometheus`; this file registers
//! the same *kind* of signal through the `prometheus` crate instead, which
//! is what the rest of this workspace, `sbproxy-observe`, standardizes on).
//! Using a second metrics stack for one binary would mean patching,
//! licensing, and keeping two Prometheus client libraries in sync for no
//! reason; `prometheus` already does the job.
//!
//! These families are registered on the process-global default registry
//! (`prometheus::default_registry()`), the same one `prometheus::gather()`
//! reads in [`crate::health`]'s `/metrics` handler. This binary runs as its
//! own process, so there is no risk of colliding with the main proxy's own
//! metric families the way there would be if this were linked into it.
//!
//! Every family here is scraped by `dashboards/grafana/sbproxy-classifier.json`;
//! see `docs/classifier-sidecar.md#metrics` for the panel-to-family mapping
//! and `scripts/check-metric-visibility.sh`'s docstring for why a metric
//! with nowhere to be seen is treated as undone.

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts};
use std::sync::OnceLock;

// Every `.expect(..)` below follows `IntCounterVec`/`HistogramVec`/`IntGauge`
// `::new(..)` on a metric name and label set that is a hardcoded literal
// right above it, never derived from a request or from operator input.
// `prometheus::Error` from this constructor means the literal itself is
// malformed (an invalid name or duplicate label), which a passing test suite
// already rules out; there is no runtime input that can make it fail here.
// Matches `sbproxy-observe`'s own `overflow_counter()` (`metrics.rs`), the
// same pattern for the same reason.

static REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static ERRORS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static TENANTS: OnceLock<IntGauge> = OnceLock::new();
static QUALITY_SCORE: OnceLock<HistogramVec> = OnceLock::new();
static SAFETY_VERDICTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

fn requests_total() -> &'static IntCounterVec {
    REQUESTS_TOTAL.get_or_init(|| {
        let counter = IntCounterVec::new(
            Opts::new(
                "sbproxy_classifier_requests_total",
                "Requests handled by the rich classifier sidecar, by transport and command.",
            ),
            &["transport", "cmd"],
        )
        .expect("requests_total constructs");
        let _ = prometheus::register(Box::new(counter.clone()));
        counter
    })
}

fn errors_total() -> &'static IntCounterVec {
    ERRORS_TOTAL.get_or_init(|| {
        let counter = IntCounterVec::new(
            Opts::new(
                "sbproxy_classifier_errors_total",
                "Requests the rich classifier sidecar could not complete, by transport, command, and reason.",
            ),
            &["transport", "cmd", "reason"],
        )
        .expect("errors_total constructs");
        let _ = prometheus::register(Box::new(counter.clone()));
        counter
    })
}

fn tenants_gauge() -> &'static IntGauge {
    TENANTS.get_or_init(|| {
        let gauge = IntGauge::new(
            "sbproxy_classifier_tenants",
            "Tenants currently registered with the rich classifier sidecar.",
        )
        .expect("tenants gauge constructs");
        let _ = prometheus::register(Box::new(gauge.clone()));
        gauge
    })
}

fn quality_score_histogram() -> &'static HistogramVec {
    QUALITY_SCORE.get_or_init(|| {
        let histogram = HistogramVec::new(
            HistogramOpts::new(
                "sbproxy_classifier_quality_score",
                "Heuristic quality scores returned by the Quality RPC/command, 0.0 (poor) to 1.0 (excellent).",
            )
            .buckets(vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]),
            &["transport"],
        )
        .expect("quality_score histogram constructs");
        let _ = prometheus::register(Box::new(histogram.clone()));
        histogram
    })
}

fn safety_verdicts_total() -> &'static IntCounterVec {
    SAFETY_VERDICTS_TOTAL.get_or_init(|| {
        let counter = IntCounterVec::new(
            Opts::new(
                "sbproxy_classifier_safety_verdicts_total",
                "Per-token streaming safety verdicts, by outcome (safe / blocked).",
            ),
            &["verdict"],
        )
        .expect("safety_verdicts_total constructs");
        let _ = prometheus::register(Box::new(counter.clone()));
        counter
    })
}

/// Record one handled request for `(transport, cmd)`. `transport` is
/// `"tcp"` or `"grpc"`; `cmd` is the command/RPC name.
pub fn record_request(transport: &str, cmd: &str) {
    requests_total().with_label_values(&[transport, cmd]).inc();
}

/// Record one failed request for `(transport, cmd, reason)`.
pub fn record_error(transport: &str, cmd: &str, reason: &str) {
    errors_total()
        .with_label_values(&[transport, cmd, reason])
        .inc();
}

/// Set the current tenant count (called after every register/delete).
pub fn set_tenant_count(count: usize) {
    tenants_gauge().set(count as i64);
}

/// Record a `Quality` score observation for `transport` (`"tcp"` or
/// `"grpc"`).
pub fn record_quality_score(transport: &str, score: f64) {
    quality_score_histogram()
        .with_label_values(&[transport])
        .observe(score);
}

/// Record one streaming-safety verdict. `verdict` is `"safe"` or
/// `"blocked"`.
pub fn record_safety_verdict(verdict: &str) {
    safety_verdicts_total().with_label_values(&[verdict]).inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_a_request_increments_the_counter() {
        record_request("tcp", "classify_test_marker");
        let value = requests_total()
            .with_label_values(&["tcp", "classify_test_marker"])
            .get();
        assert!(value >= 1);
    }

    #[test]
    fn tenant_gauge_reflects_the_last_set_value() {
        set_tenant_count(3);
        assert_eq!(tenants_gauge().get(), 3);
        set_tenant_count(0);
        assert_eq!(tenants_gauge().get(), 0);
    }

    #[test]
    fn safety_verdict_counters_are_independent_per_label() {
        record_safety_verdict("safe");
        record_safety_verdict("blocked");
        assert!(safety_verdicts_total().with_label_values(&["safe"]).get() >= 1);
        assert!(
            safety_verdicts_total()
                .with_label_values(&["blocked"])
                .get()
                >= 1
        );
    }
}
