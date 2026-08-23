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

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts};
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
static ADMISSION_REFUSALS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static ADMISSION_QUEUE: OnceLock<IntGaugeVec> = OnceLock::new();

fn normalize_transport(transport: &str) -> &'static str {
    match transport {
        "tcp" => "tcp",
        "admin_tcp" => "admin_tcp",
        "grpc" => "grpc",
        "http" => "http",
        _ => "unknown",
    }
}

fn normalize_command(command: &str) -> &'static str {
    match command {
        "" | "classify" => "classify",
        "embed" => "embed",
        "compress" => "compress",
        "model_info" => "model_info",
        "quality" => "quality",
        "quality_score" => "quality_score",
        "register" => "register",
        "delete" => "delete",
        "list" => "list",
        "version" => "version",
        "intent_detect" => "intent_detect",
        "stream_safety" => "stream_safety",
        "streaming_safety" => "streaming_safety",
        "content_type_detect" => "content_type_detect",
        "decode" => "decode",
        "tenants" => "tenants",
        _ => "unknown",
    }
}

fn normalize_reason(reason: &str) -> &'static str {
    match reason {
        "malformed_frame" => "malformed_frame",
        "unknown_command" => "unknown_command",
        "tenant_not_registered" => "tenant_not_registered",
        "invalid_config" => "invalid_config",
        "inference_failed" => "inference_failed",
        "unauthorized" => "unauthorized",
        "forbidden" => "forbidden",
        "queue_full" => "queue_full",
        "deadline" => "deadline",
        "resource_limit" => "resource_limit",
        _ => "unknown",
    }
}

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

fn admission_refusals_total() -> &'static IntCounterVec {
    ADMISSION_REFUSALS_TOTAL.get_or_init(|| {
        let counter = IntCounterVec::new(
            Opts::new(
                "sbproxy_classifier_admission_refusals_total",
                "Rich-sidecar requests refused by bounded admission, by command and reason.",
            ),
            &["cmd", "reason"],
        )
        .expect("admission refusals counter constructs");
        let _ = prometheus::register(Box::new(counter.clone()));
        counter
    })
}

fn admission_queue() -> &'static IntGaugeVec {
    ADMISSION_QUEUE.get_or_init(|| {
        let gauge = IntGaugeVec::new(
            Opts::new(
                "sbproxy_classifier_admission_queue",
                "Rich-sidecar requests currently waiting for a bounded inference slot.",
            ),
            &["cmd"],
        )
        .expect("admission queue gauge constructs");
        let _ = prometheus::register(Box::new(gauge.clone()));
        gauge
    })
}

/// Record one handled request for `(transport, cmd)`. `transport` is
/// `"tcp"` or `"grpc"`; `cmd` is the command/RPC name.
pub fn record_request(transport: &str, cmd: &str) {
    requests_total()
        .with_label_values(&[normalize_transport(transport), normalize_command(cmd)])
        .inc();
}

/// Record one failed request for `(transport, cmd, reason)`.
pub fn record_error(transport: &str, cmd: &str, reason: &str) {
    errors_total()
        .with_label_values(&[
            normalize_transport(transport),
            normalize_command(cmd),
            normalize_reason(reason),
        ])
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
        .with_label_values(&[normalize_transport(transport)])
        .observe(score);
}

/// Record one streaming-safety verdict. `verdict` is `"safe"` or
/// `"blocked"`.
pub fn record_safety_verdict(verdict: &str) {
    let verdict = match verdict {
        "safe" => "safe",
        "blocked" => "blocked",
        _ => "unknown",
    };
    safety_verdicts_total().with_label_values(&[verdict]).inc();
}

/// Record an admission refusal with closed command/reason labels.
pub fn record_admission_refusal(command: &str, reason: &str) {
    admission_refusals_total()
        .with_label_values(&[normalize_command(command), normalize_reason(reason)])
        .inc();
}

/// Adjust the current queue depth for a closed command label.
pub fn adjust_admission_queue(command: &str, delta: i64) {
    admission_queue()
        .with_label_values(&[normalize_command(command)])
        .add(delta);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_commands_collapse_to_one_unknown_label() {
        for index in 0..10_000 {
            assert_eq!(normalize_command(&format!("attacker-{index}")), "unknown");
        }
        assert_eq!(normalize_command("classify"), "classify");
        assert_eq!(normalize_command(""), "classify");
    }

    #[test]
    fn recording_a_request_increments_the_counter() {
        record_request("tcp", "classify_test_marker");
        let value = requests_total()
            .with_label_values(&["tcp", "unknown"])
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
