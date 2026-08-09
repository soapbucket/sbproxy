// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Prometheus metrics for the Gateway API controller.
//!
//! Four families, all on the global default registry so the single
//! `/metrics` handler in the binary serves everything:
//!
//! | Metric | Labels | Answers |
//! | --- | --- | --- |
//! | `sbproxy_gateway_reconcile_total` | `kind`, `result` | is the loop running, and is it succeeding |
//! | `sbproxy_gateway_reconcile_duration_seconds` | `kind` | is a reconcile taking longer than the resync interval |
//! | `sbproxy_gateway_watch_errors_total` | `kind` | is a watch stuck on auth or a missing CRD |
//! | `sbproxy_gateway_status_writes_total` | `kind`, `result` | is RBAC missing the `/status` subresource |
//!
//! `kind` is one of `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`,
//! or `periodic`, so cardinality is bounded by a closed set.
//!
//! Registration is fallible and its failure is swallowed. A duplicate
//! registration or a bad metric name is a reason to serve one fewer
//! series, never a reason to take down a controller that is otherwise
//! reconciling correctly.

use std::sync::OnceLock;

use prometheus::{
    register_histogram_vec, register_int_counter_vec, HistogramOpts, HistogramVec, IntCounterVec,
    Opts,
};

/// `result` label for an operation that succeeded.
pub const RESULT_SUCCESS: &str = "success";
/// `result` label for an operation that failed.
pub const RESULT_ERROR: &str = "error";

static RECONCILE_TOTAL: OnceLock<Option<IntCounterVec>> = OnceLock::new();
static RECONCILE_DURATION: OnceLock<Option<HistogramVec>> = OnceLock::new();
static WATCH_ERRORS: OnceLock<Option<IntCounterVec>> = OnceLock::new();
static STATUS_WRITES: OnceLock<Option<IntCounterVec>> = OnceLock::new();

fn reconcile_total() -> Option<&'static IntCounterVec> {
    RECONCILE_TOTAL
        .get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "sbproxy_gateway_reconcile_total",
                    "Gateway API reconcile attempts by triggering resource kind and outcome"
                ),
                &["kind", "result"]
            )
            .ok()
        })
        .as_ref()
}

fn reconcile_duration() -> Option<&'static HistogramVec> {
    RECONCILE_DURATION
        .get_or_init(|| {
            register_histogram_vec!(
                HistogramOpts::new(
                    "sbproxy_gateway_reconcile_duration_seconds",
                    "Gateway API reconcile latency in seconds by triggering resource kind"
                )
                .buckets(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ]),
                &["kind"]
            )
            .ok()
        })
        .as_ref()
}

fn watch_errors() -> Option<&'static IntCounterVec> {
    WATCH_ERRORS
        .get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "sbproxy_gateway_watch_errors_total",
                    "Watch stream errors by Kubernetes resource kind"
                ),
                &["kind"]
            )
            .ok()
        })
        .as_ref()
}

fn status_writes() -> Option<&'static IntCounterVec> {
    STATUS_WRITES
        .get_or_init(|| {
            register_int_counter_vec!(
                Opts::new(
                    "sbproxy_gateway_status_writes_total",
                    "Status subresource patches by Kubernetes resource kind and outcome"
                ),
                &["kind", "result"]
            )
            .ok()
        })
        .as_ref()
}

/// Record one reconcile pass.
pub fn record_reconcile(kind: &str, result: &str, duration_secs: f64) {
    if let Some(counter) = reconcile_total() {
        counter.with_label_values(&[kind, result]).inc();
    }
    if let Some(hist) = reconcile_duration() {
        hist.with_label_values(&[kind]).observe(duration_secs);
    }
}

/// Record one watch stream error.
///
/// Distinct from a reconcile error: these come from the API server
/// connection itself, so a rising count with a flat reconcile count means
/// the controller is blind rather than broken.
pub fn record_watch_error(kind: &str) {
    if let Some(counter) = watch_errors() {
        counter.with_label_values(&[kind]).inc();
    }
}

/// Record one `/status` subresource patch.
pub fn record_status_write(kind: &str, result: &str) {
    if let Some(counter) = status_writes() {
        counter.with_label_values(&[kind, result]).inc();
    }
}

/// Register every family up front so `/metrics` serves the series before
/// the first reconcile. Safe to call more than once.
pub fn init() {
    let _ = reconcile_total();
    let _ = reconcile_duration();
    let _ = watch_errors();
    let _ = status_writes();
}

/// Render the default registry in the Prometheus text exposition format.
///
/// An encoding failure yields an empty body rather than an error: a
/// scrape that returns nothing is a gap in a graph, and returning 500
/// from `/metrics` would be read as the controller being down.
pub fn gather_text() -> String {
    use prometheus::Encoder;
    let families = prometheus::gather();
    let mut buf = Vec::new();
    if prometheus::TextEncoder::new()
        .encode(&families, &mut buf)
        .is_err()
    {
        tracing::warn!(target: "k8s_audit", "failed to encode Prometheus metrics");
        return String::new();
    }
    String::from_utf8(buf).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_registers_and_increments_without_panicking() {
        init();
        record_reconcile("Gateway", RESULT_SUCCESS, 0.123);
        record_reconcile("HTTPRoute", RESULT_ERROR, 1.5);
        record_watch_error("GRPCRoute");
        record_status_write("GatewayClass", RESULT_SUCCESS);

        let text = gather_text();
        assert!(text.contains("sbproxy_gateway_reconcile_total"), "{text}");
        assert!(
            text.contains("sbproxy_gateway_watch_errors_total"),
            "{text}"
        );
        assert!(
            text.contains("sbproxy_gateway_status_writes_total"),
            "{text}"
        );
        assert!(
            text.contains("sbproxy_gateway_reconcile_duration_seconds_bucket"),
            "{text}"
        );
    }

    #[test]
    fn result_labels_are_stable() {
        // Dashboards and alerts key off these two strings.
        assert_eq!(RESULT_SUCCESS, "success");
        assert_eq!(RESULT_ERROR, "error");
    }

    #[test]
    fn init_is_idempotent() {
        init();
        init();
        // A labeled family has no children until something increments it, so
        // gathering straight after `init` says nothing either way. Record
        // once, then assert: that proves the second `init` neither panicked
        // on a duplicate registration nor replaced the first family with one
        // the recorders no longer hold.
        record_reconcile("Gateway", RESULT_SUCCESS, 0.01);
        assert!(gather_text().contains("sbproxy_gateway_reconcile_total"));
    }
}
