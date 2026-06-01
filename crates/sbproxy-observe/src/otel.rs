//! OpenTelemetry instrument handles for the observation paths that
//! mirror their Prometheus counterparts.
//!
//! The Prometheus surface in the `metrics` module is the canonical
//! metric path; every metric in `metrics-stability.md` lives there
//! and is scraped from the embedded admin server. The handles in
//! this module are a parallel surface for operators who opted into
//! `telemetry.export_metrics`. The two surfaces share label
//! vocabularies (`phase`, `origin`, etc.) so dashboards bridge
//! cleanly when both are scraped from the same backend.
//!
//! ## Lifecycle
//!
//! Each instrument is built lazily on first use via
//! [`std::sync::OnceLock`]. The build calls
//! [`opentelemetry::global::meter()`], which returns a no-op meter
//! when [`crate::init_otlp_metrics_pipeline`] has not run; in that
//! case the histogram is constructed but `record()` is a no-op, so
//! the canonical Prometheus path keeps observing without paying for
//! the OTel call beyond a vtable hop.
//!
//! ## Why not register at boot
//!
//! Boot is when the meter provider gets installed. Registering
//! instruments before the provider is installed would either bind
//! them to the global no-op meter (defeating the purpose) or force
//! every callsite to check for "has the provider installed yet".
//! Lazy first-use is the cleanest of the three.

use std::sync::OnceLock;

use opentelemetry::global;
use opentelemetry::metrics::Histogram;

/// Convenience constructor for the `origin=<hostname>` label that
/// every observation here shares. Re-exported so callers do not
/// have to import `opentelemetry::KeyValue` directly (keeps
/// downstream crates off the OTel dep tree when they only mirror
/// observations through this layer).
pub fn origin_label(origin: &str) -> opentelemetry::KeyValue {
    opentelemetry::KeyValue::new("origin", origin.to_string())
}

/// OTel histogram mirroring `sbproxy_phase_duration_seconds`.
///
/// Label vocabulary matches the Prometheus side: `phase`
/// (closed enum: `auth`, `upstream_ttfb`, `response_filter`),
/// `origin` (matched hostname). Unit is seconds.
pub fn phase_duration_histogram() -> &'static Histogram<f64> {
    static H: OnceLock<Histogram<f64>> = OnceLock::new();
    H.get_or_init(|| {
        global::meter("sbproxy")
            .f64_histogram("sbproxy.phase.duration")
            .with_description(
                "Intra-request phase duration in seconds, partitioned by phase and origin.",
            )
            .with_unit("s")
            .build()
    })
}

/// OTel histogram mirroring `sbproxy_request_duration_seconds`.
///
/// Same end-to-end latency the Prometheus histogram observes;
/// labelled by `origin` only (method + status add cardinality the
/// OTel collectors typically prefer to derive from spans).
pub fn request_duration_histogram() -> &'static Histogram<f64> {
    static H: OnceLock<Histogram<f64>> = OnceLock::new();
    H.get_or_init(|| {
        global::meter("sbproxy")
            .f64_histogram("sbproxy.request.duration")
            .with_description("End-to-end request duration in seconds, by origin.")
            .with_unit("s")
            .build()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_duration_handle_constructs_idempotently() {
        let h1 = phase_duration_histogram();
        let h2 = phase_duration_histogram();
        assert!(std::ptr::eq(h1, h2));
    }

    #[test]
    fn request_duration_handle_constructs_idempotently() {
        let h1 = request_duration_histogram();
        let h2 = request_duration_histogram();
        assert!(std::ptr::eq(h1, h2));
    }

    #[test]
    fn record_without_provider_installed_is_silent() {
        // Pre-PR no MeterProvider is installed; the global meter is a
        // no-op meter and `record()` must not panic or block.
        phase_duration_histogram().record(
            0.123,
            &[
                opentelemetry::KeyValue::new("phase", "auth"),
                opentelemetry::KeyValue::new("origin", "api.example.com"),
            ],
        );
        request_duration_histogram().record(
            0.456,
            &[opentelemetry::KeyValue::new("origin", "api.example.com")],
        );
    }
}
