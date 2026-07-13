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
use opentelemetry::metrics::{Counter, Histogram};

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

/// OTel counter mirroring `sbproxy_ai_cost_usd_micros_total`.
///
/// The unit is micro-USD (`1e-6` USD). Labels match the Prometheus
/// surface: `provider`, `model`, and `tenant_id`.
pub fn ai_cost_usd_micros_counter() -> &'static Counter<u64> {
    static C: OnceLock<Counter<u64>> = OnceLock::new();
    C.get_or_init(|| {
        global::meter("sbproxy")
            .u64_counter("sbproxy.ai.cost_usd_micros")
            .with_description(
                "Derived AI request cost in micro-USD, partitioned by provider, model, and tenant.",
            )
            .with_unit("micro_usd")
            .build()
    })
}

/// OTel histogram `gen_ai.client.operation.duration` (seconds).
///
/// Required instrument of the OpenTelemetry GenAI metrics
/// conventions (WOR-1873). Emitted alongside the canonical
/// `sbproxy_ai_request_duration_seconds` Prometheus family so
/// GenAI-aware backends (Datadog LLM Observability, Grafana GenAI
/// dashboards, Phoenix) chart duration without relabeling. Attribute
/// vocabulary follows the pinned span vocabulary in `sbproxy-ai`:
/// `gen_ai.system`, `gen_ai.operation.name`, `gen_ai.request.model`.
pub fn genai_operation_duration_histogram() -> &'static Histogram<f64> {
    static H: OnceLock<Histogram<f64>> = OnceLock::new();
    H.get_or_init(|| {
        global::meter("sbproxy")
            .f64_histogram("gen_ai.client.operation.duration")
            .with_description("GenAI client operation duration in seconds.")
            .with_unit("s")
            .build()
    })
}

/// OTel histogram `gen_ai.client.token.usage` (tokens).
///
/// Recommended instrument of the OpenTelemetry GenAI metrics
/// conventions (WOR-1873), mirroring the attributed Prometheus token
/// counter. `gen_ai.token.type` partitions `input` vs `output`,
/// matching the `direction` vocabulary on the Prometheus side.
pub fn genai_token_usage_histogram() -> &'static Histogram<u64> {
    static H: OnceLock<Histogram<u64>> = OnceLock::new();
    H.get_or_init(|| {
        global::meter("sbproxy")
            .u64_histogram("gen_ai.client.token.usage")
            .with_description("GenAI client token consumption, partitioned by token type.")
            .with_unit("{token}")
            .build()
    })
}

/// Record one GenAI operation duration under the semconv instrument
/// name. `operation` is the classified AI surface (the same value the
/// span vocabulary records on `gen_ai.operation.name`); `provider`
/// lands on `gen_ai.system`. No-op unless the OTLP metrics pipeline
/// is installed (`telemetry.export_metrics: true`).
pub fn record_genai_operation_duration(
    provider: &str,
    operation: &str,
    model: &str,
    duration_secs: f64,
) {
    genai_operation_duration_histogram().record(
        duration_secs,
        &[
            opentelemetry::KeyValue::new("gen_ai.system", provider.to_string()),
            opentelemetry::KeyValue::new("gen_ai.operation.name", operation.to_string()),
            opentelemetry::KeyValue::new("gen_ai.request.model", model.to_string()),
        ],
    );
}

/// Record GenAI token usage under the semconv instrument name.
/// `token_type` is `input` or `output`; zero counts are skipped so
/// image / audio events do not emit phantom token rows. No-op unless
/// the OTLP metrics pipeline is installed.
pub fn record_genai_token_usage(
    provider: &str,
    operation: &str,
    model: &str,
    token_type: &str,
    tokens: u64,
) {
    if tokens == 0 {
        return;
    }
    genai_token_usage_histogram().record(
        tokens,
        &[
            opentelemetry::KeyValue::new("gen_ai.system", provider.to_string()),
            opentelemetry::KeyValue::new("gen_ai.operation.name", operation.to_string()),
            opentelemetry::KeyValue::new("gen_ai.request.model", model.to_string()),
            opentelemetry::KeyValue::new("gen_ai.token.type", token_type.to_string()),
        ],
    );
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
    fn ai_cost_handle_constructs_idempotently() {
        let c1 = ai_cost_usd_micros_counter();
        let c2 = ai_cost_usd_micros_counter();
        assert!(std::ptr::eq(c1, c2));
    }

    #[test]
    fn genai_handles_construct_idempotently_and_record_silently() {
        let h1 = genai_operation_duration_histogram();
        let h2 = genai_operation_duration_histogram();
        assert!(std::ptr::eq(h1, h2));
        let t1 = genai_token_usage_histogram();
        let t2 = genai_token_usage_histogram();
        assert!(std::ptr::eq(t1, t2));
        // No MeterProvider installed: records must be silent no-ops.
        record_genai_operation_duration("openai", "chat_completions", "gpt-4o", 1.25);
        record_genai_token_usage("openai", "chat_completions", "gpt-4o", "input", 100);
        record_genai_token_usage("openai", "chat_completions", "gpt-4o", "output", 0);
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
        ai_cost_usd_micros_counter().add(
            123,
            &[
                opentelemetry::KeyValue::new("provider", "openai"),
                opentelemetry::KeyValue::new("model", "gpt-4o"),
                opentelemetry::KeyValue::new("tenant_id", "__default__"),
            ],
        );
    }
}
