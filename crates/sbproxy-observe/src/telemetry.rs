//! OpenTelemetry tracing support for sbproxy.
//!
//! Per `docs/adr-observability.md` (A1.4) the observe crate owns:
//!
//! 1. **Span context** ([`SpanContext`]): a small W3C Trace Context
//!    helper used by request handlers to propagate `traceparent`
//!    headers across hops. Has no dependency on the heavyweight OTel
//!    SDK so it costs nothing when telemetry is disabled.
//! 2. **OTLP exporter** ([`init_otlp_pipeline`]): builds and installs
//!    a tracing-subscriber layer that forwards spans to an OTLP
//!    collector over HTTP/proto. Called once at startup when the
//!    operator sets `telemetry.enabled: true` and an `endpoint`.
//! 3. **W3C TraceContext propagator** ([`init_propagator`]): registers
//!    the OTel-default propagator as the global text-map propagator so
//!    every outbound HTTP client that goes through
//!    [`inject_into_headers`] picks up the current trace.
//! 4. **Span-naming helper** ([`span`]): every pillar emits spans
//!    named `sbproxy.<pillar>.<verb>` so dashboards group cleanly.

use anyhow::Result;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace as sdktrace;
use opentelemetry_sdk::Resource;
use opentelemetry_semantic_conventions as semconv;
use serde::Deserialize;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Transport for the OTLP exporter. HTTP/proto is the lighter
/// option (one less dep tree) and the default; gRPC is what most
/// collectors expect and what the public OpenTelemetry tutorials
/// assume.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OtlpTransport {
    /// OTLP over HTTP with protobuf payload (default endpoint
    /// `http://localhost:4318/v1/traces`).
    #[default]
    Http,
    /// OTLP over gRPC (default endpoint `http://localhost:4317`).
    Grpc,
}

/// Configuration for the OpenTelemetry pipeline.
///
/// Mirrors the YAML described in `docs/adr-observability.md`. The Wave 1
/// substrate ships head-based sampling (parent-based + always-sample
/// errors + ratio for unsampled roots); tail-based sampling is deferred
/// to Wave 6 per A1.4.
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    /// Whether tracing is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// OTLP collector endpoint. The default depends on the chosen
    /// `transport`: `http://localhost:4318/v1/traces` for HTTP,
    /// `http://localhost:4327` for gRPC (matching the Day-1 reference
    /// Compose stack in `examples/00-observability-stack/`).
    pub endpoint: Option<String>,
    /// OTLP transport selector.
    #[serde(default = "default_transport")]
    pub transport: OtlpTransport,
    /// Service name reported in spans.
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// Head-based sampling probability for unsampled roots. Default is
    /// 10% per A1.4. Errors and parent-sampled requests are always
    /// captured regardless of this value.
    #[serde(default)]
    pub sample_rate: Option<f64>,
    /// When `true`, every 5xx / policy-block / ledger-denial root span
    /// is sampled at 100% even if the head ratio would have dropped it.
    /// Default `true` per A1.4.
    #[serde(default = "default_always_sample_errors")]
    pub always_sample_errors: bool,
    /// Propagation format: `"w3c"` (default), `"b3"`, or `"jaeger"`.
    /// Wave 1 only ships W3C; the other variants land in a follow-up.
    #[serde(default)]
    pub propagation: Option<String>,
    /// Free-form resource attributes attached to every span. Operators
    /// stamp `deployment.environment`, `service.version`, etc. here.
    #[serde(default)]
    pub resource_attrs: std::collections::BTreeMap<String, String>,
}

fn default_service_name() -> String {
    "sbproxy".to_string()
}

fn default_transport() -> OtlpTransport {
    OtlpTransport::Grpc
}

fn default_always_sample_errors() -> bool {
    true
}

/// Default OTLP/gRPC endpoint for the Day-1 reference observability
/// stack (`examples/00-observability-stack/`). The collector listens
/// on 4327 instead of 4317 so it doesn't collide with a host-side
/// collector that operators may also be running.
pub const DEFAULT_OTLP_ENDPOINT: &str = "http://localhost:4327";

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            transport: OtlpTransport::Grpc,
            service_name: default_service_name(),
            sample_rate: None,
            always_sample_errors: true,
            propagation: None,
            resource_attrs: std::collections::BTreeMap::new(),
        }
    }
}

// --- OTLP exporter ---

/// Initialise the OTLP tracing pipeline.
///
/// When `config.enabled` is `false` or no endpoint is configured the
/// function is a no-op. Otherwise it installs a global tracer
/// provider that batches spans and ships them to the configured
/// endpoint over HTTP/proto, plus a tracing-subscriber layer that
/// converts every `tracing` span into an OTel span.
///
/// Returns `Err` when the exporter cannot be built (e.g. invalid
/// endpoint URL); callers should log and continue rather than fail
/// the whole startup.
pub fn init_otlp_pipeline(config: &TelemetryConfig) -> Result<()> {
    if !config.enabled {
        // Even when OTLP export is off we still want propagation to
        // work end-to-end so downstream services see traceparent
        // headers we receive. Register the W3C propagator unconditionally.
        init_propagator();
        return Ok(());
    }
    // Default endpoint matches the Day-1 reference Compose stack
    // (`examples/00-observability-stack/`). Operators that point at a
    // remote collector override this.
    let endpoint_owned = config
        .endpoint
        .clone()
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| DEFAULT_OTLP_ENDPOINT.to_string());
    let endpoint = endpoint_owned.as_str();

    // --- Sampler ---
    //
    // Wave 1 ships parent-based sampling so an upstream tracer's
    // sampling decision is honored. The unsampled root rate defaults
    // to the value the operator provided (10% per A1.4 if absent).
    // Errors get sampled at 100% by the per-request shim that lives
    // alongside this config (see `should_sample_error`); the SDK
    // sampler here only handles the no-context case.
    let head_rate = config.sample_rate.unwrap_or(0.1).clamp(0.0, 1.0);
    let sampler =
        sdktrace::Sampler::ParentBased(Box::new(sdktrace::Sampler::TraceIdRatioBased(head_rate)));

    // --- Resource: identifies this proxy instance to the collector ---
    let mut resource_kv = vec![
        KeyValue::new(semconv::resource::SERVICE_NAME, config.service_name.clone()),
        KeyValue::new(
            semconv::resource::SERVICE_VERSION,
            env!("CARGO_PKG_VERSION"),
        ),
    ];
    for (k, v) in &config.resource_attrs {
        resource_kv.push(KeyValue::new(k.clone(), v.clone()));
    }
    let resource = Resource::new(resource_kv);

    // --- Exporter ---
    //
    // Build the right transport variant. HTTP/proto goes through
    // `reqwest`; gRPC goes through `tonic`. Both feed the same
    // BatchSpanProcessor downstream so the rest of the pipeline
    // does not care which one is in use.
    let exporter = match config.transport {
        OtlpTransport::Http => opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build OTLP/HTTP exporter: {}", e))?,
        OtlpTransport::Grpc => opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build OTLP/gRPC exporter: {}", e))?,
    };

    let provider = sdktrace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_sampler(sampler)
        .with_resource(resource)
        .build();
    let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, "sbproxy");
    global::set_tracer_provider(provider);

    // --- Propagator ---
    //
    // Register the W3C TraceContext propagator as the global
    // text-map propagator so `extract_from_headers` /
    // `inject_into_headers` correctly serialise the active span's
    // trace into outbound HTTP headers. A1.4 pins W3C as the only
    // shipped propagator for Wave 1; B3 / Jaeger remain on the
    // table for a follow-up ADR.
    init_propagator();

    // --- Tracing-subscriber bridge ---
    //
    // Honour `RUST_LOG` for filter levels; default to `info` if the
    // env var is unset. The OpenTelemetry layer forwards every
    // matching span to the global tracer provider we just installed.
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // We `try_init` because operators may have already wired a
    // tracing subscriber elsewhere; layering on top would panic.
    if tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer)
        .try_init()
        .is_err()
    {
        tracing::debug!(
            "telemetry: a global subscriber is already installed; OTLP layer not reinstalled"
        );
    }

    tracing::info!(
        endpoint = %endpoint,
        service = %config.service_name,
        "OTLP tracing pipeline initialised"
    );
    Ok(())
}

/// Shut down the OTLP pipeline cleanly. Should be called at process
/// exit so any pending span batches get flushed.
pub fn shutdown_otlp_pipeline() {
    global::shutdown_tracer_provider();
}

// --- W3C TraceContext propagation ---

/// Register the W3C TraceContext propagator as the global text-map
/// propagator. Idempotent: safe to call multiple times.
///
/// Called from [`init_otlp_pipeline`] on both the enabled and disabled
/// paths so propagation works even when OTLP export is off.
pub fn init_propagator() {
    global::set_text_map_propagator(TraceContextPropagator::new());
}

/// Inject the active OTel context into outbound HTTP headers.
///
/// Wave 1 propagation invariant (per A1.4): every HTTP request leaving
/// the proxy MUST carry `traceparent`. Outbound clients (ledger, Stripe,
/// facilitators, registry feeds, KYA token verifier, OAuth, webhook
/// delivery) call this to satisfy that invariant in one line.
///
/// Reads the OTel context from the current `tracing::Span` when the
/// `tracing-opentelemetry` layer is installed. Falls back to the global
/// `opentelemetry::Context::current()` (which `extract_from_headers`
/// populates) so propagation works even when no OTLP tracer is wired,
/// satisfying the A1.4 invariant for the disabled path.
///
/// Quietly does nothing when no propagator has been registered (the
/// global default is a no-op propagator).
pub fn inject_into_headers(headers: &mut http::HeaderMap) {
    use opentelemetry::propagation::Injector;

    struct HeaderInjector<'a>(&'a mut http::HeaderMap);
    impl Injector for HeaderInjector<'_> {
        fn set(&mut self, key: &str, value: String) {
            if let (Ok(name), Ok(val)) = (
                http::header::HeaderName::from_bytes(key.as_bytes()),
                http::header::HeaderValue::from_str(&value),
            ) {
                self.0.insert(name, val);
            }
        }
    }

    // Two layers of context: the per-`tracing::Span` OTel context that
    // the `tracing-opentelemetry` layer maintains, and the
    // task-local OTel context. When OTLP export is enabled, the
    // span-scoped context is the one that carries the active trace.
    // Otherwise we rely on the task-local context populated by
    // `extract_from_headers` so propagation still works.
    let cx_from_span =
        tracing_opentelemetry::OpenTelemetrySpanExt::context(&tracing::Span::current());
    let cx_from_global = opentelemetry::Context::current();
    // Prefer the span context when it carries a non-default span, else
    // the task-local one.
    let cx = if opentelemetry::trace::TraceContextExt::has_active_span(&cx_from_span) {
        cx_from_span
    } else {
        cx_from_global
    };

    global::get_text_map_propagator(|prop| {
        prop.inject_context(&cx, &mut HeaderInjector(headers));
    });
}

/// Inject the active OTel context into a `reqwest::RequestBuilder`'s
/// headers. Convenience wrapper around [`inject_into_headers`] for the
/// outbound clients that are built on top of `reqwest`.
pub fn inject_into_reqwest(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    use opentelemetry::propagation::Injector;

    struct VecInjector(Vec<(String, String)>);
    impl Injector for VecInjector {
        fn set(&mut self, key: &str, value: String) {
            self.0.push((key.to_string(), value));
        }
    }

    let cx = tracing_opentelemetry::OpenTelemetrySpanExt::context(&tracing::Span::current());
    let mut sink = VecInjector(Vec::new());
    global::get_text_map_propagator(|prop| prop.inject_context(&cx, &mut sink));
    let mut req = req;
    for (k, v) in sink.0 {
        req = req.header(k, v);
    }
    req
}

/// Extract the inbound trace context from request headers and attach it
/// to the current span so the rest of the request runs under the
/// caller's trace.
///
/// Returns the parsed [`crate::trace_ctx::w3c::TraceContext`] when a
/// well-formed `traceparent` was present, even if no global tracer is
/// configured. This lets the access log / structured log emit the
/// correct `trace_id` regardless of OTLP state.
pub fn extract_from_headers(
    headers: &http::HeaderMap,
) -> Option<crate::trace_ctx::w3c::TraceContext> {
    use opentelemetry::propagation::Extractor;

    struct HeaderExtractor<'a>(&'a http::HeaderMap);
    impl Extractor for HeaderExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|v| v.to_str().ok())
        }
        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(|k| k.as_str()).collect()
        }
    }

    // Attach the extracted context to the current tracing span so any
    // outbound `inject_into_headers` call further down the stack picks
    // up the same trace_id. We also leak the attached context guard so
    // the OTel task-local current() will return it for the rest of
    // this scope; callers that need scoped attachment should use
    // [`extract_with_guard`] instead.
    let extractor = HeaderExtractor(headers);
    let cx = global::get_text_map_propagator(|prop| prop.extract(&extractor));
    tracing_opentelemetry::OpenTelemetrySpanExt::set_parent(&tracing::Span::current(), cx.clone());

    // Wave 1: also attach to the task-local OTel context so
    // `inject_into_headers` works on the same task even if the caller
    // is not running inside a `tracing::Span` that the OpenTelemetry
    // layer recognises (for example, when the OTLP exporter is off).
    // We deliberately mem::forget the guard so the attachment lasts
    // for the remainder of the task; callers that want a scoped
    // attachment use the future-aware `with_context` adaptor on
    // their async block instead.
    let guard = cx.attach();
    std::mem::forget(guard);

    // Also return the parsed traceparent for log-line correlation.
    headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(|tp| {
            let ts = headers.get("tracestate").and_then(|v| v.to_str().ok());
            crate::trace_ctx::w3c::TraceContext::parse_with_state(tp, ts)
        })
}

// --- Span-naming helpers ---
//
// All sbproxy spans follow `sbproxy.<pillar>.<verb>` per
// `docs/adr-observability.md`. The helpers below are intentionally
// thin: they emit a `tracing::info_span!` so the OpenTelemetry layer
// converts to an OTel span automatically. Span attributes go through
// the standard `tracing` macros (record! / in_scope) so the same
// emission path works whether OTLP is enabled or not.

/// One of the eight pillars defined by A1.4. Used to build span names
/// of the form `sbproxy.<pillar>.<verb>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pillar {
    /// Inbound request acceptance + framing validation.
    Intake,
    /// Per-policy evaluation (rate limit, WAF, AI crawl, ...).
    Policy,
    /// Pillar that produces a 402 challenge or redeems a presented token.
    Action,
    /// Content transform (PDF, OCR, summarize).
    Transform,
    /// Outbound HTTP call to the ledger.
    Ledger,
    /// Outbound payment-rail settlement.
    Rail,
    /// Audit-log emission.
    Audit,
    /// Outbound webhook delivery.
    Notify,
}

impl Pillar {
    /// Return the canonical pillar slug used in span names.
    pub fn as_str(self) -> &'static str {
        match self {
            Pillar::Intake => "intake",
            Pillar::Policy => "policy",
            Pillar::Action => "action",
            Pillar::Transform => "transform",
            Pillar::Ledger => "ledger",
            Pillar::Rail => "rail",
            Pillar::Audit => "audit",
            Pillar::Notify => "notify",
        }
    }
}

/// Helpers for constructing pillar-tagged spans.
///
/// Use the macro form `tracing::info_span!()` directly for the hot
/// path; this helper is a friendly shape for one-off call sites and
/// for tests. Returned name is `sbproxy.<pillar>.<verb>`; the verb is
/// passed in as an `&'static str` so it stays low-cardinality (no
/// formatting per request).
pub mod tracing_helper {
    use super::Pillar;

    /// Build a canonical span name without creating the span. Useful
    /// when the caller already has a `tracing::Span` handle and just
    /// needs the right name to record onto it.
    ///
    /// The returned `String` is `sbproxy.<pillar>.<verb>`.
    pub fn span_name(pillar: Pillar, verb: &'static str) -> String {
        format!("sbproxy.{}.{}", pillar.as_str(), verb)
    }

    /// Construct an info-level `tracing::Span` with the canonical
    /// `sbproxy.<pillar>.<verb>` name. Returns the span unentered;
    /// the caller decides when to enter via `.in_scope` or `.entered`.
    ///
    /// We use a fixed `tracing::info_span!` macro under the hood
    /// because the macro form picks up file/line metadata for free
    /// and produces a `Span` that the `tracing-opentelemetry` layer
    /// recognises. The macro requires a literal string for the name,
    /// so this helper records the name into the span as a field
    /// rather than using it as the metadata `name` directly. Dashboards
    /// group on the `name` attribute, which the OTel layer copies from
    /// the span's recorded `otel.name` field if present.
    pub fn span(pillar: Pillar, verb: &'static str) -> tracing::Span {
        let name = span_name(pillar, verb);
        // `otel.name` is the convention recognised by
        // `tracing-opentelemetry`: the layer overrides the OTel span
        // name with this field when present.
        tracing::info_span!("sbproxy.span", otel.name = %name, pillar = pillar.as_str(), verb)
    }
}

/// Convenience re-export so callers can write `telemetry::span(...)`
/// without going through the `tracing_helper` sub-module.
pub use tracing_helper::span;

/// W3C Trace Context span context.
#[derive(Debug, Clone)]
pub struct SpanContext {
    /// 32-hex-character trace identifier.
    pub trace_id: String,
    /// 16-hex-character span identifier.
    pub span_id: String,
    /// Parent span id, if this span was derived from a traceparent header.
    pub parent_span_id: Option<String>,
    /// Whether sampling is enabled for this trace.
    pub sampled: bool,
}

impl SpanContext {
    /// Generate a new root span with random trace and span IDs.
    pub fn new() -> Self {
        let trace_id = uuid::Uuid::new_v4().to_string().replace('-', "");
        let span_id = uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
        Self {
            trace_id,
            span_id,
            parent_span_id: None,
            sampled: true,
        }
    }

    /// Parse a W3C `traceparent` header value.
    ///
    /// Expected format: `{version}-{trace_id}-{parent_id}-{flags}`
    /// Example: `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() >= 4 && parts[1].len() == 32 && parts[2].len() == 16 {
            // Generate a new span_id for this hop; the incoming id becomes parent
            let new_span = uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
            Some(Self {
                trace_id: parts[1].to_string(),
                span_id: new_span,
                parent_span_id: Some(parts[2].to_string()),
                sampled: parts[3] == "01",
            })
        } else {
            None
        }
    }

    /// Serialize to a W3C `traceparent` header value.
    pub fn to_traceparent(&self) -> String {
        let flags = if self.sampled { "01" } else { "00" };
        format!("00-{}-{}-{}", self.trace_id, self.span_id, flags)
    }
}

impl Default for SpanContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.service_name, "sbproxy");
        assert!(config.endpoint.is_none());
        assert!(config.sample_rate.is_none());
        assert!(config.propagation.is_none());
    }

    #[test]
    fn test_config_deserialize() {
        let json = r#"{
            "enabled": true,
            "endpoint": "http://localhost:4317",
            "service_name": "my-proxy",
            "sample_rate": 0.5,
            "propagation": "w3c"
        }"#;
        let config: TelemetryConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.endpoint.as_deref(), Some("http://localhost:4317"));
        assert_eq!(config.service_name, "my-proxy");
        assert_eq!(config.sample_rate, Some(0.5));
        assert_eq!(config.propagation.as_deref(), Some("w3c"));
    }

    #[test]
    fn test_span_creation() {
        let span = SpanContext::new();
        assert_eq!(span.trace_id.len(), 32);
        assert_eq!(span.span_id.len(), 16);
        assert!(span.parent_span_id.is_none());
        assert!(span.sampled);
    }

    #[test]
    fn test_traceparent_roundtrip() {
        let header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = SpanContext::from_traceparent(header).unwrap();
        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(ctx.sampled);
        assert_eq!(ctx.parent_span_id.as_deref(), Some("00f067aa0ba902b7"));

        // The generated traceparent preserves trace_id and sampled flag
        let output = ctx.to_traceparent();
        assert!(output.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
        assert!(output.ends_with("-01"));
    }

    #[test]
    fn test_traceparent_not_sampled() {
        let header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
        let ctx = SpanContext::from_traceparent(header).unwrap();
        assert!(!ctx.sampled);
        assert!(ctx.to_traceparent().ends_with("-00"));
    }

    #[test]
    fn test_traceparent_invalid() {
        assert!(SpanContext::from_traceparent("garbage").is_none());
        assert!(SpanContext::from_traceparent("00-short-id-01").is_none());
    }

    // --- Pillar / span helper ---

    #[test]
    fn pillar_slugs_are_canonical() {
        // The slugs are pinned by A1.4; dashboards group on them.
        assert_eq!(Pillar::Intake.as_str(), "intake");
        assert_eq!(Pillar::Policy.as_str(), "policy");
        assert_eq!(Pillar::Action.as_str(), "action");
        assert_eq!(Pillar::Transform.as_str(), "transform");
        assert_eq!(Pillar::Ledger.as_str(), "ledger");
        assert_eq!(Pillar::Rail.as_str(), "rail");
        assert_eq!(Pillar::Audit.as_str(), "audit");
        assert_eq!(Pillar::Notify.as_str(), "notify");
    }

    #[test]
    fn span_name_format() {
        assert_eq!(
            tracing_helper::span_name(Pillar::Ledger, "redeem"),
            "sbproxy.ledger.redeem"
        );
        assert_eq!(
            tracing_helper::span_name(Pillar::Action, "challenge"),
            "sbproxy.action.challenge"
        );
    }

    // --- Propagation ---

    #[test]
    fn propagator_round_trip_preserves_traceparent() {
        // Round-trip a known traceparent: extract from inbound headers,
        // inject into outbound headers, assert trace_id is preserved.
        init_propagator();
        let mut inbound = http::HeaderMap::new();
        let known_tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        inbound.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static(known_tp),
        );

        // Run inside a tracing span so inject_into_headers has an
        // active context to work with.
        let span = tracing::info_span!("test");
        let _g = span.enter();
        let parsed = extract_from_headers(&inbound);
        let parsed = parsed.expect("traceparent must parse");
        assert_eq!(parsed.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert!(parsed.is_sampled());

        let mut outbound = http::HeaderMap::new();
        inject_into_headers(&mut outbound);
        // The propagator may inject a fresh span_id but trace_id MUST
        // round-trip. The injected traceparent header is present.
        let injected = outbound
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("outbound traceparent missing");
        assert!(
            injected.contains("0af7651916cd43dd8448eb211c80319c"),
            "trace_id not preserved: {}",
            injected
        );
    }
}
