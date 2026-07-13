//! OpenTelemetry tracing support for sbproxy.
//!
//! Splits the observe crate's responsibilities four ways:
//!
//! 1. **Span context** ([`SpanContext`]): a small W3C Trace Context
//!    helper used by request handlers to propagate `traceparent`
//!    headers across hops. Has no dependency on the heavyweight OTel
//!    SDK so it costs nothing when telemetry is disabled.
//! 2. **OTLP exporter** ([`init_otlp_pipeline`]): builds and installs
//!    a tracing-subscriber layer that forwards spans to an OTLP
//!    collector. Startup code that already owns the process subscriber
//!    uses [`build_otlp_trace_pipeline`] and layers the returned tracer
//!    into that subscriber.
//! 3. **W3C TraceContext propagator** ([`init_propagator`]): registers
//!    the OTel-default propagator as the global text-map propagator so
//!    every outbound HTTP client that goes through
//!    [`inject_into_headers`] picks up the current trace.
//! 4. **Span-naming helper** ([`span`]): every pillar emits spans
//!    named `sbproxy.<pillar>.<verb>` so dashboards group cleanly.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::TrySendError;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use opentelemetry::trace::{
    Link, SamplingDecision, SamplingResult, SpanKind, Status, TraceContextExt, TraceError, TraceId,
    TraceResult,
};
use opentelemetry::{global, Context, KeyValue, Value};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::export::trace::{ExportResult, SpanData, SpanExporter};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace as sdktrace;
use opentelemetry_sdk::trace::{ShouldSample, SpanProcessor};
use opentelemetry_sdk::{trace::Span, Resource};
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
/// The substrate ships parent-based ratio sampling for normal traffic,
/// plus span-end keep overrides for error, cost, and latency outcomes.
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    /// Whether tracing is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// OTLP collector endpoint. The default depends on the chosen
    /// `transport`: `http://localhost:4318/v1/traces` for HTTP,
    /// `http://localhost:4327` for gRPC (matching the Day-1 reference
    /// Compose stack in `examples/observability-stack/`).
    pub endpoint: Option<String>,
    /// OTLP transport selector.
    #[serde(default = "default_transport")]
    pub transport: OtlpTransport,
    /// Service name reported in spans.
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// Head-based sampling probability for unsampled local roots.
    /// Default is 10%. Parent-sampled requests are always captured.
    #[serde(default)]
    pub sample_rate: Option<f64>,
    /// When `true`, every 5xx / policy-block / ledger-denial root span
    /// is kept at 100% even if the head ratio would have dropped it.
    /// Default `true`.
    #[serde(default = "default_always_sample_errors")]
    pub always_sample_errors: bool,
    /// Keep any trace whose derived USD cost is at or above this
    /// threshold, regardless of the head ratio. `None` disables the
    /// cost-based keep. Cost is known at request end, so the source-side
    /// span processor evaluates this once the span is complete.
    #[serde(default)]
    pub keep_over_budget_usd: Option<f64>,
    /// Keep any trace whose wall-clock duration is at or above
    /// this many seconds, regardless of the head ratio. `None` disables the
    /// latency-based keep. Like cost, this is evaluated at span end.
    #[serde(default)]
    pub keep_slower_than_secs: Option<f64>,
    /// Propagation format: `"w3c"` (default), `"b3"`, or `"jaeger"`.
    /// Only ships W3C; the other variants land in a follow-up.
    #[serde(default)]
    pub propagation: Option<String>,
    /// Free-form resource attributes attached to every span. Operators
    /// stamp `deployment.environment`, `service.version`, etc. here.
    #[serde(default)]
    pub resource_attrs: std::collections::BTreeMap<String, String>,
    /// When `true`, additionally export OTel metrics over OTLP via a
    /// PeriodicReader. The Prometheus surface (scraped from the
    /// embedded admin server's `/metrics`) is unaffected and remains
    /// the canonical surface; this is an opt-in mirror for operators
    /// who already aggregate via an OTel-aware backend (Mimir,
    /// Datadog, Honeycomb) and want the same observations without
    /// standing up a separate Prometheus scrape. Default `false`.
    #[serde(default)]
    pub export_metrics: bool,
    /// Period for the OTLP metric exporter, seconds. Default 30s.
    /// Only consulted when `export_metrics` is `true`.
    #[serde(default)]
    pub metrics_interval_secs: Option<u64>,
    /// Additional headers attached to every OTLP export request
    /// (traces and metrics; the OTLP-logs sink reads the same set via
    /// [`resolved_otlp_headers`]). Values here are already RESOLVED:
    /// the binary resolves secret references (`${VAR}`, `vault://`,
    /// `secret://`, `file:`, ...) at boot and refuses to start when
    /// one cannot be resolved, so a raw reference never reaches the
    /// collector. Hosted backends (Grafana Cloud, Honeycomb, Langfuse
    /// Cloud, Datadog OTLP) authenticate with these.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
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
/// stack (`examples/observability-stack/`). The collector listens
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
            keep_over_budget_usd: None,
            keep_slower_than_secs: None,
            propagation: None,
            resource_attrs: std::collections::BTreeMap::new(),
            export_metrics: false,
            metrics_interval_secs: None,
            headers: std::collections::BTreeMap::new(),
        }
    }
}

/// Boot-resolved OTLP export headers, installed once by the binary
/// after secret resolution (WOR-1869). The OTLP-logs sink consumes
/// this set so a config-declared log sink authenticates with the same
/// headers as the trace and metric pipelines without `sbproxy-core`
/// growing a secret-resolution dependency. Header changes require a
/// restart, matching the trace pipeline (which also initialises once
/// at boot).
static RESOLVED_OTLP_HEADERS: std::sync::OnceLock<std::collections::BTreeMap<String, String>> =
    std::sync::OnceLock::new();

/// Install the boot-resolved OTLP headers. Call once from the binary
/// after resolving secret references; a second call is ignored.
pub fn install_resolved_otlp_headers(headers: std::collections::BTreeMap<String, String>) {
    let _ = RESOLVED_OTLP_HEADERS.set(headers);
}

/// The boot-resolved OTLP headers, empty when none were configured
/// (or in contexts like `validate` / tests that never install them).
pub fn resolved_otlp_headers() -> std::collections::BTreeMap<String, String> {
    RESOLVED_OTLP_HEADERS.get().cloned().unwrap_or_default()
}

/// Build a tonic `MetadataMap` from configured header pairs, skipping
/// (and warning on) names or values that are not valid gRPC metadata.
/// Skipping rather than failing keeps a typo'd extra header from
/// taking down the whole export pipeline; the authentication header a
/// backend requires is validated by that backend rejecting the export.
pub(crate) fn tonic_metadata_from_headers(
    headers: &std::collections::BTreeMap<String, String>,
) -> tonic::metadata::MetadataMap {
    let mut metadata = tonic::metadata::MetadataMap::new();
    for (name, value) in headers {
        match (
            name.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>(),
            value.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>(),
        ) {
            (Ok(key), Ok(val)) => {
                metadata.insert(key, val);
            }
            _ => {
                tracing::warn!(
                    header = %name,
                    "telemetry: header name or value is not valid gRPC metadata; skipping"
                );
            }
        }
    }
    metadata
}

/// Cost-aware keep decision for a completed AI trace.
///
/// Head sampling (ParentBased + TraceIdRatio, configured via
/// `sample_rate`) decides at span start, before the outcome is known.
/// Whether a finished trace should be kept regardless of that ratio,
/// because it errored, cost over a budget, or ran slow, is evaluated at
/// request end by the source-side span processor. The reference collector
/// can mirror the same policy as a second line of defense.
///
/// Returns `true` when the trace should be force-kept.
pub fn should_force_sample(
    is_error: bool,
    cost_usd: f64,
    latency_secs: f64,
    always_sample_errors: bool,
    keep_over_budget_usd: Option<f64>,
    keep_slower_than_secs: Option<f64>,
) -> bool {
    (always_sample_errors && is_error)
        || keep_over_budget_usd.is_some_and(|budget| cost_usd >= budget)
        || keep_slower_than_secs.is_some_and(|threshold| latency_secs >= threshold)
}

const TRACE_EXPORT_QUEUE_SIZE: usize = 4096;
const TRACE_EXPORT_FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// Effective source-side trace sampling policy.
#[derive(Clone, Debug)]
pub struct TraceSamplingPolicy {
    /// ParentBased(TraceIdRatioBased(ratio)) ratio for local roots.
    pub sample_rate: f64,
    /// Keep completed error spans even when the head ratio did not sample them.
    pub always_sample_errors: bool,
    /// Keep completed spans whose cost meets or exceeds this USD threshold.
    pub keep_over_budget_usd: Option<f64>,
    /// Keep completed spans whose wall time meets or exceeds this threshold.
    pub keep_slower_than_secs: Option<f64>,
}

impl TraceSamplingPolicy {
    fn from_config(config: &TelemetryConfig) -> Self {
        Self {
            sample_rate: effective_sample_rate(config),
            always_sample_errors: config.always_sample_errors,
            keep_over_budget_usd: config.keep_over_budget_usd,
            keep_slower_than_secs: config.keep_slower_than_secs,
        }
    }

    fn head_sampler(&self) -> sdktrace::Sampler {
        sdktrace::Sampler::ParentBased(Box::new(sdktrace::Sampler::TraceIdRatioBased(
            self.sample_rate,
        )))
    }
}

fn effective_sample_rate(config: &TelemetryConfig) -> f64 {
    config.sample_rate.unwrap_or(0.1).clamp(0.0, 1.0)
}

/// A parent-based ratio sampler that records locally dropped spans so
/// the span-end processor can still evaluate error, cost, and latency
/// overrides. Normal sampled/exported traffic follows the same export
/// decision as `ParentBased(TraceIdRatioBased(ratio))`.
#[derive(Clone, Debug)]
struct OutcomeAwareSampler {
    policy: TraceSamplingPolicy,
}

impl OutcomeAwareSampler {
    fn new(policy: TraceSamplingPolicy) -> Self {
        Self { policy }
    }
}

impl ShouldSample for OutcomeAwareSampler {
    #[allow(clippy::too_many_arguments)]
    fn should_sample(
        &self,
        parent_context: Option<&Context>,
        trace_id: TraceId,
        name: &str,
        span_kind: &SpanKind,
        attributes: &[KeyValue],
        links: &[Link],
    ) -> SamplingResult {
        let trace_state = parent_context
            .map(|cx| cx.span().span_context().trace_state().clone())
            .unwrap_or_default();

        let decision = parent_context
            .filter(|cx| cx.has_active_span())
            .map_or_else(
                || {
                    let head = self.policy.head_sampler();
                    match head
                        .should_sample(None, trace_id, name, span_kind, attributes, links)
                        .decision
                    {
                        SamplingDecision::RecordAndSample => SamplingDecision::RecordAndSample,
                        SamplingDecision::RecordOnly | SamplingDecision::Drop => {
                            SamplingDecision::RecordOnly
                        }
                    }
                },
                |cx| {
                    if cx.span().span_context().is_sampled() {
                        SamplingDecision::RecordAndSample
                    } else {
                        SamplingDecision::RecordOnly
                    }
                },
            );

        SamplingResult {
            decision,
            attributes: Vec::new(),
            trace_state,
        }
    }
}

#[derive(Debug)]
enum TraceExportMessage {
    ExportSpan(Box<SpanData>),
    ForceFlush(mpsc::Sender<ExportResult>),
    SetResource(Resource),
    Shutdown(mpsc::Sender<ExportResult>),
}

/// Span processor that exports the spans selected by the head sampler
/// plus completed spans that satisfy the configured keep overrides.
#[derive(Debug)]
struct OutcomeSamplingSpanProcessor {
    tx: mpsc::SyncSender<TraceExportMessage>,
    policy: TraceSamplingPolicy,
    dropped_spans: AtomicUsize,
}

impl OutcomeSamplingSpanProcessor {
    fn new(exporter: Box<dyn SpanExporter>, policy: TraceSamplingPolicy) -> Self {
        let (tx, rx) = mpsc::sync_channel(TRACE_EXPORT_QUEUE_SIZE);
        spawn_trace_export_worker(exporter, rx);
        Self {
            tx,
            policy,
            dropped_spans: AtomicUsize::new(0),
        }
    }

    fn should_export(&self, span: &SpanData) -> bool {
        span.span_context.is_sampled() || should_force_export_span(span, &self.policy)
    }

    fn send_control(
        &self,
        build: impl FnOnce(mpsc::Sender<ExportResult>) -> TraceExportMessage,
    ) -> TraceResult<()> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(build(reply_tx))
            .map_err(|_| TraceError::Other("trace export worker is closed".into()))?;
        reply_rx
            .recv_timeout(TRACE_EXPORT_FLUSH_TIMEOUT)
            .map_err(|_| TraceError::Other("trace export worker timed out".into()))?
    }
}

impl SpanProcessor for OutcomeSamplingSpanProcessor {
    fn on_start(&self, _span: &mut Span, _cx: &Context) {}

    fn on_end(&self, span: SpanData) {
        if !self.should_export(&span) {
            return;
        }

        match self
            .tx
            .try_send(TraceExportMessage::ExportSpan(Box::new(span)))
        {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                let dropped = self.dropped_spans.fetch_add(1, Ordering::Relaxed);
                if dropped == 0 {
                    tracing::warn!(
                        queue_size = TRACE_EXPORT_QUEUE_SIZE,
                        "telemetry: dropping trace spans because the OTLP export queue is full"
                    );
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                tracing::debug!("telemetry: trace export worker is closed; dropping span");
            }
        }
    }

    fn force_flush(&self) -> TraceResult<()> {
        self.send_control(TraceExportMessage::ForceFlush)
    }

    fn shutdown(&self) -> TraceResult<()> {
        let dropped = self.dropped_spans.load(Ordering::Relaxed);
        if dropped > 0 {
            tracing::warn!(
                dropped_spans = dropped,
                queue_size = TRACE_EXPORT_QUEUE_SIZE,
                "telemetry: OTLP trace spans were dropped before shutdown"
            );
        }
        self.send_control(TraceExportMessage::Shutdown)
    }

    fn set_resource(&mut self, resource: &Resource) {
        let _ = self
            .tx
            .try_send(TraceExportMessage::SetResource(resource.clone()));
    }
}

fn spawn_trace_export_worker(
    mut exporter: Box<dyn SpanExporter>,
    rx: mpsc::Receiver<TraceExportMessage>,
) {
    if let Err(e) = std::thread::Builder::new()
        .name("sbproxy-otel-trace-export".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "telemetry: failed to build OTLP trace export runtime"
                    );
                    return;
                }
            };

            while let Ok(msg) = rx.recv() {
                match msg {
                    TraceExportMessage::ExportSpan(span) => {
                        if let Err(e) = rt.block_on(exporter.export(vec![*span])) {
                            tracing::debug!(error = ?e, "telemetry: OTLP span export failed");
                        }
                    }
                    TraceExportMessage::ForceFlush(reply) => {
                        let _ = reply.send(rt.block_on(exporter.force_flush()));
                    }
                    TraceExportMessage::SetResource(resource) => {
                        exporter.set_resource(&resource);
                    }
                    TraceExportMessage::Shutdown(reply) => {
                        let result = rt.block_on(exporter.force_flush());
                        exporter.shutdown();
                        let _ = reply.send(result);
                        break;
                    }
                }
            }
        })
    {
        tracing::warn!(
            error = %e,
            "telemetry: failed to spawn OTLP trace export worker"
        );
    }
}

fn should_force_export_span(span: &SpanData, policy: &TraceSamplingPolicy) -> bool {
    let is_error = span_is_error(span);
    let cost_usd = span_cost_usd(&span.attributes).unwrap_or(0.0);
    let latency_secs = span_latency_secs(span.start_time, span.end_time);
    should_force_sample(
        is_error,
        cost_usd,
        latency_secs,
        policy.always_sample_errors,
        policy.keep_over_budget_usd,
        policy.keep_slower_than_secs,
    )
}

fn span_is_error(span: &SpanData) -> bool {
    matches!(span.status, Status::Error { .. })
        || string_attr_eq(&span.attributes, "otel.status_code", "ERROR")
        || string_attr_present(&span.attributes, "error.type")
}

fn span_cost_usd(attributes: &[KeyValue]) -> Option<f64> {
    for key in [
        "gen_ai.usage.cost",
        "llm.usage.total_cost",
        "sbproxy.ai.cost_usd",
    ] {
        if let Some(value) = numeric_attr(attributes, key) {
            return Some(value);
        }
    }
    numeric_attr(attributes, "sbproxy.ai.cost_usd_micros").map(|micros| micros / 1_000_000.0)
}

fn span_latency_secs(start: SystemTime, end: SystemTime) -> f64 {
    end.duration_since(start)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn string_attr_eq(attributes: &[KeyValue], key: &str, expected: &str) -> bool {
    attributes.iter().any(|kv| {
        kv.key.as_str() == key
            && match &kv.value {
                Value::String(value) => value.to_string().eq_ignore_ascii_case(expected),
                other => other.to_string().eq_ignore_ascii_case(expected),
            }
    })
}

fn string_attr_present(attributes: &[KeyValue], key: &str) -> bool {
    attributes.iter().any(|kv| kv.key.as_str() == key)
}

fn numeric_attr(attributes: &[KeyValue], key: &str) -> Option<f64> {
    attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .and_then(|kv| match &kv.value {
            Value::I64(value) => Some(*value as f64),
            Value::F64(value) => Some(*value),
            Value::String(value) => value.to_string().parse::<f64>().ok(),
            _ => None,
        })
}

// --- OTLP exporter ---

/// Built OTLP trace pipeline metadata.
#[derive(Debug, Clone)]
pub struct OtlpTracePipeline {
    /// Tracer to attach to a `tracing-opentelemetry` layer.
    pub tracer: sdktrace::Tracer,
    /// Effective OTLP endpoint.
    pub endpoint: String,
    /// Effective service.name resource attribute.
    pub service_name: String,
    /// Effective head sample ratio for local roots.
    pub sample_rate: f64,
}

/// Build and install the global OTLP tracer provider.
///
/// This does not install a `tracing-subscriber` layer. Callers that own
/// the global subscriber should call this first, then attach
/// `tracing_opentelemetry::layer().with_tracer(pipeline.tracer.clone())`
/// to their subscriber stack.
pub fn build_otlp_trace_pipeline(config: &TelemetryConfig) -> Result<Option<OtlpTracePipeline>> {
    if !config.enabled {
        // Even when OTLP export is off we still want propagation to
        // work end-to-end so downstream services see traceparent
        // headers we receive. Register the W3C propagator unconditionally.
        init_propagator();
        return Ok(None);
    }

    let endpoint = otlp_endpoint(config);
    let policy = TraceSamplingPolicy::from_config(config);
    let resource = otlp_resource(config);
    let exporter = build_span_exporter(config, &endpoint)?;
    let processor = OutcomeSamplingSpanProcessor::new(Box::new(exporter), policy.clone());

    let provider = sdktrace::TracerProvider::builder()
        .with_span_processor(processor)
        .with_sampler(OutcomeAwareSampler::new(policy.clone()))
        .with_resource(resource)
        .build();
    let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, "sbproxy");
    global::set_tracer_provider(provider);
    init_propagator();

    Ok(Some(OtlpTracePipeline {
        tracer,
        endpoint,
        service_name: config.service_name.clone(),
        sample_rate: policy.sample_rate,
    }))
}

fn otlp_endpoint(config: &TelemetryConfig) -> String {
    config
        .endpoint
        .clone()
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| DEFAULT_OTLP_ENDPOINT.to_string())
}

/// Best-effort hostname for resource detection: `HOSTNAME` env var
/// first (set on k8s and most shells), then the `hostname` binary.
fn detect_hostname() -> Option<String> {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return Some(h);
        }
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Standard-detector resource attributes (WOR-1869): host + process
/// identity, `OTEL_RESOURCE_ATTRIBUTES` pairs, and Kubernetes
/// downward-API attributes when the conventional env vars are set
/// (`K8S_POD_NAME`, `K8S_POD_NAMESPACE`, `K8S_NODE_NAME`). Without
/// these, every node's telemetry collapses into one anonymous stream
/// when aggregated downstream. Returned as ordered pairs; later
/// entries win on key conflict, and callers append operator attrs
/// last so explicit config always beats detection.
fn detected_resource_attrs() -> Vec<(String, String)> {
    let mut kv: Vec<(String, String)> = Vec::new();
    if let Some(host) = detect_hostname() {
        kv.push(("host.name".to_string(), host.clone()));
        kv.push((
            "service.instance.id".to_string(),
            format!("{host}:{}", std::process::id()),
        ));
    }
    // Semconv os.type uses `darwin`, not Rust's `macos`.
    let os_type = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    kv.push(("os.type".to_string(), os_type.to_string()));
    kv.push(("process.pid".to_string(), std::process::id().to_string()));
    for (env_var, attr) in [
        ("K8S_POD_NAME", "k8s.pod.name"),
        ("K8S_POD_NAMESPACE", "k8s.namespace.name"),
        ("K8S_NODE_NAME", "k8s.node.name"),
    ] {
        if let Ok(v) = std::env::var(env_var) {
            if !v.is_empty() {
                kv.push((attr.to_string(), v));
            }
        }
    }
    // OTEL_RESOURCE_ATTRIBUTES=key=value,key=value (the standard env
    // detector's format). Parsed after host/process detection so the
    // operator's env pairs win over detection.
    if let Ok(pairs) = std::env::var("OTEL_RESOURCE_ATTRIBUTES") {
        for pair in pairs.split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                let (k, v) = (k.trim(), v.trim());
                if !k.is_empty() && !v.is_empty() {
                    kv.push((k.to_string(), v.to_string()));
                }
            }
        }
    }
    kv
}

fn otlp_resource(config: &TelemetryConfig) -> Resource {
    // Ordered so that later duplicates win: detected attrs, then the
    // service identity from config, then the operator's free-form
    // resource_attrs (explicit config always beats detection).
    let mut resource_kv: Vec<KeyValue> = detected_resource_attrs()
        .into_iter()
        .map(|(k, v)| KeyValue::new(k, v))
        .collect();
    resource_kv.push(KeyValue::new(
        semconv::resource::SERVICE_NAME,
        config.service_name.clone(),
    ));
    resource_kv.push(KeyValue::new(
        semconv::resource::SERVICE_VERSION,
        env!("CARGO_PKG_VERSION"),
    ));
    for (k, v) in &config.resource_attrs {
        resource_kv.push(KeyValue::new(k.clone(), v.clone()));
    }
    Resource::new(resource_kv)
}

fn build_span_exporter(
    config: &TelemetryConfig,
    endpoint: &str,
) -> Result<opentelemetry_otlp::SpanExporter> {
    match config.transport {
        OtlpTransport::Http => {
            let mut builder = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(endpoint);
            if !config.headers.is_empty() {
                builder = builder.with_headers(config.headers.clone().into_iter().collect());
            }
            builder
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build OTLP/HTTP exporter: {}", e))
        }
        OtlpTransport::Grpc => {
            let mut builder = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint);
            if !config.headers.is_empty() {
                builder = builder.with_metadata(tonic_metadata_from_headers(&config.headers));
            }
            builder
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build OTLP/gRPC exporter: {}", e))
        }
    }
}

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
    let Some(pipeline) = build_otlp_trace_pipeline(config)? else {
        return Ok(());
    };

    // --- Tracing-subscriber bridge ---
    //
    // Honour `RUST_LOG` for filter levels; default to `info` if the
    // env var is unset. The OpenTelemetry layer forwards every
    // matching span to the global tracer provider we just installed.
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let otel_layer = tracing_opentelemetry::layer().with_tracer(pipeline.tracer);

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
        endpoint = %pipeline.endpoint,
        service = %pipeline.service_name,
        sample_rate = %pipeline.sample_rate,
        "OTLP tracing pipeline initialised"
    );
    Ok(())
}

/// Shut down the OTLP pipeline cleanly. Should be called at process
/// exit so any pending span batches get flushed.
pub fn shutdown_otlp_pipeline() {
    global::shutdown_tracer_provider();
}

// --- OTLP metrics pipeline ---
//
// The proxy's first-class metric surface is Prometheus (every
// metric in `metrics-stability.md` is registered on the Prometheus
// `Registry` and scraped by the embedded admin server). The OTLP
// metric pipeline shipped here is an OPTIONAL mirror: when an
// operator configures `telemetry.export_metrics: true`, the same
// observations also reach an OTel-aware backend (Tempo + Mimir,
// Datadog, New Relic, Honeycomb) without standing up a separate
// Prometheus scrape.
//
// The mirror is opt-in for two reasons:
//
// 1. The Prometheus path is the canonical surface; not every
//    operator wants the duplicate export.
// 2. The OTLP collector add-on can be a significant deployment
//    weight if you do not already run one for traces.

/// Initialise the OTLP metrics pipeline. No-op when
/// `config.export_metrics` is false; otherwise builds a
/// `MeterProvider` that ships the registered instruments to the
/// configured OTLP endpoint on a `interval_secs` cadence.
///
/// Returns `Err` when the exporter cannot be built. Operators
/// should log and continue rather than fail boot, mirroring the
/// trace pipeline.
pub fn init_otlp_metrics_pipeline(config: &TelemetryConfig) -> Result<()> {
    if !config.enabled || !config.export_metrics {
        return Ok(());
    }
    let endpoint_owned = config
        .endpoint
        .clone()
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| DEFAULT_OTLP_ENDPOINT.to_string());
    let endpoint = endpoint_owned.as_str();

    // Same resource construction as the trace pipeline (detection +
    // service identity + operator attrs), so the two signals stay
    // joinable downstream.
    let resource = otlp_resource(config);

    let exporter = match config.transport {
        OtlpTransport::Http => {
            let mut builder = opentelemetry_otlp::MetricExporter::builder()
                .with_http()
                .with_endpoint(endpoint);
            if !config.headers.is_empty() {
                builder = builder.with_headers(config.headers.clone().into_iter().collect());
            }
            builder
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build OTLP/HTTP metric exporter: {}", e))?
        }
        OtlpTransport::Grpc => {
            let mut builder = opentelemetry_otlp::MetricExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint);
            if !config.headers.is_empty() {
                builder = builder.with_metadata(tonic_metadata_from_headers(&config.headers));
            }
            builder
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build OTLP/gRPC metric exporter: {}", e))?
        }
    };

    let interval = std::time::Duration::from_secs(config.metrics_interval_secs.unwrap_or(30));
    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(
        exporter,
        opentelemetry_sdk::runtime::Tokio,
    )
    .with_interval(interval)
    .build();

    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();
    global::set_meter_provider(provider);

    tracing::info!(
        endpoint = %endpoint,
        interval_secs = %interval.as_secs(),
        service = %config.service_name,
        "OTLP metrics pipeline initialised"
    );
    Ok(())
}

/// Shut down the OTLP metric pipeline cleanly. The 0.27 OTel API
/// has no global meter-provider shutdown; the `SdkMeterProvider`
/// installed in [`init_otlp_metrics_pipeline`] is flushed on its
/// own `Drop` when the process exits. This function exists as a
/// symmetry point with [`shutdown_otlp_pipeline`] so a shutdown
/// handler can call both without conditional compilation; today it
/// is a no-op. When upstream exposes a global flush, this fn
/// becomes the seam.
pub fn shutdown_otlp_metrics_pipeline() {
    // Intentionally empty; see fn-doc.
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
/// Propagation invariant: every HTTP request leaving
/// the proxy MUST carry `traceparent`. Outbound clients (ledger, Stripe,
/// facilitators, registry feeds, KYA token verifier, OAuth, webhook
/// delivery) call this to satisfy that invariant in one line.
///
/// Reads the OTel context from the current `tracing::Span` when the
/// `tracing-opentelemetry` layer is installed. Falls back to the global
/// `opentelemetry::Context::current()` (which `extract_from_headers`
/// populates) so propagation works even when no OTLP tracer is wired,
/// satisfying the invariant for the disabled path.
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
// All sbproxy spans follow `sbproxy.<pillar>.<verb>`. The helpers below
// are intentionally thin: they emit a `tracing::info_span!` so the
// OpenTelemetry layer
// converts to an OTel span automatically. Span attributes go through
// the standard `tracing` macros (record! / in_scope) so the same
// emission path works whether OTLP is enabled or not.

/// One of the eight standard pillars. Used to build span names
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

    fn test_trace_id(n: u8) -> opentelemetry::trace::TraceId {
        let mut bytes = [0_u8; 16];
        bytes[15] = n;
        opentelemetry::trace::TraceId::from_bytes(bytes)
    }

    fn test_span_id(n: u8) -> opentelemetry::trace::SpanId {
        let mut bytes = [0_u8; 8];
        bytes[7] = n;
        opentelemetry::trace::SpanId::from_bytes(bytes)
    }

    fn test_span_data(sampled: bool, attributes: Vec<KeyValue>, duration_secs: f64) -> SpanData {
        let flags = if sampled {
            opentelemetry::trace::TraceFlags::SAMPLED
        } else {
            opentelemetry::trace::TraceFlags::default()
        };
        let start_time = SystemTime::UNIX_EPOCH;
        SpanData {
            span_context: opentelemetry::trace::SpanContext::new(
                test_trace_id(1),
                test_span_id(2),
                flags,
                false,
                opentelemetry::trace::TraceState::default(),
            ),
            parent_span_id: opentelemetry::trace::SpanId::INVALID,
            span_kind: SpanKind::Internal,
            name: std::borrow::Cow::Borrowed("ai.request"),
            start_time,
            end_time: start_time + Duration::from_secs_f64(duration_secs),
            attributes,
            dropped_attributes_count: 0,
            events: opentelemetry_sdk::trace::SpanEvents::default(),
            links: opentelemetry_sdk::trace::SpanLinks::default(),
            status: Status::Unset,
            instrumentation_scope: opentelemetry::InstrumentationScope::builder("test").build(),
        }
    }

    #[test]
    fn test_config_defaults() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.service_name, "sbproxy");
        assert!(config.endpoint.is_none());
        assert!(config.sample_rate.is_none());
        assert!(config.propagation.is_none());
        // WOR-1230: errors kept by default; cost/latency keeps off unless set.
        assert!(config.always_sample_errors);
        assert!(config.keep_over_budget_usd.is_none());
        assert!(config.keep_slower_than_secs.is_none());
    }

    #[test]
    fn force_sample_keeps_errors_when_enabled() {
        assert!(should_force_sample(true, 0.0, 0.0, true, None, None));
        // Disabled error keep: an error alone does not force a keep.
        assert!(!should_force_sample(true, 0.0, 0.0, false, None, None));
    }

    #[test]
    fn force_sample_keeps_over_budget_and_slow() {
        // Over the cost budget.
        assert!(should_force_sample(
            false,
            0.05,
            0.0,
            true,
            Some(0.01),
            None
        ));
        assert!(!should_force_sample(
            false,
            0.005,
            0.0,
            true,
            Some(0.01),
            None
        ));
        // Slower than the latency threshold.
        assert!(should_force_sample(false, 0.0, 2.0, true, None, Some(1.0)));
        assert!(!should_force_sample(false, 0.0, 0.5, true, None, Some(1.0)));
    }

    #[test]
    fn force_sample_is_false_for_a_cheap_fast_success() {
        assert!(!should_force_sample(
            false,
            0.001,
            0.05,
            true,
            Some(1.0),
            Some(5.0)
        ));
    }

    #[test]
    fn outcome_sampler_records_locally_dropped_roots() {
        let sampler = OutcomeAwareSampler::new(TraceSamplingPolicy {
            sample_rate: 0.0,
            always_sample_errors: true,
            keep_over_budget_usd: None,
            keep_slower_than_secs: None,
        });
        let result = sampler.should_sample(
            None,
            test_trace_id(1),
            "ai.request",
            &opentelemetry::trace::SpanKind::Internal,
            &[],
            &[],
        );
        assert_eq!(result.decision, SamplingDecision::RecordOnly);
    }

    #[test]
    fn outcome_sampler_samples_all_children_of_sampled_parent() {
        let parent = opentelemetry::trace::SpanContext::new(
            test_trace_id(1),
            test_span_id(2),
            opentelemetry::trace::TraceFlags::SAMPLED,
            true,
            opentelemetry::trace::TraceState::default(),
        );
        let cx = opentelemetry::Context::new().with_remote_span_context(parent);
        let sampler = OutcomeAwareSampler::new(TraceSamplingPolicy {
            sample_rate: 0.0,
            always_sample_errors: true,
            keep_over_budget_usd: None,
            keep_slower_than_secs: None,
        });

        let result = sampler.should_sample(
            Some(&cx),
            test_trace_id(3),
            "ai.request",
            &opentelemetry::trace::SpanKind::Internal,
            &[],
            &[],
        );
        assert_eq!(result.decision, SamplingDecision::RecordAndSample);
    }

    #[test]
    fn force_export_keeps_unsampled_error_cost_and_slow_spans() {
        let policy = TraceSamplingPolicy {
            sample_rate: 0.0,
            always_sample_errors: true,
            keep_over_budget_usd: Some(0.10),
            keep_slower_than_secs: Some(2.0),
        };

        let error_span =
            test_span_data(false, vec![KeyValue::new("otel.status_code", "ERROR")], 0.1);
        assert!(should_force_export_span(&error_span, &policy));

        let cost_span = test_span_data(
            false,
            vec![KeyValue::new("sbproxy.ai.cost_usd_micros", 250_000_i64)],
            0.1,
        );
        assert!(should_force_export_span(&cost_span, &policy));

        let slow_span = test_span_data(false, vec![], 2.5);
        assert!(should_force_export_span(&slow_span, &policy));

        let normal_span = test_span_data(false, vec![], 0.1);
        assert!(!should_force_export_span(&normal_span, &policy));
    }

    #[test]
    fn test_config_deserialize() {
        let json = r#"{
            "enabled": true,
            "endpoint": "http://localhost:4317",
            "service_name": "my-proxy",
            "sample_rate": 0.5,
            "keep_over_budget_usd": 1.25,
            "keep_slower_than_secs": 4.5,
            "propagation": "w3c"
        }"#;
        let config: TelemetryConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.endpoint.as_deref(), Some("http://localhost:4317"));
        assert_eq!(config.service_name, "my-proxy");
        assert_eq!(config.sample_rate, Some(0.5));
        assert_eq!(config.keep_over_budget_usd, Some(1.25));
        assert_eq!(config.keep_slower_than_secs, Some(4.5));
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

    /// WOR-1869: header pairs become gRPC metadata; names or values
    /// that are not valid metadata are skipped, never a panic.
    #[test]
    fn tonic_metadata_from_headers_maps_and_skips_invalid() {
        let headers = std::collections::BTreeMap::from([
            ("authorization".to_string(), "Bearer tok".to_string()),
            ("x-scope-orgid".to_string(), "tenant-1".to_string()),
            // A name with a space is an invalid tonic metadata key and
            // a value with a control character is invalid; both must
            // be skipped.
            ("Bad Header".to_string(), "v".to_string()),
            ("x-bad-value".to_string(), "line\nbreak".to_string()),
        ]);
        let metadata = tonic_metadata_from_headers(&headers);
        assert_eq!(
            metadata.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer tok")
        );
        assert_eq!(
            metadata.get("x-scope-orgid").and_then(|v| v.to_str().ok()),
            Some("tenant-1")
        );
        assert!(metadata.get("bad header").is_none());
        assert!(metadata.get("x-bad-value").is_none());
    }

    /// WOR-1869: detection stamps host + process identity, and the
    /// operator's `resource_attrs` always win on key conflict.
    #[test]
    fn otlp_resource_detects_and_operator_attrs_win() {
        let detected = detected_resource_attrs();
        let keys: Vec<&str> = detected.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"os.type"), "os.type detected: {keys:?}");
        assert!(
            keys.contains(&"process.pid"),
            "process.pid detected: {keys:?}"
        );

        let mut config = TelemetryConfig {
            service_name: "sbproxy-test".to_string(),
            ..Default::default()
        };
        config
            .resource_attrs
            .insert("os.type".to_string(), "operator-override".to_string());
        let resource = otlp_resource(&config);
        assert_eq!(
            resource
                .get(opentelemetry::Key::from_static_str("os.type"))
                .map(|v| v.to_string()),
            Some("operator-override".to_string()),
            "operator resource_attrs must beat detection"
        );
        assert_eq!(
            resource
                .get(opentelemetry::Key::from_static_str("service.name"))
                .map(|v| v.to_string()),
            Some("sbproxy-test".to_string())
        );
    }
}
