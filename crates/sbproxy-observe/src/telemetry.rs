//! OpenTelemetry tracing support for sbproxy.
//!
//! Splits the observe crate's responsibilities four ways:
//!
//! 1. **Span context** ([`SpanContext`]): a small W3C Trace Context
//!    helper used by request handlers to propagate `traceparent`
//!    headers across hops. Has no dependency on the heavyweight OTel
//!    SDK so it costs nothing when telemetry is disabled.
//! 2. **OTLP exporter** ([`build_otlp_trace_pipeline`]): builds and
//!    installs the global tracer provider. Callers that own the
//!    process subscriber (`crate::logging::init_inner`, the only
//!    production caller) layer the returned tracer into their own
//!    `tracing-subscriber` stack.
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

/// Transport for the OTLP exporter. gRPC is the default, matching the
/// Day-1 reference stack (`examples/observability-stack/`) and what
/// most collectors expect; HTTP/proto is the opt-in for environments
/// that block gRPC.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OtlpTransport {
    /// OTLP over HTTP with protobuf payload (default endpoint
    /// `http://localhost:4318/v1/traces`).
    Http,
    /// OTLP over gRPC (default endpoint `http://localhost:4327`, the
    /// Day-1 reference stack's collector port).
    #[default]
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
    /// Propagation format. Only `"w3c"` (the default, used when unset)
    /// is wired; [`TelemetryConfig::validate_propagation`] rejects any
    /// other value at boot instead of silently ignoring it.
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

/// Boot-time configuration errors caught before any pipeline installs,
/// so a misconfigured operator sees a clear failure instead of a
/// silently inert flag.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryConfigError {
    /// `export_metrics: true` can never take effect while `enabled` is
    /// `false`: [`init_otlp_metrics_pipeline`] no-ops whenever tracing
    /// itself is disabled.
    #[error(
        "proxy.telemetry.export_metrics is true, but proxy.telemetry.enabled is false; the \
         OTLP metrics pipeline never starts without tracing enabled"
    )]
    MetricsExportRequestedButTracingDisabled,
    /// Only the W3C propagator is ever installed ([`init_propagator`]
    /// always registers [`TraceContextPropagator`]); any other
    /// configured value is silently ignored today.
    #[error(
        "proxy.telemetry.propagation = \"{0}\" is not supported; only \"w3c\" (the default) is \
         wired today"
    )]
    UnsupportedPropagation(String),
}

impl TelemetryConfig {
    /// Boot-time check: `export_metrics: true` must actually be able to
    /// result in a running meter provider. Reject the combination that
    /// can't, rather than leaving the flag inert.
    pub fn validate_export_metrics(&self) -> Result<(), TelemetryConfigError> {
        if self.export_metrics && !self.enabled {
            return Err(TelemetryConfigError::MetricsExportRequestedButTracingDisabled);
        }
        Ok(())
    }

    /// Boot-time check: reject any `propagation` value other than the
    /// one that is actually wired.
    pub fn validate_propagation(&self) -> Result<(), TelemetryConfigError> {
        match self.propagation.as_deref() {
            None | Some("w3c") => Ok(()),
            Some(other) => Err(TelemetryConfigError::UnsupportedPropagation(
                other.to_string(),
            )),
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
    /// Builds the exporter itself on the export worker thread, inside
    /// its Tokio runtime, rather than on the caller's thread before
    /// spawning. tonic's `connect_lazy()` (invoked by
    /// `opentelemetry_otlp::SpanExporter::builder().with_tonic()...build()`)
    /// synchronously `tokio::spawn`s a background task that services
    /// the client's request buffer for the exporter's entire lifetime;
    /// that spawn panics with no ambient runtime, and the caller here
    /// (`build_otlp_trace_pipeline`, called from `main()` before
    /// Pingora builds any runtime) has none. Building inside the
    /// worker thread's own runtime, which stays alive and gets driven
    /// by every subsequent `rt.block_on` call in its message loop,
    /// gives that background task an ambient runtime both at spawn
    /// time and for as long as it needs to keep running. Blocks
    /// (briefly, via `std::sync::mpsc`, not async) until the worker
    /// reports the build succeeded or failed, so callers keep the same
    /// synchronous `Result` contract they had when the exporter was
    /// built inline.
    fn new(config: TelemetryConfig, endpoint: String, policy: TraceSamplingPolicy) -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel(TRACE_EXPORT_QUEUE_SIZE);
        let (ready_tx, ready_rx) = mpsc::channel();
        spawn_trace_export_worker(config, endpoint, rx, ready_tx);
        ready_rx
            .recv_timeout(TRACE_EXPORT_FLUSH_TIMEOUT)
            .map_err(|_| {
                anyhow::anyhow!("OTLP trace export worker did not report ready in time")
            })??;
        Ok(Self {
            tx,
            policy,
            dropped_spans: AtomicUsize::new(0),
        })
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
    config: TelemetryConfig,
    endpoint: String,
    rx: mpsc::Receiver<TraceExportMessage>,
    ready_tx: mpsc::Sender<Result<()>>,
) {
    // Cloned so the outer spawn-failure branch below still has a
    // sender to report through even though the closure (moved into
    // `.spawn()`) also needs its own.
    let spawn_failure_tx = ready_tx.clone();
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
                    let _ = ready_tx.send(Err(anyhow::anyhow!(
                        "failed to build OTLP trace export runtime: {e}"
                    )));
                    return;
                }
            };

            // Build the exporter here, inside this thread's runtime
            // (`.enter()` is enough: the build itself is synchronous,
            // it just needs `tokio::spawn` to find an ambient runtime).
            let mut exporter = {
                let _guard = rt.enter();
                match build_span_exporter(&config, &endpoint) {
                    Ok(exporter) => exporter,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                }
            };
            // Ignore a send failure here (the caller gave up waiting and
            // timed out); still worth serving messages in case it didn't.
            let _ = ready_tx.send(Ok(()));

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
        let _ = spawn_failure_tx.send(Err(anyhow::anyhow!(
            "failed to spawn OTLP trace export worker thread: {e}"
        )));
    }
}

/// Run `build` inside a dedicated thread's Tokio runtime, keep that
/// runtime alive and actively driven for the life of the process, and
/// return the value `build` produced.
///
/// For callers whose `build` closure constructs a tonic gRPC exporter:
/// `connect_lazy()` synchronously `tokio::spawn`s a background task
/// that services the client's request buffer for the exporter's entire
/// lifetime. That spawn panics with no ambient runtime already
/// entered, and needs the runtime it lands on to keep being driven
/// afterward, not just during the spawn call -- a short-lived runtime
/// built, used, and dropped immediately would have its spawned task
/// cancelled the moment it drops, silently breaking every future call
/// through the exporter. This is `spawn_trace_export_worker`'s "build
/// inside a runtime that keeps running" fix, generalized for a caller
/// (the OTLP metrics pipeline) that has no export-worker thread of its
/// own to piggyback the build onto: `PeriodicReader`'s own worker
/// thread (spawned by `runtime::TokioCurrentThread` once the exporter
/// is handed to it) doesn't exist yet at the point the exporter itself
/// needs to be built.
///
/// Blocks (briefly, via `std::sync::mpsc`, not async) until `build`
/// reports success or failure, so callers keep a synchronous `Result`.
fn build_on_a_runtime_that_outlives_this_call<T, F>(thread_name: &str, build: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let (ready_tx, ready_rx) = mpsc::channel::<Result<T>>();
    std::thread::Builder::new()
        .name(thread_name.to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ =
                        ready_tx.send(Err(anyhow::anyhow!("failed to build export runtime: {e}")));
                    return;
                }
            };
            let result = {
                let _guard = rt.enter();
                build()
            };
            let build_ok = result.is_ok();
            if ready_tx.send(result).is_err() || !build_ok {
                // Either nothing is listening anymore, or the build
                // itself failed: nothing to keep this thread alive for.
                return;
            }
            // Keep this runtime alive and actively driven forever so
            // the background task the build spawned keeps making
            // progress for the life of the process. The exporter value
            // already went back to the caller above; it is a plain,
            // thread-agnostic handle from here on (a channel-backed
            // client), so it works from whatever thread later calls it
            // as long as this runtime keeps servicing the worker task
            // behind it.
            rt.block_on(std::future::pending::<()>());
        })
        .map_err(|e| anyhow::anyhow!("failed to spawn export runtime thread {thread_name}: {e}"))?;
    ready_rx
        .recv_timeout(TRACE_EXPORT_FLUSH_TIMEOUT)
        .map_err(|_| {
            anyhow::anyhow!("export runtime thread {thread_name} did not report ready in time")
        })?
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
    let processor =
        OutcomeSamplingSpanProcessor::new(config.clone(), endpoint.clone(), policy.clone())?;

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
    if let Some(endpoint) = config.endpoint.clone().filter(|e| !e.is_empty()) {
        return endpoint;
    }
    match config.transport {
        // gRPC's tonic exporter takes a bare authority; HTTP needs the
        // per-signal path, which the SDK does not append for us when
        // `with_endpoint` overrides the default.
        OtlpTransport::Http => "http://localhost:4318/v1/traces".to_string(),
        OtlpTransport::Grpc => DEFAULT_OTLP_ENDPOINT.to_string(),
    }
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
///
/// Uses [`opentelemetry_sdk::runtime::TokioCurrentThread`], not
/// `runtime::Tokio`, for the `PeriodicReader`: registering the reader
/// with the provider synchronously calls `Runtime::spawn`, and the
/// `Tokio` binding's `spawn` is a bare `tokio::spawn`, which panics
/// without an ambient runtime already entered. This function runs from
/// `main()` before Pingora has built any runtime. `TokioCurrentThread`
/// spawns its own dedicated OS thread with its own `current_thread`
/// runtime for the reader's export loop (mirroring
/// `spawn_trace_export_worker`'s dedicated-thread pattern for traces,
/// just via the SDK's own equivalent binding instead of hand-rolled).
///
/// The gRPC exporter build itself needed the identical fix one level
/// earlier: `opentelemetry_otlp::MetricExporter::builder().with_tonic()
/// ...build()` calls tonic's `connect_lazy()`, which synchronously
/// `tokio::spawn`s its own background task regardless of which runtime
/// binding `PeriodicReader` uses. See
/// `build_on_a_runtime_that_outlives_this_call`.
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
            // reqwest's client construction (the HTTP exporter's
            // transport) needs no ambient runtime, only a runtime to
            // actually send requests later -- safe to build here on
            // the boot thread, same as the trace pipeline's HTTP branch.
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
            // tonic's connect_lazy() synchronously tokio::spawns a
            // background task that needs a runtime both to spawn onto
            // and to keep being driven by afterward; see
            // build_on_a_runtime_that_outlives_this_call's doc comment.
            let config = config.clone();
            let endpoint = endpoint.to_string();
            build_on_a_runtime_that_outlives_this_call("sbproxy-otel-metrics-connect", move || {
                let mut builder = opentelemetry_otlp::MetricExporter::builder()
                    .with_tonic()
                    .with_endpoint(endpoint.as_str());
                if !config.headers.is_empty() {
                    builder = builder.with_metadata(tonic_metadata_from_headers(&config.headers));
                }
                builder.build().map_err(|e| {
                    anyhow::anyhow!("failed to build OTLP/gRPC metric exporter: {}", e)
                })
            })?
        }
    };

    let interval = std::time::Duration::from_secs(config.metrics_interval_secs.unwrap_or(30));
    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(
        exporter,
        opentelemetry_sdk::runtime::TokioCurrentThread,
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
/// Called from [`build_otlp_trace_pipeline`] on both the enabled and
/// disabled paths so propagation works even when OTLP export is off.
pub fn init_propagator() {
    global::set_text_map_propagator(TraceContextPropagator::new());
}

/// Inject the active OTel context into outbound HTTP headers.
///
/// Propagation invariant: every HTTP request leaving
/// the proxy MUST carry `traceparent`. Outbound clients (ledger, Stripe,
/// facilitators, registry feeds, KYA token verifier, OAuth) call this
/// to satisfy that invariant in one line.
///
/// Reads the OTel context from the current `tracing::Span` when the
/// `tracing-opentelemetry` layer is installed and the span's parent was
/// seeded (see [`parent_span_on_remote_trace_context`]). Falls back to
/// the global `opentelemetry::Context::current()`, a defensive fallback
/// for any future caller of `Context::attach`; nothing in this crate
/// populates it today (see [`extract_from_headers`]'s doc for why it no
/// longer does).
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
    // the `tracing-opentelemetry` layer maintains (the one
    // parent_span_on_remote_trace_context seeds), and the task-local
    // OTel context as a defensive fallback for callers that attach
    // their own scoped Context directly.
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

/// Parse the inbound `traceparent`/`tracestate` request headers into a
/// [`crate::trace_ctx::w3c::TraceContext`], for log-line correlation
/// (access log / structured log emit the correct `trace_id` regardless
/// of OTLP state).
///
/// Pure parsing only: no OTel SDK context is attached anywhere. An
/// earlier version of this function attached the extracted context to
/// the ambient thread/task-local `opentelemetry::Context` and
/// deliberately leaked the attach guard so it outlived the call. That
/// is a per-request leak (nothing ever detaches it), and worse, on a
/// reused worker thread a *later* request with no `traceparent` of its
/// own would inherit the *previous* request's remote span context via
/// `Context::current()`, mixing traces (and tenants) together. Use
/// [`parent_span_on_remote_trace_context`] to seed a specific span's
/// parent instead: explicit, request-scoped, and left behind with no
/// residue once the caller's stack frame returns.
pub fn extract_from_headers(
    headers: &http::HeaderMap,
) -> Option<crate::trace_ctx::w3c::TraceContext> {
    headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(|tp| {
            let ts = headers.get("tracestate").and_then(|v| v.to_str().ok());
            crate::trace_ctx::w3c::TraceContext::parse_with_state(tp, ts)
        })
}

/// Parent `span` on the caller's remote trace context, so the exported
/// OTel span shares the inbound `trace_id` instead of rooting a fresh
/// one.
///
/// Deliberately request-scoped and side-effect-free beyond the one
/// `span` passed in: no ambient thread-local or task-local OTel state
/// is touched, so there is nothing to leak and nothing for an
/// unrelated later request on a reused worker thread to inherit. `is_
/// remote` must be `true` only when `trace_ctx` came from actually
/// parsing an inbound header (W3C or B3) rather than
/// [`crate::trace_ctx::w3c::TraceContext::new_random`]'s locally
/// synthesized root; parenting a span on a context we invented
/// ourselves would be pointless. No-ops when `trace_ctx` is `None`,
/// `is_remote` is `false`, or the hex IDs fail to parse.
pub fn parent_span_on_remote_trace_context(
    span: &tracing::Span,
    trace_ctx: Option<&crate::trace_ctx::w3c::TraceContext>,
    is_remote: bool,
) {
    if !is_remote {
        return;
    }
    let Some(trace_ctx) = trace_ctx else {
        return;
    };
    let Ok(trace_id) = opentelemetry::trace::TraceId::from_hex(&trace_ctx.trace_id) else {
        return;
    };
    let Ok(span_id) = opentelemetry::trace::SpanId::from_hex(&trace_ctx.parent_id) else {
        return;
    };
    let trace_flags = if trace_ctx.is_sampled() {
        opentelemetry::trace::TraceFlags::SAMPLED
    } else {
        opentelemetry::trace::TraceFlags::default()
    };
    let span_context = opentelemetry::trace::SpanContext::new(
        trace_id,
        span_id,
        trace_flags,
        true, // is_remote
        opentelemetry::trace::TraceState::NONE,
    );
    let cx = Context::new().with_remote_span_context(span_context);
    tracing_opentelemetry::OpenTelemetrySpanExt::set_parent(span, cx);
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
    fn export_metrics_true_requires_tracing_enabled() {
        let config = TelemetryConfig {
            export_metrics: true,
            ..TelemetryConfig::default()
        };
        assert!(config.validate_export_metrics().is_err());
    }

    #[test]
    fn export_metrics_true_with_tracing_enabled_is_valid() {
        let config = TelemetryConfig {
            enabled: true,
            export_metrics: true,
            ..TelemetryConfig::default()
        };
        assert!(config.validate_export_metrics().is_ok());
    }

    #[test]
    fn export_metrics_false_needs_no_validation() {
        let config = TelemetryConfig {
            export_metrics: false,
            ..TelemetryConfig::default()
        };
        assert!(config.validate_export_metrics().is_ok());
    }

    #[test]
    fn init_otlp_metrics_pipeline_does_not_panic_without_an_ambient_tokio_runtime() {
        // A plain #[test] fn has no tokio runtime, matching main()'s
        // context when it calls this at boot (Pingora builds its
        // runtime later). TelemetryConfig::default()'s transport is
        // Grpc, so this exercises both fixed panic points: building
        // the tonic exporter itself (connect_lazy's synchronous
        // tokio::spawn, build_on_a_runtime_that_outlives_this_call) and
        // registering the PeriodicReader with the provider
        // (runtime::TokioCurrentThread, not runtime::Tokio). Port 1
        // never accepts a connection, so any background export attempt
        // just fails quietly rather than hanging.
        let config = TelemetryConfig {
            enabled: true,
            export_metrics: true,
            endpoint: Some("http://127.0.0.1:1".to_string()),
            metrics_interval_secs: Some(3600),
            ..TelemetryConfig::default()
        };
        assert!(init_otlp_metrics_pipeline(&config).is_ok());
    }

    #[test]
    fn build_otlp_trace_pipeline_does_not_panic_without_an_ambient_tokio_runtime() {
        // Same reasoning as the metrics regression test above, for the
        // trace side. TelemetryConfig::default()'s transport is Grpc
        // (the documented, codebase-wide default; see Task 1.5), so
        // this is exactly the config main() builds when an operator
        // sets telemetry.enabled: true and does not override transport.
        // Before this fix, OutcomeSamplingSpanProcessor::new built the
        // tonic exporter directly on this (runtime-less) thread; tonic's
        // connect_lazy() panics there via a bare tokio::spawn inside
        // Channel::new (tonic-0.12.3 transport/channel/mod.rs:160,
        // hyper-util-0.1.20 rt/tokio.rs:115) regardless of which
        // runtime binding the *metrics* PeriodicReader uses -- this is
        // an entirely separate code path. Port 1 never accepts a
        // connection, so any background export attempt just fails
        // quietly rather than hanging.
        let config = TelemetryConfig {
            enabled: true,
            endpoint: Some("http://127.0.0.1:1".to_string()),
            ..TelemetryConfig::default()
        };
        assert!(build_otlp_trace_pipeline(&config).is_ok());
    }

    #[test]
    fn propagation_unset_or_w3c_is_valid() {
        assert!(TelemetryConfig::default().validate_propagation().is_ok());
        let config = TelemetryConfig {
            propagation: Some("w3c".to_string()),
            ..TelemetryConfig::default()
        };
        assert!(config.validate_propagation().is_ok());
    }

    #[test]
    fn propagation_b3_is_rejected_with_a_message_naming_supported_values() {
        let config = TelemetryConfig {
            propagation: Some("b3".to_string()),
            ..TelemetryConfig::default()
        };
        let error = config
            .validate_propagation()
            .expect_err("b3 propagation is not wired");
        let message = error.to_string();
        assert!(message.contains("b3"), "{message}");
        assert!(message.contains("w3c"), "{message}");
    }

    #[test]
    fn http_transport_defaults_to_4318_with_traces_path() {
        let config = TelemetryConfig {
            transport: OtlpTransport::Http,
            endpoint: None,
            ..TelemetryConfig::default()
        };
        assert_eq!(otlp_endpoint(&config), "http://localhost:4318/v1/traces");
    }

    #[test]
    fn grpc_transport_defaults_to_4327_with_no_path() {
        let config = TelemetryConfig {
            transport: OtlpTransport::Grpc,
            endpoint: None,
            ..TelemetryConfig::default()
        };
        assert_eq!(otlp_endpoint(&config), DEFAULT_OTLP_ENDPOINT);
    }

    #[test]
    fn explicit_http_endpoint_is_used_verbatim_with_no_suffix_appended() {
        let config = TelemetryConfig {
            transport: OtlpTransport::Http,
            endpoint: Some("http://collector.internal:4318".to_string()),
            ..TelemetryConfig::default()
        };
        assert_eq!(otlp_endpoint(&config), "http://collector.internal:4318");
    }

    #[test]
    fn default_transport_agrees_with_the_documented_grpc_default() {
        // TelemetryConfig::default(), the YAML-omitted-field serde
        // default (default_transport()), and OtlpTransport's own
        // #[default] must all agree: gRPC on the Day-1 reference
        // endpoint (examples/observability-stack/, docs/observability.md).
        // HTTP is the documented opt-in for environments that block gRPC.
        assert_eq!(TelemetryConfig::default().transport, OtlpTransport::Grpc);
        assert_eq!(OtlpTransport::default(), OtlpTransport::Grpc);
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
        // Round-trip a known traceparent: extract from inbound headers
        // (pure parse, no side effects), parent a fresh span on it
        // explicitly (the request-scoped replacement for the old
        // ambient-attach mechanism), inject into outbound headers, and
        // assert trace_id is preserved.
        //
        // parent_span_on_remote_trace_context calls
        // tracing_opentelemetry::OpenTelemetrySpanExt::set_parent, and
        // inject_into_headers calls ...::context -- both look up
        // per-span OTel extension data that only exists when a real
        // tracing_opentelemetry layer is part of the active subscriber.
        // In production that's always true by the time any span is
        // created (main() installs it before serving the first
        // request); a bare #[test] fn has no subscriber installed at
        // all by default, so both calls would silently no-op without
        // one. Install a minimal in-process layer (no exporter, so no
        // network/runtime dependency) scoped to this test, matching
        // the shape production always runs under rather than
        // resurrecting the ambient-attach mechanism this test used to
        // rely on.
        use tracing_subscriber::layer::SubscriberExt;

        init_propagator();
        let mut inbound = http::HeaderMap::new();
        let known_tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        inbound.insert(
            http::header::HeaderName::from_static("traceparent"),
            http::header::HeaderValue::from_static(known_tp),
        );

        let parsed = extract_from_headers(&inbound);
        let parsed = parsed.expect("traceparent must parse");
        assert_eq!(parsed.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert!(parsed.is_sampled());

        let provider = sdktrace::TracerProvider::builder().build();
        let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, "test");
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        let subscriber = tracing_subscriber::registry().with(otel_layer);

        tracing::subscriber::with_default(subscriber, || {
            // Force a fresh interest re-evaluation against the
            // just-installed subscriber. Without this, a span/event
            // callsite whose Interest was already cached (e.g. by an
            // earlier test's tracing::info_span!("test") at a
            // different source line firing under no subscriber at
            // all) can stay cached as Never and never reach this
            // subscriber, regardless of it being installed correctly.
            tracing::callsite::rebuild_interest_cache();

            // Run inside a tracing span so inject_into_headers has an
            // active context to work with.
            let span = tracing::info_span!("test");
            parent_span_on_remote_trace_context(&span, Some(&parsed), true);
            let _g = span.enter();

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
        });
    }

    #[test]
    fn parent_span_on_remote_trace_context_ignores_a_locally_synthesized_root() {
        // TraceContext::new_random() (is_remote: false) must never seed
        // a span's parent -- there is no real caller to be a child of.
        init_propagator();
        let local_root = crate::trace_ctx::w3c::TraceContext::new_random();
        let span = tracing::info_span!("local_root_test");
        parent_span_on_remote_trace_context(&span, Some(&local_root), false);
        let _g = span.enter();

        let mut outbound = http::HeaderMap::new();
        inject_into_headers(&mut outbound);
        if let Some(injected) = outbound.get("traceparent").and_then(|v| v.to_str().ok()) {
            assert!(
                !injected.contains(&local_root.trace_id),
                "a locally synthesized root must not be injected as if it were a real \
                 parent: {injected}"
            );
        }
    }

    #[test]
    fn parent_span_on_remote_trace_context_noops_without_a_trace_ctx() {
        init_propagator();
        let span = tracing::info_span!("no_ctx_test");
        parent_span_on_remote_trace_context(&span, None, true);
        // No panic, no parent set; nothing further to assert beyond
        // "this returns cleanly" since there is nothing to parent on.
        let _g = span.enter();
    }

    #[test]
    fn parent_span_on_remote_trace_context_does_not_leak_to_other_spans() {
        // The property the old attach+forget mechanism violated: seeding
        // one span's parent must never be observable from a different
        // span, not even one created immediately afterward on the same
        // thread (simulating the next request on a reused worker thread
        // with no traceparent of its own).
        init_propagator();
        let known = crate::trace_ctx::w3c::TraceContext::parse(
            "00-11112222333344445555666677778888-1111222233334444-01",
        )
        .expect("fixture traceparent parses");

        let seeded = tracing::info_span!("seeded");
        parent_span_on_remote_trace_context(&seeded, Some(&known), true);

        let unrelated = tracing::info_span!("unrelated");
        let _g = unrelated.enter();
        let mut outbound = http::HeaderMap::new();
        inject_into_headers(&mut outbound);
        if let Some(injected) = outbound.get("traceparent").and_then(|v| v.to_str().ok()) {
            assert!(
                !injected.contains("11112222333344445555666677778888"),
                "an unrelated span must not inherit a different span's remote parent: {injected}"
            );
        }
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

    /// Regression: sbproxy-observe used to pin its own Cargo.toml
    /// version independently of the workspace, so every OTLP resource
    /// stamped `service.version = "0.1.0"` no matter what release was
    /// actually running, silently defeating version-based correlation
    /// across a rolling upgrade. sbproxy-observe now inherits
    /// `version.workspace = true`, so its own CARGO_PKG_VERSION is the
    /// same string `sbproxy --version` prints; this assertion breaks
    /// again if that inheritance is ever reverted.
    #[test]
    fn otlp_resource_service_version_matches_the_workspace_version() {
        let resource = otlp_resource(&TelemetryConfig::default());
        assert_eq!(
            resource
                .get(opentelemetry::Key::from_static_str("service.version"))
                .map(|v| v.to_string()),
            Some(env!("CARGO_PKG_VERSION").to_string())
        );
    }
}
