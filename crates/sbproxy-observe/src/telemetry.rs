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
//!    every carrier that goes through [`propagation_pairs`] picks up
//!    the current trace. [`inject_into_headers`] and
//!    [`inject_into_reqwest`] turn those pairs into HTTP headers;
//!    carriers that are not headers (a JSON body, a queue envelope)
//!    consume the pairs directly. [`outbound_trace_headers`] is the
//!    entry point for a helper HTTP call that holds a request-scoped
//!    [`crate::trace_ctx::w3c::TraceContext`] rather than relying on the
//!    ambient span. Two kinds of caller need that: the ones running
//!    after the intake span has closed, and the ones running behind a
//!    `tokio::spawn`, which does not inherit the span it was spawned
//!    from.
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

/// Authorize an OTLP exporter endpoint against the top-level
/// `egress.telemetry:` allowlist (WOR-2481), and stamp the egress
/// sightings inventory either way.
///
/// A denied endpoint refuses boot immediately and loudly, naming the
/// endpoint: unlike an exporter that merely fails to *build* (logged,
/// then boot continues without OTLP -- see `logging::init_inner`), a
/// denied destination means the operator's own allowlist is doing
/// exactly what it was configured to do, and silently continuing would
/// either export telemetry somewhere never approved or leave the
/// exporter sending nowhere with no visible reason why. Mirrors the
/// audit-chain's boot-time fail-loud contract (WOR-2478).
///
/// `None` (an omitted `egress.telemetry:` sub-block, or an authorizer
/// that permits `endpoint`) stamps the sighting, records `endpoint` as
/// this signal's active boot-only endpoint (via
/// [`record_active_boot_telemetry_endpoint`]), and returns normally, so
/// boot continues. This function itself only ever runs once per
/// process, at boot; a later config reload re-verifies the recorded
/// endpoint against the *new* generation's authorizer through the
/// separate [`reverify_active_boot_telemetry_endpoints`], called from
/// `sbproxy_core::server::lifecycle::reload_compiled_config_locked`'s
/// reject-only phase rather than by rerunning this function (WOR-2481).
///
/// Split from [`check_telemetry_egress`] so the authorization decision
/// (stamps the inventory, returns an outcome) is unit-testable on its
/// own; `std::process::exit` cannot be exercised from within the test
/// process that calls it.
///
/// **Boot-only.** Reserved for the two exporters actually built once, at
/// process boot, and never again: `build_span_exporter` (traces) and
/// `init_otlp_metrics_pipeline` (metrics). The log sink is reachable
/// from a live config reload (`install_sink_dispatcher_from_config` runs
/// there too, not just at boot), so it calls
/// [`authorize_telemetry_endpoint_or_reject`] instead, which returns an
/// error a running process can recover from rather than exiting it.
/// C2 (WOR-2481 review): the earlier version of this arming called this
/// exit-on-deny function from the log sink's constructor too, so a
/// reload that armed `egress.telemetry:` after boot (the registry slot
/// this checks is otherwise installed once, from `main`, before boot
/// even starts building a pipeline) could terminate an already-running
/// process over a log sink, the one OTLP exporter that is not actually
/// boot-only.
pub(crate) fn authorize_telemetry_endpoint_or_refuse_boot(endpoint: &str, signal: &str) {
    if let TelemetryEgressOutcome::Denied(denied) = check_telemetry_egress(endpoint, signal) {
        eprintln!(
            "Fatal: telemetry {signal} exporter endpoint '{endpoint}' is not on the \
             egress.telemetry allowlist ({denied:?}). Add it to egress.telemetry.hosts, or \
             remove the egress.telemetry block to leave telemetry ungated."
        );
        std::process::exit(1);
    }
    record_active_boot_telemetry_endpoint(signal, endpoint);
}

/// Authorize `endpoint` against `egress.telemetry:` and stamp the egress
/// sightings inventory, returning an error on denial instead of exiting
/// the process (WOR-2481 review, C2). For the OTLP-logs sink
/// specifically: unlike the trace and metric exporters, it can be
/// (re)built from a live config reload
/// (`install_sink_dispatcher_from_config` runs on every reload, not
/// only at boot), so a denial here has to be something the caller can
/// recover from. `OtlpLogSink::new`'s caller in
/// `sbproxy_core::server::lifecycle` already treats any `Err` from
/// exporter construction as "log a warning, count it, and run without
/// this sink" -- the exact posture a denied endpoint should get too,
/// since continuing to run a process over an operator's own allowlist
/// doing its job is worse than a missing log sink.
pub(crate) fn authorize_telemetry_endpoint_or_reject(endpoint: &str, signal: &str) -> Result<()> {
    match check_telemetry_egress(endpoint, signal) {
        TelemetryEgressOutcome::Proceed => Ok(()),
        TelemetryEgressOutcome::Denied(denied) => Err(anyhow::anyhow!(
            "telemetry {signal} exporter endpoint '{endpoint}' is not on the \
             egress.telemetry allowlist ({denied:?}). Add it to egress.telemetry.hosts, or \
             remove the egress.telemetry block to leave telemetry ungated."
        )),
    }
}

/// Decision [`authorize_telemetry_endpoint_or_refuse_boot`] and
/// [`authorize_telemetry_endpoint_or_reject`] both act on.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TelemetryEgressOutcome {
    /// No authorizer configured for `EgressPurpose::Telemetry` (an
    /// omitted `egress.telemetry:` sub-block), or the configured
    /// authorizer allowed the destination.
    Proceed,
    /// The configured allowlist denied the destination.
    Denied(sbproxy_security::egress::EgressDenied),
}

/// Authorize `endpoint` against `egress.telemetry:` and stamp the egress
/// sightings inventory, without acting on the result. See
/// [`authorize_telemetry_endpoint_or_refuse_boot`] (boot-only, exits on
/// denial) and [`authorize_telemetry_endpoint_or_reject`] (reload-safe,
/// returns `Err` on denial) for the two production entry points built
/// on this shared decision.
///
/// Reads the *currently installed* generation's authorizer out of the
/// process-wide configured-gate registry. See
/// [`check_telemetry_egress_against`] for the sibling that checks
/// against an explicit authorizer instead, which is what lets a config
/// reload re-verify a boot-only exporter's endpoint against the *new*
/// generation before that generation is installed anywhere (WOR-2481).
pub(crate) fn check_telemetry_egress(endpoint: &str, signal: &str) -> TelemetryEgressOutcome {
    use sbproxy_security::egress::{configured_gate, EgressPurpose};
    check_telemetry_egress_against(
        configured_gate(EgressPurpose::Telemetry).as_ref(),
        endpoint,
        signal,
    )
}

/// Same decision as [`check_telemetry_egress`], against an explicit
/// `authorizer` rather than whatever the process-wide configured-gate
/// registry currently holds. `None` means ungated, exactly as an absent
/// registry entry does.
///
/// A denial here also counts against
/// [`sbproxy_security::egress::record_egress_refused`], the same
/// Prometheus counter and typed-event bridge every other egress purpose
/// already goes through, so a refused telemetry destination is visible
/// on `sbproxy_egress_refused_total` and the `egress_refused` event feed
/// exactly like an AI-provider or usage-sink refusal (it was previously
/// stamped in the sightings inventory only).
pub(crate) fn check_telemetry_egress_against(
    authorizer: Option<&sbproxy_security::egress::EgressAuthorizer>,
    endpoint: &str,
    signal: &str,
) -> TelemetryEgressOutcome {
    use sbproxy_security::egress::{
        record_egress_refused, record_egress_seen, EgressPurpose, EgressSightingStatus,
        SystemHostResolver,
    };
    let origin = format!("telemetry.{signal}");
    let Some(authorizer) = authorizer else {
        record_egress_seen(
            EgressPurpose::Telemetry,
            endpoint,
            &origin,
            EgressSightingStatus::Ungated,
            None,
        );
        return TelemetryEgressOutcome::Proceed;
    };
    match authorizer.authorize(EgressPurpose::Telemetry, endpoint, &SystemHostResolver) {
        Ok(_) => {
            record_egress_seen(
                EgressPurpose::Telemetry,
                endpoint,
                &origin,
                EgressSightingStatus::Allowed,
                None,
            );
            TelemetryEgressOutcome::Proceed
        }
        Err(denied) => {
            record_egress_seen(
                EgressPurpose::Telemetry,
                endpoint,
                &origin,
                EgressSightingStatus::Denied,
                Some(denied),
            );
            record_egress_refused(EgressPurpose::Telemetry, denied, "unset", &origin);
            TelemetryEgressOutcome::Denied(denied)
        }
    }
}

/// Endpoints the two boot-only OTLP exporters (traces, metrics) are
/// currently dialing, keyed by signal (`"traces"` / `"metrics"`).
///
/// Populated by [`record_active_boot_telemetry_endpoint`] once
/// [`authorize_telemetry_endpoint_or_refuse_boot`] lets an exporter
/// proceed. The OTLP-logs sink is deliberately absent: it is rebuilt on
/// every config reload and re-authorizes itself at construction time
/// through [`authorize_telemetry_endpoint_or_reject`], so it never goes
/// stale the way a boot-only exporter can (WOR-2481).
fn active_boot_telemetry_endpoints(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static ACTIVE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, String>>,
    > = std::sync::OnceLock::new();
    ACTIVE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Record that the boot-only `signal` exporter is now dialing `endpoint`,
/// so a later config reload can re-verify it through
/// [`reverify_active_boot_telemetry_endpoints`] (WOR-2481).
///
/// `#[doc(hidden)]`: a cross-crate test seam, not part of the supported
/// API surface (this crate is internal to begin with; see the workspace
/// `CLAUDE.md`'s public-surface list). Its one production caller,
/// [`authorize_telemetry_endpoint_or_refuse_boot`], lives in this same
/// file, so `pub(crate)` would satisfy that call alone; `pub` is what it
/// takes for `sbproxy_core::server::lifecycle`'s reload-refusal test to
/// seed the same state a real, allowed boot-only exporter would leave
/// behind, without booting one (which needs live network I/O and a
/// tokio runtime neither test process wants to pay for). Named to match
/// the `..._for_test` seams `sbproxy_extension::mcp::federation` and
/// `sbproxy_observe::event_sink::EventEgress` expose for the same
/// reason.
#[doc(hidden)]
pub fn record_active_boot_telemetry_endpoint(signal: &str, endpoint: &str) {
    if let Ok(mut active) = active_boot_telemetry_endpoints().lock() {
        active.insert(signal.to_string(), endpoint.to_string());
    }
}

/// Re-authorize every recorded boot-only exporter endpoint against
/// `authorizer`, the *next* generation's compiled `egress.telemetry:`
/// value, stamping the sightings inventory for each exactly as the
/// original boot-time check did.
///
/// Called from
/// `sbproxy_core::server::lifecycle::reload_compiled_config_locked`'s
/// reject-only phase, before anything about the candidate reload is
/// installed. Returns `Err` naming the signal and endpoint on the first
/// one the new generation denies, which refuses the whole reload the
/// same way `reconcile_process_cluster` and `reconcile_process_secrets`
/// already refuse it over their own irreversible process state
/// (WOR-2481): the trace and metric exporters are never rebuilt, so an
/// endpoint that was allowed at boot and is denied by this reload would
/// otherwise keep exporting, silently, to a destination the operator's
/// own allowlist no longer approves. That silent continuation is
/// exactly the gap this function closes.
pub fn reverify_active_boot_telemetry_endpoints(
    authorizer: Option<&sbproxy_security::egress::EgressAuthorizer>,
) -> Result<()> {
    let active: Vec<(String, String)> = match active_boot_telemetry_endpoints().lock() {
        Ok(guard) => guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        Err(_) => Vec::new(),
    };
    for (signal, endpoint) in active {
        if let TelemetryEgressOutcome::Denied(denied) =
            check_telemetry_egress_against(authorizer, &endpoint, &signal)
        {
            anyhow::bail!(
                "reload refused: the running telemetry {signal} exporter's endpoint \
                 '{endpoint}' is no longer on the egress.telemetry allowlist ({denied:?}). \
                 This exporter is never rebuilt, so continuing would leave it exporting to a \
                 now-denied destination. Add '{endpoint}' back to egress.telemetry.hosts, or \
                 restart sbproxy once you want the new allowlist to take effect."
            );
        }
    }
    Ok(())
}

fn build_span_exporter(
    config: &TelemetryConfig,
    endpoint: &str,
) -> Result<opentelemetry_otlp::SpanExporter> {
    authorize_telemetry_endpoint_or_refuse_boot(endpoint, "traces");
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
    authorize_telemetry_endpoint_or_refuse_boot(endpoint, "metrics");

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

/// Resolve which OTel context the propagator should read.
///
/// Two layers: the per-`tracing::Span` OTel context that the
/// `tracing-opentelemetry` layer maintains (the one
/// [`parent_span_on_remote_trace_context`] seeds), and the task-local
/// `opentelemetry::Context::current()` as a fallback. The span layer
/// wins whenever it carries an active span.
///
/// The fallback is deliberate. It only runs when the span layer had
/// nothing, so it costs a clone on a path that was about to propagate
/// nothing at all, and it is the only thing that keeps working for a
/// caller that attaches a scoped `Context` without a `tracing::Span`
/// wrapped around it. Nothing in this crate populates it today; see
/// [`extract_from_headers`]'s doc for why it no longer does.
fn context_to_propagate() -> Context {
    let cx_from_span =
        tracing_opentelemetry::OpenTelemetrySpanExt::context(&tracing::Span::current());
    if opentelemetry::trace::TraceContextExt::has_active_span(&cx_from_span) {
        cx_from_span
    } else {
        Context::current()
    }
}

/// The trace-context key/value pairs the registered propagator emits
/// for the currently active context.
///
/// This is the carrier-agnostic shape, and the single implementation
/// every other injector in this module is built on.
/// [`inject_into_headers`] and [`inject_into_reqwest`] turn these pairs
/// into HTTP headers. A caller whose carrier is not a header set (a
/// JSON body, a queue envelope, a message attribute map) consumes the
/// pairs directly. The MCP gateway does exactly that: MCP carries
/// trace context in the JSON-RPC body's `params._meta` block, which is
/// the one carrier that also works on the stdio transport, where there
/// is no header surface to inject into at all.
///
/// Keys are whatever the registered propagator emits. With the W3C
/// TraceContext propagator this crate installs, that means
/// `traceparent` plus `tracestate` when the trace carries one.
///
/// Returns an empty vector when no trace context is active, or when no
/// propagator has been registered (the global default is a no-op
/// propagator). Treat empty as "attach no carrier", not "attach an
/// empty one": a reader downstream can then tell an untraced request
/// from a malformed one.
pub fn propagation_pairs() -> Vec<(String, String)> {
    use opentelemetry::propagation::Injector;

    struct VecInjector(Vec<(String, String)>);
    impl Injector for VecInjector {
        fn set(&mut self, key: &str, value: String) {
            self.0.push((key.to_string(), value));
        }
    }

    let cx = context_to_propagate();
    let mut sink = VecInjector(Vec::new());
    global::get_text_map_propagator(|prop| prop.inject_context(&cx, &mut sink));
    sink.0
}

/// Inject the active OTel context into outbound HTTP headers.
///
/// This is the ambient half of the propagation contract: it reads
/// whatever trace the calling task is already inside. A caller that
/// holds a request-scoped [`crate::trace_ctx::w3c::TraceContext`] should
/// reach for [`outbound_trace_headers`] instead, which works on the
/// paths this one cannot see: after the intake span has closed, inside a
/// `tokio::spawn`, and with OTLP switched off entirely.
///
/// Pairs come from [`propagation_pairs`], so the header path and every
/// non-header carrier propagate the same context from the same code. A
/// key or value that is not a legal HTTP header is skipped rather than
/// panicking; the W3C propagator emits neither.
pub fn inject_into_headers(headers: &mut http::HeaderMap) {
    for (key, value) in propagation_pairs() {
        if let (Ok(name), Ok(val)) = (
            http::header::HeaderName::from_bytes(key.as_bytes()),
            http::header::HeaderValue::from_str(&value),
        ) {
            headers.insert(name, val);
        }
    }
}

/// Inject the active OTel context into a `reqwest::RequestBuilder`'s
/// headers. The [`inject_into_headers`] equivalent for the outbound
/// clients that are built on top of `reqwest`, reading the same
/// [`propagation_pairs`].
///
/// The MCP gateway calls this on the REST dispatch for an
/// OpenAPI-backed tool, where the outbound request is plain HTTP and
/// has no JSON-RPC body to carry `params._meta` instead.
pub fn inject_into_reqwest(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let mut req = req;
    for (key, value) in propagation_pairs() {
        req = req.header(key, value);
    }
    req
}

/// The trace-context headers one outbound helper call should carry.
///
/// W3C Trace Context: <https://www.w3.org/TR/trace-context/>. The header
/// is `traceparent`, plus `tracestate` when the trace carries vendor
/// state, and the value is built by
/// [`crate::trace_ctx::w3c::TraceContext::to_traceparent`], which is the
/// only place in this workspace that formats one. The proxied upstream
/// path in `sbproxy-core` writes the same two headers from the same
/// formatter; the difference is only the carrier, because Pingora's
/// request header is not a `reqwest` builder.
///
/// `trace_ctx` is the request-scoped context, normally
/// `RequestContext::trace_ctx`. When it is `Some`, the returned
/// `traceparent` names a fresh [`crate::trace_ctx::w3c::TraceContext::child`]
/// of it: same `trace_id`, same sampled flag, a new span id, so the
/// helper call reads as its own hop under the request's trace rather
/// than claiming to be the request itself.
///
/// When it is `None` this falls back to [`propagation_pairs`], the
/// ambient OTel context of the calling task. That is the right source
/// for a caller that is inside an instrumented span but has no
/// `RequestContext` reachable, and it is empty when no trace is active.
///
/// **An empty return means attach nothing.** It never invents a trace id.
/// A fabricated root per outbound call would render in a trace backend as
/// a real single-span trace, indistinguishable from a genuine one and
/// linked to nothing, which is strictly worse than the header's absence:
/// absence is legible as "this hop was not traced".
///
/// # Examples
///
/// ```
/// use sbproxy_observe::telemetry::outbound_trace_headers;
/// use sbproxy_observe::TraceContext;
///
/// let parent = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
///     .expect("a well-formed traceparent");
/// let headers = outbound_trace_headers(Some(&parent));
///
/// assert_eq!(headers.len(), 1);
/// assert_eq!(headers[0].0, "traceparent");
/// // Same trace, new span id: this is a child hop, not the request.
/// assert!(headers[0].1.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
/// assert!(headers[0].1.ends_with("-01"));
/// assert!(!headers[0].1.contains("00f067aa0ba902b7"));
/// ```
pub fn outbound_trace_headers(
    trace_ctx: Option<&crate::trace_ctx::w3c::TraceContext>,
) -> Vec<(&'static str, String)> {
    let Some(parent) = trace_ctx else {
        // The ambient propagator emits `traceparent` and `tracestate`
        // and nothing else, but it is swappable, so map by name rather
        // than by position and drop anything this function has not
        // promised to emit.
        return propagation_pairs()
            .into_iter()
            .filter_map(|(key, value)| match key.as_str() {
                "traceparent" => Some(("traceparent", value)),
                "tracestate" => Some(("tracestate", value)),
                _ => None,
            })
            .collect();
    };
    let child = parent.child();
    let mut out = vec![("traceparent", child.to_traceparent())];
    if let Some(state) = child.tracestate {
        out.push(("tracestate", state));
    }
    out
}

/// Attach [`outbound_trace_headers`] to a `reqwest` request builder.
///
/// The one-line form for the outbound clients built on `reqwest`. Every
/// helper HTTP call the proxy makes on a customer's behalf goes through
/// this or through [`outbound_trace_headers`] directly, and
/// `outbound_trace_drift` fails the build for one that does neither
/// without a reviewed exemption.
pub fn inject_reqwest_trace_context(
    req: reqwest::RequestBuilder,
    trace_ctx: Option<&crate::trace_ctx::w3c::TraceContext>,
) -> reqwest::RequestBuilder {
    let mut req = req;
    for (name, value) in outbound_trace_headers(trace_ctx) {
        req = req.header(name, value);
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
///
/// The doc comment said eight and the enum had seven for as long as both
/// existed. `deploy/dashboards/traces-overview.json` had the eighth,
/// `notify`, hardcoded in its pillar template variable, so a panel offered
/// operators a filter value the code could not produce. The span drift
/// guard now pins all three lists to each other.
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
    /// Outbound notification delivery: alert webhooks and the sinks that
    /// carry them off the box.
    Notify,
}

impl Pillar {
    /// Every pillar, in the canonical order the dashboards list them.
    ///
    /// A `match` keeps [`Pillar::as_str`] exhaustive, but nothing makes a
    /// separate list of pillars complete, and two of those had already
    /// drifted apart. This is the one the guard reads.
    pub const ALL: &'static [Pillar] = &[
        Pillar::Intake,
        Pillar::Policy,
        Pillar::Action,
        Pillar::Transform,
        Pillar::Ledger,
        Pillar::Rail,
        Pillar::Audit,
        Pillar::Notify,
    ];

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

// --- WOR-2318: pillar spans on the ordinary proxied request path ---
//
// Until this landed the only spans a request could produce came from the
// AI gateway. A plain proxied HTTP request produced none at all: the eight
// `sbproxy.<pillar>.<verb>` names were published as the naming convention
// and emitted by nothing, and the one pillar span that was live ran on the
// settlement background sweep. An operator tracing a slow proxied request
// had metrics and an access-log line and no span.
//
// [`tracing_helper::span`] is the friendly shape for that vocabulary and
// the wrong one for a per-request phase. It formats
// `sbproxy.<pillar>.<verb>` into a fresh `String` on every call, before the
// span macro can decide whether any subscriber wants the span, so a proxy
// with tracing switched off still pays one allocation per phase per
// request. The constructors below name the span with a `&'static str` the
// compiler already holds and take every field borrowed or already
// computed, so the request path allocates nothing and, when the callsite
// is disabled, evaluates nothing: `tracing`'s `span!` only builds the
// value set after the callsite reports interest.
//
// They are `info_span!` rather than `debug_span!` on purpose. The root
// `EnvFilter` in [`crate::logging`] sits in front of the OpenTelemetry
// layer and not only the fmt layer, so a `debug_span!` at the default
// `info` level is never constructed and therefore never exported. That
// span would still satisfy the drift guard, which proves a call site
// exists rather than that anything reaches a collector, which is the
// quiet failure this whole registry was written to make impossible.
//
// Nothing here adds a sampling decision of its own. These spans reach the
// same `tracing-opentelemetry` layer every other span does and are
// therefore subject to the same head sampler the SDK is built with
// (ParentBased over TraceIdRatio, from `telemetry.sample_rate`).

// The four names below are `pub(crate)` rather than `pub` deliberately.
// Nothing outside this crate needs to name a span it does not open, and a
// `pub` const whose only out-of-crate reader is a test is exactly what the
// pub-item ratchet is there to refuse. `span_registry`'s own tests bind
// them to the published registry entries from inside the crate.

/// Span name for the inbound phase of one request.
///
/// Pairs with [`intake_accept_span`].
pub(crate) const SPAN_INTAKE_ACCEPT: &str = "sbproxy.intake.accept";

/// Span name for one authentication check against the origin's provider.
///
/// Pairs with [`intake_authenticate_span`].
pub(crate) const SPAN_INTAKE_AUTHENTICATE: &str = "sbproxy.intake.authenticate";

/// Span name for one policy evaluation in an origin's enforcer chain.
///
/// Pairs with [`policy_enforce_span`].
pub(crate) const SPAN_POLICY_ENFORCE: &str = "sbproxy.policy.enforce";

/// Span name for one response-body transform.
///
/// Pairs with [`transform_shape_span`].
pub(crate) const SPAN_TRANSFORM_SHAPE: &str = "sbproxy.transform.shape";

/// Build the span covering the inbound phase of one request.
///
/// Opened around the whole request filter, so origin resolution,
/// authentication, the policy chain, the response-cache probe, and
/// non-proxy action dispatch all run inside it and any span they open
/// nests under it. It closes when the filter returns, which is before the
/// upstream is dialed, so its duration is the proxy's own admission cost
/// and not the origin's latency.
///
/// `method` is the HTTP method, under the OpenTelemetry
/// `http.request.method` convention. It is the only field, and that is
/// deliberate. The request target is caller-controlled and routinely
/// carries credentials in a query string; the resolved hostname, tenant,
/// and route are not known yet at the point the span opens; and the
/// access log already carries all four against the same request id.
pub fn intake_accept_span(method: &str) -> tracing::Span {
    tracing::info_span!(
        "sbproxy.span",
        otel.name = SPAN_INTAKE_ACCEPT,
        pillar = Pillar::Intake.as_str(),
        verb = "accept",
        "http.request.method" = method,
    )
}

/// Build the span covering one authentication check.
///
/// One span per request that reaches the origin's configured auth
/// provider, which is what makes a slow forward-auth subrequest visible as
/// its own bar under the intake span instead of disappearing into it.
///
/// `auth_type` is the provider's type name (`basic`, `jwt`, `forward_auth`,
/// ...), the same bounded label `record_auth` already partitions on.
/// Nothing about the outcome rides the span: no subject, no resolved user,
/// no token, no header. A credential on a span is a credential in the
/// trace backend, and the allow/deny split is already on the auth metric
/// and in the audit record.
pub fn intake_authenticate_span(auth_type: &str) -> tracing::Span {
    tracing::info_span!(
        "sbproxy.span",
        otel.name = SPAN_INTAKE_AUTHENTICATE,
        pillar = Pillar::Intake.as_str(),
        verb = "authenticate",
        "sbproxy.auth_type" = auth_type,
    )
}

/// Build the span covering one policy evaluation.
///
/// One span per enforcer, not one per chain, so a trace answers which
/// policy spent the time rather than only that the chain did. The
/// enforcers run in order inside the intake span, so they render as
/// siblings in the order they were configured.
///
/// `policy_type` is the enforcer's own stable label (`rate_limit`, `waf`,
/// `ip_filter`, ...), borrowed from the compiled enforcer and already a
/// metric label, so the field costs nothing to produce and tells a trace
/// reader nothing the metrics do not.
pub fn policy_enforce_span(policy_type: &str) -> tracing::Span {
    tracing::info_span!(
        "sbproxy.span",
        otel.name = SPAN_POLICY_ENFORCE,
        pillar = Pillar::Policy.as_str(),
        verb = "enforce",
        policy = policy_type,
    )
}

/// Build the span covering one response-body transform.
///
/// Opened per transform in the origin's chain, on the buffered body at
/// end of stream. Transform work is the one part of the response path that
/// is the proxy's own CPU rather than the upstream's latency, so a chain
/// that is quietly costing 30ms of HTML-to-Markdown conversion is worth
/// separating from a slow origin.
///
/// `transform_type` is the configured transform's type name (`json`,
/// `html_to_markdown`, `wasm`, ...), borrowed from the compiled transform.
/// The body never touches a span attribute.
pub fn transform_shape_span(transform_type: &str) -> tracing::Span {
    tracing::info_span!(
        "sbproxy.span",
        otel.name = SPAN_TRANSFORM_SHAPE,
        pillar = Pillar::Transform.as_str(),
        verb = "shape",
        transform = transform_type,
    )
}

// --- WOR-2100: payment settlement correlation ---

/// Domain separator for the access log's settlement correlation digest.
///
/// Separated so this digest cannot be confused with, or replayed against,
/// any of the settlement crate's own digests over the same input.
const RECEIPT_CORRELATION_DOMAIN: &[u8] = b"sbproxy-access-log-receipt-correlation-v1";

/// Build the span covering one settlement rail interaction.
///
/// The name is `sbproxy.rail.<verb>`, where `verb` is the settlement or
/// recovery operation. The rail and the operation are the whole story that
/// belongs on a span: a payer identifier, a credential, a client secret, a
/// provider object identifier, or a provider body would all be readable by
/// anyone with trace access, and none of them is needed to find a slow
/// facilitator.
///
/// `verb` is `&'static str` so a caller cannot format a value into it.
pub fn settlement_span(verb: &'static str) -> tracing::Span {
    tracing_helper::span(Pillar::Rail, verb)
}

/// Derive the one-way correlation digest the access log carries for a
/// settled payment.
///
/// `receipt_key` is the durable receipt's own key. The digest is what goes
/// on the log line, and the mapping is deliberately one way: two lines for
/// the same settled payment share a value an operator can group by, and the
/// value on its own tells an attacker with log access nothing about the
/// intent, the provider object, or the payer.
///
/// Returns lowercase hex of the full 32 bytes. Truncating would make
/// collisions plausible at a volume this proxy reaches, and a collision
/// here means two different payments joining into one row.
///
/// # Examples
///
/// ```
/// use sbproxy_observe::telemetry::receipt_correlation_digest;
///
/// let digest = receipt_correlation_digest("sbpr_example");
/// assert_eq!(digest.len(), 64);
/// // Stable for the same receipt, and unrelated to its input's bytes.
/// assert_eq!(digest, receipt_correlation_digest("sbpr_example"));
/// assert_ne!(digest, receipt_correlation_digest("sbpr_other"));
/// assert!(!digest.contains("sbpr_example"));
/// ```
pub fn receipt_correlation_digest(receipt_key: &str) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(RECEIPT_CORRELATION_DOMAIN);
    hasher.update([0u8]);
    hasher.update(receipt_key.as_bytes());
    hex::encode(hasher.finalize())
}

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
        assert_eq!(Pillar::Notify.as_str(), "notify");
    }

    #[test]
    fn there_really_are_eight_pillars() {
        // The doc comment on `Pillar` said eight while the enum had seven,
        // and the missing one was already a filter value in the traces
        // dashboard. `ALL` is what the span drift guard compares against
        // the dashboard, so it has to stay complete.
        assert_eq!(Pillar::ALL.len(), 8);

        let mut slugs: Vec<&str> = Pillar::ALL.iter().map(|p| p.as_str()).collect();
        let listed = slugs.len();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(listed, slugs.len(), "a pillar slug is listed twice");
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

    #[test]
    fn request_path_span_names_are_spelled_from_their_pillar_and_verb() {
        // The request-path constructors hard-code their names so the hot
        // path does not format one per request, which trades a `format!`
        // for a literal that can drift from the pillar and verb it is
        // meant to spell. This is the check that pays for that trade: the
        // literal has to be exactly what the canonical builder would
        // produce from the same two parts.
        for (name, pillar, verb) in [
            (SPAN_INTAKE_ACCEPT, Pillar::Intake, "accept"),
            (SPAN_INTAKE_AUTHENTICATE, Pillar::Intake, "authenticate"),
            (SPAN_POLICY_ENFORCE, Pillar::Policy, "enforce"),
            (SPAN_TRANSFORM_SHAPE, Pillar::Transform, "shape"),
        ] {
            assert_eq!(
                name,
                tracing_helper::span_name(pillar, verb),
                "{name} does not spell sbproxy.{}.{verb}",
                pillar.as_str()
            );
        }
    }

    #[test]
    fn request_path_spans_carry_their_name_and_no_credential_shaped_field() {
        // Constructing each one proves the field sets typecheck and that
        // no constructor panics, and pins the one property no reviewer
        // should have to re-derive: what the auth span is allowed to hold.
        // `auth_type` is a bounded provider label. A subject, a token, or
        // an authorization header value on this span would be a
        // credential sitting in whatever backend the traces go to.
        //
        // Under a subscriber, and with the interest cache rebuilt, for the
        // reason the traceparent test below spells out: with no subscriber
        // installed the callsite's Interest caches as Never, the macro hands
        // back `Span::none()`, and `metadata()` is `None` rather than the
        // name this asserts. That made the test pass under `--workspace`,
        // where some earlier test in the binary had already installed one,
        // and fail under `cargo test -p sbproxy-observe`, which CLAUDE.md
        // recommends as the fast inner loop. Installing one here makes the
        // assertion mean the same thing under either selection.
        let subscriber = tracing_subscriber::registry();
        let (accept, authenticate, enforce, shape) =
            tracing::subscriber::with_default(subscriber, || {
                tracing::callsite::rebuild_interest_cache();
                (
                    intake_accept_span("GET"),
                    intake_authenticate_span("forward_auth"),
                    policy_enforce_span("rate_limit"),
                    transform_shape_span("html_to_markdown"),
                )
            });

        for span in [&accept, &authenticate, &enforce, &shape] {
            assert_eq!(
                span.metadata().map(|meta| meta.name()),
                Some("sbproxy.span"),
                "every pillar span is created under the shared metadata name"
            );
        }

        let auth_fields: Vec<&str> = authenticate
            .metadata()
            .expect("the auth span has metadata")
            .fields()
            .iter()
            .map(|field| field.name())
            .collect();
        assert!(
            auth_fields.contains(&"sbproxy.auth_type"),
            "the auth span must say which provider ran: {auth_fields:?}"
        );
        for forbidden in ["sub", "subject", "user", "authorization", "token", "secret"] {
            assert!(
                !auth_fields.contains(&forbidden),
                "'{forbidden}' must never be an attribute of the auth span: {auth_fields:?}"
            );
        }
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

    // --- WOR-2139: carrier-agnostic propagation pairs ---

    /// Run `body` with a real `tracing-opentelemetry` layer installed
    /// and one entered span, which is the only shape in which the
    /// per-span OTel context exists at all. `remote_parent` seeds that
    /// span's parent so the propagated trace id is a known value
    /// instead of a fresh random root. Mirrors the setup in
    /// `propagator_round_trip_preserves_traceparent`, including the
    /// interest-cache rebuild that keeps a callsite cached as `Never`
    /// by an earlier subscriber-less test from silently skipping this
    /// subscriber.
    fn with_active_span<T>(
        remote_parent: Option<&crate::trace_ctx::w3c::TraceContext>,
        body: impl FnOnce() -> T,
    ) -> T {
        use tracing_subscriber::layer::SubscriberExt;

        init_propagator();
        let provider = sdktrace::TracerProvider::builder().build();
        let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, "test");
        let subscriber =
            tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(tracer));

        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let span = tracing::info_span!("wor2139_propagation");
            parent_span_on_remote_trace_context(&span, remote_parent, remote_parent.is_some());
            let _guard = span.enter();
            body()
        })
    }

    /// The refactor's whole point: the header path is now a thin
    /// rendering of the pairs, so the two can never disagree about
    /// which context, which keys, or which values get propagated.
    #[test]
    fn propagation_pairs_match_the_header_injection_path() {
        with_active_span(None, || {
            let pairs = propagation_pairs();
            assert!(
                !pairs.is_empty(),
                "an active span must propagate at least traceparent"
            );

            let mut headers = http::HeaderMap::new();
            inject_into_headers(&mut headers);

            assert_eq!(
                headers.len(),
                pairs.len(),
                "header path emitted a different number of keys than the pairs: \
                 {headers:?} vs {pairs:?}"
            );
            for (key, value) in &pairs {
                assert_eq!(
                    headers.get(key.as_str()).and_then(|v| v.to_str().ok()),
                    Some(value.as_str()),
                    "header {key} disagrees with the pair the JSON carrier would use"
                );
            }
        });
    }

    /// The value a non-header carrier writes has to be a real W3C
    /// traceparent, and it has to name the trace that is actually
    /// active rather than a fresh root, or the correlation it exists
    /// for does not happen.
    #[test]
    fn propagation_pairs_carry_a_wellformed_traceparent_for_the_active_trace() {
        let known = crate::trace_ctx::w3c::TraceContext::parse(
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        )
        .expect("fixture traceparent parses");

        with_active_span(Some(&known), || {
            let pairs = propagation_pairs();
            let traceparent = pairs
                .iter()
                .find(|(key, _)| key == "traceparent")
                .map(|(_, value)| value.as_str())
                .expect("an active span must propagate traceparent");

            // W3C shape: version "-" 32-hex trace-id "-" 16-hex
            // parent-id "-" 2-hex flags.
            let fields: Vec<&str> = traceparent.split('-').collect();
            assert_eq!(
                fields.len(),
                4,
                "traceparent must have four fields: {traceparent}"
            );
            assert_eq!(fields[0], "00", "unexpected version: {traceparent}");
            assert_eq!(fields[1].len(), 32, "trace id width: {traceparent}");
            assert_eq!(fields[2].len(), 16, "span id width: {traceparent}");
            assert_eq!(fields[3].len(), 2, "flags width: {traceparent}");
            assert!(
                traceparent
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b'-'),
                "traceparent must be hex and dashes only: {traceparent}"
            );
            assert_eq!(
                fields[1], "0af7651916cd43dd8448eb211c80319c",
                "traceparent must name the active trace, not a fresh root: {traceparent}"
            );
        });
    }

    /// No trace, no carrier. A caller reading these pairs decides
    /// whether to attach anything at all from the emptiness, so an
    /// empty-but-present pair would turn "this request was not traced"
    /// into "this request carries a broken trace".
    #[test]
    fn propagation_pairs_are_empty_with_no_active_trace_context() {
        init_propagator();
        assert!(
            propagation_pairs().is_empty(),
            "with no active context there is nothing to propagate"
        );
    }

    // --- WOR-2318: the outbound helper-client injector ---

    /// A well-formed inbound `traceparent`, from the W3C Trace Context
    /// specification's own example.
    const FIXTURE_TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    fn fixture_context() -> crate::trace_ctx::w3c::TraceContext {
        crate::trace_ctx::w3c::TraceContext::parse(FIXTURE_TRACEPARENT)
            .expect("the fixture traceparent parses")
    }

    /// The header a helper call carries has to name the request's trace
    /// and a new span, in that order. Same trace id means a backend can
    /// hang the helper call under the request that caused it; a new span
    /// id means it renders as its own hop rather than overwriting the
    /// one the upstream request already claimed.
    #[test]
    fn outbound_trace_headers_build_a_child_of_the_request_context() {
        let parent = fixture_context();
        let headers = outbound_trace_headers(Some(&parent));

        assert_eq!(
            headers.len(),
            1,
            "no tracestate on the fixture: {headers:?}"
        );
        assert_eq!(headers[0].0, "traceparent");

        let emitted = crate::trace_ctx::w3c::TraceContext::parse(&headers[0].1)
            .expect("the emitted header must round-trip through the same parser");
        assert_eq!(
            emitted.trace_id, parent.trace_id,
            "a helper call joins the request's trace, it does not start one"
        );
        assert_ne!(
            emitted.parent_id, parent.parent_id,
            "the helper call is its own hop and needs its own span id"
        );
        assert_eq!(
            emitted.trace_flags, parent.trace_flags,
            "the sampling decision is the caller's to make, not this function's"
        );
    }

    /// `tracestate` is carried only because the workspace already
    /// represents it: `TraceContext` has the field, the proxied upstream
    /// path forwards it, and the downstream response echoes it. A trace
    /// with no vendor state must not grow one here.
    #[test]
    fn outbound_trace_headers_carry_tracestate_only_when_the_trace_has_it() {
        let mut parent = fixture_context();
        parent.tracestate = Some("vendor=abc".to_string());

        let headers = outbound_trace_headers(Some(&parent));
        assert_eq!(headers.len(), 2, "{headers:?}");
        assert_eq!(headers[1], ("tracestate", "vendor=abc".to_string()));

        let bare = fixture_context();
        assert!(
            outbound_trace_headers(Some(&bare))
                .iter()
                .all(|(name, _)| *name != "tracestate"),
            "a trace with no vendor state must not acquire one on the way out"
        );
    }

    /// The property the whole design turns on. With no request context
    /// and no ambient span there is nothing true to say, so this says
    /// nothing. A fabricated root here would put one orphan single-span
    /// trace in the backend per outbound call, and an operator cannot
    /// tell those from real ones.
    #[test]
    fn outbound_trace_headers_are_empty_rather_than_fabricated() {
        init_propagator();
        assert!(
            outbound_trace_headers(None).is_empty(),
            "no context anywhere must mean no header, never an invented trace"
        );
    }

    /// The `None` arm is not a dead branch: it is the path every caller
    /// takes that sits inside an instrumented span but has no
    /// `RequestContext` reachable (the forward-auth subrequest, the
    /// bot-auth directory fetch, the ledger redeem).
    #[test]
    fn outbound_trace_headers_fall_back_to_the_ambient_span() {
        let known = fixture_context();
        with_active_span(Some(&known), || {
            let headers = outbound_trace_headers(None);
            let traceparent = headers
                .iter()
                .find(|(name, _)| *name == "traceparent")
                .map(|(_, value)| value.clone())
                .expect("an active span must produce a traceparent");
            assert!(
                traceparent.contains("4bf92f3577b34da6a3ce929d0e0e4736"),
                "the ambient fallback must name the active trace, not a fresh \
                 root: {traceparent}"
            );
        });
    }

    // WOR-2481: `egress.telemetry:` boot-time authorization.
    //
    // `authorize_telemetry_endpoint_or_refuse_boot` calls
    // `std::process::exit(1)` on denial, which cannot run inside this
    // test process, so these tests exercise `check_telemetry_egress`,
    // the pure decision-plus-stamp half it wraps.

    fn enforce_telemetry(
        hosts: &[&str],
        allow_private: bool,
    ) -> sbproxy_security::egress::EgressAuthorizer {
        use sbproxy_security::egress::{
            EgressAuthorizer, EgressConfig, EgressPurpose, PurposeAllowlist,
        };
        use std::collections::{HashMap, HashSet};
        let allow = PurposeAllowlist {
            hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
            schemes: HashSet::from(["https".to_string(), "http".to_string()]),
            ports: HashSet::from([443, 80]),
            allow_private,
        };
        EgressAuthorizer::new(EgressConfig {
            purposes: HashMap::from([(EgressPurpose::Telemetry, allow)]),
        })
    }

    #[test]
    fn denied_telemetry_endpoint_is_stamped_and_would_refuse_boot() {
        use sbproxy_security::egress::{
            egress_inventory_snapshot, install_configured_gate, EgressDenied, EgressPurpose,
        };

        install_configured_gate(
            EgressPurpose::Telemetry,
            Some(enforce_telemetry(&["otel-collector.example.com"], false)),
        );

        let outcome = check_telemetry_egress(
            "http://attacker-collector.invalid:4317",
            "traces-wor2481-denied",
        );
        assert_eq!(
            outcome,
            TelemetryEgressOutcome::Denied(EgressDenied::UnlistedHost)
        );

        let sighting = egress_inventory_snapshot()
            .into_iter()
            .find(|s| s.host == "attacker-collector.invalid")
            .expect("the denied endpoint must be stamped in the inventory");
        assert_eq!(sighting.status, "denied");
        assert_eq!(sighting.origin, "telemetry.traces-wor2481-denied");

        install_configured_gate(EgressPurpose::Telemetry, None);
    }

    #[test]
    fn omitted_egress_telemetry_stamps_ungated_and_proceeds() {
        use sbproxy_security::egress::{
            egress_inventory_snapshot, install_configured_gate, EgressPurpose,
        };

        // No `egress.telemetry:` sub-block configured: nothing installed.
        install_configured_gate(EgressPurpose::Telemetry, None);

        let outcome =
            check_telemetry_egress("http://collector.internal:4317", "traces-wor2481-omitted");
        assert_eq!(outcome, TelemetryEgressOutcome::Proceed);

        let sighting = egress_inventory_snapshot()
            .into_iter()
            .find(|s| s.host == "collector.internal")
            .expect("an ungated endpoint must still be stamped in the inventory");
        assert_eq!(sighting.status, "ungated");
    }

    #[test]
    fn allowed_telemetry_endpoint_proceeds_and_is_stamped_allowed() {
        use sbproxy_security::egress::{
            egress_inventory_snapshot, install_configured_gate, EgressPurpose,
        };

        // 127.0.0.1 resolves with no network I/O (an IP literal needs no
        // DNS lookup), so this stays hermetic. A collector reachable only
        // on loopback is also the realistic shape for a sidecar OTLP
        // agent, which is why `allow_private` exists at all.
        install_configured_gate(
            EgressPurpose::Telemetry,
            Some(enforce_telemetry(&["127.0.0.1"], true)),
        );

        let outcome = check_telemetry_egress("https://127.0.0.1", "metrics-wor2481-allowed");
        assert_eq!(outcome, TelemetryEgressOutcome::Proceed);

        let sighting = egress_inventory_snapshot()
            .into_iter()
            .find(|s| s.host == "127.0.0.1" && s.origin == "telemetry.metrics-wor2481-allowed")
            .expect("the allowed endpoint must be stamped in the inventory");
        assert_eq!(sighting.status, "allowed");

        install_configured_gate(EgressPurpose::Telemetry, None);
    }

    /// A denied telemetry endpoint used to stop at the sightings
    /// inventory. `record_egress_refused` is the same funnel every other
    /// egress purpose (AI provider, usage sink, token exchange, ...)
    /// already goes through for its Prometheus counter and its bridge to
    /// the `egress_refused` typed event; a telemetry denial has to reach
    /// it too, or that counter and event feed silently under-report the
    /// one purpose whose exporters run unattended.
    #[test]
    fn denied_telemetry_endpoint_also_records_egress_refused() {
        use sbproxy_security::egress::{
            install_configured_gate, install_egress_refused_hook, EgressDenied, EgressPurpose,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        static CALLS: AtomicUsize = AtomicUsize::new(0);
        static SEEN: std::sync::Mutex<Vec<(&'static str, &'static str, String, String)>> =
            std::sync::Mutex::new(Vec::new());

        fn hook(purpose: EgressPurpose, reason: EgressDenied, tenant: &str, origin: &str) {
            CALLS.fetch_add(1, Ordering::SeqCst);
            SEEN.lock().expect("test lock").push((
                purpose.as_label(),
                reason.as_label(),
                tenant.to_owned(),
                origin.to_owned(),
            ));
        }
        let _ = install_egress_refused_hook(hook);

        install_configured_gate(
            EgressPurpose::Telemetry,
            Some(enforce_telemetry(&["otel-collector.example.com"], false)),
        );

        let outcome = check_telemetry_egress(
            "http://attacker-collector.invalid:4317",
            "traces-wor2481-refused-bridge",
        );
        assert_eq!(
            outcome,
            TelemetryEgressOutcome::Denied(EgressDenied::UnlistedHost)
        );

        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "a denied telemetry endpoint must reach record_egress_refused"
        );
        let seen = SEEN.lock().expect("test lock");
        assert_eq!(
            seen.last(),
            Some(&(
                "telemetry",
                "unlisted_host",
                "unset".to_string(),
                "telemetry.traces-wor2481-refused-bridge".to_string()
            ))
        );

        install_configured_gate(EgressPurpose::Telemetry, None);
    }

    /// `authorize_telemetry_endpoint_or_refuse_boot` calls
    /// `std::process::exit(1)` on denial, so only the allow path is
    /// reachable from this test process; that is exactly the path that
    /// has to record the endpoint for later reload re-verification.
    #[test]
    fn authorize_telemetry_endpoint_or_refuse_boot_records_the_active_boot_endpoint_when_allowed() {
        use sbproxy_security::egress::{install_configured_gate, EgressPurpose};

        let signal = "wor2481-record-active-traces";
        let endpoint = "https://127.0.0.1:4317";
        install_configured_gate(
            EgressPurpose::Telemetry,
            Some(enforce_telemetry(&["127.0.0.1"], true)),
        );

        authorize_telemetry_endpoint_or_refuse_boot(endpoint, signal);

        let recorded = active_boot_telemetry_endpoints()
            .lock()
            .expect("test lock")
            .get(signal)
            .cloned();
        assert_eq!(
            recorded,
            Some(endpoint.to_string()),
            "an allowed boot-only endpoint must be recorded for later reload re-verification"
        );

        install_configured_gate(EgressPurpose::Telemetry, None);
    }

    // WOR-2481: reload re-verification of the boot-only trace and metric
    // exporters. The exporters themselves are never rebuilt on reload
    // (see `reverify_active_boot_telemetry_endpoints`'s doc comment), so
    // these tests seed the active-endpoint registry directly with
    // `record_active_boot_telemetry_endpoint`, the same call
    // `authorize_telemetry_endpoint_or_refuse_boot` makes on its allow
    // path, rather than building a real exporter.

    #[test]
    fn reverify_active_boot_telemetry_endpoints_proceeds_when_the_new_generation_still_allows() {
        let signal = "wor2481-reverify-still-allowed";
        let endpoint = "https://otel-collector.example.com:4317";
        record_active_boot_telemetry_endpoint(signal, endpoint);

        let authorizer = enforce_telemetry(&["otel-collector.example.com"], false);
        reverify_active_boot_telemetry_endpoints(Some(&authorizer))
            .expect("an endpoint the new generation still allows must not refuse the reload");
    }

    #[test]
    fn reverify_active_boot_telemetry_endpoints_refuses_when_the_new_generation_denies() {
        let signal = "wor2481-reverify-now-denied";
        let endpoint = "https://otel-collector.example.com:4317";
        record_active_boot_telemetry_endpoint(signal, endpoint);

        // The new generation's `egress.telemetry:` allowlist no longer
        // names this host: a config change that revokes an endpoint the
        // running, never-rebuilt exporter is still dialing.
        let authorizer = enforce_telemetry(&["a-different-collector.example.com"], false);
        let error = reverify_active_boot_telemetry_endpoints(Some(&authorizer))
            .expect_err("an endpoint the new generation denies must refuse the reload");
        let message = error.to_string();
        assert!(
            message.contains(signal) && message.contains(endpoint),
            "the refusal must name the signal and endpoint so an operator can act on it: \
             {message}"
        );
    }
}
