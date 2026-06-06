//! sbproxy-observe: Observability - logging, metrics, and events.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod access_log;
/// Per-agent metric label bundle.
pub mod agent_labels;
pub mod alerting;
pub mod audit;
/// P0 edge capture helpers: custom properties, session IDs,
/// and user IDs.
pub mod capture;
pub mod cardinality;
/// Clock-skew monitor: SNTP poller + `/readyz` probe.
pub mod clock_skew;
/// Typed proxy events and the in-process subscriber bus.
pub mod events;
/// OpenMetrics exemplar side-store used to wire trace IDs
/// onto the request-duration and ledger histograms.
pub mod exemplars;
pub mod export;
/// Test-only in-memory capture for the redaction fan-out e2e
/// suite. Disabled by default; opted into via the
/// `SBPROXY_TEST_FAKE_SINKS=1` environment variable.
pub mod fake_sinks;
pub mod golden_signals;
/// `/healthz` and `/readyz` registry, probes, and HTTP handlers.
pub mod health;
/// Global tracing subscriber configuration (log level and format).
pub mod logging;
/// Prometheus metrics registry, helpers, and per-origin recorders.
pub mod metrics;
/// Outbound webhook framework. Per-tenant signing (Ed25519
/// default, HMAC-SHA256 fallback) with dual-key rotation, exponential
/// backoff retries, and a deadletter queue.
pub mod notify;
pub mod otel;
/// WOR-1046 OTLP-logs sink output. Wraps `opentelemetry_otlp::LogExporter`
/// behind the [`sink_dispatcher::SinkOutput`] trait so the dispatcher
/// can forward records to an OTLP collector.
pub mod otlp_logs;
pub mod redact;
/// P0 `RequestEvent` envelope shared by the four streams.
pub mod request_event;
/// Generic transport adapter: a global sink for
/// completed `RequestEvent` values. Default no-op; enterprise
/// registers a NATS-backed implementation.
pub mod request_sink;
/// WOR-1186 session ledger: per-tool-call run records emitted from the
/// live MCP traffic path, conforming to the canonical mcptest
/// `session-ledger-v1` schema.
pub mod session_ledger;
/// WOR-1045 PR2 sink dispatcher. Replaces the single tracing
/// subscriber with a multi-writer fan-out filtered by proxy / tenant /
/// origin scope.
pub mod sink_dispatcher;
/// In-process synthetic probe state for `/readyz`.
pub mod synthetic;
pub mod telemetry;
pub mod topology;
pub mod trace_ctx;

pub use access_log::AccessLogEntry;
pub use agent_labels::AgentLabels;
pub use alerting::{Alert, AlertChannelConfig, AlertDispatcher};
pub use audit::{ConfigAuditEntry, SecurityAuditEntry};
pub use capture::{
    capture_parent_session_id, capture_properties, capture_session_id, capture_user_id,
    AutoGenerate, BudgetConfig, PropertiesConfig, PropertyDropCounts, RedactConfig,
    SessionDropCounts, SessionsConfig, UserConfig, UserDropCounts,
};
pub use cardinality::{CardinalityConfig, CardinalityLimiter};
pub use clock_skew::{
    sntp_query, ClockSkewConfig, ClockSkewMonitor, ProbeError as ClockSkewProbeError,
    DEFAULT_NTP_SOURCE, DEFAULT_POLL_INTERVAL_SECS, SNTP_TIMEOUT, TOLERANCE_SECS,
};
pub use events::{EventBus, EventType, PolicySurface, PolicyVerdictEvent, ProxyEvent, VerdictTag};
pub use export::{WebhookConfig, WebhookExporter};
pub use health::{
    default_registry, default_registry_optional, handle_health, handle_healthz, handle_livez,
    handle_readyz, ComponentReport, ComponentStatus, HealthMetadata, HealthRegistry, HealthReport,
    NotConfiguredProbe, Probe, ReadinessReport, Recency, RecencyProbe, SyntheticProbe,
};
pub use logging::{
    apply_redaction, apply_redaction_for, emit as emit_structured,
    should_sample as should_sample_log, EventType as LogEventType, LogLevel, LoggingConfig,
    SamplingConfig, Sink, StructuredLog, SCHEMA_VERSION,
};
pub use metrics::{metrics, sanitize_label, ProxyMetrics};
pub use notify::{
    event_type_matches, verify_signature, DeadletterItem, InMemoryStore, Notifier, NotifierStore,
    OutboundEvent, SigningKey, Subscription, VerificationKey, VerifyError,
};
pub use otlp_logs::{OtlpLogSink, OtlpLogSinkOptions};
pub use request_event::{RequestEvent, UserIdSource};
pub use request_sink::{
    dispatch_request_event, set_request_event_sink, LoggingSink, NoopSink, RequestEventSink,
};
pub use session_ledger::{
    emit_tool_call, is_enabled as session_ledger_enabled, set_session_ledger_sink, Caller,
    FileLedgerSink, LedgerHeader, LedgerRecord, LedgerToolCall, LoggingLedgerSink,
    SessionLedgerSink, ToolCallObservation,
};
pub use sink_dispatcher::{
    current_sink_dispatcher, install_sink_dispatcher, CompiledSink, Profile, SinkDispatcher,
    SinkFormat, SinkOutput, SinkScope,
};
pub use synthetic::{
    SyntheticProbeRegistration, SyntheticProbeState, DEFAULT_SYNTHETIC_HOSTNAME,
    DEFAULT_SYNTHETIC_INTERVAL_SECS, DEFAULT_SYNTHETIC_PATH, DEFAULT_SYNTHETIC_TIMEOUT_MS,
};
pub use telemetry::{
    extract_from_headers, init_otlp_metrics_pipeline, init_otlp_pipeline, init_propagator,
    inject_into_headers, inject_into_reqwest, shutdown_otlp_metrics_pipeline,
    shutdown_otlp_pipeline, span as pillar_span, tracing_helper, OtlpTransport, Pillar,
    TelemetryConfig,
};
pub use topology::{Edge, EdgeStats, TopologyTracker};
pub use trace_ctx::w3c::TraceContext;
