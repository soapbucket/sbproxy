//! sbproxy-observe: Observability - logging, metrics, and events.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod access_log;
/// Per-agent metric label bundle.
pub mod agent_labels;
pub mod alerting;
pub mod audit;
pub mod audit_chain;
pub mod audit_ring;
/// P0 edge capture helpers: custom properties, session IDs,
/// and user IDs.
pub mod capture;
pub mod cardinality;
/// Clock-skew monitor: SNTP poller + `/readyz` probe.
pub mod clock_skew;
/// The decision-event vocabulary: which pipeline points decide, which
/// engine answered, what came out, and the one metric family plus
/// OCSF-shaped audit record they all share instead of hand-rolling
/// their own (WOR-2365, WOR-2370).
pub mod decision;
pub mod decision_contract;
/// Bridge from `sbproxy_security::egress::record_egress_refused` to the
/// typed `EgressRefused` proxy event (WOR-2486).
pub mod egress_bridge;
pub mod event_ingest;
/// Egress for the typed proxy events: the `events:` block's bounded
/// queue, background worker, and file / webhook sinks. Delivery never
/// runs on the publisher's thread, which is the difference between this
/// and [`events::EventBus`].
pub mod event_sink;
/// Typed proxy events and the in-process subscriber bus.
pub mod events;
/// Per-tenant gapless sequence numbers for `mcp_governance_decision` and
/// future evidence records (WOR-2384).
pub mod evidence_seq;
/// OpenMetrics exemplar side-store used to wire trace IDs
/// onto the request-duration and ledger histograms.
pub mod exemplars;
/// Test-only in-memory capture for the redaction fan-out e2e
/// suite. Disabled by default; opted into via the
/// `SBPROXY_TEST_FAKE_SINKS=1` environment variable.
pub mod fake_sinks;
pub mod golden_signals;
/// `/healthz` and `/readyz` registry, probes, and HTTP handlers.
pub mod health;
/// The identifier of this proxy process, carried by every record whose
/// meaning depends on knowing which replica emitted it.
pub mod instance;
/// Global tracing subscriber configuration (log level and format).
pub mod logging;
/// The `sbproxy_meter_*` families: what the attested meter reports about
/// its own health, on both the OTLP push path and the Prometheus scrape.
/// None of it is the billing record; the signed chain is.
pub mod meter_metrics;
/// The executable metric registry: every family, its writer, and its stability.
pub mod metric_registry;
/// Prometheus metrics registry, helpers, and per-origin recorders.
pub mod metrics;
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
/// The executable span registry: every span name, what opens it, and its
/// stability. The traces counterpart of [`metric_registry`].
pub mod span_registry;
/// In-process synthetic probe state for `/readyz`.
pub mod synthetic;
pub mod telemetry;
pub mod trace_ctx;
/// WOR-1875 durable windowed usage rollups: hour/day spend buckets in
/// redb feeding the windowed `/api/usage/spend` admin API, so spend
/// history survives restarts without an external Prometheus.
pub mod usage_rollup;

pub use access_log::AccessLogEntry;
pub use agent_labels::AgentLabels;
pub use alerting::{Alert, AlertChannelConfig, AlertDispatcher};
pub use audit::{AdminActionAuditEntry, ConfigAuditEntry, KeyAuditEntry, SecurityAuditEntry};
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
pub use event_sink::{
    arm_webhook_ssrf_allowlist, install_event_egress, publish_proxy_event,
    publish_proxy_event_checked, wants_event, EventEgress, EventPublishError, EventSinkTarget,
    EventTypeMask, DEFAULT_QUEUE_CAPACITY as DEFAULT_EVENT_QUEUE_CAPACITY,
};
pub use events::{
    EventBus, EventType, PolicySurface, PolicyVerdictEvent, ProxyEvent, VerdictTag, ALL_EVENT_TYPES,
};
pub use health::{
    default_registry, default_registry_optional, handle_health, handle_healthz, handle_livez,
    handle_readyz, mark_process_start, ComponentReport, ComponentStatus, HealthMetadata,
    HealthRegistry, HealthReport, NotConfiguredProbe, Probe, ReadinessReport, Recency,
    RecencyProbe, SyntheticProbe,
};
pub use logging::{
    apply_redaction, apply_redaction_for, current_log_filter, emit as emit_structured,
    pin_log_filter_override, set_log_filter, set_log_filter_from_config,
    should_sample as should_sample_log, EventType as LogEventType, LogLevel, LoggingConfig,
    SamplingConfig, Sink, StructuredLog, SCHEMA_VERSION,
};
pub use metrics::{metrics, sanitize_label, ProxyMetrics};
pub use otlp_logs::{OtlpLogSink, OtlpLogSinkOptions};
pub use request_event::{RequestEvent, UserIdSource};
pub use request_sink::{
    dispatch_request_event, set_request_event_sink, FileEventSink, LoggingSink, NoopSink,
    RequestEventSink,
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
    SYNTHETIC_NO_OUTCOME_DETAIL, SYNTHETIC_STALE_DETAIL_PREFIX,
};
pub use telemetry::{
    extract_from_headers, init_otlp_metrics_pipeline, init_propagator, inject_into_headers,
    inject_into_reqwest, inject_reqwest_trace_context, outbound_trace_headers,
    parent_span_on_remote_trace_context, shutdown_otlp_metrics_pipeline, shutdown_otlp_pipeline,
    span as pillar_span, tracing_helper, OtlpTransport, Pillar, TelemetryConfig,
};
pub use trace_ctx::w3c::TraceContext;
