//! sbproxy-observe: Observability - logging, metrics, and events.

#![warn(missing_docs)]

pub mod access_log;
/// Wave 1 / G1.6 per-agent metric label bundle.
pub mod agent_labels;
pub mod alerting;
pub mod audit;
/// Wave 8 P0 edge capture helpers: custom properties, session IDs,
/// user IDs (per `docs/adr-custom-properties.md`,
/// `docs/adr-session-id.md`, `docs/adr-user-id.md`).
pub mod capture;
pub mod cardinality;
/// Wave 3 / R3.3 clock-skew monitor: SNTP poller + `/readyz` probe
/// per `docs/adr-time-sync-requirements.md` (A3.5).
pub mod clock_skew;
/// Typed proxy events and the in-process subscriber bus.
pub mod events;
/// OpenMetrics exemplar side-store used by R1.1 to wire trace IDs
/// onto the histograms named in `docs/adr-observability.md`.
pub mod exemplars;
pub mod export;
pub mod golden_signals;
/// `/healthz` and `/readyz` registry, probes, and HTTP handlers (R1.3).
pub mod health;
/// Global tracing subscriber configuration (log level and format).
pub mod logging;
/// Prometheus metrics registry, helpers, and per-origin recorders.
pub mod metrics;
/// R1.4 outbound webhook framework. Per-tenant signing (Ed25519
/// default, HMAC-SHA256 fallback) with dual-key rotation, exponential
/// backoff retries, and a deadletter queue. See
/// `docs/adr-webhook-security.md`.
pub mod notify;
pub mod redact;
/// Wave 8 P0 `RequestEvent` envelope shared by the four streams
/// (per `docs/adr-event-envelope.md`).
pub mod request_event;
/// Wave 8 / T4.6 generic transport adapter: a global sink for
/// completed `RequestEvent` values. Default no-op; enterprise
/// registers a NATS-backed implementation.
pub mod request_sink;
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
pub use events::{EventBus, EventType, ProxyEvent};
pub use export::{WebhookConfig, WebhookExporter};
pub use health::{
    default_registry, handle_healthz, handle_readyz, ComponentReport, ComponentStatus,
    HealthRegistry, NotConfiguredProbe, Probe, ReadinessReport, Recency, RecencyProbe,
};
pub use logging::{
    apply_redaction, emit as emit_structured, should_sample as should_sample_log,
    EventType as LogEventType, LogLevel, LoggingConfig, SamplingConfig, Sink, StructuredLog,
    SCHEMA_VERSION,
};
pub use metrics::{metrics, sanitize_label, ProxyMetrics};
pub use notify::{
    event_type_matches, verify_signature, DeadletterItem, InMemoryStore, Notifier, NotifierStore,
    OutboundEvent, SigningKey, Subscription, VerificationKey, VerifyError,
};
pub use request_event::{RequestEvent, UserIdSource};
pub use request_sink::{
    dispatch_request_event, set_request_event_sink, LoggingSink, NoopSink, RequestEventSink,
};
pub use telemetry::{
    extract_from_headers, init_otlp_pipeline, init_propagator, inject_into_headers,
    inject_into_reqwest, shutdown_otlp_pipeline, span as pillar_span, tracing_helper,
    OtlpTransport, Pillar, TelemetryConfig,
};
pub use topology::{Edge, EdgeStats, TopologyTracker};
pub use trace_ctx::w3c::TraceContext;
