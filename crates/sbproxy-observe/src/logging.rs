//! Global tracing subscriber config + structured-log schema v1
//! scaffolding.
//!
//! Two layers:
//!
//! 1. [`LoggingConfig`] holds the per-process logging knobs: filter
//!    level, output format, and per-level sampling. `init` installs a
//!    global subscriber.
//! 2. [`StructuredLog`] / [`Sink`] / `emit` implement the typed
//!    schema-v1 envelope every emitter (access, error, audit, trace
//!    attributes) routes through. The redaction middleware in
//!    [`apply_redaction`] runs at sink-write time so a single
//!    regression test covers every sink via one harness.
//!
//! Two redaction profiles ship today: `internal` (denylist only) and
//! `external` (denylist + JA3/JA4 + URL → route).
//!
//! # Where the process log level and format come from
//!
//! This is the one place the whole chain is written down. Four sources
//! can name a filter and three can name a format; the most specific
//! wins, and none of them is consulted twice.
//!
//! | Rank | Filter (`level`) | Format |
//! |---|---|---|
//! | 1 | `--log-level`, or `SB_LOG_LEVEL` when the flag is absent | `--log-format`, or `SB_LOG_FORMAT` when the flag is absent |
//! | 2 | `RUST_LOG` | none |
//! | 3 | `proxy.observability.log.level` | `proxy.observability.log.format` |
//! | 4 | `info` | `compact` |
//!
//! The binary resolves rank 1 through 4 before it builds a subscriber
//! and hands the answer to
//! [`LoggingConfig::init_with_resolved_filter_and_telemetry`], which is
//! why that entry point does not look at `RUST_LOG` a second time.
//! [`LoggingConfig::init`] and
//! [`LoggingConfig::init_with_telemetry`] are the embedder-facing
//! entry points: they have no CLI to read, so they let `RUST_LOG`
//! override `self.level` and never see YAML.
//!
//! Two more inputs sit outside that table because they are not
//! startup selectors:
//!
//! * `--request-log-level` / `SB_REQUEST_LOG_LEVEL` appends an
//!   `access_log=<level>` directive to whatever rank 1 through 4
//!   resolved. It narrows one target rather than replacing the filter.
//! * `PUT /admin/log-level` calls [`set_log_filter`] against the live
//!   reload handle. It outranks everything for as long as the process
//!   runs, or until a config reload re-asserts YAML (see below).
//!
//! # What a config reload can and cannot change
//!
//! `level` hot-reloads. The root `EnvFilter` sits behind a
//! [`tracing_subscriber::reload::Layer`], so [`set_log_filter_from_config`] can swap the
//! directive on a running proxy, and the reload path calls it on every
//! SIGHUP, admin reload, and file-watcher pass. Rank 1 and rank 2 stay
//! ahead of it: a process started with `--log-level` or `RUST_LOG` has
//! [`pin_log_filter_override`] set, and the config reload leaves the
//! filter alone rather than demoting an explicit operator override to
//! whatever the file says. An operator who changed the level through
//! the admin API and then reloads config does lose that runtime value
//! when YAML names a level, because a reload re-asserts the file.
//!
//! `format` does not hot-reload. The `fmt` layer is chosen once, when
//! the subscriber is built, and the reload handle covers the filter
//! layer only; there is no handle that could swap a
//! `json` layer for a `pretty` one. Changing
//! `proxy.observability.log.format` needs a process restart.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tracing_subscriber::{fmt, prelude::*, reload, EnvFilter, Registry};

/// Reload handle for the root `EnvFilter`, installed at startup so the
/// admin API can change the log level of a running proxy (WOR-1759). The
/// filter layer wraps the base `Registry`, so the handle type is fixed
/// regardless of the output format.
static LOG_RELOAD: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();
/// The current filter directive string, kept alongside the handle since a
/// `reload::Handle` does not expose its value.
static CURRENT_FILTER: Mutex<String> = Mutex::new(String::new());
/// Whether the filter this process started with came from an explicit
/// operator override (`--log-level` / `SB_LOG_LEVEL` / `RUST_LOG`)
/// rather than from YAML or the built-in default. Set once by the
/// binary before the subscriber is installed; read by
/// [`set_log_filter_from_config`] so a config reload cannot demote an
/// override the operator typed.
static FILTER_PINNED_BY_OVERRIDE: AtomicBool = AtomicBool::new(false);

/// The active tracing filter directive (e.g. `info`, `sbproxy_ai=debug`).
pub fn current_log_filter() -> String {
    CURRENT_FILTER.lock().map(|g| g.clone()).unwrap_or_default()
}

/// Record that `--log-level`, `SB_LOG_LEVEL`, or `RUST_LOG` supplied
/// the startup filter, so `proxy.observability.log.level` stays behind
/// it for the life of the process.
///
/// Called by the binary while it resolves the startup filter, before
/// the subscriber exists. Without this call a config reload would
/// overwrite the operator's `RUST_LOG` with whatever the file says,
/// which is the one outcome the precedence order promises cannot
/// happen. Idempotent; nothing ever clears it, because no later event
/// makes a typed override stop being one.
pub fn pin_log_filter_override() {
    FILTER_PINNED_BY_OVERRIDE.store(true, Ordering::Relaxed);
}

/// Apply `proxy.observability.log.level` to the running process.
///
/// Returns `Ok(true)` when the directive was installed and `Ok(false)`
/// when it was declined because an explicit CLI or environment
/// override is pinned (see [`pin_log_filter_override`]). `Err` carries
/// an invalid directive or a missing reload handle, exactly as
/// [`set_log_filter`] does.
///
/// This is the reload half of the chain documented at the top of this
/// module. Boot does not need it: the binary folds YAML into the
/// filter it resolves before building the subscriber. A reload does,
/// because by then the subscriber is already running with the previous
/// generation's directive.
pub fn set_log_filter_from_config(directive: &str) -> Result<bool, String> {
    if FILTER_PINNED_BY_OVERRIDE.load(Ordering::Relaxed) {
        return Ok(false);
    }
    set_log_filter(directive)?;
    Ok(true)
}

/// Change the tracing filter of the running process at runtime. Returns
/// an error if the directive is invalid or the reload handle was never
/// installed (logging not initialized). Admin-gated by the caller.
pub fn set_log_filter(directive: &str) -> Result<(), String> {
    let handle = LOG_RELOAD
        .get()
        .ok_or_else(|| "log reload handle not installed".to_string())?;
    let new = directive
        .parse::<EnvFilter>()
        .map_err(|e| format!("invalid filter directive: {e}"))?;
    handle
        .reload(new)
        .map_err(|e| format!("reload failed: {e}"))?;
    if let Ok(mut g) = CURRENT_FILTER.lock() {
        *g = directive.to_string();
    }
    Ok(())
}

// --- Logging subscriber config ---

/// Configuration for the global tracing subscriber (log level and format).
///
/// The caller supplies already-resolved values. Which source won, and
/// which of these fields a config reload can still change, is the
/// precedence chain documented at the top of this module.
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Log level filter, one of `debug`, `info`, `warn`, `error`, or
    /// any `tracing-subscriber` per-target directive.
    #[serde(default = "default_level")]
    pub level: String, // "debug", "info", "warn", "error"
    /// Output format, one of `json`, `pretty`, `compact`. Fixed for
    /// the life of the process once the subscriber is built.
    #[serde(default = "default_format")]
    pub format: String, // "json", "pretty", "compact"
    /// Per-level emission sampling rates.
    ///
    /// Inert today. [`should_sample`] is the only reader and no
    /// emitter calls it: [`emit`] renders, redacts, and hands every
    /// record to `tracing` unconditionally. Building the subscriber
    /// ignores this field entirely, so neither these rates nor the
    /// defaults below drop a single line. The rate-limited log surface
    /// operators actually have is `access_log.sampling:`, which is a
    /// different block with a live consumer.
    #[serde(default)]
    pub sampling: SamplingConfig,
}

/// Per-level emission sampling rates. See [`LoggingConfig::sampling`]
/// for why nothing reads these yet.
#[derive(Debug, Clone, Deserialize)]
pub struct SamplingConfig {
    /// Fraction of `info` lines to emit (default 1.0).
    #[serde(default = "default_info_rate")]
    pub info: f64,
    /// Fraction of `debug` lines to emit (default 0.1).
    #[serde(default = "default_debug_rate")]
    pub debug: f64,
    /// Fraction of `trace` lines to emit (default 0.01).
    #[serde(default = "default_trace_rate")]
    pub trace: f64,
}

fn default_info_rate() -> f64 {
    1.0
}
fn default_debug_rate() -> f64 {
    0.1
}
fn default_trace_rate() -> f64 {
    0.01
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            info: default_info_rate(),
            debug: default_debug_rate(),
            trace: default_trace_rate(),
        }
    }
}

fn default_level() -> String {
    "info".to_string()
}

fn default_format() -> String {
    "compact".to_string()
}

impl LoggingConfig {
    /// Initialize the global tracing subscriber. Embedder entry point:
    /// with no CLI to read, `RUST_LOG` overrides `self.level` here.
    pub fn init(&self) {
        self.init_inner(None, true, false);
    }

    /// Initialize the global tracing subscriber with an optional OTLP
    /// trace layer. `RUST_LOG` still overrides `self.level`, matching
    /// [`Self::init`].
    pub fn init_with_telemetry(&self, telemetry: Option<&crate::telemetry::TelemetryConfig>) {
        self.init_inner(telemetry, true, false);
    }

    /// Initialize with an already-resolved filter string. The binary
    /// uses this after applying CLI, `RUST_LOG`, and YAML precedence
    /// itself, so an ambient `RUST_LOG` cannot override an explicit
    /// `--log-level` and a `proxy.observability.log.level` cannot
    /// override either of them.
    pub fn init_with_resolved_filter_and_telemetry(
        &self,
        telemetry: Option<&crate::telemetry::TelemetryConfig>,
    ) {
        self.init_inner(telemetry, false, false);
    }

    /// Initialize with an already-resolved filter and write tracing output to
    /// stderr. CLI commands use this so their stdout remains a clean
    /// machine-readable document.
    pub fn init_with_resolved_filter_and_telemetry_to_stderr(
        &self,
        telemetry: Option<&crate::telemetry::TelemetryConfig>,
    ) {
        self.init_inner(telemetry, false, true);
    }

    fn init_inner(
        &self,
        telemetry: Option<&crate::telemetry::TelemetryConfig>,
        prefer_rust_log: bool,
        write_to_stderr: bool,
    ) {
        let filter = if prefer_rust_log {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&self.level))
        } else {
            EnvFilter::new(&self.level)
        };

        // WOR-1759: make the root filter reloadable so the admin API can
        // change the log level at runtime. The handle is stored globally.
        let (filter_layer, reload_handle) = reload::Layer::new(filter);
        let _ = LOG_RELOAD.set(reload_handle);
        if let Ok(mut g) = CURRENT_FILTER.lock() {
            *g = self.level.clone();
        }

        let otlp = telemetry.and_then(|config| {
            match crate::telemetry::build_otlp_trace_pipeline(config) {
                Ok(pipeline) => pipeline,
                Err(err) => {
                    eprintln!("telemetry: failed to initialize OTLP tracing: {err:#}");
                    None
                }
            }
        });
        if let Some(config) = telemetry {
            if let Err(err) = crate::telemetry::init_otlp_metrics_pipeline(config) {
                eprintln!("telemetry: failed to initialize OTLP metrics: {err:#}");
            }
        }
        let writer = if write_to_stderr {
            fmt::writer::BoxMakeWriter::new(std::io::stderr)
        } else {
            fmt::writer::BoxMakeWriter::new(std::io::stdout)
        };
        match self.format.as_str() {
            "json" => {
                tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().json().with_writer(writer))
                    .with(otlp.as_ref().map(|pipeline| {
                        tracing_opentelemetry::layer().with_tracer(pipeline.tracer.clone())
                    }))
                    .init();
            }
            "pretty" => {
                tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().pretty().with_writer(writer))
                    .with(otlp.as_ref().map(|pipeline| {
                        tracing_opentelemetry::layer().with_tracer(pipeline.tracer.clone())
                    }))
                    .init();
            }
            _ => {
                tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().compact().with_writer(writer))
                    .with(otlp.as_ref().map(|pipeline| {
                        tracing_opentelemetry::layer().with_tracer(pipeline.tracer.clone())
                    }))
                    .init();
            }
        }

        if let Some(pipeline) = otlp {
            tracing::info!(
                endpoint = %pipeline.endpoint,
                service = %pipeline.service_name,
                sample_rate = %pipeline.sample_rate,
                "OTLP tracing pipeline initialised"
            );
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
            format: default_format(),
            sampling: SamplingConfig::default(),
        }
    }
}

// --- Structured-log schema v2 ---

/// Schema version stamped on every emitted line. v2 is additive over
/// v1 (every v1 reader keeps working with strict-mode JSON parsers
/// because every new field is `skip_serializing_if = "Option::is_none"`):
///
/// * Adds optional `session_id` and `user_id` so cross-surface
///   correlation no longer relies on `request_id` alone. Both surface
///   the same identifiers the `RequestEvent` envelope already
///   carries (`crates/sbproxy-observe/src/request_event.rs`).
/// * Normalises the field-key redaction marker to `[REDACTED:<NAME>]`
///   so the schema-v1 layer matches the existing PII-rule replacement
///   shape (`crates/sbproxy-security/src/pii.rs:458`). Downstream
///   tooling no longer has to handle two marker conventions.
///
/// Breaking changes still require a dual-emit window; this version is
/// purely additive on the field set and changes only the redaction
/// marker string (callers that grep for the old `<redacted:...>`
/// shape need to update; the schema check at parse time still
/// accepts both forms during the rollout window).
pub const SCHEMA_VERSION: &str = "2";

/// Pinned event-type enum. Renaming or removing a variant is
/// a breaking change.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Per-request middleware: inbound request accepted, before policy.
    RequestStarted,
    /// Per-request middleware: response sent, before close.
    RequestCompleted,
    /// Per-request middleware: terminal error path.
    RequestError,
    /// Policy module: result of one policy evaluation.
    PolicyEvaluated,
    /// Policy module: policy denied / blocked the request.
    PolicyBlocked,
    /// Action: 402 challenge issued.
    ActionChallengeIssued,
    /// Action: presented token / receipt redeemed.
    ActionRedeemed,
    /// Outbound HTTP call to the ledger.
    LedgerCall,
    /// Audit-log entry (admin actions, authn events).
    AuditEmit,
    /// Outbound webhook delivery attempt.
    NotifyDispatch,
    /// System lifecycle: tracer / metrics / cache init.
    Boot,
    /// System: hot config reload.
    ConfigReload,
    /// System: `/readyz` flipped between healthy and unhealthy.
    HealthStatusChange,
}

impl EventType {
    /// Whether this event MUST be emitted regardless of sampling.
    /// Audit lines are never sampled.
    pub fn is_unsampleable(self) -> bool {
        matches!(self, EventType::AuditEmit)
    }
}

/// Log level enum mirroring the schema-v1 string set.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Lowest level (most verbose).
    Trace,
    /// Diagnostic logging used during development.
    Debug,
    /// Informational events that confirm normal operation.
    Info,
    /// Recoverable issue that may warrant operator attention.
    Warn,
    /// Operation failed; the request did not succeed.
    Error,
    /// Unrecoverable: the process is about to die.
    Fatal,
}

impl LogLevel {
    /// Canonical lowercase slug emitted in `level`.
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Fatal => "fatal",
        }
    }
}

/// One JSON-line structured-log record. Top-level fields match
/// schema v1 verbatim. `extra` carries the per-event payload.
#[derive(Debug, Clone, Serialize)]
pub struct StructuredLog {
    /// RFC 3339 timestamp with millisecond precision.
    pub ts: String,
    /// Log level slug (`trace` / `debug` / `info` / `warn` / `error` /
    /// `fatal`).
    pub level: &'static str,
    /// Constant-per-callsite human-readable message.
    pub msg: String,
    /// Module path (e.g. `sbproxy_modules::policy::ai_crawl`).
    pub target: String,
    /// Pinned event-type enum.
    pub event_type: EventType,
    /// Schema version. Always `"1"` for this ADR.
    pub schema_version: &'static str,

    // --- Per-request linkage (omitted on boot / shutdown / config-reload) ---
    /// Request ULID matching `RequestEvent.request_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// 32-hex W3C trace ID. Absent when emitted outside a span.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// 16-hex W3C span ID. Absent when emitted outside a span.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    /// Tenant / workspace owner. `"default"` in OSS single-tenant mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Origin route key (`hostname` plus path-prefix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// Per-session identifier (schema v2). Mirrors
    /// `RequestEvent.session_id`. Absent for non-session traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Resolved end-user identifier (schema v2). Mirrors
    /// `RequestEvent.user_id`. Absent for anonymous traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    // --- Per-request lifecycle (request_started / completed / error) ---
    /// Resolved agent identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Agent class (`vendor:purpose`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_class: Option<String>,
    /// Payment rail discriminator (`stripe`, `x402`, `mpp`, `lightning`,
    /// `none`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rail: Option<String>,
    /// Content shape discriminator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    /// HTTP status returned to the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// End-to-end latency in milliseconds (terminal events only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u32>,
    /// Compact failure label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,

    /// Per-event-type payload. Renderers serialise this object after
    /// applying redaction (see `apply_redaction`).
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl StructuredLog {
    /// Build an empty record with the given level + msg + event type.
    /// All optional fields are unset; the caller fills in what applies.
    pub fn new(level: LogLevel, msg: impl Into<String>, event_type: EventType) -> Self {
        Self {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            level: level.as_str(),
            msg: msg.into(),
            target: String::new(),
            event_type,
            schema_version: SCHEMA_VERSION,
            request_id: None,
            trace_id: None,
            span_id: None,
            tenant_id: None,
            route: None,
            session_id: None,
            user_id: None,
            agent_id: None,
            agent_class: None,
            rail: None,
            shape: None,
            status_code: None,
            latency_ms: None,
            error_class: None,
            extra: BTreeMap::new(),
        }
    }

    /// Stamp the W3C trace ID + span ID by reading the current OTel
    /// context. No-ops when no context is active.
    pub fn with_current_trace(mut self) -> Self {
        let (trace, span) = crate::metrics::current_trace_ids();
        if !trace.is_empty() {
            self.trace_id = Some(trace);
        }
        if !span.is_empty() {
            self.span_id = Some(span);
        }
        self
    }
}

// --- Sink + redaction profile ---

/// Where a structured-log line is heading. Per-variant redaction
/// profile lets us ship the same proxy binary to a strict tenant and
/// a permissive one without a code change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sink {
    /// Internal access log: full denylist redaction; JA3/JA4 etc. kept.
    AccessLog,
    /// Internal error log. Same profile as access.
    ErrorLog,
    /// Audit log: same profile as access; never sampled.
    AuditLog,
    /// Outbound trace exporter (span attributes). Stricter profile:
    /// applies the denylist and replaces full URLs with the route.
    TraceExporter,
    /// Customer-facing external sink. Strictest profile.
    External,
}

impl Sink {
    /// Whether this sink requires the strict `external` redaction
    /// profile.
    pub fn is_external(self) -> bool {
        matches!(self, Sink::TraceExporter | Sink::External)
    }
}

// --- Redaction middleware ---

/// Operator-extensible redaction state installed at config load via
/// [`install_op_redact_config`]. Stored process-wide because the
/// redaction path is called from emit sites that do not thread a
/// config view. Empty (the global default) until the operator
/// configures `proxy.observability.log.redact:`.
pub struct OpRedactState {
    /// Proxy-scope additional field-key denylist (lowercase ASCII).
    /// Always additive on top of the built-in baseline; never
    /// disable-able at any scope.
    pub fields: Vec<String>,
    /// Proxy-scope compiled regex masks. Each entry is
    /// `(regex, replacement)`. WOR-1042 PR1 (this is the proxy path).
    pub patterns: Vec<(regex::Regex, String)>,
    /// WOR-1042: pre-composed per-tenant field-key denylist additions
    /// (proxy ∪ tenant). Keyed by tenant id. A tenant without an
    /// entry inherits the proxy-scope `fields` only.
    pub tenant_fields: std::collections::HashMap<String, Vec<String>>,
    /// WOR-1042: pre-composed per-tenant pattern set
    /// ((proxy ∪ tenant) − tenant.disable). Keyed by tenant id.
    pub tenant_patterns: std::collections::HashMap<String, Vec<(regex::Regex, String)>>,
    /// WOR-1042: pre-composed per-origin field-key denylist additions
    /// (proxy ∪ tenant ∪ origin). Keyed by the route string the
    /// emitter stamps on `StructuredLog.route` (today: the origin's
    /// hostname).
    pub origin_fields: std::collections::HashMap<String, Vec<String>>,
    /// WOR-1042: pre-composed per-origin pattern set
    /// (((proxy ∪ tenant) − tenant.disable) ∪ origin) − origin.disable.
    /// Keyed by route (origin hostname today).
    pub origin_patterns: std::collections::HashMap<String, Vec<(regex::Regex, String)>>,
    /// Resolved PII redactor at proxy scope (the PR1 path). `None`
    /// when the operator has not enabled PII at proxy scope. Built
    /// once from the resolved rule set with Aho-Corasick anchor
    /// prefiltering so the hot path is allocation-free on clean
    /// input.
    pub proxy_pii: Option<sbproxy_security::pii::PiiRedactor>,
    /// Pre-built per-tenant redactor. Keyed by tenant id. A tenant
    /// without an entry inherits the proxy-scope redactor. A tenant
    /// with an entry whose stored value is `None` opts out of all
    /// PII redaction (the explicit-disable case); a `Some(redactor)`
    /// is the composed rule set (parent inheritance plus this scope's
    /// add list minus the disable list).
    pub tenant_pii: std::collections::HashMap<String, Option<sbproxy_security::pii::PiiRedactor>>,
    /// Pre-built per-origin redactor. Keyed by the route string the
    /// emitter stamps on `StructuredLog.route` (today: the origin's
    /// `hostname`). Resolution at emit time is origin > tenant >
    /// proxy. A `Some(None)` slot is the explicit-disable case.
    pub origin_pii: std::collections::HashMap<String, Option<sbproxy_security::pii::PiiRedactor>>,
}

impl OpRedactState {
    /// Empty state: no operator additions.
    pub fn empty() -> Self {
        Self {
            fields: Vec::new(),
            patterns: Vec::new(),
            tenant_fields: std::collections::HashMap::new(),
            tenant_patterns: std::collections::HashMap::new(),
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
            proxy_pii: None,
            tenant_pii: std::collections::HashMap::new(),
            origin_pii: std::collections::HashMap::new(),
        }
    }

    /// Resolve the active PII redactor for a (tenant, route) pair.
    /// Most-specific scope wins: an origin entry (even one that opts
    /// out with `Some(None)`) overrides the tenant entry, which in
    /// turn overrides the proxy-scope redactor. A scope that has no
    /// entry at all inherits the next scope up. Returns `None` when
    /// no scope has a redactor installed or the most-specific scope
    /// explicitly opted out.
    ///
    /// Deliberately not public (WOR-2405). This is one of three scrub
    /// passes, and an outside caller reaching for it alone gets PII
    /// rules without the operator's `redact.patterns:` masks, which is
    /// the exact defect that shipped and had to be fixed here. Callers
    /// outside this module want [`Self::redact_free_text`], which runs
    /// the whole sequence in the order the log path runs it.
    fn resolve_pii(
        &self,
        tenant_id: Option<&str>,
        route: Option<&str>,
    ) -> Option<&sbproxy_security::pii::PiiRedactor> {
        if let Some(r) = route {
            if let Some(slot) = self.origin_pii.get(r) {
                return slot.as_ref();
            }
        }
        if let Some(t) = tenant_id {
            if let Some(slot) = self.tenant_pii.get(t) {
                return slot.as_ref();
            }
        }
        self.proxy_pii.as_ref()
    }

    /// WOR-1042: resolve the active field-key denylist additions for a
    /// (tenant, route) pair. Most-specific scope wins; an absent scope
    /// falls through. The returned slice is ADDITIVE on top of the
    /// built-in baseline (never replaces it).
    pub fn resolve_fields(&self, tenant_id: Option<&str>, route: Option<&str>) -> &[String] {
        if let Some(r) = route {
            if let Some(v) = self.origin_fields.get(r) {
                return v;
            }
        }
        if let Some(t) = tenant_id {
            if let Some(v) = self.tenant_fields.get(t) {
                return v;
            }
        }
        &self.fields
    }

    /// WOR-1042: resolve the active regex pattern set for a (tenant,
    /// route) pair. Most-specific scope wins. The composition + the
    /// per-scope `disable:` subtraction happens at install time so
    /// this is just a HashMap lookup on the hot path.
    pub fn resolve_patterns(
        &self,
        tenant_id: Option<&str>,
        route: Option<&str>,
    ) -> &[(regex::Regex, String)] {
        if let Some(r) = route {
            if let Some(v) = self.origin_patterns.get(r) {
                return v;
            }
        }
        if let Some(t) = tenant_id {
            if let Some(v) = self.tenant_patterns.get(t) {
                return v;
            }
        }
        &self.patterns
    }

    /// Scrub one bare free-text string for a (tenant, route) scope.
    ///
    /// [`apply_redaction_for`] is the chokepoint for anything shaped like
    /// a rendered log line. This is the chokepoint for the other case: a
    /// single untrusted string that is about to be embedded in a record
    /// built somewhere else, where there is no JSON document to walk. The
    /// decision-audit `reason` (WOR-2405) is the caller that motivated it,
    /// because that string is written by an operator-authored Lua, JS, or
    /// CEL hook and lands in a customer's SIEM.
    ///
    /// Three passes, in the same order [`apply_redaction_for`] runs them:
    ///
    /// 1. [`crate::redact::redact_secrets`], the config-free floor for
    ///    known credential shapes. Unconditional, so a deployment with no
    ///    `redact:` block still cannot ship a Bearer token.
    /// 2. The operator's `redact.patterns:` regex masks for this scope,
    ///    resolved through [`Self::resolve_patterns`] (origin, then
    ///    tenant, then proxy).
    /// 3. The operator's PII rules for this scope, resolved the same
    ///    way (origin, then tenant, then proxy). An explicit opt-out at
    ///    a more-specific scope skips the pass, exactly as it does on
    ///    the log path.
    ///
    /// ## The field-key denylist is deliberately not run
    ///
    /// [`apply_redaction_for`]'s second pass matches JSON *field keys*
    /// against the built-in baseline plus the operator's
    /// `redact.fields:` additions. A bare string has no field key, so
    /// there is nothing for that pass to match on and running it would
    /// mean inventing a key the caller never wrote. A caller that holds a
    /// key/value pair and wants the denylist applied should render it as
    /// JSON and go through [`apply_redaction_for`] instead.
    ///
    /// ## Do not truncate before calling this
    ///
    /// Every detection pattern in passes 1 and 2 needs a minimum body
    /// length: `Bearer [a-zA-Z0-9._\-]{20,}` needs twenty characters
    /// after the keyword. A caller that bounds the string first can cut a
    /// token below that length, the pattern then stops matching, and the
    /// surviving prefix of a live credential ships as ordinary text. Pass
    /// the full string here and apply any length bound to the result.
    ///
    /// ## Picking the arguments
    ///
    /// `route` is the route string the log emitter stamps on
    /// [`StructuredLog::route`], which today is the origin's **hostname**.
    /// It is not necessarily a configured origin id, and passing the id
    /// where the hostname is expected silently skips the origin-scope
    /// rules. Pass `None` for a scope the caller genuinely does not have
    /// rather than a guess: `None` falls through to the next scope up,
    /// while a wrong key falls through to proxy scope having quietly
    /// skipped the rules the operator wrote for the real one.
    pub fn redact_free_text(&self, tenant: Option<&str>, route: Option<&str>, raw: &str) -> String {
        let floor = crate::redact::redact_secrets(raw);
        let patterns = self.resolve_patterns(tenant, route);
        apply_op_regex_patterns_with(&floor, tenant, route, patterns, self)
    }
}

static OP_REDACT_STATE: OnceLock<std::sync::RwLock<std::sync::Arc<OpRedactState>>> =
    OnceLock::new();

fn op_redact_lock() -> &'static std::sync::RwLock<std::sync::Arc<OpRedactState>> {
    OP_REDACT_STATE
        .get_or_init(|| std::sync::RwLock::new(std::sync::Arc::new(OpRedactState::empty())))
}

/// Install (or replace) the operator-extensible redaction state from
/// the compiled config. Returns `true` after every successful swap so
/// config reload can re-apply.
pub fn install_op_redact_config(state: OpRedactState) -> bool {
    let lock = op_redact_lock();
    if let Ok(mut guard) = lock.write() {
        *guard = std::sync::Arc::new(state);
        return true;
    }
    false
}

fn op_redact_state() -> std::sync::Arc<OpRedactState> {
    let lock = op_redact_lock();
    lock.read()
        .map(|g| g.clone())
        .unwrap_or_else(|_| std::sync::Arc::new(OpRedactState::empty()))
}

/// The installed operator redaction state, for emitters outside this
/// module that must scrub a string before it leaves the process.
///
/// The decision-audit path (WOR-2405) is the first such caller: a
/// `reason` string comes from operator-authored script text, so it is
/// scrubbed with [`OpRedactState::redact_free_text`] for the request's
/// scope before it reaches a customer's log store. That method is the
/// only scrub entry point this module exposes, and it is the whole
/// sequence rather than any one pass of it: the earlier draft of this
/// path resolved the PII rules alone and silently skipped every
/// `redact.patterns:` mask the operator had written. Returns an owned handle because the state is
/// swapped whole on config reload; hold it only for the length of one
/// scrub.
pub fn operator_redact_state() -> std::sync::Arc<OpRedactState> {
    op_redact_state()
}

/// Apply the denylist + per-sink overrides to an in-progress JSON
/// rendering. The function is the single chokepoint every emitter
/// routes through, so the regression test only has to fuzz
/// one entry point to cover access / error / audit / trace exporter.
///
/// Three layers, applied in order:
///
/// 1. Value-pattern scrubber (`crate::redact::redact_secrets`) for
///    obvious secret shapes (Bearer tokens, sk-* keys).
/// 2. Built-in field-key denylist (the hard-coded baseline) + the
///    operator-extensible `proxy.observability.log.redact.fields:`
///    additions. Operator entries cannot override or disable the
///    built-in baseline.
/// 3. Operator-extensible regex masks
///    (`proxy.observability.log.redact.patterns:`). Each pattern is
///    applied to the rendered JSON after the field-key pass.
pub fn apply_redaction(json: &str, sink: Sink) -> String {
    apply_redaction_for(json, sink, None, None)
}

/// Sink-agnostic line redaction: the twelve secret regexes plus the
/// field-key denylist (`prompt`, `messages`, `tool_arguments`, ...),
/// without the per-tenant operator rules that `apply_redaction_for`
/// layers on. For emitters that write JSON lines outside the
/// StructuredLog path (request events, access log). WOR-2473.
///
/// # The two layers are not independent
///
/// The denylist runs only when the secret pass left something that
/// still parses. A pattern that consumed a key separator therefore did
/// not just mangle its own field: it dropped the denylist for the
/// entire record, and `prompt` / `cookie` / a bundle secret var later
/// on the same line shipped verbatim. Three patterns did exactly that
/// until they were given capture groups; the module docs on
/// [`crate::redact`] carry the rule. The `Err` arm here is a floor for
/// genuinely non-JSON input (a `tracing` text line), not a tolerated
/// outcome for a rendered record.
pub fn redact_json_line(input: &str) -> String {
    let secrets_scrubbed = crate::redact::redact_secrets(input);
    match serde_json::from_str::<serde_json::Value>(&secrets_scrubbed) {
        Ok(mut value) => {
            redact_value(&mut value, Sink::AccessLog, &[]);
            serde_json::to_string(&value).unwrap_or(secrets_scrubbed)
        }
        Err(_) => secrets_scrubbed,
    }
}

/// Tenant- and route-aware variant of [`apply_redaction`]. The hot
/// emit path threads `StructuredLog.tenant_id` and `StructuredLog.route`
/// into the resolver so the PII pass can pick a tenant- or origin-scope
/// rule set (per WOR-1043 PR2 / PR3). `None, None` reproduces the
/// legacy behaviour and is what [`apply_redaction`] passes for callers
/// without a scope.
pub fn apply_redaction_for(
    json: &str,
    sink: Sink,
    tenant_id: Option<&str>,
    route: Option<&str>,
) -> String {
    let pattern_redacted = crate::redact::redact_secrets(json);

    // WOR-1042: resolve the per-scope field-key denylist + regex
    // pattern set ONCE per emit so the recursive `redact_value` walk
    // and the regex pass both see the same composed set. Holding the
    // state `Arc` for the duration of the emit pins the lookup; the
    // Arc clone is cheap.
    let state = op_redact_state();
    let extra_fields = state.resolve_fields(tenant_id, route);
    let patterns = state.resolve_patterns(tenant_id, route);

    let mut value: serde_json::Value = match serde_json::from_str(&pattern_redacted) {
        Ok(v) => v,
        Err(_) => {
            return apply_op_regex_patterns_with(
                &pattern_redacted,
                tenant_id,
                route,
                patterns,
                &state,
            )
        }
    };
    redact_value(&mut value, sink, extra_fields);
    let rendered = serde_json::to_string(&value).unwrap_or(pattern_redacted);

    apply_op_regex_patterns_with(&rendered, tenant_id, route, patterns, &state)
}

/// Apply the operator-supplied regex patterns and, when configured,
/// the PII redactor to the JSON-rendered string. Compiled at config
/// load so the hot path is just pattern dispatch. The PII redactor
/// is selected by walking origin -> tenant -> proxy via
/// [`OpRedactState::resolve_pii`]; an explicit opt-out at a
/// more-specific scope (the `Some(None)` slot) skips the PII pass
/// entirely.
/// WOR-1042: variant that takes a pre-resolved pattern slice and state
/// snapshot so `apply_redaction_for` does not re-resolve per call.
///
/// WOR-2405: shared with [`OpRedactState::redact_free_text`], which is
/// why it takes `&OpRedactState` rather than the `Arc` the log path
/// happens to hold. It is the string-level half of the pipeline, so a
/// caller with no JSON document gets the same two passes rather than a
/// second copy of the loop that can drift from this one.
fn apply_op_regex_patterns_with(
    input: &str,
    tenant_id: Option<&str>,
    route: Option<&str>,
    patterns: &[(regex::Regex, String)],
    state: &OpRedactState,
) -> String {
    let needs_regex = !patterns.is_empty();
    let pii = state.resolve_pii(tenant_id, route);
    let needs_pii = pii.is_some();
    if !needs_regex && !needs_pii {
        return input.to_string();
    }
    let mut out: std::borrow::Cow<'_, str> = std::borrow::Cow::Borrowed(input);
    if needs_regex {
        let mut owned = out.into_owned();
        for (re, replacement) in patterns {
            owned = re.replace_all(&owned, replacement.as_str()).into_owned();
        }
        out = std::borrow::Cow::Owned(owned);
    }
    if let Some(p) = pii {
        // PiiRedactor::redact returns Cow::Borrowed on clean input
        // (no allocation when there is no PII to redact) and
        // Cow::Owned on a match.
        out = p.redact(out.as_ref()).into_owned().into();
    }
    out.into_owned()
}

/// Header names the inbound minted-key sweep reads, lowercased.
///
/// Fed from `key_management.inbound.headers` at load and on every reload
/// rather than hardcoded, because an operator who configures a custom header
/// would otherwise get no redaction at all: a name like `x-tool-auth` matches
/// none of the `-key` / `-secret` / `-token` suffix rules below, and their live
/// key would reach the access log in plaintext. Making the redactor follow the
/// configuration means adding a sweep header cannot silently open that hole.
static SWEPT_HEADERS: OnceLock<std::sync::RwLock<std::sync::Arc<Vec<String>>>> = OnceLock::new();

fn swept_headers_slot() -> &'static std::sync::RwLock<std::sync::Arc<Vec<String>>> {
    SWEPT_HEADERS.get_or_init(|| std::sync::RwLock::new(std::sync::Arc::new(Vec::new())))
}

/// Replace the set of header names treated as key-bearing for redaction.
///
/// Call on config load and on every reload with
/// `KeyInboundConfig::header_names()`. Names are lowercased by the caller;
/// this lowercases again so a hand-built list cannot slip through uncased.
pub fn set_swept_header_names(names: Vec<String>) {
    let lowered: Vec<String> = names
        .into_iter()
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    if let Ok(mut slot) = swept_headers_slot().write() {
        *slot = std::sync::Arc::new(lowered);
    }
}

/// The currently configured sweep header names, for diagnostics and tests.
pub fn swept_header_names() -> std::sync::Arc<Vec<String>> {
    swept_headers_slot()
        .read()
        .map(|slot| slot.clone())
        .unwrap_or_else(|_| std::sync::Arc::new(Vec::new()))
}

/// Whether `k` is a header the sweep reads, and therefore carries a live key.
fn is_swept_header(k: &str) -> bool {
    swept_headers_slot()
        .read()
        .map(|slot| slot.iter().any(|n| n == k))
        .unwrap_or(false)
}

/// WOR-2289: field-key denylist additions declared by the currently
/// serving extension bundles (a hook manifest's `secret_vars` and
/// `masked_vars`). Same shape as [`SWEPT_HEADERS`]: publishing a
/// pipeline replaces the whole set, so a reload that drops a bundle
/// also drops the names it declared. Additive on top of the built-in
/// baseline and every operator-configured scope; there is no config
/// key that can disable it, matching the guarantee `OpRedactState`
/// makes for its own `fields`.
///
/// The set moves at pipeline publication, not at bundle candidate
/// load. Loading is not adopting: validate-only loads (a publish dry
/// run, doctor) build a registry that is dropped, and installing from
/// there let a candidate carrying no bundles un-redact the secrets of
/// the generation still serving.
static BUNDLE_SECRET_FIELD_NAMES: OnceLock<std::sync::RwLock<std::sync::Arc<Vec<String>>>> =
    OnceLock::new();

fn bundle_secret_field_names_slot() -> &'static std::sync::RwLock<std::sync::Arc<Vec<String>>> {
    BUNDLE_SECRET_FIELD_NAMES
        .get_or_init(|| std::sync::RwLock::new(std::sync::Arc::new(Vec::new())))
}

/// Replace the set of bundle-declared secret/masked var names treated
/// as key-bearing for redaction.
///
/// Call it from pipeline publication with every `secret_vars` and
/// `masked_vars` the adopted registry's hooks declare
/// (`DynamicBundleRegistry::secret_field_names`). A name here is
/// redacted by key in every structured sink, regardless of tenant or
/// origin scope, the same way a `secret_vars` value is always resolved
/// and always masked regardless of which attachment used it.
///
/// Twice per publication, in practice: the publisher installs the
/// union of the outgoing and incoming sets before the pipeline swap
/// and narrows to the incoming set after it, so no field is
/// under-redacted on either side of the boundary. Going only one way
/// leaves a window: install early and a dropped bundle's fields are in
/// cleartext while its generation is still serving; install late and a
/// newly added bundle's fields are in cleartext once its generation
/// is.
///
/// Do not call it from a load path. A candidate that is built and
/// dropped must leave the serving generation's denylist alone.
pub fn set_bundle_secret_field_names(names: Vec<String>) {
    let lowered: Vec<String> = names
        .into_iter()
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    if let Ok(mut slot) = bundle_secret_field_names_slot().write() {
        *slot = std::sync::Arc::new(lowered);
    }
}

/// The currently registered bundle secret/masked field names, for
/// diagnostics and tests.
pub fn bundle_secret_field_names() -> std::sync::Arc<Vec<String>> {
    bundle_secret_field_names_slot()
        .read()
        .map(|slot| slot.clone())
        .unwrap_or_else(|_| std::sync::Arc::new(Vec::new()))
}

/// Whether `k` is a var name a loaded bundle declared `secret_vars` or
/// `masked_vars`, and therefore carries a live secret or a value an
/// extension author explicitly chose not to log.
fn is_bundle_secret_field(k: &str) -> bool {
    bundle_secret_field_names_slot()
        .read()
        .map(|slot| slot.iter().any(|n| n == k))
        .unwrap_or(false)
}

/// Recursively walk a JSON value and redact any field whose key is on
/// the denylist. Replacements use the typed `[REDACTED:FOO]` marker
/// (schema v2).
fn redact_value(value: &mut serde_json::Value, sink: Sink, extra_fields: &[String]) {
    match value {
        serde_json::Value::Object(map) => {
            // Collect keys first so we can mutate values without
            // double-borrowing the map.
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if let Some(marker) = match_denylist(&k, sink, extra_fields) {
                    if let Some(v) = map.get_mut(&k) {
                        *v = serde_json::Value::String(marker.to_string());
                    }
                } else if let Some(v) = map.get_mut(&k) {
                    redact_value(v, sink, extra_fields);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                redact_value(v, sink, extra_fields);
            }
        }
        _ => {}
    }
}

/// Match a JSON field key against the denylist. Returns the
/// typed marker that should replace the value, or `None` to leave it
/// alone. The `extra_fields` slice is the per-scope (proxy / tenant /
/// origin) field-key denylist resolved by the caller; it sits in
/// front of the operator-extensible global `state.fields` slot so the
/// most-specific scope's additions fire.
fn match_denylist(key: &str, sink: Sink, extra_fields: &[String]) -> Option<&'static str> {
    let k = key.to_ascii_lowercase();
    // RFC 9449 proofs are bearer-adjacent sender-constraining material. A
    // compact JWS does not match the value-shape redactor, so protect it by
    // field name in every structured sink.
    if k == "dpop" {
        return Some("[REDACTED:DPOP_PROOF]");
    }
    // Authorization headers + cookies: every sink redacts these.
    if k == "authorization" || k == "proxy-authorization" {
        return Some("[REDACTED:AUTHORIZATION]");
    }
    if k == "cookie" || k == "set-cookie" {
        return Some("[REDACTED:COOKIE]");
    }
    if k == "x-stripe-signature" || k == "stripe-signature" {
        return Some("[REDACTED:STRIPE_SIGNATURE]");
    }
    // Stripe SK fields under any key. Includes the request-header
    // shape `x-stripe-key` (and its underscore-normalised form
    // `x_stripe_key`) so a typed inbound carrying the live secret in a
    // bespoke header still hits the typed marker rather than falling
    // through to the generic api-key catch-all.
    if k.contains("stripe_sk")
        || k == "stripe_secret_key"
        || k == "x-stripe-key"
        || k == "x_stripe_key"
    {
        return Some("[REDACTED:STRIPE_SECRET_KEY]");
    }
    if k == "ledger_hmac_key" || k == "sbproxy_ledger_hmac_key" {
        return Some("[REDACTED:LEDGER_HMAC_KEY]");
    }
    // KYA tokens. The historical match handled `kya_*` prefixed
    // fields; the request-header shape is `x-kya` (so the lowercased
    // / underscore-normalised key is `x_kya` or `x-kya`). Match both.
    if k == "kya_token" || k.starts_with("kya_") || k == "x-kya" || k == "x_kya" {
        return Some("[REDACTED:KYA_TOKEN]");
    }
    if k == "oauth_client_secret" {
        return Some("[REDACTED:OAUTH_CLIENT_SECRET]");
    }
    // Receipt secrets. Request-header form is `x-sb-receipt-secret`
    // (underscore-normalised: `x_sb_receipt_secret`). Without this
    // explicit match, the generic `_secret` suffix would route the
    // value through the wrong typed marker.
    if k == "payment_receipt_secret" || k == "x-sb-receipt-secret" || k == "x_sb_receipt_secret" {
        return Some("[REDACTED:PAYMENT_RECEIPT_SECRET]");
    }
    if k == "prompt" || k == "messages" || k == "tool_arguments" {
        return Some("[REDACTED:PROMPT_BODY]");
    }
    if k == "envelope_payload_raw" {
        return Some("[REDACTED:ENVELOPE_PAYLOAD_RAW]");
    }
    // WOR-2289: a var a loaded bundle declared `secret_vars` or
    // `masked_vars` in its manifest. Checked by key so this fires
    // even for a field no other rule here anticipates, regardless of
    // which sink or scope is rendering it.
    if is_bundle_secret_field(&k) {
        return Some("[REDACTED:BUNDLE_SECRET_VAR]");
    }
    // External-only: JA3 / JA4 fingerprints are kept on internal
    // sinks but redacted outbound.
    if sink.is_external() && (k == "ja3" || k == "ja3_hash" || k == "ja4" || k == "ja4_hash") {
        return Some("[REDACTED:JA_FINGERPRINT]");
    }
    // Generic suffix match: *_secret / *_token / *_key / api_key.
    // Also covers the hyphenated request-header form `x-api-key`
    // (and any other `*-key` / `*-secret` / `*-token` shape) so an
    // inbound header is redacted even before the underscore
    // normalisation pass that the JSON renderer would do.
    if k == "api_key"
        || k == "x-api-key"
        // Any header the operator configured the key sweep to read carries a
        // live token by definition, whatever it happens to be called.
        || is_swept_header(&k)
        || k.ends_with("_secret")
        || k.ends_with("_token")
        || k.ends_with("_key")
        || k.ends_with("-key")
        || k.ends_with("-secret")
        || k.ends_with("-token")
    {
        return Some("[REDACTED:API_KEY]");
    }
    // Operator-extensible field-key denylist. `extra_fields` is the
    // per-scope (proxy / tenant / origin) resolved set passed in by
    // the caller; an empty slice falls back to the global state's
    // proxy-scope `fields` (the legacy path for emit sites that have
    // not threaded a scope through). The match runs case-insensitively
    // against the lowercased key (`k`).
    if !extra_fields.is_empty() && extra_fields.iter().any(|f| f == &k) {
        return Some("[REDACTED:OPERATOR_FIELD]");
    }
    if extra_fields.is_empty() {
        let state = op_redact_state();
        if !state.fields.is_empty() && state.fields.iter().any(|f| f == &k) {
            return Some("[REDACTED:OPERATOR_FIELD]");
        }
    }
    None
}

/// Decide whether a structured-log line at the given level should be
/// emitted given the per-level sampling rates. Audit events are never
/// sampled. The sampling decision is deterministic for a given
/// `request_id` so every line tied to one request shares the same
/// keep/drop verdict.
///
/// No emitter calls this. [`emit`] does not consult it, so the
/// process logger samples nothing and `proxy.observability.log.sampling`
/// has no effect regardless of what it is set to. Wiring the emit path
/// to this function is the work that would make those rates real.
pub fn should_sample(
    sampling: &SamplingConfig,
    level: LogLevel,
    event_type: EventType,
    request_id: Option<&str>,
) -> bool {
    if event_type.is_unsampleable() {
        return true;
    }
    let rate = match level {
        LogLevel::Trace => sampling.trace,
        LogLevel::Debug => sampling.debug,
        // Info+ defaults to 100% per A1.5.
        _ => sampling.info,
    };
    if rate >= 1.0 {
        return true;
    }
    if rate <= 0.0 {
        return false;
    }
    let rid = request_id.unwrap_or("");
    let hash: u64 = rid
        .bytes()
        .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
    (hash % 1000) < (rate * 1000.0) as u64
}

/// Render + redact + emit a structured log line.
///
/// When an operator-installed [`crate::sink_dispatcher::SinkDispatcher`]
/// is live (WOR-1045 PR2), the record fans out to every matching
/// declared sink via [`crate::sink_dispatcher::SinkDispatcher::dispatch`].
/// Each sink picks its own redaction profile (tenant- and origin-scope
/// sinks default to `external`) and its own format.
///
/// When no dispatcher is installed (boot time, tests, single-tenant
/// deployments without a sinks block), the legacy `tracing::*!`
/// fallback below keeps driving stdout. The `target` is set per-sink
/// so log routers continue to fan the same line out to access /
/// error / audit / trace exporter pipes independently.
pub fn emit(record: &StructuredLog, sink: Sink) {
    // WOR-1045 PR2: when the operator declared a sinks block, hand
    // the record off to the dispatcher and skip the legacy
    // `tracing::*!` fallback. This is the only behavioural change
    // for an existing single-stdout deployment is "no change" because
    // a deployment without a sinks block keeps `current_sink_dispatcher`
    // returning `None`.
    if let Some(dispatcher) = crate::sink_dispatcher::current_sink_dispatcher() {
        dispatcher.dispatch(record, sink);
        return;
    }

    let json = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(_) => return,
    };
    // Route the PII pass through the record's tenant + origin
    // identifiers so a tenant- or origin-scope override can win
    // over the proxy-scope rule set (WOR-1043 PR2 / PR3). Records
    // without a tenant / route fall back to the proxy-scope behaviour
    // exactly as PR1 emitted them.
    let redacted = apply_redaction_for(
        &json,
        sink,
        record.tenant_id.as_deref(),
        record.route.as_deref(),
    );
    // `tracing::*!` requires a literal target. Branch on the
    // (sink, level) pair so each call site is a static literal.
    match (sink, record.level) {
        (Sink::AccessLog, "error") | (Sink::AccessLog, "fatal") => {
            tracing::error!(target: "access_log", "{}", redacted)
        }
        (Sink::AccessLog, "warn") => tracing::warn!(target: "access_log", "{}", redacted),
        (Sink::AccessLog, "debug") => tracing::debug!(target: "access_log", "{}", redacted),
        (Sink::AccessLog, "trace") => tracing::trace!(target: "access_log", "{}", redacted),
        (Sink::AccessLog, _) => tracing::info!(target: "access_log", "{}", redacted),

        (Sink::ErrorLog, "warn") => tracing::warn!(target: "error_log", "{}", redacted),
        (Sink::ErrorLog, "debug") => tracing::debug!(target: "error_log", "{}", redacted),
        (Sink::ErrorLog, "trace") => tracing::trace!(target: "error_log", "{}", redacted),
        // Error log defaults to error level even for info/etc lines so
        // log routers can ship the whole channel as alerts.
        (Sink::ErrorLog, _) => tracing::error!(target: "error_log", "{}", redacted),

        (Sink::AuditLog, _) => tracing::info!(target: "audit_log", "{}", redacted),
        (Sink::TraceExporter, _) => tracing::info!(target: "trace_exporter", "{}", redacted),
        (Sink::External, "error") | (Sink::External, "fatal") => {
            tracing::error!(target: "external_log", "{}", redacted)
        }
        (Sink::External, "warn") => tracing::warn!(target: "external_log", "{}", redacted),
        (Sink::External, _) => tracing::info!(target: "external_log", "{}", redacted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, "info");
        assert_eq!(config.format, "compact");
    }

    #[test]
    fn test_deserialize_with_defaults() {
        let json = r#"{}"#;
        let config: LoggingConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.level, "info");
        assert_eq!(config.format, "compact");
    }

    #[test]
    fn test_deserialize_with_values() {
        let json = r#"{"level": "debug", "format": "json"}"#;
        let config: LoggingConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.level, "debug");
        assert_eq!(config.format, "json");
    }

    #[test]
    fn test_deserialize_partial() {
        let json = r#"{"level": "warn"}"#;
        let config: LoggingConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.level, "warn");
        assert_eq!(config.format, "compact");
    }

    /// The reload half of the precedence chain: YAML reaches the live
    /// filter, but never past an override the operator typed.
    ///
    /// Both halves live in one test on purpose. The pin is a
    /// process-global with no way to clear it (nothing in production
    /// ever un-types a `--log-level`), so a separate unpinned test
    /// would pass or fail on test-ordering under a thread-per-test
    /// runner. Asserting the before state first makes the order the
    /// test's own.
    #[test]
    fn config_log_level_yields_to_a_pinned_cli_override() {
        // Unpinned: the call is not declined. It still fails here,
        // because no test in this crate installs a subscriber, so
        // there is no reload handle to swap; what matters is that the
        // refusal is not `Ok(false)`.
        assert_ne!(set_log_filter_from_config("debug"), Ok(false));

        pin_log_filter_override();

        // Pinned: declined without touching the running filter.
        assert_eq!(set_log_filter_from_config("debug"), Ok(false));
        assert_eq!(set_log_filter_from_config("trace"), Ok(false));
    }

    // --- Schema v1 ---

    #[test]
    fn structured_log_emits_top_level_fields() {
        let mut rec = StructuredLog::new(
            LogLevel::Info,
            "request completed",
            EventType::RequestCompleted,
        );
        rec.target = "sbproxy_modules::policy::ai_crawl".to_string();
        rec.request_id = Some("01JX7QV2HB7PQF7FJ8C9C70RBE".to_string());
        rec.tenant_id = Some("default".to_string());
        let json = serde_json::to_string(&rec).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["level"], "info");
        assert_eq!(v["event_type"], "request_completed");
        assert_eq!(v["schema_version"], "2");
        assert_eq!(v["target"], "sbproxy_modules::policy::ai_crawl");
    }

    /// Schema v2 adds optional `session_id` and `user_id` so a
    /// downstream ClickHouse / SIEM JOIN against the RequestEvent
    /// envelope no longer relies on `request_id` alone.
    #[test]
    fn schema_v2_surfaces_session_and_user_ids() {
        let mut rec = StructuredLog::new(
            LogLevel::Info,
            "request completed",
            EventType::RequestCompleted,
        );
        rec.session_id = Some("sess_acme_42".to_string());
        rec.user_id = Some("user_acme_alice".to_string());
        let json = serde_json::to_string(&rec).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema_version"], "2");
        assert_eq!(v["session_id"], "sess_acme_42");
        assert_eq!(v["user_id"], "user_acme_alice");
    }

    /// Schema v2 normalises every field-key redaction marker to
    /// `[REDACTED:<NAME>]`. A v1-shape marker must never leak
    /// through.
    #[test]
    fn schema_v2_uses_bracket_uppercase_redaction_markers() {
        let json = r#"{"authorization":"Bearer x","cookie":"session=y","stripe_sk":"sk_live_a","payment_receipt_secret":"pq","prompt":"hello"}"#;
        let out = apply_redaction(json, Sink::AccessLog);
        for marker in [
            "[REDACTED:AUTHORIZATION]",
            "[REDACTED:COOKIE]",
            "[REDACTED:STRIPE_SECRET_KEY]",
            "[REDACTED:PAYMENT_RECEIPT_SECRET]",
            "[REDACTED:PROMPT_BODY]",
        ] {
            assert!(out.contains(marker), "missing {marker} in {out}");
        }
        assert!(
            !out.contains("<redacted:"),
            "legacy v1-shape marker leaked: {out}"
        );
    }

    #[test]
    fn redact_json_line_covers_prompt_and_tool_arguments_keys() {
        let line = r#"{"prompt":"steal the plans","tool_arguments":"{\"cmd\":\"rm\"}","ok":"x"}"#;
        let out = redact_json_line(line);
        assert!(out.contains("[REDACTED:PROMPT_BODY]"), "{out}");
        assert!(!out.contains("steal the plans"), "{out}");
        assert!(!out.contains("rm"), "{out}");
        assert!(out.contains("\"ok\":\"x\""), "{out}");
    }

    #[test]
    fn redact_json_line_on_non_json_still_scrubs_secrets() {
        let out = redact_json_line("bearer sk-abc123def456ghi789jkl012");
        assert!(!out.contains("sk-abc123def456ghi789jkl012"), "{out}");
    }

    /// A captured `x-api-key` header used to leave the rendered line
    /// unparseable, and this function answers a parse failure by
    /// returning the string as it stands, so the field-key denylist
    /// never ran and the `prompt` on the same record shipped verbatim.
    /// Both halves are asserted: the line is still JSON, and the
    /// second secret is still masked. A test that only checked the api
    /// key was gone passed before the fix as well.
    #[test]
    fn a_captured_api_key_header_does_not_disable_the_denylist_for_the_line() {
        let line = concat!(
            r#"{"request_headers":{"x-api-key":"abcdefghijklmnop1234"},"#,
            r#""prompt":"steal the plans","status":200}"#
        );
        let out = redact_json_line(line);
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("redacted access-log line is not JSON ({e}): {out}"));
        assert_eq!(parsed["prompt"], "[REDACTED:PROMPT_BODY]", "{out}");
        assert!(!out.contains("steal the plans"), "{out}");
        assert!(!out.contains("abcdefghijklmnop1234"), "{out}");
        assert_eq!(parsed["status"], 200, "{out}");
    }

    /// The same coupling for the other two patterns that ate their
    /// separator. One denylisted field on each line, so a skipped
    /// denylist is visible.
    #[test]
    fn a_keyed_secret_earlier_in_the_line_does_not_cost_the_prompt() {
        for (label, line) in [
            (
                "aws secret label",
                concat!(
                    r#"{"secret_hash":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","#,
                    r#""prompt":"steal the plans"}"#
                ),
            ),
            (
                "password",
                r#"{"upstream_password":"hunter2xyz","prompt":"steal the plans"}"#,
            ),
            (
                "api key",
                r#"{"api_key":"abcdefghijklmnop1234","prompt":"steal the plans"}"#,
            ),
        ] {
            let out = redact_json_line(line);
            let parsed: serde_json::Value = serde_json::from_str(&out)
                .unwrap_or_else(|e| panic!("{label}: redacted line is not JSON ({e}): {out}"));
            assert_eq!(
                parsed["prompt"], "[REDACTED:PROMPT_BODY]",
                "{label}: denylist did not run: {out}"
            );
            assert!(
                !out.contains("steal the plans"),
                "{label}: prompt survived: {out}"
            );
        }
    }

    #[test]
    fn structured_logs_redact_compact_dpop_proofs_by_field_key() {
        const DPOP_PROOF: &str = concat!(
            "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2",
            "IjoiUC0yNTYiLCJ4IjoibDh0RnIzRjdrS3Rjb2J4NWVmMHlONUR1ejN0RDdmWUZQUmRaeFk1",
            "VlFKMCIsInkiOiI0cE4tNUo3azZKbTZUdmVXZEVLd3FWRE1IWVE1bk5vVEhUY0xRa0cxZDVN",
            "In19.",
            "eyJqdGkiOiJmNmE4ZjMyZC00YzY1LTRjMjctYThiOS0zMDQ3ZjY4ZTI3MTUiLCJodG0iOiJH",
            "RVQiLCJodHUiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbS9yZXNvdXJjZSIsImlhdCI6MTc4",
            "NTA5MTIwMH0.",
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1",
            "Njc4OWFiY2RlZg",
        );
        let json = serde_json::json!({
            "request_headers": {
                "dpop": DPOP_PROOF,
            },
        })
        .to_string();

        let out = apply_redaction(&json, Sink::AccessLog);
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();

        assert_eq!(value["request_headers"]["dpop"], "[REDACTED:DPOP_PROOF]");
        assert!(
            !out.contains(DPOP_PROOF),
            "compact DPoP proof leaked from structured log: {out}"
        );
    }

    /// Serialise the operator-redact tests because they swap a
    /// process-global slot installed by `install_op_redact_config`.
    /// Each test installs the state it needs and asserts, then resets
    /// to empty so a parallel cargo-test run does not see a state
    /// installed by a sibling. Before WOR-1042 PR1 the slot was a
    /// `OnceLock::set`, so the first-installer-wins kept ordering
    /// from mattering; the hot-swap now requires explicit serialisation.
    static OP_REDACT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Operator-supplied `proxy.observability.log.redact.fields:`
    /// extends the built-in field-key denylist. The operator entry
    /// `internal_account_id` redacts a freshly-named JSON key while
    /// the baseline `authorization` keeps being redacted independently.
    #[test]
    fn op_redact_fields_extend_the_baseline() {
        let _guard = OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = install_op_redact_config(OpRedactState {
            fields: vec!["internal_account_id".to_string()],
            patterns: Vec::new(),
            proxy_pii: None,
            tenant_pii: std::collections::HashMap::new(),
            origin_pii: std::collections::HashMap::new(),
            tenant_fields: std::collections::HashMap::new(),
            tenant_patterns: std::collections::HashMap::new(),
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
        });
        let json = r#"{"authorization":"Bearer x","internal_account_id":"acct-123456"}"#;
        let out = apply_redaction(json, Sink::AccessLog);
        assert!(
            out.contains("[REDACTED:AUTHORIZATION]"),
            "baseline auth missing: {out}"
        );
        assert!(
            out.contains("[REDACTED:OPERATOR_FIELD]"),
            "operator field marker missing: {out}"
        );
        assert!(
            !out.contains("acct-123456"),
            "raw operator value leaked: {out}"
        );
        let _ = install_op_redact_config(OpRedactState::empty());
    }

    /// Operator-supplied `proxy.observability.log.redact.patterns:`
    /// run after the field-key pass on the rendered JSON. The pattern
    /// catches a fresh value shape that the built-in denylist would
    /// not match.
    #[test]
    fn op_redact_patterns_run_after_field_pass() {
        let _guard = OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = install_op_redact_config(OpRedactState {
            fields: vec!["internal_account_id".to_string()],
            patterns: vec![(
                regex::Regex::new(r"cust_[a-z0-9]{6,}").expect("compiles"),
                "[REDACTED:CUSTOMER_UUID]".to_string(),
            )],
            proxy_pii: None,
            tenant_pii: std::collections::HashMap::new(),
            origin_pii: std::collections::HashMap::new(),
            tenant_fields: std::collections::HashMap::new(),
            tenant_patterns: std::collections::HashMap::new(),
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
        });
        let json = r#"{"freeform":"cust_abc1234567 was here"}"#;
        let out = apply_redaction(json, Sink::AccessLog);
        assert!(
            out.contains("[REDACTED:CUSTOMER_UUID]"),
            "operator pattern missing: {out}"
        );
        assert!(
            !out.contains("cust_abc1234567"),
            "raw pattern value leaked: {out}"
        );
        let _ = install_op_redact_config(OpRedactState::empty());
    }

    /// Operator-supplied `proxy.observability.log.redact.pii:` runs as
    /// a fourth pass after the field-key and regex passes. The
    /// built-in `email` rule fires on a freeform string field that no
    /// other redaction layer would catch.
    #[test]
    fn op_redact_pii_runs_email_rule() {
        let _guard = OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let email_rule = sbproxy_security::pii::default_rules()
            .into_iter()
            .find(|r| r.name == "email")
            .expect("email is a built-in default rule");
        let pii_cfg = sbproxy_security::pii::PiiConfig {
            enabled: true,
            defaults: false,
            redact_request: false,
            redact_response: false,
            rules: vec![email_rule],
        };
        let pii = sbproxy_security::pii::PiiRedactor::from_config(&pii_cfg).expect("rule compiles");

        let _ = install_op_redact_config(OpRedactState {
            fields: Vec::new(),
            patterns: Vec::new(),
            proxy_pii: Some(pii),
            tenant_pii: std::collections::HashMap::new(),
            origin_pii: std::collections::HashMap::new(),
            tenant_fields: std::collections::HashMap::new(),
            tenant_patterns: std::collections::HashMap::new(),
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
        });
        let json = r#"{"freeform":"ping alice@example.com please"}"#;
        let out = apply_redaction(json, Sink::AccessLog);
        assert!(
            out.contains("[REDACTED:EMAIL]"),
            "operator PII pass missed email: {out}"
        );
        assert!(
            !out.contains("alice@example.com"),
            "raw email leaked through PII pass: {out}"
        );
        let _ = install_op_redact_config(OpRedactState::empty());
    }

    /// Helper for the tenant- / origin-scope tests below. Builds a
    /// `PiiRedactor` that runs exactly the named built-in rules.
    /// Panics on an unknown rule name so the test fixtures fail loud
    /// instead of silently dropping a rule.
    fn build_pii_for_test(rule_names: &[&str]) -> sbproxy_security::pii::PiiRedactor {
        let defaults = sbproxy_security::pii::default_rules();
        let mut selected = Vec::new();
        for want in rule_names {
            let r = defaults
                .iter()
                .find(|r| r.name.as_str() == *want)
                .unwrap_or_else(|| panic!("rule `{want}` is not a built-in default"))
                .clone();
            selected.push(r);
        }
        let cfg = sbproxy_security::pii::PiiConfig {
            enabled: true,
            defaults: false,
            redact_request: false,
            redact_response: false,
            rules: selected,
        };
        sbproxy_security::pii::PiiRedactor::from_config(&cfg).expect("rules compile")
    }

    /// WOR-1043 PR2: a tenant-scope `pii:` block overrides the
    /// proxy-scope decision. Proxy scope ships no PII pass; tenant
    /// `acme` enables the `email` rule. A record carrying
    /// `tenant_id = Some("acme")` must redact the email; a record at
    /// any other tenant must not (covered by
    /// `proxy_pii_isolated_from_other_tenant` below).
    #[test]
    fn tenant_pii_overrides_proxy_runs_email_rule() {
        let _guard = OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut tenant_pii: std::collections::HashMap<
            String,
            Option<sbproxy_security::pii::PiiRedactor>,
        > = std::collections::HashMap::new();
        tenant_pii.insert("acme".to_string(), Some(build_pii_for_test(&["email"])));

        let _ = install_op_redact_config(OpRedactState {
            fields: Vec::new(),
            patterns: Vec::new(),
            proxy_pii: None,
            tenant_pii,
            origin_pii: std::collections::HashMap::new(),
            tenant_fields: std::collections::HashMap::new(),
            tenant_patterns: std::collections::HashMap::new(),
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
        });

        let json = r#"{"freeform":"ping alice@example.com please"}"#;
        let out = apply_redaction_for(json, Sink::AccessLog, Some("acme"), None);
        assert!(
            out.contains("[REDACTED:EMAIL]"),
            "tenant-scope PII pass missed email: {out}"
        );
        assert!(
            !out.contains("alice@example.com"),
            "raw email leaked through tenant PII pass: {out}"
        );

        let _ = install_op_redact_config(OpRedactState::empty());
    }

    /// WOR-1043 PR2: a tenant-scope `pii:` block does NOT leak to a
    /// sibling tenant. Proxy scope is off; only tenant `acme` enables
    /// the `email` rule; a record at tenant `other` must keep its
    /// email verbatim.
    #[test]
    fn proxy_pii_isolated_from_other_tenant() {
        let _guard = OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut tenant_pii: std::collections::HashMap<
            String,
            Option<sbproxy_security::pii::PiiRedactor>,
        > = std::collections::HashMap::new();
        tenant_pii.insert("acme".to_string(), Some(build_pii_for_test(&["email"])));

        let _ = install_op_redact_config(OpRedactState {
            fields: Vec::new(),
            patterns: Vec::new(),
            proxy_pii: None,
            tenant_pii,
            origin_pii: std::collections::HashMap::new(),
            tenant_fields: std::collections::HashMap::new(),
            tenant_patterns: std::collections::HashMap::new(),
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
        });

        let json = r#"{"freeform":"ping alice@example.com please"}"#;
        let out = apply_redaction_for(json, Sink::AccessLog, Some("other"), None);
        assert!(
            !out.contains("[REDACTED:EMAIL]"),
            "sibling tenant should not have run PII pass: {out}"
        );
        assert!(
            out.contains("alice@example.com"),
            "raw email expected to remain at sibling tenant: {out}"
        );

        let _ = install_op_redact_config(OpRedactState::empty());
    }

    /// WOR-1043 PR3: an origin-scope `pii:` block extends the
    /// tenant-scope rule set. Tenant `acme` enables `email`; origin
    /// `api.acme.example.com` adds `credit_card`. A record at both
    /// scopes must redact both shapes.
    #[test]
    fn origin_pii_extends_tenant_rules() {
        let _guard = OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut tenant_pii: std::collections::HashMap<
            String,
            Option<sbproxy_security::pii::PiiRedactor>,
        > = std::collections::HashMap::new();
        tenant_pii.insert("acme".to_string(), Some(build_pii_for_test(&["email"])));
        let mut origin_pii: std::collections::HashMap<
            String,
            Option<sbproxy_security::pii::PiiRedactor>,
        > = std::collections::HashMap::new();
        origin_pii.insert(
            "api.acme.example.com".to_string(),
            Some(build_pii_for_test(&["email", "credit_card"])),
        );

        let _ = install_op_redact_config(OpRedactState {
            fields: Vec::new(),
            patterns: Vec::new(),
            proxy_pii: None,
            tenant_pii,
            origin_pii,
            tenant_fields: std::collections::HashMap::new(),
            tenant_patterns: std::collections::HashMap::new(),
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
        });

        let json = r#"{"freeform":"alice@example.com paid via 4111 1111 1111 1111 last week"}"#;
        let out = apply_redaction_for(
            json,
            Sink::AccessLog,
            Some("acme"),
            Some("api.acme.example.com"),
        );
        assert!(
            out.contains("[REDACTED:EMAIL]"),
            "origin-scope PII pass missed email: {out}"
        );
        assert!(
            out.contains("[REDACTED:CARD]"),
            "origin-scope PII pass missed credit card: {out}"
        );
        assert!(
            !out.contains("alice@example.com"),
            "raw email leaked: {out}"
        );
        assert!(
            !out.contains("4111 1111 1111 1111"),
            "raw credit card leaked: {out}"
        );

        let _ = install_op_redact_config(OpRedactState::empty());
    }

    /// WOR-1043 PR2: an explicit opt-out at tenant scope wins over a
    /// proxy-scope `enabled: true`. Proxy enables `email`; tenant
    /// `hipaa` stores `Some(None)` (the explicit-disable case). A
    /// record at tenant `hipaa` keeps its email verbatim; a record
    /// outside the tenant still gets redacted by the proxy default.
    #[test]
    fn pii_resolution_explicit_disable_at_tenant_overrides_proxy() {
        let _guard = OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let proxy_pii = build_pii_for_test(&["email"]);
        let mut tenant_pii: std::collections::HashMap<
            String,
            Option<sbproxy_security::pii::PiiRedactor>,
        > = std::collections::HashMap::new();
        tenant_pii.insert("hipaa".to_string(), None);

        let _ = install_op_redact_config(OpRedactState {
            fields: Vec::new(),
            patterns: Vec::new(),
            proxy_pii: Some(proxy_pii),
            tenant_pii,
            origin_pii: std::collections::HashMap::new(),
            tenant_fields: std::collections::HashMap::new(),
            tenant_patterns: std::collections::HashMap::new(),
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
        });

        let json = r#"{"freeform":"ping alice@example.com please"}"#;
        let at_hipaa = apply_redaction_for(json, Sink::AccessLog, Some("hipaa"), None);
        assert!(
            !at_hipaa.contains("[REDACTED:EMAIL]"),
            "tenant explicit-disable should have skipped the PII pass: {at_hipaa}"
        );
        assert!(
            at_hipaa.contains("alice@example.com"),
            "raw email expected at opted-out tenant: {at_hipaa}"
        );

        let at_default = apply_redaction_for(json, Sink::AccessLog, None, None);
        assert!(
            at_default.contains("[REDACTED:EMAIL]"),
            "proxy-scope default should still redact: {at_default}"
        );

        let _ = install_op_redact_config(OpRedactState::empty());
    }

    /// WOR-1042: a tenant-scope `fields:` entry adds to (does not
    /// replace) the proxy-scope denylist. Proxy adds `x-proxy-token`;
    /// tenant `acme` adds `x-acme-license`. A record at tenant `acme`
    /// redacts BOTH; a record at any other tenant only sees the
    /// proxy-scope entry.
    #[test]
    fn tenant_fields_extend_proxy_fields_additively() {
        let _guard = OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut tenant_fields: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        // Tenant entry MUST include the proxy-scope set verbatim plus
        // its own additions; that is what the lifecycle composer does
        // at install time. The resolver returns this set as-is. The
        // field names below avoid the built-in `_token` / `_key`
        // suffix matchers so the OPERATOR_FIELD marker fires (rather
        // than the built-in API_KEY marker).
        tenant_fields.insert(
            "acme".to_string(),
            vec!["x-internal-acct".to_string(), "x-acme-license".to_string()],
        );

        let _ = install_op_redact_config(OpRedactState {
            fields: vec!["x-internal-acct".to_string()],
            patterns: Vec::new(),
            proxy_pii: None,
            tenant_pii: std::collections::HashMap::new(),
            origin_pii: std::collections::HashMap::new(),
            tenant_fields,
            tenant_patterns: std::collections::HashMap::new(),
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
        });

        let json = r#"{"x-acme-license":"a-l-1","x-internal-acct":"i-a-1","keep":"me"}"#;
        let at_acme = apply_redaction_for(json, Sink::AccessLog, Some("acme"), None);
        assert!(
            at_acme.contains("[REDACTED:OPERATOR_FIELD]"),
            "tenant-scope acme fields not honoured: {at_acme}"
        );
        // Both denylisted keys carry the OPERATOR_FIELD marker.
        assert_eq!(at_acme.matches("[REDACTED:OPERATOR_FIELD]").count(), 2);

        let at_other = apply_redaction_for(json, Sink::AccessLog, Some("other"), None);
        // Tenant `other` has no entry, falls through to proxy-scope.
        // Only `x-internal-acct` denylisted; `x-acme-license` passes.
        assert_eq!(at_other.matches("[REDACTED:OPERATOR_FIELD]").count(), 1);
        assert!(
            at_other.contains("\"x-acme-license\":\"a-l-1\""),
            "tenant `other` should NOT redact acme fields: {at_other}"
        );

        let _ = install_op_redact_config(OpRedactState::empty());
    }

    /// WOR-1042: a tenant-scope `patterns:` entry composes on top of
    /// the proxy patterns; tenant `disable:` opts out of a proxy
    /// pattern by name. The composer lives in `lifecycle.rs`; this
    /// test asserts the resolver returns the composed slice.
    #[test]
    fn tenant_patterns_compose_with_disable() {
        let _guard = OP_REDACT_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let proxy_patterns = vec![
            (
                regex::Regex::new(r"acct-[a-z0-9]+").expect("compiles"),
                "[REDACTED:ACCOUNT]".to_string(),
            ),
            (
                regex::Regex::new(r"cust-[a-z0-9]+").expect("compiles"),
                "[REDACTED:CUSTOMER]".to_string(),
            ),
        ];
        // Tenant `hipaa` opts out of CUSTOMER (e.g. compliance reason)
        // and adds its own MRN pattern. The lifecycle composer would
        // emit this; we hand-roll it here.
        let mut tenant_patterns: std::collections::HashMap<String, Vec<(regex::Regex, String)>> =
            std::collections::HashMap::new();
        tenant_patterns.insert(
            "hipaa".to_string(),
            vec![
                (
                    regex::Regex::new(r"acct-[a-z0-9]+").expect("compiles"),
                    "[REDACTED:ACCOUNT]".to_string(),
                ),
                (
                    regex::Regex::new(r"mrn-[0-9]+").expect("compiles"),
                    "[REDACTED:MRN]".to_string(),
                ),
            ],
        );

        let _ = install_op_redact_config(OpRedactState {
            fields: Vec::new(),
            patterns: proxy_patterns,
            proxy_pii: None,
            tenant_pii: std::collections::HashMap::new(),
            origin_pii: std::collections::HashMap::new(),
            tenant_fields: std::collections::HashMap::new(),
            tenant_patterns,
            origin_fields: std::collections::HashMap::new(),
            origin_patterns: std::collections::HashMap::new(),
        });

        let json = r#"{"body":"saw acct-abc123 and cust-foo and mrn-987 today"}"#;
        let at_hipaa = apply_redaction_for(json, Sink::AccessLog, Some("hipaa"), None);
        assert!(
            at_hipaa.contains("[REDACTED:ACCOUNT]"),
            "tenant `hipaa` lost the inherited ACCOUNT pattern: {at_hipaa}"
        );
        assert!(
            at_hipaa.contains("[REDACTED:MRN]"),
            "tenant `hipaa` did not pick up its own MRN pattern: {at_hipaa}"
        );
        assert!(
            at_hipaa.contains("cust-foo"),
            "tenant `hipaa` disable: should have dropped CUSTOMER from the composed set: {at_hipaa}"
        );

        let at_other = apply_redaction_for(json, Sink::AccessLog, Some("other"), None);
        // Tenant `other` falls back to proxy-scope: both ACCOUNT +
        // CUSTOMER fire, MRN does not.
        assert!(at_other.contains("[REDACTED:ACCOUNT]"));
        assert!(at_other.contains("[REDACTED:CUSTOMER]"));
        assert!(at_other.contains("mrn-987"));

        let _ = install_op_redact_config(OpRedactState::empty());
    }

    // --- Redaction ---

    #[test]
    fn the_default_sidecar_header_is_redacted() {
        set_swept_header_names(vec!["x-sb-api".to_string()]);
        let mut value = serde_json::json!({"x-sb-api": "sbp_secret_value"});
        redact_value(&mut value, Sink::AccessLog, &[]);
        assert_eq!(value["x-sb-api"], "[REDACTED:API_KEY]");
        set_swept_header_names(Vec::new());
    }

    #[test]
    fn a_custom_sweep_header_is_redacted_without_editing_any_denylist() {
        // The trap this closes. `x-tool-auth` ends in none of -key, -secret or
        // -token, so before the sweep list drove redaction an operator who
        // configured it got their live key written to the access log.
        let mut before = serde_json::json!({"x-tool-auth": "sbp_secret_value"});
        redact_value(&mut before, Sink::AccessLog, &[]);
        assert_eq!(
            before["x-tool-auth"], "sbp_secret_value",
            "precondition: nothing else redacts this name"
        );

        set_swept_header_names(vec!["x-tool-auth".to_string()]);
        let mut after = serde_json::json!({"x-tool-auth": "sbp_secret_value"});
        redact_value(&mut after, Sink::AccessLog, &[]);
        assert_eq!(after["x-tool-auth"], "[REDACTED:API_KEY]");
        set_swept_header_names(Vec::new());
    }

    #[test]
    fn sweep_header_names_are_matched_case_insensitively() {
        set_swept_header_names(vec!["  X-Tool-Auth ".to_string()]);
        assert_eq!(*swept_header_names(), vec!["x-tool-auth".to_string()]);
        let mut value = serde_json::json!({"x-tool-auth": "sbp_secret_value"});
        redact_value(&mut value, Sink::AccessLog, &[]);
        assert_eq!(value["x-tool-auth"], "[REDACTED:API_KEY]");
        set_swept_header_names(Vec::new());
    }

    // --- WOR-2289: bundle secret_vars/masked_vars field-key redaction ---

    #[test]
    fn a_bundle_declared_secret_var_name_is_redacted_without_editing_any_denylist() {
        // The trap this closes, mirroring the sweep-header test above:
        // an extension author's `customer_reference` var name matches
        // none of the built-in suffix rules (it is not `*_key`,
        // `*_secret`, or `*_token`), so before a bundle could register
        // its own names, a field with that exact key sailed through
        // unredacted the moment anything logged it by key.
        let mut before = serde_json::json!({"customer_reference": "sbp_secret_value"});
        redact_value(&mut before, Sink::AccessLog, &[]);
        assert_eq!(
            before["customer_reference"], "sbp_secret_value",
            "precondition: nothing else redacts this name"
        );

        set_bundle_secret_field_names(vec!["customer_reference".to_string()]);
        let mut after = serde_json::json!({"customer_reference": "sbp_secret_value"});
        redact_value(&mut after, Sink::AccessLog, &[]);
        assert_eq!(after["customer_reference"], "[REDACTED:BUNDLE_SECRET_VAR]");
        set_bundle_secret_field_names(Vec::new());
    }

    #[test]
    fn bundle_secret_field_names_are_matched_case_insensitively() {
        set_bundle_secret_field_names(vec!["  Tenant_ID  ".to_string()]);
        assert_eq!(*bundle_secret_field_names(), vec!["tenant_id".to_string()]);
        let mut value = serde_json::json!({"tenant_id": "acme-corp"});
        redact_value(&mut value, Sink::AccessLog, &[]);
        assert_eq!(value["tenant_id"], "[REDACTED:BUNDLE_SECRET_VAR]");
        set_bundle_secret_field_names(Vec::new());
    }

    #[test]
    fn registering_a_new_bundle_candidate_replaces_the_previous_names() {
        set_bundle_secret_field_names(vec!["old_secret_var".to_string()]);
        set_bundle_secret_field_names(vec!["new_secret_var".to_string()]);

        let mut value =
            serde_json::json!({"old_secret_var": "still-here", "new_secret_var": "live"});
        redact_value(&mut value, Sink::AccessLog, &[]);

        assert_eq!(
            value["old_secret_var"], "still-here",
            "a reload that drops a bundle must also drop the names it declared"
        );
        assert_eq!(value["new_secret_var"], "[REDACTED:BUNDLE_SECRET_VAR]");
        set_bundle_secret_field_names(Vec::new());
    }

    #[test]
    fn redaction_replaces_authorization_header() {
        let json = r#"{"headers":{"authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.veryreallong"}}"#;
        let out = apply_redaction(json, Sink::AccessLog);
        assert!(out.contains("[REDACTED:AUTHORIZATION]"), "got: {}", out);
        assert!(!out.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    #[test]
    fn redaction_applies_to_every_sink() {
        let json =
            r#"{"headers":{"authorization":"Bearer secret-bearer-eyJsdkjfsd-lots-of-chars"}}"#;
        for sink in [
            Sink::AccessLog,
            Sink::ErrorLog,
            Sink::AuditLog,
            Sink::TraceExporter,
            Sink::External,
        ] {
            let out = apply_redaction(json, sink);
            assert!(
                out.contains("[REDACTED:"),
                "redaction missing for sink {:?}: {}",
                sink,
                out
            );
            assert!(
                !out.contains("secret-bearer-eyJsdkjfsd"),
                "raw bearer leaked on sink {:?}: {}",
                sink,
                out
            );
        }
    }

    #[test]
    fn redaction_external_drops_ja3() {
        let json = r#"{"ja3":"771,49195-49199-..."}"#;
        let internal = apply_redaction(json, Sink::AccessLog);
        let external = apply_redaction(json, Sink::External);
        assert!(
            internal.contains("771,49195"),
            "internal sink should keep JA3"
        );
        assert!(
            external.contains("[REDACTED:JA_FINGERPRINT]"),
            "external sink should redact JA3: {}",
            external
        );
    }

    #[test]
    fn redaction_redacts_nested_secret_keys() {
        let json = r#"{"a":{"b":{"stripe_sk":"sk_live_abcdef"}}}"#;
        let out = apply_redaction(json, Sink::AuditLog);
        assert!(out.contains("[REDACTED:STRIPE_SECRET_KEY]"));
        assert!(!out.contains("sk_live_abcdef"));
    }

    #[test]
    fn redaction_pattern_pass_catches_bearer_in_value() {
        // Value-based redaction kicks in even when the JSON key isn't
        // on the denylist (defence in depth).
        let json = r#"{"freeform":"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.x"}"#;
        let out = apply_redaction(json, Sink::AccessLog);
        assert!(out.contains("Bearer [REDACTED]"));
    }

    // --- Sampling ---

    #[test]
    fn audit_events_never_sampled() {
        let cfg = SamplingConfig {
            info: 0.0,
            debug: 0.0,
            trace: 0.0,
        };
        for i in 0..50 {
            let rid = format!("req-{i}");
            assert!(should_sample(
                &cfg,
                LogLevel::Info,
                EventType::AuditEmit,
                Some(&rid)
            ));
        }
    }

    #[test]
    fn sampling_is_deterministic_per_request_id() {
        let cfg = SamplingConfig {
            info: 0.5,
            debug: 0.5,
            trace: 0.5,
        };
        let rid = "01HZX7";
        let first = should_sample(&cfg, LogLevel::Info, EventType::RequestCompleted, Some(rid));
        for _ in 0..20 {
            assert_eq!(
                should_sample(&cfg, LogLevel::Info, EventType::RequestCompleted, Some(rid)),
                first
            );
        }
    }
}
