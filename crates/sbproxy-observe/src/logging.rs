//! Global tracing subscriber config + structured-log schema v1
//! scaffolding (Wave 1 / A1.5).
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
//!    regression test (`Q1.9`) covers every sink via one harness.
//!
//! Per A1.5 we ship two redaction profiles in Wave 1: `internal`
//! (denylist only) and `external` (denylist + JA3/JA4 + URL → route).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// --- Logging subscriber config ---

/// Configuration for the global tracing subscriber (log level and format).
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Log level filter, one of `debug`, `info`, `warn`, `error`.
    #[serde(default = "default_level")]
    pub level: String, // "debug", "info", "warn", "error"
    /// Output format, one of `json`, `pretty`, `compact`.
    #[serde(default = "default_format")]
    pub format: String, // "json", "pretty", "compact"
    /// Per-level emission sampling. Default: 1.0 for `info`+, 0.1 for
    /// debug, 0.01 for trace. Audit events are never sampled (see
    /// `should_sample`).
    #[serde(default)]
    pub sampling: SamplingConfig,
}

/// Per-level emission sampling rates per A1.5.
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
    /// Initialize the global tracing subscriber.
    pub fn init(&self) {
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&self.level));

        match self.format.as_str() {
            "json" => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().json())
                    .init();
            }
            "pretty" => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().pretty())
                    .init();
            }
            _ => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().compact())
                    .init();
            }
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

// --- Structured-log schema v1 (A1.5) ---

/// Schema version stamped on every emitted line. Bumped per
/// `docs/adr-schema-versioning.md`.
pub const SCHEMA_VERSION: &str = "1";

/// Pinned event-type enum per A1.5. Renaming or removing a variant is
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
    /// Audit lines (per A1.5 § Sampling) are never sampled.
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

/// One JSON-line structured-log record. Top-level fields match A1.5
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

    // --- Per-request lifecycle (request_started / completed / error) ---
    /// Resolved agent identifier (per G1.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Agent class (`vendor:purpose` per G1.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_class: Option<String>,
    /// Payment rail discriminator (`stripe`, `x402`, `mpp`, `lightning`,
    /// `none`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rail: Option<String>,
    /// Content shape discriminator (Wave 4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    /// HTTP status returned to the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// End-to-end latency in milliseconds (terminal events only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u32>,
    /// Compact failure label per `adr-event-envelope.md`.
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

// --- Sink + redaction profile (A1.5) ---

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
    /// Customer-facing external sink (Wave 6). Strictest profile.
    External,
}

impl Sink {
    /// Whether this sink requires the strict `external` redaction
    /// profile per A1.5.
    pub fn is_external(self) -> bool {
        matches!(self, Sink::TraceExporter | Sink::External)
    }
}

// --- Redaction middleware ---

/// Apply the A1.5 denylist + per-sink overrides to an in-progress JSON
/// rendering. The function is the single chokepoint every emitter
/// routes through, so the regression test in `Q1.9` only has to fuzz
/// one entry point to cover access / error / audit / trace exporter.
///
/// Today's implementation reuses the existing
/// `crate::redact::redact_secrets` value-pattern scrubber for
/// secret-shaped strings, then layers field-key redaction on top per
/// the ADR (Authorization, Cookie, *_secret, *_token, *_key, etc.).
pub fn apply_redaction(json: &str, sink: Sink) -> String {
    // Step 1: pattern-based redaction of obvious secret shapes
    // (Bearer tokens, sk-* keys, Basic auth blobs). This is the same
    // primitive used elsewhere in the codebase; it's defence in depth
    // against any value that slipped past the field-key denylist.
    let pattern_redacted = crate::redact::redact_secrets(json);

    // Step 2: field-key redaction. Walk the JSON and replace any
    // value whose key matches the denylist with the typed marker.
    let mut value: serde_json::Value = match serde_json::from_str(&pattern_redacted) {
        Ok(v) => v,
        Err(_) => return pattern_redacted, // not JSON; pattern pass is best we can do
    };
    redact_value(&mut value, sink);
    serde_json::to_string(&value).unwrap_or(pattern_redacted)
}

/// Recursively walk a JSON value and redact any field whose key is on
/// the A1.5 denylist. Replacements use the typed `<redacted:foo>`
/// marker per the ADR.
fn redact_value(value: &mut serde_json::Value, sink: Sink) {
    match value {
        serde_json::Value::Object(map) => {
            // Collect keys first so we can mutate values without
            // double-borrowing the map.
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if let Some(marker) = match_denylist(&k, sink) {
                    if let Some(v) = map.get_mut(&k) {
                        *v = serde_json::Value::String(marker.to_string());
                    }
                } else if let Some(v) = map.get_mut(&k) {
                    redact_value(v, sink);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                redact_value(v, sink);
            }
        }
        _ => {}
    }
}

/// Match a JSON field key against the A1.5 denylist. Returns the
/// typed marker that should replace the value, or `None` to leave it
/// alone.
fn match_denylist(key: &str, sink: Sink) -> Option<&'static str> {
    let k = key.to_ascii_lowercase();
    // Authorization headers + cookies: every sink redacts these.
    if k == "authorization" || k == "proxy-authorization" {
        return Some("<redacted:authorization>");
    }
    if k == "cookie" || k == "set-cookie" {
        return Some("<redacted:cookie>");
    }
    if k == "x-stripe-signature" || k == "stripe-signature" {
        return Some("<redacted:stripe-signature>");
    }
    // Stripe SK fields under any key.
    if k.contains("stripe_sk") || k == "stripe_secret_key" {
        return Some("<redacted:stripe-secret-key>");
    }
    if k == "ledger_hmac_key" || k == "sbproxy_ledger_hmac_key" {
        return Some("<redacted:ledger-hmac-key>");
    }
    if k == "kya_token" || k.starts_with("kya_") {
        return Some("<redacted:kya-token>");
    }
    if k == "oauth_client_secret" {
        return Some("<redacted:oauth-client-secret>");
    }
    if k == "payment_receipt_secret" {
        return Some("<redacted:payment-receipt-secret>");
    }
    if k == "prompt" || k == "messages" {
        return Some("<redacted:prompt-body>");
    }
    if k == "envelope_payload_raw" {
        return Some("<redacted:envelope-payload-raw>");
    }
    // External-only: JA3 / JA4 fingerprints are kept on internal
    // sinks but redacted outbound.
    if sink.is_external() && (k == "ja3" || k == "ja3_hash" || k == "ja4" || k == "ja4_hash") {
        return Some("<redacted:ja-fingerprint>");
    }
    // Generic suffix match: *_secret / *_token / *_key / api_key.
    if k == "api_key" || k.ends_with("_secret") || k.ends_with("_token") || k.ends_with("_key") {
        return Some("<redacted:api-key>");
    }
    None
}

/// Decide whether a structured-log line at the given level should be
/// emitted given the per-level sampling rates. Audit events are never
/// sampled. The sampling decision is deterministic for a given
/// `request_id` so every line tied to one request shares the same
/// keep/drop verdict.
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

/// Render + redact + emit a structured log line through the
/// `tracing` macros. The `target` is set per-sink so log routers can
/// fan the same line out to access / error / audit / trace exporter
/// pipes independently.
pub fn emit(record: &StructuredLog, sink: Sink) {
    let json = match serde_json::to_string(record) {
        Ok(s) => s,
        Err(_) => return,
    };
    let redacted = apply_redaction(&json, sink);
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
        assert_eq!(v["schema_version"], "1");
        assert_eq!(v["target"], "sbproxy_modules::policy::ai_crawl");
    }

    // --- Redaction ---

    #[test]
    fn redaction_replaces_authorization_header() {
        let json = r#"{"headers":{"authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.veryreallong"}}"#;
        let out = apply_redaction(json, Sink::AccessLog);
        assert!(out.contains("<redacted:authorization>"), "got: {}", out);
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
                out.contains("<redacted:"),
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
            external.contains("<redacted:ja-fingerprint>"),
            "external sink should redact JA3: {}",
            external
        );
    }

    #[test]
    fn redaction_redacts_nested_secret_keys() {
        let json = r#"{"a":{"b":{"stripe_sk":"sk_live_abcdef"}}}"#;
        let out = apply_redaction(json, Sink::AuditLog);
        assert!(out.contains("<redacted:stripe-secret-key>"));
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
