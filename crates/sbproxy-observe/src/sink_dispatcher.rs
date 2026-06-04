//! WOR-1045 PR2: multi-writer sink dispatcher.
//!
//! Replaces the single-subscriber model in [`crate::logging::emit`]
//! with a fan-out. Every emitted [`StructuredLog`] flows through one
//! `apply_redaction_for` pass per matching sink, then each sink's
//! [`SinkOutput`] writer ships the line to its declared destination
//! (stdout, stderr, file, OTLP, ...).
//!
//! ## Scopes
//!
//! Three scope kinds gate which records reach which sinks:
//!
//! * [`SinkScope::Proxy`] receives every record. The default for
//!   `proxy.observability.log.sinks:` entries.
//! * [`SinkScope::Tenant`] receives only records whose
//!   `StructuredLog.tenant_id` matches the tenant id carried in the
//!   variant. Cross-tenant lines never reach a tenant-scoped sink.
//! * [`SinkScope::Origin`] receives only records whose
//!   `StructuredLog.route` matches the hostname carried in the
//!   variant. Matches the same hostname-keyed route string the PII
//!   resolver consumes today.
//!
//! ## Target
//!
//! Each sink also carries a [`crate::logging::Sink`] target so the
//! dispatcher can short-circuit when the emitting site declares a
//! sink the operator did not subscribe to. A sink that subscribes to
//! [`crate::logging::Sink::AccessLog`] never sees an audit record.
//!
//! ## Fallback
//!
//! When no dispatcher is installed (boot time, tests, single-tenant
//! deployments without a sinks block), the legacy `tracing::*!`
//! emission path keeps driving stdout. The fan-out lights up only
//! when [`install_sink_dispatcher`] runs.

use std::sync::{Arc, OnceLock, RwLock};

use crate::logging::{apply_redaction_for, LogLevel, Sink, StructuredLog};

/// Wire format for a sink. Matches the proxy-scope
/// `observability.log.format` choices so an operator can override the
/// default at the sink granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SinkFormat {
    /// Compact JSON: one line per record, no whitespace. Default.
    #[default]
    Compact,
    /// Multi-line indented JSON. Useful for local development.
    Pretty,
    /// Strict JSON. Today identical to `Compact` (the renderer is
    /// already JSON).
    Json,
}

impl SinkFormat {
    /// Render a `(record, redacted_json)` pair into the wire format.
    /// Today every variant returns the redacted JSON unchanged because
    /// the emitter is JSON-only; pretty-printing pretty-formats the
    /// JSON value, and the compact / json paths return the line as
    /// emitted.
    pub fn render(self, redacted_json: &str) -> String {
        match self {
            SinkFormat::Pretty => {
                // Re-parse + pretty-print only when feasible; on a
                // parse failure (the redaction pass may produce a
                // non-JSON string when patterns rewrite the rendered
                // form) fall back to the compact text.
                serde_json::from_str::<serde_json::Value>(redacted_json)
                    .ok()
                    .and_then(|v| serde_json::to_string_pretty(&v).ok())
                    .unwrap_or_else(|| redacted_json.to_string())
            }
            SinkFormat::Compact | SinkFormat::Json => redacted_json.to_string(),
        }
    }
}

/// Redaction profile. `Internal` keeps JA3/JA4 fingerprints and raw
/// query strings (the default for proxy-scope sinks); `External`
/// strips them (the default for tenant- and origin-scoped sinks where
/// the downstream backend is outside the operator's trust boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Internal sinks: full denylist redaction; JA3 / JA4 kept.
    Internal,
    /// External sinks: stricter profile; JA3 / JA4 dropped + URLs
    /// folded into route.
    External,
}

impl Profile {
    /// Map the profile onto the existing [`Sink`] sink-side decision.
    /// The redaction helpers downstream only branch on the
    /// internal-vs-external bit; the [`Sink`] discriminator carries
    /// other information today (which channel a line came from) which
    /// we keep separate.
    pub fn redaction_sink(self, fallback: Sink) -> Sink {
        match self {
            // External profile forces the strictest redaction path
            // regardless of the originating channel.
            Profile::External => Sink::External,
            // Internal sinks keep their channel's profile so audit /
            // access / error continue to see the same redaction shape
            // they got before the fan-out landed.
            Profile::Internal => fallback,
        }
    }
}

/// Scope filter for a [`CompiledSink`]. Each scope kind decides which
/// records the sink subscribes to.
#[derive(Debug, Clone)]
pub enum SinkScope {
    /// Receives every record.
    Proxy,
    /// Receives only records whose `tenant_id` matches this string.
    Tenant(String),
    /// Receives only records whose `route` matches this string.
    Origin(String),
}

impl SinkScope {
    /// Return `true` when this scope subscribes to the record. Proxy
    /// scope is unconditional; tenant scope requires a `Some` match;
    /// origin scope requires a `Some` match on the stamped route.
    pub fn matches(&self, record: &StructuredLog) -> bool {
        match self {
            SinkScope::Proxy => true,
            SinkScope::Tenant(t) => record.tenant_id.as_deref() == Some(t.as_str()),
            SinkScope::Origin(o) => record.route.as_deref() == Some(o.as_str()),
        }
    }
}

/// Writer trait every [`CompiledSink`] is parameterised on. The
/// dispatcher hands the rendered, redacted line to `write_line`; the
/// implementor is responsible for buffering, batching, or shipping it.
pub trait SinkOutput: Send + Sync {
    /// Write one structured-log line to the underlying sink. The line
    /// arrives without a trailing newline; implementors decide whether
    /// to add one (stdout / stderr / file all do; OTLP does not).
    fn write_line(&self, line: &str);

    /// Flush any buffered writes. Default no-op for synchronous sinks;
    /// the OTLP sink overrides this to drain the batch processor on
    /// SIGHUP / shutdown.
    fn flush(&self) {}
}

/// One configured sink. The dispatcher walks the live `Vec<CompiledSink>`
/// per emit and writes every matching record. Construction is the
/// operator's wiring (config-time) plus the dispatcher's installation
/// (boot or reload time); the hot path is immutable.
pub struct CompiledSink {
    /// Operator-supplied name (for diagnostics + metrics).
    pub name: String,
    /// Scope filter. Decides whether a record reaches this sink at all.
    pub scope: SinkScope,
    /// Channel discriminator. Records emitted to a different channel
    /// are skipped.
    pub target: Sink,
    /// Wire format. Picked from the parent's `format:` value when
    /// the operator does not override at the sink granularity.
    pub format: SinkFormat,
    /// Redaction profile. Tenant + origin scopes default to
    /// [`Profile::External`].
    pub profile: Profile,
    /// Writer implementation.
    pub output: Box<dyn SinkOutput>,
}

/// Process-wide dispatcher. Owns the live sink list and a counter for
/// diagnostics. Installed at config compile and atomic-swapped on
/// reload via [`install_sink_dispatcher`].
pub struct SinkDispatcher {
    sinks: Vec<CompiledSink>,
}

impl SinkDispatcher {
    /// Build a dispatcher from a list of compiled sinks. The order is
    /// preserved so dashboards that index sinks by position keep the
    /// same column ordering across reloads as long as the YAML order
    /// is stable.
    pub fn new(sinks: Vec<CompiledSink>) -> Self {
        Self { sinks }
    }

    /// Empty dispatcher. Useful in tests that want to short-circuit
    /// the fallback path without installing real outputs.
    pub fn empty() -> Self {
        Self { sinks: Vec::new() }
    }

    /// Number of configured sinks. Diagnostic accessor used by the
    /// startup log line.
    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    /// Whether any sink is installed.
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Dispatch a record to every subscribed sink. Records whose
    /// scope or target does not match a given sink are skipped
    /// without rendering. The per-sink redaction pass runs once per
    /// matching sink because tenant- and origin-scoped sinks may
    /// resolve a different PII rule set than the proxy scope.
    pub fn dispatch(&self, record: &StructuredLog, sink: Sink) {
        // Pre-serialise once. Each sink runs its own redaction pass
        // because the PII resolver picks a different rule set per
        // tenant + origin pair; the field-key + regex passes are
        // tenant-agnostic but cheap so we keep them inside the per-sink
        // helper rather than caching by `(tenant, route)`.
        let raw_json = match serde_json::to_string(record) {
            Ok(s) => s,
            Err(_) => return,
        };
        for s in &self.sinks {
            if s.target != sink {
                continue;
            }
            if !s.scope.matches(record) {
                continue;
            }
            let redaction_sink = s.profile.redaction_sink(sink);
            let redacted = apply_redaction_for(
                &raw_json,
                redaction_sink,
                record.tenant_id.as_deref(),
                record.route.as_deref(),
            );
            let line = s.format.render(&redacted);
            s.output.write_line(&line);
        }
    }

    /// Flush every sink's writer. Called on SIGHUP, on reload, and on
    /// shutdown so the OTLP batch processor drains.
    pub fn flush_all(&self) {
        for s in &self.sinks {
            s.output.flush();
        }
    }
}

static SINK_DISPATCHER: OnceLock<RwLock<Arc<SinkDispatcher>>> = OnceLock::new();

fn dispatcher_lock() -> &'static RwLock<Arc<SinkDispatcher>> {
    SINK_DISPATCHER.get_or_init(|| RwLock::new(Arc::new(SinkDispatcher::empty())))
}

/// Install (or replace) the process-wide sink dispatcher. Returns
/// `true` on a successful swap. The hot-emit path reads the dispatcher
/// behind a `RwLock<Arc<>>` so reads never block on a reload's writer.
pub fn install_sink_dispatcher(dispatcher: SinkDispatcher) -> bool {
    let lock = dispatcher_lock();
    if let Ok(mut guard) = lock.write() {
        *guard = Arc::new(dispatcher);
        return true;
    }
    false
}

/// WOR-1102: report whether the sink-dispatcher lock is usable.
///
/// Returns `false` only when the dispatcher slot has been initialised
/// but its `RwLock` is poisoned (a sink panicked while holding the
/// lock), which means the hot-emit path can no longer read the
/// dispatcher and telemetry export is effectively down. An
/// uninitialised slot (boot time, a config with no sinks) returns
/// `true`: that is a valid state, not a failure. The readiness probe
/// in [`crate::health`] consults this so a poisoned dispatcher drains
/// the pod instead of silently black-holing telemetry.
pub fn sink_dispatcher_healthy() -> bool {
    match SINK_DISPATCHER.get() {
        None => true,
        Some(lock) => lock.read().is_ok(),
    }
}

/// Read the current dispatcher. Returns `Some(arc)` when at least one
/// sink is installed; returns `None` when the dispatcher slot is
/// empty (boot time, tests, no sinks block). The [`crate::logging::emit`]
/// path reads this and falls back to the legacy `tracing::*!` macros
/// when `None`.
pub fn current_sink_dispatcher() -> Option<Arc<SinkDispatcher>> {
    let lock = SINK_DISPATCHER.get()?;
    let arc = lock.read().ok()?;
    if arc.is_empty() {
        None
    } else {
        Some(arc.clone())
    }
}

/// Reset the dispatcher slot to empty. Used by tests that install a
/// fixture dispatcher and need to restore the default fallback path
/// before the next test runs.
pub fn reset_sink_dispatcher_for_test() {
    let _ = install_sink_dispatcher(SinkDispatcher::empty());
}

/// Map an [`crate::logging::LogLevel`] onto the OTLP severity number
/// the WOR-1046 exporter consumes. Exposed at module scope so tests
/// + the OTLP wrapper see the same canonical mapping.
pub const fn otlp_severity_number(level: LogLevel) -> u8 {
    match level {
        LogLevel::Trace => 1,
        LogLevel::Debug => 5,
        LogLevel::Info => 9,
        LogLevel::Warn => 13,
        LogLevel::Error | LogLevel::Fatal => 17,
    }
}

// --- Built-in writers ---

/// Writer that locks the process [`std::io::Stdout`] per line.
pub struct StdoutSink;

impl SinkOutput for StdoutSink {
    fn write_line(&self, line: &str) {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut h = stdout.lock();
        let _ = writeln!(h, "{line}");
    }
}

/// Writer that locks the process [`std::io::Stderr`] per line.
pub struct StderrSink;

impl SinkOutput for StderrSink {
    fn write_line(&self, line: &str) {
        use std::io::Write;
        let stderr = std::io::stderr();
        let mut h = stderr.lock();
        let _ = writeln!(h, "{line}");
    }
}

/// Writer that appends to a file, rotating with the access-log
/// rotation stack from [`crate::access_log`]. The seam reuses the
/// shared `rotate_log_file` + `gzip_log_file` helpers exported from
/// the access-log module so a single test suite covers rotation +
/// gzip across both surfaces.
pub struct FileSink {
    /// Output path. The parent directory must exist.
    pub path: std::path::PathBuf,
    /// Max active-file size before rotation, in bytes.
    pub max_size_bytes: u64,
    /// Number of rotated backups to keep.
    pub max_backups: usize,
    /// Whether to gzip rotated backups.
    pub compress: bool,
    /// Mutex serialising rotation + append; per-write locking is light
    /// because the write itself is one `writeln!`.
    pub guard: std::sync::Mutex<()>,
}

impl FileSink {
    /// Build a `FileSink` with sensible defaults: 100 MiB rotation,
    /// 7 backups, gzip compression. The caller can override any field
    /// after construction.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_size_bytes: 100 * 1024 * 1024,
            max_backups: 7,
            compress: true,
            guard: std::sync::Mutex::new(()),
        }
    }
}

impl SinkOutput for FileSink {
    fn write_line(&self, line: &str) {
        use std::io::Write;
        let _g = self.guard.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(parent) = self.path.parent() {
            // WOR-1100: a failed mkdir means the subsequent append also
            // fails and the log line is silently lost. Count + log it
            // so the blackhole is visible.
            if let Err(e) = std::fs::create_dir_all(parent) {
                crate::metrics::record_telemetry_dropped("file_sink", "mkdir_failed");
                tracing::warn!(
                    path = %parent.display(),
                    error = %e,
                    "file sink: could not create parent directory; log line dropped"
                );
            }
        }
        // Rotate before the append when the active file has reached
        // the configured threshold.
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() >= self.max_size_bytes.max(1) {
                if let Err(e) =
                    crate::access_log::rotate_log_file(&self.path, self.max_backups, self.compress)
                {
                    // Don't abort the emit on a rotation failure;
                    // tracing the error is enough.
                    tracing::warn!(
                        path = %self.path.display(),
                        error = %e,
                        "file sink rotation failed; appending without rotation"
                    );
                }
            }
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut f) => {
                let _ = writeln!(f, "{line}");
            }
            Err(e) => {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "file sink append failed; dropping line"
                );
            }
        }
    }
}

/// In-memory writer used by tests. Stores each emitted line in a
/// `Vec<String>` for assertions.
#[cfg(test)]
pub struct VecSink {
    /// The captured lines.
    pub lines: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl Default for VecSink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl VecSink {
    /// Build an empty vector-backed sink.
    pub fn new() -> Self {
        Self {
            lines: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Snapshot of the captured lines.
    pub fn snapshot(&self) -> Vec<String> {
        self.lines.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(test)]
impl SinkOutput for VecSink {
    fn write_line(&self, line: &str) {
        self.lines
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(line.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{EventType, LogLevel, StructuredLog};

    /// Serialise the dispatcher tests because they swap a
    /// process-global slot. Each test installs its own dispatcher,
    /// asserts, then calls `reset_sink_dispatcher_for_test` so a
    /// sibling test does not see leftover state.
    static DISPATCHER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn record_for_test(tenant: Option<&str>, route: Option<&str>) -> StructuredLog {
        let mut r = StructuredLog::new(
            LogLevel::Info,
            "request completed",
            EventType::RequestCompleted,
        );
        r.target = "test".to_string();
        r.tenant_id = tenant.map(|s| s.to_string());
        r.route = route.map(|s| s.to_string());
        r
    }

    fn vec_sink_arc() -> Arc<VecSink> {
        Arc::new(VecSink::new())
    }

    fn proxy_compiled(name: &str, output: Arc<VecSink>) -> CompiledSink {
        struct ArcVec(Arc<VecSink>);
        impl SinkOutput for ArcVec {
            fn write_line(&self, line: &str) {
                self.0.write_line(line);
            }
        }
        CompiledSink {
            name: name.to_string(),
            scope: SinkScope::Proxy,
            target: Sink::AccessLog,
            format: SinkFormat::Compact,
            profile: Profile::Internal,
            output: Box::new(ArcVec(output)),
        }
    }

    fn tenant_compiled(name: &str, tenant: &str, output: Arc<VecSink>) -> CompiledSink {
        struct ArcVec(Arc<VecSink>);
        impl SinkOutput for ArcVec {
            fn write_line(&self, line: &str) {
                self.0.write_line(line);
            }
        }
        CompiledSink {
            name: name.to_string(),
            scope: SinkScope::Tenant(tenant.to_string()),
            target: Sink::AccessLog,
            format: SinkFormat::Compact,
            profile: Profile::External,
            output: Box::new(ArcVec(output)),
        }
    }

    fn origin_compiled(name: &str, origin: &str, output: Arc<VecSink>) -> CompiledSink {
        struct ArcVec(Arc<VecSink>);
        impl SinkOutput for ArcVec {
            fn write_line(&self, line: &str) {
                self.0.write_line(line);
            }
        }
        CompiledSink {
            name: name.to_string(),
            scope: SinkScope::Origin(origin.to_string()),
            target: Sink::AccessLog,
            format: SinkFormat::Compact,
            profile: Profile::External,
            output: Box::new(ArcVec(output)),
        }
    }

    #[test]
    fn sink_dispatcher_fans_out_to_all_proxy_sinks() {
        let _g = DISPATCHER_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let a = vec_sink_arc();
        let b = vec_sink_arc();
        let dispatcher = SinkDispatcher::new(vec![
            proxy_compiled("a", a.clone()),
            proxy_compiled("b", b.clone()),
        ]);
        install_sink_dispatcher(dispatcher);

        let rec = record_for_test(None, None);
        let live =
            current_sink_dispatcher().expect("dispatcher installed by the test should be live");
        live.dispatch(&rec, Sink::AccessLog);

        assert_eq!(a.snapshot().len(), 1, "sink A should have one line");
        assert_eq!(b.snapshot().len(), 1, "sink B should have one line");
        reset_sink_dispatcher_for_test();
    }

    #[test]
    fn sink_dispatcher_tenant_filter_blocks_cross_tenant() {
        let _g = DISPATCHER_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let acme = vec_sink_arc();
        let proxy_wide = vec_sink_arc();
        let dispatcher = SinkDispatcher::new(vec![
            tenant_compiled("acme-tenant", "acme", acme.clone()),
            proxy_compiled("proxy-wide", proxy_wide.clone()),
        ]);
        install_sink_dispatcher(dispatcher);

        let rec = record_for_test(Some("other"), None);
        let live = current_sink_dispatcher().expect("dispatcher live");
        live.dispatch(&rec, Sink::AccessLog);

        assert!(
            acme.snapshot().is_empty(),
            "tenant sink must not receive cross-tenant line: {:?}",
            acme.snapshot()
        );
        assert_eq!(
            proxy_wide.snapshot().len(),
            1,
            "proxy-scope sink should still receive the line"
        );
        reset_sink_dispatcher_for_test();
    }

    #[test]
    fn sink_dispatcher_origin_filter() {
        let _g = DISPATCHER_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let api = vec_sink_arc();
        let other = vec_sink_arc();
        let dispatcher = SinkDispatcher::new(vec![
            origin_compiled("api-acme", "api.acme.example.com", api.clone()),
            origin_compiled("api-other", "api.other.example.com", other.clone()),
        ]);
        install_sink_dispatcher(dispatcher);

        let rec = record_for_test(Some("acme"), Some("api.acme.example.com"));
        let live = current_sink_dispatcher().expect("dispatcher live");
        live.dispatch(&rec, Sink::AccessLog);

        assert_eq!(
            api.snapshot().len(),
            1,
            "matching origin sink should receive the line"
        );
        assert!(
            other.snapshot().is_empty(),
            "non-matching origin sink must stay empty: {:?}",
            other.snapshot()
        );
        reset_sink_dispatcher_for_test();
    }

    #[test]
    fn sink_dispatcher_fallback_to_tracing_when_uninstalled() {
        let _g = DISPATCHER_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Ensure no dispatcher is installed.
        reset_sink_dispatcher_for_test();

        // The fallback path is exercised by `crate::logging::emit`
        // directly when `current_sink_dispatcher` returns `None`. We
        // assert here that `current_sink_dispatcher` returns `None`
        // after a reset; the `emit` smoke test in `logging.rs` covers
        // the rest because it cannot panic when no subscriber is
        // installed.
        assert!(
            current_sink_dispatcher().is_none(),
            "after reset, no dispatcher should be returned"
        );

        let rec = record_for_test(None, None);
        // Call emit through the public API; the fallback path must
        // not panic and must not produce output we can capture (no
        // assertion needed beyond non-panic).
        crate::logging::emit(&rec, Sink::AccessLog);
    }

    #[test]
    fn sink_dispatcher_skips_target_mismatch() {
        let _g = DISPATCHER_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let access = vec_sink_arc();
        let dispatcher = SinkDispatcher::new(vec![proxy_compiled("access-only", access.clone())]);
        install_sink_dispatcher(dispatcher);

        let rec = record_for_test(None, None);
        let live = current_sink_dispatcher().expect("dispatcher live");
        // Dispatch into a channel the sink did not subscribe to.
        live.dispatch(&rec, Sink::AuditLog);

        assert!(
            access.snapshot().is_empty(),
            "sink should not see lines from a different target: {:?}",
            access.snapshot()
        );
        reset_sink_dispatcher_for_test();
    }

    #[test]
    fn otlp_severity_number_matches_spec() {
        // OTel spec values; these are stable across the SeverityNumber
        // enum in the OTLP-logs protobuf.
        assert_eq!(otlp_severity_number(LogLevel::Trace), 1);
        assert_eq!(otlp_severity_number(LogLevel::Debug), 5);
        assert_eq!(otlp_severity_number(LogLevel::Info), 9);
        assert_eq!(otlp_severity_number(LogLevel::Warn), 13);
        assert_eq!(otlp_severity_number(LogLevel::Error), 17);
        assert_eq!(otlp_severity_number(LogLevel::Fatal), 17);
    }
}
