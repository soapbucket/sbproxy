//! Test-only in-memory capture for redaction-eligible events.
//!
//! When fake-sink mode is enabled (via the `SBPROXY_TEST_FAKE_SINKS=1`
//! environment variable), every redaction-eligible event the proxy
//! observes is appended to a per-sink in-memory buffer. The two admin
//! debug endpoints (`POST /api/_test/sinks/reset` +
//! `GET /api/_test/sinks/{name}`) read and clear these buffers; the
//! end-to-end redaction fan-out test (`e2e/tests/redaction.rs`)
//! exercises them.
//!
//! This is a TEST-ONLY surface. The mode is opt-in (default off) and
//! the request-pipeline routes that expose the buffers also gate on the
//! same env var, so a production binary never serves them.
//!
//! The capture happens AFTER `crate::logging::apply_redaction` runs, so
//! the buffer contents are exactly what would land in the real sink.
//! Any secret that survives redaction would also leak into the buffer,
//! which is the contract the e2e test asserts on.
//!
//! Implementation notes:
//!
//! - The state lives in a `OnceLock<Mutex<HashMap<String, Vec<String>>>>`.
//!   Construction is lazy so the cost when the mode is off is one
//!   atomic load per request.
//! - The mode is read once at the first `enabled()` call and cached
//!   (the env var is process-static for the proxy's lifetime). Tests
//!   that toggle mid-process should call `force_enabled(true)` instead.
//! - `capture` is a no-op when the mode is off and when the sink name
//!   is unknown to the buffer map; the latter is intentional so test
//!   fixtures cannot quietly grow the sink set.

use std::collections::HashMap;
use std::env;
use std::sync::atomic::{AtomicBool, AtomicI8, Ordering};
use std::sync::{Mutex, OnceLock};

/// Environment variable that enables fake-sink mode.
///
/// Set to `1`, `true`, `yes`, or `on` (case-insensitive) to opt in.
/// Any other value (or absence) keeps the mode off.
pub const FAKE_SINKS_ENV: &str = "SBPROXY_TEST_FAKE_SINKS";

/// Sink names recognised by the fake-sink capture. Mirrors the four
/// real sinks the redactor fans into per A1.5 (`access_log`,
/// `error_log`, `audit_log`, `trace_exporter`). The `external` sink
/// is intentionally absent because the redaction e2e tests target the
/// internal-profile fan-out only.
pub const SINK_NAMES: &[&str] = &["access_log", "error_log", "audit_log", "trace_exporter"];

/// Cached `enabled()` verdict.
///
/// Tri-state: `0` = unknown (read env on next call), `1` = enabled,
/// `-1` = disabled. We cache so the hot-path read on every request is
/// a single relaxed atomic load. Tests force the value through
/// `force_enabled` rather than mutating the env var.
static CACHED: AtomicI8 = AtomicI8::new(0);

/// Override flag set by tests via `force_enabled`. When set, takes
/// priority over the env-var read.
static FORCED: AtomicBool = AtomicBool::new(false);
static FORCED_VALUE: AtomicBool = AtomicBool::new(false);

/// Per-sink buffer storage. Keys are the strings in [`SINK_NAMES`];
/// values are append-ordered redacted log lines.
fn buffers() -> &'static Mutex<HashMap<String, Vec<String>>> {
    static BUFS: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
    BUFS.get_or_init(|| {
        let mut map = HashMap::new();
        for &name in SINK_NAMES {
            map.insert(name.to_string(), Vec::new());
        }
        Mutex::new(map)
    })
}

/// Whether fake-sink mode is enabled for this process.
///
/// Reads `SBPROXY_TEST_FAKE_SINKS` once and caches the verdict.
/// Tests that need to flip the mode mid-run should call
/// [`force_enabled`].
pub fn enabled() -> bool {
    if FORCED.load(Ordering::Relaxed) {
        return FORCED_VALUE.load(Ordering::Relaxed);
    }
    match CACHED.load(Ordering::Relaxed) {
        1 => true,
        -1 => false,
        _ => {
            let on = match env::var(FAKE_SINKS_ENV).ok() {
                Some(v) => matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                ),
                None => false,
            };
            CACHED.store(if on { 1 } else { -1 }, Ordering::Relaxed);
            on
        }
    }
}

/// Test helper: force the mode on or off without touching the env var.
/// Subsequent `enabled()` calls return `value` until `clear_forced()`.
pub fn force_enabled(value: bool) {
    FORCED_VALUE.store(value, Ordering::Relaxed);
    FORCED.store(true, Ordering::Relaxed);
}

/// Test helper: drop the forced override so `enabled()` re-reads the
/// env var on its next call.
pub fn clear_forced() {
    FORCED.store(false, Ordering::Relaxed);
    CACHED.store(0, Ordering::Relaxed);
}

/// Append `line` to the buffer for `sink`. No-op when the mode is off
/// or when `sink` is not one of [`SINK_NAMES`].
pub fn capture(sink: &str, line: String) {
    if !enabled() {
        return;
    }
    let mut bufs = match buffers().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(v) = bufs.get_mut(sink) {
        v.push(line);
    }
}

/// Drop every buffer's contents. Used by `POST /api/_test/sinks/reset`.
/// No-op when the mode is off so production code paths that
/// accidentally call it stay free.
pub fn reset() {
    if !enabled() {
        return;
    }
    let mut bufs = match buffers().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    for v in bufs.values_mut() {
        v.clear();
    }
}

/// Return the named sink's buffered lines joined by newline. Empty
/// string when the sink is unknown or has no captures. Used by
/// `GET /api/_test/sinks/{name}`.
pub fn read(sink: &str) -> String {
    if !enabled() {
        return String::new();
    }
    let bufs = match buffers().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    match bufs.get(sink) {
        Some(v) => v.join("\n"),
        None => String::new(),
    }
}

/// Capture one synthetic event into every known sink, applying the
/// per-sink redaction profile to the input JSON before storage. The
/// caller passes the unredacted JSON string; this function runs
/// `crate::logging::apply_redaction` for each sink so the buffer
/// content matches what the real sink would have written.
///
/// Returns the number of sinks captured to (zero when the mode is off).
pub fn capture_all_sinks(unredacted_json: &str) -> usize {
    if !enabled() {
        return 0;
    }
    use crate::logging::Sink;
    let pairs: &[(&str, Sink)] = &[
        ("access_log", Sink::AccessLog),
        ("error_log", Sink::ErrorLog),
        ("audit_log", Sink::AuditLog),
        ("trace_exporter", Sink::TraceExporter),
    ];
    let mut count = 0;
    for (name, sink) in pairs {
        let redacted = crate::logging::apply_redaction(unredacted_json, *sink);
        capture(name, redacted);
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The mode flag and per-sink buffers are process-global; cargo
    // runs tests in parallel by default. Serialise every test that
    // touches the global state through this lock so one test's
    // `force_enabled(true)` cannot land between another test's
    // `reset()` and its later `read()`.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_enabled<F: FnOnce()>(f: F) {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_enabled(true);
        reset();
        f();
        // Wipe again on the way out so the next test sees an empty
        // map even if it forgets to reset.
        reset();
        clear_forced();
    }

    #[test]
    fn disabled_capture_is_noop() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_forced();
        force_enabled(false);
        capture("access_log", "leak".to_string());
        // Even when forced false, read() returns empty.
        assert_eq!(read("access_log"), "");
        clear_forced();
    }

    #[test]
    fn enabled_capture_round_trips_lines() {
        with_enabled(|| {
            capture("access_log", "line1".to_string());
            capture("access_log", "line2".to_string());
            let out = read("access_log");
            assert!(out.contains("line1"));
            assert!(out.contains("line2"));
        });
    }

    #[test]
    fn unknown_sink_is_dropped() {
        with_enabled(|| {
            capture("unknown_sink", "ignore".to_string());
            assert_eq!(read("unknown_sink"), "");
        });
    }

    #[test]
    fn reset_clears_every_buffer() {
        with_enabled(|| {
            for &name in SINK_NAMES {
                capture(name, "x".to_string());
            }
            reset();
            for &name in SINK_NAMES {
                assert_eq!(read(name), "", "sink {name} not cleared");
            }
        });
    }

    #[test]
    fn capture_all_sinks_runs_redaction_per_sink() {
        with_enabled(|| {
            let json = r#"{"headers":{"authorization":"Bearer eyJlongtokenvalue1234567890"}}"#;
            let n = capture_all_sinks(json);
            assert_eq!(n, SINK_NAMES.len());
            for &name in SINK_NAMES {
                let buf = read(name);
                assert!(
                    buf.contains("<redacted:authorization>"),
                    "sink {name} missing marker: {buf}"
                );
                assert!(
                    !buf.contains("eyJlongtokenvalue"),
                    "sink {name} leaked secret: {buf}"
                );
            }
        });
    }
}
