//! Payload-shaped signal extractors (WOR-591, slice 8 of WOR-499).
//!
//! Pure functions over a request body that build a
//! [`PayloadSignals`] for the scorer to consult. Each extractor is
//! stateless and allocates only when the body actually contains a
//! candidate match; the empty-body fast path returns the all-default
//! signal bag without touching a regex.
//!
//! ## Signals
//!
//! - **Filesystem-path leakage** ([`count_unique_filesystem_paths`]):
//!   counts unique absolute paths matching `/Users/<name>/...`,
//!   `C:\Users\<name>\...`, or `/home/<name>/...`. The extractor
//!   surfaces the count, never the path text, so the metric is safe
//!   to ship to the audit log without leaking PII.
//! - **Stack-trace shape** ([`is_stack_trace_shaped`]): boolean
//!   detector for four common runtime traceback formats (Python,
//!   Node, Go panic, Java).
//! - **Embedding burst**: rate / session signal. A single body does
//!   not carry enough state to compute the burst; this slice ships
//!   the field hard-wired to `false` and leaves the wiring for a
//!   follow-up that observes a session window. See the doc-comment
//!   on [`crate::PayloadSignals::embedding_burst`].
//!
//! [`PayloadSignals`]: crate::PayloadSignals

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::PayloadSignals;

/// Macro-free regex set. `LazyLock` matches the workspace convention
/// (see `crates/sbproxy-core/src/server.rs`); the regex objects compile
/// at first use and are reused for the lifetime of the process.
///
/// The three patterns together cover the three home-directory shapes
/// the proxy actually sees in agent-origin traffic: macOS, the most
/// common shape for individual-developer agents; Windows, which uses
/// backslash separators; and Linux, which most server-side automation
/// runs against. We intentionally do not try to match relative paths
/// or `/tmp/...` shapes; those are common in non-agent traffic too
/// and would inflate false positives.
static FILESYSTEM_PATH_REGEXES: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    [
        // macOS: /Users/<name>/... ; consume up to whitespace, quote,
        // backtick, or end-of-line so we capture the full path even
        // when it sits inside JSON.
        Regex::new(r#"/Users/[^/\s"'`]+/[^\s"'`]*"#).expect("macOS path regex compiles"),
        // Windows: C:\Users\<name>\... ; backslash-separated. We pin
        // the drive letter to `C` because that is what every shipped
        // Windows agent fixture surfaces; later slices can broaden if
        // needed.
        Regex::new(r#"C:\\Users\\[^\\\s"'`]+\\[^\s"'`]*"#).expect("Windows path regex compiles"),
        // Linux: /home/<name>/...
        Regex::new(r#"/home/[^/\s"'`]+/[^\s"'`]*"#).expect("Linux path regex compiles"),
    ]
});

/// Python `Traceback (most recent call last):` literal.
static PYTHON_TRACEBACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Traceback \(most recent call last\):").expect("Python traceback regex compiles")
});

/// Node.js stack frame: indented `    at <name> (`.
static NODE_STACK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"    at [^\s(]+ \(").expect("Node stack regex compiles"));

/// Go panic header: `goroutine 1 [running]:`.
static GO_PANIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"goroutine \d+ \[").expect("Go panic regex compiles"));

/// Java stack frame: tab-prefixed `\tat package.Class(...)`. The
/// pattern broadens the spec's `\w+\.\w+\(` to allow the multi-segment
/// package names every real Java stack trace carries (`\w+(?:\.\w+)+\(`).
static JAVA_STACK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\tat \w+(?:\.\w+)+\(").expect("Java stack regex compiles"));

/// Count the number of distinct filesystem paths leaked in `body`.
///
/// Returns the cardinality, not the paths themselves; the caller can
/// surface this to metrics and audit without leaking the operator's
/// directory layout into a downstream sink.
///
/// Two occurrences of the same path collapse to one. The match is
/// case-sensitive (filesystems on macOS and Linux are commonly
/// case-sensitive at the API level even when the volume is not, and
/// Windows tooling that emits paths tends to preserve case).
#[must_use]
pub fn count_unique_filesystem_paths(body: &str) -> u32 {
    if body.is_empty() {
        return 0;
    }
    let mut seen: HashSet<&str> = HashSet::new();
    for re in FILESYSTEM_PATH_REGEXES.iter() {
        for m in re.find_iter(body) {
            seen.insert(m.as_str());
        }
    }
    // u32 is plenty: the request body is bounded long before this
    // count could overflow, and the proxy enforces a max-body-size
    // policy upstream. Saturating cast for defence in depth.
    u32::try_from(seen.len()).unwrap_or(u32::MAX)
}

/// True when `body` contains a recognised stack-trace shape.
///
/// Detected dialects: Python, Node.js, Go panic, Java. The check is
/// a regex match against each pattern in turn; the first hit
/// short-circuits.
#[must_use]
pub fn is_stack_trace_shaped(body: &str) -> bool {
    if body.is_empty() {
        return false;
    }
    PYTHON_TRACEBACK.is_match(body)
        || NODE_STACK.is_match(body)
        || GO_PANIC.is_match(body)
        || JAVA_STACK.is_match(body)
}

/// Build a [`PayloadSignals`] from a request body.
///
/// Composes [`count_unique_filesystem_paths`] and
/// [`is_stack_trace_shaped`]. `embedding_burst` is always `false` in
/// this slice; the rate-based heuristic requires session-window
/// state the per-request extractor does not have.
///
/// Empty bodies short-circuit to [`PayloadSignals::default`] without
/// touching a regex.
#[must_use]
pub fn extract_payload_signals(body: &str) -> PayloadSignals {
    if body.is_empty() {
        return PayloadSignals::default();
    }
    PayloadSignals {
        filesystem_paths_leaked: count_unique_filesystem_paths(body),
        stack_trace_shaped: is_stack_trace_shaped(body),
        embedding_burst: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- filesystem path detection ------------------------------------------

    #[test]
    fn macos_path_is_detected() {
        let body = "see /Users/alice/projects/foo/main.rs for the stub";
        assert_eq!(count_unique_filesystem_paths(body), 1);
    }

    #[test]
    fn linux_path_is_detected() {
        let body = "log: /home/bob/.cache/agent/run.log not found";
        assert_eq!(count_unique_filesystem_paths(body), 1);
    }

    #[test]
    fn windows_path_is_detected() {
        let body = r"opened C:\Users\carol\Documents\notes.txt";
        assert_eq!(count_unique_filesystem_paths(body), 1);
    }

    #[test]
    fn duplicate_path_counts_as_one() {
        // The same macOS path appears twice; the extractor dedupes.
        let body = "first /Users/alice/foo.rs then /Users/alice/foo.rs again";
        assert_eq!(count_unique_filesystem_paths(body), 1);
    }

    #[test]
    fn distinct_paths_count_separately() {
        let body = "edit /Users/alice/a.rs and /Users/alice/b.rs and /home/dave/c.rs";
        assert_eq!(count_unique_filesystem_paths(body), 3);
    }

    #[test]
    fn pii_safety_signal_carries_count_not_path_text() {
        // Compile-time guarantee that the field is `u32`, not a
        // string or a `Vec<String>`. If anyone ever changes the
        // field type to leak the path text, this test stops
        // compiling.
        let body = "secret: /Users/topsecret/foo";
        let signals = extract_payload_signals(body);
        let _count_is_u32: u32 = signals.filesystem_paths_leaked;
        assert_eq!(signals.filesystem_paths_leaked, 1);
    }

    // --- stack trace detection ----------------------------------------------

    #[test]
    fn python_traceback_is_detected() {
        let body = "Traceback (most recent call last):\n  File \"main.py\", line 1";
        assert!(is_stack_trace_shaped(body));
    }

    #[test]
    fn node_stack_is_detected() {
        let body = "Error: nope\n    at fooBar (/tmp/x.js:1:1)\n    at next (/tmp/x.js:2:1)";
        assert!(is_stack_trace_shaped(body));
    }

    #[test]
    fn go_panic_is_detected() {
        let body = "panic: runtime error: nil pointer\n\ngoroutine 17 [running]:\nmain.main()";
        assert!(is_stack_trace_shaped(body));
    }

    #[test]
    fn java_stack_is_detected() {
        let body = "java.lang.NullPointerException\n\tat com.example.Foo(Foo.java:42)";
        assert!(is_stack_trace_shaped(body));
    }

    // --- composition + safe defaults ----------------------------------------

    #[test]
    fn clean_prose_body_has_no_signals() {
        let body = "The quick brown fox jumps over the lazy dog. Nothing path-shaped here.";
        let signals = extract_payload_signals(body);
        assert_eq!(signals.filesystem_paths_leaked, 0);
        assert!(!signals.stack_trace_shaped);
        assert!(!signals.embedding_burst);
    }

    #[test]
    fn empty_body_returns_defaults_without_regex_work() {
        // Behavioural check: empty body returns the default bag.
        // The implementation also guarantees we never construct a
        // `HashSet` or touch a regex on this path; that property is
        // a comment-and-code-review contract because Rust does not
        // give us a runtime hook to observe "did this allocate".
        let signals = extract_payload_signals("");
        assert_eq!(signals, PayloadSignals::default());
        assert_eq!(count_unique_filesystem_paths(""), 0);
        assert!(!is_stack_trace_shaped(""));
    }

    #[test]
    fn embedding_burst_is_always_false_for_now() {
        // Documents the slice-8 behaviour: the field exists on the
        // struct so callers can branch on it, but the value is hard-
        // wired to `false` until the session-window slice lands.
        let body = "{\"embeddings\":[[0.1,0.2,0.3],[0.4,0.5,0.6],[0.7,0.8,0.9],[1.0,1.1,1.2]]}";
        let signals = extract_payload_signals(body);
        assert!(!signals.embedding_burst);
    }

    #[test]
    fn full_signal_bag_composes() {
        let body = "Traceback (most recent call last):\n  File \"/Users/alice/main.py\", line 1";
        let signals = extract_payload_signals(body);
        assert_eq!(signals.filesystem_paths_leaked, 1);
        assert!(signals.stack_trace_shaped);
        assert!(!signals.embedding_burst);
    }
}
