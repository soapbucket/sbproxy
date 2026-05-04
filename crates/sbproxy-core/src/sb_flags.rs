//! Per-request feature flag parsing.
//!
//! Implements WOR-114 Phase 1: parse `x-sb-flags` request header and
//! `?_sb.<key>[=<value>]` query-string params into a typed
//! `RequestFlags` struct that the request pipeline reads to alter
//! behavior on the current request only.
//!
//! Three built-ins are surfaced through dedicated bools because they
//! are checked on the hot path and the config / cache modules want a
//! cheap branch:
//!
//! * `debug`: emit `x-sbproxy-debug-request-id` and
//!   `x-sbproxy-debug-config-rev` response headers and a `tracing::debug!`
//!   event tagged with the request's session id.
//! * `trace`: force-enable W3C trace context propagation for this
//!   request even when `tracing.propagation` is unset in `sb.yml`.
//! * `no-cache`: bypass the response cache lookup for this request
//!   (the upstream is asked, and the response is not written into the
//!   cache).
//!
//! Any other key=value pair the client sends is preserved in
//! [`crate::sb_flags::RequestFlags::extra`] so CEL / Lua / WASM
//! scripts can read it through a future `features[…]` namespace
//! (Phase 2, separate ticket).
//!
//! The whole surface can be locked off at process start with
//! `--disable-sb-flags` / `SB_DISABLE_SB_FLAGS=1`; see
//! [`crate::sb_flags::disabled`].

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// Process-wide kill switch. Set true by [`set_disabled`] before
/// listeners start; checked by [`parse_request`] on every request.
static DISABLED: AtomicBool = AtomicBool::new(false);

/// Lock the surface off. Idempotent.
///
/// Called once from `main.rs` when `--disable-sb-flags` /
/// `SB_DISABLE_SB_FLAGS=1` is set. After this, [`parse_request`]
/// returns the all-zero default regardless of what the client sends.
pub fn set_disabled(value: bool) {
    DISABLED.store(value, Ordering::Relaxed);
}

/// Whether the kill switch is engaged. Hot path; uses Relaxed ordering
/// because consistency across cores is irrelevant for a global
/// per-process toggle that flips exactly once at boot.
pub fn disabled() -> bool {
    DISABLED.load(Ordering::Relaxed)
}

/// Parsed feature flags for a single request.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RequestFlags {
    /// `x-sb-flags: debug` or `?_sb.debug`. Drives the per-request
    /// DEBUG-level log entry and stamps `x-sbproxy-debug-*` response
    /// headers.
    pub debug: bool,
    /// `x-sb-flags: trace` or `?_sb.trace`. Forces W3C trace context
    /// propagation on for this request.
    pub trace: bool,
    /// `x-sb-flags: no-cache` or `?_sb.no-cache`. Bypasses the response
    /// cache lookup; upstream is consulted and the answer is not stored.
    pub no_cache: bool,
    /// Any unknown key=value pair the client supplied. Forward-compat:
    /// later phases will expose this through a CEL/Lua/WASM `features[…]`
    /// namespace. Kept as a sorted map so test assertions are stable.
    pub extra: BTreeMap<String, String>,
}

impl RequestFlags {
    /// True if any flag (built-in or extra) is set. Used by the
    /// response phase to skip the debug-header stamp on the common
    /// path where no client opted in.
    pub fn any_set(&self) -> bool {
        self.debug || self.trace || self.no_cache || !self.extra.is_empty()
    }

    fn merge(&mut self, other: RequestFlags) {
        self.debug |= other.debug;
        self.trace |= other.trace;
        self.no_cache |= other.no_cache;
        for (k, v) in other.extra {
            self.extra.insert(k, v);
        }
    }
}

/// Parse the value of an `x-sb-flags` header.
///
/// Tokens separated by `,` or `;`; whitespace around tokens is
/// trimmed. Each token is either `key` (interpreted as `key=`) or
/// `key=value`. Empty tokens are skipped.
///
/// Built-in keys (`debug`, `trace`, `no-cache`) set the typed bool.
/// Anything else lands in `RequestFlags::extra` verbatim.
///
/// ```
/// use sbproxy_core::sb_flags::parse_header;
/// let f = parse_header("debug, no-cache, env=staging");
/// assert!(f.debug);
/// assert!(f.no_cache);
/// assert!(!f.trace);
/// assert_eq!(f.extra.get("env").map(String::as_str), Some("staging"));
/// ```
pub fn parse_header(value: &str) -> RequestFlags {
    let mut out = RequestFlags::default();
    for raw in value.split([',', ';']) {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let (key, val) = match token.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (token, ""),
        };
        if key.is_empty() {
            continue;
        }
        apply(&mut out, key, val);
    }
    out
}

/// Parse the query string from the request URI for `_sb.<key>[=<value>]`
/// parameters.
///
/// Accepts `query` as either the raw query string after the `?` or
/// the empty string. Multiple `_sb.*` params are honoured; non-`_sb.*`
/// params are ignored. Standard URL-encoded values are not decoded;
/// the canonical form for `debug` and friends is the bare key, and
/// arbitrary opaque values are passed through to `RequestFlags::extra`.
///
/// ```
/// use sbproxy_core::sb_flags::parse_query;
/// let f = parse_query("foo=bar&_sb.debug&_sb.no-cache");
/// assert!(f.debug);
/// assert!(f.no_cache);
/// ```
pub fn parse_query(query: &str) -> RequestFlags {
    let mut out = RequestFlags::default();
    if query.is_empty() {
        return out;
    }
    for pair in query.split('&') {
        let (key, val) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let Some(name) = key.strip_prefix("_sb.") else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        apply(&mut out, name, val);
    }
    out
}

/// Convenience: parse both surfaces, header first then query, into a
/// single struct. Honours [`disabled`]; if the kill switch is on,
/// returns the empty default.
///
/// `header_value` is the raw `x-sb-flags` header (or `""` when absent);
/// `query` is the raw query string.
pub fn parse_request(header_value: &str, query: &str) -> RequestFlags {
    if disabled() {
        return RequestFlags::default();
    }
    let mut flags = parse_header(header_value);
    flags.merge(parse_query(query));
    flags
}

fn apply(out: &mut RequestFlags, key: &str, val: &str) {
    match key {
        "debug" => out.debug = true,
        "trace" => out.trace = true,
        "no-cache" => out.no_cache = true,
        other => {
            out.extra.insert(other.to_string(), val.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parses_three_builtins() {
        let f = parse_header("debug, trace, no-cache");
        assert!(f.debug);
        assert!(f.trace);
        assert!(f.no_cache);
        assert!(f.extra.is_empty());
    }

    #[test]
    fn header_handles_semicolon_and_comma_mix() {
        let f = parse_header("debug; trace, no-cache");
        assert!(f.debug && f.trace && f.no_cache);
    }

    #[test]
    fn header_passes_unknown_kv_to_extra() {
        let f = parse_header("debug, env=staging, region=us-east-1");
        assert!(f.debug);
        assert_eq!(f.extra.get("env").map(String::as_str), Some("staging"));
        assert_eq!(f.extra.get("region").map(String::as_str), Some("us-east-1"));
    }

    #[test]
    fn header_skips_empty_tokens() {
        let f = parse_header(",,debug,,;");
        assert!(f.debug);
    }

    #[test]
    fn header_ignores_whitespace_around_tokens() {
        let f = parse_header("  debug  ,   no-cache   ");
        assert!(f.debug);
        assert!(f.no_cache);
    }

    #[test]
    fn query_parses_underscore_sb_prefix() {
        let f = parse_query("_sb.debug&_sb.trace=true");
        assert!(f.debug);
        assert!(f.trace);
    }

    #[test]
    fn query_ignores_non_sb_params() {
        let f = parse_query("foo=bar&page=2&_sb.no-cache");
        assert!(f.no_cache);
        assert!(!f.debug);
        assert!(f.extra.is_empty());
    }

    #[test]
    fn query_passes_unknown_kv_to_extra() {
        let f = parse_query("_sb.env=staging&_sb.region=us-east-1");
        assert_eq!(f.extra.get("env").map(String::as_str), Some("staging"));
        assert_eq!(f.extra.get("region").map(String::as_str), Some("us-east-1"));
    }

    #[test]
    fn parse_request_merges_header_and_query() {
        let f = parse_request("debug", "_sb.no-cache");
        assert!(f.debug);
        assert!(f.no_cache);
    }

    #[test]
    fn disabled_kill_switch_returns_empty() {
        // Manipulating the global is fine here because the test runs
        // serially under #[cfg(test)]; we restore the value before
        // returning so other tests are unaffected.
        let prev = disabled();
        set_disabled(true);
        let f = parse_request("debug, no-cache", "_sb.trace");
        assert!(!f.debug);
        assert!(!f.trace);
        assert!(!f.no_cache);
        set_disabled(prev);
    }

    #[test]
    fn any_set_works() {
        let mut f = RequestFlags::default();
        assert!(!f.any_set());
        f.debug = true;
        assert!(f.any_set());
    }
}
