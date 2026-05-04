// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! Edge capture helpers that read inbound headers and produce values
//! for [`crate::request_event::RequestEvent`].
//!
//! Three concerns live here, each one driven by its own ADR:
//!
//! * Custom properties (T1.1): [`capture_properties`] reads
//!   `X-Sb-Property-*` headers per `docs/adr-custom-properties.md`,
//!   enforces caps, applies redaction.
//! * Session linkage (T2.1): [`capture_session_id`] /
//!   [`capture_parent_session_id`] read `X-Sb-Session-Id` and
//!   `X-Sb-Parent-Session-Id` per `docs/adr-session-id.md`, validate
//!   ULID format, and auto-generate when configured.
//! * User identity (T3.1): [`capture_user_id`] resolves `X-Sb-User-Id`
//!   / JWT `sub` / forward-auth header in precedence order per
//!   `docs/adr-user-id.md`.
//!
//! Pipeline integration is a separate slice; this module ships the
//! primitives and unit tests only.

use http::HeaderMap;
use once_cell::sync::OnceCell;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use ulid::Ulid;

use crate::request_event::UserIdSource;

// --- Properties (T1.1) ---

/// Per-origin properties capture configuration. Defaults match the
/// "capture on, no echo, no redaction" baseline; operators tune via
/// `sb.yml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PropertiesConfig {
    /// Master switch. When `false`, [`capture_properties`] returns an
    /// empty map regardless of headers.
    #[serde(default = "default_true")]
    pub capture: bool,
    /// Echo captured properties back as `X-Sb-Property-<key>` response
    /// headers. Off by default; opt-in per origin.
    #[serde(default)]
    pub echo: bool,
    /// Redaction rules applied after capture and before any subscriber
    /// observes the event.
    #[serde(default)]
    pub redact: RedactConfig,
}

impl Default for PropertiesConfig {
    fn default() -> Self {
        Self {
            capture: true,
            echo: false,
            redact: RedactConfig::default(),
        }
    }
}

/// Redaction rules for captured property values.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RedactConfig {
    /// Exact-match keys whose values are replaced with `"[redacted]"`.
    /// Match is case-insensitive on the lowercased captured key.
    #[serde(default)]
    pub keys: Vec<String>,
    /// Value-content regex patterns. Any value matching any pattern is
    /// replaced wholesale with `"[redacted]"`.
    #[serde(default)]
    pub value_regex: Vec<String>,
}

/// Per-request counters reporting why properties were dropped.
/// Callers wire these into Prometheus
/// (`sbproxy_property_dropped_total{reason}`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PropertyDropCounts {
    /// Dropped because the per-request count cap was reached.
    pub count: u32,
    /// Dropped because the key exceeded `MAX_PROPERTY_KEY_LEN`.
    pub key_len: u32,
    /// Dropped because the value exceeded `MAX_PROPERTY_VALUE_LEN`.
    pub value_len: u32,
    /// Whole batch rejected because the cumulative payload exceeded
    /// `MAX_PROPERTY_PAYLOAD_BYTES`. When this fires, the captured
    /// map is empty.
    pub payload_size: u32,
    /// Dropped because the key did not match the allowlist regex.
    pub regex: u32,
}

/// Maximum number of properties retained per request.
pub const MAX_PROPERTIES_PER_REQUEST: usize = 20;
/// Maximum allowed length of a normalized property key.
pub const MAX_PROPERTY_KEY_LEN: usize = 64;
/// Maximum allowed length of a property value.
pub const MAX_PROPERTY_VALUE_LEN: usize = 512;
/// Maximum cumulative wire payload (sum of key + value lengths).
pub const MAX_PROPERTY_PAYLOAD_BYTES: usize = 8 * 1024;
/// Header prefix that triggers property capture. Lowercased here so
/// `iter()`'s lowercased header name matches directly.
const PROPERTY_HEADER_PREFIX: &str = "x-sb-property-";

fn default_true() -> bool {
    true
}

fn property_key_regex() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9][a-z0-9_-]{0,63}$").expect("static regex compiles"))
}

fn redact_value_regexes(patterns: &[String]) -> Vec<Regex> {
    patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
}

/// Read `X-Sb-Property-*` headers and produce the captured map plus
/// drop counts, applying caps and redaction per
/// `docs/adr-custom-properties.md`.
///
/// Behavior:
///
/// * Each header name is lowercased; the prefix `x-sb-property-` is
///   stripped to derive the key. Surrounding whitespace on key and
///   value is trimmed.
/// * Keys that fail the allowlist regex are dropped (counted in
///   `regex`).
/// * Keys longer than `MAX_PROPERTY_KEY_LEN` are dropped (counted in
///   `key_len`); values longer than `MAX_PROPERTY_VALUE_LEN` are
///   dropped (counted in `value_len`).
/// * If the cumulative wire payload (sum of key + value lengths)
///   exceeds `MAX_PROPERTY_PAYLOAD_BYTES`, the entire batch is rejected
///   (drop count `payload_size = 1`, captured map empty).
/// * Past `MAX_PROPERTIES_PER_REQUEST` accepted entries the rest are
///   dropped (counted in `count`).
/// * Redaction runs on the surviving map: exact key match replaces the
///   value with `"[redacted]"`; value regex match does the same.
pub fn capture_properties(
    headers: &HeaderMap,
    cfg: &PropertiesConfig,
) -> (BTreeMap<String, String>, PropertyDropCounts) {
    let mut drops = PropertyDropCounts::default();
    if !cfg.capture {
        return (BTreeMap::new(), drops);
    }

    // First pass: collect candidates while accounting for the payload cap.
    let mut candidates: Vec<(String, String)> = Vec::new();
    let mut payload_bytes: usize = 0;

    for (name, value) in headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        let Some(suffix) = lname.strip_prefix(PROPERTY_HEADER_PREFIX) else {
            continue;
        };
        let key = suffix.trim().to_ascii_lowercase();
        let val_bytes = value.as_bytes();
        // Header value must be valid UTF-8 to land in our string-typed map.
        let Ok(value_str) = std::str::from_utf8(val_bytes) else {
            continue;
        };
        let value = value_str.trim().to_string();

        if key.len() > MAX_PROPERTY_KEY_LEN {
            drops.key_len += 1;
            continue;
        }
        if value.len() > MAX_PROPERTY_VALUE_LEN {
            drops.value_len += 1;
            continue;
        }
        if !property_key_regex().is_match(&key) {
            drops.regex += 1;
            continue;
        }

        payload_bytes = payload_bytes
            .saturating_add(key.len())
            .saturating_add(value.len());
        if payload_bytes > MAX_PROPERTY_PAYLOAD_BYTES {
            // Reject the entire batch as the ADR specifies; we do not
            // partially accept a payload that grew past the cap.
            drops.payload_size = 1;
            return (BTreeMap::new(), drops);
        }
        candidates.push((key, value));
    }

    // Second pass: enforce the per-request count cap and apply redaction.
    let mut captured: BTreeMap<String, String> = BTreeMap::new();
    let value_regexes = redact_value_regexes(&cfg.redact.value_regex);

    for (k, v) in candidates {
        if captured.len() >= MAX_PROPERTIES_PER_REQUEST {
            drops.count += 1;
            continue;
        }
        let redacted_by_key = cfg.redact.keys.iter().any(|rk| rk.eq_ignore_ascii_case(&k));
        let redacted_by_value = !redacted_by_key && value_regexes.iter().any(|re| re.is_match(&v));
        let final_value = if redacted_by_key || redacted_by_value {
            "[redacted]".to_string()
        } else {
            v
        };
        captured.insert(k, final_value);
    }

    (captured, drops)
}

// --- Sessions (T2.1) ---

/// Auto-generation policy for session IDs when the caller does not
/// supply one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoGenerate {
    /// Never mint a session ID. Capture caller-supplied IDs only.
    Never,
    /// Mint a session ID only when the caller is anonymous (no
    /// resolved user identity). This is the default for AI gateway
    /// origins; bursts of anonymous traffic get one session per burst
    /// rather than one per request.
    #[default]
    Anonymous,
    /// Always mint a session ID when one is not supplied.
    Always,
}

/// Per-origin sessions configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionsConfig {
    /// Master capture switch. When `false`, callers see no session ID
    /// regardless of headers or auto-generation policy.
    #[serde(default = "default_true")]
    pub capture: bool,
    /// When to auto-generate a session ID for callers that did not
    /// supply one.
    #[serde(default)]
    pub auto_generate: AutoGenerate,
    /// Sessions index TTL in seconds. The proxy itself does not
    /// enforce TTL; this knob feeds the ClickHouse projections (T2.4)
    /// which key storage on `(workspace_id, session_id)`.
    #[serde(default = "default_session_ttl")]
    pub ttl_seconds: u64,
    /// Cap on auto-generated session IDs per workspace per window.
    /// `None` disables the gate (default). When the cap is hit, the
    /// dimension is dropped silently and
    /// `sbproxy_capture_budget_dropped_total{workspace,dimension="session"}`
    /// is incremented. Caller-supplied session IDs from
    /// `X-Sb-Session-Id` are never gated.
    #[serde(default)]
    pub budget: Option<BudgetConfig>,
}

impl Default for SessionsConfig {
    fn default() -> Self {
        Self {
            capture: true,
            auto_generate: AutoGenerate::default(),
            ttl_seconds: default_session_ttl(),
            budget: None,
        }
    }
}

fn default_session_ttl() -> u64 {
    86_400
}

/// Per-request counters reporting why session IDs were dropped.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SessionDropCounts {
    /// Header value did not parse as a valid ULID.
    pub invalid_format: u32,
    /// Header value exceeded the ULID length (26 chars). Kept separate
    /// so dashboards can spot length-bombs distinctly from format errors.
    pub too_long: u32,
    /// Header was present but the value was empty after trimming.
    pub empty: u32,
}

/// Header used to carry the caller-supplied session ID.
pub const SESSION_ID_HEADER: &str = "x-sb-session-id";
/// Header used to carry the caller-supplied parent session ID.
pub const PARENT_SESSION_ID_HEADER: &str = "x-sb-parent-session-id";

fn parse_ulid_header(headers: &HeaderMap, name: &str) -> (Option<Ulid>, SessionDropCounts) {
    let mut drops = SessionDropCounts::default();
    let Some(value) = headers.get(name) else {
        return (None, drops);
    };
    let Ok(s) = value.to_str() else {
        drops.invalid_format += 1;
        return (None, drops);
    };
    let trimmed = s.trim();
    if trimmed.is_empty() {
        drops.empty += 1;
        return (None, drops);
    }
    if trimmed.len() > 26 {
        drops.too_long += 1;
        return (None, drops);
    }
    match Ulid::from_string(trimmed) {
        Ok(u) => (Some(u), drops),
        Err(_) => {
            drops.invalid_format += 1;
            (None, drops)
        }
    }
}

/// Capture the session ID for the current request.
///
/// Resolution order:
///
/// 1. If the caller supplied `X-Sb-Session-Id` and it parses as a ULID,
///    use it. Auto-generation never overwrites a caller-supplied value.
/// 2. Otherwise, consult `cfg.auto_generate`. `Never` produces nothing;
///    `Always` mints a fresh ULID; `Anonymous` mints a ULID only when
///    `user_id_resolved` is `false`.
/// 3. When capture is disabled (`cfg.capture == false`), always
///    produce nothing regardless of headers.
///
/// `user_id_resolved` is the caller-side signal that
/// [`capture_user_id`] returned `Some`. Pass `false` for unauthenticated
/// requests so the `Anonymous` policy lights up.
///
/// `workspace_id` is consulted by the T2.3 budget gate
/// ([`SessionsConfig::budget`]) before any auto-generation: when the
/// per-workspace cap is reached the dimension is dropped silently and
/// `sbproxy_capture_budget_dropped_total{workspace,dimension="session"}`
/// is incremented. Caller-supplied (header) session IDs are never
/// gated; only auto-generated IDs count against the budget.
pub fn capture_session_id(
    headers: &HeaderMap,
    cfg: &SessionsConfig,
    user_id_resolved: bool,
    workspace_id: &str,
) -> (Option<Ulid>, SessionDropCounts) {
    if !cfg.capture {
        return (None, SessionDropCounts::default());
    }
    let (parsed, drops) = parse_ulid_header(headers, SESSION_ID_HEADER);
    if parsed.is_some() {
        return (parsed, drops);
    }
    let auto = match cfg.auto_generate {
        AutoGenerate::Never => false,
        AutoGenerate::Always => true,
        AutoGenerate::Anonymous => !user_id_resolved,
    };
    if !auto {
        return (None, drops);
    }
    if let Some(budget) = cfg.budget.as_ref() {
        if !budget_admits(workspace_id, "session", budget) {
            return (None, drops);
        }
    }
    (Some(Ulid::new()), drops)
}

/// Capture the parent session ID for the current request.
///
/// Parent linkage is caller-supplied only; the proxy does not
/// auto-generate parent IDs because there is no defensible default.
/// The proxy validates ULID format but does NOT verify the parent
/// session exists; the portal reconstructs trees from
/// `(session_id, parent_session_id)` pairs at query time.
pub fn capture_parent_session_id(headers: &HeaderMap) -> (Option<Ulid>, SessionDropCounts) {
    parse_ulid_header(headers, PARENT_SESSION_ID_HEADER)
}

// --- Users (T3.1) ---

/// Per-origin user-ID configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserConfig {
    /// Master capture switch. When `false`, [`capture_user_id`] always
    /// returns `None`.
    #[serde(default = "default_true")]
    pub capture: bool,
    /// Maximum allowed length of the resolved user ID. Values longer
    /// than this are dropped wholesale (no truncation, since
    /// truncation collides distinct identities).
    #[serde(default = "default_user_max_length")]
    pub max_length: usize,
    /// Cap on captured user IDs per workspace per window. `None`
    /// disables the gate (default). When the cap is hit, the
    /// dimension is dropped silently and
    /// `sbproxy_capture_budget_dropped_total{workspace,dimension="user"}`
    /// is incremented.
    #[serde(default)]
    pub budget: Option<BudgetConfig>,
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            capture: true,
            max_length: default_user_max_length(),
            budget: None,
        }
    }
}

// --- Budget gate (T2.3 / T3.3) ---

/// Per-dimension cap that the capture helpers consult before stamping
/// auto-generated session IDs or admitting user IDs onto the request
/// envelope. Counts are kept per workspace and rotate on a fixed
/// window so a hostile burst from one tenant does not poison the
/// shared envelope shape.
///
/// When the cap is hit the offending dimension is dropped silently
/// (no 4xx); a dedicated metric tracks the drop for ops visibility.
/// See `docs/A30.md` (decision log) for the rationale on why this
/// path drops rather than rejects.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BudgetConfig {
    /// Maximum admissions per window. Exceeding this floors further
    /// admissions in the same window to drop-with-metric.
    pub max_per_window: u64,
    /// Window length in seconds. Counters rotate per
    /// `floor(now / window_seconds)` slot.
    #[serde(default = "default_budget_window_secs")]
    pub window_seconds: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_per_window: 1000,
            window_seconds: default_budget_window_secs(),
        }
    }
}

fn default_budget_window_secs() -> u64 {
    60
}

/// Internal counter cell. Each `(workspace, dimension)` key maps to
/// the latest window's start slot and the running count inside it.
#[derive(Debug, Clone, Copy)]
struct BudgetCell {
    window_slot: u64,
    count: u64,
}

fn budget_state() -> &'static Mutex<HashMap<(String, &'static str), BudgetCell>> {
    static STATE: OnceCell<Mutex<HashMap<(String, &'static str), BudgetCell>>> = OnceCell::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns true when `dimension` should be admitted under the budget
/// for `workspace_id`; returns false (and increments
/// `sbproxy_capture_budget_dropped_total`) when the cap is exceeded.
///
/// `dimension` is a `'static str` so the metric label cardinality
/// stays bounded; pass `"session"` or `"user"`.
pub(crate) fn budget_admits(
    workspace_id: &str,
    dimension: &'static str,
    cfg: &BudgetConfig,
) -> bool {
    let window_secs = cfg.window_seconds.max(1);
    let slot = now_secs() / window_secs;
    let key = (workspace_id.to_string(), dimension);

    let mut guard = match budget_state().lock() {
        Ok(g) => g,
        // Poisoned mutex: degrade to admit (fail-open). The capture
        // path is observability, not security; failing closed would
        // silently lose dimensions on a panic in another caller.
        Err(poisoned) => poisoned.into_inner(),
    };
    let cell = guard.entry(key).or_insert(BudgetCell {
        window_slot: slot,
        count: 0,
    });
    if cell.window_slot != slot {
        cell.window_slot = slot;
        cell.count = 0;
    }
    if cell.count >= cfg.max_per_window {
        drop(guard);
        crate::metrics::record_capture_budget_drop(workspace_id, dimension);
        tracing::warn!(
            target: "capture_budget",
            workspace_id = workspace_id,
            dimension = dimension,
            cap = cfg.max_per_window,
            window_seconds = window_secs,
            "capture dimension dropped: per-workspace budget exhausted"
        );
        return false;
    }
    cell.count += 1;
    true
}

fn default_user_max_length() -> usize {
    256
}

/// Per-request counters reporting why user IDs were dropped.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UserDropCounts {
    /// Resolved value exceeded `cfg.max_length`.
    pub length: u32,
    /// Header / claim was present but empty after trimming.
    pub empty: u32,
}

/// Header carrying a caller-supplied user identifier.
pub const USER_ID_HEADER: &str = "x-sb-user-id";

/// Resolve the user ID for the current request per
/// `docs/adr-user-id.md`.
///
/// Precedence:
///
/// 1. `X-Sb-User-Id` request header.
/// 2. JWT `sub` claim (caller passes the value extracted by the JWT
///    auth provider, or `None` when JWT auth is not in the chain).
/// 3. Forward-auth user header (caller passes the value the upstream
///    auth gateway returned, or `None` when forward-auth is not in
///    the chain).
///
/// Returns `(user_id, source)` describing both the value and where it
/// came from. The source is stamped on the event for ops audit.
///
/// Returns `None` when no source resolved (anonymous) or when capture
/// is disabled. Anonymous resolution is *not* an error; the caller
/// should leave [`crate::request_event::RequestEvent::user_id`] as
/// `None`.
///
/// `workspace_id` is consulted by the T3.3 budget gate
/// ([`UserConfig::budget`]) BEFORE the user is admitted. When the
/// per-workspace cap on distinct user IDs is reached the dimension is
/// dropped silently and
/// `sbproxy_capture_budget_dropped_total{workspace,dimension="user"}`
/// is incremented. The cap exists to bound cardinality under attack;
/// dropping is the user-chosen behavior (see ADR + A30 decision log).
pub fn capture_user_id(
    headers: &HeaderMap,
    jwt_sub: Option<&str>,
    forward_auth_user: Option<&str>,
    cfg: &UserConfig,
    workspace_id: &str,
) -> (Option<(String, UserIdSource)>, UserDropCounts) {
    let mut drops = UserDropCounts::default();
    if !cfg.capture {
        return (None, drops);
    }

    // Resolve in precedence order; on the first valid value, ask the
    // budget gate. Two outcomes shape the return:
    //   * admitted: stamp the (id, source) pair on the envelope.
    //   * over budget: drop silently, keep the existing `drops`
    //     counters (no `length`/`empty` bump because the value passed
    //     local validation).
    let resolved: Option<(String, UserIdSource)> = (|| {
        if let Some(v) = headers.get(USER_ID_HEADER) {
            if let Ok(s) = v.to_str() {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    drops.empty += 1;
                } else if trimmed.len() > cfg.max_length {
                    drops.length += 1;
                } else {
                    return Some((trimmed.to_string(), UserIdSource::Header));
                }
            }
        }
        if let Some(sub) = jwt_sub {
            let trimmed = sub.trim();
            if trimmed.is_empty() {
                drops.empty += 1;
            } else if trimmed.len() > cfg.max_length {
                drops.length += 1;
            } else {
                return Some((trimmed.to_string(), UserIdSource::Jwt));
            }
        }
        if let Some(fa) = forward_auth_user {
            let trimmed = fa.trim();
            if trimmed.is_empty() {
                drops.empty += 1;
            } else if trimmed.len() > cfg.max_length {
                drops.length += 1;
            } else {
                return Some((trimmed.to_string(), UserIdSource::ForwardAuth));
            }
        }
        None
    })();

    let Some(pair) = resolved else {
        return (None, drops);
    };

    if let Some(budget) = cfg.budget.as_ref() {
        if !budget_admits(workspace_id, "user", budget) {
            return (None, drops);
        }
    }
    (Some(pair), drops)
}

// --- Generic header capture for the access log ---

/// Default truncation suffix appended to over-cap header values.
pub const HEADER_TRUNCATION_SUFFIX: &str = "...";

/// Capture the subset of `headers` that `is_allowed` accepts, with
/// per-value truncation and an optional redaction pass.
///
/// The caller owns matching policy: `is_allowed` is invoked with the
/// lowercased header name. Wiring lives in `sbproxy-core`, where the
/// `CompiledHeaderAllowlist` (sbproxy-config) and `PiiRedactor`
/// (sbproxy-security) get composed. Keeping this helper closure-based
/// stops `sbproxy-observe` from pulling those crates in.
///
/// Behaviour:
///
/// * Header names are lowercased once for matching; the captured map
///   uses the lowercased form as the key.
/// * Non-UTF-8 header values are skipped silently. The HTTP spec
///   technically allows arbitrary bytes, but emitting them in JSON
///   would either fail or produce escape soup; logs prioritise
///   readability over fidelity for malformed inputs.
/// * Multi-valued headers (RFC 9110 list-form) are joined with `", "`
///   to mirror what an upstream sees.
/// * Values longer than `max_value_bytes` are truncated to the cap and
///   the suffix `"..."` is appended in place of the trailing bytes
///   (the suffix counts toward the cap). A cap of 0 disables capture
///   for non-empty values; an empty value passes through.
/// * `redact` runs after truncation. Returning the input unchanged is
///   the cheap path; the closure can short-circuit when nothing
///   matches.
pub fn capture_headers<F, R>(
    headers: &HeaderMap,
    is_allowed: F,
    max_value_bytes: usize,
    redact: Option<R>,
) -> BTreeMap<String, String>
where
    F: Fn(&str) -> bool,
    R: Fn(&str) -> String,
{
    // Group multi-valued headers under a single lowercased key first so
    // the join order matches HeaderMap iteration order.
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if !is_allowed(&lname) {
            continue;
        }
        let Ok(s) = std::str::from_utf8(value.as_bytes()) else {
            continue;
        };
        grouped.entry(lname).or_default().push(s.to_string());
    }

    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (name, values) in grouped {
        let joined = values.join(", ");
        let truncated = truncate_with_suffix(&joined, max_value_bytes);
        let final_value = match &redact {
            Some(f) => f(&truncated),
            None => truncated,
        };
        out.insert(name, final_value);
    }
    out
}

/// Truncate `s` to at most `max_bytes` bytes, replacing the trailing
/// bytes with [`HEADER_TRUNCATION_SUFFIX`] when truncation occurs.
/// The suffix counts toward the cap, so the output is always
/// `<= max_bytes` bytes. Truncation is byte-aligned to the nearest
/// preceding UTF-8 char boundary so the result remains valid UTF-8.
fn truncate_with_suffix(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let suffix = HEADER_TRUNCATION_SUFFIX;
    if max_bytes <= suffix.len() {
        // Cap is too tight to fit even the suffix; return a prefix of
        // the suffix itself so the result still respects max_bytes.
        return suffix[..max_bytes].to_string();
    }
    let keep = max_bytes - suffix.len();
    // Walk back to the nearest char boundary so we never split a
    // multi-byte codepoint.
    let mut boundary = keep;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut out = String::with_capacity(boundary + suffix.len());
    out.push_str(&s[..boundary]);
    out.push_str(suffix);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderName, HeaderValue};

    fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            let n = HeaderName::from_bytes(name.as_bytes()).unwrap();
            let v = HeaderValue::from_str(value).unwrap();
            h.append(n, v);
        }
        h
    }

    // --- properties ---

    #[test]
    fn properties_basic_capture_lowercases_keys() {
        let headers = headers_from(&[
            ("X-Sb-Property-Environment", "prod"),
            ("X-Sb-Property-Feature-Flag", "agent-v2"),
            ("X-Sb-Property-Customer-Tier", "enterprise"),
        ]);
        let (props, drops) = capture_properties(&headers, &PropertiesConfig::default());
        assert_eq!(props.len(), 3);
        assert_eq!(props.get("environment").unwrap(), "prod");
        assert_eq!(props.get("feature-flag").unwrap(), "agent-v2");
        assert_eq!(props.get("customer-tier").unwrap(), "enterprise");
        assert_eq!(drops, PropertyDropCounts::default());
    }

    #[test]
    fn properties_capture_disabled_returns_empty() {
        let headers = headers_from(&[("X-Sb-Property-Environment", "prod")]);
        let cfg = PropertiesConfig {
            capture: false,
            ..PropertiesConfig::default()
        };
        let (props, drops) = capture_properties(&headers, &cfg);
        assert!(props.is_empty());
        assert_eq!(drops, PropertyDropCounts::default());
    }

    #[test]
    fn properties_count_cap_drops_extras() {
        let mut headers = HeaderMap::new();
        for i in 0..25u32 {
            let n = HeaderName::from_bytes(format!("x-sb-property-k{i}").as_bytes()).unwrap();
            headers.append(n, HeaderValue::from_static("v"));
        }
        let (props, drops) = capture_properties(&headers, &PropertiesConfig::default());
        assert_eq!(props.len(), MAX_PROPERTIES_PER_REQUEST);
        assert_eq!(drops.count, 25 - MAX_PROPERTIES_PER_REQUEST as u32);
    }

    #[test]
    fn properties_oversize_value_dropped() {
        let big = "x".repeat(MAX_PROPERTY_VALUE_LEN + 1);
        let headers = headers_from(&[("X-Sb-Property-Big", big.as_str())]);
        let (props, drops) = capture_properties(&headers, &PropertiesConfig::default());
        assert!(props.is_empty());
        assert_eq!(drops.value_len, 1);
    }

    #[test]
    fn properties_oversize_key_dropped() {
        let big_key = format!("x-sb-property-{}", "a".repeat(MAX_PROPERTY_KEY_LEN + 1));
        let headers = headers_from(&[(big_key.as_str(), "v")]);
        let (props, drops) = capture_properties(&headers, &PropertiesConfig::default());
        assert!(props.is_empty());
        assert_eq!(drops.key_len, 1);
    }

    #[test]
    fn properties_payload_bomb_rejects_entire_batch() {
        // Use values that each pass the per-value length cap but sum
        // past the 8 KiB total payload cap. 20 × 411 bytes = 8220 > 8192.
        let val = "x".repeat(410);
        let mut headers = HeaderMap::new();
        for i in 0..20u32 {
            // Two-char keys keep us under MAX_PROPERTY_KEY_LEN and
            // satisfy the allowlist regex.
            let n = HeaderName::from_bytes(format!("x-sb-property-k{i}").as_bytes()).unwrap();
            headers.append(n, HeaderValue::from_str(&val).unwrap());
        }
        let (props, drops) = capture_properties(&headers, &PropertiesConfig::default());
        assert!(
            props.is_empty(),
            "payload-bomb batch must be rejected wholesale"
        );
        assert_eq!(drops.payload_size, 1);
    }

    #[test]
    fn properties_disallowed_key_charset_dropped() {
        // Spaces and dots violate the allowlist regex.
        let headers = headers_from(&[("x-sb-property-bad.key", "v")]);
        let (props, drops) = capture_properties(&headers, &PropertiesConfig::default());
        assert!(props.is_empty());
        assert_eq!(drops.regex, 1);
    }

    #[test]
    fn properties_redaction_by_exact_key() {
        let headers = headers_from(&[("X-Sb-Property-Customer-Email", "alice@example.com")]);
        let cfg = PropertiesConfig {
            redact: RedactConfig {
                keys: vec!["customer-email".to_string()],
                value_regex: vec![],
            },
            ..PropertiesConfig::default()
        };
        let (props, _) = capture_properties(&headers, &cfg);
        assert_eq!(props.get("customer-email").unwrap(), "[redacted]");
    }

    #[test]
    fn properties_redaction_by_value_regex() {
        let headers = headers_from(&[("X-Sb-Property-Note", "ssn 123-45-6789 leaked")]);
        let cfg = PropertiesConfig {
            redact: RedactConfig {
                keys: vec![],
                value_regex: vec![r"\b\d{3}-\d{2}-\d{4}\b".to_string()],
            },
            ..PropertiesConfig::default()
        };
        let (props, _) = capture_properties(&headers, &cfg);
        assert_eq!(props.get("note").unwrap(), "[redacted]");
    }

    // --- sessions ---

    fn ulid_str() -> String {
        Ulid::new().to_string()
    }

    /// Workspace id for capture tests; the budget gate is keyed on
    /// it but tests run with `budget = None` so the value is simply a
    /// pass-through label.
    const TEST_WS: &str = "test_ws";

    #[test]
    fn session_caller_supplied_wins() {
        let id = ulid_str();
        let headers = headers_from(&[("X-Sb-Session-Id", id.as_str())]);
        let (got, drops) = capture_session_id(&headers, &SessionsConfig::default(), false, TEST_WS);
        assert_eq!(got.unwrap().to_string(), id);
        assert_eq!(drops, SessionDropCounts::default());
    }

    #[test]
    fn session_invalid_format_dropped_then_auto_generated() {
        let headers = headers_from(&[("X-Sb-Session-Id", "not-a-ulid")]);
        let (got, drops) = capture_session_id(&headers, &SessionsConfig::default(), false, TEST_WS);
        // Anonymous default: invalid header drops, then auto-generation
        // mints a fresh ULID because no user_id is resolved.
        assert!(got.is_some());
        assert_eq!(drops.invalid_format, 1);
    }

    #[test]
    fn session_anonymous_only_when_no_user_resolved() {
        let headers = HeaderMap::new();

        // user resolved -> no auto-gen.
        let (got, _) = capture_session_id(&headers, &SessionsConfig::default(), true, TEST_WS);
        assert!(got.is_none());

        // user not resolved -> auto-gen.
        let (got, _) = capture_session_id(&headers, &SessionsConfig::default(), false, TEST_WS);
        assert!(got.is_some());
    }

    #[test]
    fn session_never_policy_does_not_auto_generate() {
        let cfg = SessionsConfig {
            auto_generate: AutoGenerate::Never,
            ..SessionsConfig::default()
        };
        let headers = HeaderMap::new();
        let (got, _) = capture_session_id(&headers, &cfg, false, TEST_WS);
        assert!(got.is_none());
    }

    #[test]
    fn session_always_policy_auto_generates_for_authenticated_too() {
        let cfg = SessionsConfig {
            auto_generate: AutoGenerate::Always,
            ..SessionsConfig::default()
        };
        let headers = HeaderMap::new();
        let (got, _) = capture_session_id(&headers, &cfg, true, TEST_WS);
        assert!(got.is_some());
    }

    #[test]
    fn session_capture_disabled_returns_none_even_with_header() {
        let cfg = SessionsConfig {
            capture: false,
            ..SessionsConfig::default()
        };
        let headers = headers_from(&[("X-Sb-Session-Id", ulid_str().as_str())]);
        let (got, _) = capture_session_id(&headers, &cfg, false, TEST_WS);
        assert!(got.is_none());
    }

    /// Mint a unique workspace identifier per test invocation so the
    /// shared budget map (process-global) cannot leak counters
    /// between test cases when cargo runs them in parallel.
    fn unique_test_workspace(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        format!(
            "{prefix}_{}_{}",
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )
    }

    #[test]
    fn session_budget_drops_after_cap() {
        // Auto-generated session IDs count against the budget; the
        // first three pass, the fourth drops silently.
        let cfg = SessionsConfig {
            budget: Some(BudgetConfig {
                max_per_window: 3,
                window_seconds: 60,
            }),
            ..SessionsConfig::default()
        };
        let headers = HeaderMap::new();
        let workspace = unique_test_workspace("session_budget");

        let (a, _) = capture_session_id(&headers, &cfg, false, &workspace);
        let (b, _) = capture_session_id(&headers, &cfg, false, &workspace);
        let (c, _) = capture_session_id(&headers, &cfg, false, &workspace);
        let (d, _) = capture_session_id(&headers, &cfg, false, &workspace);
        assert!(a.is_some());
        assert!(b.is_some());
        assert!(c.is_some());
        assert!(d.is_none(), "fourth admission must be dropped by budget");
    }

    #[test]
    fn session_budget_does_not_count_caller_supplied_ids() {
        // X-Sb-Session-Id wins before the budget check; no auto-gen
        // means no budget consumption.
        let cfg = SessionsConfig {
            budget: Some(BudgetConfig {
                max_per_window: 1,
                window_seconds: 60,
            }),
            ..SessionsConfig::default()
        };
        let workspace = unique_test_workspace("session_caller");

        for _ in 0..5 {
            let id = ulid_str();
            let headers = headers_from(&[("X-Sb-Session-Id", id.as_str())]);
            let (got, _) = capture_session_id(&headers, &cfg, false, &workspace);
            assert!(got.is_some(), "caller-supplied IDs are never gated");
        }
    }

    #[test]
    fn parent_session_validates_format() {
        let id = ulid_str();
        let headers = headers_from(&[("X-Sb-Parent-Session-Id", id.as_str())]);
        let (got, drops) = capture_parent_session_id(&headers);
        assert_eq!(got.unwrap().to_string(), id);
        assert_eq!(drops, SessionDropCounts::default());

        let headers = headers_from(&[("X-Sb-Parent-Session-Id", "junk")]);
        let (got, drops) = capture_parent_session_id(&headers);
        assert!(got.is_none());
        assert_eq!(drops.invalid_format, 1);
    }

    // --- users ---

    #[test]
    fn user_header_wins_over_jwt_and_forward_auth() {
        let headers = headers_from(&[("X-Sb-User-Id", "from-header")]);
        let (got, _) = capture_user_id(
            &headers,
            Some("from-jwt"),
            Some("from-fa"),
            &UserConfig::default(),
            TEST_WS,
        );
        let (id, src) = got.unwrap();
        assert_eq!(id, "from-header");
        assert_eq!(src, UserIdSource::Header);
    }

    #[test]
    fn user_jwt_wins_over_forward_auth_when_no_header() {
        let headers = HeaderMap::new();
        let (got, _) = capture_user_id(
            &headers,
            Some("from-jwt"),
            Some("from-fa"),
            &UserConfig::default(),
            TEST_WS,
        );
        let (id, src) = got.unwrap();
        assert_eq!(id, "from-jwt");
        assert_eq!(src, UserIdSource::Jwt);
    }

    #[test]
    fn user_forward_auth_used_only_when_no_header_no_jwt() {
        let headers = HeaderMap::new();
        let (got, _) = capture_user_id(
            &headers,
            None,
            Some("from-fa"),
            &UserConfig::default(),
            TEST_WS,
        );
        let (id, src) = got.unwrap();
        assert_eq!(id, "from-fa");
        assert_eq!(src, UserIdSource::ForwardAuth);
    }

    #[test]
    fn user_no_source_resolves_to_none() {
        let headers = HeaderMap::new();
        let (got, drops) = capture_user_id(&headers, None, None, &UserConfig::default(), TEST_WS);
        assert!(got.is_none());
        assert_eq!(drops, UserDropCounts::default());
    }

    #[test]
    fn user_length_cap_drops() {
        let big = "u".repeat(257);
        let headers = headers_from(&[("X-Sb-User-Id", big.as_str())]);
        let (got, drops) = capture_user_id(&headers, None, None, &UserConfig::default(), TEST_WS);
        assert!(got.is_none());
        assert_eq!(drops.length, 1);
    }

    #[test]
    fn user_empty_header_falls_through_to_jwt() {
        let headers = headers_from(&[("X-Sb-User-Id", "  ")]);
        let (got, drops) = capture_user_id(
            &headers,
            Some("from-jwt"),
            None,
            &UserConfig::default(),
            TEST_WS,
        );
        let (id, src) = got.unwrap();
        assert_eq!(id, "from-jwt");
        assert_eq!(src, UserIdSource::Jwt);
        // The empty header was counted as a drop before falling through.
        assert_eq!(drops.empty, 1);
    }

    #[test]
    fn user_capture_disabled_returns_none() {
        let headers = headers_from(&[("X-Sb-User-Id", "u")]);
        let cfg = UserConfig {
            capture: false,
            ..UserConfig::default()
        };
        let (got, _) = capture_user_id(&headers, Some("j"), Some("f"), &cfg, TEST_WS);
        assert!(got.is_none());
    }

    #[test]
    fn user_budget_drops_after_cap() {
        let cfg = UserConfig {
            budget: Some(BudgetConfig {
                max_per_window: 2,
                window_seconds: 60,
            }),
            ..UserConfig::default()
        };
        let workspace = unique_test_workspace("user_budget");

        let h1 = headers_from(&[("X-Sb-User-Id", "u1")]);
        let h2 = headers_from(&[("X-Sb-User-Id", "u2")]);
        let h3 = headers_from(&[("X-Sb-User-Id", "u3")]);
        let (a, _) = capture_user_id(&h1, None, None, &cfg, &workspace);
        let (b, _) = capture_user_id(&h2, None, None, &cfg, &workspace);
        let (c, _) = capture_user_id(&h3, None, None, &cfg, &workspace);
        assert!(a.is_some());
        assert!(b.is_some());
        assert!(
            c.is_none(),
            "third admission should be dropped silently by the budget"
        );
    }

    #[test]
    fn user_budget_isolated_per_workspace() {
        let cfg = UserConfig {
            budget: Some(BudgetConfig {
                max_per_window: 1,
                window_seconds: 60,
            }),
            ..UserConfig::default()
        };
        let h = headers_from(&[("X-Sb-User-Id", "alice")]);
        let ws_a = unique_test_workspace("user_isol_a");
        let ws_b = unique_test_workspace("user_isol_b");
        let (a, _) = capture_user_id(&h, None, None, &cfg, &ws_a);
        // Same id but a different workspace owns its own counter.
        let (b, _) = capture_user_id(&h, None, None, &cfg, &ws_b);
        let (a2, _) = capture_user_id(&h, None, None, &cfg, &ws_a);
        assert!(a.is_some());
        assert!(b.is_some());
        assert!(
            a2.is_none(),
            "second admission for ws_a must drop while ws_b stays open"
        );
    }

    // --- capture_headers ---

    fn always_allow(_: &str) -> bool {
        true
    }
    fn never_allow(_: &str) -> bool {
        false
    }

    #[test]
    fn capture_headers_lowercases_and_filters() {
        let h = headers_from(&[
            ("User-Agent", "curl/8.0"),
            ("Referer", "https://example.com"),
            ("X-Cache", "HIT"),
        ]);
        let allow = |name: &str| matches!(name, "user-agent" | "x-cache");
        let captured = capture_headers(&h, allow, 1024, None::<fn(&str) -> String>);
        assert_eq!(captured.len(), 2);
        assert_eq!(captured.get("user-agent").unwrap(), "curl/8.0");
        assert_eq!(captured.get("x-cache").unwrap(), "HIT");
        assert!(!captured.contains_key("referer"));
    }

    #[test]
    fn capture_headers_empty_when_no_match() {
        let h = headers_from(&[("user-agent", "curl/8.0")]);
        let captured = capture_headers(&h, never_allow, 1024, None::<fn(&str) -> String>);
        assert!(captured.is_empty());
    }

    #[test]
    fn capture_headers_truncates_long_values_with_suffix() {
        let value = "a".repeat(2048);
        let h = headers_from(&[("user-agent", value.as_str())]);
        let captured = capture_headers(&h, always_allow, 32, None::<fn(&str) -> String>);
        let got = captured.get("user-agent").unwrap();
        assert_eq!(got.len(), 32);
        assert!(got.ends_with(HEADER_TRUNCATION_SUFFIX));
        assert!(got.starts_with("aaa"));
    }

    #[test]
    fn capture_headers_short_value_passes_through() {
        let h = headers_from(&[("user-agent", "curl/8.0")]);
        let captured = capture_headers(&h, always_allow, 1024, None::<fn(&str) -> String>);
        assert_eq!(captured.get("user-agent").unwrap(), "curl/8.0");
    }

    #[test]
    fn capture_headers_joins_multi_valued() {
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("text/html"),
        );
        h.append(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("application/json"),
        );
        let captured = capture_headers(&h, always_allow, 1024, None::<fn(&str) -> String>);
        assert_eq!(
            captured.get("accept").unwrap(),
            "text/html, application/json"
        );
    }

    #[test]
    fn capture_headers_skips_non_utf8_silently() {
        // HeaderValue accepts arbitrary bytes via from_bytes; build a
        // value with a non-UTF8 sequence (0xff is never valid UTF-8).
        let mut h = HeaderMap::new();
        h.append(
            HeaderName::from_static("x-binary"),
            HeaderValue::from_bytes(&[0xff, 0xfe, 0xfd]).unwrap(),
        );
        h.append(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("curl/8.0"),
        );
        let captured = capture_headers(&h, always_allow, 1024, None::<fn(&str) -> String>);
        // Non-UTF8 silently dropped; valid neighbour still captured.
        assert!(!captured.contains_key("x-binary"));
        assert_eq!(captured.get("user-agent").unwrap(), "curl/8.0");
    }

    #[test]
    fn capture_headers_redact_callback_runs_after_truncation() {
        let h = headers_from(&[("authorization", "Bearer sk-leaked-value")]);
        let captured = capture_headers(
            &h,
            always_allow,
            1024,
            Some(|v: &str| v.replace("sk-leaked-value", "[REDACTED]")),
        );
        assert_eq!(captured.get("authorization").unwrap(), "Bearer [REDACTED]");
    }

    #[test]
    fn capture_headers_truncation_preserves_utf8_boundary() {
        // Multi-byte char at the cap boundary must not be split.
        // "café" = 5 bytes (c, a, f, c3, a9). Cap at 4 should
        // truncate to "c..." (the suffix takes 3 bytes leaving 1 for
        // content).
        let h = headers_from(&[("x-foo", "café and more text here")]);
        let captured = capture_headers(&h, always_allow, 4, None::<fn(&str) -> String>);
        let got = captured.get("x-foo").unwrap();
        assert!(got.is_char_boundary(got.len()));
        assert!(got.ends_with("..."));
        assert!(got.len() <= 4);
    }

    #[test]
    fn truncate_with_suffix_short_input_passes_through() {
        assert_eq!(truncate_with_suffix("hi", 10), "hi");
    }

    #[test]
    fn truncate_with_suffix_cap_smaller_than_suffix() {
        // Defensive: cap=2 cannot fit the 3-char suffix. Output must
        // not exceed the cap.
        let out = truncate_with_suffix("abcdefg", 2);
        assert!(out.len() <= 2);
    }
}
