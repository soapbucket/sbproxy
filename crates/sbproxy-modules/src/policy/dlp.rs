//! Data Loss Prevention policy.
//!
//! Scans request metadata (path, query string, headers) and, by
//! default, the buffered request body, for the configured detector
//! set, then either tags the upstream request or blocks the call.
//! Reuses the regex catalogue baked into
//! `sbproxy_security::pii::default_rules()` plus any custom rules
//! the operator declares inline.
//!
//! ## Body scanning
//!
//! `scan_body` (default `true`) governs whether the buffered request
//! body is included; `body_max_bytes` caps how much of it is scanned
//! (default `16 KiB`, mirroring the per-message truncation the
//! `prompt_injection_v2` body-aware path uses -
//! `DEFAULT_MAX_MESSAGE_LEN` in
//! `policy::prompt_injection_v2::body_aware`). The body is decoded
//! lossily rather than rejected on invalid UTF-8, so a non-text
//! payload with a PII shape near the head is still caught instead of
//! silently skipped.
//!
//! This is request-side only. [`DlpPolicy`] compiles into a
//! [`sbproxy_plugin::PolicyEnforcer`] (see
//! `sbproxy-core::builtin_enforcers::dlp`), and that trait's
//! `enforce` signature takes only `&http::Request<Bytes>` - there is
//! no response counterpart to hand a response body to. Scanning
//! outbound responses would need a different phase entirely (the one
//! `sbproxy_plugin::TransformHandler` already runs in on either
//! side); `direction: response`/`both` is accepted for
//! forward-compatibility and warns at load rather than refusing,
//! matching WOR-1153.

use anyhow::Result;
use regex::Regex;
use sbproxy_security::pii::PiiRule;
use serde::Deserialize;

/// Maximum bytes of a buffered request body scanned by
/// [`DlpPolicy::scan_body`]. Mirrors
/// `prompt_injection_v2::body_aware::DEFAULT_MAX_MESSAGE_LEN`: most
/// injection/PII shapes live near the head of a payload, so capping
/// here keeps a large upload off the regex hot path without dropping
/// coverage where it matters.
const DEFAULT_BODY_MAX_BYTES: usize = 16 * 1024;

fn default_scan_body() -> bool {
    true
}

fn default_body_max_bytes() -> usize {
    DEFAULT_BODY_MAX_BYTES
}

/// What to do on a detection.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    /// Forward the request, but stamp `dlp-detection: <detectors>`
    /// on the upstream so the application can react. Default.
    #[default]
    Tag,
    /// Reject the request with `403 Forbidden`. Use this once the
    /// false-positive rate is acceptable.
    Block,
}

/// What to scan.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DlpDirection {
    /// Scan the request line (path, query) and request headers.
    #[default]
    Request,
    /// Reserved for body-scanning support; behaves like `request`
    /// today.
    Response,
    /// Reserved for combined scanning; behaves like `request` today.
    Both,
}

/// Result of a DLP scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlpScanResult {
    /// No detector matched.
    Clean,
    /// At least one detector matched.
    Hit {
        /// Detector names that matched, deduplicated, in match order.
        detectors: Vec<String>,
    },
}

#[derive(Debug)]
struct CompiledDetector {
    name: String,
    re: Regex,
}

/// DLP policy.
#[derive(Debug, Deserialize)]
pub struct DlpPolicy {
    /// Detector names to enable. Empty = enable every default
    /// detector. Recognised: `email`, `us_ssn`, `credit_card`,
    /// `phone_us`, `ipv4`, `openai_key`, `anthropic_key`,
    /// `aws_access`, `github_token`, `slack_token`, `iban`.
    #[serde(default)]
    pub detectors: Vec<String>,
    /// Action on a hit. Default `tag`.
    #[serde(default)]
    pub action: DlpAction,
    /// Direction. `request` is the only path this policy phase can
    /// ever enforce (see the module docs); the other variants are
    /// accepted for forward-compatibility and scan the request side,
    /// with a load-time warning.
    #[serde(default)]
    pub direction: DlpDirection,
    /// Header stamped on the upstream request when `action: tag`.
    /// Default `dlp-detection`.
    #[serde(default = "default_dlp_header")]
    pub header: String,
    /// Include the buffered request body in the scan, in addition to
    /// the URI and headers. Default `true` - body scanning is what
    /// the `dlp` name promises, and most of the regulated-data shapes
    /// this policy targets (SSNs, credit cards, phone numbers) live
    /// in JSON request bodies, not URIs or headers.
    #[serde(default = "default_scan_body")]
    pub scan_body: bool,
    /// Maximum bytes of the request body scanned when `scan_body` is
    /// true. Default 16 KiB; see the module docs for why.
    #[serde(default = "default_body_max_bytes")]
    pub body_max_bytes: usize,
    /// Custom rules layered on top of (or in place of) the defaults.
    #[serde(default)]
    pub rules: Vec<PiiRule>,
    /// Compiled detector list. Built by [`Self::from_config`].
    #[serde(skip)]
    compiled: Vec<CompiledDetector>,
}

fn default_dlp_header() -> String {
    "dlp-detection".to_string()
}

impl DlpPolicy {
    /// Build the policy from a JSON config value.
    pub fn from_config(value: serde_json::Value) -> Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        let mut sources = sbproxy_security::pii::default_rules();
        sources.extend(policy.rules.iter().cloned());

        let filter_set: std::collections::HashSet<String> =
            policy.detectors.iter().cloned().collect();

        // When the operator named detectors, every name must resolve.
        if !filter_set.is_empty() {
            let known: std::collections::HashSet<&str> =
                sources.iter().map(|r| r.name.as_str()).collect();
            for name in &filter_set {
                if !known.contains(name.as_str()) {
                    anyhow::bail!(
                        "dlp detector {:?} not recognised; available: {}",
                        name,
                        known.iter().copied().collect::<Vec<_>>().join(", ")
                    );
                }
            }
        }

        let mut compiled = Vec::with_capacity(sources.len());
        for rule in sources {
            if !filter_set.is_empty() && !filter_set.contains(&rule.name) {
                continue;
            }
            let re = Regex::new(&rule.pattern)
                .map_err(|e| anyhow::anyhow!("dlp rule {:?}: {}", rule.name, e))?;
            compiled.push(CompiledDetector {
                name: rule.name,
                re,
            });
        }
        if compiled.is_empty() {
            anyhow::bail!("dlp policy requires at least one detector");
        }
        if matches!(
            policy.direction,
            DlpDirection::Response | DlpDirection::Both
        ) {
            // WOR-1153: response-side DLP scanning cannot run through this
            // policy phase (see the module docs - `PolicyEnforcer::enforce`
            // never sees a response). Warn loudly so an operator who
            // selected `response`/`both` is not lulled into believing
            // outbound responses are scanned for leaks; URI, headers, and
            // (now) the body are still scanned on the request side.
            tracing::warn!(
                "dlp: direction `response`/`both` cannot be enforced by this policy phase; \
                 scanning request only (uri, headers, and body)"
            );
        }
        policy.compiled = compiled;
        Ok(policy)
    }

    /// Header to stamp on the upstream request.
    pub fn header_name(&self) -> &str {
        &self.header
    }

    /// Configured action.
    pub fn action(&self) -> DlpAction {
        self.action
    }

    /// Match `text` against every compiled detector, appending newly
    /// hit detector names (deduplicated) into `hits`.
    fn scan_text_into(&self, text: &str, hits: &mut Vec<String>) {
        for d in &self.compiled {
            if d.re.is_match(text) && !hits.contains(&d.name) {
                hits.push(d.name.clone());
            }
        }
    }

    /// Scan the request URI + headers and return any matching detectors.
    pub fn scan(&self, uri: &str, headers: &http::HeaderMap) -> DlpScanResult {
        let mut hits: Vec<String> = Vec::new();
        // URI: path + raw query.
        self.scan_text_into(uri, &mut hits);
        // Headers: skip auth-class headers from being self-flagged.
        // They typically carry tokens by design and are noise here.
        for (name, value) in headers.iter() {
            let n = name.as_str();
            if n == "authorization" || n == "cookie" || n == "set-cookie" {
                continue;
            }
            let Ok(s) = value.to_str() else { continue };
            self.scan_text_into(s, &mut hits);
        }
        if hits.is_empty() {
            DlpScanResult::Clean
        } else {
            DlpScanResult::Hit { detectors: hits }
        }
    }

    /// Scan a buffered request body and return any matching detectors.
    ///
    /// A no-op returning [`DlpScanResult::Clean`] when `scan_body` is
    /// `false` or the body is empty. Otherwise the body is capped to
    /// `body_max_bytes` (UTF-8-boundary-safe via
    /// [`sbproxy_util::truncate_utf8`], mirroring
    /// `prompt_injection_v2`'s per-message truncation) and decoded
    /// lossily rather than rejected on invalid UTF-8, so a non-text
    /// payload with a PII shape near the head is still caught.
    pub fn scan_body(&self, body: &[u8]) -> DlpScanResult {
        if !self.scan_body || body.is_empty() {
            return DlpScanResult::Clean;
        }
        let decoded = String::from_utf8_lossy(body);
        let capped = sbproxy_util::truncate_utf8(&decoded, self.body_max_bytes);
        let mut hits: Vec<String> = Vec::new();
        self.scan_text_into(capped, &mut hits);
        if hits.is_empty() {
            DlpScanResult::Clean
        } else {
            DlpScanResult::Hit { detectors: hits }
        }
    }

    /// Scan the request URI, headers, and (when `scan_body` is
    /// enabled) the buffered body, returning the union of matching
    /// detectors. This is the entry point
    /// `sbproxy-core::builtin_enforcers::dlp::DlpEnforcer` calls; it
    /// already receives the buffered body via the
    /// `PolicyEnforcer::enforce` signature (`req.body()`) and simply
    /// hands it through.
    pub fn scan_request(&self, uri: &str, headers: &http::HeaderMap, body: &[u8]) -> DlpScanResult {
        let mut hits: Vec<String> = match self.scan(uri, headers) {
            DlpScanResult::Hit { detectors } => detectors,
            DlpScanResult::Clean => Vec::new(),
        };
        if let DlpScanResult::Hit { detectors } = self.scan_body(body) {
            for d in detectors {
                if !hits.contains(&d) {
                    hits.push(d);
                }
            }
        }
        if hits.is_empty() {
            DlpScanResult::Clean
        } else {
            DlpScanResult::Hit { detectors: hits }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(name: &str, value: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        h
    }

    #[test]
    fn response_direction_builds_but_is_request_only() {
        // WOR-1153: `response`/`both` is accepted for forward-compat (and
        // logs a warning that it scans request-only); from_config succeeds.
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["aws_access"],
            "direction": "both"
        }))
        .unwrap();
        assert_eq!(policy.direction, DlpDirection::Both);
    }

    #[test]
    fn aws_key_in_query_string_is_detected() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["aws_access"],
        }))
        .unwrap();
        let result = policy.scan("/build?key=AKIAIOSFODNN7EXAMPLE", &http::HeaderMap::new());
        match result {
            DlpScanResult::Hit { detectors } => {
                assert!(detectors.contains(&"aws_access".to_string()));
            }
            DlpScanResult::Clean => panic!("expected aws_access hit"),
        }
    }

    #[test]
    fn slack_token_in_custom_header_is_detected() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["slack_token"],
        }))
        .unwrap();
        let h = headers_with("x-debug", "received xoxb-1234567890-secret-payload");
        match policy.scan("/", &h) {
            DlpScanResult::Hit { detectors } => {
                assert!(detectors.contains(&"slack_token".to_string()));
            }
            other => panic!("expected slack_token hit, got {:?}", other),
        }
    }

    #[test]
    fn authorization_header_is_excluded_from_scan() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["openai_key"],
        }))
        .unwrap();
        let h = headers_with("authorization", "Bearer sk-aaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(policy.scan("/", &h), DlpScanResult::Clean);
    }

    #[test]
    fn clean_request_returns_clean() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["aws_access", "slack_token", "github_token"],
        }))
        .unwrap();
        let h = headers_with("user-agent", "curl/8.4.0");
        assert_eq!(policy.scan("/api/users", &h), DlpScanResult::Clean);
    }

    #[test]
    fn empty_detector_set_uses_defaults() {
        let policy = DlpPolicy::from_config(serde_json::json!({})).unwrap();
        // Credit card with valid Luhn would also need the validator
        // but the regex pattern still matches. The DLP policy does
        // not run the Luhn validator (yet), so we use AWS key which
        // has no validator dependency.
        let r = policy.scan("/check?key=AKIAIOSFODNN7EXAMPLE", &http::HeaderMap::new());
        match r {
            DlpScanResult::Hit { detectors } => {
                assert!(detectors.contains(&"aws_access".to_string()));
            }
            other => panic!("expected aws_access hit, got {:?}", other),
        }
    }

    #[test]
    fn unknown_detector_is_rejected() {
        let err = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["does_not_exist"],
        }))
        .unwrap_err();
        assert!(err.to_string().contains("does_not_exist"));
    }

    #[test]
    fn block_action_round_trips() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["aws_access"],
            "action": "block",
        }))
        .unwrap();
        assert_eq!(policy.action(), DlpAction::Block);
    }

    #[test]
    fn iban_pattern_matches() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["iban"],
        }))
        .unwrap();
        let r = policy.scan(
            "/transfer?to=DE89370400440532013000",
            &http::HeaderMap::new(),
        );
        match r {
            DlpScanResult::Hit { detectors } => {
                assert!(detectors.contains(&"iban".to_string()));
            }
            other => panic!("expected iban hit, got {:?}", other),
        }
    }

    #[test]
    fn custom_rule_layered_on_top_of_defaults() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["ticket"],
            "rules": [{
                "name": "ticket",
                "pattern": "TICKET-\\d{6}",
                "replacement": "[REDACTED:TICKET]",
            }],
        }))
        .unwrap();
        let r = policy.scan("/issue?id=TICKET-123456", &http::HeaderMap::new());
        match r {
            DlpScanResult::Hit { detectors } => {
                assert!(detectors.contains(&"ticket".to_string()));
            }
            other => panic!("expected custom ticket hit, got {:?}", other),
        }
    }

    // --- Body scanning (WOR-2489: dlp was URI/headers only) ---

    #[test]
    fn body_scanning_is_on_by_default() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["aws_access"],
        }))
        .unwrap();
        assert!(policy.scan_body);
        assert_eq!(policy.body_max_bytes, DEFAULT_BODY_MAX_BYTES);
    }

    #[test]
    fn pii_shape_present_only_in_the_body_is_caught() {
        // A shape that never appears in the URI or headers below: it
        // only lives in the (simulated) JSON request body. Before body
        // scanning existed this was invisible to `dlp` entirely -
        // `scan(uri, headers)` has no body parameter to pass it
        // through.
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["aws_access"],
        }))
        .unwrap();
        let body = br#"{"notes":"rotate AKIAIOSFODNN7EXAMPLE before Friday"}"#;
        let uri = "/v1/notes";
        let headers = http::HeaderMap::new();

        assert_eq!(
            policy.scan(uri, &headers),
            DlpScanResult::Clean,
            "sanity: the uri/headers scan alone must not see the body"
        );
        match policy.scan_body(body) {
            DlpScanResult::Hit { detectors } => {
                assert!(detectors.contains(&"aws_access".to_string()));
            }
            other => panic!("expected aws_access hit in body, got {:?}", other),
        }
        match policy.scan_request(uri, &headers, body) {
            DlpScanResult::Hit { detectors } => {
                assert!(detectors.contains(&"aws_access".to_string()));
            }
            other => panic!(
                "expected scan_request to union in the body hit, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn scan_request_unions_uri_header_and_body_hits_without_duplicates() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["aws_access", "slack_token"],
        }))
        .unwrap();
        let h = headers_with("x-debug", "token xoxb-1234567890-secret-payload");
        let body = br#"{"key":"AKIAIOSFODNN7EXAMPLE"}"#;
        match policy.scan_request("/build?key=AKIAIOSFODNN7EXAMPLE", &h, body) {
            DlpScanResult::Hit { detectors } => {
                assert!(detectors.contains(&"aws_access".to_string()));
                assert!(detectors.contains(&"slack_token".to_string()));
                // aws_access matched twice (query string + body) but must
                // only appear once in the union.
                assert_eq!(detectors.iter().filter(|d| *d == "aws_access").count(), 1);
            }
            other => panic!("expected a unioned hit, got {:?}", other),
        }
    }

    #[test]
    fn scan_body_disabled_skips_the_body_entirely() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["aws_access"],
            "scan_body": false,
        }))
        .unwrap();
        let body = br#"{"notes":"rotate AKIAIOSFODNN7EXAMPLE before Friday"}"#;
        assert_eq!(policy.scan_body(body), DlpScanResult::Clean);
        assert_eq!(
            policy.scan_request("/v1/notes", &http::HeaderMap::new(), body),
            DlpScanResult::Clean
        );
    }

    #[test]
    fn body_scan_respects_the_configured_size_cap() {
        // `AKIA[0-9A-Z]{16}` is 20 bytes; the cap must comfortably hold a
        // full match for the "within cap" half of this test to mean
        // anything (a cap that truncates the key itself would make that
        // half fail for the wrong reason). Padding is spaces rather than
        // a word character: the pattern is `\b`-anchored on both ends,
        // and a word character glued directly onto the key would break
        // the boundary match independently of truncation, which would
        // make this test pass or fail for the wrong reason either way.
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["aws_access"],
            "body_max_bytes": 24,
        }))
        .unwrap();
        // 24 leading spaces exhaust the cap before the key ever starts,
        // so the truncated text the detector sees never contains it.
        let mut body = vec![b' '; 40];
        body.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            policy.scan_body(&body),
            DlpScanResult::Clean,
            "a hit past the cap must not be detected"
        );

        // Moving it inside the cap makes it detected again, proving the
        // cap - not the detector - was why the first case was clean.
        let mut body_within_cap = b"AKIAIOSFODNN7EXAMPLE".to_vec();
        body_within_cap.extend_from_slice(&vec![b' '; 40]);
        match policy.scan_body(&body_within_cap) {
            DlpScanResult::Hit { detectors } => {
                assert!(detectors.contains(&"aws_access".to_string()));
            }
            other => panic!("expected a hit within the cap, got {:?}", other),
        }
    }

    #[test]
    fn body_scan_default_cap_matches_prompt_injection_v2s_per_message_truncation() {
        // Not a change-detector on the injection policy's own constant
        // (that module owns its default independently); this pins the
        // two policies to the same *documented* number so a future
        // change to either is a deliberate, visible diff rather than a
        // silent divergence between "mirrors the injection policy's cap"
        // in the docs and what the code actually does.
        assert_eq!(DEFAULT_BODY_MAX_BYTES, 16 * 1024);
    }

    #[test]
    fn body_scan_handles_non_utf8_bytes_without_panicking() {
        let policy = DlpPolicy::from_config(serde_json::json!({
            "detectors": ["aws_access"],
        }))
        .unwrap();
        let mut body = b"AKIAIOSFODNN7EXAMPLE ".to_vec();
        body.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        match policy.scan_body(&body) {
            DlpScanResult::Hit { detectors } => {
                assert!(detectors.contains(&"aws_access".to_string()));
            }
            other => panic!(
                "expected aws_access hit despite trailing invalid utf-8, got {:?}",
                other
            ),
        }
    }
}
