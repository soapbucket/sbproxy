//! Data Loss Prevention policy.
//!
//! Scans request metadata (path, query string, headers) for the
//! configured detector set and either tags the upstream request or
//! blocks the call. Reuses the regex catalogue baked into
//! `sbproxy_security::pii::default_rules()` plus any custom rules
//! the operator declares inline.
//!
//! Body scanning is intentionally out of scope for this OSS cut. The
//! existing `pii:` block on `ai_proxy` origins handles request-body
//! redaction with the same regex catalogue today; a follow-up
//! extends this policy to consume the buffered body produced by
//! `RequestValidator`.

use anyhow::Result;
use regex::Regex;
use sbproxy_security::pii::PiiRule;
use serde::Deserialize;

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
    /// Direction. `request` is the only path enforced today; the
    /// other variants are accepted for forward-compatibility but
    /// scan the request side until body buffering lands.
    #[serde(default)]
    pub direction: DlpDirection,
    /// Header stamped on the upstream request when `action: tag`.
    /// Default `dlp-detection`.
    #[serde(default = "default_dlp_header")]
    pub header: String,
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

    /// Scan the request URI + headers and return any matching detectors.
    pub fn scan(&self, uri: &str, headers: &http::HeaderMap) -> DlpScanResult {
        let mut hits: Vec<String> = Vec::new();
        // URI: path + raw query.
        for d in &self.compiled {
            if d.re.is_match(uri) && !hits.contains(&d.name) {
                hits.push(d.name.clone());
            }
        }
        // Headers: skip auth-class headers from being self-flagged.
        // They typically carry tokens by design and are noise here.
        for (name, value) in headers.iter() {
            let n = name.as_str();
            if n == "authorization" || n == "cookie" || n == "set-cookie" {
                continue;
            }
            let Ok(s) = value.to_str() else { continue };
            for d in &self.compiled {
                if d.re.is_match(s) && !hits.contains(&d.name) {
                    hits.push(d.name.clone());
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
}
