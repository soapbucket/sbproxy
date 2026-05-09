//! Web Application Firewall policy.
//!
//! Provides OWASP CRS-based request filtering, custom rules, and
//! configurable actions on match. Supports a remote rule-feed
//! subscription that hot-loads signed rule bundles into the running
//! policy without a restart.

use regex::Regex;
use serde::Deserialize;
use std::sync::Arc;

use super::feed::{FeedRuleAction, WafFeedConfig, WafFeedSubscriber};

/// Default paranoia level when none is configured. Mirrors the OWASP CRS
/// convention where 1 is the lowest false-positive setting.
const DEFAULT_PARANOIA: u8 = 1;

/// Maximum supported paranoia level. Matches the OWASP CRS 1-4 range.
const MAX_PARANOIA: u8 = 4;

/// Web Application Firewall policy.
///
/// Provides OWASP CRS-based request filtering, custom rules, and
/// configurable actions on match. Fields are stored as generic values
/// for forward compatibility with the Go implementation.
///
/// The `paranoia` field follows the OWASP CRS convention. Level 1 is the
/// default and runs only the lowest-false-positive rules. Levels 2-4
/// progressively enable stricter rules at the cost of more false
/// positives. Rules without an explicit paranoia attribute default to
/// paranoia=1 and therefore always run.
#[derive(Debug, Deserialize)]
pub struct WafPolicy {
    /// OWASP Core Rule Set configuration.
    #[serde(default)]
    pub owasp_crs: Option<serde_json::Value>,
    /// Action to take when a rule matches (e.g. "block", "log").
    #[serde(default)]
    pub action_on_match: Option<String>,
    /// If true, log matches but do not block.
    #[serde(default)]
    pub test_mode: bool,
    /// If true, allow requests through on WAF engine failure.
    #[serde(default)]
    pub fail_open: bool,
    /// Paranoia level (1-4). Only rules whose paranoia attribute is less
    /// than or equal to this value are evaluated. Defaults to 1 (lowest
    /// false-positive). For backward compatibility, the value can also be
    /// supplied as `owasp_crs.paranoia_level`; the top-level field wins
    /// when both are present.
    #[serde(default)]
    pub paranoia: Option<u8>,
    /// Custom WAF rules.
    #[serde(default)]
    pub custom_rules: Vec<serde_json::Value>,
    /// Optional remote rule-feed subscription. When present and
    /// `enabled: true`, the policy spawns a background subscriber that
    /// hot-loads signed rule bundles from the publisher and merges them
    /// with the static rule corpus on every request. See
    /// [`WafFeedConfig`] for the wire shape and
    /// [`WafFeedSubscriber`] for the runtime behaviour.
    ///
    /// The deserialised config is the *blueprint*; the live
    /// subscriber that owns the background task lives in
    /// [`Self::feed_subscriber`].
    #[serde(default)]
    pub feed: Option<WafFeedConfig>,
    /// Live feed subscriber. Skipped from serde because it owns
    /// runtime state (an [`arc_swap::ArcSwap`] of the current
    /// [`super::feed::RuleSet`] plus a background task handle).
    /// Populated by [`Self::from_config`] when [`Self::feed`] is
    /// `Some(_)` and `enabled: true`.
    #[serde(skip)]
    pub feed_subscriber: Option<Arc<WafFeedSubscriber>>,
}

/// Result of a WAF check.
pub enum WafResult {
    /// Request is clean - allow it through.
    Clean,
    /// Attack detected - block with a message.
    Blocked(String),
    /// WAF engine error occurred during evaluation.
    Error(String),
}

// --- OWASP-lite built-in patterns ---
//
// Each pattern carries an OWASP CRS-style paranoia tag. Paranoia=1 is the
// always-on baseline (high-confidence signatures). Paranoia>=2 patterns
// only run when the operator explicitly opts into a higher-strictness
// posture via `WafPolicy::paranoia`.

/// Built-in WAF signature with an associated paranoia level.
struct BuiltinPattern {
    name: &'static str,
    paranoia: u8,
    regex: std::sync::LazyLock<Regex>,
}

static SQLI_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "sqli",
    paranoia: 1,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|insert\s+into|select\s+.*\s+from|;\s*delete|;\s*update|--\s*$)").unwrap()
    }),
};

static XSS_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "xss",
    paranoia: 1,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(<script|javascript:|on\w+\s*=|<img[^>]+onerror|<svg[^>]+onload|alert\s*\(|document\.cookie)").unwrap()
    }),
};

static PATH_TRAVERSAL_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "path_traversal",
    paranoia: 1,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(\.\./|\.\.\\|%2e%2e|%252e|etc/passwd|/proc/self|/dev/null)").unwrap()
    }),
};

/// Stricter SQLi signature catching boolean-blind and time-delay edge
/// cases that the paranoia=1 corpus tolerates. Enabled at paranoia>=2.
static SQLI_STRICT_PATTERN: BuiltinPattern = BuiltinPattern {
    name: "sqli_strict",
    paranoia: 2,
    regex: std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)(\bwaitfor\s+delay\b|\bbenchmark\s*\(|\bsleep\s*\(\s*\d+\s*\)|\bextractvalue\s*\(|\bload_file\s*\(|\binformation_schema\b|\bxp_cmdshell\b|\bcase\s+when\b.*\bthen\b)").unwrap()
    }),
};

impl WafPolicy {
    /// Build a WafPolicy from a generic JSON config value.
    ///
    /// When the deserialized config carries a `feed` block with
    /// `enabled: true`, a [`WafFeedSubscriber`] is built and its
    /// background task spawned on [`super::feed::WAF_FEED_TASKS`].
    /// Subscriber construction errors propagate; rule-feed downloads
    /// do *not* (a flaky publisher must never break config compile).
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        if let Some(feed_cfg) = policy.feed.clone() {
            if feed_cfg.enabled {
                let sub = WafFeedSubscriber::new(feed_cfg)?;
                policy.feed_subscriber = Some(sub);
            }
        }
        Ok(policy)
    }

    /// Check whether OWASP CRS is enabled.
    fn owasp_enabled(&self) -> bool {
        match &self.owasp_crs {
            Some(v) => v.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false),
            None => false,
        }
    }

    /// Resolve the effective paranoia level. The top-level `paranoia` field
    /// wins. If unset, fall back to `owasp_crs.paranoia_level` for OWASP
    /// CRS-style configs. Defaults to 1 and is clamped to the 1-4 range.
    fn effective_paranoia(&self) -> u8 {
        let raw = self.paranoia.or_else(|| {
            self.owasp_crs.as_ref().and_then(|v| {
                v.get("paranoia_level")
                    .and_then(|p| p.as_u64())
                    .map(|n| n as u8)
            })
        });
        let level = raw.unwrap_or(DEFAULT_PARANOIA);
        level.clamp(1, MAX_PARANOIA)
    }

    /// Check a request against WAF rules. Returns a WafResult indicating
    /// whether the request is clean, blocked, or if an error occurred.
    ///
    /// Rule selection follows the OWASP CRS paranoia model: only rules
    /// whose paranoia level is less than or equal to the policy's
    /// configured level are evaluated. Custom rules without a paranoia
    /// attribute default to paranoia=1 and therefore always run.
    pub fn check_request(
        &self,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> WafResult {
        let action = self.action_on_match.as_deref().unwrap_or("block");
        let paranoia = self.effective_paranoia();

        // --- OWASP CRS built-in patterns ---
        if self.owasp_enabled() {
            // URL-decode the URI before pattern matching (e.g., %3D -> =, + -> space)
            let decoded_uri = percent_encoding::percent_decode_str(uri)
                .decode_utf8_lossy()
                .replace('+', " ");

            // Collect all text to scan: decoded URI, header values, body.
            let header_text: String = headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n");

            let targets = [Some(decoded_uri.as_str()), Some(header_text.as_str()), body];

            // Built-in pattern corpus. Each entry carries an OWASP-style
            // paranoia tag and a human-readable block message.
            let builtins: [(&BuiltinPattern, &str); 4] = [
                (&SQLI_PATTERN, "WAF: SQL injection detected"),
                (&XSS_PATTERN, "WAF: XSS detected"),
                (&PATH_TRAVERSAL_PATTERN, "WAF: path traversal detected"),
                (&SQLI_STRICT_PATTERN, "WAF: SQL injection (strict) detected"),
            ];

            for target in targets.into_iter().flatten() {
                for (rule, block_msg) in builtins.iter() {
                    // Paranoia gate: skip rules above the configured level.
                    if rule.paranoia > paranoia {
                        continue;
                    }
                    if rule.regex.is_match(target) {
                        if action == "log" || self.test_mode {
                            tracing::warn!(
                                pattern = rule.name,
                                paranoia = rule.paranoia,
                                "WAF: pattern detected (log mode)"
                            );
                        } else {
                            return WafResult::Blocked((*block_msg).to_string());
                        }
                    }
                }
            }
        }

        // --- Feed rules (subscribed via WafFeedSubscriber) ---
        //
        // Rules from the remote feed are evaluated alongside the
        // built-in corpus and the inline custom rules. Their paranoia
        // attribute is gated by the policy's `paranoia` setting just
        // like the built-in patterns. A rule from the feed with the
        // same `id` as a built-in or earlier custom rule is the
        // authoritative version; the static corpus does not carry
        // numeric ids today, so override is by-id only and only takes
        // effect against custom_rules below (which we filter
        // accordingly).
        //
        // The subscriber's background task is lazy-spawned on the
        // first request that reaches this branch, since OSS config
        // compile runs before Pingora's Tokio runtime exists. Once
        // started, the call is a no-op (`std::sync::Once`).
        if let Some(sub) = &self.feed_subscriber {
            sub.ensure_started();
        }
        let feed_snapshot = self.feed_subscriber.as_ref().map(|s| s.current_rules());
        let feed_rule_ids: std::collections::HashSet<&str> = match &feed_snapshot {
            Some(snap) => snap.rules.iter().map(|r| r.id.as_str()).collect(),
            None => std::collections::HashSet::new(),
        };
        if let Some(snap) = feed_snapshot.as_ref() {
            // URL-decoded URI plus joined headers, mirroring the
            // built-in scan corpus so feed signatures do not have to
            // re-implement encoding.
            let decoded_uri = percent_encoding::percent_decode_str(uri)
                .decode_utf8_lossy()
                .replace('+', " ");
            let header_text: String = headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n");
            let targets = [Some(decoded_uri.as_str()), Some(header_text.as_str()), body];

            for rule in &snap.rules {
                if rule.paranoia > paranoia {
                    continue;
                }
                let mut matched = false;
                for target in targets.into_iter().flatten() {
                    if rule.regex.is_match(target) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    continue;
                }
                let log_only =
                    matches!(rule.action, FeedRuleAction::Log) || action == "log" || self.test_mode;
                if log_only {
                    tracing::warn!(
                        rule_id = rule.id.as_str(),
                        category = rule.category.as_str(),
                        paranoia = rule.paranoia,
                        "WAF feed: rule matched (log mode)"
                    );
                } else {
                    return WafResult::Blocked(format!(
                        "WAF feed: {} matched [rule {}]",
                        rule.category, rule.id
                    ));
                }
            }
        }

        // --- Custom rules ---
        for rule_value in &self.custom_rules {
            // Feed rules with the same `id` shadow inline custom rules.
            // Skip the inline rule when a feed rule of the same id
            // already evaluated above, so operators can override
            // bundled signatures from upstream without redeploying.
            if let Some(id) = rule_value.get("id").and_then(|v| v.as_str()) {
                if feed_rule_ids.contains(id) {
                    continue;
                }
            }
            // Paranoia gate for custom rules. Rules without a `paranoia`
            // attribute default to paranoia=1 (always run).
            let rule_paranoia = rule_value
                .get("paranoia")
                .and_then(|p| p.as_u64())
                .map(|n| (n as u8).clamp(1, MAX_PARANOIA))
                .unwrap_or(DEFAULT_PARANOIA);
            if rule_paranoia > paranoia {
                continue;
            }
            match self.evaluate_custom_rule(rule_value, uri, headers, body) {
                Ok(true) => {
                    // Rule matched.
                    let rule_action = rule_value
                        .get("action")
                        .and_then(|a| a.as_str())
                        .unwrap_or(action);
                    let message = rule_value
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("WAF: custom rule matched");
                    let rule_id = rule_value
                        .get("id")
                        .and_then(|id| id.as_str())
                        .unwrap_or("unknown");

                    if rule_action == "log" || self.test_mode {
                        tracing::warn!(rule_id = rule_id, "WAF: custom rule matched (log mode)");
                    } else {
                        return WafResult::Blocked(format!("{} [rule {}]", message, rule_id));
                    }
                }
                Ok(false) => {} // No match, continue.
                Err(e) => {
                    return WafResult::Error(format!("WAF custom rule error: {}", e));
                }
            }
        }

        WafResult::Clean
    }

    /// Evaluate a single custom rule against the request.
    /// Returns Ok(true) if the rule matched, Ok(false) if not, Err on engine error.
    fn evaluate_custom_rule(
        &self,
        rule: &serde_json::Value,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Result<bool, String> {
        // Check for Lua-based custom rules
        if let Some(lua_script) = rule.get("lua_script").and_then(|s| s.as_str()) {
            return self.evaluate_lua_custom_rule(lua_script, uri, headers, body);
        }

        // Check for JavaScript-based custom rules (js_script field, or engine: "javascript")
        let js_script = rule.get("js_script").and_then(|s| s.as_str()).or_else(|| {
            let engine = rule.get("engine").and_then(|e| e.as_str()).unwrap_or("lua");
            if engine == "javascript" {
                rule.get("script").and_then(|s| s.as_str())
            } else {
                None
            }
        });
        if let Some(script) = js_script {
            return self.evaluate_js_custom_rule(script, uri, headers, body);
        }

        let pattern = rule
            .get("pattern")
            .and_then(|p| p.as_str())
            .ok_or_else(|| {
                "custom rule missing 'pattern', 'lua_script', or 'js_script' field".to_string()
            })?;

        let operator = rule
            .get("operator")
            .and_then(|o| o.as_str())
            .unwrap_or("contains");

        let variables = rule
            .get("variables")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        // If no variables specified, scan the full URI.
        if variables.is_empty() {
            return self.match_operator(operator, uri, pattern);
        }

        for var in &variables {
            let var_name = var
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("REQUEST_URI");
            let var_key = var.get("key").and_then(|k| k.as_str());

            let target_values = self.resolve_variable(var_name, var_key, uri, headers, body);
            for target in &target_values {
                if self.match_operator(operator, target, pattern)? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Evaluate a Lua-based custom WAF rule.
    ///
    /// The script must define a `match(request)` function that receives a
    /// request object with a `header()` method for looking up HTTP headers.
    /// Returns true if the rule matched (request should be blocked).
    fn evaluate_lua_custom_rule(
        &self,
        script: &str,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Result<bool, String> {
        use sbproxy_extension::lua::LuaEngine;

        let engine = LuaEngine::new().map_err(|e| format!("Lua engine init error: {}", e))?;

        // Build headers map for the Lua engine
        let mut headers_map = std::collections::HashMap::new();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_string(), v.to_string());
            }
        }

        engine
            .waf_match(script, uri, &headers_map, body)
            .map_err(|e| format!("Lua WAF script error: {}", e))
    }

    /// Evaluate a JavaScript-based custom WAF rule.
    ///
    /// The script must define a `match(request)` function. The request object
    /// has `uri`, `headers`, `body` fields and a `header(name)` method for
    /// case-insensitive header lookup. Returns true if the rule matched
    /// (request should be blocked).
    ///
    /// Use `js_script` in the rule config, or set `engine: "javascript"` with
    /// a `script` field.
    fn evaluate_js_custom_rule(
        &self,
        script: &str,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Result<bool, String> {
        use sbproxy_extension::js::JsEngine;

        let engine = JsEngine::new().map_err(|e| format!("JS engine init error: {}", e))?;

        // Build headers map for the JS engine
        let mut headers_map = std::collections::HashMap::new();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_string(), v.to_string());
            }
        }

        engine
            .waf_match(script, uri, &headers_map, body)
            .map_err(|e| format!("JS WAF script error: {}", e))
    }

    /// Resolve a WAF variable name to the actual string values to scan.
    fn resolve_variable(
        &self,
        name: &str,
        key: Option<&str>,
        uri: &str,
        headers: &http::HeaderMap,
        body: Option<&str>,
    ) -> Vec<String> {
        match name {
            "REQUEST_URI" => vec![uri.to_string()],
            "REQUEST_HEADERS" => {
                if let Some(header_name) = key {
                    headers
                        .get_all(header_name)
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                        .collect()
                } else {
                    // All header values.
                    headers
                        .iter()
                        .filter_map(|(_, v)| v.to_str().ok())
                        .map(|s| s.to_string())
                        .collect()
                }
            }
            "REQUEST_BODY" => {
                if let Some(b) = body {
                    vec![b.to_string()]
                } else {
                    vec![]
                }
            }
            _ => {
                tracing::debug!(variable = name, "WAF: unknown variable, skipping");
                vec![]
            }
        }
    }

    /// Apply the operator to check if target matches pattern.
    fn match_operator(&self, operator: &str, target: &str, pattern: &str) -> Result<bool, String> {
        match operator {
            "contains" => Ok(target.contains(pattern)),
            "rx" | "regex" => {
                let re = Regex::new(pattern)
                    .map_err(|e| format!("invalid regex '{}': {}", pattern, e))?;
                Ok(re.is_match(target))
            }
            "eq" | "equals" => Ok(target == pattern),
            "starts_with" => Ok(target.starts_with(pattern)),
            "ends_with" => Ok(target.ends_with(pattern)),
            _ => Err(format!("unknown WAF operator: {}", operator)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header_map(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn waf_js_rule_blocks_malicious_user_agent() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-ua-check",
                    "js_script": r#"
                        function match(request) {
                            const ua = request.header("user-agent") || "";
                            return ua.includes("malicious-bot");
                        }
                    "#,
                    "message": "blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[("user-agent", "malicious-bot/1.0")]);
        let result = policy.check_request("/api", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    #[test]
    fn waf_js_rule_allows_safe_user_agent() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-ua-check",
                    "js_script": r#"
                        function match(request) {
                            const ua = request.header("user-agent") || "";
                            return ua.includes("malicious-bot");
                        }
                    "#,
                    "message": "blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[("user-agent", "Mozilla/5.0 (safe browser)")]);
        let result = policy.check_request("/api", &headers, None);
        assert!(matches!(result, WafResult::Clean));
    }

    #[test]
    fn waf_js_rule_via_engine_field_blocks() {
        // Alternative config: engine: "javascript" + script field
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-uri-check",
                    "engine": "javascript",
                    "script": r#"
                        function match(request) {
                            return request.uri.includes("../");
                        }
                    "#,
                    "message": "path traversal blocked by JS"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/etc/../passwd", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    #[test]
    fn waf_js_rule_body_check_blocks() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-body-check",
                    "js_script": r#"
                        function match(request) {
                            const body = request.body || "";
                            return body.includes("<script>");
                        }
                    "#,
                    "message": "XSS blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/submit", &headers, Some("<script>alert(1)</script>"));
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    #[test]
    fn waf_js_rule_body_check_allows_clean() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "js-body-check",
                    "js_script": r#"
                        function match(request) {
                            const body = request.body || "";
                            return body.includes("<script>");
                        }
                    "#,
                    "message": "XSS blocked by JS rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/submit", &headers, Some("clean input data"));
        assert!(matches!(result, WafResult::Clean));
    }

    #[test]
    fn waf_lua_and_js_rules_can_coexist() {
        // A WAF policy with one Lua rule and one JS rule
        let policy = WafPolicy::from_config(serde_json::json!({
            "custom_rules": [
                {
                    "id": "lua-check",
                    "lua_script": r#"
                        function match(request)
                            local ua = request:header("user-agent") or ""
                            return ua:find("evilbot") ~= nil
                        end
                    "#,
                    "message": "lua: blocked"
                },
                {
                    "id": "js-check",
                    "js_script": r#"
                        function match(request) {
                            return request.uri.includes("/admin");
                        }
                    "#,
                    "message": "js: blocked admin"
                }
            ]
        }))
        .unwrap();

        // JS rule blocks /admin
        let headers = make_header_map(&[("user-agent", "Mozilla/5.0")]);
        let result = policy.check_request("/admin/panel", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));

        // Neither rule matches for clean request
        let result = policy.check_request("/api/users", &headers, None);
        assert!(matches!(result, WafResult::Clean));
    }

    // --- Paranoia level tests ---

    /// Default paranoia is 1 when no field is set on the policy.
    #[test]
    fn waf_default_paranoia_is_one() {
        let policy = WafPolicy::from_config(serde_json::json!({})).unwrap();
        assert_eq!(policy.effective_paranoia(), 1);
    }

    /// Top-level `paranoia` overrides the nested CRS field for back-compat.
    #[test]
    fn waf_top_level_paranoia_wins_over_owasp_crs() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 3,
            "owasp_crs": { "enabled": true, "paranoia_level": 1 },
        }))
        .unwrap();
        assert_eq!(policy.effective_paranoia(), 3);
    }

    /// `owasp_crs.paranoia_level` is honored when the top-level field is unset.
    #[test]
    fn waf_owasp_crs_paranoia_level_used_as_fallback() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "enabled": true, "paranoia_level": 2 },
        }))
        .unwrap();
        assert_eq!(policy.effective_paranoia(), 2);
    }

    /// Out-of-range values clamp into the 1-4 window.
    #[test]
    fn waf_paranoia_clamps_to_valid_range() {
        let high = WafPolicy::from_config(serde_json::json!({ "paranoia": 99 })).unwrap();
        assert_eq!(high.effective_paranoia(), 4);
        let low = WafPolicy::from_config(serde_json::json!({ "paranoia": 0 })).unwrap();
        assert_eq!(low.effective_paranoia(), 1);
    }

    /// Built-in stricter SQLi pattern (paranoia=2) does not fire at paranoia=1.
    #[test]
    fn waf_strict_sqli_pattern_skipped_at_paranoia_one() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "enabled": true },
            "paranoia": 1,
            "action_on_match": "block",
        }))
        .unwrap();

        // Payload only matches SQLI_STRICT_PATTERN (paranoia=2), not the
        // baseline SQLI_PATTERN, XSS_PATTERN, or PATH_TRAVERSAL_PATTERN.
        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?q=BENCHMARK(1000000,sha1(1))", &headers, None);
        assert!(
            matches!(result, WafResult::Clean),
            "paranoia=1 must skip strict-only signatures, got {:?}",
            std::mem::discriminant(&result)
        );
    }

    /// Same payload triggers when paranoia is raised to 2.
    #[test]
    fn waf_strict_sqli_pattern_fires_at_paranoia_two() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "owasp_crs": { "enabled": true },
            "paranoia": 2,
            "action_on_match": "block",
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?q=BENCHMARK(1000000,sha1(1))", &headers, None);
        assert!(
            matches!(result, WafResult::Blocked(_)),
            "paranoia=2 must run strict signatures"
        );
    }

    /// Custom rules without a paranoia attribute always run (default=1).
    #[test]
    fn waf_custom_rule_default_paranoia_always_runs() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 1,
            "custom_rules": [
                {
                    "id": "default-paranoia",
                    "operator": "contains",
                    "pattern": "/forbidden",
                    "action": "block",
                    "message": "default paranoia rule"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/forbidden/path", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }

    /// Custom rule tagged paranoia=3 is suppressed when policy paranoia=1.
    #[test]
    fn waf_high_paranoia_custom_rule_skipped_at_low_policy_paranoia() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 1,
            "custom_rules": [
                {
                    "id": "noisy-rule",
                    "paranoia": 3,
                    "operator": "contains",
                    "pattern": "edge-case",
                    "action": "block",
                    "message": "edge case"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?x=edge-case", &headers, None);
        assert!(
            matches!(result, WafResult::Clean),
            "paranoia=3 rule must not run at policy paranoia=1"
        );
    }

    /// Same custom rule fires once policy paranoia is raised.
    #[test]
    fn waf_high_paranoia_custom_rule_fires_at_matching_policy_paranoia() {
        let policy = WafPolicy::from_config(serde_json::json!({
            "paranoia": 3,
            "custom_rules": [
                {
                    "id": "noisy-rule",
                    "paranoia": 3,
                    "operator": "contains",
                    "pattern": "edge-case",
                    "action": "block",
                    "message": "edge case"
                }
            ]
        }))
        .unwrap();

        let headers = make_header_map(&[]);
        let result = policy.check_request("/api?x=edge-case", &headers, None);
        assert!(matches!(result, WafResult::Blocked(_)));
    }
}
