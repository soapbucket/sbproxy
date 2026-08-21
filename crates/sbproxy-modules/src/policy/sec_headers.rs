//! Security headers policy.
//!
//! Injects response headers (X-Frame-Options, CSP, HSTS, etc.) and
//! supports per-request CSP nonce generation plus per-route CSP
//! overrides.

use base64::Engine as _;
use serde::Deserialize;
use std::collections::HashMap;

/// A single security header name/value pair.
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityHeader {
    /// The HTTP header name (e.g. `X-Frame-Options`).
    pub name: String,
    /// The HTTP header value (e.g. `DENY`).
    pub value: String,
}

/// Advanced Content-Security-Policy configuration.
///
/// Supports per-request nonce generation and per-URL-prefix route overrides.
/// Use this when a plain CSP header value via the `headers:` array is not
/// enough.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ContentSecurityPolicy {
    /// The CSP policy string (e.g. `default-src 'self'`).
    #[serde(default)]
    pub policy: String,
    /// When true, a per-request nonce is generated and injected into
    /// `script-src` and `style-src` directives of the policy.
    #[serde(default)]
    pub enable_nonce: bool,
    /// When true, emit `Content-Security-Policy-Report-Only` instead of
    /// `Content-Security-Policy`.
    #[serde(default)]
    pub report_only: bool,
    /// Optional CSP violation report URI, appended as `; report-uri <uri>`.
    #[serde(default)]
    pub report_uri: String,
    /// Per-route overrides. Keys are URL path prefixes. On a request, the
    /// longest-matching prefix wins; an exact key match beats prefix match.
    /// If no key matches, the outer policy is used.
    #[serde(default)]
    pub dynamic_routes: HashMap<String, ContentSecurityPolicy>,
}

impl ContentSecurityPolicy {
    /// Resolve the CSP config for a given URL path.
    ///
    /// Exact key match wins; otherwise longest matching path prefix wins;
    /// otherwise falls back to `self`.
    pub fn resolve_for_path<'a>(&'a self, path: &str) -> &'a ContentSecurityPolicy {
        if self.dynamic_routes.is_empty() {
            return self;
        }
        if let Some(route_csp) = self.dynamic_routes.get(path) {
            return route_csp;
        }
        let mut best: Option<(&str, &ContentSecurityPolicy)> = None;
        for (route, route_csp) in &self.dynamic_routes {
            if path.starts_with(route.as_str()) {
                match best {
                    Some((cur, _)) if cur.len() >= route.len() => {}
                    _ => best = Some((route.as_str(), route_csp)),
                }
            }
        }
        best.map(|(_, csp)| csp).unwrap_or(self)
    }
}

/// CSP configuration value. Accepts either a plain policy string (legacy
/// shortcut) or a detailed object with nonce, report-only, dynamic routes.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ContentSecurityPolicySpec {
    /// Shortcut: just a policy string. Equivalent to `{ policy: "<s>" }`.
    Simple(String),
    /// Detailed config supporting per-request nonce and dynamic routes.
    Detailed(ContentSecurityPolicy),
}

impl ContentSecurityPolicySpec {
    /// Returns the policy string for this spec. For detailed specs with an
    /// empty policy field, returns `None`.
    pub(crate) fn as_legacy_str(&self) -> Option<&str> {
        match self {
            Self::Simple(s) => Some(s.as_str()),
            Self::Detailed(d) if !d.policy.is_empty() => Some(d.policy.as_str()),
            Self::Detailed(_) => None,
        }
    }
}

/// Generate a base64-encoded 16-byte random nonce for CSP.
pub fn generate_csp_nonce() -> Option<String> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Inject a nonce into `script-src` and `style-src` directives of a CSP
/// policy string. If the directive already contains a nonce, it is left
/// unchanged. Returns the policy unchanged if `nonce` is empty.
fn inject_nonce_into_policy(policy: &str, nonce: &str) -> String {
    if nonce.is_empty() {
        return policy.to_string();
    }
    policy
        .split(';')
        .map(|part| {
            let trimmed = part.trim();
            if (trimmed.starts_with("script-src") || trimmed.starts_with("style-src"))
                && !trimmed.contains("'nonce-")
            {
                format!("{} 'nonce-{}'", trimmed, nonce)
            } else {
                trimmed.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Injects security headers into responses.
///
/// This is a response-phase policy. The proxy applies these headers
/// to outgoing responses before sending them to the client.
///
/// Canonical format uses a `headers` array:
/// ```yaml
/// - type: security_headers
///   headers:
///     - name: X-Frame-Options
///       value: DENY
/// ```
///
/// Legacy flat fields (`x_frame_options`, `x_content_type_options`, etc.) are
/// still accepted for backward compatibility but trigger a deprecation log.
#[derive(Debug, Deserialize)]
pub struct SecHeadersPolicy {
    /// Canonical: list of `{name, value}` header pairs to inject.
    #[serde(default)]
    pub headers: Vec<SecurityHeader>,
    // --- Legacy flat fields (deprecated, kept for backward compatibility) ---
    /// Legacy `X-Frame-Options` value (e.g. `DENY`).
    #[serde(default)]
    pub x_frame_options: Option<String>,
    /// Legacy `X-Content-Type-Options` value (e.g. `nosniff`).
    #[serde(default)]
    pub x_content_type_options: Option<String>,
    /// Legacy `X-XSS-Protection` value.
    #[serde(default)]
    pub x_xss_protection: Option<String>,
    /// Legacy `Referrer-Policy` value.
    #[serde(default)]
    pub referrer_policy: Option<String>,
    /// Content-Security-Policy. Accepts either a plain policy string (legacy
    /// shortcut) or a detailed object with `enable_nonce`, `report_only`,
    /// `report_uri`, and `dynamic_routes`.
    #[serde(default)]
    pub content_security_policy: Option<ContentSecurityPolicySpec>,
    /// Legacy `Permissions-Policy` value.
    #[serde(default)]
    pub permissions_policy: Option<String>,
    /// Legacy `Strict-Transport-Security` value (HSTS shortcut).
    #[serde(default)]
    pub strict_transport_security: Option<String>,
}

impl SecHeadersPolicy {
    /// Build a SecHeadersPolicy from a generic JSON config value.
    ///
    /// Supports three formats:
    /// 1. New array format: `{ "headers": [{"name": "X-Frame-Options", "value": "DENY"}] }`
    /// 2. Flat (legacy): `{ "x_frame_options": "DENY" }`
    /// 3. Nested (Go compat legacy): `{ "x_frame_options": { "enabled": true, "value": "DENY" } }`
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        // Check if the new `headers` array key is present.
        let has_headers_array = value
            .get("headers")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);

        // `flat` is `value` with the Go-compat nested CSP spelling folded
        // into the canonical one. `value` itself is left untouched, because
        // the nested reader at the bottom still has to see what the operator
        // actually wrote.
        let flat = Self::fold_nested_csp(&value);

        if has_headers_array {
            // New canonical format - deserialize directly.
            let policy = serde_json::from_value::<Self>(flat)
                .map_err(|e| anyhow::anyhow!("security_headers parse error: {}", e))?;
            policy.validate()?;
            return Ok(policy);
        }

        // Try flat legacy format first.
        if let Ok(policy) = serde_json::from_value::<Self>(flat) {
            policy.validate()?;
            // Log deprecation warning if any legacy fields are set. The
            // detailed `content_security_policy` object is deliberately not
            // on this list: it is the documented way to ask for a nonce,
            // report-only mode, a report URI, or per-route overrides, none
            // of which a `headers:` entry can express. Only the plain-string
            // shortcut form is a legacy spelling of a static header.
            if policy.x_frame_options.is_some()
                || policy.x_content_type_options.is_some()
                || policy.x_xss_protection.is_some()
                || policy.referrer_policy.is_some()
                || matches!(
                    policy.content_security_policy,
                    Some(ContentSecurityPolicySpec::Simple(_))
                )
                || policy.permissions_policy.is_some()
                || policy.strict_transport_security.is_some()
            {
                tracing::warn!(
                    "security_headers: flat fields (x_frame_options, x_content_type_options, \
                     etc.) are deprecated. Use `headers: [{{name, value}}]` format instead."
                );
            }
            return Ok(policy);
        }
        // Fall back to Go nested format.
        let policy = Self::from_nested_config(&value)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Fold the Go-compat nested CSP spelling into the canonical one.
    ///
    /// The nested form writes a CSP as `{enabled: bool, policy: "..."}`.
    /// [`ContentSecurityPolicy`] has no `enabled` field and does not deny
    /// unknown keys, so that same object also deserializes as a detailed
    /// spec, with `enabled` dropped on the floor. The two readers therefore
    /// disagree about what `{enabled: false}` means: the nested one reads a
    /// deliberately disabled CSP, the flat one reads a CSP with an empty
    /// policy string.
    ///
    /// That disagreement was harmless only while an empty policy was a
    /// silent no-op. Now that [`Self::validate`] refuses a block that can
    /// emit no header, a config saying `enabled: false` would be refused
    /// with an error about a missing `policy:` string, which is both wrong
    /// and confusing, and it would never reach the nested reader that
    /// understands it. Resolve the spelling before any parse decides.
    ///
    /// `enabled: true` keeps every other key rather than collapsing to a
    /// plain string: an operator who mixed the two spellings should not
    /// lose `enable_nonce` or `report_only` to this.
    fn fold_nested_csp(value: &serde_json::Value) -> serde_json::Value {
        let mut out = value.clone();
        let Some(obj) = out.as_object_mut() else {
            return out;
        };
        let Some(csp) = obj.get_mut("content_security_policy") else {
            return out;
        };
        let Some(csp_obj) = csp.as_object_mut() else {
            return out;
        };
        let Some(enabled) = csp_obj.remove("enabled") else {
            return out;
        };
        if enabled.as_bool() != Some(true) {
            obj.remove("content_security_policy");
        }
        out
    }

    /// Reject or flag configurations whose stated intent cannot be honored.
    ///
    /// Two silent drops motivated this (WOR-2526). A `content_security_policy`
    /// block used to be discarded whenever a `headers:` array was also present
    /// and `enable_nonce` was false, and a CSP block with an empty `policy`
    /// string emitted nothing at all. Both looked like an accepted config and
    /// shipped a response with no CSP.
    ///
    /// The block and the array now merge, so the only combination left that
    /// has no single honest answer is a CSP authored in *both* places. That is
    /// refused here rather than resolved quietly, because picking a winner
    /// silently is what produced the original bug.
    fn validate(&self) -> anyhow::Result<()> {
        if self.content_security_policy.is_some() {
            if let Some(dup) = self.headers.iter().find(|h| {
                let n = h.name.to_ascii_lowercase();
                n == "content-security-policy" || n == "content-security-policy-report-only"
            }) {
                anyhow::bail!(
                    "security_headers: `{}` is set in the `headers:` array and a \
                     `content_security_policy:` block is set as well. Only one of them can \
                     define the policy. Use `content_security_policy:` when you need a nonce, \
                     report-only mode, a report URI, or per-route overrides; use the \
                     `headers:` entry for a plain static policy. Refusing rather than \
                     silently dropping one of them.",
                    dup.name
                );
            }
        }

        if let Some(spec) = &self.content_security_policy {
            let emits_nothing = match spec {
                ContentSecurityPolicySpec::Simple(s) => s.trim().is_empty(),
                ContentSecurityPolicySpec::Detailed(d) => {
                    d.policy.trim().is_empty() && d.dynamic_routes.is_empty()
                }
            };
            anyhow::ensure!(
                !emits_nothing,
                "security_headers: `content_security_policy` is set but its `policy` string is \
                 empty and no `dynamic_routes` are defined, so no Content-Security-Policy \
                 header can ever be emitted. Set `policy:` or drop the block."
            );
        }

        // A non-empty `headers:` array supersedes the legacy flat shortcuts
        // (documented precedence), but doing so without a word is the same
        // silent-drop shape as the CSP bug. Name the fields that will not be
        // emitted. This is a warning, not a refusal: the precedence is
        // long-standing and configs depend on it.
        if !self.headers.is_empty() {
            let mut superseded: Vec<&str> = Vec::new();
            for (name, set) in [
                ("x_frame_options", self.x_frame_options.is_some()),
                (
                    "x_content_type_options",
                    self.x_content_type_options.is_some(),
                ),
                ("x_xss_protection", self.x_xss_protection.is_some()),
                ("referrer_policy", self.referrer_policy.is_some()),
                ("permissions_policy", self.permissions_policy.is_some()),
                (
                    "strict_transport_security",
                    self.strict_transport_security.is_some(),
                ),
            ] {
                if set {
                    superseded.push(name);
                }
            }
            if !superseded.is_empty() {
                tracing::warn!(
                    target: "sbproxy::security_headers",
                    superseded = %superseded.join(", "),
                    "security_headers: the `headers:` array supersedes these legacy flat \
                     fields, so they will not be emitted. Move them into `headers:` as \
                     {{name, value}} entries."
                );
            }
        }

        Ok(())
    }

    /// Build the Content-Security-Policy header for one request path.
    ///
    /// This is the single place a CSP header value is produced. Both config
    /// shapes (the plain policy string and the detailed object) and every
    /// knob on the detailed one (`enable_nonce`, `report_only`, `report_uri`,
    /// `dynamic_routes`) run through it, so the emitted header no longer
    /// depends on which internal path happened to run (WOR-2526).
    ///
    /// Returns the header name, its value, and the generated nonce if the
    /// resolved policy asked for one. `None` means this policy configures no
    /// CSP, or configures one that resolves to an empty policy string for
    /// this path.
    fn csp_for_path(&self, path: &str) -> Option<(&'static str, String, Option<String>)> {
        let resolved = match self.content_security_policy.as_ref()? {
            // A plain string carries no nonce, report-only, or route
            // overrides by construction; emit it as an enforcing policy.
            ContentSecurityPolicySpec::Simple(s) if !s.trim().is_empty() => {
                return Some(("content-security-policy", s.clone(), None));
            }
            ContentSecurityPolicySpec::Simple(_) => return None,
            ContentSecurityPolicySpec::Detailed(d) => d.resolve_for_path(path),
        };

        let nonce = if resolved.enable_nonce {
            generate_csp_nonce()
        } else {
            None
        };
        let mut value = match &nonce {
            Some(n) => inject_nonce_into_policy(&resolved.policy, n),
            None => resolved.policy.clone(),
        };
        // An empty policy string means this path opts out; appending a
        // report-uri to nothing would emit a header with no directives.
        if value.trim().is_empty() {
            return None;
        }
        if !resolved.report_uri.is_empty() {
            value.push_str("; report-uri ");
            value.push_str(&resolved.report_uri);
        }
        let name = if resolved.report_only {
            "content-security-policy-report-only"
        } else {
            "content-security-policy"
        };
        Some((name, value, nonce))
    }

    /// Resolve all headers to inject, merging canonical `headers` array with
    /// legacy flat fields. The `headers` array takes precedence; legacy fields
    /// are appended only when the canonical array is empty.
    ///
    /// This method does not build the Content-Security-Policy header. The CSP
    /// entry it returns from the legacy fallback below is a static
    /// best-effort that [`resolved_headers_for_request`] always replaces with
    /// the properly built one. Response paths must call
    /// [`resolved_headers_for_request`] and never this method directly, or
    /// they will drop nonce, report-only, report-uri, and per-route CSP
    /// handling on the floor.
    ///
    /// [`resolved_headers_for_request`]: Self::resolved_headers_for_request
    pub(crate) fn resolved_headers(&self) -> Vec<(String, String)> {
        if !self.headers.is_empty() {
            return self
                .headers
                .iter()
                .map(|h| (h.name.to_lowercase(), h.value.clone()))
                .collect();
        }
        // Fall back to legacy flat fields.
        let mut out = Vec::new();
        if let Some(v) = &self.x_frame_options {
            out.push(("x-frame-options".into(), v.clone()));
        }
        if let Some(v) = &self.x_content_type_options {
            out.push(("x-content-type-options".into(), v.clone()));
        }
        if let Some(v) = &self.x_xss_protection {
            out.push(("x-xss-protection".into(), v.clone()));
        }
        if let Some(v) = &self.referrer_policy {
            out.push(("referrer-policy".into(), v.clone()));
        }
        if let Some(spec) = &self.content_security_policy {
            if let Some(v) = spec.as_legacy_str() {
                out.push(("content-security-policy".into(), v.to_string()));
            }
        }
        if let Some(v) = &self.permissions_policy {
            out.push(("permissions-policy".into(), v.clone()));
        }
        if let Some(v) = &self.strict_transport_security {
            out.push(("strict-transport-security".into(), v.clone()));
        }
        out
    }

    /// Resolve headers for a given request path, handling CSP nonce generation
    /// and dynamic routes when the `content_security_policy` field is the
    /// detailed variant.
    ///
    /// Returns the header list and the generated nonce (if any). Callers that
    /// expose the nonce to response templating should forward the nonce to
    /// downstream stages; a common pattern is also to emit an `X-CSP-Nonce`
    /// header so browser-side code can read it.
    pub fn resolved_headers_for_request(
        &self,
        path: &str,
    ) -> (Vec<(String, String)>, Option<String>) {
        let mut headers = self.resolved_headers();

        // The CSP is always built here, not conditionally. Gating this on
        // "does the spec need per-request work" is what silently dropped a
        // configured `content_security_policy` whenever a `headers:` array
        // was also present and `enable_nonce` was false (WOR-2526): the
        // static path above returns the array verbatim and never reaches the
        // legacy CSP fallback.
        let Some((name, value, nonce)) = self.csp_for_path(path) else {
            return (headers, None);
        };

        // The `content_security_policy` block is the single source of truth
        // for this header, so drop whatever the static resolution produced
        // before pushing the built value. `validate` refuses a config that
        // authors a CSP in both places, so in practice this only strips the
        // legacy fallback's own entry.
        headers.retain(|(n, _)| {
            n != "content-security-policy" && n != "content-security-policy-report-only"
        });
        headers.push((name.to_string(), value));

        (headers, nonce)
    }

    /// Parse Go-style nested security headers config.
    fn from_nested_config(value: &serde_json::Value) -> anyhow::Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("security_headers config must be an object"))?;

        tracing::warn!(
            "security_headers: nested Go-compat format is deprecated. \
             Use `headers: [{{name, value}}]` format instead."
        );

        let x_frame_options = Self::extract_nested_value(obj, "x_frame_options");
        let x_content_type_options = if let Some(sub) = obj.get("x_content_type_options") {
            if let Some(sub_obj) = sub.as_object() {
                let enabled = sub_obj
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let no_sniff = sub_obj
                    .get("no_sniff")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if enabled && no_sniff {
                    Some("nosniff".to_string())
                } else {
                    None
                }
            } else {
                sub.as_str().map(|s| s.to_string())
            }
        } else {
            None
        };

        let referrer_policy = Self::extract_nested_policy(obj, "referrer_policy");
        let content_security_policy = Self::extract_nested_policy(obj, "content_security_policy")
            .map(ContentSecurityPolicySpec::Simple);

        // HSTS from strict_transport_security
        let strict_transport_security = Self::extract_hsts(obj);
        let x_xss_protection = Self::extract_nested_value(obj, "x_xss_protection");
        let permissions_policy = Self::extract_nested_value(obj, "permissions_policy");

        Ok(Self {
            headers: Vec::new(),
            x_frame_options,
            x_content_type_options,
            x_xss_protection,
            referrer_policy,
            content_security_policy,
            permissions_policy,
            strict_transport_security,
        })
    }

    /// Extract a value from a nested `{ "enabled": true, "value": "X" }` object.
    fn extract_nested_value(
        obj: &serde_json::Map<String, serde_json::Value>,
        key: &str,
    ) -> Option<String> {
        let sub = obj.get(key)?;
        if let Some(s) = sub.as_str() {
            return Some(s.to_string());
        }
        let sub_obj = sub.as_object()?;
        let enabled = sub_obj
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        sub_obj
            .get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Extract HSTS header value from a nested strict_transport_security config.
    ///
    /// Accepts Go-compat format:
    /// `{ "enabled": true, "max_age": 31536000, "include_subdomains": true }`
    fn extract_hsts(obj: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
        let sub = obj.get("strict_transport_security")?;
        if let Some(s) = sub.as_str() {
            return Some(s.to_string());
        }
        let sub_obj = sub.as_object()?;
        let enabled = sub_obj
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let max_age = sub_obj
            .get("max_age")
            .and_then(|v| v.as_u64())
            .unwrap_or(31_536_000);
        let include_subdomains = sub_obj
            .get("include_subdomains")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let preload = sub_obj
            .get("preload")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut value = format!("max-age={}", max_age);
        if include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if preload {
            value.push_str("; preload");
        }
        Some(value)
    }

    /// Extract a policy string from a nested `{ "enabled": true, "policy": "X" }` object.
    fn extract_nested_policy(
        obj: &serde_json::Map<String, serde_json::Value>,
        key: &str,
    ) -> Option<String> {
        let sub = obj.get(key)?;
        if let Some(s) = sub.as_str() {
            return Some(s.to_string());
        }
        let sub_obj = sub.as_object()?;
        let enabled = sub_obj
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        sub_obj
            .get("policy")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn sec_headers_policy_type() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "headers": [{"name": "X-Frame-Options", "value": "DENY"}]
        }))
        .unwrap();
        let policy = Policy::SecHeaders(policy);
        assert_eq!(policy.policy_type(), "security_headers");
    }

    #[test]
    fn sec_headers_from_config_new_format() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "headers": [
                {"name": "X-Frame-Options", "value": "SAMEORIGIN"},
                {"name": "X-Content-Type-Options", "value": "nosniff"},
                {"name": "Referrer-Policy", "value": "no-referrer"},
                {"name": "Content-Security-Policy", "value": "default-src 'self'"}
            ]
        }))
        .unwrap();

        let resolved = policy.resolved_headers();
        assert_eq!(resolved.len(), 4);
        assert!(resolved
            .iter()
            .any(|(n, v)| n == "x-frame-options" && v == "SAMEORIGIN"));
        assert!(resolved
            .iter()
            .any(|(n, v)| n == "x-content-type-options" && v == "nosniff"));
        assert!(resolved
            .iter()
            .any(|(n, v)| n == "referrer-policy" && v == "no-referrer"));
        assert!(resolved
            .iter()
            .any(|(n, v)| n == "content-security-policy" && v == "default-src 'self'"));
    }

    #[test]
    fn sec_headers_from_config_legacy_flat() {
        // Legacy flat format still works (backward compat).
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "x_frame_options": "SAMEORIGIN",
            "x_content_type_options": "nosniff",
            "referrer_policy": "no-referrer",
            "content_security_policy": "default-src 'self'"
        }))
        .unwrap();

        assert_eq!(policy.x_frame_options.as_deref(), Some("SAMEORIGIN"));
        assert_eq!(policy.x_content_type_options.as_deref(), Some("nosniff"));
        assert_eq!(policy.referrer_policy.as_deref(), Some("no-referrer"));
        assert_eq!(
            policy
                .content_security_policy
                .as_ref()
                .and_then(|s| s.as_legacy_str()),
            Some("default-src 'self'")
        );
        assert!(policy.x_xss_protection.is_none());
        assert!(policy.permissions_policy.is_none());

        let resolved = policy.resolved_headers();
        assert!(resolved.iter().any(|(n, _)| n == "x-frame-options"));
    }

    #[test]
    fn sec_headers_empty_config() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({})).unwrap();
        assert!(policy.headers.is_empty());
        assert!(policy.x_frame_options.is_none());
        assert!(policy.resolved_headers().is_empty());
    }

    #[test]
    fn sec_headers_csp_detailed_with_nonce() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "policy": "default-src 'self'; script-src 'self'",
                "enable_nonce": true
            }
        }))
        .unwrap();

        let (headers, nonce) = policy.resolved_headers_for_request("/");
        let nonce = nonce.expect("nonce should be generated when enable_nonce is true");
        assert!(!nonce.is_empty());

        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .expect("CSP header should be set");
        assert!(
            csp.1.contains(&format!("'nonce-{}'", nonce)),
            "nonce should be injected into script-src: {}",
            csp.1
        );
    }

    #[test]
    fn sec_headers_csp_report_only() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "policy": "default-src 'self'",
                "report_only": true,
                "report_uri": "/csp-report",
                "enable_nonce": true
            }
        }))
        .unwrap();

        let (headers, _nonce) = policy.resolved_headers_for_request("/");
        let h = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy-report-only")
            .expect("report-only CSP header should be set");
        assert!(h.1.contains("report-uri /csp-report"));
        assert!(
            headers.iter().all(|(n, _)| n != "content-security-policy"),
            "must not emit both enforcing and report-only CSP"
        );
    }

    #[test]
    fn sec_headers_csp_dynamic_routes() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "policy": "default-src 'self'",
                "dynamic_routes": {
                    "/admin": { "policy": "default-src 'self' admin.example.com" },
                    "/admin/users": { "policy": "default-src 'self' admin.example.com users.example.com" }
                }
            }
        }))
        .unwrap();

        // Root path uses the outer policy.
        let (headers, _) = policy.resolved_headers_for_request("/");
        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .unwrap();
        assert_eq!(csp.1, "default-src 'self'");

        // `/admin` prefix uses admin policy.
        let (headers, _) = policy.resolved_headers_for_request("/admin/something");
        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .unwrap();
        assert_eq!(csp.1, "default-src 'self' admin.example.com");

        // Longer prefix wins.
        let (headers, _) = policy.resolved_headers_for_request("/admin/users/42");
        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .unwrap();
        assert_eq!(
            csp.1,
            "default-src 'self' admin.example.com users.example.com"
        );
    }

    #[test]
    fn sec_headers_csp_simple_string_still_works() {
        // The plain string form of content_security_policy must still parse
        // and produce a simple CSP header with no nonce or routes.
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": "default-src 'self'"
        }))
        .unwrap();

        let (headers, nonce) = policy.resolved_headers_for_request("/any/path");
        assert!(nonce.is_none());
        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .unwrap();
        assert_eq!(csp.1, "default-src 'self'");
    }

    #[test]
    fn sec_headers_nonce_injection_preserves_existing_nonce() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "policy": "script-src 'self' 'nonce-fixed'; style-src 'self'",
                "enable_nonce": true
            }
        }))
        .unwrap();

        let (headers, nonce) = policy.resolved_headers_for_request("/");
        let nonce = nonce.unwrap();
        let csp = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy")
            .unwrap();
        // The existing 'nonce-fixed' directive is preserved (no double-injection).
        assert!(csp.1.contains("'nonce-fixed'"));
        // style-src gets the new nonce injected.
        assert!(csp
            .1
            .contains(&format!("style-src 'self' 'nonce-{}'", nonce)));
    }

    // --- WOR-2526: a configured CSP must never be silently dropped ---

    /// The reported bug. A `headers:` array plus a `content_security_policy`
    /// block with `enable_nonce: false` used to emit the array and drop the
    /// CSP entirely, with no error and no warning.
    #[test]
    fn csp_ships_alongside_headers_array_without_nonce() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "headers": [
                {"name": "X-Frame-Options", "value": "DENY"},
                {"name": "X-Content-Type-Options", "value": "nosniff"}
            ],
            "content_security_policy": {
                "policy": "default-src 'self'; script-src 'self'",
                "enable_nonce": false,
                "report_only": false
            }
        }))
        .unwrap();

        let (headers, nonce) = policy.resolved_headers_for_request("/get");
        assert!(nonce.is_none(), "enable_nonce is false, so no nonce");
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "x-frame-options" && v == "DENY"),
            "the headers: array must still ship: {headers:?}"
        );
        assert!(
            headers.iter().any(|(n, v)| n == "content-security-policy"
                && v == "default-src 'self'; script-src 'self'"),
            "the configured content_security_policy must ship alongside the \
             headers: array: {headers:?}"
        );
    }

    /// The plain-string CSP shortcut has the same collision.
    #[test]
    fn simple_string_csp_ships_alongside_headers_array() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "headers": [{"name": "X-Frame-Options", "value": "DENY"}],
            "content_security_policy": "default-src 'self'"
        }))
        .unwrap();

        let (headers, _) = policy.resolved_headers_for_request("/");
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "content-security-policy" && v == "default-src 'self'"),
            "a plain-string CSP must ship alongside the headers: array: {headers:?}"
        );
    }

    /// Sibling of the reported bug: `report_only` was consulted only on the
    /// per-request build path, which ran only for `enable_nonce` or
    /// `dynamic_routes`. An operator asking for report-only monitoring got an
    /// enforcing CSP instead, and lost `report_uri` with it.
    #[test]
    fn csp_report_only_honored_without_nonce() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "policy": "default-src 'self'",
                "enable_nonce": false,
                "report_only": true,
                "report_uri": "https://csp.example.com/report"
            }
        }))
        .unwrap();

        let (headers, _) = policy.resolved_headers_for_request("/");
        assert!(
            !headers.iter().any(|(n, _)| n == "content-security-policy"),
            "report_only must not emit an enforcing CSP: {headers:?}"
        );
        let (_, value) = headers
            .iter()
            .find(|(n, _)| n == "content-security-policy-report-only")
            .expect("report_only must emit the report-only header");
        assert_eq!(
            value,
            "default-src 'self'; report-uri https://csp.example.com/report"
        );
    }

    /// Authoring the CSP in both places has no honest winner, so the config
    /// is refused instead of one of them being picked quietly.
    #[test]
    fn csp_authored_in_both_places_is_refused() {
        let err = SecHeadersPolicy::from_config(serde_json::json!({
            "headers": [
                {"name": "Content-Security-Policy", "value": "default-src 'none'"}
            ],
            "content_security_policy": {"policy": "default-src 'self'"}
        }))
        .expect_err("a CSP in both the headers: array and the block must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("Content-Security-Policy") && msg.contains("content_security_policy"),
            "the refusal must name both keys the operator wrote: {msg}"
        );
    }

    /// A `headers:` array with a CSP entry and no block stays legal: there is
    /// nothing ambiguous about it.
    #[test]
    fn csp_in_headers_array_alone_is_accepted() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "headers": [
                {"name": "Content-Security-Policy", "value": "default-src 'none'"}
            ]
        }))
        .unwrap();
        let (headers, _) = policy.resolved_headers_for_request("/");
        assert!(headers
            .iter()
            .any(|(n, v)| n == "content-security-policy" && v == "default-src 'none'"));
    }

    /// A CSP block that can never produce a header is a configured control
    /// that ships nothing. Refuse it at compile rather than serve responses
    /// with no CSP.
    #[test]
    fn csp_block_that_emits_nothing_is_refused() {
        let err = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {"enable_nonce": true}
        }))
        .expect_err("a CSP block with an empty policy must be refused");
        assert!(
            err.to_string().contains("policy"),
            "the refusal must point at the empty `policy` string: {err}"
        );
    }

    /// Per-route overrides still work when the outer policy is empty, so the
    /// empty-policy refusal must not fire on that shape.
    #[test]
    fn csp_dynamic_routes_with_empty_outer_policy_is_accepted() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "policy": "",
                "dynamic_routes": {"/admin": {"policy": "default-src 'none'"}}
            }
        }))
        .unwrap();
        let (headers, _) = policy.resolved_headers_for_request("/admin");
        assert!(headers
            .iter()
            .any(|(n, v)| n == "content-security-policy" && v == "default-src 'none'"));
        // A path with no override emits no CSP, which is the documented
        // meaning of an empty outer policy.
        let (headers, _) = policy.resolved_headers_for_request("/public");
        assert!(!headers
            .iter()
            .any(|(n, _)| n.starts_with("content-security")));
    }

    /// The Go-compat nested spelling of a disabled CSP. `enabled: false`
    /// means "no CSP", and it must not be read as "a CSP with an empty
    /// policy string" and refused. Before the fold, this config parsed as a
    /// detailed spec with `enabled` silently discarded, which the
    /// empty-policy refusal then rejected without ever reaching the nested
    /// reader that understands the key.
    #[test]
    fn nested_csp_disabled_compiles_to_no_policy() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {"enabled": false}
        }))
        .expect("a disabled nested CSP must compile, not be refused");
        assert!(policy.content_security_policy.is_none());
        let (headers, _) = policy.resolved_headers_for_request("/");
        assert!(!headers
            .iter()
            .any(|(n, _)| n.starts_with("content-security")));
    }

    /// The same spelling with `enabled: true` keeps the policy, and keeps
    /// the richer keys alongside it rather than collapsing to a bare string.
    #[test]
    fn nested_csp_enabled_keeps_the_policy_and_its_knobs() {
        let policy = SecHeadersPolicy::from_config(serde_json::json!({
            "content_security_policy": {
                "enabled": true,
                "policy": "default-src 'self'",
                "report_only": true
            }
        }))
        .expect("an enabled nested CSP must compile");
        let (headers, _) = policy.resolved_headers_for_request("/");
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "content-security-policy-report-only"
                    && v == "default-src 'self'"),
            "report_only must survive the fold: {headers:?}"
        );
    }
}
