//! Subresource Integrity (SRI) inspection policy.
//!
//! Scans HTML response bodies for `<script>` and `<link rel="stylesheet">`
//! tags pointing at external origins. Each external reference must
//! carry an `integrity="..."` attribute using one of the configured
//! algorithms; missing or weak attributes are reported as violations.

use serde::Deserialize;

/// One SRI violation observed on an HTML response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SriViolation {
    /// Tag that triggered the violation (`script` or `link`).
    pub tag: String,
    /// Source URL (`src` for script tags, `href` for link tags).
    pub url: String,
    /// Why the violation fired.
    pub reason: SriViolationReason,
}

/// Why an HTML subresource reference failed the SRI check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SriViolationReason {
    /// No `integrity="..."` attribute was present.
    MissingIntegrity,
    /// The integrity attribute used an algorithm not in `algorithms`.
    DisallowedAlgorithm {
        /// Algorithm prefix that was found (e.g. `sha1`, `md5`).
        found: String,
    },
}

/// Outcome of `SriPolicy::check_html_body`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SriCheckResult {
    /// The response is not HTML or the policy is disabled; no inspection done.
    NotApplicable,
    /// HTML was inspected and every external subresource carried a valid
    /// integrity attribute.
    Clean,
    /// One or more subresources failed the check.
    Violations(Vec<SriViolation>),
}

/// Subresource Integrity (SRI) inspection policy.
///
/// When `enforce` is true and a response is `text/html`, the body is
/// scanned for `<script src="..."></script>` and
/// `<link rel="stylesheet" href="...">` tags pointing at external
/// origins (absolute `http://` or `https://` URLs). Each external
/// reference must carry an `integrity="..."` attribute using one of
/// the configured algorithms; references that do not are reported as
/// violations.
///
/// SRI is fundamentally a browser-side mechanism, so this policy is
/// observational by design: it surfaces missing or weak integrity
/// attributes so an operator can fix the upstream HTML, without
/// rewriting the body or blocking the response. Violations are
/// emitted on the response as the `X-SRI-Violations` header by the
/// response-phase wiring in `sbproxy-core`.
#[derive(Debug, Deserialize)]
pub struct SriPolicy {
    /// When true, scan HTML responses and emit the `X-SRI-Violations`
    /// header for any missing or weak integrity attributes. Default
    /// false (no-op).
    #[serde(default)]
    pub enforce: bool,
    /// Integrity hash algorithms to accept. Defaults to
    /// `["sha256", "sha384", "sha512"]` when not set, matching the
    /// algorithms the SRI spec admits for subresource integrity.
    #[serde(default)]
    pub algorithms: Vec<String>,
}

impl SriPolicy {
    /// Build an SriPolicy from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        if policy.algorithms.is_empty() {
            policy.algorithms = vec![
                "sha256".to_string(),
                "sha384".to_string(),
                "sha512".to_string(),
            ];
        }
        Ok(policy)
    }

    /// Inspect an HTML response body for missing or weak SRI attributes.
    ///
    /// Returns `NotApplicable` when the policy is disabled (`enforce =
    /// false`) or when the response is not `text/html`. Returns `Clean`
    /// when every external subresource reference carries an acceptable
    /// `integrity` attribute. Returns `Violations` listing each
    /// problem otherwise.
    pub fn check_html_body(&self, body: &[u8], content_type: &str) -> SriCheckResult {
        if !self.enforce {
            return SriCheckResult::NotApplicable;
        }
        if !content_type
            .split(';')
            .next()
            .map(|s| s.trim().eq_ignore_ascii_case("text/html"))
            .unwrap_or(false)
        {
            return SriCheckResult::NotApplicable;
        }
        let html = match std::str::from_utf8(body) {
            Ok(s) => s,
            // Non-UTF-8 bodies are not text/html in practice; skip rather than panic.
            Err(_) => return SriCheckResult::NotApplicable,
        };

        let violations = scan_html_for_sri(html, &self.algorithms);
        if violations.is_empty() {
            SriCheckResult::Clean
        } else {
            SriCheckResult::Violations(violations)
        }
    }
}

/// Scan an HTML document and return any SRI violations.
///
/// Uses a single regex pass that captures every `<script>` and `<link>`
/// open-tag, then per-tag predicates classify subresource references
/// and check the integrity attribute. Inline scripts (no `src=`) and
/// non-stylesheet `<link>` tags (`preconnect`, `icon`, etc.) are
/// ignored. Same-origin references (relative URLs and protocol-
/// relative `//host/...`) are also ignored because the page itself
/// already vouches for them.
fn scan_html_for_sri(html: &str, allowed_algorithms: &[String]) -> Vec<SriViolation> {
    use regex::Regex;
    use std::sync::OnceLock;

    static TAG_RE: OnceLock<Regex> = OnceLock::new();
    let tag_re = TAG_RE.get_or_init(|| {
        // Match the open-tag of every <script ...> and <link ...>.
        // (?is) = case-insensitive, dot matches newline.
        Regex::new(r#"(?is)<(script|link)\b([^>]*)>"#).expect("static SRI tag regex compiles")
    });

    let mut violations = Vec::new();
    for cap in tag_re.captures_iter(html) {
        let tag = cap.get(1).map(|m| m.as_str().to_lowercase());
        let attrs = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let tag = match tag.as_deref() {
            Some("script") => "script",
            Some("link") => "link",
            _ => continue,
        };

        // Pick the URL attribute relevant to the tag and decide if it
        // points at an external origin worth checking.
        let url = if tag == "script" {
            attr_value(attrs, "src")
        } else {
            // Only stylesheet links carry subresources we can validate
            // with SRI today. preconnect, dns-prefetch, icon, etc. are
            // out of scope.
            let rel = attr_value(attrs, "rel").unwrap_or_default();
            if !rel
                .split_ascii_whitespace()
                .any(|r| r.eq_ignore_ascii_case("stylesheet"))
            {
                continue;
            }
            attr_value(attrs, "href")
        };

        let url = match url {
            Some(u) if is_external_url(&u) => u,
            // Inline (no src/href) or same-origin: SRI does not apply.
            _ => continue,
        };

        match attr_value(attrs, "integrity") {
            None => violations.push(SriViolation {
                tag: tag.to_string(),
                url,
                reason: SriViolationReason::MissingIntegrity,
            }),
            Some(integrity) => {
                // Integrity is a space-separated list of hashes; each
                // entry is `<algorithm>-<base64-hash>`. We require at
                // least one entry to use an allowed algorithm.
                let any_allowed = integrity.split_ascii_whitespace().any(|entry| {
                    let alg = entry.split('-').next().unwrap_or("").to_ascii_lowercase();
                    allowed_algorithms
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(&alg))
                });
                if !any_allowed {
                    let found = integrity
                        .split_ascii_whitespace()
                        .filter_map(|entry| entry.split('-').next())
                        .collect::<Vec<_>>()
                        .join(",");
                    violations.push(SriViolation {
                        tag: tag.to_string(),
                        url,
                        reason: SriViolationReason::DisallowedAlgorithm { found },
                    });
                }
            }
        }
    }

    violations
}

/// Pull a single attribute value out of an HTML open-tag attribute string.
///
/// Handles double-quoted, single-quoted, and unquoted values. Returns
/// `None` when the attribute is missing.
fn attr_value(attrs: &str, name: &str) -> Option<String> {
    use regex::Regex;
    // Build the regex at call time. Attribute count is small (a handful
    // per tag) and SRI scanning is response-time, not request-hot-path,
    // so this is acceptable.
    let pattern = format!(
        r#"(?is)\b{}\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))"#,
        regex::escape(name)
    );
    let re = Regex::new(&pattern).ok()?;
    let cap = re.captures(attrs)?;
    cap.get(2)
        .or_else(|| cap.get(3))
        .or_else(|| cap.get(4))
        .map(|m| m.as_str().to_string())
}

/// Heuristic: does this URL point at an external origin?
///
/// Absolute `http://` or `https://` URLs are external. Relative URLs
/// (`/path`, `path`) and protocol-relative URLs (`//host/path`) are
/// treated as same-origin and skipped, matching how browsers exempt
/// same-origin subresources from SRI requirements by default.
fn is_external_url(url: &str) -> bool {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn sri_policy_type() {
        let policy = SriPolicy::from_config(serde_json::json!({})).unwrap();
        let policy = Policy::Sri(policy);
        assert_eq!(policy.policy_type(), "sri");
    }

    #[test]
    fn sri_from_config_defaults() {
        let policy = SriPolicy::from_config(serde_json::json!({})).unwrap();
        assert!(!policy.enforce);
        // Default to the SRI-spec-approved algorithm set so an enabled
        // policy is useful out of the box without an explicit list.
        assert_eq!(policy.algorithms, vec!["sha256", "sha384", "sha512"]);
    }

    #[test]
    fn sri_from_config_custom() {
        let policy = SriPolicy::from_config(serde_json::json!({
            "enforce": true,
            "algorithms": ["sha256", "sha384", "sha512"]
        }))
        .unwrap();

        assert!(policy.enforce);
        assert_eq!(policy.algorithms, vec!["sha256", "sha384", "sha512"]);
    }

    fn enforced_sri() -> SriPolicy {
        SriPolicy::from_config(serde_json::json!({"enforce": true})).unwrap()
    }

    #[test]
    fn sri_disabled_policy_is_noop() {
        let policy = SriPolicy::from_config(serde_json::json!({})).unwrap();
        let result =
            policy.check_html_body(b"<script src=\"https://x/y.js\"></script>", "text/html");
        assert_eq!(result, SriCheckResult::NotApplicable);
    }

    #[test]
    fn sri_skips_non_html_responses() {
        let policy = enforced_sri();
        let body = b"{\"foo\": 1}";
        assert_eq!(
            policy.check_html_body(body, "application/json"),
            SriCheckResult::NotApplicable
        );
        assert_eq!(
            policy.check_html_body(body, "text/plain"),
            SriCheckResult::NotApplicable
        );
    }

    #[test]
    fn sri_html_with_no_subresources_is_clean() {
        let policy = enforced_sri();
        let html = b"<html><body><h1>hello</h1><p>no scripts</p></body></html>";
        assert_eq!(
            policy.check_html_body(html, "text/html"),
            SriCheckResult::Clean
        );
    }

    #[test]
    fn sri_inline_script_is_ignored() {
        let policy = enforced_sri();
        // Inline script (no src attribute) is not a subresource.
        let html = b"<script>console.log('hi')</script>";
        assert_eq!(
            policy.check_html_body(html, "text/html"),
            SriCheckResult::Clean
        );
    }

    #[test]
    fn sri_relative_url_is_treated_as_same_origin() {
        let policy = enforced_sri();
        let html = br#"<script src="/static/app.js"></script>
<link rel="stylesheet" href="theme.css">"#;
        // Relative URLs are same-origin; SRI does not apply.
        assert_eq!(
            policy.check_html_body(html, "text/html"),
            SriCheckResult::Clean
        );
    }

    #[test]
    fn sri_external_script_with_valid_integrity_is_clean() {
        let policy = enforced_sri();
        let html = br#"<script src="https://cdn.example.com/lib.js"
                       integrity="sha384-abc123"
                       crossorigin="anonymous"></script>"#;
        assert_eq!(
            policy.check_html_body(html, "text/html"),
            SriCheckResult::Clean
        );
    }

    #[test]
    fn sri_external_script_missing_integrity_is_violation() {
        let policy = enforced_sri();
        let html = br#"<script src="https://cdn.example.com/lib.js"></script>"#;
        let result = policy.check_html_body(html, "text/html");
        match result {
            SriCheckResult::Violations(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].tag, "script");
                assert_eq!(v[0].url, "https://cdn.example.com/lib.js");
                assert_eq!(v[0].reason, SriViolationReason::MissingIntegrity);
            }
            other => panic!("expected Violations, got {other:?}"),
        }
    }

    #[test]
    fn sri_external_stylesheet_missing_integrity_is_violation() {
        let policy = enforced_sri();
        let html = br#"<link rel="stylesheet" href="https://cdn.example.com/theme.css">"#;
        let result = policy.check_html_body(html, "text/html");
        match result {
            SriCheckResult::Violations(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].tag, "link");
                assert_eq!(v[0].url, "https://cdn.example.com/theme.css");
                assert_eq!(v[0].reason, SriViolationReason::MissingIntegrity);
            }
            other => panic!("expected Violations, got {other:?}"),
        }
    }

    #[test]
    fn sri_non_stylesheet_link_is_ignored() {
        let policy = enforced_sri();
        // preconnect, dns-prefetch, icon, etc. are not subresources we
        // can validate via SRI.
        let html = br#"<link rel="preconnect" href="https://cdn.example.com">
<link rel="icon" href="https://cdn.example.com/favicon.ico">"#;
        assert_eq!(
            policy.check_html_body(html, "text/html"),
            SriCheckResult::Clean
        );
    }

    #[test]
    fn sri_weak_algorithm_is_violation() {
        let policy = SriPolicy::from_config(serde_json::json!({
            "enforce": true,
            "algorithms": ["sha384", "sha512"]
        }))
        .unwrap();
        // sha256 hash present but the policy only accepts sha384/sha512.
        let html = br#"<script src="https://cdn.example.com/lib.js"
                       integrity="sha256-abc"></script>"#;
        let result = policy.check_html_body(html, "text/html");
        match result {
            SriCheckResult::Violations(v) => {
                assert_eq!(v.len(), 1);
                assert!(matches!(
                    v[0].reason,
                    SriViolationReason::DisallowedAlgorithm { ref found } if found == "sha256"
                ));
            }
            other => panic!("expected Violations, got {other:?}"),
        }
    }

    #[test]
    fn sri_multiple_violations_reported_individually() {
        let policy = enforced_sri();
        let html = br#"<html>
<link rel="stylesheet" href="https://cdn1.example.com/a.css">
<script src="https://cdn2.example.com/a.js"></script>
<script src="https://cdn3.example.com/b.js" integrity="sha384-OK"></script>
<script src="/local.js"></script>
</html>"#;
        let result = policy.check_html_body(html, "text/html");
        match result {
            SriCheckResult::Violations(v) => {
                // 2 external violations (cdn1 stylesheet + cdn2 script).
                // cdn3 is fine; /local.js is same-origin.
                assert_eq!(v.len(), 2, "violations: {v:?}");
                let urls: Vec<&str> = v.iter().map(|x| x.url.as_str()).collect();
                assert!(urls.contains(&"https://cdn1.example.com/a.css"));
                assert!(urls.contains(&"https://cdn2.example.com/a.js"));
            }
            other => panic!("expected Violations, got {other:?}"),
        }
    }

    #[test]
    fn sri_content_type_with_charset_still_matches_html() {
        let policy = enforced_sri();
        let html = br#"<script src="https://cdn.example.com/lib.js"></script>"#;
        let result = policy.check_html_body(html, "text/html; charset=utf-8");
        assert!(matches!(result, SriCheckResult::Violations(_)));
    }
}
