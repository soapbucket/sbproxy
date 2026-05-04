//! Custom error pages per origin and status code.
//!
//! Allows operators to configure per-origin, per-status-code custom response
//! bodies.  When the upstream returns a matching status code the proxy
//! substitutes the configured body and `Content-Type` instead of forwarding
//! the upstream error response.
//!
//! # YAML example
//!
//! ```yaml
//! error_pages:
//!   pages:
//!     503:
//!       content_type: "text/html; charset=utf-8"
//!       body: "<h1>Service Unavailable</h1><p>We'll be right back.</p>"
//!     404:
//!       content_type: "application/json"
//!       body: '{"error":"not_found","message":"The resource was not found."}'
//! ```

use serde::Deserialize;
use std::collections::HashMap;

// --- ErrorPage ---

/// A single custom error response for a given HTTP status code.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ErrorPage {
    /// The `Content-Type` header value to send with the custom response.
    pub content_type: String,
    /// The response body to send instead of the upstream error body.
    pub body: String,
}

// --- ErrorPageConfig ---

/// Per-origin custom error page configuration.
///
/// Maps HTTP status codes (as `u16`) to their custom [`ErrorPage`] responses.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ErrorPageConfig {
    /// Map of HTTP status code → custom error page.
    #[serde(default)]
    pub pages: HashMap<u16, ErrorPage>,
}

impl ErrorPageConfig {
    /// Look up a custom error page for the given HTTP `status` code.
    ///
    /// Returns `None` when no custom page has been configured for `status`.
    pub fn get_page(&self, status: u16) -> Option<&ErrorPage> {
        self.pages.get(&status)
    }

    /// Returns `true` when at least one custom page is configured.
    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_deserializes() {
        let json = r#"{}"#;
        let cfg: ErrorPageConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.is_empty());
        assert!(cfg.get_page(503).is_none());
    }

    #[test]
    fn config_with_pages_deserializes() {
        let json = r#"{
            "pages": {
                "503": {
                    "content_type": "text/html",
                    "body": "<h1>Down</h1>"
                },
                "404": {
                    "content_type": "application/json",
                    "body": "{\"error\":\"not_found\"}"
                }
            }
        }"#;
        let cfg: ErrorPageConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.is_empty());

        let page_503 = cfg.get_page(503).expect("503 page should be present");
        assert_eq!(page_503.content_type, "text/html");
        assert_eq!(page_503.body, "<h1>Down</h1>");

        let page_404 = cfg.get_page(404).expect("404 page should be present");
        assert_eq!(page_404.content_type, "application/json");
        assert_eq!(page_404.body, r#"{"error":"not_found"}"#);
    }

    #[test]
    fn get_page_returns_none_for_unknown_status() {
        let json = r#"{"pages": {"503": {"content_type": "text/plain", "body": "oops"}}}"#;
        let cfg: ErrorPageConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.get_page(200).is_none());
        assert!(cfg.get_page(404).is_none());
        assert!(cfg.get_page(500).is_none());
    }

    #[test]
    fn get_page_returns_correct_entry() {
        let json = r#"{"pages": {"429": {"content_type": "application/json", "body": "{\"error\":\"rate_limited\"}"}}}"#;
        let cfg: ErrorPageConfig = serde_json::from_str(json).unwrap();
        let page = cfg.get_page(429).unwrap();
        assert_eq!(page.content_type, "application/json");
        assert!(page.body.contains("rate_limited"));
    }

    #[test]
    fn yaml_deserialization() {
        let yaml = r#"
pages:
  502:
    content_type: "text/html; charset=utf-8"
    body: "<h1>Bad Gateway</h1>"
  504:
    content_type: "text/plain"
    body: "Gateway Timeout"
"#;
        let cfg: ErrorPageConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.pages.len(), 2);

        let p502 = cfg.get_page(502).unwrap();
        assert_eq!(p502.content_type, "text/html; charset=utf-8");

        let p504 = cfg.get_page(504).unwrap();
        assert_eq!(p504.body, "Gateway Timeout");
    }

    #[test]
    fn default_config_is_empty() {
        let cfg = ErrorPageConfig::default();
        assert!(cfg.is_empty());
        for status in [400u16, 401, 403, 404, 429, 500, 502, 503, 504] {
            assert!(
                cfg.get_page(status).is_none(),
                "unexpected page for {status}"
            );
        }
    }

    #[test]
    fn multiple_codes_independent() {
        // Verify that looking up one code does not affect lookups for others.
        let json = r#"{
            "pages": {
                "500": {"content_type": "text/plain", "body": "server error"},
                "503": {"content_type": "text/plain", "body": "service unavailable"}
            }
        }"#;
        let cfg: ErrorPageConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.get_page(500).unwrap().body, "server error");
        assert_eq!(cfg.get_page(503).unwrap().body, "service unavailable");
        assert!(cfg.get_page(504).is_none());
    }
}
