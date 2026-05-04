//! CORS (Cross-Origin Resource Sharing) middleware.
//!
//! Provides functions to detect preflight requests, apply CORS response headers,
//! and build preflight response headers based on [`CorsConfig`].

use http::{HeaderMap, HeaderValue, Method};
use sbproxy_config::CorsConfig;

/// Check if the request is a CORS preflight (OPTIONS with Origin header).
pub fn is_preflight(method: &Method, headers: &HeaderMap) -> bool {
    method == Method::OPTIONS && headers.contains_key("origin")
}

/// Apply CORS headers to a response based on the config and request origin.
///
/// Headers are only added when the request origin is present and allowed by
/// the configuration.
///
/// # Security defaults (OPENSOURCE.md H5)
///
/// - **Empty `allowed_origins` is deny-all.** Earlier revisions echoed any
///   `Origin` back when the list was empty; that combined with
///   `allow_credentials: true` to grant credentialed cross-origin access to
///   anyone. Operators who genuinely want to permit any origin must set
///   `allowed_origins: ["*"]` explicitly.
/// - **Wildcard plus credentials is refused.** When `allowed_origins` is
///   `["*"]` and `allow_credentials` is `true`, no CORS headers are emitted
///   and a `tracing::warn!` is logged. Browsers reject this combination per
///   the Fetch spec; refusing it at the proxy layer prevents the proxy from
///   appearing to authorise something the browser will then strip.
pub fn apply_cors_headers(
    config: &CorsConfig,
    request_origin: Option<&str>,
    response_headers: &mut HeaderMap,
) {
    let Some(origin) = request_origin else {
        return;
    };

    // Empty list is now deny-all. The previous "empty means any" behaviour
    // was a credential-leak footgun; see OPENSOURCE.md H5.
    if config.allowed_origins.is_empty() {
        return;
    }

    let has_wildcard = config.allowed_origins.iter().any(|o| o == "*");

    // Wildcard + credentials is a config error: browsers reject it and
    // the proxy must not pretend to allow it.
    if has_wildcard && config.allow_credentials {
        tracing::warn!(
            "CORS misconfiguration: allowed_origins=[\"*\"] cannot be combined with allow_credentials=true; refusing to emit CORS headers"
        );
        return;
    }

    let allowed = has_wildcard || config.allowed_origins.iter().any(|o| o == origin);
    if !allowed {
        return;
    }

    // Set Access-Control-Allow-Origin
    let origin_value = if has_wildcard {
        HeaderValue::from_static("*")
    } else {
        // Safe: origin came from an HTTP header so it is valid header material.
        match HeaderValue::from_str(origin) {
            Ok(v) => v,
            Err(_) => return,
        }
    };
    response_headers.insert("access-control-allow-origin", origin_value);

    // Vary: Origin when we echo back the specific origin (not wildcard)
    if !has_wildcard {
        response_headers.append(http::header::VARY, HeaderValue::from_static("Origin"));
    }

    if config.allow_credentials {
        response_headers.insert(
            "access-control-allow-credentials",
            HeaderValue::from_static("true"),
        );
    }

    if !config.expose_headers.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&config.expose_headers.join(", ")) {
            response_headers.insert("access-control-expose-headers", v);
        }
    }
}

/// Validate a CORS configuration at config-load time.
///
/// Returns an error when the configuration combines unsafe options that
/// the runtime would otherwise silently refuse. Currently this rejects
/// `allowed_origins: ["*"]` together with `allow_credentials: true`.
///
/// Operators load configs through `sbproxy-config`; the compiler should
/// invoke this function on every `CorsConfig` it sees so that obviously
/// broken settings surface as load-time errors instead of silent runtime
/// no-ops. The runtime path in [`apply_cors_headers`] still defends
/// against the same combination as a belt-and-suspenders check.
pub fn validate_cors_config(config: &CorsConfig) -> Result<(), String> {
    let has_wildcard = config.allowed_origins.iter().any(|o| o == "*");
    if has_wildcard && config.allow_credentials {
        return Err(
            "CORS allowed_origins=[\"*\"] cannot be combined with allow_credentials=true"
                .to_string(),
        );
    }
    Ok(())
}

/// Build CORS preflight response headers.
///
/// Returns a complete set of headers suitable for a 204 No Content preflight response.
pub fn preflight_headers(config: &CorsConfig, request_origin: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();

    // Start with the common CORS headers
    apply_cors_headers(config, request_origin, &mut headers);

    // Access-Control-Allow-Methods
    if !config.allowed_methods.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&config.allowed_methods.join(", ")) {
            headers.insert("access-control-allow-methods", v);
        }
    }

    // Access-Control-Allow-Headers
    if !config.allowed_headers.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&config.allowed_headers.join(", ")) {
            headers.insert("access-control-allow-headers", v);
        }
    }

    // Access-Control-Max-Age
    if let Some(max_age) = config.max_age {
        if let Ok(v) = HeaderValue::from_str(&max_age.to_string()) {
            headers.insert("access-control-max-age", v);
        }
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> CorsConfig {
        CorsConfig {
            allowed_origins: vec![
                "https://example.com".into(),
                "https://app.example.com".into(),
            ],
            allowed_methods: vec!["GET".into(), "POST".into(), "PUT".into()],
            allowed_headers: vec!["Content-Type".into(), "Authorization".into()],
            expose_headers: vec!["X-Request-Id".into()],
            max_age: Some(3600),
            allow_credentials: true,
            enable: None,
        }
    }

    // --- Preflight Detection ---

    #[test]
    fn test_is_preflight_true() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("https://example.com"));
        assert!(is_preflight(&Method::OPTIONS, &headers));
    }

    #[test]
    fn test_is_preflight_false_no_origin() {
        let headers = HeaderMap::new();
        assert!(!is_preflight(&Method::OPTIONS, &headers));
    }

    #[test]
    fn test_is_preflight_false_wrong_method() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("https://example.com"));
        assert!(!is_preflight(&Method::GET, &headers));
        assert!(!is_preflight(&Method::POST, &headers));
    }

    // --- Origin Matching ---

    #[test]
    fn test_apply_cors_allowed_origin() {
        let config = sample_config();
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://example.com"), &mut headers);

        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn test_apply_cors_disallowed_origin() {
        let config = sample_config();
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://evil.com"), &mut headers);

        assert!(headers.get("access-control-allow-origin").is_none());
    }

    #[test]
    fn test_apply_cors_no_origin() {
        let config = sample_config();
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, None, &mut headers);

        assert!(headers.get("access-control-allow-origin").is_none());
    }

    // --- Wildcard ---

    #[test]
    fn test_apply_cors_wildcard_origin() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            allow_credentials: false,
            ..sample_config()
        };
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://anything.com"), &mut headers);

        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
    }

    // --- H5 regression: empty list is deny-all (OPENSOURCE.md) ---

    #[test]
    fn test_apply_cors_empty_origins_is_deny_all() {
        // Regression for OPENSOURCE.md H5: empty allowed_origins must
        // be treated as deny-all, not "echo any origin".
        let config = CorsConfig {
            allowed_origins: vec![],
            allow_credentials: false,
            ..sample_config()
        };
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://anything.com"), &mut headers);

        assert!(headers.get("access-control-allow-origin").is_none());
        assert!(headers.get("access-control-allow-credentials").is_none());
        assert!(headers.get(http::header::VARY).is_none());
    }

    #[test]
    fn test_apply_cors_empty_origins_with_credentials_is_deny_all() {
        // The combination that was previously catastrophic: empty list
        // plus credentials. Must emit no headers.
        let config = CorsConfig {
            allowed_origins: vec![],
            allow_credentials: true,
            ..sample_config()
        };
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://attacker.example"), &mut headers);
        assert!(headers.get("access-control-allow-origin").is_none());
        assert!(headers.get("access-control-allow-credentials").is_none());
    }

    #[test]
    fn test_apply_cors_wildcard_with_credentials_refused() {
        // ["*"] is the explicit "any origin" opt-in. Combined with
        // allow_credentials=true it is a misconfiguration; the proxy
        // must emit no CORS headers and warn.
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            allow_credentials: true,
            ..sample_config()
        };
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://anything.com"), &mut headers);
        assert!(headers.get("access-control-allow-origin").is_none());
        assert!(headers.get("access-control-allow-credentials").is_none());
    }

    #[test]
    fn test_apply_cors_explicit_allowlist_only_reflects_match() {
        // Explicit allowlist: only matching origins are echoed back.
        let config = CorsConfig {
            allowed_origins: vec!["https://app.example.com".into()],
            allow_credentials: true,
            ..sample_config()
        };

        // Matching origin is echoed.
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://app.example.com"), &mut headers);
        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://app.example.com"
        );

        // Non-matching origin gets no headers.
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://evil.example"), &mut headers);
        assert!(headers.get("access-control-allow-origin").is_none());
    }

    // --- Validation ---

    #[test]
    fn test_validate_cors_config_rejects_wildcard_plus_credentials() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            allow_credentials: true,
            ..sample_config()
        };
        let err = validate_cors_config(&config).expect_err("expected validation failure");
        assert!(err.contains("allow_credentials"), "got: {err}");
    }

    #[test]
    fn test_validate_cors_config_accepts_wildcard_without_credentials() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            allow_credentials: false,
            ..sample_config()
        };
        validate_cors_config(&config).expect("wildcard without credentials should be accepted");
    }

    #[test]
    fn test_validate_cors_config_accepts_explicit_allowlist() {
        let config = sample_config();
        validate_cors_config(&config).expect("explicit allowlist should be accepted");
    }

    #[test]
    fn test_validate_cors_config_accepts_empty_allowlist() {
        // Empty is now deny-all at runtime, but it is not invalid.
        let config = CorsConfig {
            allowed_origins: vec![],
            allow_credentials: false,
            ..sample_config()
        };
        validate_cors_config(&config).expect("empty allowlist should pass validation");
    }

    // --- Credentials ---

    #[test]
    fn test_apply_cors_credentials() {
        let config = sample_config();
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://example.com"), &mut headers);

        assert_eq!(
            headers.get("access-control-allow-credentials").unwrap(),
            "true"
        );
    }

    #[test]
    fn test_apply_cors_no_credentials() {
        let config = CorsConfig {
            allow_credentials: false,
            ..sample_config()
        };
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://example.com"), &mut headers);

        assert!(headers.get("access-control-allow-credentials").is_none());
    }

    // --- Expose Headers ---

    #[test]
    fn test_apply_cors_expose_headers() {
        let config = sample_config();
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://example.com"), &mut headers);

        assert_eq!(
            headers.get("access-control-expose-headers").unwrap(),
            "X-Request-Id"
        );
    }

    #[test]
    fn test_apply_cors_no_expose_headers() {
        let config = CorsConfig {
            expose_headers: vec![],
            ..sample_config()
        };
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://example.com"), &mut headers);

        assert!(headers.get("access-control-expose-headers").is_none());
    }

    // --- Vary Header ---

    #[test]
    fn test_vary_header_set_for_specific_origin() {
        let config = sample_config();
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://example.com"), &mut headers);

        assert_eq!(headers.get(http::header::VARY).unwrap(), "Origin");
    }

    #[test]
    fn test_no_vary_header_for_wildcard() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            allow_credentials: false,
            ..sample_config()
        };
        let mut headers = HeaderMap::new();
        apply_cors_headers(&config, Some("https://example.com"), &mut headers);

        assert!(headers.get(http::header::VARY).is_none());
    }

    // --- Preflight Headers ---

    #[test]
    fn test_preflight_headers_methods() {
        let config = sample_config();
        let headers = preflight_headers(&config, Some("https://example.com"));

        assert_eq!(
            headers.get("access-control-allow-methods").unwrap(),
            "GET, POST, PUT"
        );
    }

    #[test]
    fn test_preflight_headers_allowed_headers() {
        let config = sample_config();
        let headers = preflight_headers(&config, Some("https://example.com"));

        assert_eq!(
            headers.get("access-control-allow-headers").unwrap(),
            "Content-Type, Authorization"
        );
    }

    #[test]
    fn test_preflight_headers_max_age() {
        let config = sample_config();
        let headers = preflight_headers(&config, Some("https://example.com"));

        assert_eq!(headers.get("access-control-max-age").unwrap(), "3600");
    }

    #[test]
    fn test_preflight_headers_no_max_age() {
        let config = CorsConfig {
            max_age: None,
            ..sample_config()
        };
        let headers = preflight_headers(&config, Some("https://example.com"));

        assert!(headers.get("access-control-max-age").is_none());
    }

    #[test]
    fn test_preflight_includes_common_cors_headers() {
        let config = sample_config();
        let headers = preflight_headers(&config, Some("https://example.com"));

        // Should include the standard CORS headers too
        assert!(headers.get("access-control-allow-origin").is_some());
        assert!(headers.get("access-control-allow-credentials").is_some());
    }
}
