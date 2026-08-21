//! CORS (Cross-Origin Resource Sharing) middleware.
//!
//! Provides functions to detect preflight requests, apply CORS response headers,
//! and build preflight response headers based on [`CorsConfig`].

use http::{HeaderMap, HeaderValue, Method};
use sbproxy_config::CorsConfig;

/// Check whether the request is a CORS preflight.
///
/// The Fetch standard defines a preflight as an `OPTIONS` request that
/// carries `Access-Control-Request-Method`. `Origin` alone is not enough:
/// it rides on every cross-origin request of every method, so treating
/// `OPTIONS` + `Origin` as a preflight made the proxy answer 204 to any
/// plain `OPTIONS` from a browser and deleted the upstream's own
/// `OPTIONS` handler (a REST discovery endpoint returning `Allow:`, or
/// anything WebDAV) the moment a `cors:` block was added.
///
/// Both headers are required here, so a plain `OPTIONS` falls through to
/// the normal request path and reaches the upstream.
pub fn is_preflight(method: &Method, headers: &HeaderMap) -> bool {
    method == Method::OPTIONS
        && headers.contains_key("origin")
        && headers.contains_key("access-control-request-method")
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
///   `["*"]` and `allow_credentials` is `true`, no CORS headers are emitted.
///   Browsers reject this combination per the Fetch spec; refusing it at the
///   proxy layer prevents the proxy from appearing to authorize something the
///   browser will then strip. The config compiler now fails the load on the
///   same pair, so this guard only fires for a `CorsConfig` built in code.
///   It logs once per process and counts every refusal on
///   `sbproxy_cors_refusals_total{reason}`, because the previous per-request
///   `warn!` put one line per request into the log for as long as the config
///   stayed live.
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
    // the proxy must not pretend to allow it. Same predicate the compiler
    // refuses the config with, so the two cannot drift apart.
    if config.wildcard_with_credentials() {
        sbproxy_observe::metrics::record_cors_refusal("wildcard_with_credentials");
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "CORS misconfiguration: allowed_origins=[\"*\"] cannot be combined with allow_credentials=true; refusing to emit CORS headers. Logged once per process; every occurrence is counted on sbproxy_cors_refusals_total"
            );
        });
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

/// Validate a CORS configuration before it reaches the request path.
///
/// Returns an error when the configuration combines unsafe options that
/// the runtime would otherwise silently refuse. Currently this rejects
/// `allowed_origins: ["*"]` together with `allow_credentials: true`.
///
/// A config loaded from YAML never reaches here: `sbproxy-config`'s
/// compiler fails the load on the same combination, using the same
/// [`CorsConfig::wildcard_with_credentials`] predicate this function and
/// [`apply_cors_headers`] call, so the three cannot drift apart. This
/// entry point remains for a caller that assembles a `CorsConfig` in code
/// (an embedder, a test) and wants the same answer before serving with it.
pub fn validate_cors_config(config: &CorsConfig) -> Result<(), String> {
    if config.wildcard_with_credentials() {
        return Err(
            "CORS allowed_origins=[\"*\"] cannot be combined with allow_credentials=true"
                .to_string(),
        );
    }
    Ok(())
}

/// Build CORS preflight response headers.
///
/// Returns a complete set of headers suitable for a 204 No Content
/// preflight response.
///
/// When the request origin is not allowed (or the config is the refused
/// wildcard-plus-credentials pair), [`apply_cors_headers`] produces no
/// `Access-Control-Allow-Origin` and this function stops there: the
/// method, header, and max-age lines are the answer to a question the
/// caller was not allowed to ask, and emitting them anyway let any caller
/// read the configured method and header allowlists off the 204.
pub fn preflight_headers(config: &CorsConfig, request_origin: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();

    // Start with the common CORS headers
    apply_cors_headers(config, request_origin, &mut headers);

    if !headers.contains_key("access-control-allow-origin") {
        return headers;
    }

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

    /// The two headers the Fetch standard requires on a preflight.
    fn preflight_request_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("https://example.com"));
        headers.insert(
            "access-control-request-method",
            HeaderValue::from_static("POST"),
        );
        headers
    }

    #[test]
    fn test_is_preflight_true() {
        assert!(is_preflight(&Method::OPTIONS, &preflight_request_headers()));
    }

    #[test]
    fn test_is_preflight_false_no_origin() {
        let headers = HeaderMap::new();
        assert!(!is_preflight(&Method::OPTIONS, &headers));
    }

    #[test]
    fn test_is_preflight_false_wrong_method() {
        let headers = preflight_request_headers();
        assert!(!is_preflight(&Method::GET, &headers));
        assert!(!is_preflight(&Method::POST, &headers));
    }

    #[test]
    fn plain_options_with_only_origin_is_not_a_preflight() {
        // The upstream-endpoint-deletion case: a browser page on an
        // allowed origin calling fetch('/v1/orders', {method: 'OPTIONS'}).
        // `Origin` rides on every cross-origin request, so treating it as
        // a preflight meant the proxy answered 204 and the upstream's own
        // OPTIONS handler (Allow:, a capability document, WebDAV) never
        // ran. Only `Access-Control-Request-Method` marks a preflight.
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("https://example.com"));
        assert!(
            !is_preflight(&Method::OPTIONS, &headers),
            "a plain OPTIONS must reach the upstream"
        );
    }

    #[test]
    fn options_with_the_request_method_header_is_a_preflight() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("https://example.com"));
        headers.insert(
            "access-control-request-method",
            HeaderValue::from_static("DELETE"),
        );
        assert!(is_preflight(&Method::OPTIONS, &headers));
    }

    #[test]
    fn access_control_request_method_without_origin_is_not_a_preflight() {
        // A real preflight always carries both. One without `Origin` is
        // not a browser preflight, so it goes to the upstream rather than
        // collecting a 204 from the proxy.
        let mut headers = HeaderMap::new();
        headers.insert(
            "access-control-request-method",
            HeaderValue::from_static("POST"),
        );
        assert!(!is_preflight(&Method::OPTIONS, &headers));
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

    #[test]
    fn preflight_for_a_disallowed_origin_leaks_no_allowlist() {
        // `apply_cors_headers` produced nothing for this origin, so the
        // 204 must not go on to publish the configured method and header
        // allowlists to a caller that was refused.
        let config = sample_config();
        let headers = preflight_headers(&config, Some("https://evil.example"));

        assert!(headers.get("access-control-allow-origin").is_none());
        assert!(
            headers.get("access-control-allow-methods").is_none(),
            "a refused preflight must not publish the method allowlist"
        );
        assert!(
            headers.get("access-control-allow-headers").is_none(),
            "a refused preflight must not publish the header allowlist"
        );
        assert!(headers.get("access-control-max-age").is_none());
        assert!(headers.is_empty(), "got: {headers:?}");
    }

    #[test]
    fn preflight_under_wildcard_plus_credentials_leaks_no_allowlist() {
        // The refused-config path reaches the same early return.
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            allow_credentials: true,
            ..sample_config()
        };
        let headers = preflight_headers(&config, Some("https://anything.example"));
        assert!(headers.is_empty(), "got: {headers:?}");
    }
}
