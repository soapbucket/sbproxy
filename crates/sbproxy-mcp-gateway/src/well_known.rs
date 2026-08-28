// `GET /.well-known/oauth-authorization-server` (RFC 8414).
//
// Surfaces the broker's own metadata so MCP clients can discover the
// authorization, token, and (optionally) registration endpoints
// without baking URLs into client code. Most fields are mirrored from
// the cached upstream AS metadata; the broker overrides the four
// endpoint fields and the PKCE/grant/auth-method advertisements so
// clients always see sbproxy's URLs and broker-enforced policy.
//
// Cache-Control: public, max-age=300 keeps this cheap for the user
// agent while still letting the broker rotate config inside an
// operator-friendly window.

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::as_metadata::AuthorizationServerMetadata;
use crate::config::McpGatewayConfig;
use crate::AppState;

// --- Document model ---

/// Broker-side view of RFC 8414 Authorization-Server metadata.
///
/// Field ordering and naming follows RFC 8414 verbatim so deployers
/// can grep their AS console docs against the served document. Fields
/// the broker does not own (e.g. `service_documentation`) are dropped
/// rather than echoed; clients should consult the upstream AS for
/// anything not listed here.
#[derive(Clone, Debug, Serialize)]
pub struct BrokerMetadata {
    /// The broker's issuer identifier. Operators set this to the
    /// canonical URL their MCP clients trust; it does NOT have to
    /// equal the upstream AS issuer.
    pub issuer: String,

    /// Broker-served authorize endpoint (`<base_url><base_path>/authorize`).
    pub authorization_endpoint: String,

    /// Broker-served token endpoint (`<base_url><base_path>/token`).
    pub token_endpoint: String,

    /// Broker-served dynamic client registration endpoint. Present
    /// only when DCR is enabled (the upstream registration URL is
    /// configured); RFC 8414 says callers MUST treat absence as
    /// "registration not supported".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    /// JWKS URI. Mirrored from the upstream AS metadata when
    /// available so clients can validate id_tokens minted upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Grant types the broker accepts. Always equals
    /// `["authorization_code", "refresh_token", "client_credentials"]`
    /// because the /token handler hardcodes this list and rejects
    /// `password` + unknown grants.
    pub grant_types_supported: Vec<String>,

    /// Response types the broker advertises. OAuth 2.1 forbids the
    /// implicit grant, so this is fixed at `["code"]`.
    pub response_types_supported: Vec<String>,

    /// Client-authentication methods the broker accepts at the token
    /// endpoint. Sourced from `accepted_client_auth_methods`.
    pub token_endpoint_auth_methods_supported: Vec<String>,

    /// PKCE methods. Hardcoded to `["S256"]` because the broker
    /// rejects `plain` at /authorize time and requires `code_verifier`
    /// at /token time.
    pub code_challenge_methods_supported: Vec<String>,

    /// Optional scope list, mirrored verbatim from the upstream AS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// DPoP (RFC 9449) signing algorithms the broker accepts on the
    /// `/token` endpoint. Present only when `dpop_supported` is true.
    /// Mirrors the asymmetric allow-list inside `dpop::is_alg_allowed`
    /// so clients pick a compatible curve up front.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    /// RFC 8628 device authorization endpoint URL. Present only when
    /// `device_code_enabled` is true so clients that key off the
    /// metadata document never see a stale URL after the master
    /// switch flips off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,

    /// RFC 9126 Pushed Authorization Request endpoint URL. Present
    /// only when the broker has a PAR store wired (Wave 4D.3a).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,

    /// RFC 9126 sec 5: when present and `true`, the broker requires
    /// every authorization request to be pushed first (no inline
    /// /authorize parameters). Defaults to absent for backward
    /// compatibility; future per-tenant config can flip it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,

    /// RFC 7009 token revocation endpoint URL. Present only when
    /// the broker has `upstream_revocation_endpoint_url` configured
    /// so clients keying off the metadata document never see a stale
    /// URL after the upstream wiring flips off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// RFC 7662 token introspection endpoint URL. Present only when
    /// the broker has `upstream_introspection_endpoint_url` configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,

    /// RFC 9207 advertisement: the broker emits the `iss` parameter
    /// on every authorization response (callback redirect to the
    /// client). Always `true` because this broker has no off switch
    /// for the protection; we set the field explicitly so RFC
    /// 9207-aware clients can rely on it being present.
    pub authorization_response_iss_parameter_supported: bool,
}

// --- Builder ---

/// Build a `BrokerMetadata` document from broker config plus the
/// optional upstream AS metadata. The upstream doc is consulted for
/// `jwks_uri` and (in future revisions) scope lists; everything else
/// is broker-owned.
pub fn build_metadata(
    cfg: &McpGatewayConfig,
    upstream: Option<&AuthorizationServerMetadata>,
    base_url: &str,
) -> BrokerMetadata {
    let base = base_url.trim_end_matches('/').to_string();
    let path = cfg.base_path.trim_end_matches('/').to_string();

    let registration_endpoint = cfg
        .upstream_registration_endpoint_url
        .as_ref()
        .map(|_| format!("{base}{path}/register"));

    let dpop_signing_alg_values_supported = if cfg.dpop_supported {
        Some(crate::config::default_dpop_signing_algs())
    } else {
        None
    };

    // --- Grant types ---
    //
    // Always advertise the three OAuth 2.1 baseline grants. When the
    // device-code or token-exchange master switches are on, append the
    // RFC 8628 / RFC 8693 URNs so clients reading the metadata
    // document discover those flows automatically.
    let mut grant_types_supported = vec![
        "authorization_code".to_string(),
        "refresh_token".to_string(),
        "client_credentials".to_string(),
    ];
    if cfg.device_code_enabled {
        grant_types_supported.push(crate::device_code::DEVICE_CODE_GRANT_TYPE.to_string());
    }
    if cfg.token_exchange_enabled {
        grant_types_supported.push(crate::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE.to_string());
    }

    let device_authorization_endpoint = if cfg.device_code_enabled {
        Some(format!("{base}{path}/device_authorization"))
    } else {
        None
    };

    // RFC 7009: only advertise /revoke when the upstream revocation
    // endpoint is wired. The router omits the /revoke route under
    // the same condition; advertising it without the route would
    // leak a 404.
    let revocation_endpoint = if cfg.upstream_revocation_endpoint_url.is_some() {
        Some(format!("{base}{path}/revoke"))
    } else {
        None
    };

    // RFC 7662: same condition for /introspect.
    let introspection_endpoint = if cfg.upstream_introspection_endpoint_url.is_some() {
        Some(format!("{base}{path}/introspect"))
    } else {
        None
    };

    // RFC 9068: prefer the broker's own JWKS URL when a signing key
    // is configured (the broker mints its own access tokens). When
    // no signing key is configured, fall back to the upstream's
    // jwks_uri so RFC 9068-aware verifiers can still find it.
    let jwks_uri = if cfg.broker_signing_key.is_some() {
        Some(format!("{base}{path}/.well-known/jwks.json"))
    } else {
        upstream.and_then(|u| u.jwks_uri.clone())
    };

    BrokerMetadata {
        issuer: derive_issuer(cfg, &base, &path),
        authorization_endpoint: format!("{base}{path}/authorize"),
        token_endpoint: format!("{base}{path}/token"),
        registration_endpoint,
        jwks_uri,
        grant_types_supported,
        response_types_supported: vec!["code".to_string()],
        token_endpoint_auth_methods_supported: cfg.accepted_client_auth_methods.clone(),
        code_challenge_methods_supported: vec!["S256".to_string()],
        scopes_supported: None,
        dpop_signing_alg_values_supported,
        device_authorization_endpoint,
        // PAR endpoint advertisement is set by the handler based on
        // whether `app.par_store` is plumbed; the builder cannot tell
        // from `cfg` alone. Default to None here; the handler patches
        // the field after build_metadata returns.
        pushed_authorization_request_endpoint: None,
        require_pushed_authorization_requests: None,
        revocation_endpoint,
        introspection_endpoint,
        authorization_response_iss_parameter_supported: true,
    }
}

/// Patch the PAR endpoint URL onto a previously-built metadata
/// document. Called by the well-known handler when `app.par_store` is
/// configured. Kept as a separate helper so `build_metadata` stays
/// pure (`cfg`-only) and easy to unit test.
pub fn patch_par_endpoint(doc: &mut BrokerMetadata, cfg: &McpGatewayConfig, base_url: &str) {
    let base = base_url.trim_end_matches('/').to_string();
    let path = cfg.base_path.trim_end_matches('/').to_string();
    doc.pushed_authorization_request_endpoint = Some(format!("{base}{path}/par"));
}

/// Issuer derivation: prefer the upstream's `<base_url><base_path>`
/// concatenation. The config layer doesn't yet have a dedicated
/// `issuer` field; operators that need a custom issuer should set
/// `base_path` accordingly. A future revision will promote `issuer`
/// to a first-class config field.
fn derive_issuer(_cfg: &McpGatewayConfig, base: &str, path: &str) -> String {
    if path.is_empty() {
        base.to_string()
    } else {
        format!("{base}{path}")
    }
}

/// The broker's RFC 9207 issuer string, suitable for emitting as the
/// `iss` parameter on authorization responses or as the `iss` claim
/// on JWTs the broker mints itself. Uses the legacy
/// `MCP_GATEWAY_BASE_URL` override or the configured external base
/// URL, plus the configured base path.
pub fn broker_issuer(cfg: &McpGatewayConfig) -> String {
    let base_url = base_url_from_env_or_config(cfg);
    let base = base_url.trim_end_matches('/').to_string();
    let path = cfg.base_path.trim_end_matches('/').to_string();
    derive_issuer(cfg, &base, &path)
}

// --- Handler ---

/// `GET {base_path}/.well-known/oauth-authorization-server` handler.
pub async fn well_known(State(app): State<AppState>) -> Response {
    // Never derive public endpoints from the request Host header.
    // Operators configure one canonical origin; the environment
    // variable remains a backwards-compatible standalone override.
    let base_url = base_url_from_env_or_config(&app.config);

    let upstream = match app.as_metadata.as_ref() {
        Some(cache) => {
            // Best-effort fetch within the configured staleness
            // window. The well-known doc serves a fallback shape if
            // the upstream is unreachable.
            cache
                .fetch_or_cached(
                    app.config.metadata_refresh_secs,
                    app.config.max_metadata_staleness_secs,
                )
                .await
                .ok()
        }
        None => None,
    };

    let mut doc = build_metadata(&app.config, upstream.as_deref(), &base_url);
    if app.par_store.is_some() {
        patch_par_endpoint(&mut doc, &app.config, &base_url);
    }
    let body = match serde_json::to_string(&doc) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize well-known doc");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error"})),
            )
                .into_response();
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json;charset=UTF-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    (StatusCode::OK, headers, body).into_response()
}

/// `GET {base_path}/.well-known/jwks.json` handler. Returns the
/// public half of the broker's signing key (when configured) so RFC
/// 9068-aware resource servers can verify broker-issued JWTs by
/// JWKS lookup. Returns an empty `keys` array when no signing key
/// is configured rather than 404, so verifiers do not retry forever.
pub async fn jwks(State(app): State<AppState>) -> Response {
    let doc = crate::at_jwt::broker_jwks(app.config.broker_signing_key.as_ref());
    let body = match serde_json::to_string(&doc) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize JWKS doc");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error"})),
            )
                .into_response();
        }
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json;charset=UTF-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    (StatusCode::OK, headers, body).into_response()
}

/// Derive the broker's externally-visible base URL. The environment
/// override is retained for older standalone deployments.
fn base_url_from_env_or_config(cfg: &McpGatewayConfig) -> String {
    std::env::var("MCP_GATEWAY_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| cfg.external_base_url.clone())
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_accepted_client_auth_methods;
    use crate::session::InMemorySessionStore;
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn test_config() -> McpGatewayConfig {
        // Use Default and override only what differs; this keeps the
        // test fixture stable as new fields land in McpGatewayConfig
        // (Wave 4D.2 added device-code + token-exchange knobs).
        let _ = default_accepted_client_auth_methods; // referenced by other tests
        McpGatewayConfig {
            upstream_token_endpoint_url: "https://idp.example.com/oauth/token".to_string(),
            upstream_registration_endpoint_url: Some(
                "https://idp.example.com/oauth/register".to_string(),
            ),
            upstream_authorization_server_url: "https://idp.example.com/oauth/authorize"
                .to_string(),
            resource_uri: "https://mcp.example/api".to_string(),
            allowed_redirect_uris: vec!["https://client.example/cb".to_string()],
            ..McpGatewayConfig::default()
        }
    }

    #[test]
    fn document_has_required_rfc8414_fields() {
        let cfg = test_config();
        let doc = build_metadata(&cfg, None, "https://broker.example");
        assert_eq!(doc.issuer, "https://broker.example/mcp/oauth");
        assert_eq!(
            doc.authorization_endpoint,
            "https://broker.example/mcp/oauth/authorize"
        );
        assert_eq!(doc.token_endpoint, "https://broker.example/mcp/oauth/token");
        assert_eq!(
            doc.registration_endpoint.as_deref(),
            Some("https://broker.example/mcp/oauth/register")
        );
    }

    #[test]
    fn pkce_methods_are_s256_only() {
        let cfg = test_config();
        let doc = build_metadata(&cfg, None, "https://broker.example");
        assert_eq!(doc.code_challenge_methods_supported, vec!["S256"]);
    }

    #[test]
    fn registration_endpoint_omitted_when_dcr_disabled() {
        let mut cfg = test_config();
        cfg.upstream_registration_endpoint_url = None;
        let doc = build_metadata(&cfg, None, "https://broker.example");
        assert!(doc.registration_endpoint.is_none());
    }

    #[test]
    fn auth_methods_mirror_config() {
        let mut cfg = test_config();
        cfg.accepted_client_auth_methods =
            vec!["client_secret_basic".to_string(), "none".to_string()];
        let doc = build_metadata(&cfg, None, "https://broker.example");
        assert_eq!(
            doc.token_endpoint_auth_methods_supported,
            vec!["client_secret_basic", "none"]
        );
    }

    #[test]
    fn jwks_uri_mirrors_upstream_when_present() {
        let cfg = test_config();
        let upstream = AuthorizationServerMetadata {
            issuer: "https://idp.example.com".to_string(),
            jwks_uri: Some("https://idp.example.com/.well-known/jwks.json".to_string()),
            ..Default::default()
        };
        let doc = build_metadata(&cfg, Some(&upstream), "https://broker.example");
        assert_eq!(
            doc.jwks_uri.as_deref(),
            Some("https://idp.example.com/.well-known/jwks.json")
        );
    }

    #[test]
    fn response_types_only_lists_code() {
        let cfg = test_config();
        let doc = build_metadata(&cfg, None, "https://broker.example");
        assert_eq!(doc.response_types_supported, vec!["code"]);
    }

    #[test]
    fn dpop_algs_advertised_when_supported() {
        let cfg = test_config();
        let doc = build_metadata(&cfg, None, "https://broker.example");
        let algs = doc
            .dpop_signing_alg_values_supported
            .as_ref()
            .expect("dpop_supported defaults to true");
        assert!(algs.iter().any(|a| a == "ES256"));
        assert!(algs.iter().any(|a| a == "EdDSA"));
        // RFC 9449 §5.1: PKCS1v1.5 RSA (RS256/384/512) MUST NOT be advertised.
        assert!(!algs.iter().any(|a| a == "RS256"));
    }

    #[test]
    fn dpop_algs_omitted_when_disabled() {
        let mut cfg = test_config();
        cfg.dpop_supported = false;
        let doc = build_metadata(&cfg, None, "https://broker.example");
        assert!(doc.dpop_signing_alg_values_supported.is_none());
    }

    #[test]
    fn device_code_flag_toggles_grant_and_endpoint() {
        // Off path: neither the grant nor the endpoint shows up.
        let cfg = test_config();
        let off = build_metadata(&cfg, None, "https://broker.example");
        assert!(!off
            .grant_types_supported
            .iter()
            .any(|g| g == crate::device_code::DEVICE_CODE_GRANT_TYPE));
        assert!(off.device_authorization_endpoint.is_none());

        // On path: the grant URN is appended and the endpoint is set.
        let mut cfg_on = test_config();
        cfg_on.device_code_enabled = true;
        let on = build_metadata(&cfg_on, None, "https://broker.example");
        assert!(on
            .grant_types_supported
            .iter()
            .any(|g| g == crate::device_code::DEVICE_CODE_GRANT_TYPE));
        assert_eq!(
            on.device_authorization_endpoint.as_deref(),
            Some("https://broker.example/mcp/oauth/device_authorization")
        );
    }

    #[test]
    fn token_exchange_flag_toggles_grant_only() {
        // Off path: the grant URN is absent.
        let cfg = test_config();
        let off = build_metadata(&cfg, None, "https://broker.example");
        assert!(!off
            .grant_types_supported
            .iter()
            .any(|g| g == crate::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE));

        // On path: the grant URN is appended; no dedicated endpoint
        // field exists in RFC 8693 so the only observable change is
        // grant_types_supported.
        let mut cfg_on = test_config();
        cfg_on.token_exchange_enabled = true;
        let on = build_metadata(&cfg_on, None, "https://broker.example");
        assert!(on
            .grant_types_supported
            .iter()
            .any(|g| g == crate::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE));
        // No device authorization endpoint should be set just because
        // token-exchange flipped on.
        assert!(on.device_authorization_endpoint.is_none());
    }

    #[tokio::test]
    async fn handler_returns_json_with_cache_control() {
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        let app = crate::router(Arc::new(test_config()), store);
        let req = Request::builder()
            .method("GET")
            .uri("/mcp/oauth/.well-known/oauth-authorization-server")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "application/json;charset=UTF-8"
        );
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap(),
            "public, max-age=300"
        );
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        // Required RFC 8414 fields are always present in the JSON.
        assert!(body_str.contains("\"issuer\""));
        assert!(body_str.contains("\"authorization_endpoint\""));
        assert!(body_str.contains("\"token_endpoint\""));
        assert!(body_str.contains("\"code_challenge_methods_supported\""));
        assert!(body_str.contains("\"S256\""));
    }
}
