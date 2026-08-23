// /authorize handler for the MCP OAuth 2.1 broker.
//
// Validates the inbound request, persists a `Session` keyed by a
// freshly minted broker-side `state`, and 302-redirects the user
// agent to the upstream Authorization Server with the broker's
// callback URL substituted in for `redirect_uri`.
//
// Validation contract (rejected with HTTP 400 + OAuth error JSON):
//
//   * `client_id` must be present and non-empty.
//   * `redirect_uri` must exact-match an entry in
//     `allowed_redirect_uris` (RFC 6749 §3.1.2.4).
//   * `response_type` must equal `code`. `token` (implicit grant)
//     is forbidden by OAuth 2.1.
//   * `code_challenge` must be present.
//   * `code_challenge_method` must equal `S256`. `plain` is
//     forbidden by OAuth 2.1.
//   * `state` must be present and non-empty.
//   * `resource` (RFC 8707) must be present and non-empty.
//
// The `resource` parameter is bound to the broker's configured
// resource set (`config.resource_uri` plus an optional
// `config.resource_uri_allowlist`). Mismatches are rejected with the
// RFC 8707 §2 `invalid_target` error. The same check runs against
// PAR-backed requests after the stored params have been replayed
// into the `AuthorizeQuery`, so PAR cannot be used to bypass the
// binding.

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::pkce::CodeChallengeMethod;
use crate::session::Session;
use crate::AppState;

// --- Query model ---

/// Inbound /authorize query string.
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    /// Client identifier: either a pre-registered opaque string or an
    /// `https://` URL treated as a Client ID Metadata Document
    /// reference when `cimd_enabled` is true.
    pub client_id: Option<String>,
    /// Redirect URI. Must exact-match an entry in
    /// `allowed_redirect_uris` (or the resolved CIMD document's own
    /// `redirect_uris`) per RFC 6749 §3.1.2.4.
    pub redirect_uri: Option<String>,
    /// OAuth response_type. OAuth 2.1 permits only `code`; `token`
    /// (the implicit grant) is rejected.
    pub response_type: Option<String>,
    /// PKCE code challenge (RFC 7636).
    pub code_challenge: Option<String>,
    /// PKCE challenge method. Only `S256` is accepted; `plain` is
    /// forbidden by OAuth 2.1.
    pub code_challenge_method: Option<String>,
    /// Client-supplied opaque state, echoed back on `/callback`. The
    /// broker never inspects or interprets this value.
    pub state: Option<String>,
    /// RFC 8707 resource indicator. Must equal `config.resource_uri`
    /// or a member of `config.resource_uri_allowlist`.
    pub resource: Option<String>,
    /// Optional `scope` parameter is forwarded verbatim if present.
    pub scope: Option<String>,
    /// Wave 4D.3a: Pushed Authorization Request URI (RFC 9126
    /// §2.2). When present, the broker consumes the stored params
    /// from the PAR store and ignores any other query parameters
    /// (per the RFC: when request_uri is supplied, all other request
    /// parameters MUST be ignored).
    pub request_uri: Option<String>,
}

// --- Error response ---

/// Render an OAuth error response per RFC 6749 §5.2 with the given
/// HTTP status. Always returns JSON; the user agent will see the
/// payload only when the upstream redirect cannot be performed (the
/// broker has nowhere safe to send the user when the client is not
/// yet validated).
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

// --- Handler ---

/// `GET {base_path}/authorize` handler.
pub async fn authorize(State(app): State<AppState>, Query(q): Query<AuthorizeQuery>) -> Response {
    let cfg = &app.config;

    // --- Wave 4D.3a PAR request_uri consumption ---
    //
    // Per RFC 9126 sec 2.2: when request_uri is present, the broker
    // looks up the stored params (single-use) and ignores all other
    // query parameters. Two failure modes both 400:
    //   1. PAR is not enabled on this broker (no par_store).
    //   2. The request_uri does not resolve (expired, malformed, or
    //      already consumed).
    let q = if let Some(uri) = q.request_uri.as_deref().filter(|s| !s.is_empty()) {
        let Some(store) = app.par_store.as_ref() else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request_uri parameter not supported on this broker",
            );
        };
        let Some(params) = crate::par::consume(store, uri).await else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request_uri is unknown, expired, or already consumed",
            );
        };
        AuthorizeQuery {
            client_id: Some(params.client_id),
            redirect_uri: Some(params.redirect_uri),
            response_type: Some(params.response_type),
            code_challenge: Some(params.code_challenge),
            code_challenge_method: Some(params.code_challenge_method),
            state: params.state,
            resource: params.resource,
            scope: params.scope,
            request_uri: None,
        }
    } else {
        q
    };

    // --- Required scalar params ---

    let client_id = match q.client_id.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing client_id",
            )
        }
    };

    let redirect_uri = match q.redirect_uri.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing redirect_uri",
            )
        }
    };

    // --- CIMD detection + validation ---
    //
    // If the client_id parses as an https URL we treat it as a Client
    // ID Metadata Document reference (Wave 4C, parecki draft). The
    // broker resolves the URL through the CIMD cache, then validates
    // the requested redirect_uri + scope against the document. On any
    // CIMD failure we return invalid_client with a clear description;
    // we deliberately do NOT fall through to the pre-registered allow
    // list because the client picked the URL form on purpose.
    //
    // Pre-registered (opaque-string) client_ids continue to use the
    // existing allowlist check.
    let cimd_doc = match detect_cimd_client_id(client_id) {
        Some(_url) if cfg.cimd_enabled => match &app.cimd_cache {
            Some(cache) => match cache
                .get_or_fetch(
                    client_id,
                    &sbproxy_httpkit::token_bearing_outbound(),
                    cfg.cimd_max_doc_bytes,
                )
                .await
            {
                Ok(doc) => Some(doc),
                Err(e) => {
                    tracing::warn!(error = %e, client_id = %client_id, "CIMD resolve failed");
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client",
                        &format!("CIMD resolution failed: {e}"),
                    );
                }
            },
            None => {
                tracing::warn!(
                    client_id = %client_id,
                    "URL-shaped client_id received but no CIMD cache configured"
                );
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_client",
                    "URL-shaped client_id received but CIMD cache is not configured",
                );
            }
        },
        Some(_) => {
            // CIMD disabled but the client_id is URL-shaped. Fail closed.
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "URL-shaped client_id received but cimd_enabled is false",
            );
        }
        None => None,
    };

    // RFC 6749 §3.1.2.4 mandates exact matching. CIMD clients validate
    // against the document's redirect_uris; pre-registered clients use
    // the broker-side allowlist.
    let redirect_ok = match &cimd_doc {
        Some(doc) => doc.allows_redirect_uri(redirect_uri),
        None => cfg.allowed_redirect_uris.iter().any(|r| r == redirect_uri),
    };
    if !redirect_ok {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is not registered",
        );
    }

    // OAuth 2.1: only `code` is allowed; the implicit `token` flow
    // is removed.
    match q.response_type.as_deref() {
        Some("code") => {}
        Some("token") => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_response_type",
                "implicit grant is forbidden by OAuth 2.1; use response_type=code",
            )
        }
        Some(other) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_response_type",
                &format!("unsupported response_type {other:?}"),
            )
        }
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing response_type",
            )
        }
    }

    let code_challenge = match q.code_challenge.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "PKCE code_challenge is required",
            )
        }
    };

    let method_str = q.code_challenge_method.as_deref().unwrap_or("");
    let method = match CodeChallengeMethod::parse(method_str) {
        Ok(m) => m,
        Err(e) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", &format!("{e}")),
    };

    let client_state = match q.state.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing state"),
    };

    let resource_uri = match q.resource.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "RFC 8707 resource indicator is required",
            )
        }
    };

    // RFC 8707 §2 binding. The broker only honors the configured
    // resource_uri (always) plus any explicit allowlist member. Any
    // other value is rejected as `invalid_target` so the broker
    // cannot be induced to participate in authorization flows for
    // resources it does not own. The same check applies to PAR-backed
    // requests because the stored params are projected into `q`
    // earlier in this function.
    if !is_resource_bound(resource_uri, cfg) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource not bound to this broker",
        );
    }

    // CIMD scope check: requested scope MUST be a subset of the
    // document's declared scope. Pre-registered clients delegate scope
    // validation to the upstream AS.
    if let Some(doc) = &cimd_doc {
        if let Some(req_scope) = q.scope.as_deref() {
            if !doc.allows_scope(req_scope) {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "requested scope is not a subset of CIMD document scope",
                );
            }
        }
    }

    // --- Optional CIMD → DCR translation ---
    //
    // When `dcr_translate_cimd_clients` is enabled, the broker swaps
    // the CIMD URL for an opaque server-side client_id obtained via
    // RFC 7591 DCR. The mapping is cached on a fingerprint of the
    // CIMD document content so repeat /authorize calls skip the
    // double round trip.
    let outbound_client_id =
        if let (Some(doc), true) = (cimd_doc.as_ref(), cfg.dcr_translate_cimd_clients) {
            match resolve_dcr_translation(&app, client_id, doc).await {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(error = %e, "CIMD → DCR translation failed");
                    return oauth_error(
                        StatusCode::BAD_GATEWAY,
                        "server_error",
                        &format!("CIMD translation failed: {e}"),
                    );
                }
            }
        } else {
            client_id.to_string()
        };

    // --- Persist session under broker-side state ---

    let upstream_state = mint_state();
    let session = Session {
        client_state: client_state.to_string(),
        redirect_uri: redirect_uri.to_string(),
        resource_uri: resource_uri.to_string(),
        code_challenge: code_challenge.to_string(),
        code_challenge_method: method.to_string(),
    };
    app.session_store.put(&upstream_state, session).await;

    // --- Build upstream redirect URL ---

    let callback_url = match url::Url::parse(&cfg.upstream_redirect_uri) {
        Ok(url)
            if matches!(url.scheme(), "https" | "http")
                && url.has_host()
                && url.fragment().is_none() =>
        {
            cfg.upstream_redirect_uri.clone()
        }
        _ => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "upstream_redirect_uri must be an absolute registered HTTP(S) URI",
            );
        }
    };
    let upstream = match build_upstream_url(
        &cfg.upstream_authorization_server_url,
        &outbound_client_id,
        &callback_url,
        code_challenge,
        method,
        &upstream_state,
        resource_uri,
        q.scope.as_deref(),
    ) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "failed to construct upstream authorize URL");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to construct upstream URL",
            );
        }
    };

    // --- 302 redirect ---

    let mut headers = HeaderMap::new();
    let value = match HeaderValue::from_str(&upstream) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "invalid Location header value");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "invalid upstream URL",
            );
        }
    };
    headers.insert(header::LOCATION, value);
    (StatusCode::FOUND, headers).into_response()
}

// --- Helpers ---

/// Returns `true` when `requested` is bound to this broker, meaning
/// it equals `config.resource_uri` or is a member of the configured
/// `config.resource_uri_allowlist`. Comparison is byte-exact; RFC
/// 8707 §2 mandates exact matching of resource indicators.
pub(crate) fn is_resource_bound(requested: &str, cfg: &crate::config::McpGatewayConfig) -> bool {
    if !cfg.resource_uri.is_empty() && requested == cfg.resource_uri {
        return true;
    }
    cfg.resource_uri_allowlist.iter().any(|r| r == requested)
}

/// Returns `Some(parsed_url)` when `client_id` is shaped as a CIMD
/// reference (an https URL); returns `None` otherwise. Pre-registered
/// opaque-string client_ids continue down the existing path.
fn detect_cimd_client_id(client_id: &str) -> Option<url::Url> {
    let parsed = url::Url::parse(client_id).ok()?;
    if parsed.scheme() == "https" {
        Some(parsed)
    } else {
        None
    }
}

/// Resolve a CIMD client through the broker's DCR translation cache.
/// Returns the upstream-assigned `client_id`. The cache is keyed by
/// the document's fingerprint, so a doc rewrite invalidates cleanly.
async fn resolve_dcr_translation(
    app: &AppState,
    cimd_url: &str,
    doc: &crate::cimd::ClientIdMetadataDocument,
) -> anyhow::Result<String> {
    let cache = app
        .cimd_to_dcr
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("CIMD → DCR cache not configured"))?;
    let dcr_endpoint = app
        .config
        .upstream_registration_endpoint_url
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "upstream_registration_endpoint_url must be set when dcr_translate_cimd_clients is true"
            )
        })?;
    // No ETag stream-through here yet; fingerprint by document content.
    let fp = crate::cimd_to_dcr::fingerprint(None, doc);
    if let Some(reg) = cache.get(cimd_url, &fp).await {
        return Ok(reg.registered_client_id);
    }
    // WOR-170: DCR upstream is credential-bearing; refuse redirects.
    let http = sbproxy_httpkit::token_bearing_outbound();
    let reg = crate::cimd_to_dcr::translate_cimd_to_dcr(doc, dcr_endpoint, &http).await?;
    cache.put(cimd_url, &fp, reg.clone()).await;
    Ok(reg.registered_client_id)
}

/// Mint a fresh, opaque, URL-safe `state` value for the upstream hop.
/// Uses 32 bytes of randomness (256 bits) base64url-encoded.
fn mint_state() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Append the upstream authorize parameters to the configured AS URL.
/// Uses a `BTreeMap` for deterministic ordering, which makes tests
/// readable without affecting protocol semantics.
#[allow(clippy::too_many_arguments)]
fn build_upstream_url(
    base: &str,
    client_id: &str,
    callback_path: &str,
    code_challenge: &str,
    method: CodeChallengeMethod,
    state: &str,
    resource: &str,
    scope: Option<&str>,
) -> Result<String, url::ParseError> {
    let mut url = url::Url::parse(base)?;
    let mut params: BTreeMap<&str, String> = BTreeMap::new();
    params.insert("client_id", client_id.to_string());
    params.insert("redirect_uri", callback_path.to_string());
    params.insert("response_type", "code".to_string());
    params.insert("code_challenge", code_challenge.to_string());
    params.insert("code_challenge_method", method.to_string());
    params.insert("state", state.to_string());
    params.insert("resource", resource.to_string());
    if let Some(s) = scope {
        params.insert("scope", s.to_string());
    }
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in &params {
            q.append_pair(k, v);
        }
    }
    Ok(url.to_string())
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpGatewayConfig;
    use crate::session::{InMemorySessionStore, SessionStore};
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn test_config() -> McpGatewayConfig {
        McpGatewayConfig {
            base_path: "/mcp/oauth".to_string(),
            upstream_authorization_server_url: "https://idp.example.com/oauth/authorize"
                .to_string(),
            upstream_redirect_uri: "https://broker.example/mcp/oauth/callback".to_string(),
            resource_uri: "https://mcp.example/api".to_string(),
            allowed_redirect_uris: vec!["https://client.example/cb".to_string()],
            session_ttl_secs: 600,
            ..McpGatewayConfig::default()
        }
    }

    fn build_app() -> (axum::Router, Arc<InMemorySessionStore>) {
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        let app = crate::router(Arc::new(test_config()), store.clone());
        (app, store)
    }

    async fn send(app: axum::Router, uri: &str) -> (StatusCode, HeaderMap, String) {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&body).to_string())
    }

    fn ok_uri() -> String {
        "/mcp/oauth/authorize?\
         client_id=cli\
         &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
         &response_type=code\
         &code_challenge=abc\
         &code_challenge_method=S256\
         &state=cli-state\
         &resource=https%3A%2F%2Fmcp.example%2Fapi"
            .to_string()
    }

    #[tokio::test]
    async fn happy_path_redirects_and_persists_session() {
        let (app, store) = build_app();
        let (status, headers, _body) = send(app, &ok_uri()).await;
        assert_eq!(status, StatusCode::FOUND);
        let loc = headers
            .get(header::LOCATION)
            .expect("missing Location")
            .to_str()
            .unwrap();
        assert!(loc.starts_with("https://idp.example.com/oauth/authorize?"));
        assert!(loc.contains("response_type=code"));
        assert!(loc.contains("code_challenge=abc"));
        assert!(loc.contains("code_challenge_method=S256"));
        assert!(loc.contains("resource=https%3A%2F%2Fmcp.example%2Fapi"));
        assert!(loc.contains("redirect_uri=https%3A%2F%2Fbroker.example%2Fmcp%2Foauth%2Fcallback"));
        // Broker minted its own state and stored a row under it.
        let parsed = url::Url::parse(loc).unwrap();
        let upstream_state = parsed
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .expect("state param missing from upstream URL");
        assert_ne!(upstream_state, "cli-state");
        let row = store.take(&upstream_state).await.expect("session missing");
        assert_eq!(row.client_state, "cli-state");
        assert_eq!(row.redirect_uri, "https://client.example/cb");
        assert_eq!(row.resource_uri, "https://mcp.example/api");
        assert_eq!(row.code_challenge, "abc");
        assert_eq!(row.code_challenge_method, "S256");
    }

    #[tokio::test]
    async fn rejects_missing_pkce() {
        let (app, _) = build_app();
        let uri = "/mcp/oauth/authorize?\
                   client_id=cli\
                   &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                   &response_type=code\
                   &code_challenge_method=S256\
                   &state=cli-state\
                   &resource=https%3A%2F%2Fmcp.example%2Fapi";
        let (status, _, body) = send(app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_request"));
        assert!(body.contains("code_challenge"));
    }

    #[tokio::test]
    async fn rejects_plain_pkce_method() {
        let (app, _) = build_app();
        let uri = "/mcp/oauth/authorize?\
                   client_id=cli\
                   &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                   &response_type=code\
                   &code_challenge=abc\
                   &code_challenge_method=plain\
                   &state=cli-state\
                   &resource=https%3A%2F%2Fmcp.example%2Fapi";
        let (status, _, body) = send(app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("plain"));
    }

    #[tokio::test]
    async fn rejects_unregistered_redirect_uri() {
        let (app, _) = build_app();
        let uri = "/mcp/oauth/authorize?\
                   client_id=cli\
                   &redirect_uri=https%3A%2F%2Fevil.example%2Fcb\
                   &response_type=code\
                   &code_challenge=abc\
                   &code_challenge_method=S256\
                   &state=cli-state\
                   &resource=https%3A%2F%2Fmcp.example%2Fapi";
        let (status, _, body) = send(app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("redirect_uri"));
    }

    #[tokio::test]
    async fn rejects_implicit_response_type() {
        let (app, _) = build_app();
        let uri = "/mcp/oauth/authorize?\
                   client_id=cli\
                   &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                   &response_type=token\
                   &code_challenge=abc\
                   &code_challenge_method=S256\
                   &state=cli-state\
                   &resource=https%3A%2F%2Fmcp.example%2Fapi";
        let (status, _, body) = send(app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("unsupported_response_type"));
    }

    #[tokio::test]
    async fn rejects_missing_resource() {
        let (app, _) = build_app();
        let uri = "/mcp/oauth/authorize?\
                   client_id=cli\
                   &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                   &response_type=code\
                   &code_challenge=abc\
                   &code_challenge_method=S256\
                   &state=cli-state";
        let (status, _, body) = send(app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("resource"));
    }

    #[tokio::test]
    async fn rejects_missing_state() {
        let (app, _) = build_app();
        let uri = "/mcp/oauth/authorize?\
                   client_id=cli\
                   &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                   &response_type=code\
                   &code_challenge=abc\
                   &code_challenge_method=S256\
                   &resource=https%3A%2F%2Fmcp.example%2Fapi";
        let (status, _, body) = send(app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("state"));
    }

    #[tokio::test]
    async fn rejects_missing_client_id() {
        let (app, _) = build_app();
        let uri = "/mcp/oauth/authorize?\
                   redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                   &response_type=code\
                   &code_challenge=abc\
                   &code_challenge_method=S256\
                   &state=cli-state\
                   &resource=https%3A%2F%2Fmcp.example%2Fapi";
        let (status, _, body) = send(app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("client_id"));
    }

    // --- WOR-41: RFC 8707 resource binding ---

    /// Builds an app whose config sets `resource_uri_allowlist` in
    /// addition to the default `resource_uri`. The PAR store is wired
    /// up so the allowlist + PAR cases can both run against the same
    /// router.
    fn build_app_with(
        cfg_mut: impl FnOnce(&mut McpGatewayConfig),
    ) -> (
        axum::Router,
        Arc<InMemorySessionStore>,
        Arc<dyn sbproxy_storage::EphemeralKv>,
    ) {
        let mut cfg = test_config();
        cfg_mut(&mut cfg);
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        let par_store: Arc<dyn sbproxy_storage::EphemeralKv> =
            Arc::new(crate::local_store::LocalStore::new());
        let app = crate::router_full_with_par(
            Arc::new(cfg),
            store.clone(),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(par_store.clone()),
        );
        (app, store, par_store)
    }

    /// Direct /authorize with `resource=config.resource_uri` succeeds.
    /// Locks in the happy path against the new is_resource_bound check.
    #[tokio::test]
    async fn accepts_resource_matching_resource_uri() {
        let (app, store) = build_app();
        let (status, headers, _body) = send(app, &ok_uri()).await;
        assert_eq!(status, StatusCode::FOUND);
        let loc = headers.get(header::LOCATION).unwrap().to_str().unwrap();
        let parsed = url::Url::parse(loc).unwrap();
        let upstream_state = parsed
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        let row = store.take(&upstream_state).await.expect("session missing");
        assert_eq!(row.resource_uri, "https://mcp.example/api");
    }

    /// Direct /authorize with a mismatched resource returns 400
    /// invalid_target per RFC 8707 §2.
    #[tokio::test]
    async fn rejects_resource_not_bound_to_broker() {
        let (app, _) = build_app();
        let uri = "/mcp/oauth/authorize?\
                   client_id=cli\
                   &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                   &response_type=code\
                   &code_challenge=abc\
                   &code_challenge_method=S256\
                   &state=cli-state\
                   &resource=https%3A%2F%2Fevil.example%2Fapi";
        let (status, _, body) = send(app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_target"), "body: {body}");
        assert!(body.contains("resource not bound"), "body: {body}");
    }

    /// PAR-backed /authorize: when the stored params carry a
    /// resource the broker does not own, /authorize MUST fail with
    /// invalid_target after replaying the params. PAR is not a
    /// bypass.
    #[tokio::test]
    async fn rejects_par_backed_resource_not_bound_to_broker() {
        let (app, _store, par_store) = build_app_with(|_| {});
        // Pre-seed the PAR store with a payload whose resource does
        // not match the broker's resource_uri.
        let params = crate::par::PushedAuthorizationParams {
            client_id: "cli".to_string(),
            redirect_uri: "https://client.example/cb".to_string(),
            response_type: "code".to_string(),
            code_challenge: "abc".to_string(),
            code_challenge_method: "S256".to_string(),
            state: Some("cli-state".to_string()),
            resource: Some("https://evil.example/api".to_string()),
            scope: None,
        };
        let request_uri = crate::par::mint_request_uri();
        par_store
            .put(
                &request_uri,
                bytes::Bytes::from(serde_json::to_vec(&params).unwrap()),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let encoded: String =
            url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect();
        let uri = format!("/mcp/oauth/authorize?request_uri={encoded}");
        let (status, _, body) = send(app, &uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_target"), "body: {body}");
    }

    /// PAR-backed /authorize: when the stored params carry the
    /// configured resource_uri, the request succeeds. Sister test to
    /// the rejection case above to keep the binding regression-tight.
    #[tokio::test]
    async fn accepts_par_backed_resource_matching_resource_uri() {
        let (app, _store, par_store) = build_app_with(|_| {});
        let params = crate::par::PushedAuthorizationParams {
            client_id: "cli".to_string(),
            redirect_uri: "https://client.example/cb".to_string(),
            response_type: "code".to_string(),
            code_challenge: "abc".to_string(),
            code_challenge_method: "S256".to_string(),
            state: Some("cli-state".to_string()),
            resource: Some("https://mcp.example/api".to_string()),
            scope: None,
        };
        let request_uri = crate::par::mint_request_uri();
        par_store
            .put(
                &request_uri,
                bytes::Bytes::from(serde_json::to_vec(&params).unwrap()),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let encoded: String =
            url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect();
        let uri = format!("/mcp/oauth/authorize?request_uri={encoded}");
        let (status, _, _body) = send(app, &uri).await;
        assert_eq!(status, StatusCode::FOUND);
    }

    /// With a non-empty `resource_uri_allowlist`, an allowlist member
    /// succeeds and the configured `resource_uri` still succeeds.
    #[tokio::test]
    async fn allowlist_member_resource_succeeds() {
        let (app, _, _) = build_app_with(|cfg| {
            cfg.resource_uri_allowlist = vec![
                "https://mcp.example/api/v2".to_string(),
                "https://mcp.example/admin".to_string(),
            ];
        });
        // Allowlist member.
        let uri = "/mcp/oauth/authorize?\
                   client_id=cli\
                   &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                   &response_type=code\
                   &code_challenge=abc\
                   &code_challenge_method=S256\
                   &state=cli-state\
                   &resource=https%3A%2F%2Fmcp.example%2Fapi%2Fv2";
        let (status, _, body) = send(app, uri).await;
        assert_eq!(status, StatusCode::FOUND, "body: {body}");
    }

    /// With a non-empty `resource_uri_allowlist`, the original
    /// `resource_uri` is still accepted alongside the allowlist
    /// entries.
    #[tokio::test]
    async fn allowlist_does_not_replace_resource_uri() {
        let (app, _, _) = build_app_with(|cfg| {
            cfg.resource_uri_allowlist = vec!["https://mcp.example/api/v2".to_string()];
        });
        let (status, _, _) = send(app, &ok_uri()).await;
        assert_eq!(status, StatusCode::FOUND);
    }

    /// With a non-empty `resource_uri_allowlist`, a value that is
    /// neither the configured `resource_uri` nor on the allowlist is
    /// rejected with invalid_target.
    #[tokio::test]
    async fn allowlist_non_member_resource_fails() {
        let (app, _, _) = build_app_with(|cfg| {
            cfg.resource_uri_allowlist = vec!["https://mcp.example/api/v2".to_string()];
        });
        let uri = "/mcp/oauth/authorize?\
                   client_id=cli\
                   &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                   &response_type=code\
                   &code_challenge=abc\
                   &code_challenge_method=S256\
                   &state=cli-state\
                   &resource=https%3A%2F%2Fother.example%2Fapi";
        let (status, _, body) = send(app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_target"), "body: {body}");
    }
}
