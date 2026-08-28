// /callback handler for the MCP OAuth 2.1 broker.
//
// Wave 4B.1 keeps the callback path minimal: look up the in-flight
// session by `state`, optionally validate the RFC 9207 `iss` param,
// and 302-redirect the user agent back to the original client
// `redirect_uri` carrying either `code+state` (success) or the
// upstream `error` payload (failure).
//
// The actual code-for-token exchange happens in 4B.2's /token
// handler. This slice intentionally does not call the upstream
// /token endpoint; it just relays the authorization code back to
// the client unchanged.

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::AppState;

// --- Query model ---

/// Inbound /callback query string. The exact set of keys depends on
/// whether the upstream AS succeeded or failed.
#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub iss: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
}

// --- Helpers ---

/// Render an OAuth error JSON payload. Used only when the broker
/// cannot safely redirect (state lookup failed, so we do not know
/// where to send the user).
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

/// Build a `Location:` redirect response back to the client's
/// `redirect_uri` with the supplied query parameters appended.
/// Existing query parameters on the `redirect_uri` are preserved.
fn redirect_to_client(client_uri: &str, params: &BTreeMap<&str, String>) -> Response {
    let mut url = match url::Url::parse(client_uri) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "client redirect_uri failed to parse");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "client redirect URI is malformed",
            );
        }
    };
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in params {
            q.append_pair(k, v);
        }
    }
    let mut headers = HeaderMap::new();
    let value = match HeaderValue::from_str(url.as_str()) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "callback Location value failed to encode");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "callback URL was not a valid header value",
            );
        }
    };
    headers.insert(header::LOCATION, value);
    (StatusCode::FOUND, headers).into_response()
}

// --- Handler ---

/// `GET {base_path}/callback` handler.
pub(crate) async fn callback(
    State(app): State<AppState>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    // --- Look up the session ---

    let upstream_state = match q.state.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return oauth_error(StatusCode::BAD_REQUEST, "invalid_state", "missing state"),
    };

    let session = match app.session_store.take(upstream_state).await {
        Some(s) => s,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_state",
                "no in-flight session matched the supplied state",
            )
        }
    };

    // --- RFC 9207 issuer check ---
    //
    // If the upstream AS supplied `iss`, it MUST equal the issuer in
    // its RFC 8414 metadata. The authorization endpoint is not an
    // issuer identifier and may legitimately live at a different URL.
    if let Some(iss) = q.iss.as_deref() {
        let Some(metadata) = app.as_metadata.as_ref() else {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "AS metadata is required to validate callback issuer",
            );
        };
        let expected = match metadata
            .fetch_or_cached(
                app.config.metadata_refresh_secs,
                app.config.max_metadata_staleness_secs,
            )
            .await
        {
            Ok(document) => document.issuer.clone(),
            Err(e) => {
                tracing::warn!(error = %e, "AS metadata unavailable for callback issuer check");
                return oauth_error(
                    StatusCode::BAD_GATEWAY,
                    "server_error",
                    "AS metadata unavailable for callback issuer validation",
                );
            }
        };
        if iss != expected {
            tracing::warn!(
                expected = %expected,
                actual = %iss,
                "RFC 9207 iss mismatch on /callback"
            );
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "issuer mismatch",
            );
        }
    }

    // --- RFC 9207 issuer parameter on the response back to client ---
    //
    // The broker is the AS as far as the client is concerned, so we
    // emit our own issuer string. This lets clients running multiple
    // AS connections defend against cross-AS response replay (the
    // mix-up attack class the RFC was written to close). Empty
    // issuer (when MCP_GATEWAY_BASE_URL is unset) is omitted rather
    // than sent as an empty value.
    let broker_iss = crate::well_known::broker_issuer(&app.config);

    // --- Forward upstream errors to the client unchanged ---

    if let Some(error) = q.error.as_deref() {
        let mut params: BTreeMap<&str, String> = BTreeMap::new();
        params.insert("error", error.to_string());
        if let Some(d) = q.error_description.as_deref() {
            params.insert("error_description", d.to_string());
        }
        if let Some(u) = q.error_uri.as_deref() {
            params.insert("error_uri", u.to_string());
        }
        params.insert("state", session.client_state.clone());
        if !broker_iss.is_empty() {
            params.insert("iss", broker_iss.clone());
        }
        return redirect_to_client(&session.redirect_uri, &params);
    }

    // --- Forward the authorization code ---

    let code = match q.code.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing code on success callback",
            )
        }
    };

    let mut params: BTreeMap<&str, String> = BTreeMap::new();
    params.insert("code", code);
    params.insert("state", session.client_state.clone());
    if !broker_iss.is_empty() {
        params.insert("iss", broker_iss);
    }
    redirect_to_client(&session.redirect_uri, &params)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpGatewayConfig;
    use crate::session::{InMemorySessionStore, Session, SessionStore};
    use axum::body::Body;
    use http::Request;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn test_config() -> McpGatewayConfig {
        McpGatewayConfig {
            base_path: "/mcp/oauth".to_string(),
            upstream_authorization_server_url: "https://idp.example.com/oauth/authorize"
                .to_string(),
            upstream_metadata_url: Some(
                "https://idp.example.com/.well-known/oauth-authorization-server".to_string(),
            ),
            resource_uri: "https://mcp.example/api".to_string(),
            allowed_redirect_uris: vec!["https://client.example/cb".to_string()],
            session_ttl_secs: 600,
            ..McpGatewayConfig::default()
        }
    }

    fn fixture_session() -> Session {
        Session {
            client_state: "cli-state".to_string(),
            redirect_uri: "https://client.example/cb".to_string(),
            resource_uri: "https://mcp.example/api".to_string(),
            code_challenge: "abc".to_string(),
            code_challenge_method: "S256".to_string(),
        }
    }

    async fn build_app_with_session(
        upstream_state: &str,
    ) -> (axum::Router, Arc<InMemorySessionStore>) {
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        store.put(upstream_state, fixture_session()).await.unwrap();
        let cfg = test_config();
        let metadata = Arc::new(crate::as_metadata::AsMetadataCache::new(
            sbproxy_httpkit::default_outbound(),
            cfg.upstream_metadata_url.clone().unwrap(),
        ));
        metadata
            .seed_metadata(
                crate::as_metadata::AuthorizationServerMetadata {
                    issuer: "https://idp.example.com".to_string(),
                    ..Default::default()
                },
                std::time::Instant::now(),
            )
            .await;
        let app = crate::router_full_with_par(
            Arc::new(cfg),
            store.clone(),
            Some(metadata),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        (app, store)
    }

    async fn send(app: axum::Router, uri: &str) -> (StatusCode, HeaderMap) {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        (resp.status(), resp.headers().clone())
    }

    #[tokio::test]
    async fn unknown_state_is_rejected() {
        let (app, _) = build_app_with_session("known").await;
        let (status, _) = send(app, "/mcp/oauth/callback?state=ghost&code=auth-code-123").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_state_is_rejected() {
        let (app, _) = build_app_with_session("known").await;
        let (status, _) = send(app, "/mcp/oauth/callback?code=auth-code-123").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn iss_mismatch_is_rejected() {
        let (app, _) = build_app_with_session("known").await;
        let (status, _) = send(
            app,
            "/mcp/oauth/callback?state=known&code=auth-code-123\
             &iss=https%3A%2F%2Fattacker.example",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn iss_match_is_accepted() {
        let (app, _) = build_app_with_session("known").await;
        let (status, headers) = send(
            app,
            "/mcp/oauth/callback?state=known&code=auth-code-123\
             &iss=https%3A%2F%2Fidp.example.com",
        )
        .await;
        assert_eq!(status, StatusCode::FOUND);
        let loc = headers.get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(loc.starts_with("https://client.example/cb?"));
        assert!(loc.contains("code=auth-code-123"));
        assert!(loc.contains("state=cli-state"));
    }

    #[tokio::test]
    async fn upstream_error_is_forwarded() {
        let (app, _) = build_app_with_session("known").await;
        let (status, headers) = send(
            app,
            "/mcp/oauth/callback?state=known&error=access_denied\
             &error_description=user%20said%20no",
        )
        .await;
        assert_eq!(status, StatusCode::FOUND);
        let loc = headers.get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(loc.starts_with("https://client.example/cb?"));
        assert!(loc.contains("error=access_denied"));
        assert!(loc.contains("error_description=user"));
        // The client receives its original state, not the broker's.
        assert!(loc.contains("state=cli-state"));
    }

    #[tokio::test]
    async fn success_redirects_with_code_and_client_state() {
        let (app, _) = build_app_with_session("known").await;
        let (status, headers) = send(app, "/mcp/oauth/callback?state=known&code=the-code").await;
        assert_eq!(status, StatusCode::FOUND);
        let loc = headers.get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(loc.starts_with("https://client.example/cb?"));
        assert!(loc.contains("code=the-code"));
        assert!(loc.contains("state=cli-state"));
    }

    #[tokio::test]
    async fn state_is_consumed_after_callback() {
        let (app, store) = build_app_with_session("known").await;
        // First callback succeeds.
        let (status, _) = send(app.clone(), "/mcp/oauth/callback?state=known&code=c1").await;
        assert_eq!(status, StatusCode::FOUND);
        // Store no longer holds the row.
        assert!(store.take("known").await.is_none());
        // Second callback with the same state is rejected (single-use).
        let (status, _) = send(app, "/mcp/oauth/callback?state=known&code=c1").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn success_without_code_is_rejected() {
        let (app, _) = build_app_with_session("known").await;
        let (status, _) = send(app, "/mcp/oauth/callback?state=known").await;
        // Note: state is consumed even on this rejection. That is
        // acceptable because the client can simply restart the flow.
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
