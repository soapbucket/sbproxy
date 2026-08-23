// /register handler for the MCP OAuth 2.1 broker.
//
// Implements RFC 7591 Dynamic Client Registration. The broker
// validates inbound metadata, optionally translates it into an
// upstream-specific shape (currently only Auth0 v2 is supported in
// addition to the RFC 7591 default), and forwards to the upstream
// registration endpoint configured in `upstream_registration_endpoint_url`.
//
// When `upstream_registration_endpoint_url` is `None`, the handler
// returns HTTP 501 with `error: registration_not_supported`.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::config::default_accepted_client_auth_methods;
use crate::AppState;

// --- Constants ---

/// Implicit grant is forbidden by OAuth 2.1; we drop it from any
/// inbound `grant_types` list.
const FORBIDDEN_GRANTS: &[&str] = &["password", "implicit"];
const MAX_DCR_RESPONSE_BYTES: usize = 64 * 1024;

// --- Helpers ---

/// Render a JSON OAuth-style error.
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

/// Filter `grant_types`, dropping forbidden values. Returns the
/// filtered list and a vector of dropped values for log context.
fn filter_grant_types(input: Option<&serde_json::Value>) -> (Vec<String>, Vec<String>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    if let Some(serde_json::Value::Array(arr)) = input {
        for item in arr {
            if let Some(s) = item.as_str() {
                if FORBIDDEN_GRANTS.contains(&s) {
                    dropped.push(s.to_string());
                } else {
                    kept.push(s.to_string());
                }
            }
        }
    }
    (kept, dropped)
}

/// Validate the inbound RFC 7591 metadata against broker policy.
fn validate(
    body: &serde_json::Value,
    accepted_auth_methods: &[String],
) -> Result<(), (StatusCode, String, String)> {
    // redirect_uris must be present and non-empty.
    let redirect_uris = body
        .get("redirect_uris")
        .and_then(|v| v.as_array())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri".to_string(),
            "redirect_uris is required".to_string(),
        ))?;
    if redirect_uris.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri".to_string(),
            "redirect_uris must be non-empty".to_string(),
        ));
    }
    for r in redirect_uris {
        if r.as_str().map(|s| s.is_empty()).unwrap_or(true) {
            return Err((
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri".to_string(),
                "redirect_uris contains an empty value".to_string(),
            ));
        }
    }

    // token_endpoint_auth_method, if present, must be in the accepted set.
    if let Some(m) = body
        .get("token_endpoint_auth_method")
        .and_then(|v| v.as_str())
    {
        if !accepted_auth_methods.iter().any(|a| a == m) {
            return Err((
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata".to_string(),
                format!("token_endpoint_auth_method {m:?} not accepted"),
            ));
        }
    }

    Ok(())
}

/// Translate RFC 7591 metadata into the Auth0 v2 management API
/// shape. Field renames per Auth0 docs:
///   * `redirect_uris` → `callbacks`
///   * `client_name` → `name`
///   * `token_endpoint_auth_method` → `token_endpoint_auth_method` (no
///     rename, but we map the values: `client_secret_basic` ⇒
///     `client_secret_basic` is left as-is; `none` becomes
///     `none`).
fn map_to_auth0(body: &serde_json::Value) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    let in_obj = match body.as_object() {
        Some(o) => o,
        None => return body.clone(),
    };
    for (k, v) in in_obj {
        match k.as_str() {
            "redirect_uris" => {
                out.insert("callbacks".to_string(), v.clone());
            }
            "client_name" => {
                out.insert("name".to_string(), v.clone());
            }
            // Pass everything else through verbatim.
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    serde_json::Value::Object(out)
}

// --- Handler ---

/// `POST {base_path}/register` handler.
pub async fn register(
    State(app): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let cfg = &app.config;

    let upstream_url = match cfg.upstream_registration_endpoint_url.as_deref() {
        Some(u) if !u.is_empty() => u,
        _ => {
            return (
                StatusCode::NOT_IMPLEMENTED,
                Json(serde_json::json!({
                    "error": "registration_not_supported",
                    "error_description": "dynamic client registration is disabled in this deployment",
                })),
            )
                .into_response();
        }
    };

    let accepted = if cfg.accepted_client_auth_methods.is_empty() {
        default_accepted_client_auth_methods()
    } else {
        cfg.accepted_client_auth_methods.clone()
    };

    if let Err((status, error, description)) = validate(&body, &accepted) {
        return oauth_error(status, &error, &description);
    }

    // Filter grant_types to drop password / implicit.
    let (kept_grants, dropped_grants) = filter_grant_types(body.get("grant_types"));
    if !dropped_grants.is_empty() {
        tracing::warn!(
            dropped = ?dropped_grants,
            "dropping forbidden grant_types from /register payload"
        );
    }
    let mut filtered = body.clone();
    if body.get("grant_types").is_some() {
        if let Some(obj) = filtered.as_object_mut() {
            obj.insert(
                "grant_types".to_string(),
                serde_json::Value::Array(
                    kept_grants
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    }

    // Apply the upstream-shape mapping.
    let upstream_payload = match cfg.dcr_upstream_shape.as_deref() {
        Some("auth0") => map_to_auth0(&filtered),
        // RFC 7591 is the default; "rfc7591" is also accepted.
        _ => filtered,
    };

    // Forward to the upstream.
    // WOR-170: DCR call may carry an initial-access-token bearer; use
    // the token-bearing client so a 302 cannot leak it cross-host.
    let http = sbproxy_httpkit::token_bearing_outbound();
    let resp = match http
        .post(upstream_url)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(upstream_payload.to_string())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                error = %sbproxy_httpkit::request_error_summary(&e),
                "upstream /register call failed"
            );
            return oauth_error(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "upstream registration endpoint unreachable",
            );
        }
    };

    let status = resp.status();
    let body_bytes = match crate::remote_body::bounded_response_body(
        resp,
        MAX_DCR_RESPONSE_BYTES,
        "upstream registration",
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                error = %e,
                "upstream /register body read failed"
            );
            return oauth_error(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "upstream registration response unreadable",
            );
        }
    };

    if !status.is_success() {
        tracing::warn!(
            upstream_status = %status,
            "upstream /register rejected request; response body suppressed"
        );
        return oauth_error(
            axum::http::StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            "invalid_client_metadata",
            "upstream registration rejected request",
        );
    }

    Response::builder()
        .status(
            axum::http::StatusCode::from_u16(status.as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        )
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/json;charset=UTF-8",
        )
        .body(axum::body::Body::from(body_bytes))
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to assemble register response");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "response assembly failed",
            )
        })
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpGatewayConfig;
    use crate::session::InMemorySessionStore;
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    async fn response_server(status: &str, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_string();
        let body = body.to_string();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{address}/register")
    }

    fn cfg_with_upstream(url: Option<&str>, shape: Option<&str>) -> McpGatewayConfig {
        // Default-driven fixture so newly-added McpGatewayConfig
        // fields (Wave 4D.2 device-code + token-exchange) inherit
        // sensible defaults without forcing every test file to enumerate
        // the full struct.
        let _ = default_accepted_client_auth_methods; // kept for symmetry with neighbors
        McpGatewayConfig {
            upstream_authorization_server_url: "https://idp.example.com/oauth/authorize"
                .to_string(),
            resource_uri: "https://mcp.example/api".to_string(),
            allowed_redirect_uris: vec!["https://client.example/cb".to_string()],
            upstream_token_endpoint_url: "http://127.0.0.1:1/token".to_string(),
            upstream_registration_endpoint_url: url.map(|s| s.to_string()),
            dcr_upstream_shape: shape.map(|s| s.to_string()),
            ..McpGatewayConfig::default()
        }
    }

    fn build_app(cfg: McpGatewayConfig) -> Router {
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        crate::router(Arc::new(cfg), store)
    }

    async fn post_json(app: Router, uri: &str, body: serde_json::Value) -> (StatusCode, String) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    #[tokio::test]
    async fn registration_disabled_returns_501() {
        let app = build_app(cfg_with_upstream(None, None));
        let (status, body) = post_json(
            app,
            "/mcp/oauth/register",
            serde_json::json!({
                "redirect_uris": ["https://client.example/cb"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert!(body.contains("registration_not_supported"));
    }

    #[tokio::test]
    async fn empty_redirect_uris_rejected() {
        let app = build_app(cfg_with_upstream(Some("http://127.0.0.1:1/r"), None));
        let (status, body) = post_json(
            app,
            "/mcp/oauth/register",
            serde_json::json!({
                "redirect_uris": [],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_redirect_uri"));
    }

    #[tokio::test]
    async fn missing_redirect_uris_rejected() {
        let app = build_app(cfg_with_upstream(Some("http://127.0.0.1:1/r"), None));
        let (status, body) = post_json(
            app,
            "/mcp/oauth/register",
            serde_json::json!({
                "client_name": "no-uris-here",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("redirect_uris"));
    }

    #[tokio::test]
    async fn unaccepted_token_endpoint_auth_method_rejected() {
        let mut cfg = cfg_with_upstream(Some("http://127.0.0.1:1/r"), None);
        cfg.accepted_client_auth_methods = vec!["client_secret_basic".to_string()];
        let app = build_app(cfg);
        let (status, body) = post_json(
            app,
            "/mcp/oauth/register",
            serde_json::json!({
                "redirect_uris": ["https://client.example/cb"],
                "token_endpoint_auth_method": "private_key_jwt",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_client_metadata"));
    }

    #[tokio::test]
    async fn rfc7591_default_passes_through_unmodified_grants_when_safe() {
        // Forward to a closed port so we exercise the validate +
        // upstream-error path without a real AS.
        let app = build_app(cfg_with_upstream(Some("http://127.0.0.1:1/r"), None));
        let (status, _body) = post_json(
            app,
            "/mcp/oauth/register",
            serde_json::json!({
                "redirect_uris": ["https://client.example/cb"],
                "grant_types": ["authorization_code", "refresh_token"],
            }),
        )
        .await;
        // Validation succeeds; the upstream call fails closed at the
        // network layer, mapped to 502.
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn upstream_registration_error_body_is_not_reflected_to_the_client() {
        let upstream = response_server(
            "400 Bad Request",
            "{\"client_secret\":\"REGISTER-SECRET-SENTINEL\"}\nInjected-Header: yes",
        )
        .await;
        let app = build_app(cfg_with_upstream(Some(&upstream), None));
        let (status, body) = post_json(
            app,
            "/mcp/oauth/register",
            serde_json::json!({
                "redirect_uris": ["https://client.example/cb"],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!body.contains("REGISTER-SECRET-SENTINEL"), "{body}");
        assert!(!body.contains("Injected-Header"), "{body}");
    }

    #[test]
    fn filter_grant_types_drops_password_and_implicit() {
        let input = serde_json::json!([
            "authorization_code",
            "implicit",
            "password",
            "refresh_token"
        ]);
        let (kept, dropped) = filter_grant_types(Some(&input));
        assert_eq!(kept, vec!["authorization_code", "refresh_token"]);
        assert_eq!(dropped, vec!["implicit", "password"]);
    }

    #[test]
    fn map_to_auth0_renames_known_fields() {
        let input = serde_json::json!({
            "redirect_uris": ["https://client.example/cb"],
            "client_name": "My App",
            "grant_types": ["authorization_code"],
        });
        let out = map_to_auth0(&input);
        let obj = out.as_object().unwrap();
        assert!(obj.contains_key("callbacks"), "callbacks rename missing");
        assert!(obj.contains_key("name"), "name rename missing");
        assert!(!obj.contains_key("redirect_uris"));
        assert!(!obj.contains_key("client_name"));
        // Pass-through fields preserved.
        assert!(obj.contains_key("grant_types"));
    }

    #[test]
    fn map_to_auth0_passthrough_when_not_object() {
        let input = serde_json::json!("not-an-object");
        let out = map_to_auth0(&input);
        assert_eq!(out, input);
    }

    #[test]
    fn validate_rejects_redirect_uri_with_empty_string_entry() {
        let body = serde_json::json!({
            "redirect_uris": [""],
        });
        let result = validate(&body, &default_accepted_client_auth_methods());
        assert!(result.is_err());
    }

    #[test]
    fn validate_accepts_minimal_payload() {
        let body = serde_json::json!({
            "redirect_uris": ["https://client.example/cb"],
        });
        let result = validate(&body, &default_accepted_client_auth_methods());
        assert!(result.is_ok());
    }

    #[test]
    fn validate_accepts_token_endpoint_auth_method_when_in_set() {
        let body = serde_json::json!({
            "redirect_uris": ["https://client.example/cb"],
            "token_endpoint_auth_method": "client_secret_post",
        });
        let result = validate(&body, &default_accepted_client_auth_methods());
        assert!(result.is_ok());
    }
}
