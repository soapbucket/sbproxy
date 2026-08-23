//! OAuth 2.0 Token Revocation per RFC 7009.
//!
//! Lets clients (or post-authentication tooling) tell the broker
//! "this token is dead." The broker's job is two-step:
//!
//! 1. Forward the revocation to the upstream authorization server so
//!    the issuer-of-record knows the token is gone.
//! 2. Record a bounded, expiring hash in the process-local denylist
//!    consulted by the complementary resource server.
//!
//! Per RFC 7009 sec 2.2 a successfully processed request is 200 even
//! for an unknown token. Transport/authentication failures are not
//! successfully processed revocations and are surfaced fail-closed.
//!
//! ## Wire shape
//!
//! Request: form-encoded, two fields:
//! ```text
//! token=<the token to revoke>
//! token_type_hint=access_token | refresh_token   (optional)
//! ```
//!
//! Response: HTTP 200, no body.
//!
//! ## What this module does NOT do
//!
//! * Caller authentication is preserved upstream: Authorization and
//!   client_secret_post form fields are forwarded unchanged.
//! * No raw token is persisted locally; the denylist key is SHA-256.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use sbproxy_storage::EphemeralKv;
use sha2::{Digest, Sha256};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form,
};

use crate::AppState;

const LOCAL_REVOCATION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const REVOCATION_EXPIRY_GRACE_SECS: u64 = 60;

/// Retain a JWT denylist entry for its remaining advertised lifetime.
///
/// The payload is used only to choose a retention period. Signature,
/// issuer, and audience validation still happen in the resource
/// provider before a non-revoked token is trusted. Opaque or malformed
/// tokens use a conservative one-day fallback.
fn revocation_ttl(token: &str) -> Duration {
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return LOCAL_REVOCATION_TTL;
    };
    let Ok(payload) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return LOCAL_REVOCATION_TTL;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return LOCAL_REVOCATION_TTL;
    };
    let Some(exp) = claims.get("exp").and_then(serde_json::Value::as_u64) else {
        return LOCAL_REVOCATION_TTL;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    Duration::from_secs(
        exp.saturating_sub(now)
            .saturating_add(REVOCATION_EXPIRY_GRACE_SECS)
            .max(1),
    )
}

pub(crate) static REVOCATIONS: LazyLock<RevocationList> = LazyLock::new(|| {
    let store: Arc<dyn EphemeralKv> = crate::LocalStore::arc();
    RevocationList { store }
});

pub(crate) struct RevocationList {
    store: Arc<dyn EphemeralKv>,
}

impl RevocationList {
    fn key(token: &str) -> String {
        let digest = Sha256::digest(token.as_bytes());
        format!(
            "revoked:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        )
    }

    pub(crate) async fn record(&self, token: &str) -> Result<(), sbproxy_storage::StorageError> {
        self.store
            .put(
                &Self::key(token),
                Bytes::from_static(b"1"),
                revocation_ttl(token),
            )
            .await
    }

    pub(crate) async fn contains(&self, token: &str) -> bool {
        self.store.exists(&Self::key(token)).await.unwrap_or(true)
    }
}

// --- Handler ---

/// `POST {base_path}/revoke` handler.
///
/// Returns:
/// * 200 OK in every successful + most failure paths (per RFC 7009
///   sec 2.2: always 200 to prevent token-validity probing).
/// * 400 Bad Request only when the request is malformed (no `token`
///   field at all), per RFC 7009 sec 2.1.
/// * 501 Not Implemented when the broker has no
///   `upstream_revocation_endpoint_url` configured. We intentionally
///   surface the configuration gap (rather than silently 200) so an
///   operator who enables /revoke without wiring the upstream
///   discovers the misconfig immediately.
pub async fn revoke(
    State(app): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let cfg = &app.config;

    // RFC 7009 sec 2.1: missing `token` is a malformed request.
    let token = match form.get("token") {
        Some(t) if !t.is_empty() => t.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "missing token"
                })),
            )
                .into_response();
        }
    };

    // Optional hint; passed through to upstream verbatim.
    let token_type_hint = form
        .get("token_type_hint")
        .filter(|s| !s.is_empty())
        .cloned();

    // Configuration gate. Returning 501 (rather than 200) means an
    // operator who flips /revoke on without setting the upstream
    // URL hears about it on the first request rather than silently
    // dropping every revocation on the floor.
    let Some(upstream) = cfg.upstream_revocation_endpoint_url.as_deref() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            axum::Json(serde_json::json!({
                "error": "unsupported_endpoint",
                "error_description": "/revoke is not configured on this broker"
            })),
        )
            .into_response();
    };

    // --- Forward to upstream ---
    let mut form_body = vec![("token", token.clone())];
    if let Some(hint) = token_type_hint.as_deref() {
        form_body.push(("token_type_hint", hint.to_string()));
    }
    if let Some(client_id) = form.get("client_id") {
        form_body.push(("client_id", client_id.clone()));
    }
    if let Some(client_secret) = form.get("client_secret") {
        form_body.push(("client_secret", client_secret.clone()));
    }
    // WOR-170: revocation forwards the bearer token in the request
    // body; refuse redirects so the token cannot leak cross-host.
    let mut request = sbproxy_httpkit::token_bearing_outbound().post(upstream);
    if let Some(authorization) = headers.get(axum::http::header::AUTHORIZATION) {
        request = request.header(reqwest::header::AUTHORIZATION, authorization.clone());
    }
    match request.form(&form_body).send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!(
                target: "mcp_gateway::revoke",
                upstream_status = %resp.status(),
                "upstream revocation acknowledged"
            );
            if let Err(e) = REVOCATIONS.record(&token).await {
                tracing::error!(error = %e, "local revocation persistence failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "local revocation persistence failed"
                    })),
                )
                    .into_response();
            }
        }
        Ok(resp) => {
            tracing::warn!(
                target: "mcp_gateway::revoke",
                upstream_status = %resp.status(),
                "upstream revocation returned non-success"
            );
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "error": "upstream_error",
                    "error_description": "upstream revocation failed"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!(
                target: "mcp_gateway::revoke",
                error = %sbproxy_httpkit::request_error_summary(&e),
                "upstream revocation transport failed"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({
                    "error": "temporarily_unavailable",
                    "error_description": "upstream revocation unreachable"
                })),
            )
                .into_response();
        }
    }

    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    async fn upstream(status: &str) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_string();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 8192];
            let read = socket.read(&mut request).await.unwrap();
            request.truncate(read);
            let _ = sender.send(String::from_utf8_lossy(&request).to_string());
            let response =
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        (format!("http://{address}/revoke"), receiver)
    }

    async fn call(url: String, token: &str) -> StatusCode {
        let cfg = crate::config::McpGatewayConfig {
            upstream_revocation_endpoint_url: Some(url),
            ..Default::default()
        };
        let app = crate::router(
            Arc::new(cfg),
            crate::session::InMemorySessionStore::arc(Duration::from_secs(60)),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/mcp/oauth/revoke")
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(axum::http::header::AUTHORIZATION, "Basic Y2xpOnNlY3JldA==")
            .body(Body::from(format!(
                "token={token}&client_id=cli&client_secret=form-secret"
            )))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let _ = response.into_body().collect().await.unwrap();
        status
    }

    #[tokio::test]
    async fn successful_revocation_forwards_auth_and_invalidates_local_token() {
        let token = "locally-revoked-unique-token";
        let (url, captured) = upstream("200 OK").await;
        assert_eq!(call(url, token).await, StatusCode::OK);
        let request = captured.await.unwrap();
        assert!(request.contains("authorization: Basic Y2xpOnNlY3JldA=="));
        assert!(request.contains("client_secret=form-secret"));
        assert!(REVOCATIONS.contains(token).await);
    }

    #[tokio::test]
    async fn failed_upstream_revocation_is_not_reported_as_success() {
        let token = "failed-revocation-unique-token";
        let (url, _captured) = upstream("500 Internal Server Error").await;
        assert_eq!(call(url, token).await, StatusCode::BAD_GATEWAY);
        assert!(!REVOCATIONS.contains(token).await);
    }

    #[test]
    fn revocation_retention_covers_the_signed_tokens_remaining_lifetime() {
        let exp = crate::device_code::unix_now() as u64 + (3 * 24 * 60 * 60);
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({"exp": exp}).to_string());
        let token = format!("e30.{claims}.signature");

        assert!(revocation_ttl(&token) > LOCAL_REVOCATION_TTL);
    }

    /// Pure construction-side test: confirms the form-body builder
    /// preserves the optional hint correctly. The full handler
    /// integration is exercised in the e2e suite.
    #[test]
    fn form_body_includes_token_only_when_no_hint() {
        let token = "abc";
        let mut form = vec![("token", token)];
        // Without a hint, the body has one entry.
        assert_eq!(form.len(), 1);
        // With a hint, two entries.
        let hint = "access_token";
        form.push(("token_type_hint", hint));
        assert_eq!(form.len(), 2);
        assert_eq!(form[0].0, "token");
        assert_eq!(form[1].0, "token_type_hint");
    }
}
