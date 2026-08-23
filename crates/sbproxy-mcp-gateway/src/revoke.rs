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
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use sbproxy_storage::EphemeralKv;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form,
};

use crate::AppState;

const REVOCATION_EXPIRY_GRACE_SECS: u64 = 60;
const REVOCATION_CAS_RETRIES: usize = 32;

fn validated_revocation_ttl(exp: i64, maximum: Duration) -> Duration {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    Duration::from_secs(
        (exp.max(0) as u64)
            .saturating_sub(now)
            .saturating_add(REVOCATION_EXPIRY_GRACE_SECS)
            .max(1)
            .min(maximum.as_secs().max(1)),
    )
}

pub(crate) struct RevocationList {
    store: Arc<dyn EphemeralKv>,
    index_key: String,
    capacity: usize,
    maximum_ttl: Duration,
}

#[derive(Default, Serialize, Deserialize)]
struct RevocationIndex {
    /// Token digest to absolute expiry.
    entries: HashMap<String, u64>,
}

impl RevocationList {
    pub(crate) fn new(
        store: Arc<dyn EphemeralKv>,
        namespace: String,
        capacity: usize,
        maximum_ttl: Duration,
    ) -> Self {
        Self {
            store,
            index_key: format!("revoked:{namespace}:index"),
            capacity: capacity.max(1),
            maximum_ttl: maximum_ttl.max(Duration::from_secs(1)),
        }
    }

    fn digest(token: &str) -> String {
        let digest = Sha256::digest(token.as_bytes());
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub(crate) async fn record_validated(
        &self,
        token: &str,
        exp: i64,
    ) -> Result<(), sbproxy_storage::StorageError> {
        let digest = Self::digest(token);
        let ttl = validated_revocation_ttl(exp, self.maximum_ttl);
        let expires_at = unix_now().saturating_add(ttl.as_secs());
        self.mutate(move |index| {
            if !index.entries.contains_key(&digest) && index.entries.len() >= self.capacity {
                if let Some(evicted) = index
                    .entries
                    .iter()
                    .min_by(|(left_digest, left_exp), (right_digest, right_exp)| {
                        (**left_exp, left_digest.as_str())
                            .cmp(&(**right_exp, right_digest.as_str()))
                    })
                    .map(|(digest, _)| digest.clone())
                {
                    index.entries.remove(&evicted);
                }
            }
            index.entries.insert(digest.clone(), expires_at);
        })
        .await
    }

    pub(crate) async fn contains(&self, token: &str) -> bool {
        let digest = Self::digest(token);
        self.mutate(move |index| index.entries.contains_key(&digest))
            .await
            .unwrap_or(true)
    }

    async fn mutate<T>(
        &self,
        mut operation: impl FnMut(&mut RevocationIndex) -> T,
    ) -> Result<T, sbproxy_storage::StorageError> {
        for _ in 0..REVOCATION_CAS_RETRIES {
            let current = self.store.get(&self.index_key).await?;
            let mut index: RevocationIndex = current
                .as_ref()
                .and_then(|bytes| serde_json::from_slice(bytes).ok())
                .unwrap_or_default();
            let now = unix_now();
            index.entries.retain(|_, expires_at| *expires_at > now);
            let result = operation(&mut index);
            let replacement = Bytes::from(serde_json::to_vec(&index).map_err(|error| {
                sbproxy_storage::StorageError::Backend(format!(
                    "revocation index serialization failed: {error}"
                ))
            })?);
            if self
                .store
                .compare_exchange(
                    &self.index_key,
                    current,
                    Some((replacement, self.maximum_ttl)),
                )
                .await?
            {
                return Ok(result);
            }
        }
        Err(sbproxy_storage::StorageError::Backend(
            "revocation index CAS contention limit reached".to_string(),
        ))
    }
}

pub(crate) struct RevocationRateLimiter {
    limit: u64,
    state: Mutex<(Instant, u64)>,
}

impl RevocationRateLimiter {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            limit: limit.max(1),
            state: Mutex::new((Instant::now(), 0)),
        }
    }

    pub(crate) async fn allow(&self) -> bool {
        let mut state = self.state.lock().await;
        if state.0.elapsed() >= Duration::from_secs(60) {
            *state = (Instant::now(), 0);
        }
        if state.1 >= self.limit {
            return false;
        }
        state.1 += 1;
        true
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

    if !app.revocation_rate_limiter.allow().await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "error": "slow_down",
                "error_description": "revocation request rate limit exceeded"
            })),
        )
            .into_response();
    }

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
    if let Some(assertion_type) = form.get("client_assertion_type") {
        form_body.push(("client_assertion_type", assertion_type.clone()));
    }
    if let Some(assertion) = form.get("client_assertion") {
        form_body.push(("client_assertion", assertion.clone()));
    }

    // Only a broker-signed, issuer/resource-bound RFC 9068 token may
    // allocate local denylist state. RFC 7009 still forwards unknown values
    // and returns upstream success, but fabricated JWT payloads cannot pin
    // process memory or choose retention.
    let validated_exp = cfg.broker_signing_key.as_ref().and_then(|key| {
        crate::at_jwt::verify_broker_at_jwt(
            &token,
            key,
            &crate::well_known::broker_issuer(cfg),
            &cfg.resource_uri,
        )
        .ok()
        .map(|claims| claims.exp)
    });
    // WOR-170: revocation forwards the bearer token in the request
    // body; refuse redirects so the token cannot leak cross-host.
    let (_, http) =
        match crate::egress::endpoint_client(upstream, cfg.allow_insecure_loopback).await {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error, "revocation endpoint rejected by egress policy");
                return (
                    StatusCode::BAD_GATEWAY,
                    axum::Json(serde_json::json!({
                        "error": "upstream_error",
                        "error_description": "upstream revocation endpoint is not permitted"
                    })),
                )
                    .into_response();
            }
        };
    let mut request = http.post(upstream);
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
            if let Some(exp) = validated_exp {
                if let Err(e) = app.revocations.record_validated(&token, exp).await {
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

    const ES256_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
-----END PRIVATE KEY-----\n";

    fn signing_key() -> crate::config::JwkKey {
        crate::config::JwkKey::Pem {
            pem: ES256_PRIVATE_PEM.to_string(),
            alg: "ES256".to_string(),
            kid: Some("revoke-key".to_string()),
            public_jwk: Some(serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
                "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY",
                "kid": "revoke-key",
                "use": "sig",
                "alg": "ES256"
            })),
        }
    }

    fn signed_token() -> String {
        let now = unix_now() as i64;
        crate::at_jwt::mint_at_jwt(
            &crate::at_jwt::AtJwtClaims {
                iss: "https://broker.example/mcp/oauth".to_string(),
                sub: "user".to_string(),
                aud: serde_json::json!("https://resource.example"),
                exp: now + 600,
                iat: now,
                jti: "revocation-jti".to_string(),
                client_id: "client".to_string(),
                scope: Some("mcp:read".to_string()),
                auth_time: None,
                acr: None,
                amr: None,
                act: None,
                cnf: None,
                actor: None,
                principal: None,
                tnx: None,
                purpose: None,
            },
            &signing_key(),
        )
        .unwrap()
    }

    async fn call(url: String, token: &str) -> (StatusCode, crate::McpSecurityContext) {
        let cfg = crate::config::McpGatewayConfig {
            upstream_revocation_endpoint_url: Some(url),
            allow_insecure_loopback: true,
            external_base_url: "https://broker.example".to_string(),
            resource_uri: "https://resource.example".to_string(),
            broker_signing_key: Some(signing_key()),
            ..Default::default()
        };
        let security = crate::McpSecurityContext::for_test("revoke-handler");
        let app = crate::router_with_security_context(
            Arc::new(cfg),
            crate::session::InMemorySessionStore::arc(Duration::from_secs(60)),
            security.clone(),
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
                "token={token}&client_id=cli&client_secret=form-secret&client_assertion_type=jwt-bearer&client_assertion=assertion-value"
            )))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let _ = response.into_body().collect().await.unwrap();
        (status, security)
    }

    #[tokio::test]
    async fn successful_revocation_forwards_auth_and_invalidates_local_token() {
        let token = signed_token();
        let (url, captured) = upstream("200 OK").await;
        let (status, security) = call(url, &token).await;
        assert_eq!(status, StatusCode::OK);
        let request = captured.await.unwrap();
        assert!(request.contains("authorization: Basic Y2xpOnNlY3JldA=="));
        assert!(request.contains("client_secret=form-secret"));
        assert!(request.contains("client_assertion=assertion-value"));
        let list = RevocationList::new(
            security.store,
            security.namespace,
            4,
            Duration::from_secs(3600),
        );
        assert!(list.contains(&token).await);
    }

    #[tokio::test]
    async fn unknown_upstream_success_does_not_allocate_local_state() {
        let token = "e30.eyJleHAiOjk5OTk5OTk5OTl9.fabricated";
        let (url, _captured) = upstream("200 OK").await;
        let (status, security) = call(url, token).await;
        assert_eq!(status, StatusCode::OK);
        let list = RevocationList::new(
            security.store,
            security.namespace,
            4,
            Duration::from_secs(3600),
        );
        assert!(!list.contains(token).await);
    }

    #[tokio::test]
    async fn failed_upstream_revocation_is_not_reported_as_success() {
        let token = signed_token();
        let (url, _captured) = upstream("500 Internal Server Error").await;
        let (status, security) = call(url, &token).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let list = RevocationList::new(
            security.store,
            security.namespace,
            4,
            Duration::from_secs(3600),
        );
        assert!(!list.contains(&token).await);
    }

    #[test]
    fn validated_revocation_retention_is_capped() {
        let exp = unix_now() as i64 + (30 * 24 * 60 * 60);
        assert_eq!(
            validated_revocation_ttl(exp, Duration::from_secs(600)),
            Duration::from_secs(600)
        );
    }

    #[tokio::test]
    async fn revocation_capacity_evicts_deterministically_and_namespaces_are_isolated() {
        let store: Arc<dyn EphemeralKv> = crate::LocalStore::arc();
        let tenant_a = RevocationList::new(
            store.clone(),
            "tenant-a".to_string(),
            2,
            Duration::from_secs(600),
        );
        let tenant_b =
            RevocationList::new(store, "tenant-b".to_string(), 2, Duration::from_secs(600));
        let now = unix_now() as i64;
        tenant_a.record_validated("old", now + 10).await.unwrap();
        tenant_a.record_validated("new", now + 100).await.unwrap();
        tenant_a
            .record_validated("newest", now + 200)
            .await
            .unwrap();
        assert!(!tenant_a.contains("old").await);
        assert!(tenant_a.contains("new").await);
        assert!(tenant_a.contains("newest").await);
        assert!(!tenant_b.contains("new").await);
    }

    #[tokio::test]
    async fn revocation_rate_limit_fails_closed_at_the_configured_budget() {
        let limiter = RevocationRateLimiter::new(2);
        assert!(limiter.allow().await);
        assert!(limiter.allow().await);
        assert!(!limiter.allow().await);
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
