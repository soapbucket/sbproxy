//! OAuth 2.0 Token Introspection per RFC 7662 (server side).
//!
//! Lets a protected resource ask the broker "is this token live, and
//! what is it for?" Per RFC 7662 §2.2 the response shape is:
//!
//! ```json
//! {
//!   "active": true,
//!   "scope": "read write",
//!   "client_id": "abc",
//!   "username": "alice@example",
//!   "exp": 1700000000,
//!   "iat": 1699999000,
//!   "sub": "user_42",
//!   "aud": "https://api.example",
//!   "iss": "https://broker.example"
//! }
//! ```
//!
//! When the token is invalid / unknown / expired the broker returns
//! `{"active": false}` (and HTTP 200 - per RFC 7662 §2.2 only the
//! active claim is required on a negative response, and the status
//! is 200 OK regardless).
//!
//! ## Posture
//!
//! The broker is a **passthrough**: it forwards the introspection
//! request to the upstream introspection endpoint and proxies the
//! response. The broker does not maintain its own JWT validation
//! path on this slice; the upstream Authorization Server is the
//! authoritative source of truth on whether a token is still live.
//! Wave 4D.3d (RFC 9068) lands the broker-side JWT validation that
//! lets the broker answer locally without a round trip.
//!
//! ## Caller authentication
//!
//! Per RFC 7662 §2.1 the introspection endpoint MUST require some
//! form of authorization to prevent token-scanning attacks. The
//! broker enforces a minimal liveness check on the inbound auth -
//! either an `Authorization: Basic` header or `Authorization: Bearer`
//! header or a `client_id`+`client_secret` form pair MUST be
//! present - then forwards that auth verbatim to the upstream which
//! does the real validation. A request with no auth at all gets
//! 401 with `WWW-Authenticate: Basic`.
//!
//! ## What this module does NOT do
//!
//! * No local JWT decode. We do not parse the token; the upstream
//!   does. RFC 9068 (Wave 4D.3d) introduces broker-side JWT
//!   validation as a separate path.
//! * No caching. Introspection responses are intentionally NOT
//!   cached today because the upstream can revoke at any time and
//!   stale-cached `active: true` is the most damaging cache hit
//!   class. A future slice can add a short opt-in TTL behind
//!   per-tenant config.

use std::collections::HashMap;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form, Json,
};

use crate::AppState;

// --- Handler ---

/// `POST {base_path}/introspect` handler.
///
/// Status codes:
/// * 200 OK with the proxied upstream JSON body when the upstream
///   responds 2xx. Includes both the `active: true` and
///   `active: false` cases per RFC 7662 §2.2.
/// * 401 Unauthorized with `WWW-Authenticate: Basic` when no
///   inbound auth was presented.
/// * 400 Bad Request when the form is malformed (missing token).
/// * 502 Bad Gateway when the upstream is reachable but returns
///   non-2xx.
/// * 503 Service Unavailable when the upstream call fails to
///   complete (network error, DNS, TLS).
/// * 501 Not Implemented when the broker has no
///   `upstream_introspection_endpoint_url` configured.
pub async fn introspect(
    State(app): State<AppState>,
    verified_client_cert: Option<axum::extract::Extension<crate::VerifiedClientCertificate>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let cfg = &app.config;

    // RFC 7662 §2.1: require some form of auth on the request
    // before we even touch the upstream. Without this gate, the
    // broker becomes a token-scanner amplifier.
    if !has_caller_auth(&headers, &form) {
        let mut resp = (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "introspection requires caller authentication",
            })),
        )
            .into_response();
        // RFC 6749 §5.2: a 401 SHOULD include WWW-Authenticate.
        resp.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static("Basic"),
        );
        return resp;
    }

    // RFC 7662 §2.1: the request must carry a token.
    let token = match form.get("token") {
        Some(t) if !t.is_empty() => t.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "missing token",
                })),
            )
                .into_response();
        }
    };

    let token_type_hint = form
        .get("token_type_hint")
        .filter(|s| !s.is_empty())
        .cloned();

    // Configuration gate: 501 lets the operator notice they enabled
    // /introspect without wiring the upstream URL.
    let Some(upstream) = cfg.upstream_introspection_endpoint_url.as_deref() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({
                "error": "unsupported_endpoint",
                "error_description": "/introspect is not configured on this broker",
            })),
        )
            .into_response();
    };

    // --- Forward to upstream ---
    //
    // We forward the original Authorization header verbatim (when
    // present) so the upstream sees the same client_secret_basic /
    // bearer auth the caller supplied. For client_secret_post the
    // form fields flow through naturally.
    let mut form_body: Vec<(&str, String)> = vec![("token", token)];
    if let Some(hint) = token_type_hint {
        form_body.push(("token_type_hint", hint));
    }
    if let Some(client_id) = form.get("client_id") {
        form_body.push(("client_id", client_id.clone()));
    }
    if let Some(client_secret) = form.get("client_secret") {
        form_body.push(("client_secret", client_secret.clone()));
    }

    // WOR-170: introspection forwards the inbound Authorization header
    // upstream; refuse redirects so a malicious AS cannot bounce the
    // request cross-host and capture the credential.
    let mut req = sbproxy_httpkit::token_bearing_outbound().post(upstream);
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = auth.to_str() {
            req = req.header(reqwest::header::AUTHORIZATION, s);
        }
    }
    let result = req.form(&form_body).send().await;

    let resp = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target: "mcp_gateway::introspect",
                error = %sbproxy_httpkit::request_error_summary(&e),
                "upstream introspection transport failed"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "temporarily_unavailable",
                    "error_description": "upstream introspection unreachable",
                })),
            )
                .into_response();
        }
    };

    let status = resp.status();
    if !status.is_success() {
        tracing::warn!(
            target: "mcp_gateway::introspect",
            upstream_status = %status,
            "upstream introspection returned non-success"
        );
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "upstream_error",
                "error_description": format!("upstream introspection returned {status}"),
            })),
        )
            .into_response();
    }

    // Proxy the upstream JSON back. We do not parse / re-emit
    // because RFC 7662 §2.2 lets the AS include implementation
    // extensions; round-tripping bytes preserves them.
    let body = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                target: "mcp_gateway::introspect",
                error = %sbproxy_httpkit::request_error_summary(&e),
                "upstream introspection body read failed"
            );
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "upstream_error",
                    "error_description": "upstream body read failed",
                })),
            )
                .into_response();
        }
    };

    // WOR-517: RFC 8705 §3 binding enforcement.
    //
    // If the upstream's claim set advertises cnf.x5t#S256 we MUST
    // verify the request's mTLS client cert matches before reporting
    // the token as active. RFC 8705 §3 maps a binding failure to
    // `invalid_token`; the introspection contract (RFC 7662 §2.2)
    // expresses that by flipping `active` to false. We surface the
    // ergonomic mismatch on a separate `x5t_s256_binding` field so
    // operators can debug without parsing the suppressed claim set.
    let body = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(claims) => match crate::mtls_binding::verify_cnf_x5t_s256_thumbprint(
            &claims,
            verified_client_cert
                .as_ref()
                .map(|axum::extract::Extension(cert)| cert.x5t_s256.as_str()),
        ) {
            Ok(_) => body,
            Err(e) => {
                tracing::warn!(
                    target: "mcp_gateway::introspect",
                    error = %e,
                    "RFC 8705 cnf.x5t#S256 binding verification failed; suppressing token"
                );
                let suppressed = serde_json::json!({
                    "active": false,
                    "x5t_s256_binding": "failed",
                });
                bytes::Bytes::from(serde_json::to_vec(&suppressed).unwrap_or_default())
            }
        },
        Err(e) => {
            // Body was not JSON; pass it through verbatim. The
            // upstream may have returned an implementation-specific
            // shape and RFC 7662 lets us forward what we cannot
            // parse.
            tracing::debug!(
                target: "mcp_gateway::introspect",
                error = %e,
                "upstream body is not JSON; passing through without binding check"
            );
            body
        }
    };
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

/// Returns true when the request carries any of the auth shapes
/// RFC 7662 §2.1 contemplates: HTTP Basic, Bearer, or
/// client_id+client_secret form fields.
fn has_caller_auth(headers: &HeaderMap, form: &HashMap<String, String>) -> bool {
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = value.to_str() {
            if s.starts_with("Basic ") || s.starts_with("Bearer ") {
                return true;
            }
        }
    }
    let cid = form.get("client_id").map(String::as_str).unwrap_or("");
    let cs = form.get("client_secret").map(String::as_str).unwrap_or("");
    !cid.is_empty() && !cs.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_auth_form() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("token".into(), "any".into());
        m
    }

    #[test]
    fn has_caller_auth_basic_header() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Basic Zm9vOmJhcg=="),
        );
        assert!(has_caller_auth(&h, &no_auth_form()));
    }

    #[test]
    fn has_caller_auth_bearer_header() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer abc.def.ghi"),
        );
        assert!(has_caller_auth(&h, &no_auth_form()));
    }

    #[test]
    fn has_caller_auth_form_credentials() {
        let h = HeaderMap::new();
        let mut form = no_auth_form();
        form.insert("client_id".into(), "c".into());
        form.insert("client_secret".into(), "s".into());
        assert!(has_caller_auth(&h, &form));
    }

    #[test]
    fn has_caller_auth_rejects_no_auth() {
        let h = HeaderMap::new();
        assert!(!has_caller_auth(&h, &no_auth_form()));
    }

    #[test]
    fn has_caller_auth_rejects_only_client_id() {
        let h = HeaderMap::new();
        let mut form = no_auth_form();
        form.insert("client_id".into(), "c".into());
        // No client_secret -> not enough.
        assert!(!has_caller_auth(&h, &form));
    }

    #[test]
    fn has_caller_auth_rejects_unrecognized_authorization_scheme() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Digest username=alice"),
        );
        assert!(!has_caller_auth(&h, &no_auth_form()));
    }

    #[test]
    fn has_caller_auth_empty_form_credentials_rejected() {
        let h = HeaderMap::new();
        let mut form = no_auth_form();
        form.insert("client_id".into(), "".into());
        form.insert("client_secret".into(), "".into());
        assert!(!has_caller_auth(&h, &form));
    }
}
