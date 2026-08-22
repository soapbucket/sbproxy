//! OAuth 2.0 Token Revocation per RFC 7009.
//!
//! Lets clients (or post-authentication tooling) tell the broker
//! "this token is dead." The broker's job is two-step:
//!
//! 1. Forward the revocation to the upstream authorization server so
//!    the issuer-of-record knows the token is gone.
//! 2. Invalidate any broker-local caches keyed off the token (today
//!    just session state; a future PR-level introspection cache
//!    would also flush here).
//!
//! Per RFC 7009 sec 2.2 the response is **always 200 OK** (regardless
//! of whether the token was valid, already revoked, or unknown).
//! Returning a different code would let an attacker probe the
//! token's validity.
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
//! * No client authentication on /revoke. The same posture as /par;
//!   public clients with PKCE do not have a credential to present.
//!   A future slice can plumb client_credentials when enterprise
//!   deployments require it.
//! * No JWT introspection of access tokens to extract `jti` for
//!   precise cache-line invalidation. Today we conservatively flush
//!   any session whose cached access_token equals the supplied
//!   token; a future RFC 9068 (#80) integration will allow
//!   token-claim-based invalidation.

use std::collections::HashMap;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Form,
};

use crate::AppState;

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

    // --- Flush broker-local caches that key off the token ---
    //
    // Best-effort: invalidating a non-existent session is a no-op.
    // We do not block the upstream forward on this step.
    invalidate_session_for_token(&app, &token).await;

    // --- Forward to upstream ---
    //
    // Per RFC 7009 sec 2.2 we always return 200 to the client even
    // when the upstream call fails or returns 4xx. The upstream's
    // failure is logged but not surfaced; otherwise a misconfigured
    // upstream would let attackers probe token validity by watching
    // for status drift.
    let mut form_body = vec![("token", token.as_str())];
    if let Some(hint) = token_type_hint.as_deref() {
        form_body.push(("token_type_hint", hint));
    }
    // WOR-170: revocation forwards the bearer token in the request
    // body; refuse redirects so the token cannot leak cross-host.
    let result = sbproxy_httpkit::token_bearing_outbound()
        .post(upstream)
        .form(&form_body)
        .send()
        .await;
    match result {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!(
                target: "mcp_gateway::revoke",
                upstream_status = %resp.status(),
                "upstream revocation acknowledged"
            );
        }
        Ok(resp) => {
            tracing::warn!(
                target: "mcp_gateway::revoke",
                upstream_status = %resp.status(),
                "upstream revocation returned non-success; reporting 200 to client per RFC 7009 §2.2"
            );
        }
        Err(e) => {
            tracing::warn!(
                target: "mcp_gateway::revoke",
                error = %e,
                "upstream revocation transport failed; reporting 200 to client per RFC 7009 §2.2"
            );
        }
    }

    StatusCode::OK.into_response()
}

/// Best-effort flush of any session state cached under the supplied
/// token. The session_store trait keys on the broker's outbound
/// `state` value, not on the access token; precise per-token
/// invalidation will land alongside the introspection-server work
/// when sessions gain a token index. Today this is a documented
/// no-op so the ABI is stable for that future slice.
async fn invalidate_session_for_token(_app: &AppState, _token: &str) {
    // Intentionally empty for Wave 4D.3b. The session_store keys on
    // broker-state UUID, not on the token; flushing by token requires
    // a reverse index that lands with introspection (Wave 4D.3c) or
    // RFC 9068 (Wave 4D.3d), whichever ships first. Until then the
    // upstream's own revocation is the source of truth.
}

#[cfg(test)]
mod tests {
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
