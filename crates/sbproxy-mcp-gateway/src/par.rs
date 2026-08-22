//! Pushed Authorization Requests (PAR) per RFC 9126.
//!
//! PAR moves the authorization request parameters off the wire (and
//! out of browser history / referer headers / server access logs)
//! by having the client POST them to `/par` first, getting back an
//! opaque `request_uri`, then redirecting the user agent to
//! `/authorize?request_uri=...` instead of putting every parameter
//! in the URL.
//!
//! ## Wire shape
//!
//! Request: standard form-encoded body with the same fields as
//! `/authorize` (client_id, redirect_uri, response_type,
//! code_challenge, code_challenge_method, state, scope, resource).
//! Per RFC 9126 §2.1 the broker MAY also accept client
//! authentication on this endpoint; today we trust the client_id
//! at face value (matches the rest of the broker's posture for
//! public OAuth 2.1 clients with PKCE).
//!
//! Response (200):
//! ```json
//! {
//!   "request_uri": "urn:ietf:params:oauth:request_uri:abc123...",
//!   "expires_in": 60
//! }
//! ```
//!
//! ## Storage
//!
//! Each accepted PAR request is stored in
//! [`AppState::par_store`] (an [`sbproxy_storage::EphemeralKv`])
//! with the [`PAR_TTL_SECS`] TTL. The key is the `request_uri` value;
//! the value is a JSON-serialized [`PushedAuthorizationParams`].
//!
//! `/authorize` consumes the entry via `EphemeralKv::take` so a
//! request_uri is single-use per RFC 9126 §2.2.
//!
//! ## What this module does NOT do
//!
//! * No client authentication on /par. Public clients with PKCE
//!   are the broker's primary use case; adding mTLS / private-key-jwt
//!   here belongs in a future slice once enterprise deployments
//!   request it.
//! * No request_object (signed JWT) support per RFC 9101. We accept
//!   plain form-encoded parameters only; signing the request is
//!   the next step beyond PAR and not P0 for the broker.
//! * No PAR endpoint discovery beyond the AS metadata
//!   `pushed_authorization_request_endpoint` field added by
//!   `well_known.rs` when par_store is configured.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Form, Json,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::AppState;

/// TTL applied to every accepted PAR entry. Per RFC 9126 §6 the AS
/// SHOULD use a short lifetime; 60 seconds matches Auth0 / Okta /
/// Keycloak defaults.
pub const PAR_TTL_SECS: u64 = 60;

/// URN namespace prefix for PAR request_uri values per RFC 9126 §2.2.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

// --- Wire types ---

/// JSON response body returned on a successful /par.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushedAuthorizationResponse {
    /// The request_uri the client passes to /authorize. Single-use.
    pub request_uri: String,
    /// Seconds until the request_uri expires. Always [`PAR_TTL_SECS`]
    /// today; a future per-tenant override could shorten it.
    pub expires_in: i64,
}

/// Parameters captured from a /par request and replayed by /authorize
/// when the client redirects with `?request_uri=urn:...`. Fields
/// mirror `AuthorizeQuery` (in `authorize.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushedAuthorizationParams {
    /// Client identifier. Required.
    pub client_id: String,
    /// Redirect URI. Required.
    pub redirect_uri: String,
    /// OAuth response_type. Required; OAuth 2.1 mandates "code".
    pub response_type: String,
    /// PKCE code challenge. Required for OAuth 2.1.
    pub code_challenge: String,
    /// PKCE method. "S256" or "plain"; OAuth 2.1 forbids plain.
    pub code_challenge_method: String,
    /// Optional client-supplied state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Optional RFC 8707 resource indicator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Optional scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl PushedAuthorizationParams {
    /// Pull the PAR fields out of the form body, returning the OAuth
    /// error tuple on missing required fields.
    pub fn from_form(
        form: &HashMap<String, String>,
    ) -> Result<Self, (StatusCode, &'static str, &'static str)> {
        let req = |name: &'static str| -> Result<String, (StatusCode, &'static str, &'static str)> {
            match form.get(name) {
                Some(s) if !s.is_empty() => Ok(s.clone()),
                _ => Err((
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    match name {
                        "client_id" => "missing client_id",
                        "redirect_uri" => "missing redirect_uri",
                        "response_type" => "missing response_type",
                        "code_challenge" => "missing code_challenge",
                        "code_challenge_method" => "missing code_challenge_method",
                        _ => "missing required parameter",
                    },
                )),
            }
        };
        Ok(Self {
            client_id: req("client_id")?,
            redirect_uri: req("redirect_uri")?,
            response_type: req("response_type")?,
            code_challenge: req("code_challenge")?,
            code_challenge_method: req("code_challenge_method")?,
            state: form.get("state").filter(|s| !s.is_empty()).cloned(),
            resource: form.get("resource").filter(|s| !s.is_empty()).cloned(),
            scope: form.get("scope").filter(|s| !s.is_empty()).cloned(),
        })
    }
}

// --- Request URI minting ---

/// Generate a fresh opaque request_uri value. 32 hex chars of CSPRNG
/// entropy keeps collisions astronomically unlikely (2^128 keyspace);
/// the urn:ietf prefix makes the value self-identifying.
pub fn mint_request_uri() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{REQUEST_URI_PREFIX}{hex}")
}

/// Validate that `value` looks like a request_uri this broker would
/// have minted. Used by /authorize before consulting the store so a
/// random user-supplied URN does not waste a storage round trip.
pub fn is_well_formed_request_uri(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix(REQUEST_URI_PREFIX) else {
        return false;
    };
    suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
}

// --- Errors ---

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

/// `POST {base_path}/par` handler.
///
/// Returns 503 Service Unavailable when `par_store` is not
/// configured on the broker so deployments that have not opted in
/// produce a clear error rather than an obscure 404.
pub async fn par(
    State(app): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let Some(store) = app.par_store.as_ref() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "PAR endpoint is not configured on this broker",
        );
    };

    let params = match PushedAuthorizationParams::from_form(&form) {
        Ok(p) => p,
        Err((status, error, description)) => return oauth_error(status, error, description),
    };

    // Encode the params as JSON for storage. Failures here are
    // impossible in practice (every field is a String / Option<String>
    // and serde_json never fails on those), but we return a clean
    // 500 if it ever does.
    let bytes = match serde_json::to_vec(&params) {
        Ok(b) => bytes::Bytes::from(b),
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to encode PAR params",
            )
        }
    };

    let request_uri = mint_request_uri();
    let ttl = Duration::from_secs(PAR_TTL_SECS);
    if let Err(e) = store.put(&request_uri, bytes, ttl).await {
        tracing::warn!(
            target: "mcp_gateway::par",
            error = %e,
            "failed to store PAR entry"
        );
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "failed to persist PAR entry",
        );
    }

    let response = PushedAuthorizationResponse {
        request_uri,
        expires_in: PAR_TTL_SECS as i64,
    };
    (StatusCode::CREATED, Json(response)).into_response()
}

/// Helper called by `/authorize` to consume a PAR entry by
/// `request_uri`. Returns the stored params on hit + None on miss /
/// expiry (the authorize handler then 400s with `invalid_request`).
///
/// Atomic take semantics: a request_uri is single-use, so the
/// underlying [`sbproxy_storage::EphemeralKv::take`]
/// removes the entry as it returns it.
pub async fn consume(
    store: &Arc<dyn sbproxy_storage::EphemeralKv>,
    request_uri: &str,
) -> Option<PushedAuthorizationParams> {
    if !is_well_formed_request_uri(request_uri) {
        return None;
    }
    let bytes = store.take(request_uri).await.ok().flatten()?;
    serde_json::from_slice(&bytes).ok()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn full_form() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("client_id".into(), "https://client.example/cimd".into());
        m.insert("redirect_uri".into(), "https://client.example/cb".into());
        m.insert("response_type".into(), "code".into());
        m.insert("code_challenge".into(), "abc_challenge".into());
        m.insert("code_challenge_method".into(), "S256".into());
        m.insert("state".into(), "client-state-value".into());
        m.insert("scope".into(), "read".into());
        m.insert("resource".into(), "https://api.example/v1".into());
        m
    }

    #[test]
    fn from_form_extracts_every_field() {
        let p = PushedAuthorizationParams::from_form(&full_form()).expect("valid form");
        assert_eq!(p.client_id, "https://client.example/cimd");
        assert_eq!(p.redirect_uri, "https://client.example/cb");
        assert_eq!(p.response_type, "code");
        assert_eq!(p.code_challenge, "abc_challenge");
        assert_eq!(p.code_challenge_method, "S256");
        assert_eq!(p.state.as_deref(), Some("client-state-value"));
        assert_eq!(p.scope.as_deref(), Some("read"));
        assert_eq!(p.resource.as_deref(), Some("https://api.example/v1"));
    }

    #[test]
    fn from_form_rejects_missing_client_id() {
        let mut form = full_form();
        form.remove("client_id");
        let err = PushedAuthorizationParams::from_form(&form).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "invalid_request");
        assert!(err.2.contains("client_id"));
    }

    #[test]
    fn from_form_rejects_empty_required_field() {
        let mut form = full_form();
        form.insert("redirect_uri".into(), String::new());
        let err = PushedAuthorizationParams::from_form(&form).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.2.contains("redirect_uri"));
    }

    #[test]
    fn from_form_optional_fields_default_to_none() {
        let mut form = HashMap::new();
        form.insert("client_id".into(), "c".into());
        form.insert("redirect_uri".into(), "https://c/cb".into());
        form.insert("response_type".into(), "code".into());
        form.insert("code_challenge".into(), "x".into());
        form.insert("code_challenge_method".into(), "S256".into());
        let p = PushedAuthorizationParams::from_form(&form).unwrap();
        assert!(p.state.is_none());
        assert!(p.resource.is_none());
        assert!(p.scope.is_none());
    }

    #[test]
    fn mint_request_uri_uses_correct_prefix_and_length() {
        let uri = mint_request_uri();
        assert!(uri.starts_with(REQUEST_URI_PREFIX));
        let suffix = &uri[REQUEST_URI_PREFIX.len()..];
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn mint_request_uri_collisions_are_practically_zero() {
        // 100 mints should produce 100 unique values. Birthday
        // paradox collision probability over a 2^128 keyspace at
        // 100 samples is ~10^-35; if this test ever fails, a CSPRNG
        // is broken.
        use std::collections::HashSet;
        let set: HashSet<_> = (0..100).map(|_| mint_request_uri()).collect();
        assert_eq!(set.len(), 100);
    }

    #[test]
    fn well_formed_request_uri_accepts_minted_values() {
        let uri = mint_request_uri();
        assert!(is_well_formed_request_uri(&uri));
    }

    #[test]
    fn well_formed_request_uri_rejects_random_inputs() {
        assert!(!is_well_formed_request_uri(""));
        assert!(!is_well_formed_request_uri("not a urn"));
        assert!(!is_well_formed_request_uri(REQUEST_URI_PREFIX));
        // Right prefix, wrong length.
        assert!(!is_well_formed_request_uri(&format!(
            "{REQUEST_URI_PREFIX}abc"
        )));
        // Right length, wrong charset.
        let bad: String = "z".repeat(32);
        assert!(!is_well_formed_request_uri(&format!(
            "{REQUEST_URI_PREFIX}{bad}"
        )));
    }

    #[tokio::test]
    async fn consume_returns_stored_params_then_evicts() {
        let store: Arc<dyn sbproxy_storage::EphemeralKv> =
            Arc::new(crate::local_store::LocalStore::new());
        let params = PushedAuthorizationParams::from_form(&full_form()).unwrap();
        let uri = mint_request_uri();

        store
            .put(
                &uri,
                bytes::Bytes::from(serde_json::to_vec(&params).unwrap()),
                Duration::from_secs(60),
            )
            .await
            .unwrap();

        let first = consume(&store, &uri).await.expect("first take should hit");
        assert_eq!(first.client_id, params.client_id);

        // Single-use: the second take returns None.
        assert!(
            consume(&store, &uri).await.is_none(),
            "request_uri must be single-use"
        );
    }

    #[tokio::test]
    async fn consume_returns_none_for_malformed_uri() {
        let store: Arc<dyn sbproxy_storage::EphemeralKv> =
            Arc::new(crate::local_store::LocalStore::new());
        assert!(consume(&store, "junk").await.is_none());
        assert!(consume(&store, "urn:ietf:params:oauth:request_uri:short")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn consume_returns_none_when_store_garbage() {
        // Pre-seed the store with non-JSON bytes at a valid-looking
        // request_uri. Defends against schema drift.
        let store: Arc<dyn sbproxy_storage::EphemeralKv> =
            Arc::new(crate::local_store::LocalStore::new());
        let uri = mint_request_uri();
        store
            .put(
                &uri,
                bytes::Bytes::from_static(b"not json"),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert!(consume(&store, &uri).await.is_none());
    }
}
