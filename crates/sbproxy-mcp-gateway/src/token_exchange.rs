//! RFC 8693 OAuth 2.0 Token Exchange for the MCP Auth Gateway.
//!
//! Token exchange is the load-bearing primitive behind the Wave 5
//! "outbound credential resolver" story: a service holding an inbound
//! access token (the `subject_token`) asks the broker to mint a new
//! token bound to a different audience or with a different actor
//! identity, without re-prompting the human. The broker validates the
//! subject token, walks any existing `act` claim chain to enforce a
//! depth bound, forwards the exchange to the upstream Authorization
//! Server, and (optionally) wraps the upstream's response in a fresh
//! `act` envelope so downstream resource servers can audit the full
//! delegation chain.
//!
//! This module implements:
//!
//! * `handle_token_exchange` - the `POST /token` branch that runs
//!   when `grant_type == TOKEN_EXCHANGE_GRANT_TYPE`. Validates the
//!   inbound parameters, parses and inspects the `subject_token`,
//!   forwards the request to the upstream, and post-processes the
//!   response to inject the broker's actor envelope.
//! * [`TOKEN_EXCHANGE_GRANT_TYPE`] - the canonical RFC 8693 §2.1 URN.
//! * [`SUBJECT_TOKEN_TYPE_ACCESS`] - the access-token subject type the
//!   broker requires (other types are accepted but logged).
//! * `chain_depth` - the recursive `act` chain walker used for the
//!   `token_exchange_max_chain_depth` policy check.
//!
//! Threat model: the broker treats the inbound `subject_token` as
//! untrusted input until its issuer is matched against
//! `subject_token_issuers`. Audience steering (`audience` parameter)
//! is rejected with `invalid_target` unless the value is enrolled.
//! The broker forwards `resource` (RFC 8707) verbatim so the upstream
//! can bind the issued token to the correct resource server.

use std::collections::HashMap;

use axum::{http::StatusCode, response::Response};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::client_auth::ClientAuthMethod;
use crate::dpop::DpopProof;
use crate::AppState;

// --- RFC 8693 grant URN + token types ---

/// RFC 8693 §2.1 grant_type URN polled at /token.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 §3 subject_token_type for an OAuth 2.0 access token.
pub const SUBJECT_TOKEN_TYPE_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";

/// RFC 8693 §3 token_type URN for a JWT-shaped issued token. Used as
/// the default `issued_token_type` when the upstream omits it.
const ISSUED_TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

// --- Public claim envelope ---

/// Minimal JWT claim envelope the broker reads from a `subject_token`.
/// We deliberately ignore signature, expiry, and audience here: those
/// checks are the upstream's job (we forward verbatim) and the broker
/// only cares about `iss`, `sub`, and the nested `act` chain for its
/// own policy enforcement.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubjectClaims {
    /// Issuer claim (RFC 7519 §4.1.1). Required; matched against
    /// [`crate::config::McpGatewayConfig::subject_token_issuers`].
    #[serde(default)]
    pub iss: Option<String>,
    /// Subject claim (RFC 7519 §4.1.2). Forwarded into the new `act`
    /// envelope so audit trails can attribute the exchange.
    #[serde(default)]
    pub sub: Option<String>,
    /// Nested actor claim (RFC 8693 §4.1). The broker walks this
    /// recursively to compute chain depth.
    #[serde(default)]
    pub act: Option<Box<ActClaim>>,
}

/// One link in the `act` chain. RFC 8693 §4.1 says `act` is itself a
/// JSON object with the same shape as the outer claim set, so we
/// model it recursively.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActClaim {
    /// Issuer of the actor token, when the upstream populated it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Subject of the actor token. Most upstreams set this to the
    /// service-account or human that triggered the exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Nested actor for multi-hop delegation chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
}

// --- Helpers ---

/// Base64url-decode the JWT payload (the second segment) and parse it
/// as a [`SubjectClaims`]. Returns `None` on any structural failure;
/// the caller surfaces this as `invalid_request`.
pub fn parse_subject_token(token: &str) -> Option<SubjectClaims> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _sig = parts.next()?;
    if parts.next().is_some() {
        // More than three segments is not a JWS Compact Serialization.
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice::<SubjectClaims>(&raw).ok()
}

/// Compute the depth of an existing `act` claim chain. An absent
/// chain is depth 0; a single-level `act` is depth 1; nested `act`s
/// add one each. The broker compares this against
/// `token_exchange_max_chain_depth` before forwarding upstream.
pub fn chain_depth(claims: &SubjectClaims) -> usize {
    fn walk(act: &ActClaim) -> usize {
        match &act.act {
            Some(inner) => 1 + walk(inner),
            None => 1,
        }
    }
    match &claims.act {
        Some(act) => walk(act),
        None => 0,
    }
}

// --- Handler ---

/// Handle a `POST /token` request whose `grant_type` is
/// [`TOKEN_EXCHANGE_GRANT_TYPE`].
///
/// Validation order (each step short-circuits with the documented
/// OAuth error code):
///
///   1. `token_exchange_enabled` master switch.
///   2. `subject_token` and `subject_token_type` presence.
///   3. `subject_token_type` model gate (access tokens only,
///      WOR-40).
///   4. JWT structural parse of `subject_token`.
///   5. `iss` allowlist via `subject_token_issuers`.
///   6. Optional `audience` allowlist via
///      `allowed_token_exchange_audiences`.
///   7. Chain-depth check against
///      `token_exchange_max_chain_depth`.
///   8. Forward to upstream `/token`.
///   9. On a JWT response, inject a fresh `act` envelope wrapping the
///      original subject's `(sub, iss)` plus any prior chain. The
///      rewrite is gated on broker re-signing capability (WOR-47):
///      without a `broker_signing_key`, the broker passes the
///      upstream JWT through unchanged.
///  10. Re-sign the exchanged JWT with any DPoP and verified mTLS
///      confirmation claims established by the shared endpoint seam.
///
/// `_method` is the inbound client-auth method detected by the
/// caller in `token::token`; the token-endpoint preflight already
/// rejected an unaccepted method, so this handler trusts the gate
/// and only consumes the value for audit logging in future slices.
/// `dpop_proof` and `verified_client_certificate` are verified identity
/// supplied by the shared token-endpoint preflight and the host TLS seam;
/// successful exchanged tokens are freshly re-signed with both bindings.
pub async fn handle_token_exchange(
    app: &AppState,
    form: &HashMap<String, String>,
    _method: ClientAuthMethod,
    dpop_proof: Option<&DpopProof>,
    verified_client_certificate: Option<&crate::VerifiedClientCertificate>,
) -> Response {
    let cfg = &app.config;

    // --- 1. Master switch ---
    if !cfg.token_exchange_enabled {
        return crate::token::oauth_error(
            StatusCode::NOT_FOUND,
            "unsupported_grant_type",
            "token exchange is disabled",
        );
    }

    // --- 2. Required parameters ---
    let subject_token = match form.get("subject_token") {
        Some(s) if !s.is_empty() => s.clone(),
        _ => {
            return crate::token::oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "subject_token is required",
            );
        }
    };
    let subject_token_type = match form.get("subject_token_type") {
        Some(s) if !s.is_empty() => s.clone(),
        _ => {
            return crate::token::oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "subject_token_type is required",
            );
        }
    };

    // --- 3. WOR-40: fail closed on unsupported subject_token_type ---
    //
    // RFC 8693 §2.1 enumerates several subject token types
    // (access_token, refresh_token, id_token, saml1, saml2, jwt). The
    // broker only models access-token subjects: the issuer allowlist,
    // chain-depth math, and `act` envelope all assume that the
    // payload is an OAuth access token JWT. Other types must be
    // rejected with `unsupported_token_type` rather than silently
    // forwarded so a caller cannot smuggle an id_token or
    // saml-shaped subject through a path that does not validate it.
    if subject_token_type != SUBJECT_TOKEN_TYPE_ACCESS {
        return crate::token::oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_token_type",
            &format!(
                "subject_token_type {subject_token_type:?} is not modeled by the broker; \
                 only urn:ietf:params:oauth:token-type:access_token is supported"
            ),
        );
    }

    // --- 3. Parse the subject_token ---
    let claims = match parse_subject_token(&subject_token) {
        Some(c) => c,
        None => {
            return crate::token::oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "subject_token is not a parseable JWT",
            );
        }
    };

    // --- 4. Issuer allowlist ---
    let iss = match claims.iss.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return crate::token::oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "subject_token is missing iss claim",
            );
        }
    };
    if !cfg.subject_token_issuers.iter().any(|i| i == &iss) {
        return crate::token::oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject_token issuer is not enrolled",
        );
    }

    // --- 5. Audience allowlist ---
    if let Some(aud) = form.get("audience").filter(|s| !s.is_empty()) {
        if !cfg
            .allowed_token_exchange_audiences
            .iter()
            .any(|a| a == aud)
        {
            return crate::token::oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "audience is not enrolled",
            );
        }
    }

    // --- 6. Chain depth check ---
    let depth = chain_depth(&claims);
    if depth >= cfg.token_exchange_max_chain_depth {
        return crate::token::oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "delegation chain too deep",
        );
    }

    // --- 6b. WOR-521: agent-profile token request ---
    //
    // draft-oauth-transaction-tokens-for-agents: when the caller asks
    // for the agent-profile token type, the broker stamps the agent
    // (`actor`), the human (`principal`, the subject token's `sub`), a
    // per-exchange transaction id (`tnx`), and the truncated `purpose`
    // onto the re-signed token. Rides the same re-sign path as the act
    // envelope below, so the claims land only when the broker has a
    // signing key. An agent-profile request whose subject token is not
    // user-authenticated (no `sub`) is rejected: the profile's whole
    // point is binding an agent action to a human principal.
    let agent_profile = match form.get("requested_token_type").map(String::as_str) {
        Some(crate::at_jwt::REQUESTED_TOKEN_TYPE_AGENT) => match claims.sub.as_ref() {
            Some(principal) => Some(AgentProfileInputs {
                actor: form.get("client_id").cloned().unwrap_or_default(),
                principal: principal.clone(),
                tnx: gen_transaction_id(),
                purpose: form.get("purpose").cloned(),
            }),
            None => {
                return crate::token::oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "agent-profile token exchange requires a user-authenticated \
                     subject_token (the subject token carries no `sub`)",
                );
            }
        },
        _ => None,
    };

    // The subject is an access token being presented to this token
    // endpoint, so RFC 9449 binds the proof to its hash. Run this after
    // structural/policy validation so malformed exchanges retain their
    // precise OAuth errors, but before any token is forwarded upstream.
    if let Err(description) = crate::token::require_access_token_ath(dpop_proof, &subject_token) {
        crate::metrics::record_dpop("rejected");
        return crate::token::oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            &description,
        );
    }

    // --- 7. Forward to upstream /token ---
    if cfg.upstream_token_endpoint_url.is_empty() {
        return crate::token::oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "upstream_token_endpoint_url not configured",
        );
    }

    // Build the forwarded form. RFC 8707 `resource` is injected when
    // the caller did not supply one and the broker has a default; the
    // upstream uses it to bind the issued token to a resource server.
    let mut forwarded: HashMap<String, String> = form.clone();
    if !forwarded.contains_key("resource") && !cfg.resource_uri.is_empty() {
        forwarded.insert("resource".to_string(), cfg.resource_uri.clone());
    }

    // WOR-170: token-exchange forwards the subject token to the
    // upstream token endpoint; refuse redirects.
    let http = sbproxy_httpkit::token_bearing_outbound();
    let resp = match http
        .post(&cfg.upstream_token_endpoint_url)
        .form(&forwarded)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                error = %sbproxy_httpkit::request_error_summary(&e),
                "upstream token-exchange call failed"
            );
            return crate::token::oauth_error(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "upstream token endpoint unreachable",
            );
        }
    };

    let status = resp.status();
    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                error = %sbproxy_httpkit::request_error_summary(&e),
                "upstream token-exchange body read failed"
            );
            return crate::token::oauth_error(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "upstream token endpoint body unreadable",
            );
        }
    };

    // --- 8. Optional act-envelope injection ---
    //
    // WOR-47: rewriting the JWT payload while preserving the upstream
    // signature produces an invalid token (the signature no longer
    // matches the rewritten payload). The broker therefore only
    // injects the `act` envelope when it is configured to re-sign
    // with `broker_signing_key`. When no signing key is configured,
    // the upstream JWT passes through unchanged and the broker still
    // adds the missing `issued_token_type` to the wrapper for RFC
    // 8693 §2.2.1 compliance.
    let mut body_bytes = if status.is_success() {
        match inject_act_envelope(
            &body_bytes,
            &claims,
            cfg.broker_signing_key.as_ref(),
            agent_profile.as_ref(),
            &crate::well_known::broker_issuer(cfg),
        ) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "act-envelope issuance failed closed");
                return crate::token::oauth_error(
                    StatusCode::BAD_GATEWAY,
                    "server_error",
                    "broker could not issue a delegated access token",
                );
            }
        }
    } else {
        body_bytes
    };

    if status.is_success() {
        body_bytes =
            match apply_sender_bindings(cfg, body_bytes, dpop_proof, verified_client_certificate) {
                Ok(body) => body,
                Err(error) => {
                    tracing::warn!(%error, "token-exchange sender binding failed closed");
                    return crate::token::oauth_error(
                        StatusCode::BAD_GATEWAY,
                        "server_error",
                        "broker could not sender-constrain exchanged token",
                    );
                }
            };
    }

    // --- Pass-through response ---
    let mut response = Response::builder()
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
            tracing::error!(error = %e, "failed to assemble token-exchange response");
            crate::token::oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "response assembly failed",
            )
        });
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert("Pragma", axum::http::HeaderValue::from_static("no-cache"));
    response
}

fn apply_sender_bindings(
    cfg: &crate::config::McpGatewayConfig,
    mut body: bytes::Bytes,
    dpop_proof: Option<&DpopProof>,
    verified_client_certificate: Option<&crate::VerifiedClientCertificate>,
) -> Result<bytes::Bytes, anyhow::Error> {
    let broker_issuer = crate::well_known::broker_issuer(cfg);
    if let Some(proof) = dpop_proof {
        body = crate::token::inject_cnf_jkt(
            &body,
            proof,
            cfg.broker_signing_key.as_ref(),
            &broker_issuer,
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    }
    if let Some(certificate) = verified_client_certificate {
        body = crate::mtls_binding::inject_cnf_x5t_s256_thumbprint(
            &body,
            &certificate.x5t_s256,
            cfg.broker_signing_key.as_ref(),
            &broker_issuer,
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    }
    Ok(body)
}

// --- act-envelope injection ---

/// WOR-521: inputs for the draft-oauth-transaction-tokens-for-agents
/// claim set, assembled by the handler when the caller requests the
/// agent-profile token type.
#[derive(Debug, Clone)]
pub struct AgentProfileInputs {
    /// Agent identity (the OAuth `client_id` that drove the exchange).
    pub actor: String,
    /// Human identity (the subject token's `sub`).
    pub principal: String,
    /// Per-exchange transaction id.
    pub tnx: String,
    /// Optional natural-language purpose; truncated on the token.
    pub purpose: Option<String>,
}

/// Generate a 128-bit transaction id, hex-encoded. Mirrors the
/// random-jti pattern used elsewhere in the gateway.
pub fn gen_transaction_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inject a fresh `act` envelope into the upstream's JWT response.
///
/// Behavior is gated on broker re-signing capability (WOR-47):
///
/// * **No `broker_signing_key`:** the wrapper-level
///   `issued_token_type` is filled in for RFC 8693 §2.2.1 compliance,
///   but the upstream `access_token` is passed through unchanged.
///   Rewriting the JWT payload while preserving the upstream
///   signature would yield a token that fails verification at every
///   downstream resource server.
/// * **Broker has a signing key:** the broker re-mints the access token
///   with the new `act` envelope and a fresh signature/issuer/jti.
///
/// Bodies that are not JSON-shaped pass through untouched.
pub fn inject_act_envelope(
    body: &bytes::Bytes,
    subject: &SubjectClaims,
    broker_signing_key: Option<&crate::config::JwkKey>,
    agent_profile: Option<&AgentProfileInputs>,
    broker_issuer: &str,
) -> Result<bytes::Bytes, anyhow::Error> {
    let mut value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| anyhow::anyhow!("upstream body not JSON: {e}"))?;
    let obj = match value.as_object_mut() {
        Some(o) => o,
        None => return Ok(body.clone()),
    };
    // Default the issued_token_type when the upstream omitted it; RFC
    // 8693 §2.2.1 says the field is REQUIRED but real-world ASes
    // often elide it on JWT responses. Wrapper-level metadata is
    // safe to set without re-signing the token itself.
    if !obj.contains_key("issued_token_type") {
        obj.insert(
            "issued_token_type".to_string(),
            serde_json::Value::String(ISSUED_TOKEN_TYPE_JWT.to_string()),
        );
    }
    let Some(signing_key) = broker_signing_key else {
        return Ok(serialize_value(&value));
    };
    let access_token = match obj.get("access_token").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return Err(anyhow::anyhow!("upstream response missing access_token")),
    };
    let mutations = act_mutations(&access_token, subject, agent_profile)?;
    let rewritten =
        crate::at_jwt::resign_at_jwt(&access_token, signing_key, broker_issuer, &mutations)?;
    obj.insert(
        "access_token".to_string(),
        serde_json::Value::String(rewritten),
    );
    Ok(serialize_value(&value))
}

/// Build the claims a freshly signed broker token adds for RFC 8693.
fn act_mutations(
    jwt: &str,
    subject: &SubjectClaims,
    agent_profile: Option<&AgentProfileInputs>,
) -> Result<serde_json::Map<String, serde_json::Value>, anyhow::Error> {
    let mut parts = jwt.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("access token is not a JWT"))?;
    let payload = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("access token is not a JWT"))?;
    let _signature = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("access token is not a JWT"))?;
    if parts.next().is_some() {
        return Err(anyhow::anyhow!("access token is not a three-segment JWT"));
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| anyhow::anyhow!("access token payload decode failed: {e}"))?;
    let value: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| anyhow::anyhow!("access token payload is not JSON: {e}"))?;
    // Build the new act envelope. Existing `act` (if any) is preserved
    // as the inner act for chain auditing.
    let prior_act = value.get("act").cloned();
    let mut new_act = serde_json::Map::new();
    if let Some(sub) = subject.sub.as_ref() {
        new_act.insert("sub".to_string(), serde_json::Value::String(sub.clone()));
    }
    if let Some(iss) = subject.iss.as_ref() {
        new_act.insert("iss".to_string(), serde_json::Value::String(iss.clone()));
    }
    if let Some(prev) = prior_act {
        new_act.insert("act".to_string(), prev);
    }
    let mut mutations = serde_json::Map::new();
    mutations.insert("act".to_string(), serde_json::Value::Object(new_act));

    // WOR-521: stamp the draft-oauth-transaction-tokens-for-agents
    // claim set when the exchange requested the agent profile.
    if let Some(ap) = agent_profile {
        mutations.insert(
            "actor".to_string(),
            serde_json::Value::String(ap.actor.clone()),
        );
        mutations.insert(
            "principal".to_string(),
            serde_json::Value::String(ap.principal.clone()),
        );
        mutations.insert("tnx".to_string(), serde_json::Value::String(ap.tnx.clone()));
        if let Some(purpose) = ap.purpose.as_deref() {
            mutations.insert(
                "purpose".to_string(),
                serde_json::Value::String(crate::at_jwt::truncate_purpose(purpose)),
            );
        }
    }
    Ok(mutations)
}

/// Serialize a JSON value into bytes::Bytes for response assembly.
fn serialize_value(value: &serde_json::Value) -> bytes::Bytes {
    bytes::Bytes::from(serde_json::to_vec(value).unwrap_or_default())
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
    use tower::ServiceExt;

    /// Encode a JSON value as a JWS Compact Serialization fixture. The
    /// signature segment is a fixed dummy value; the broker only
    /// inspects the payload in 4D.2.
    fn fixture_jwt(payload: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({"alg":"none","typ":"JWT"})).unwrap());
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        format!("{header}.{p}.sig")
    }

    fn enabled_config() -> McpGatewayConfig {
        McpGatewayConfig {
            token_exchange_enabled: true,
            subject_token_issuers: vec!["https://idp.example".to_string()],
            allowed_token_exchange_audiences: vec!["https://api.downstream".to_string()],
            // Closed port; upstream calls return BAD_GATEWAY.
            upstream_token_endpoint_url: "http://127.0.0.1:1/token".to_string(),
            ..McpGatewayConfig::default()
        }
    }

    fn build_app(cfg: McpGatewayConfig) -> Router {
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        crate::router(Arc::new(cfg), store)
    }

    async fn post_form(app: Router, uri: &str, body: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    #[tokio::test]
    async fn disabled_returns_404() {
        let mut cfg = enabled_config();
        cfg.token_exchange_enabled = false;
        let app = build_app(cfg);
        let body = format!(
            "grant_type={}&subject_token=tok&subject_token_type={}&client_id=cli",
            urlencode(TOKEN_EXCHANGE_GRANT_TYPE),
            urlencode(SUBJECT_TOKEN_TYPE_ACCESS),
        );
        let (status, body) = post_form(app, "/mcp/oauth/token", &body).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("unsupported_grant_type"));
    }

    #[tokio::test]
    async fn missing_subject_token_returns_invalid_request() {
        let app = build_app(enabled_config());
        let body = format!(
            "grant_type={}&subject_token_type={}&client_id=cli",
            urlencode(TOKEN_EXCHANGE_GRANT_TYPE),
            urlencode(SUBJECT_TOKEN_TYPE_ACCESS),
        );
        let (status, body) = post_form(app, "/mcp/oauth/token", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_request"));
        assert!(body.contains("subject_token"));
    }

    #[tokio::test]
    async fn unknown_issuer_rejected() {
        let app = build_app(enabled_config());
        let token = fixture_jwt(serde_json::json!({
            "iss": "https://attacker.example",
            "sub": "alice",
        }));
        let body = format!(
            "grant_type={}&subject_token={}&subject_token_type={}&client_id=cli",
            urlencode(TOKEN_EXCHANGE_GRANT_TYPE),
            urlencode(&token),
            urlencode(SUBJECT_TOKEN_TYPE_ACCESS),
        );
        let (status, body) = post_form(app, "/mcp/oauth/token", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_request"));
        assert!(body.contains("not enrolled"));
    }

    #[tokio::test]
    async fn audience_not_allowed_returns_invalid_target() {
        let app = build_app(enabled_config());
        let token = fixture_jwt(serde_json::json!({
            "iss": "https://idp.example",
            "sub": "alice",
        }));
        let body = format!(
            "grant_type={}&subject_token={}&subject_token_type={}&audience={}&client_id=cli",
            urlencode(TOKEN_EXCHANGE_GRANT_TYPE),
            urlencode(&token),
            urlencode(SUBJECT_TOKEN_TYPE_ACCESS),
            urlencode("https://other.example"),
        );
        let (status, body) = post_form(app, "/mcp/oauth/token", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_target"));
    }

    #[tokio::test]
    async fn chain_too_deep_rejected() {
        let mut cfg = enabled_config();
        cfg.token_exchange_max_chain_depth = 2;
        let app = build_app(cfg);
        // Build a 2-deep act chain so the next exchange would reach
        // depth 3 == limit. The handler rejects when current depth
        // is >= max, so depth=2 with limit=2 fails.
        let token = fixture_jwt(serde_json::json!({
            "iss": "https://idp.example",
            "sub": "alice",
            "act": {
                "sub": "service-a",
                "act": {"sub": "service-b"},
            },
        }));
        let body = format!(
            "grant_type={}&subject_token={}&subject_token_type={}&client_id=cli",
            urlencode(TOKEN_EXCHANGE_GRANT_TYPE),
            urlencode(&token),
            urlencode(SUBJECT_TOKEN_TYPE_ACCESS),
        );
        let (status, body) = post_form(app, "/mcp/oauth/token", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_request"));
        assert!(body.contains("chain too deep"));
    }

    #[tokio::test]
    async fn policy_valid_exchange_without_dpop_is_rejected_before_upstream() {
        // The subject is an access token, so reaching the upstream also
        // requires a DPoP proof whose ath covers it. A policy-valid
        // exchange with no proof must stop at the last pre-network gate.
        let app = build_app(enabled_config());
        let token = fixture_jwt(serde_json::json!({
            "iss": "https://idp.example",
            "sub": "alice",
        }));
        let body = format!(
            "grant_type={}&subject_token={}&subject_token_type={}&audience={}&client_id=cli",
            urlencode(TOKEN_EXCHANGE_GRANT_TYPE),
            urlencode(&token),
            urlencode(SUBJECT_TOKEN_TYPE_ACCESS),
            urlencode("https://api.downstream"),
        );
        let (status, body) = post_form(app, "/mcp/oauth/token", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_dpop_proof"));
    }

    /// WOR-40: token exchange with no client authentication material
    /// MUST be rejected with `invalid_client` 401. Pre-fix the
    /// handler short-circuited on `subject_token` parsing and never
    /// reached `detect_method`, so requests with no `client_id` and
    /// no Authorization header silently passed the client-auth gate.
    #[tokio::test]
    async fn no_client_auth_returns_401() {
        let app = build_app(enabled_config());
        let token = fixture_jwt(serde_json::json!({
            "iss": "https://idp.example",
            "sub": "alice",
        }));
        let body = format!(
            "grant_type={}&subject_token={}&subject_token_type={}",
            urlencode(TOKEN_EXCHANGE_GRANT_TYPE),
            urlencode(&token),
            urlencode(SUBJECT_TOKEN_TYPE_ACCESS),
        );
        let (status, body) = post_form(app, "/mcp/oauth/token", &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("invalid_client"));
    }

    /// WOR-40: an unaccepted client-auth method is rejected before the
    /// token-exchange handler sees the request. Configure the broker
    /// to accept only `client_secret_basic`; a public-client (`none`)
    /// request must trip the gate.
    #[tokio::test]
    async fn unaccepted_client_auth_method_rejected() {
        let mut cfg = enabled_config();
        cfg.accepted_client_auth_methods = vec!["client_secret_basic".to_string()];
        let app = build_app(cfg);
        let token = fixture_jwt(serde_json::json!({
            "iss": "https://idp.example",
            "sub": "alice",
        }));
        let body = format!(
            "grant_type={}&subject_token={}&subject_token_type={}&client_id=cli",
            urlencode(TOKEN_EXCHANGE_GRANT_TYPE),
            urlencode(&token),
            urlencode(SUBJECT_TOKEN_TYPE_ACCESS),
        );
        let (status, body) = post_form(app, "/mcp/oauth/token", &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("invalid_client"));
    }

    /// WOR-40: `subject_token_type` other than the access-token URN
    /// MUST be rejected with `unsupported_token_type` 400. The broker
    /// only models access-token subjects; forwarding an id_token or
    /// JWT-typed subject would let a caller bypass the issuer
    /// allowlist by smuggling a different token shape.
    #[tokio::test]
    async fn unsupported_subject_token_type_rejected() {
        let app = build_app(enabled_config());
        let token = fixture_jwt(serde_json::json!({
            "iss": "https://idp.example",
            "sub": "alice",
        }));
        let body = format!(
            "grant_type={}&subject_token={}&subject_token_type={}&client_id=cli",
            urlencode(TOKEN_EXCHANGE_GRANT_TYPE),
            urlencode(&token),
            urlencode("urn:ietf:params:oauth:token-type:jwt"),
        );
        let (status, body) = post_form(app, "/mcp/oauth/token", &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("unsupported_token_type"));
    }

    #[test]
    fn chain_depth_math_handles_all_levels() {
        // No act -> depth 0.
        let none = SubjectClaims {
            iss: Some("a".into()),
            sub: Some("b".into()),
            act: None,
        };
        assert_eq!(chain_depth(&none), 0);
        // Single act -> depth 1.
        let one = SubjectClaims {
            iss: Some("a".into()),
            sub: Some("b".into()),
            act: Some(Box::new(ActClaim {
                iss: None,
                sub: Some("svc".into()),
                act: None,
            })),
        };
        assert_eq!(chain_depth(&one), 1);
        // Three nested acts -> depth 3.
        let three = SubjectClaims {
            iss: Some("a".into()),
            sub: Some("b".into()),
            act: Some(Box::new(ActClaim {
                iss: None,
                sub: Some("svc-1".into()),
                act: Some(Box::new(ActClaim {
                    iss: None,
                    sub: Some("svc-2".into()),
                    act: Some(Box::new(ActClaim {
                        iss: None,
                        sub: Some("svc-3".into()),
                        act: None,
                    })),
                })),
            })),
        };
        assert_eq!(chain_depth(&three), 3);
    }

    /// WOR-47: when the broker has no signing key, `inject_act_envelope`
    /// MUST NOT mutate the upstream JWT payload. Rewriting the payload
    /// while preserving the original signature produces a token that
    /// fails verification at every resource server.
    #[test]
    fn envelope_passthrough_when_broker_cannot_resign() {
        let inner_jwt = fixture_jwt(serde_json::json!({
            "iss": "https://idp.example",
            "sub": "alice",
            "act": {"sub": "service-a"},
        }));
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "access_token": inner_jwt.clone(),
                "token_type": "Bearer",
                "issued_token_type": ISSUED_TOKEN_TYPE_JWT,
            }))
            .unwrap(),
        );
        let subject = SubjectClaims {
            iss: Some("https://idp.example".into()),
            sub: Some("alice".into()),
            act: None,
        };
        // No signing key: pass-through.
        let rewritten =
            inject_act_envelope(&body, &subject, None, None, "https://broker.example").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        // access_token is unchanged.
        assert_eq!(parsed["access_token"].as_str().unwrap(), inner_jwt);
        // Decoded payload still carries the original act ("service-a"),
        // not a broker-injected envelope keyed on alice.
        let payload_b64 = parsed["access_token"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(claims["act"]["sub"], "service-a");
        assert!(claims["act"].get("act").is_none());
    }

    #[test]
    fn envelope_with_broker_key_is_resigned_after_act_mutation() {
        let inner_jwt = fixture_jwt(serde_json::json!({
            "iss": "https://idp.example",
            "sub": "alice",
            "aud": "https://api.downstream",
            "exp": 4102444800_i64,
            "iat": 1700000000_i64,
            "jti": "old-jti",
            "client_id": "client-1"
        }));
        let body = bytes::Bytes::from(
            serde_json::json!({
                "access_token": inner_jwt,
                "token_type": "Bearer",
                "issued_token_type": ISSUED_TOKEN_TYPE_JWT
            })
            .to_string(),
        );
        let subject = SubjectClaims {
            iss: Some("https://idp.example".into()),
            sub: Some("alice".into()),
            act: None,
        };
        let key = crate::config::JwkKey::Pem {
            pem: include_str!("../../sbproxy-modules/src/auth/dpop_test_ec_p256.pem").to_string(),
            alg: "ES256".to_string(),
            kid: Some("broker-key".to_string()),
        };

        let rewritten =
            inject_act_envelope(&body, &subject, Some(&key), None, "https://broker.example")
                .unwrap();
        let wrapper: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        let token = wrapper["access_token"].as_str().unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(claims["iss"], "https://broker.example");
        assert_eq!(claims["act"]["sub"], "alice");
        assert_ne!(token.split('.').nth(2), Some("sig"));
    }

    #[test]
    fn exchanged_token_preserves_act_while_signing_dpop_and_mtls_bindings() {
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "MCP_GATEWAY_BASE_URL",
            Some("https://broker.example"),
        )]);
        let access_token = fixture_jwt(serde_json::json!({
            "iss": "https://idp.example",
            "sub": "alice",
            "aud": "https://api.downstream",
            "exp": 4102444800_i64,
            "iat": 1700000000_i64,
            "jti": "old-jti",
            "client_id": "client-1",
            "act": {"sub": "delegating-service"}
        }));
        let body = bytes::Bytes::from(
            serde_json::json!({"access_token": access_token, "token_type": "Bearer"}).to_string(),
        );
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
            "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY"
        }))
        .unwrap();
        let proof = DpopProof {
            jwk,
            jti: "exchange-jti".to_string(),
            htm: "POST".to_string(),
            htu: "https://broker.example/mcp/oauth/token".to_string(),
            iat: 0,
            nonce: None,
            ath: Some("subject-token-hash".to_string()),
            raw_jwt: "header.payload.proof-signature".to_string(),
        };
        let mut cfg = enabled_config();
        cfg.broker_signing_key = Some(crate::config::JwkKey::Pem {
            pem: include_str!("../../sbproxy-modules/src/auth/dpop_test_ec_p256.pem").to_string(),
            alg: "ES256".to_string(),
            kid: Some("broker-key".to_string()),
        });
        let certificate = crate::VerifiedClientCertificate {
            x5t_s256: "verified-certificate-thumbprint".to_string(),
        };

        let bound = apply_sender_bindings(&cfg, body, Some(&proof), Some(&certificate)).unwrap();
        let wrapper: serde_json::Value = serde_json::from_slice(&bound).unwrap();
        let token = wrapper["access_token"].as_str().unwrap();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(claims["act"]["sub"], "delegating-service");
        assert_eq!(
            claims["cnf"]["jkt"],
            crate::dpop::jwk_thumbprint(&proof.jwk).unwrap()
        );
        assert_eq!(claims["cnf"]["x5t#S256"], "verified-certificate-thumbprint");
        assert_ne!(token.split('.').nth(2), Some("sig"));
    }

    /// WOR-521: the agent-profile claim set (actor / principal / tnx /
    /// purpose) lands on the rewritten payload alongside the act
    /// envelope when an `AgentProfileInputs` is supplied.
    #[test]
    fn rewrite_act_stamps_agent_profile_claims() {
        use base64::Engine;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({"sub": "agent-client", "iss": "https://idp"}))
                .unwrap(),
        );
        let jwt = format!("hdr.{payload}.sig");
        let subject = SubjectClaims {
            iss: Some("https://idp".into()),
            sub: Some("alice".into()),
            act: None,
        };
        let ap = AgentProfileInputs {
            actor: "agent-client".into(),
            principal: "alice".into(),
            tnx: "abc123".into(),
            purpose: Some("clean up staging".into()),
        };
        let v = act_mutations(&jwt, &subject, Some(&ap)).expect("claims");
        assert_eq!(v["actor"], "agent-client");
        assert_eq!(v["principal"], "alice");
        assert_eq!(v["tnx"], "abc123");
        assert_eq!(v["purpose"], "clean up staging");
        // The act envelope (the human at the top of the chain) is still
        // built so the agent profile and the act chain coexist.
        assert_eq!(v["act"]["sub"], "alice");
    }

    /// Without an agent profile, no agent-profile claims are added: a
    /// classic act-only rewrite stays clean.
    #[test]
    fn rewrite_act_without_agent_profile_adds_no_agent_claims() {
        use base64::Engine;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({"sub": "svc"})).unwrap());
        let jwt = format!("hdr.{payload}.sig");
        let subject = SubjectClaims {
            iss: None,
            sub: Some("alice".into()),
            act: None,
        };
        let v = act_mutations(&jwt, &subject, None).expect("claims");
        assert!(v.get("actor").is_none());
        assert!(v.get("principal").is_none());
        assert!(v.get("tnx").is_none());
    }

    /// `gen_transaction_id` produces a 32-hex-char (128-bit) id and is
    /// unique across calls.
    #[test]
    fn transaction_id_is_128_bit_hex_and_unique() {
        let a = gen_transaction_id();
        let b = gen_transaction_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    /// Tiny URL-encoder good enough for the fixed-shape test bodies.
    /// Escapes the chars we actually use (`:`, `/`, `?`, `=`, `&`,
    /// `+`, `.`, `-`, `_`).
    fn urlencode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char)
                }
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    }
}
