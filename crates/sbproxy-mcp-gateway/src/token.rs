// /token handler for the MCP OAuth 2.1 broker.
//
// Accepts `application/x-www-form-urlencoded` per RFC 6749 §3.2 and
// forwards the request to the upstream Authorization Server's token
// endpoint, injecting the RFC 8707 `resource` parameter when missing.
//
// Supported grants:
//   * `authorization_code` (with PKCE)
//   * `refresh_token` (rotation enforced for public clients)
//   * `client_credentials`
//
// Rejected:
//   * `password` (RFC 6749 §4.3 grant; OAuth 2.1 forbids it)
//   * Anything else returns `unsupported_grant_type`.

use std::collections::HashMap;
use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form, Json,
};

use crate::client_auth::{detect_method, ensure_method_accepted, ClientAuthMethod};
use crate::dpop::{jwk_thumbprint, parse_and_verify, DpopError, DpopProof};
use crate::AppState;

/// Header name for the DPoP proof JWT (RFC 9449 §4).
const DPOP_HEADER: &str = "DPoP";
/// Header name for the AS-issued DPoP nonce (RFC 9449 §8).
pub(crate) const DPOP_NONCE_HEADER: &str = "DPoP-Nonce";

// --- Error helpers ---

/// Render an OAuth-compliant error response.
pub(crate) fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

/// Render an OAuth error response that also carries a `DPoP-Nonce`
/// header. RFC 9449 §8 requires the AS to deliver a fresh nonce in the
/// 401 response so the client can retry with the nonce embedded in the
/// proof.
pub(crate) fn dpop_nonce_challenge(error: &str, description: &str, nonce: &str) -> Response {
    let mut resp = oauth_error(StatusCode::UNAUTHORIZED, error, description);
    let headers = resp.headers_mut();
    if let Ok(value) =
        format!("DPoP error=\"use_dpop_nonce\", error_description=\"{description}\"").parse()
    {
        headers.insert(axum::http::header::WWW_AUTHENTICATE, value);
    }
    if let Ok(value) = nonce.parse() {
        headers.insert(DPOP_NONCE_HEADER, value);
    }
    resp
}

/// Build the canonical /token URL from broker config. Tests use a
/// loopback URL at port 1; production deployments derive the host from
/// `MCP_GATEWAY_BASE_URL` (the same env hook the well-known doc reads).
fn token_endpoint_url_for_proof(cfg: &crate::config::McpGatewayConfig) -> Option<url::Url> {
    let base = std::env::var("MCP_GATEWAY_BASE_URL").ok()?;
    let path = cfg.base_path.trim_end_matches('/');
    let full = format!("{}{}/token", base.trim_end_matches('/'), path);
    url::Url::parse(&full).ok()
}

// --- Handler ---

/// `POST {base_path}/token` handler.
pub async fn token(
    State(app): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let cfg = &app.config;

    // --- Grant type gating ---
    let grant_type = match form.get("grant_type") {
        Some(g) if !g.is_empty() => g.clone(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing grant_type",
            );
        }
    };

    // Pre-dispatch validation: every grant type that touches the
    // token endpoint goes through the same security preflight (DPoP
    // proof + client-auth detection + accepted-method gate). WOR-40
    // pulled these out of the legacy-grant branch because the
    // RFC 8693 token-exchange branch used to skip them entirely.
    match grant_type.as_str() {
        "password" => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "password grant is forbidden by OAuth 2.1",
            );
        }
        "authorization_code"
        | "refresh_token"
        | "client_credentials"
        | crate::device_code::DEVICE_CODE_GRANT_TYPE
        | crate::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE => {
            // Accepted; fall through to the shared preflight.
        }
        other => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                &format!("unsupported grant_type {other:?}"),
            );
        }
    }

    // --- DPoP proof handling (RFC 9449) ---
    //
    // Process DPoP before client-auth so the nonce challenge is
    // emitted before the broker forwards anything upstream. The
    // returned `dpop_proof` (if any) is used post-issuance to bind
    // the access token via `cnf.jkt`.
    let dpop_proof = match process_dpop(&app, &headers).await {
        Ok(opt) => {
            if opt.is_some() {
                crate::metrics::record_dpop("verified");
            }
            opt
        }
        Err(DpopProcessError::NonceRequired(desc, nonce)) => {
            crate::metrics::record_dpop("nonce_required");
            return dpop_nonce_challenge("invalid_dpop_proof", &desc, &nonce);
        }
        Err(DpopProcessError::ProofInvalid(desc)) => {
            crate::metrics::record_dpop("rejected");
            tracing::info!(
                target: "mcp_gateway::decision",
                event = "mcp_oauth_dpop_decision",
                outcome = "rejected",
                reason = %desc,
                "DPoP proof verification failed"
            );
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_dpop_proof", &desc);
        }
    };

    // --- Client authentication detection ---
    let (method, cid) = match detect_method(&headers, &form) {
        Ok(m) => m,
        Err(e) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                &format!("client auth detection failed: {e}"),
            );
        }
    };
    if let Err(e) = ensure_method_accepted(method, &cfg.accepted_client_auth_methods) {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", &e.to_string());
    }

    // --- Sub-handlers for grants that do not forward upstream ---
    //
    // device_code and token_exchange manage their own response
    // shaping. Both must run AFTER the preflight above so DPoP and
    // client-auth gates apply uniformly (WOR-40).
    match grant_type.as_str() {
        crate::device_code::DEVICE_CODE_GRANT_TYPE => {
            return handle_device_code_grant(&app, &form, dpop_proof.as_ref()).await;
        }
        crate::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE => {
            return crate::token_exchange::handle_token_exchange(
                &app,
                &form,
                method,
                dpop_proof.as_ref(),
            )
            .await;
        }
        _ => {}
    }

    // --- CIMD client_id handling ---
    //
    // If the inbound client_id is an https URL we treat it as a CIMD
    // reference and resolve the document through the cache. CIMD
    // clients are public; the only acceptable token_endpoint_auth_method
    // is `none`. A document declaring `client_secret_*` is rejected
    // with `invalid_client` (the parecki draft is explicit that CIMD
    // is for public clients with PKCE).
    let cid_str: Option<&str> = cid.as_deref();
    // `Option<&str>` is `Copy`, so this stays available for the CIMD ->
    // DCR translation branch further down without re-deriving whether
    // the client_id is CIMD-shaped or re-unwrapping `cid_str`.
    let cimd_url: Option<&str> = cid_str
        .filter(|_| cfg.cimd_enabled)
        .filter(|s| is_https_url(s));
    let cimd_doc = if let Some(cid_url) = cimd_url {
        match &app.cimd_cache {
            Some(cache) => match cache
                .get_or_fetch(
                    cid_url,
                    &sbproxy_httpkit::token_bearing_outbound(),
                    cfg.cimd_max_doc_bytes,
                )
                .await
            {
                Ok(doc) => Some(doc),
                Err(e) => {
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        &format!("CIMD resolve failed: {e}"),
                    );
                }
            },
            None => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "URL-shaped client_id received but CIMD cache is not configured",
                );
            }
        }
    } else {
        None
    };

    if let Some(doc) = cimd_doc.as_ref() {
        // CIMD clients are public; the inbound auth method MUST be `none`.
        if method != ClientAuthMethod::None {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "CIMD clients are public; only token_endpoint_auth_method=none is accepted",
            );
        }
        // Anti-spoof: the document MUST also declare `none` (or omit
        // the field, defaulting to `none`).
        if let Some(declared) = doc.token_endpoint_auth_method.as_deref() {
            if declared != "none" {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "CIMD document declares an unsupported token_endpoint_auth_method",
                );
            }
        }
    }

    // --- Per-grant validation ---
    if grant_type == "authorization_code" {
        if !form.contains_key("code") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "authorization_code requires `code`",
            );
        }
        if !form.contains_key("redirect_uri") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "authorization_code requires `redirect_uri`",
            );
        }
        if !form.contains_key("code_verifier") {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "OAuth 2.1 requires PKCE code_verifier on authorization_code",
            );
        }
    }
    if grant_type == "refresh_token" && !form.contains_key("refresh_token") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token grant requires `refresh_token`",
        );
    }

    // --- Build forwarded form ---
    let mut forwarded = form.clone();
    if !forwarded.contains_key("resource") && !cfg.resource_uri.is_empty() {
        // RFC 8707: bind the issued token to a specific resource.
        forwarded.insert("resource".to_string(), cfg.resource_uri.clone());
    }
    // CIMD → DCR translation: swap the URL-shaped client_id for the
    // upstream-assigned opaque client_id when translation is enabled.
    if let (Some(doc), Some(cid_url), true) =
        (cimd_doc.as_ref(), cimd_url, cfg.dcr_translate_cimd_clients)
    {
        match resolve_dcr_for_token(&app, cid_url, doc).await {
            Ok(registered) => {
                forwarded.insert("client_id".to_string(), registered);
            }
            Err(e) => {
                return oauth_error(
                    StatusCode::BAD_GATEWAY,
                    "server_error",
                    &format!("CIMD translation failed: {e}"),
                );
            }
        }
    }
    let original_refresh_token = forwarded.get("refresh_token").cloned();

    // --- Forward to upstream ---
    if cfg.upstream_token_endpoint_url.is_empty() {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "upstream_token_endpoint_url not configured",
        );
    }

    // WOR-170: token-bearing endpoint; refuse redirects so a malicious
    // upstream cannot 302 the Authorization header cross-origin.
    let http = sbproxy_httpkit::token_bearing_outbound();
    let mut req = http.post(&cfg.upstream_token_endpoint_url).form(&forwarded);
    // Replay the Authorization header for client_secret_basic so the
    // upstream sees the same credentials we accepted.
    if method == ClientAuthMethod::ClientSecretBasic {
        if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
            req = req.header(axum::http::header::AUTHORIZATION, value.clone());
        }
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                error = %sbproxy_httpkit::request_error_summary(&e),
                "upstream /token call failed"
            );
            return oauth_error(
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
                "upstream /token body read failed"
            );
            return oauth_error(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "upstream token endpoint body unreadable",
            );
        }
    };

    // --- Refresh-token rotation enforcement ---
    if grant_type == "refresh_token" && method == ClientAuthMethod::None && status.is_success() {
        let parsed: serde_json::Value = match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "upstream /token returned non-JSON success");
                return oauth_error(
                    StatusCode::BAD_GATEWAY,
                    "server_error",
                    "upstream token response was not JSON",
                );
            }
        };
        let new_refresh = parsed
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        match (original_refresh_token, new_refresh) {
            (Some(old), Some(new)) if old == new => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh_token rotation required for public clients (OAuth 2.1 §4.3.1)",
                );
            }
            (_, None) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "upstream did not issue a new refresh_token; rotation required",
                );
            }
            _ => {}
        }
    }

    // --- DPoP cnf.jkt injection (RFC 9449 §6) ---
    //
    // When the request carried a valid DPoP proof and the upstream
    // returned a 2xx, the broker either:
    //   * passes the upstream body through unchanged (when the broker
    //     has no signing key), preserving the upstream's `token_type`
    //     so resource servers cannot be tricked into accepting a
    //     bearer-replayable token labeled "DPoP"; or
    //   * rewrites the wrapper for opaque tokens (no JWT payload to
    //     bind), or re-issues a fresh broker-signed JWT carrying
    //     `cnf.jkt` inside the JWT payload (broker re-issuance is a
    //     follow-up, see at_jwt::mint_at_jwt).
    //
    // Pre-WOR-47 the broker rewrote the wrapper to claim `token_type:
    // DPoP` and inject a top-level `cnf.jkt` even though the inner JWT
    // had no `cnf` claim. Resource servers (mcp_resource_server) verify
    // `cnf.jkt` only inside the JWT payload, so the rewrite produced
    // bearer-replayable tokens dressed up as sender-constrained ones.
    let body_bytes = if let (Some(proof), true) = (dpop_proof.as_ref(), status.is_success()) {
        match inject_cnf_jkt(&body_bytes, proof, cfg.broker_signing_key.as_ref()) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "DPoP cnf.jkt injection failed; passing upstream body through");
                body_bytes
            }
        }
    } else {
        body_bytes
    };

    // --- RFC 8705 cnf.x5t#S256 injection (WOR-517) ---
    //
    // When the inbound request rode an mTLS channel (cert handed over
    // via the XFCC header), and the upstream issuance succeeded, bind
    // the access token to the client cert via the SHA-256 thumbprint
    // RFC 8705 §3.1 specifies. JWT-shaped tokens are passed through
    // when the broker cannot re-sign (same WOR-47 fail-safe the DPoP
    // path uses); opaque tokens get the wrapper-level cnf so resource
    // servers see the binding via introspection.
    let body_bytes = if status.is_success() {
        if let Some(cert_der) = crate::mtls_binding::extract_client_cert_der(&headers) {
            match crate::mtls_binding::inject_cnf_x5t_s256(
                &body_bytes,
                &cert_der,
                cfg.broker_signing_key.as_ref(),
            ) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "mTLS cnf.x5t#S256 injection failed; passing body through"
                    );
                    body_bytes
                }
            }
        } else {
            body_bytes
        }
    } else {
        body_bytes
    };

    // --- Pass-through response body ---
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
            tracing::error!(error = %e, "failed to assemble token response");
            oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "response assembly failed",
            )
        });
    // Disallow caching of token responses per RFC 6749 §5.1.
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert("Pragma", axum::http::HeaderValue::from_static("no-cache"));
    response
}

// --- DPoP helpers ---

/// Errors that can short-circuit the /token handler before the upstream
/// call. Surfaced as either an `invalid_dpop_proof` 400 or a
/// `use_dpop_nonce` 401 challenge.
pub(crate) enum DpopProcessError {
    /// Proof was missing, malformed, or signature-invalid.
    ProofInvalid(String),
    /// Nonce was required but missing or invalid. Carries the
    /// description and a fresh nonce to embed in the response header.
    NonceRequired(String, String),
}

/// Run the per-request DPoP pipeline. Returns:
///   * `Ok(Some(proof))` when a valid proof was supplied
///   * `Ok(None)` when no DPoP header was present and none was required
///   * `Err(_)` when the proof was invalid or a nonce challenge is owed
pub(crate) async fn process_dpop(
    app: &AppState,
    headers: &HeaderMap,
) -> Result<Option<DpopProof>, DpopProcessError> {
    let cfg = &app.config;
    let raw_header = headers.get(DPOP_HEADER).and_then(|v| v.to_str().ok());

    // --- No DPoP header path ---
    let Some(raw) = raw_header else {
        if cfg.dpop_require_nonce {
            // Even nonce-required deployments need a way to bootstrap
            // the round-trip: emit a fresh nonce so the client can
            // retry with both DPoP and the nonce.
            let nonce = match &app.dpop_nonce {
                Some(issuer) => issuer.issue().await.map_err(|e| {
                    DpopProcessError::ProofInvalid(format!("nonce issuance failed: {e}"))
                })?,
                None => {
                    return Err(DpopProcessError::ProofInvalid(
                        "DPoP required but no nonce issuer configured".to_string(),
                    ));
                }
            };
            return Err(DpopProcessError::NonceRequired(
                "DPoP proof with nonce is required".to_string(),
                nonce,
            ));
        }
        return Ok(None);
    };

    // --- Verify the proof ---
    let token_url = match token_endpoint_url_for_proof(cfg) {
        Some(u) => u,
        None => {
            // Without MCP_GATEWAY_BASE_URL we cannot construct the
            // canonical URL the proof's `htu` is matched against. Fail
            // closed whenever DPoP is advertised so a misconfigured
            // deployment cannot silently downgrade a sender-constrained
            // proof to a no-op (WOR-47). The startup validator in
            // `validate_dpop_startup` should catch this before traffic
            // hits the broker; this branch is the second line of
            // defense for hot-reloaded configs.
            if cfg.dpop_supported || cfg.dpop_require_nonce {
                return Err(DpopProcessError::ProofInvalid(
                    "MCP_GATEWAY_BASE_URL not set; refusing to validate DPoP htu".to_string(),
                ));
            }
            tracing::debug!("MCP_GATEWAY_BASE_URL not set; DPoP not advertised; ignoring proof");
            return Ok(None);
        }
    };
    let proof = match parse_and_verify(
        raw,
        "POST",
        &token_url,
        Duration::from_secs(cfg.dpop_max_clock_skew_secs),
    ) {
        Ok(p) => p,
        Err(e) => return Err(DpopProcessError::ProofInvalid(format!("{e}"))),
    };

    // --- Nonce check (optional) ---
    if cfg.dpop_require_nonce {
        let nonce_value = proof.nonce.clone();
        let issuer = app.dpop_nonce.as_ref().ok_or_else(|| {
            DpopProcessError::ProofInvalid(
                "dpop_require_nonce is set but no DpopNonceIssuer is configured".to_string(),
            )
        })?;
        match nonce_value {
            Some(n) => {
                if let Err(e) = issuer.validate(&n).await {
                    let fresh = issuer
                        .issue()
                        .await
                        .unwrap_or_else(|_| String::from("retry"));
                    return Err(DpopProcessError::NonceRequired(format!("{e}"), fresh));
                }
            }
            None => {
                let fresh = issuer
                    .issue()
                    .await
                    .map_err(|e| DpopProcessError::ProofInvalid(format!("{e}")))?;
                return Err(DpopProcessError::NonceRequired(
                    "DPoP proof must carry a nonce claim".to_string(),
                    fresh,
                ));
            }
        }
    }

    // --- Replay check ---
    if let Some(replay) = &app.dpop_replay {
        if let Err(e) = replay.record_jti(&proof).await {
            return Err(DpopProcessError::ProofInvalid(format!("{e}")));
        }
    }

    Ok(Some(proof))
}

/// Inject `cnf.jkt` into the upstream's JSON token response.
///
/// Behavior is chosen to avoid the WOR-47 trap (bearer-replayable
/// token labeled DPoP):
///
/// * **JWT access_token + no broker signing key:** the broker cannot
///   produce a JWT with `cnf.jkt` in the payload and the resource
///   server only honours the JWT-internal claim, so the wrapper is
///   passed through unchanged. The upstream's `token_type` is
///   preserved (Bearer stays Bearer); claiming DPoP here would be a
///   security bug.
/// * **JWT access_token + broker signing key:** broker re-issuance
///   is a follow-up. For now the broker logs and passes through.
/// * **Opaque access_token (not a JWS Compact Serialization) + valid
///   proof:** the wrapper is decorated with the top-level
///   `cnf.jkt` so resource servers that consult opaque-token
///   introspection (which surfaces wrapper-level cnf) still get the
///   binding, and `token_type` is rewritten to `DPoP`. RFC 9449 §6
///   permits the binding to live next to the access_token; only the
///   JWT path requires it inside the payload.
/// * **Body not JSON-shaped:** passed through.
///
/// Visibility note: this is `pub` rather than module-private so the
/// integration test in `tests/prompt_injection_corpus.rs` can drive
/// the WOR-47 invariants directly without standing up a full HTTP
/// upstream. Production callers should keep going through `token`.
pub fn inject_cnf_jkt(
    body: &bytes::Bytes,
    proof: &DpopProof,
    broker_signing_key: Option<&crate::config::JwkKey>,
) -> Result<bytes::Bytes, DpopError> {
    let body_is_secret_reference = std::str::from_utf8(body)
        .ok()
        .is_some_and(|text| sbproxy_vault::looks_like_secret_reference_uri(text));
    if body_is_secret_reference {
        return Err(DpopError::PayloadInvalid(
            "upstream token response is a secret reference".to_string(),
        ));
    }
    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| DpopError::PayloadInvalid(format!("upstream body: {e}")))?;
    let obj = match value.as_object_mut() {
        Some(o) => o,
        None => return Ok(body.clone()),
    };
    // Inspect the access_token shape. JWS Compact Serialization is
    // three base64url segments separated by dots; everything else is
    // treated as opaque (introspection-style) tokens.
    let access_token = obj
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let token_is_jwt = access_token
        .as_deref()
        .map(|t| t.split('.').count() == 3)
        .unwrap_or(false);
    if token_is_jwt && broker_signing_key.is_none() {
        // FOLLOW-UP: when broker_signing_key is configured, re-mint
        // the access_token with `cnf.jkt` in the JWT payload via
        // crate::at_jwt::mint_at_jwt. That requires copying the
        // upstream claim set and signing it as the broker, a
        // behavior change that warrants its own design slice. Until
        // then, refuse to claim DPoP on a token we cannot bind.
        tracing::warn!(
            "DPoP proof present but broker has no signing key; preserving upstream Bearer token"
        );
        return Ok(body.clone());
    }
    let jkt = jwk_thumbprint(&proof.jwk)?;
    let mut cnf = serde_json::Map::new();
    cnf.insert("jkt".to_string(), serde_json::Value::String(jkt));
    obj.insert("cnf".to_string(), serde_json::Value::Object(cnf));
    obj.insert(
        "token_type".to_string(),
        serde_json::Value::String("DPoP".to_string()),
    );
    let serialized = serde_json::to_vec(&value)
        .map_err(|e| DpopError::PayloadInvalid(format!("serialize body: {e}")))?;
    Ok(bytes::Bytes::from(serialized))
}

// --- CIMD helpers ---

/// True when `s` parses as an https URL. Used at /token-time to
/// detect CIMD-shaped client_ids without dragging url::Url into every
/// branch.
fn is_https_url(s: &str) -> bool {
    match url::Url::parse(s) {
        Ok(u) => u.scheme() == "https",
        Err(_) => false,
    }
}

/// Same translation flow as the /authorize handler uses, factored for
/// the /token endpoint. Returns the upstream-assigned client_id to
/// substitute into the forwarded form body.
async fn resolve_dcr_for_token(
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
            anyhow::anyhow!("upstream_registration_endpoint_url required for CIMD translation")
        })?;
    let fp = crate::cimd_to_dcr::fingerprint(None, doc);
    if let Some(reg) = cache.get(cimd_url, &fp).await {
        return Ok(reg.registered_client_id);
    }
    // WOR-170: DCR translation forwards credentials to the upstream
    // registration endpoint; use the token-bearing client.
    let http = sbproxy_httpkit::token_bearing_outbound();
    let reg = crate::cimd_to_dcr::translate_cimd_to_dcr(doc, dcr_endpoint, &http).await?;
    cache.put(cimd_url, &fp, reg.clone()).await;
    Ok(reg.registered_client_id)
}

// --- Device-code grant (RFC 8628 §3.4) ---

/// Handle a `urn:ietf:params:oauth:grant-type:device_code` poll.
///
/// RFC 8628 §3.5 defines five terminal states the AS can return:
///   * `authorization_pending` (HTTP 400) - user has not yet visited
///     /verify; client should keep polling.
///   * `slow_down` (HTTP 400) - client polled faster than the
///     advertised `interval`; client should double its delay.
///   * `expired_token` (HTTP 400) - the device_code TTL elapsed.
///   * `access_denied` (HTTP 400) - user clicked "deny" on /verify.
///   * 200 with a token body - user authorized.
async fn handle_device_code_grant(
    app: &AppState,
    form: &HashMap<String, String>,
    dpop_proof: Option<&DpopProof>,
) -> Response {
    let cfg = &app.config;
    if !cfg.device_code_enabled {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "device authorization grant is disabled",
        );
    }

    let store = match app.device_code_store.as_ref() {
        Some(s) => s.clone(),
        None => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "device code store not configured",
            );
        }
    };

    let device_code = match form.get("device_code") {
        Some(s) if !s.is_empty() => s.clone(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "device_code is required",
            );
        }
    };
    let req_client_id = form.get("client_id").cloned();

    let mut state = match store.get(&device_code).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "device_code is unknown or expired",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "device_code: store get failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "device code lookup failed",
            );
        }
    };

    // --- client_id binding check ---
    //
    // RFC 8628 §3.4: the client_id on the poll MUST match the one
    // supplied at /device_authorization. Without this check an
    // attacker who learned a device_code could redeem it under a
    // different client identity.
    if let Some(rcid) = req_client_id.as_deref() {
        if rcid != state.client_id {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client_id does not match the original request",
            );
        }
    }

    // --- Expiry ---
    let now = crate::device_code::unix_now();
    if now >= state.expires_at {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "device_code expired",
        );
    }

    // --- Rate limiting ---
    let too_fast = crate::device_code::apply_poll_rate_limit(&mut state, now);
    if too_fast {
        // Persist the doubled interval so the next poll sees it.
        if let Err(e) = store.update(&device_code, &state).await {
            tracing::warn!(error = %e, "device_code: rate-limit state persist failed");
        }
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "slow_down",
            "polling interval exceeded; double your delay",
        );
    }

    // --- Status checks ---
    match state.status {
        crate::device_code::DeviceCodeStatus::Pending => {
            // Persist the new last_polled_at without changing status.
            if let Err(e) = store.update(&device_code, &state).await {
                tracing::warn!(error = %e, "device_code: poll-time persist failed");
            }
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "authorization_pending",
                "user has not yet authorized this request",
            );
        }
        crate::device_code::DeviceCodeStatus::Denied => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "user denied the authorization request",
            );
        }
        crate::device_code::DeviceCodeStatus::Authorized => {}
    }

    // --- Issue the stored token ---
    let token_value = match state.authorized_token.as_ref() {
        Some(v) => v.clone(),
        None => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "authorized state has no token",
            );
        }
    };

    // Optional cnf.jkt injection when the caller supplied a DPoP
    // proof. We always serialize through bytes so the same shared
    // helper handles bearer to DPoP rewriting.
    let body_bytes = match serde_json::to_vec(&token_value) {
        Ok(v) => bytes::Bytes::from(v),
        Err(e) => {
            tracing::error!(error = %e, "device_code: token JSON serialize failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "token serialization failed",
            );
        }
    };
    let body_bytes = if let Some(proof) = dpop_proof {
        match inject_cnf_jkt(&body_bytes, proof, cfg.broker_signing_key.as_ref()) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "device_code: cnf.jkt injection failed");
                body_bytes
            }
        }
    } else {
        body_bytes
    };

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/json;charset=UTF-8",
        )
        .body(axum::body::Body::from(body_bytes))
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "device_code: response assembly failed");
            oauth_error(
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

    // Drop the device_code state once it has been redeemed so a
    // replayed poll cannot mint a second token.
    if let Err(e) = store.delete(&device_code, &state.user_code).await {
        tracing::warn!(error = %e, "device_code: post-issue cleanup failed");
    }
    response
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

    fn test_config() -> McpGatewayConfig {
        // Default-driven fixture; override only what each test needs
        // so newly-added config fields (Wave 4D.2 device-code +
        // token-exchange) inherit sensible defaults.
        McpGatewayConfig {
            // Point at a closed port so any accidental network call
            // fails fast without flake.
            upstream_token_endpoint_url: "http://127.0.0.1:1/token".to_string(),
            upstream_authorization_server_url: "https://idp.example.com/oauth/authorize"
                .to_string(),
            resource_uri: "https://mcp.example/api".to_string(),
            allowed_redirect_uris: vec!["https://client.example/cb".to_string()],
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
    async fn rejects_password_grant() {
        let app = build_app(test_config());
        let (status, body) = post_form(
            app,
            "/mcp/oauth/token",
            "grant_type=password&username=u&password=p&client_id=cli",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("unsupported_grant_type"));
    }

    #[tokio::test]
    async fn rejects_unknown_grant_type() {
        let app = build_app(test_config());
        let (status, body) =
            post_form(app, "/mcp/oauth/token", "grant_type=magic&client_id=cli").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("unsupported_grant_type"));
    }

    #[tokio::test]
    async fn rejects_missing_grant_type() {
        let app = build_app(test_config());
        let (status, body) = post_form(app, "/mcp/oauth/token", "client_id=cli").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid_request"));
    }

    #[tokio::test]
    async fn rejects_authorization_code_without_pkce_verifier() {
        let app = build_app(test_config());
        let (status, body) = post_form(
            app,
            "/mcp/oauth/token",
            "grant_type=authorization_code&code=c1\
             &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
             &client_id=cli",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("code_verifier"));
    }

    #[tokio::test]
    async fn rejects_authorization_code_without_code() {
        let app = build_app(test_config());
        let (status, body) = post_form(
            app,
            "/mcp/oauth/token",
            "grant_type=authorization_code\
             &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
             &code_verifier=v&client_id=cli",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("code"));
    }

    #[tokio::test]
    async fn rejects_unaccepted_client_auth_method() {
        let mut cfg = test_config();
        // Only allow basic. A `none`-method request must be rejected.
        cfg.accepted_client_auth_methods = vec!["client_secret_basic".to_string()];
        let app = build_app(cfg);
        let (status, body) = post_form(
            app,
            "/mcp/oauth/token",
            "grant_type=authorization_code&code=c1\
             &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
             &code_verifier=v&client_id=cli",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("invalid_client"));
    }

    #[tokio::test]
    async fn rejects_request_with_no_client_credentials() {
        let app = build_app(test_config());
        let (status, body) = post_form(
            app,
            "/mcp/oauth/token",
            "grant_type=authorization_code&code=c1\
             &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
             &code_verifier=v",
        )
        .await;
        // No client_id at all means detect_method errors out.
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("invalid_client"));
    }

    #[tokio::test]
    async fn refresh_token_grant_requires_refresh_token() {
        let app = build_app(test_config());
        let (status, body) = post_form(
            app,
            "/mcp/oauth/token",
            "grant_type=refresh_token&client_id=cli",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("refresh_token"));
    }

    #[tokio::test]
    async fn upstream_unreachable_returns_502() {
        // All required fields present; method is `none` (allowed by default).
        let app = build_app(test_config());
        let (status, body) = post_form(
            app,
            "/mcp/oauth/token",
            "grant_type=authorization_code&code=c1\
             &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
             &code_verifier=v&client_id=cli",
        )
        .await;
        // Closed port at 127.0.0.1:1; reqwest returns a connection error.
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.contains("server_error"));
    }

    // --- DPoP integration tests ---

    fn build_app_with_dpop(cfg: McpGatewayConfig) -> Router {
        use crate::dpop::{DpopNonceIssuer, DpopReplayCache};
        use sbproxy_storage::mock::MockEphemeralKv;
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        let kv: Arc<dyn sbproxy_storage::EphemeralKv> = Arc::new(MockEphemeralKv::new());
        let replay = Arc::new(DpopReplayCache::new(
            kv.clone(),
            Duration::from_secs(cfg.dpop_jti_ttl_secs),
        ));
        let nonce = Arc::new(DpopNonceIssuer::new(
            kv,
            Duration::from_secs(cfg.dpop_nonce_ttl_secs),
        ));
        crate::router_full_with_par(
            Arc::new(cfg),
            store,
            None,
            None,
            None,
            Some(replay),
            Some(nonce),
            None,
            None,
        )
    }

    #[tokio::test]
    async fn dpop_required_with_no_proof_returns_use_dpop_nonce() {
        let mut cfg = test_config();
        cfg.dpop_require_nonce = true;
        let app = build_app_with_dpop(cfg);
        let req = Request::builder()
            .method("POST")
            .uri("/mcp/oauth/token")
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(
                "grant_type=authorization_code&code=c1\
                 &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                 &code_verifier=v&client_id=cli"
                    .to_string(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            www_auth.contains("DPoP") && www_auth.contains("use_dpop_nonce"),
            "{www_auth}"
        );
        assert!(resp.headers().contains_key("DPoP-Nonce"));
    }

    #[test]
    fn inject_cnf_jkt_adds_cnf_and_rewrites_token_type_for_opaque_token() {
        use crate::dpop::DpopProof;
        use jsonwebtoken::jwk::Jwk;
        let jwk_value = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
            "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY",
        });
        let jwk: Jwk = serde_json::from_value(jwk_value).unwrap();
        let proof = DpopProof {
            jwk,
            jti: "j1".to_string(),
            htm: "POST".to_string(),
            htu: "https://broker.example/mcp/oauth/token".to_string(),
            iat: 0,
            nonce: None,
            ath: None,
            raw_jwt: "header.payload.sig".to_string(),
        };
        // "abc" is opaque (not a 3-segment JWS), so the wrapper-level
        // cnf injection is safe; the resource server reads cnf via
        // introspection rather than the JWT payload.
        let upstream_body =
            bytes::Bytes::from(r#"{"access_token":"abc","token_type":"Bearer","expires_in":3600}"#);
        let rewritten = super::inject_cnf_jkt(&upstream_body, &proof, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(parsed["token_type"], "DPoP");
        assert!(parsed["cnf"]["jkt"].is_string());
        assert_eq!(parsed["access_token"], "abc");
    }

    /// WOR-47: a JWT-shaped access_token MUST NOT be relabeled "DPoP"
    /// when the broker has no signing key and therefore cannot mint a
    /// fresh JWT with `cnf.jkt` in the payload. Resource servers
    /// (mcp_resource_server) verify the cnf claim from the JWT
    /// payload, not the wrapper, so a wrapper-only rewrite produces
    /// bearer-replayable tokens dressed up as sender-constrained.
    #[test]
    fn inject_cnf_jkt_passes_through_jwt_when_broker_cannot_resign() {
        use crate::dpop::DpopProof;
        use jsonwebtoken::jwk::Jwk;
        let jwk_value = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
            "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY",
        });
        let jwk: Jwk = serde_json::from_value(jwk_value).unwrap();
        let proof = DpopProof {
            jwk,
            jti: "j2".to_string(),
            htm: "POST".to_string(),
            htu: "https://broker.example/mcp/oauth/token".to_string(),
            iat: 0,
            nonce: None,
            ath: None,
            raw_jwt: "header.payload.sig".to_string(),
        };
        // 3-segment JWT-shaped access_token. Broker has no signing
        // key (None) so the wrapper MUST NOT claim DPoP.
        let upstream_body = bytes::Bytes::from(
            r#"{"access_token":"hdr.payload.sig","token_type":"Bearer","expires_in":3600}"#,
        );
        let result = super::inject_cnf_jkt(&upstream_body, &proof, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed["token_type"], "Bearer");
        assert!(parsed.get("cnf").is_none());
    }

    #[tokio::test]
    async fn empty_upstream_url_returns_500() {
        let mut cfg = test_config();
        cfg.upstream_token_endpoint_url = String::new();
        let app = build_app(cfg);
        let (status, body) = post_form(
            app,
            "/mcp/oauth/token",
            "grant_type=client_credentials&client_id=cli&client_secret=shh",
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("upstream_token_endpoint_url"));
    }
}
