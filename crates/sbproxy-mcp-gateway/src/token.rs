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
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form, Json,
};
use base64::Engine;

use crate::client_auth::{detect_method, ensure_method_accepted, ClientAuthMethod};
use crate::dpop::{jwk_thumbprint, parse_and_verify, DpopError, DpopProof};
use crate::AppState;

/// Header name for the DPoP proof JWT (RFC 9449 §4).
const DPOP_HEADER: &str = "DPoP";
/// Header name for the AS-issued DPoP nonce (RFC 9449 §8).
pub(crate) const DPOP_NONCE_HEADER: &str = "DPoP-Nonce";
const MAX_TOKEN_RESPONSE_BYTES: usize = 256 * 1024;
const REFRESH_BINDING_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

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
/// config, with the legacy environment hook taking precedence.
fn token_endpoint_url_for_proof(cfg: &crate::config::McpGatewayConfig) -> Option<url::Url> {
    let base = std::env::var("MCP_GATEWAY_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| cfg.external_base_url.clone());
    if base.is_empty() {
        return None;
    }
    let path = cfg.base_path.trim_end_matches('/');
    let full = format!("{}{}/token", base.trim_end_matches('/'), path);
    url::Url::parse(&full).ok()
}

// --- Handler ---

/// `POST {base_path}/token` handler.
pub async fn token(
    State(app): State<AppState>,
    verified_client_cert: Option<Extension<crate::mtls_binding::VerifiedClientCertificate>>,
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
    let client_id = match cid.as_deref().filter(|value| !value.is_empty()) {
        Some(client_id) => client_id,
        None => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "authenticated client identity is missing",
            );
        }
    };

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
                client_id,
                headers.get(axum::http::header::AUTHORIZATION),
                dpop_proof.as_ref(),
                verified_client_cert
                    .as_ref()
                    .map(|Extension(certificate)| certificate),
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
            Some(cache) => match cache.get_or_fetch(cid_url, cfg.cimd_max_doc_bytes).await {
                Ok(doc) => Some(doc),
                Err(e) => {
                    // Same reasoning as `/authorize`: the detail names
                    // the resolved address, and the caller chose the
                    // URL. Log it, do not answer with it.
                    tracing::warn!(
                        target: "mcp_gateway::cimd",
                        error = %e,
                        client_id = %sbproxy_security::url_redact::redacted_url(cid_url),
                        "CIMD resolve failed"
                    );
                    crate::metrics::record_broker_decision("token", "cimd_unresolved");
                    return oauth_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "client_id metadata document could not be resolved",
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
    if grant_type == "authorization_code" {
        if url::Url::parse(&cfg.upstream_redirect_uri)
            .ok()
            .filter(|url| matches!(url.scheme(), "https" | "http") && url.has_host())
            .is_none()
        {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "upstream_redirect_uri must be an absolute registered HTTP(S) URI",
            );
        }
        forwarded.insert(
            "redirect_uri".to_string(),
            cfg.upstream_redirect_uri.clone(),
        );
    }
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

    if grant_type == "refresh_token" && method == ClientAuthMethod::None {
        if let Some(refresh_token) = original_refresh_token.as_deref() {
            match require_refresh_sender_binding(
                app.security_store.as_ref(),
                &app.security_namespace,
                refresh_token,
                dpop_proof.as_ref(),
            )
            .await
            {
                Ok(()) => {}
                Err(description) => {
                    return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", &description);
                }
            }
        }
    }

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
    let (_, http) = match crate::egress::endpoint_client(
        &cfg.upstream_token_endpoint_url,
        cfg.allow_insecure_loopback,
    )
    .await
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%error, "upstream token endpoint rejected by egress policy");
            return oauth_error(
                StatusCode::BAD_GATEWAY,
                "server_error",
                "upstream token endpoint is not permitted",
            );
        }
    };
    let mut req = http.post(&cfg.upstream_token_endpoint_url).form(&forwarded);
    // Replay the Authorization header for client_secret_basic so the
    // upstream sees the same credentials we accepted.
    if method == ClientAuthMethod::ClientSecretBasic {
        if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
            req = req.header(axum::http::header::AUTHORIZATION, value.clone());
        }
    }
    if let Some(proof) = dpop_proof.as_ref() {
        req = req.header(DPOP_HEADER, &proof.raw_jwt);
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
    let body_bytes = match crate::remote_body::bounded_response_body(
        resp,
        MAX_TOKEN_RESPONSE_BYTES,
        "upstream token",
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                error = %e,
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
        match (original_refresh_token.as_ref(), new_refresh.as_ref()) {
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

    if status.is_success() && method == ClientAuthMethod::None {
        if let Some(proof) = dpop_proof.as_ref() {
            let new_refresh = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                .ok()
                .and_then(|body| {
                    body.get("refresh_token")
                        .and_then(|value| value.as_str())
                        .map(str::to_string)
                });
            if let Some(new_refresh) = new_refresh {
                if let Err(error) = store_refresh_sender_binding(
                    app.security_store.as_ref(),
                    &app.security_namespace,
                    &new_refresh,
                    proof,
                )
                .await
                {
                    tracing::error!(%error, "refresh-token sender binding persistence failed");
                    return oauth_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "refresh-token sender binding could not be persisted",
                    );
                }
                if let Some(old_refresh) = original_refresh_token.as_deref() {
                    let _ = app
                        .security_store
                        .delete(&refresh_binding_key(&app.security_namespace, old_refresh))
                        .await;
                }
            }
        }
    }

    // --- DPoP cnf.jkt injection (RFC 9449 §6) ---
    //
    // When the request carried a valid DPoP proof and the upstream
    // returned a 2xx, the broker re-issues a fresh broker-signed JWT
    // carrying `cnf.jkt`. Opaque tokens and missing signing keys fail
    // closed rather than advertising a wrapper-only binding.
    //
    // Pre-WOR-47 the broker rewrote the wrapper to claim `token_type:
    // DPoP` and inject a top-level `cnf.jkt` even though the inner JWT
    // had no `cnf` claim. Resource servers (mcp_resource_server) verify
    // `cnf.jkt` only inside the JWT payload, so the rewrite produced
    // bearer-replayable tokens dressed up as sender-constrained ones.
    let body_bytes = if let (Some(proof), true) = (dpop_proof.as_ref(), status.is_success()) {
        let broker_issuer = crate::well_known::broker_issuer(cfg);
        match inject_cnf_jkt(
            &body_bytes,
            proof,
            cfg.broker_signing_key.as_ref(),
            &broker_issuer,
        ) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "DPoP cnf.jkt issuance failed closed");
                return oauth_error(
                    StatusCode::BAD_GATEWAY,
                    "server_error",
                    "broker could not issue a sender-constrained access token",
                );
            }
        }
    } else {
        body_bytes
    };

    // --- RFC 8705 cnf.x5t#S256 injection (WOR-517) ---
    //
    // When the host established a verified client certificate and the
    // upstream issuance succeeded, bind a freshly signed JWT to its
    // SHA-256 thumbprint. Raw forwarded certificate headers are never
    // read by this handler.
    let body_bytes = if status.is_success() {
        if let Some(Extension(cert)) = verified_client_cert {
            match crate::mtls_binding::inject_cnf_x5t_s256_thumbprint(
                &body_bytes,
                &cert.x5t_s256,
                cfg.broker_signing_key.as_ref(),
                &crate::well_known::broker_issuer(cfg),
            ) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "mTLS cnf.x5t#S256 issuance failed closed"
                    );
                    return oauth_error(
                        StatusCode::BAD_GATEWAY,
                        "server_error",
                        "broker could not issue an mTLS-bound access token",
                    );
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

fn refresh_binding_key(namespace: &str, refresh_token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(refresh_token.as_bytes());
    let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("refresh-binding:{namespace}:{digest}")
}

async fn store_refresh_sender_binding(
    store: &dyn sbproxy_storage::EphemeralKv,
    namespace: &str,
    refresh_token: &str,
    proof: &DpopProof,
) -> anyhow::Result<()> {
    let jkt = jwk_thumbprint(&proof.jwk)?;
    store
        .put(
            &refresh_binding_key(namespace, refresh_token),
            bytes::Bytes::from(jkt),
            REFRESH_BINDING_TTL,
        )
        .await?;
    Ok(())
}

async fn require_refresh_sender_binding(
    store: &dyn sbproxy_storage::EphemeralKv,
    namespace: &str,
    refresh_token: &str,
    proof: Option<&DpopProof>,
) -> Result<(), String> {
    let expected = store
        .get(&refresh_binding_key(namespace, refresh_token))
        .await
        .map_err(|_| "refresh-token sender binding is unavailable".to_string())?;
    let Some(expected) = expected else {
        return Err(
            "public-client refresh token is unknown or its sender binding expired".to_string(),
        );
    };
    let proof = proof.ok_or_else(|| {
        "DPoP proof required for this sender-constrained refresh token".to_string()
    })?;
    let actual = jwk_thumbprint(&proof.jwk)
        .map_err(|_| "DPoP key thumbprint could not be computed".to_string())?;
    if expected.as_ref() != actual.as_bytes() {
        return Err("DPoP key does not match this refresh token's original binding".to_string());
    }
    Ok(())
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
            // Without a configured canonical base URL we cannot construct the
            // canonical URL the proof's `htu` is matched against. Fail
            // closed whenever DPoP is advertised so a misconfigured
            // deployment cannot silently downgrade a sender-constrained
            // proof to a no-op (WOR-47). The startup validator in
            // `validate_dpop_startup` should catch this before traffic
            // hits the broker; this branch is the second line of
            // defense for hot-reloaded configs.
            if cfg.dpop_supported || cfg.dpop_require_nonce {
                return Err(DpopProcessError::ProofInvalid(
                    "external broker base URL not set; refusing to validate DPoP htu".to_string(),
                ));
            }
            tracing::debug!(
                "external broker base URL not set; DPoP not advertised; ignoring proof"
            );
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
    let replay = app.dpop_replay.as_ref().ok_or_else(|| {
        DpopProcessError::ProofInvalid(
            "DPoP replay protection is unavailable; refusing proof".to_string(),
        )
    })?;
    if let Err(e) = replay.record_jti(&proof).await {
        return Err(DpopProcessError::ProofInvalid(format!("{e}")));
    }

    Ok(Some(proof))
}

pub(crate) fn require_access_token_ath(
    proof: Option<&DpopProof>,
    access_token: &str,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};

    let proof = proof.ok_or_else(|| {
        "a DPoP proof is required when an access token is used at the token endpoint".to_string()
    })?;
    let actual = proof
        .ath
        .as_deref()
        .ok_or_else(|| "DPoP proof is missing required ath claim".to_string())?;
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(access_token.as_bytes()));
    if !constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        return Err("DPoP ath does not match the access token".to_string());
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

/// Inject `cnf.jkt` into the upstream's JSON token response.
///
/// Behavior is chosen to avoid the WOR-47 trap (bearer-replayable
/// token labeled DPoP):
///
/// * **JWT access_token + no broker signing key:** fail closed. The
///   broker cannot produce a JWT with `cnf.jkt` in its signed payload.
/// * **JWT access_token + broker signing key:** re-issue the token
///   with a signed `cnf.jkt` claim and fresh broker timestamps.
/// * **Opaque access_token or malformed/non-object body:** fail closed
///   because this provider verifies signed JWT claims.
///
/// Visibility note: this is `pub` rather than module-private so the
/// integration test in `tests/prompt_injection_corpus.rs` can drive
/// the WOR-47 invariants directly without standing up a full HTTP
/// upstream. Production callers should keep going through `token`.
pub fn inject_cnf_jkt(
    body: &bytes::Bytes,
    proof: &DpopProof,
    broker_signing_key: Option<&crate::config::JwkKey>,
    broker_issuer: &str,
) -> Result<bytes::Bytes, DpopError> {
    let body_is_secret_reference = std::str::from_utf8(body)
        .ok()
        .is_some_and(sbproxy_vault::looks_like_secret_reference_uri);
    if body_is_secret_reference {
        return Err(DpopError::PayloadInvalid(
            "upstream token response is a secret reference".to_string(),
        ));
    }
    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| DpopError::PayloadInvalid(format!("upstream body: {e}")))?;
    let obj = value.as_object_mut().ok_or_else(|| {
        DpopError::PayloadInvalid("upstream token response must be a JSON object".to_string())
    })?;
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
    if !token_is_jwt {
        return Err(DpopError::PayloadInvalid(
            "DPoP binding requires a JWT access token".to_string(),
        ));
    }
    let signing_key = broker_signing_key.ok_or_else(|| {
        DpopError::PayloadInvalid(
            "DPoP binding requires a configured broker signing key".to_string(),
        )
    })?;
    let access_token = access_token.ok_or_else(|| {
        DpopError::PayloadInvalid("upstream response missing access_token".to_string())
    })?;
    let jkt = jwk_thumbprint(&proof.jwk)?;
    let mut cnf = crate::mtls_binding::signed_cnf_from_token(&access_token)
        .map_err(|error| DpopError::PayloadInvalid(error.to_string()))?;
    cnf.insert("jkt".to_string(), serde_json::Value::String(jkt));
    let mut mutations = serde_json::Map::new();
    mutations.insert("cnf".to_string(), serde_json::Value::Object(cnf));
    let resigned =
        crate::at_jwt::resign_at_jwt(&access_token, signing_key, broker_issuer, &mutations)
            .map_err(|e| DpopError::PayloadInvalid(e.to_string()))?;
    obj.insert(
        "access_token".to_string(),
        serde_json::Value::String(resigned),
    );
    obj.remove("cnf");
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
    let (_, http) =
        crate::egress::endpoint_client(dcr_endpoint, app.config.allow_insecure_loopback).await?;
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
    let req_client_id = match form.get("client_id").filter(|value| !value.is_empty()) {
        Some(client_id) => client_id,
        None => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client_id is required for device-code redemption",
            );
        }
    };

    let state = match store
        .poll_and_consume(&device_code, req_client_id, crate::device_code::unix_now())
        .await
    {
        Ok(crate::device_code::DevicePollOutcome::Authorized(state)) => *state,
        Ok(crate::device_code::DevicePollOutcome::Missing) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "device_code is unknown, expired, or already consumed",
            );
        }
        Ok(crate::device_code::DevicePollOutcome::InvalidClient) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client_id does not match the original request",
            );
        }
        Ok(crate::device_code::DevicePollOutcome::Pending) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "authorization_pending",
                "user has not yet authorized this request",
            );
        }
        Ok(crate::device_code::DevicePollOutcome::SlowDown) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "slow_down",
                "polling interval exceeded; double your delay",
            );
        }
        Ok(crate::device_code::DevicePollOutcome::Expired) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "device_code expired",
            );
        }
        Ok(crate::device_code::DevicePollOutcome::Denied) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "user denied the authorization request",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "device_code: atomic poll failed");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "device code lookup failed",
            );
        }
    };

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
        let broker_issuer = crate::well_known::broker_issuer(cfg);
        match inject_cnf_jkt(
            &body_bytes,
            proof,
            cfg.broker_signing_key.as_ref(),
            &broker_issuer,
        ) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "device_code: cnf.jkt issuance failed closed");
                return oauth_error(
                    StatusCode::BAD_GATEWAY,
                    "server_error",
                    "broker could not issue a sender-constrained access token",
                );
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
            upstream_redirect_uri: "https://broker.example/mcp/oauth/callback".to_string(),
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

    fn token_endpoint_dpop_proof(jti: &str, ath: Option<&str>) -> String {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
-----END PRIVATE KEY-----\n";
        let public_jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
            "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY"
        });
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(serde_json::from_value(public_jwk).unwrap());
        let key = EncodingKey::from_ec_pem(PRIVATE_KEY.as_bytes()).unwrap();
        let mut claims = serde_json::json!({
            "htm": "POST",
            "htu": "https://broker.example/mcp/oauth/token",
            "iat": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            "jti": jti
        });
        if let Some(ath) = ath {
            claims["ath"] = serde_json::Value::String(ath.to_string());
        }
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    async fn post_with_dpop(app: Router, proof: &str) -> StatusCode {
        let req = Request::builder()
            .method("POST")
            .uri("/mcp/oauth/token")
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header("DPoP", proof)
            .body(Body::from(
                "grant_type=authorization_code&code=c1\
                 &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
                 &code_verifier=v&client_id=cli",
            ))
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn ordinary_router_rejects_replayed_token_endpoint_dpop_jti() {
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "MCP_GATEWAY_BASE_URL",
            Some("https://broker.example"),
        )]);
        let app = build_app(test_config());
        let proof = token_endpoint_dpop_proof("single-use-token-jti", None);
        assert_eq!(
            post_with_dpop(app.clone(), &proof).await,
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(post_with_dpop(app, &proof).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_endpoint_rejects_dpop_when_replay_cache_is_unavailable() {
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "MCP_GATEWAY_BASE_URL",
            Some("https://broker.example"),
        )]);
        let cfg = test_config();
        let store = InMemorySessionStore::arc(Duration::from_secs(60));
        let app = crate::router_full_with_par(
            Arc::new(cfg),
            store,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let proof = token_endpoint_dpop_proof("unprotected-jti", None);

        assert_eq!(post_with_dpop(app, &proof).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_exchange_requires_ath_for_its_access_token_subject() {
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "MCP_GATEWAY_BASE_URL",
            Some("https://broker.example"),
        )]);
        let mut cfg = test_config();
        cfg.token_exchange_enabled = true;
        cfg.external_base_url = "https://broker.example".to_string();
        cfg.allow_insecure_loopback = true;
        cfg.broker_signing_key = Some(crate::config::JwkKey::Pem {
            pem: "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
-----END PRIVATE KEY-----"
                .to_string(),
            alg: "ES256".to_string(),
            kid: Some("broker-key".to_string()),
            public_jwk: Some(serde_json::json!({
                "kty": "EC", "crv": "P-256",
                "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
                "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY",
                "kid": "broker-key", "use": "sig", "alg": "ES256"
            })),
        });
        let issuer = crate::well_known::broker_issuer(&cfg);
        cfg.subject_token_issuers = vec![issuer.clone()];
        let proof_jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
            "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY"
        }))
        .unwrap();
        let now = crate::device_code::unix_now();
        let subject_token = crate::at_jwt::mint_at_jwt(
            &crate::at_jwt::AtJwtClaims {
                iss: issuer,
                sub: "alice".to_string(),
                aud: serde_json::Value::String(cfg.resource_uri.clone()),
                exp: now + 300,
                iat: now,
                jti: "exchange-subject".to_string(),
                client_id: "cli".to_string(),
                scope: Some("tools:call".to_string()),
                auth_time: None,
                acr: None,
                amr: None,
                act: None,
                cnf: Some(serde_json::json!({
                    "jkt": crate::dpop::jwk_thumbprint(&proof_jwk).unwrap()
                })),
                actor: None,
                principal: None,
                tnx: None,
                purpose: None,
            },
            cfg.broker_signing_key.as_ref().unwrap(),
        )
        .unwrap();
        let app = build_app(cfg);
        let proof = token_endpoint_dpop_proof("token-exchange-no-ath", None);
        let request = Request::builder()
            .method("POST")
            .uri("/mcp/oauth/token")
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header("DPoP", proof)
            .body(Body::from(format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                 &subject_token={subject_token}\
                 &subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token\
                 &client_id=cli"
            )))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("missing required ath"));
    }

    fn sender_proof(jwk: serde_json::Value, jti: &str) -> DpopProof {
        DpopProof {
            jwk: serde_json::from_value(jwk).unwrap(),
            jti: jti.to_string(),
            htm: "POST".to_string(),
            htu: "https://broker.example/mcp/oauth/token".to_string(),
            iat: crate::device_code::unix_now(),
            nonce: None,
            ath: None,
            raw_jwt: "[REDACTED TEST PROOF]".to_string(),
        }
    }

    #[tokio::test]
    async fn public_refresh_binding_rejects_missing_and_wrong_proof_keys() {
        let store = crate::LocalStore::arc();
        let original = sender_proof(
            serde_json::json!({
                "kty": "EC", "crv": "P-256",
                "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
                "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY"
            }),
            "original",
        );
        let attacker = sender_proof(
            serde_json::json!({
                "kty": "EC", "crv": "P-256",
                "x": "DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4",
                "y": "bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc"
            }),
            "attacker",
        );

        store_refresh_sender_binding(store.as_ref(), "tenant-a", "refresh-secret", &original)
            .await
            .unwrap();
        assert!(
            require_refresh_sender_binding(store.as_ref(), "tenant-a", "refresh-secret", None,)
                .await
                .is_err()
        );
        assert!(require_refresh_sender_binding(
            store.as_ref(),
            "tenant-a",
            "refresh-secret",
            Some(&attacker),
        )
        .await
        .unwrap_err()
        .contains("does not match"));
        require_refresh_sender_binding(
            store.as_ref(),
            "tenant-a",
            "refresh-secret",
            Some(&original),
        )
        .await
        .unwrap();
        assert!(require_refresh_sender_binding(
            store.as_ref(),
            "tenant-b",
            "refresh-secret",
            Some(&original),
        )
        .await
        .unwrap_err()
        .contains("unknown"));
    }

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
    fn inject_cnf_jkt_refuses_opaque_token_that_cannot_carry_signed_binding() {
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
        let upstream_body =
            bytes::Bytes::from(r#"{"access_token":"abc","token_type":"Bearer","expires_in":3600}"#);
        let err = super::inject_cnf_jkt(&upstream_body, &proof, None, "https://broker.example")
            .unwrap_err();
        assert!(err.to_string().contains("JWT"));
    }

    #[test]
    fn inject_cnf_jkt_rejects_non_object_success_body() {
        use crate::dpop::DpopProof;
        use jsonwebtoken::jwk::Jwk;
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
            "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY"
        }))
        .unwrap();
        let proof = DpopProof {
            jwk,
            jti: "non-object".to_string(),
            htm: "POST".to_string(),
            htu: "https://broker.example/mcp/oauth/token".to_string(),
            iat: 0,
            nonce: None,
            ath: None,
            raw_jwt: "header.payload.sig".to_string(),
        };
        let body = bytes::Bytes::from_static(br#"["not","an","object"]"#);

        let error = inject_cnf_jkt(&body, &proof, None, "https://broker.example")
            .expect_err("a bound token response must be an object");
        assert!(error.to_string().contains("JSON object"));
    }

    /// WOR-47: a JWT-shaped access_token MUST NOT be relabeled "DPoP"
    /// when the broker has no signing key and therefore cannot mint a
    /// fresh JWT with `cnf.jkt` in the payload. Resource servers
    /// (mcp_resource_server) verify the cnf claim from the JWT
    /// payload, not the wrapper, so a wrapper-only rewrite produces
    /// bearer-replayable tokens dressed up as sender-constrained.
    #[test]
    fn inject_cnf_jkt_refuses_jwt_when_broker_cannot_resign() {
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
        let err = super::inject_cnf_jkt(&upstream_body, &proof, None, "https://broker.example")
            .unwrap_err();
        assert!(err.to_string().contains("signing key"));
    }

    #[test]
    fn inject_cnf_jkt_resigns_jwt_with_binding_inside_signed_payload() {
        use crate::dpop::DpopProof;
        use jsonwebtoken::jwk::Jwk;
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
            "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY"
        }))
        .unwrap();
        let proof = DpopProof {
            jwk,
            jti: "j3".to_string(),
            htm: "POST".to_string(),
            htu: "https://broker.example/mcp/oauth/token".to_string(),
            iat: 0,
            nonce: None,
            ath: None,
            raw_jwt: "header.payload.sig".to_string(),
        };
        let claims = serde_json::json!({
            "iss": "https://upstream.example",
            "sub": "user-1",
            "aud": "https://mcp.example",
            "exp": 4102444800_i64,
            "iat": 1700000000_i64,
            "jti": "old-jti",
            "client_id": "client-1",
            "cnf": {"x5t#S256": "existing-certificate-binding"}
        });
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let upstream_body = bytes::Bytes::from(
            serde_json::json!({
                "access_token": format!("{header}.{payload}.upstream-signature"),
                "token_type": "Bearer",
                "expires_in": 3600
            })
            .to_string(),
        );
        let key = crate::config::JwkKey::Pem {
            pem: include_str!("../../sbproxy-modules/src/auth/dpop_test_ec_p256.pem").to_string(),
            alg: "ES256".to_string(),
            kid: Some("broker-key".to_string()),
            public_jwk: None,
        };

        let rewritten =
            super::inject_cnf_jkt(&upstream_body, &proof, Some(&key), "https://broker.example")
                .unwrap();
        let wrapper: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        let token = wrapper["access_token"].as_str().unwrap();
        assert_eq!(wrapper["token_type"], "DPoP");
        assert_ne!(token.split('.').nth(2), Some("upstream-signature"));
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap();
        let signed_claims: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(signed_claims["iss"], "https://broker.example");
        assert!(signed_claims["cnf"]["jkt"].is_string());
        assert_eq!(
            signed_claims["cnf"]["x5t#S256"],
            "existing-certificate-binding"
        );
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
