//! MCP OAuth 2.1 broker: an axum-based authorization gateway sitting in
//! front of MCP servers on the token-issuance side of the flow.
//!
//! Implements `/authorize`, `/callback`, `/token`, `/register`,
//! `/device_authorization`, `/verify`, `/par`, `/revoke`,
//! `/introspect`, the two well-known metadata routes, RFC 9449 DPoP
//! proof verification, RFC 8705 mTLS-bound tokens, and RFC
//! 8707/8693/7591 (resource indicators, token exchange, dynamic client
//! registration) on top of PKCE.
//!
//! All state this crate holds is OAuth flow state: PKCE-adjacent
//! session rows, DPoP replay jtis, device codes, PAR entries. Every
//! piece of it is written against [`sbproxy_storage::EphemeralKv`] /
//! [`sbproxy_storage::PersistentKv`], with Redis as the optional
//! multi-replica backend and [`LocalStore`] as the in-process default
//! when no Redis URL is configured (see its module docs for why that
//! is a first-class type here rather than a repurposed test double).
//!
//! [`resource_server`] is the companion resource-server half of the
//! same flow: it validates the Bearer/DPoP tokens this broker issues,
//! on the origin that actually serves MCP traffic. See its module docs
//! for what is and is not ported there.
//!
//! Threat model: the broker validates every inbound parameter before
//! persisting state, mints its own opaque `state` for the upstream hop
//! so the client's `state` never reaches the upstream Authorization
//! Server, and treats sessions as single-use.
//!
//! See `docs/mcp-oauth-gateway.md` for the operator-facing guide and
//! `examples/standalone_broker.rs` for a runnable deployment.

use axum::{
    extract::Request,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

/// Operator-facing `/admin/status` JSON surface.
pub mod admin;
/// RFC 8414 Authorization-Server metadata cache (fetch, TTL, ETag).
pub mod as_metadata;
/// RFC 9068 JWT Profile for OAuth Access Tokens.
pub mod at_jwt;
/// `GET /authorize`: validates the inbound request and redirects to
/// the upstream Authorization Server.
pub mod authorize;
/// `GET /callback`: relays the upstream's authorization result back
/// to the original client.
pub mod callback;
/// Client ID Metadata Documents (the `parecki` CIMD draft): fetch,
/// SSRF-guarded resolution, and caching.
pub mod cimd;
/// Translates a CIMD document into an RFC 7591 dynamic-client
/// registration for upstreams that do not speak CIMD natively.
pub mod cimd_to_dcr;
/// The five RFC 6749 / RFC 7523 client-authentication methods
/// accepted at `/token`.
pub mod client_auth;
/// Broker configuration (`McpGatewayConfig`) and startup validation.
pub mod config;
/// RFC 8628 device authorization grant for headless clients.
pub mod device_code;
/// RFC 9449 DPoP proof verification and replay protection.
pub mod dpop;
/// OAuth 2.0 Token Introspection (RFC 7662, server side).
pub mod introspect;
/// In-process default backend for [`sbproxy_storage::EphemeralKv`] /
/// [`sbproxy_storage::PersistentKv`].
pub mod local_store;
/// Prometheus metrics for this crate.
pub mod metrics;
/// RFC 8705 §3 mTLS certificate-bound access tokens.
pub mod mtls_binding;
/// Pushed Authorization Requests (RFC 9126).
pub mod par;
/// RFC 7636 PKCE verifier/challenge types and derivation.
pub mod pkce;
/// `POST /register`: RFC 7591 dynamic client registration, proxied to
/// the upstream Authorization Server.
pub mod register;
/// MCP resource-server companion: validates the tokens this broker
/// issues, on the origin that serves MCP traffic.
pub mod resource_server;
/// OAuth 2.0 Token Revocation (RFC 7009).
pub mod revoke;
/// In-flight authorization session storage, keyed by the broker's
/// outbound `state` value.
pub mod session;
#[cfg(test)]
mod test_env;
/// `POST /token`: forwards authorization-code, refresh-token,
/// client-credentials, device-code, and token-exchange grants to the
/// upstream Authorization Server.
pub mod token;
/// RFC 8693 OAuth 2.0 Token Exchange.
pub mod token_exchange;
/// `GET /.well-known/oauth-authorization-server` and
/// `GET /.well-known/jwks.json`.
pub mod well_known;

pub use as_metadata::{AsMetadataCache, AuthorizationServerMetadata};
pub use at_jwt::{broker_jwks, mint_at_jwt, AtJwtClaims, JwksDocument};
pub use cimd::{
    fetch as fetch_cimd, CimdCache, ClientIdMetadataDocument, FetchedCimd, InMemoryCimdCache,
};
pub use cimd_to_dcr::{
    fingerprint as cimd_fingerprint, translate_cimd_to_dcr, CimdToDcrCache, DcrRegisteredClient,
};
pub use client_auth::{
    detect_method, ensure_method_accepted, verify_basic, verify_post, verify_private_key_jwt,
    verify_secret_jwt, ClientAuthMethod,
};
pub use config::{
    default_accepted_client_auth_methods, validate_startup, JwkKey, McpGatewayConfig,
    StartupConfigError, DEFAULT_CIMD_CACHE_TTL_SECS, DEFAULT_CIMD_MAX_DOC_BYTES,
    DEFAULT_DEVICE_CODE_LIFETIME_SECS, DEFAULT_DEVICE_CODE_POLLING_INTERVAL_SECS,
    DEFAULT_METADATA_MAX_STALENESS_SECS, DEFAULT_METADATA_REFRESH_SECS,
    DEFAULT_TOKEN_EXCHANGE_MAX_CHAIN_DEPTH,
};
pub use device_code::{
    DeviceAuthorizationRequest, DeviceAuthorizationResponse, DeviceCodeError, DeviceCodeState,
    DeviceCodeStatus, DeviceCodeStore, DEVICE_CODE_GRANT_TYPE,
};
pub use dpop::{
    jwk_thumbprint, parse_and_verify as parse_and_verify_dpop, DpopError, DpopNonceIssuer,
    DpopProof, DpopReplayCache,
};
pub use local_store::LocalStore;
pub use mtls_binding::{
    client_cert_thumbprint, extract_client_cert_der, inject_cnf_x5t_s256, verify_cnf_x5t_s256,
    MtlsBindingError, CLIENT_CERT_HEADER,
};
pub use par::{
    consume as consume_par, mint_request_uri, PushedAuthorizationParams,
    PushedAuthorizationResponse, PAR_TTL_SECS, REQUEST_URI_PREFIX,
};
pub use pkce::{CodeChallenge, CodeChallengeMethod, CodeVerifier, PkceError};
pub use session::{InMemorySessionStore, RedisSessionStore, Session, SessionStore};
pub use token::inject_cnf_jkt;
pub use token_exchange::{
    chain_depth as token_exchange_chain_depth, inject_act_envelope, parse_subject_token, ActClaim,
    SubjectClaims, SUBJECT_TOKEN_TYPE_ACCESS, TOKEN_EXCHANGE_GRANT_TYPE,
};
pub use well_known::{build_metadata, BrokerMetadata};

// --- Application state ---

/// Shared state injected into every handler via axum's `with_state`.
/// Cloning is cheap because every field is an `Arc`.
#[derive(Clone)]
pub struct AppState {
    /// Loaded broker configuration.
    pub config: Arc<McpGatewayConfig>,
    /// Backing session store. The trait object lets the same router
    /// drive either the in-memory store (4B.1) or the Redis store
    /// shipping in 4B.3.
    pub session_store: Arc<dyn SessionStore>,
    /// Optional AS metadata cache. The well-known route consults it
    /// for upstream-derived fields. When absent, the route still
    /// serves the broker-overridden subset (issuer, endpoints,
    /// PKCE methods, advertised auth methods, grant types).
    pub as_metadata: Option<Arc<AsMetadataCache>>,
    /// Optional Client ID Metadata Document (CIMD) cache. When
    /// `cimd_enabled` is true and a URL-shaped `client_id` arrives at
    /// /authorize, the broker resolves the document through this
    /// cache. When None the broker falls back to fail-closed behaviour
    /// for URL-shaped client_ids (rejecting them with `invalid_client`).
    pub cimd_cache: Option<Arc<dyn CimdCache>>,
    /// Optional CIMD → DCR translation cache. Only consulted when
    /// `dcr_translate_cimd_clients` is true.
    pub cimd_to_dcr: Option<Arc<CimdToDcrCache>>,
    /// Optional DPoP replay cache. When present and a `DPoP` header
    /// arrives at /token, the gateway validates and records the proof's
    /// jti. When absent and a DPoP header arrives, the gateway still
    /// verifies the proof but cannot enforce single-use jti semantics
    /// (replay protection becomes best-effort).
    pub dpop_replay: Option<Arc<DpopReplayCache>>,
    /// Optional DPoP nonce issuer. Required when
    /// `dpop_require_nonce` is true; otherwise unused.
    pub dpop_nonce: Option<Arc<DpopNonceIssuer>>,
    /// Optional device-code state store (Wave 4D.2). Required when
    /// `device_code_enabled` is true; the `/device_authorization`,
    /// `/verify`, and `/token` (with `device_code` grant) routes all
    /// read and write through this single backing store.
    pub device_code_store: Option<Arc<DeviceCodeStore>>,
    /// Optional Pushed Authorization Request (PAR, RFC 9126) store.
    /// When `Some`, the broker mounts `POST /par`, advertises the
    /// endpoint in AS metadata, and `/authorize` consumes
    /// `request_uri` parameters by calling
    /// `crate::par::consume`. When `None` the endpoint is unmounted
    /// and `/authorize` rejects any `request_uri` parameter as
    /// `invalid_request`.
    pub par_store: Option<Arc<dyn sbproxy_storage::EphemeralKv>>,
}

// --- Router ---

/// Build an axum router with `/authorize`, `/callback`, `/token`,
/// `/register`, `/admin/status`, and the two well-known metadata routes
/// mounted under the configured base path, with every optional
/// collaborator (AS metadata cache, CIMD caches, DPoP replay cache and
/// nonce issuer, device-code store, PAR store) disabled. The router
/// consumes its own state, so callers wanting to merge it into a wider
/// router should call `Router::nest` or `Router::merge` after this
/// returns.
///
/// This is the common case: an operator who wants every optional
/// collaborator turned on calls [`router_full_with_par`] directly
/// instead, since Rust has no default arguments and a constructor
/// between these two extremes would only cover a specific subset of
/// features nobody but its own test happened to name (which is exactly
/// how the ratchet in `scripts/check-pub-item-ratchet.sh` catches
/// exactly this shape of API sprawl).
pub fn router(config: Arc<McpGatewayConfig>, session_store: Arc<dyn SessionStore>) -> Router {
    router_full_with_par(
        config,
        session_store,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

/// Full constructor taking every optional collaborator this crate
/// supports:
///
/// * `as_metadata` - upstream AS metadata cache the well-known route
///   reads from. `None` still serves the broker-overridden subset.
/// * `cimd_cache` / `cimd_to_dcr` - Client ID Metadata Document
///   support. Pass `cimd_cache = Some(InMemoryCimdCache::arc(ttl))`
///   and (optionally) `cimd_to_dcr = Some(CimdToDcrCache::arc())` to
///   enable URL-shaped `client_id` values.
/// * `dpop_replay` / `dpop_nonce` - RFC 9449 sender-constrained
///   tokens. Construct a `DpopReplayCache` and (optionally) a
///   `DpopNonceIssuer` over the shared `EphemeralKv` backend.
/// * `device_code_store` - RFC 8628 device-code grant. Required when
///   `config.device_code_enabled` is true; `None` disables
///   `/device_authorization` and `/verify`.
/// * `par_store` - RFC 9126 Pushed Authorization Requests. When
///   `Some`, the broker mounts `POST /par`, advertises the endpoint in
///   AS metadata, and `/authorize` accepts a `request_uri` parameter.
///   `None` leaves PAR off; `/authorize` continues to accept inline
///   parameters.
#[allow(clippy::too_many_arguments)]
pub fn router_full_with_par(
    config: Arc<McpGatewayConfig>,
    session_store: Arc<dyn SessionStore>,
    as_metadata: Option<Arc<AsMetadataCache>>,
    cimd_cache: Option<Arc<dyn CimdCache>>,
    cimd_to_dcr: Option<Arc<CimdToDcrCache>>,
    dpop_replay: Option<Arc<DpopReplayCache>>,
    dpop_nonce: Option<Arc<DpopNonceIssuer>>,
    device_code_store: Option<Arc<DeviceCodeStore>>,
    par_store: Option<Arc<dyn sbproxy_storage::EphemeralKv>>,
) -> Router {
    let base = config.base_path.trim_end_matches('/').to_string();
    let par_enabled = par_store.is_some();
    let state = AppState {
        config,
        session_store,
        as_metadata,
        cimd_cache,
        cimd_to_dcr,
        dpop_replay,
        dpop_nonce,
        device_code_store,
        par_store,
    };
    let mut router = Router::new()
        .route(&format!("{base}/authorize"), get(authorize::authorize))
        .route(&format!("{base}/callback"), get(callback::callback))
        .route(&format!("{base}/token"), post(token::token))
        .route(&format!("{base}/register"), post(register::register))
        .route(
            &format!("{base}/device_authorization"),
            post(device_code::device_authorization),
        )
        .route(
            &format!("{base}/verify"),
            get(device_code::verify_get).post(device_code::verify_post),
        )
        .route(
            &format!("{base}/.well-known/oauth-authorization-server"),
            get(well_known::well_known),
        );
    if par_enabled {
        router = router.route(&format!("{base}/par"), post(par::par));
    }
    if state.config.upstream_revocation_endpoint_url.is_some() {
        router = router.route(&format!("{base}/revoke"), post(revoke::revoke));
    }
    if state.config.upstream_introspection_endpoint_url.is_some() {
        router = router.route(&format!("{base}/introspect"), post(introspect::introspect));
    }
    // RFC 9068: always mount /.well-known/jwks.json. When no signing
    // key is configured the endpoint serves an empty `keys` array
    // rather than 404, so RFC 9068-aware verifiers do not retry
    // forever. The route stays cheap (one OnceLock load + JSON
    // serialize) so leaving it always on is harmless.
    router = router.route(
        &format!("{base}/.well-known/jwks.json"),
        get(well_known::jwks),
    );
    // Always mounted: a small, unauthenticated JSON surface listing
    // which optional collaborators are wired in. See `admin` module
    // docs for why this exists instead of a `ui/` admin console page.
    router = router.route(&format!("{base}/admin/status"), get(admin::status));
    router
        .layer(middleware::from_fn(record_route_metrics))
        .with_state(state)
}

/// Records [`metrics::AUTHORIZE_REQUESTS_TOTAL`],
/// [`metrics::TOKEN_REQUESTS_TOTAL`], and
/// [`metrics::RFC7009_RFC7662_REQUESTS_TOTAL`], and emits one
/// structured `mcp_oauth_*_decision` log line per request, from the
/// response status class keyed off the request path.
///
/// A response-status-only view necessarily loses the specific OAuth
/// `error` code a rejection carries; recovering that would mean
/// buffering and JSON-parsing every response body in a layer that
/// runs on every request, including the ones with no useful failure
/// detail to extract. The per-branch OAuth error string is already
/// visible to an operator two ways: in the HTTP response itself, and
/// (for the one path with enough internal branching to warrant it)
/// in `token::process_dpop`'s own `mcp_oauth_dpop_decision` log line.
/// `docs/mcp-oauth-gateway.md` documents both event shapes as the
/// audit trail for this crate's decisions, per this workspace's
/// "evidence is structured logs" convention.
async fn record_route_metrics(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let resp = next.run(req).await;
    let status = resp.status();
    let class = if status.is_success() || status.is_redirection() {
        "allowed"
    } else if status.is_client_error() {
        "rejected"
    } else {
        "error"
    };
    if path.ends_with("/authorize") {
        let outcome = if status.is_client_error() {
            "rejected"
        } else if status.is_server_error() {
            "error"
        } else {
            "redirected"
        };
        metrics::record_authorize(outcome);
        tracing::info!(
            target: "mcp_gateway::decision",
            event = "mcp_oauth_authorize_decision",
            outcome = class,
            status = status.as_u16(),
            "authorize request decided"
        );
    } else if path.ends_with("/token") {
        let outcome = if status.is_success() {
            "issued"
        } else if status.is_client_error() {
            "rejected"
        } else {
            "upstream_error"
        };
        metrics::record_token(outcome);
        tracing::info!(
            target: "mcp_gateway::decision",
            event = "mcp_oauth_token_decision",
            outcome = class,
            status = status.as_u16(),
            "token request decided"
        );
    } else if path.ends_with("/revoke") {
        let outcome = if status.is_success() { "ok" } else { "error" };
        metrics::record_revocation_or_introspection("revoke", outcome);
        tracing::info!(
            target: "mcp_gateway::decision",
            event = "mcp_oauth_revoke_decision",
            outcome = class,
            status = status.as_u16(),
            "revocation request decided"
        );
    } else if path.ends_with("/introspect") {
        let outcome = if status.is_success() { "ok" } else { "error" };
        metrics::record_revocation_or_introspection("introspect", outcome);
        tracing::info!(
            target: "mcp_gateway::decision",
            event = "mcp_oauth_introspect_decision",
            outcome = class,
            status = status.as_u16(),
            "introspection request decided"
        );
    }
    resp
}
