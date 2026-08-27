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
    body::Body,
    extract::Request,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use std::sync::Arc;
use tower::ServiceExt;

/// Runtime-local security state shared by a colocated OAuth broker and MCP
/// resource verifier. A fresh unguessable namespace prevents one action or
/// tenant from consuming or observing another action's replay/revocation
/// partitions even when both use the same process.
#[derive(Clone)]
pub struct McpSecurityContext {
    pub(crate) store: Arc<dyn sbproxy_storage::EphemeralKv>,
    pub(crate) namespace: String,
    /// Whether this router mounts `GET {base_path}/admin/status`.
    ///
    /// True for a standalone embedding, where the host process decides
    /// what to put in front of the router. False when the broker runs
    /// inside sbproxy, because there the OAuth routes have to stay
    /// unauthenticated for the flow to work at all and the whole route
    /// tree is dispatched before the resource-server check: the status
    /// route would be world-readable on the public MCP origin,
    /// answering "which security controls are off" to anyone who asks.
    /// The proxy's own authenticated admin API is where that belongs.
    pub(crate) mount_admin_status: bool,
}

impl McpSecurityContext {
    /// Create a bounded in-process context with a random runtime namespace.
    pub fn new() -> Self {
        use rand::RngCore;
        let mut identifier = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut identifier);
        let namespace = identifier
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Self {
            store: LocalStore::arc(),
            namespace,
            mount_admin_status: true,
        }
    }

    /// Build a context for a broker mounted inside the sbproxy request
    /// path, where `/admin/status` must not be served on the public
    /// origin. See the `mount_admin_status` field on this struct.
    #[must_use]
    pub fn in_process() -> Self {
        Self {
            mount_admin_status: false,
            ..Self::new()
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(namespace: &str) -> Self {
        Self {
            store: LocalStore::arc(),
            namespace: namespace.to_string(),
            mount_admin_status: true,
        }
    }
}

impl Default for McpSecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

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
mod egress;
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
mod remote_body;
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
    AuthenticatedDeviceUser, DeviceAuthorizationRequest, DeviceAuthorizationResponse,
    DeviceCodeError, DeviceCodeState, DeviceCodeStatus, DeviceCodeStore, DEVICE_CODE_GRANT_TYPE,
};
pub use dpop::{
    jwk_thumbprint, parse_and_verify as parse_and_verify_dpop, DpopError, DpopNonceIssuer,
    DpopProof, DpopReplayCache,
};
pub use local_store::LocalStore;
pub use mtls_binding::{
    client_cert_thumbprint, inject_cnf_x5t_s256, MtlsBindingError, VerifiedClientCertificate,
};
pub use par::{
    consume as consume_par, mint_request_uri, PushedAuthorizationParams,
    PushedAuthorizationResponse, PAR_TTL_SECS, REQUEST_URI_PREFIX,
};
pub use pkce::{CodeChallenge, CodeChallengeMethod, CodeVerifier, PkceError};
pub use resource_server::{
    AudienceConfig, McpResourceServerConfig, McpResourceServerProvider, ResourceServerAuthError,
    VerifiedToken,
};
pub use session::{InMemorySessionStore, RedisSessionStore, Session, SessionStore};
pub use token::inject_cnf_jkt;
pub use token_exchange::{
    chain_depth as token_exchange_chain_depth, inject_act_envelope, parse_subject_token, ActClaim,
    SubjectClaims, SUBJECT_TOKEN_TYPE_ACCESS, TOKEN_EXCHANGE_GRANT_TYPE,
};
pub use well_known::{build_metadata, BrokerMetadata};

/// Host-neutral request passed from sbproxy's Pingora action path to
/// the in-process OAuth broker. Identity fields are typed and can only
/// be populated from the host's verified auth/TLS state.
pub struct GatewayHttpRequest {
    /// HTTP method.
    pub method: String,
    /// Origin-form URI (path plus optional query).
    pub uri: String,
    /// Raw header names and values.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Bounded request body.
    pub body: Bytes,
    /// Verified TLS client certificate thumbprint, if present.
    pub verified_client_certificate: Option<VerifiedClientCertificate>,
    /// Authenticated browser user for RFC 8628 consent, if present.
    pub authenticated_device_user: Option<AuthenticatedDeviceUser>,
}

/// Host-neutral response returned by the in-process OAuth broker.
pub struct GatewayHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Raw response headers.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Bounded response body.
    pub body: Bytes,
}

/// Cloneable in-process broker adapter used by `action: mcp`.
#[derive(Clone)]
pub struct McpGatewayRuntime {
    base_path: String,
    router: Router,
}

impl McpGatewayRuntime {
    /// Build the broker and every enabled collaborator from one config.
    pub fn new(config: McpGatewayConfig) -> anyhow::Result<Self> {
        Self::new_with_security_context(config, McpSecurityContext::new())
    }

    /// Build a broker using the same runtime-local security context as its
    /// colocated resource verifier.
    pub fn new_with_security_context(
        config: McpGatewayConfig,
        security: McpSecurityContext,
    ) -> anyhow::Result<Self> {
        if !config.base_path.starts_with('/') || config.base_path.starts_with("//") {
            anyhow::bail!("MCP OAuth base_path must be an origin-relative path");
        }
        for (field, value) in [
            ("external_base_url", config.external_base_url.as_str()),
            (
                "upstream_redirect_uri",
                config.upstream_redirect_uri.as_str(),
            ),
            ("resource_uri", config.resource_uri.as_str()),
        ] {
            let valid = url::Url::parse(value).ok().is_some_and(|url| {
                matches!(url.scheme(), "http" | "https")
                    && url.has_host()
                    && url.fragment().is_none()
                    && url.username().is_empty()
                    && url.password().is_none()
            });
            if !valid {
                anyhow::bail!(
                    "MCP OAuth {field} must be an absolute HTTP(S) URL without a fragment"
                );
            }
        }
        let external = url::Url::parse(&config.external_base_url)?;
        if external.path() != "/" || external.query().is_some() {
            anyhow::bail!("MCP OAuth external_base_url must be an origin without path or query");
        }
        let callback = url::Url::parse(&config.upstream_redirect_uri)?;
        let expected_callback_path = format!("{}/callback", config.base_path.trim_end_matches('/'));
        if callback.origin() != external.origin() || callback.path() != expected_callback_path {
            anyhow::bail!(
                "MCP OAuth upstream_redirect_uri must target this broker's configured callback"
            );
        }
        validate_startup(&config)?;
        let base_path = config.base_path.trim_end_matches('/').to_string();
        // `validate_startup` above refuses a zero `session_ttl_secs`, so
        // this no longer clamps it on the way past.
        let sessions =
            InMemorySessionStore::arc(std::time::Duration::from_secs(config.session_ttl_secs));
        Ok(Self {
            base_path,
            router: router_with_security_context(Arc::new(config), sessions, security),
        })
    }

    /// True when `path` belongs to this broker's configured route tree.
    pub fn matches_path(&self, path: &str) -> bool {
        path == self.base_path
            || path
                .strip_prefix(&self.base_path)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    /// Dispatch one request through the same Axum routes used by the
    /// standalone harness, while carrying only host-verified identity.
    pub async fn dispatch(
        &self,
        request: GatewayHttpRequest,
    ) -> anyhow::Result<GatewayHttpResponse> {
        let GatewayHttpRequest {
            method,
            uri,
            headers,
            body,
            verified_client_certificate,
            authenticated_device_user,
        } = request;
        let mut builder = axum::http::Request::builder()
            .method(method.as_str())
            .uri(uri.as_str());
        for (name, value) in headers {
            let name = axum::http::HeaderName::from_bytes(name.as_bytes())?;
            let value = axum::http::HeaderValue::from_bytes(&value)?;
            builder = builder.header(name, value);
        }
        let request = builder.body(Body::from(body))?;
        let mut service = self.router.clone();
        if let Some(certificate) = verified_client_certificate {
            service = service.layer(axum::extract::Extension(certificate));
        }
        if let Some(user) = authenticated_device_user {
            service = service.layer(axum::extract::Extension(user));
        }
        let response = service.oneshot(request).await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect();
        let body = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024).await?;
        Ok(GatewayHttpResponse {
            status,
            headers,
            body,
        })
    }
}

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
    /// cache. When None the broker falls back to fail-closed behavior
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
    /// Runtime-scoped, bounded local access-token denylist.
    pub(crate) revocations: Arc<revoke::RevocationList>,
    /// Runtime-scoped fixed-window limiter for the revocation endpoint.
    pub(crate) revocation_rate_limiter: Arc<revoke::FixedWindowRateLimiter>,
    /// Runtime-scoped fixed-window limiter shared by `/authorize` and
    /// `/par`, the two unauthenticated endpoints that consume session
    /// capacity.
    pub(crate) authorize_rate_limiter: Arc<revoke::FixedWindowRateLimiter>,
    /// Shared runtime store for refresh-token sender bindings and other
    /// namespaced credential state.
    pub(crate) security_store: Arc<dyn sbproxy_storage::EphemeralKv>,
    /// Opaque per-action namespace for credential-state keys.
    pub(crate) security_namespace: String,
}

// --- Router ---

/// Build an axum router with `/authorize`, `/callback`, `/token`,
/// `/register`, `/admin/status`, and the two well-known metadata routes
/// mounted under the configured base path. It wires bounded in-process
/// DPoP replay/nonce storage and every enabled CIMD, DCR, metadata, and
/// device-code collaborator. PAR remains available through
/// [`router_full_with_par`] because it requires caller-owned storage.
pub fn router(config: Arc<McpGatewayConfig>, session_store: Arc<dyn SessionStore>) -> Router {
    router_with_security_context(config, session_store, McpSecurityContext::new())
}

fn router_with_security_context(
    config: Arc<McpGatewayConfig>,
    session_store: Arc<dyn SessionStore>,
    security: McpSecurityContext,
) -> Router {
    let runtime_store = security.store.clone();
    let replay_store: Arc<dyn sbproxy_storage::EphemeralKv> = runtime_store.clone();
    let dpop_replay = Arc::new(DpopReplayCache::new(
        replay_store,
        std::time::Duration::from_secs(config.dpop_jti_ttl_secs),
    ));
    let nonce_store: Arc<dyn sbproxy_storage::EphemeralKv> = runtime_store.clone();
    let dpop_nonce = Arc::new(DpopNonceIssuer::new(
        nonce_store,
        std::time::Duration::from_secs(config.dpop_nonce_ttl_secs),
    ));
    let device_code_store = config.device_code_enabled.then(|| {
        let store: Arc<dyn sbproxy_storage::EphemeralKv> = runtime_store.clone();
        DeviceCodeStore::arc(store)
    });
    let cimd_cache = config.cimd_enabled.then(|| {
        InMemoryCimdCache::arc(std::time::Duration::from_secs(config.cimd_cache_ttl_secs))
    });
    let cimd_to_dcr = config.dcr_translate_cimd_clients.then(CimdToDcrCache::arc);
    let as_metadata = config
        .upstream_metadata_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .map(|url| {
            let cache = if config.allow_insecure_loopback {
                AsMetadataCache::new_with_development_loopback(
                    sbproxy_httpkit::default_outbound(),
                    url,
                )
            } else {
                AsMetadataCache::new(sbproxy_httpkit::default_outbound(), url)
            };
            Arc::new(cache)
        });
    router_full_with_par_and_security(
        config,
        session_store,
        as_metadata,
        cimd_cache,
        cimd_to_dcr,
        Some(dpop_replay),
        Some(dpop_nonce),
        device_code_store,
        None,
        security,
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
    router_full_with_par_and_security(
        config,
        session_store,
        as_metadata,
        cimd_cache,
        cimd_to_dcr,
        dpop_replay,
        dpop_nonce,
        device_code_store,
        par_store,
        McpSecurityContext::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn router_full_with_par_and_security(
    config: Arc<McpGatewayConfig>,
    session_store: Arc<dyn SessionStore>,
    as_metadata: Option<Arc<AsMetadataCache>>,
    cimd_cache: Option<Arc<dyn CimdCache>>,
    cimd_to_dcr: Option<Arc<CimdToDcrCache>>,
    dpop_replay: Option<Arc<DpopReplayCache>>,
    dpop_nonce: Option<Arc<DpopNonceIssuer>>,
    device_code_store: Option<Arc<DeviceCodeStore>>,
    par_store: Option<Arc<dyn sbproxy_storage::EphemeralKv>>,
    security: McpSecurityContext,
) -> Router {
    let base = config.base_path.trim_end_matches('/').to_string();
    let par_enabled = par_store.is_some();
    let mount_admin_status = security.mount_admin_status;
    let revocations = Arc::new(revoke::RevocationList::new(
        security.store.clone(),
        security.namespace.clone(),
        config.revocation_max_entries,
        std::time::Duration::from_secs(config.revocation_max_ttl_secs.max(1)),
    ));
    let revocation_rate_limiter = Arc::new(revoke::FixedWindowRateLimiter::new(
        config.revocation_requests_per_minute.max(1),
    ));
    let authorize_rate_limiter = Arc::new(revoke::FixedWindowRateLimiter::new(
        config.authorize_requests_per_minute.max(1),
    ));
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
        revocations,
        revocation_rate_limiter,
        authorize_rate_limiter,
        security_store: security.store,
        security_namespace: security.namespace,
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
    // Mounted only for a standalone embedding. See
    // `McpSecurityContext::mount_admin_status`.
    if mount_admin_status {
        router = router.route(&format!("{base}/admin/status"), get(admin::status));
    }
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
