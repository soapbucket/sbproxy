//! MCP resource-server companion: verify tokens this crate's broker
//! issued, on the origin that actually serves MCP traffic.
//!
//! The broker in the rest of this crate is the token-issuance half of
//! the MCP Authorization spec
//! (<https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization>);
//! this module is the resource-server half that validates the tokens
//! it issued. Both halves share the same DPoP primitives
//! ([`crate::dpop::parse_and_verify`], [`crate::dpop::jwk_thumbprint`]):
//! a token the broker bound to a key via `cnf.jkt` is checked here with
//! the identical proof-verification code, not a reimplementation that
//! could drift from it.
//!
//! A resource server built on `McpResourceServerProvider` does three
//! things per the spec:
//!
//! 1. Validates the inbound Bearer token's signature against the
//!    authorization server's JWKS, then binds it to this resource via
//!    RFC 8707: the token's `resource` claim (or, failing that, its
//!    `aud` claim) must contain the configured `resource_uri`. A token
//!    that validates but was issued for a different resource is
//!    rejected even though the signature is genuine, closing the
//!    replay-across-resources gap a bare JWKS check leaves open.
//! 2. Advertises the authorization server and accepted scopes at
//!    `GET {metadata_path}` per RFC 9728, unauthenticated.
//! 3. On rejection, emits an RFC 6750 `WWW-Authenticate` challenge
//!    carrying `resource_metadata` so the client can discover the AS
//!    without out-of-band configuration.
//!
//! # Scope: JWKS mode only
//!
//! The MCP Authorization spec's other verification path,
//! delegating every token to the AS's RFC 7662 introspection endpoint,
//! is deliberately not ported here: it depends on an introspection
//! auth provider that is itself a separate, not-yet-ported piece of
//! this epic's disposition plan (`oauth_introspection`, listed
//! alongside this ticket as an independent child). Building a second,
//! bespoke introspection client inside this crate to fill that gap
//! would duplicate work the sibling ticket already owns and would drift
//! from it the moment either side changes its retry or caching policy.
//! JWKS mode is both the spec-recommended default and the mode that
//! needs nothing from that sibling ticket, so it is what ships here;
//! `docs/mcp-oauth-gateway.md` records the introspection gap explicitly
//! rather than silently.
//!
//! # Wiring
//!
//! An `action: mcp` can compile this provider from its nested
//! `oauth.resource_server` configuration. Core dispatch applies it after
//! MCP transport trust and before catalogue reads, body parsing, or
//! upstream work. The same type remains usable directly by MCP servers
//! that are not hosted behind sbproxy.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::dpop::{jwk_thumbprint, parse_and_verify, DpopError, DpopReplayCache};

const MAX_RESOURCE_JWKS_BYTES: usize = 256 * 1024;

// --- Audience ---

/// Accepts either a single audience string or a list, mirroring how
/// most authorization servers let operators paste either shape
/// straight out of their AS console.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AudienceConfig {
    /// A single accepted audience value.
    Single(String),
    /// Multiple accepted audience values.
    Multi(Vec<String>),
}

impl AudienceConfig {
    /// Render as a `Vec<&str>` regardless of which shape was
    /// configured.
    pub fn as_list(&self) -> Vec<&str> {
        match self {
            Self::Single(s) => vec![s.as_str()],
            Self::Multi(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

// --- Config ---

/// Configuration for [`McpResourceServerProvider`].
///
/// Unknown keys are refused, for the same reason
/// [`crate::config::McpGatewayConfig`] refuses them: a misspelled
/// binding flag here turns a verification check off without saying so.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpResourceServerConfig {
    /// Public URI of this MCP resource server (e.g.
    /// `https://mcp.example.com`). Checked against the token's RFC
    /// 8707 `resource` (or `aud`) claim on every request, and used to
    /// build the `resource_metadata` URL in the `WWW-Authenticate`
    /// challenge.
    pub resource_uri: String,

    /// Authorization server(s) that issue tokens valid for this
    /// resource. Surfaced verbatim in the RFC 9728 metadata document.
    /// At least one is required.
    pub authorization_servers: Vec<String>,

    /// JWKS endpoint URL the provider fetches signing keys from.
    pub jwks_url: String,

    /// Development-only plaintext loopback override for JWKS retrieval.
    #[serde(default)]
    pub allow_insecure_loopback: bool,

    /// Accepted `aud` values. Must contain (or equal) `resource_uri`
    /// to bind tokens to this server.
    pub audience: AudienceConfig,

    /// Expected `iss` claim. Defaults to the first
    /// `authorization_servers` entry when omitted.
    #[serde(default)]
    pub issuer: Option<String>,

    /// Cache TTL for the fetched JWKS, in seconds.
    #[serde(default = "default_jwks_cache_ttl_secs")]
    pub jwks_cache_ttl_secs: u64,

    /// Scopes advertised to clients in the metadata document.
    #[serde(default)]
    pub scopes_supported: Vec<String>,

    /// Explicit asymmetric JWT algorithms accepted for RFC 9068 access
    /// tokens. The verifier never selects an algorithm solely from an
    /// attacker-controlled token header.
    #[serde(default = "default_access_token_algorithms")]
    pub access_token_algorithms: Vec<String>,

    /// Optional documentation URL (RFC 9728 `resource_documentation`).
    #[serde(default)]
    pub resource_documentation: Option<String>,

    /// Path the metadata document is served from.
    #[serde(default = "default_metadata_path")]
    pub metadata_path: String,

    /// Legacy compatibility knob. Signed `cnf.jkt` claims are always
    /// enforced; setting this false cannot downgrade a bound token to
    /// bearer semantics.
    #[serde(default)]
    pub dpop_enforce_binding: bool,

    /// Maximum acceptable skew between a DPoP proof's `iat` and wall
    /// clock, in seconds.
    #[serde(default = "default_dpop_skew_secs")]
    pub dpop_max_clock_skew_secs: u64,
}

fn default_jwks_cache_ttl_secs() -> u64 {
    300
}

fn default_metadata_path() -> String {
    "/.well-known/oauth-protected-resource".to_string()
}

fn default_dpop_skew_secs() -> u64 {
    30
}

fn default_access_token_algorithms() -> Vec<String> {
    vec!["ES256".to_string(), "RS256".to_string()]
}

impl McpResourceServerConfig {
    /// Validate cross-field invariants.
    pub fn validate(&self) -> Result<()> {
        validate_absolute_http_url("resource_uri", &self.resource_uri)?;
        if self.authorization_servers.is_empty() {
            return Err(anyhow!(
                "mcp_resource_server requires at least one authorization_servers entry"
            ));
        }
        for as_url in &self.authorization_servers {
            validate_absolute_http_url("authorization_servers entry", as_url)?;
        }
        validate_absolute_http_url("jwks_url", &self.jwks_url)?;
        if self.access_token_algorithms.is_empty() {
            return Err(anyhow!(
                "mcp_resource_server access_token_algorithms must not be empty"
            ));
        }
        for algorithm in &self.access_token_algorithms {
            parse_access_token_algorithm(algorithm)?;
        }
        if self.audience.as_list().is_empty()
            || self.audience.as_list().iter().any(|s| s.trim().is_empty())
        {
            return Err(anyhow!(
                "mcp_resource_server audience must contain at least one non-empty value"
            ));
        }
        if !self
            .audience
            .as_list()
            .iter()
            .any(|audience| audience == &self.resource_uri)
        {
            return Err(anyhow!(
                "mcp_resource_server audience must include resource_uri"
            ));
        }
        if !self.metadata_path.starts_with('/') || self.metadata_path.starts_with("//") {
            return Err(anyhow!(
                "mcp_resource_server metadata_path must be an origin-relative path"
            ));
        }
        Ok(())
    }
}

fn validate_absolute_http_url(field: &str, value: &str) -> Result<()> {
    let parsed = url::Url::parse(value)
        .map_err(|_| anyhow!("mcp_resource_server {field} must be an absolute HTTP(S) URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.has_host()
        || parsed.fragment().is_some()
        || parsed.query().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(anyhow!(
            "mcp_resource_server {field} must be an absolute HTTP(S) URL without credentials, query, or fragment"
        ));
    }
    Ok(())
}

// --- Errors ---

/// Failure modes [`McpResourceServerProvider::authenticate`] can
/// return. Every variant maps to an RFC 6750 error code via
/// [`ResourceServerAuthError::rfc6750_error_code`].
#[derive(Debug, thiserror::Error)]
pub enum ResourceServerAuthError {
    /// No `Authorization: Bearer`/`DPoP` header at all.
    #[error("bearer token required")]
    MissingToken,
    /// Signature, issuer, audience, or expiry check failed.
    #[error("invalid bearer token: {0}")]
    InvalidToken(String),
    /// Token validated but is not bound to this resource (RFC 8707).
    #[error("token not bound to this resource ({0})")]
    NotBoundToResource(String),
    /// Token carries `cnf.jkt` but the request had no (or a
    /// mismatched) DPoP proof.
    #[error("dpop binding failed: {0}")]
    DpopBindingFailed(String),
    /// JWKS fetch or parse failed.
    #[error("jwks unavailable: {0}")]
    JwksUnavailable(String),
}

impl ResourceServerAuthError {
    /// RFC 6750 §3.1 error code for this failure.
    pub fn rfc6750_error_code(&self) -> &'static str {
        match self {
            Self::MissingToken => "invalid_request",
            Self::InvalidToken(_) => "invalid_token",
            Self::NotBoundToResource(_) => "invalid_token",
            Self::DpopBindingFailed(_) => "invalid_token",
            Self::JwksUnavailable(_) => "invalid_token",
        }
    }

    fn public_description(&self) -> &'static str {
        match self {
            Self::MissingToken => "access token required",
            Self::InvalidToken(_) | Self::NotBoundToResource(_) => "access token is invalid",
            Self::DpopBindingFailed(_) => "sender-constrained access token is invalid",
            Self::JwksUnavailable(_) => "access-token verification is temporarily unavailable",
        }
    }
}

/// The claims and resolved subject of a token that passed every check.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    /// The token's `sub` claim, or empty string when absent.
    pub sub: String,
    /// The full decoded claim set, for callers that need scopes or
    /// other application-specific fields.
    pub claims: serde_json::Value,
}

// --- JWKS cache ---

struct JwksCache {
    current: Mutex<Option<(Arc<JwkSet>, Instant)>>,
}

impl JwksCache {
    fn new() -> Self {
        Self {
            current: Mutex::new(None),
        }
    }

    async fn fetch_or_cached(
        &self,
        url: &str,
        ttl: Duration,
        allow_insecure_loopback: bool,
    ) -> Result<Arc<JwkSet>> {
        {
            let guard = self.current.lock().await;
            if let Some((set, at)) = guard.as_ref() {
                if at.elapsed() < ttl {
                    return Ok(set.clone());
                }
            }
        }
        let (_, pinned_http) = crate::egress::endpoint_client(url, allow_insecure_loopback)
            .await
            .map_err(|error| {
                anyhow!("resource JWKS endpoint rejected by egress policy: {error}")
            })?;
        let resp = pinned_http.get(url).send().await.map_err(|error| {
            tracing::warn!(
                target: "mcp_gateway::resource_server",
                error = %sbproxy_httpkit::request_error_summary(&error),
                "resource JWKS fetch failed"
            );
            anyhow!("resource JWKS endpoint unavailable")
        })?;
        if !resp.status().is_success() {
            return Err(anyhow!("jwks fetch returned status {}", resp.status()));
        }
        let body = crate::remote_body::bounded_response_body(
            resp,
            MAX_RESOURCE_JWKS_BYTES,
            "resource JWKS",
        )
        .await?;
        let set: JwkSet = serde_json::from_slice(&body)
            .map_err(|e| anyhow!("resource JWKS response is invalid JSON: {e}"))?;
        let arc = Arc::new(set);
        let mut guard = self.current.lock().await;
        *guard = Some((arc.clone(), Instant::now()));
        Ok(arc)
    }
}

// --- Provider ---

/// MCP resource-server token verifier.
pub struct McpResourceServerProvider {
    config: McpResourceServerConfig,
    jwks: JwksCache,
    /// Key set supplied in process rather than fetched.
    ///
    /// Set when the verifier's `jwks_url` is the colocated broker's own
    /// `/.well-known/jwks.json` route. That URL is the proxy's own
    /// external base URL, which inside a pod or behind a load balancer
    /// resolves to a private address or to a VIP the pod cannot
    /// hairpin, and the JWKS fetch goes through the egress policy,
    /// which refuses both. The result was that the documented
    /// single-process configuration 401'd every MCP request. There is
    /// no reason to dial ourselves for a key we are holding.
    local_jwks: Option<Arc<JwkSet>>,
    dpop_replay: Arc<DpopReplayCache>,
    revocations: Arc<crate::revoke::RevocationList>,
}

impl McpResourceServerProvider {
    /// Build a provider from validated config.
    pub fn new(config: McpResourceServerConfig) -> Result<Self> {
        Self::new_with_security_context(config, crate::McpSecurityContext::new())
    }

    /// Verify against `jwks` held in this process instead of fetching
    /// `jwks_url`.
    ///
    /// The one caller is the colocated configuration: an `mcp` action
    /// that compiles both an `oauth.broker` and an `oauth.resource_server`
    /// whose `jwks_url` is the broker's own route. Nothing else should
    /// use it: a real remote authorization server rotates its keys, and
    /// the fetch path is what picks that up.
    ///
    /// # Errors
    ///
    /// Returns an error when `jwks` carries no keys, which is the
    /// failure this exists to prevent: a broker signing key configured
    /// as a PEM with no `public_jwk` publishes an empty key set, and
    /// binding the verifier to it would 401 every request forever.
    /// Whether this provider verifies against an in-process key set
    /// rather than dialing `jwks_url`.
    ///
    /// Exists so a caller that wires the colocated shortcut can assert
    /// it took effect. The binding is a string comparison between two
    /// operator-supplied config values, and its failure mode is silent
    /// and total: the verifier falls back to the fetch, the egress
    /// policy refuses the proxy's own address, and every MCP request
    /// 401s. Nothing went red for that until this accessor let a test
    /// look.
    pub fn uses_local_jwks(&self) -> bool {
        self.local_jwks.is_some()
    }

    pub fn with_local_jwks(mut self, jwks: JwkSet) -> Result<Self> {
        if jwks.keys.is_empty() {
            return Err(anyhow!(
                "colocated resource server was given an empty key set: set oauth.broker.broker_signing_key.public_jwk"
            ));
        }
        self.local_jwks = Some(Arc::new(jwks));
        Ok(self)
    }

    /// Build a provider sharing runtime-local replay and revocation state
    /// with its colocated OAuth broker.
    pub fn new_with_security_context(
        config: McpResourceServerConfig,
        security: crate::McpSecurityContext,
    ) -> Result<Self> {
        config.validate()?;
        let replay_ttl_secs = 300_u64.max(config.dpop_max_clock_skew_secs.saturating_mul(2));
        let revocations = Arc::new(crate::revoke::RevocationList::new(
            security.store.clone(),
            security.namespace,
            crate::config::DEFAULT_REVOCATION_MAX_ENTRIES,
            Duration::from_secs(crate::config::DEFAULT_REVOCATION_MAX_TTL_SECS),
        ));
        Ok(Self {
            config,
            jwks: JwksCache::new(),
            local_jwks: None,
            dpop_replay: Arc::new(DpopReplayCache::with_prefix(
                security.store,
                Duration::from_secs(replay_ttl_secs),
                "resource:dpop:jti",
            )),
            revocations,
        })
    }

    /// Borrowed access to the validated config.
    pub fn config(&self) -> &McpResourceServerConfig {
        &self.config
    }

    /// Returns true when `path` matches the configured metadata path.
    pub fn matches_metadata_path(&self, path: &str) -> bool {
        path == self.config.metadata_path
    }

    /// Build the RFC 9728 protected-resource metadata document.
    pub fn metadata_document(&self) -> serde_json::Value {
        let mut doc = serde_json::json!({
            "resource": self.config.resource_uri,
            "authorization_servers": self.config.authorization_servers,
            "bearer_methods_supported": ["header"],
        });
        if !self.config.scopes_supported.is_empty() {
            doc["scopes_supported"] = serde_json::json!(self.config.scopes_supported);
        }
        if let Some(docs) = &self.config.resource_documentation {
            doc["resource_documentation"] = serde_json::json!(docs);
        }
        doc
    }

    /// Render [`Self::metadata_document`] as a JSON string.
    pub fn metadata_document_json(&self) -> String {
        serde_json::to_string(&self.metadata_document()).unwrap_or_else(|_| "{}".to_string())
    }

    /// `Cache-Control` value recommended for the metadata document.
    pub const METADATA_CACHE_CONTROL: &'static str = "public, max-age=300";

    /// Build the RFC 6750 `WWW-Authenticate` header value for a 401.
    pub fn www_authenticate_header(&self, err: &ResourceServerAuthError) -> String {
        // `metadata_path` is mounted at the resource origin by the live
        // action adapter. Do not append it to a resource URI path (for
        // example `/mcp`), which would advertise a route that is not served.
        let metadata_url = url::Url::parse(&self.config.resource_uri)
            .map(|url| {
                format!(
                    "{}{}",
                    url.origin().ascii_serialization().trim_end_matches('/'),
                    self.config.metadata_path
                )
            })
            .unwrap_or_else(|_| self.config.metadata_path.clone());
        let escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            "Bearer realm=\"{realm}\", resource_metadata=\"{md}\", error=\"{ec}\", error_description=\"{desc}\"",
            realm = escape(&self.config.resource_uri),
            md = escape(&metadata_url),
            ec = err.rfc6750_error_code(),
            desc = escape(err.public_description()),
        )
    }

    /// Verify an inbound request against every check the resource
    /// server owns: signature + issuer + audience + expiry, RFC 8707
    /// resource binding, and (when configured) RFC 9449 DPoP binding.
    ///
    /// `authorization_header` is the raw `Authorization` header value.
    /// `dpop_header`, `method`, and `url` are used whenever the
    /// presented token carries a signed `cnf.jkt` claim.
    pub async fn authenticate(
        &self,
        authorization_header: Option<&str>,
        dpop_header: Option<&str>,
        method: &str,
        url: &url::Url,
    ) -> Result<VerifiedToken, ResourceServerAuthError> {
        self.authenticate_with_certificate(authorization_header, dpop_header, method, url, None)
            .await
    }

    /// Wire-level variant that rejects duplicate credential/proof headers
    /// before choosing any value. Adjacent HTTP parsers must not disagree
    /// about which replayable proof was authenticated.
    pub async fn authenticate_header_values(
        &self,
        authorization_headers: &[&str],
        dpop_headers: &[&str],
        method: &str,
        url: &url::Url,
        verified_cert_x5t_s256: Option<&str>,
    ) -> Result<VerifiedToken, ResourceServerAuthError> {
        if authorization_headers.len() != 1 {
            return Err(if authorization_headers.is_empty() {
                ResourceServerAuthError::MissingToken
            } else {
                ResourceServerAuthError::InvalidToken(
                    "multiple authorization headers are not allowed".to_string(),
                )
            });
        }
        if dpop_headers.len() > 1 {
            return Err(ResourceServerAuthError::DpopBindingFailed(
                "multiple DPoP proof headers are not allowed".to_string(),
            ));
        }
        self.authenticate_with_certificate(
            Some(authorization_headers[0]),
            dpop_headers.first().copied(),
            method,
            url,
            verified_cert_x5t_s256,
        )
        .await
    }

    /// Authenticate with a certificate thumbprint obtained from the
    /// verified TLS connection. Forwarded certificate headers are not
    /// read here; the process integrating this provider owns the
    /// trusted-proxy boundary and passes only verified identity.
    pub async fn authenticate_with_certificate(
        &self,
        authorization_header: Option<&str>,
        dpop_header: Option<&str>,
        method: &str,
        url: &url::Url,
        verified_cert_x5t_s256: Option<&str>,
    ) -> Result<VerifiedToken, ResourceServerAuthError> {
        let (scheme, token) = parse_authorization(authorization_header)?;

        if self.revocations.contains(token).await {
            return Err(ResourceServerAuthError::InvalidToken(
                "token has been revoked".to_string(),
            ));
        }

        let claims = self.verify_signature_and_claims(token).await?;
        self.enforce_resource_binding(&claims)?;
        self.enforce_dpop_binding(&claims, scheme, token, dpop_header, method, url)
            .await?;
        self.enforce_mtls_binding(&claims, verified_cert_x5t_s256)?;

        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(VerifiedToken { sub, claims })
    }

    async fn verify_signature_and_claims(
        &self,
        token: &str,
    ) -> Result<serde_json::Value, ResourceServerAuthError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| ResourceServerAuthError::InvalidToken(format!("header: {e}")))?;
        if !header.typ.as_deref().is_some_and(|token_type| {
            token_type.eq_ignore_ascii_case("at+jwt")
                || token_type.eq_ignore_ascii_case("application/at+jwt")
        }) {
            return Err(ResourceServerAuthError::InvalidToken(
                "JWT typ must identify an access token (at+jwt)".to_string(),
            ));
        }
        let algorithm_name = format!("{:?}", header.alg);
        if !self
            .config
            .access_token_algorithms
            .iter()
            .any(|configured| configured == &algorithm_name)
        {
            return Err(ResourceServerAuthError::InvalidToken(format!(
                "JWT algorithm {algorithm_name} is not allowed"
            )));
        }
        let jwk_set = match self.local_jwks.as_ref() {
            Some(local) => local.clone(),
            None => self
                .jwks
                .fetch_or_cached(
                    &self.config.jwks_url,
                    Duration::from_secs(self.config.jwks_cache_ttl_secs.max(1)),
                    self.config.allow_insecure_loopback,
                )
                .await
                .map_err(|e| ResourceServerAuthError::JwksUnavailable(e.to_string()))?,
        };

        let issuer = self
            .config
            .issuer
            .clone()
            .unwrap_or_else(|| self.config.authorization_servers[0].clone());
        let audience = self.config.audience.as_list();

        let mut last_error: Option<String> = None;
        for jwk in candidate_keys(&jwk_set, header.kid.as_deref()) {
            if !jwk_matches_access_token_profile(jwk, header.alg) {
                continue;
            }
            let Ok(key) = DecodingKey::from_jwk(jwk) else {
                continue;
            };
            let mut validation = Validation::new(header.alg);
            validation.set_issuer(&[issuer.as_str()]);
            validation.set_audience(&audience);
            match jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation) {
                Ok(data) => match validate_rfc9068_claim_types(&data.claims) {
                    Ok(()) => return Ok(data.claims),
                    Err(error) => last_error = Some(error),
                },
                Err(e) => last_error = Some(e.to_string()),
            }
        }
        Err(ResourceServerAuthError::InvalidToken(
            last_error.unwrap_or_else(|| "no matching JWKS key verified the signature".into()),
        ))
    }

    fn enforce_resource_binding(
        &self,
        claims: &serde_json::Value,
    ) -> Result<(), ResourceServerAuthError> {
        let resource_uri = self.config.resource_uri.as_str();
        let bound = claim_contains(claims.get("resource"), resource_uri)
            || claim_contains(claims.get("aud"), resource_uri);
        if bound {
            Ok(())
        } else {
            Err(ResourceServerAuthError::NotBoundToResource(
                resource_uri.to_string(),
            ))
        }
    }

    async fn enforce_dpop_binding(
        &self,
        claims: &serde_json::Value,
        authorization_scheme: AuthorizationScheme,
        access_token: &str,
        dpop_header: Option<&str>,
        method: &str,
        url: &url::Url,
    ) -> Result<(), ResourceServerAuthError> {
        let Some(expected_jkt) = claims
            .get("cnf")
            .and_then(|c| c.get("jkt"))
            .and_then(|v| v.as_str())
        else {
            // Bearer-style token (no cnf.jkt): DPoP is opt-in per
            // token, not forced by the resource server.
            return Ok(());
        };
        if authorization_scheme != AuthorizationScheme::Dpop {
            return Err(ResourceServerAuthError::DpopBindingFailed(
                "DPoP authorization scheme required for sender-constrained token".to_string(),
            ));
        }
        let proof_header = dpop_header.ok_or_else(|| {
            ResourceServerAuthError::DpopBindingFailed(
                "DPoP proof required for sender-constrained token".to_string(),
            )
        })?;
        let proof = parse_and_verify(
            proof_header,
            method,
            url,
            Duration::from_secs(self.config.dpop_max_clock_skew_secs),
        )
        .map_err(|e: DpopError| ResourceServerAuthError::DpopBindingFailed(e.to_string()))?;
        let proof_jkt = jwk_thumbprint(&proof.jwk)
            .map_err(|e| ResourceServerAuthError::DpopBindingFailed(e.to_string()))?;
        if proof_jkt != expected_jkt {
            return Err(ResourceServerAuthError::DpopBindingFailed(
                "DPoP key thumbprint mismatch".to_string(),
            ));
        }
        let expected_ath = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(access_token.as_bytes()));
        let actual_ath = proof.ath.as_deref().ok_or_else(|| {
            ResourceServerAuthError::DpopBindingFailed(
                "DPoP ath claim required when an access token is used".to_string(),
            )
        })?;
        if !constant_time_eq(expected_ath.as_bytes(), actual_ath.as_bytes()) {
            return Err(ResourceServerAuthError::DpopBindingFailed(
                "DPoP ath does not match the presented access token".to_string(),
            ));
        }
        self.dpop_replay
            .record_jti(&proof)
            .await
            .map_err(|e| ResourceServerAuthError::DpopBindingFailed(e.to_string()))?;
        Ok(())
    }

    fn enforce_mtls_binding(
        &self,
        claims: &serde_json::Value,
        verified_cert_x5t_s256: Option<&str>,
    ) -> Result<(), ResourceServerAuthError> {
        let Some(expected) = claims.get("cnf").and_then(|cnf| cnf.get("x5t#S256")) else {
            return Ok(());
        };
        let expected = expected.as_str().ok_or_else(|| {
            ResourceServerAuthError::InvalidToken("cnf.x5t#S256 must be a string".to_string())
        })?;
        let actual = verified_cert_x5t_s256.ok_or_else(|| {
            ResourceServerAuthError::InvalidToken(
                "mTLS-bound token requires a verified client certificate".to_string(),
            )
        })?;
        if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
            return Err(ResourceServerAuthError::InvalidToken(
                "verified client certificate does not match cnf.x5t#S256".to_string(),
            ));
        }
        Ok(())
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthorizationScheme {
    Bearer,
    Dpop,
}

fn parse_authorization(
    authorization_header: Option<&str>,
) -> Result<(AuthorizationScheme, &str), ResourceServerAuthError> {
    let value = authorization_header.ok_or(ResourceServerAuthError::MissingToken)?;
    let (scheme, credential) = value
        .split_once(char::is_whitespace)
        .ok_or(ResourceServerAuthError::MissingToken)?;
    let scheme = if scheme.eq_ignore_ascii_case("bearer") {
        AuthorizationScheme::Bearer
    } else if scheme.eq_ignore_ascii_case("dpop") {
        AuthorizationScheme::Dpop
    } else {
        return Err(ResourceServerAuthError::MissingToken);
    };
    let credential = credential.trim();
    if credential.is_empty() || credential.chars().any(char::is_whitespace) {
        return Err(ResourceServerAuthError::MissingToken);
    }
    Ok((scheme, credential))
}

fn parse_access_token_algorithm(value: &str) -> Result<Algorithm> {
    match value {
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "EdDSA" => Ok(Algorithm::EdDSA),
        other => Err(anyhow!(
            "mcp_resource_server access_token_algorithms contains unsupported or symmetric algorithm {other:?}"
        )),
    }
}

fn jwk_matches_access_token_profile(jwk: &jsonwebtoken::jwk::Jwk, algorithm: Algorithm) -> bool {
    if jwk.common.public_key_use != Some(PublicKeyUse::Signature) {
        return false;
    }
    if jwk.common.key_algorithm.map(|value| value.to_string()) != Some(format!("{algorithm:?}")) {
        return false;
    }
    matches!(
        (&jwk.algorithm, algorithm),
        (
            AlgorithmParameters::EllipticCurve(_),
            Algorithm::ES256 | Algorithm::ES384
        ) | (
            AlgorithmParameters::RSA(_),
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
        ) | (AlgorithmParameters::OctetKeyPair(_), Algorithm::EdDSA)
    )
}

fn validate_rfc9068_claim_types(claims: &serde_json::Value) -> Result<(), String> {
    let object = claims
        .as_object()
        .ok_or_else(|| "access-token claims must be a JSON object".to_string())?;
    for claim in ["iss", "sub", "client_id", "jti"] {
        if object
            .get(claim)
            .and_then(serde_json::Value::as_str)
            .is_none_or(|value| value.is_empty())
        {
            return Err(format!(
                "access token requires non-empty string claim {claim}"
            ));
        }
    }
    for claim in ["exp", "iat"] {
        if object
            .get(claim)
            .and_then(serde_json::Value::as_i64)
            .is_none()
        {
            return Err(format!("access token requires integer claim {claim}"));
        }
    }
    let audience_is_valid = match object.get("aud") {
        Some(serde_json::Value::String(value)) => !value.is_empty(),
        Some(serde_json::Value::Array(values)) => {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|audience| !audience.is_empty()))
        }
        _ => false,
    };
    if !audience_is_valid {
        return Err("access token requires string or non-empty string-array aud claim".to_string());
    }
    if object.get("scope").is_some_and(|scope| !scope.is_string()) {
        return Err("access token scope claim must be a string".to_string());
    }
    Ok(())
}

/// The JWKs a token's header selects.
///
/// When the token carries a `kid`, only keys advertising exactly that
/// `kid` are candidates, and there is no fallback to the rest of the
/// set: a token naming a key the AS has retired must not verify against
/// its replacement. When the token carries no `kid`, every key in the
/// set is a candidate, which tolerates an AS that publishes keys
/// without one (uncommon but not spec-violating).
fn candidate_keys<'a>(
    set: &'a JwkSet,
    kid: Option<&str>,
) -> impl Iterator<Item = &'a jsonwebtoken::jwk::Jwk> {
    let kid = kid.map(str::to_string);
    set.keys.iter().filter(move |key| match &kid {
        Some(kid) => key.common.key_id.as_deref() == Some(kid.as_str()),
        None => true,
    })
}

fn claim_contains(claim: Option<&serde_json::Value>, needle: &str) -> bool {
    match claim {
        Some(serde_json::Value::String(s)) => s == needle,
        Some(serde_json::Value::Array(values)) => values.iter().any(|v| v.as_str() == Some(needle)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Same ES256 test key used by dpop.rs's test suite, reused here so
    // this module does not need its own key-material fixture.
    const ES256_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
-----END PRIVATE KEY-----\n";
    const TEST_KID: &str = "rs-test-key-1";

    fn jwk_value() -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84",
            "y": "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY",
            "kid": TEST_KID,
            "use": "sig",
            "alg": "ES256",
        })
    }

    fn complete_claims(mut overrides: serde_json::Value) -> serde_json::Value {
        let mut claims = serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "aud": "https://mcp.example.com",
            "resource": "https://mcp.example.com",
            "exp": now() + 300,
            "iat": now(),
            "jti": "access-token-jti",
            "client_id": "client-1",
            "scope": "mcp:read"
        });
        if let (Some(base), Some(extra)) = (claims.as_object_mut(), overrides.as_object_mut()) {
            base.append(extra);
        }
        claims
    }

    fn issue_jwt(claims: serde_json::Value) -> String {
        issue_jwt_with_type(complete_claims(claims), Some("at+jwt"))
    }

    fn issue_jwt_with_type(claims: serde_json::Value, token_type: Option<&str>) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(TEST_KID.to_string());
        header.typ = token_type.map(str::to_string);
        let key = EncodingKey::from_ec_pem(ES256_PRIVATE_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    async fn spawn_jwks_server() -> SocketAddr {
        let body = serde_json::json!({"keys": [jwk_value()]}).to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = vec![0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
            }
        });
        addr
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn base_config(jwks_url: String) -> McpResourceServerConfig {
        McpResourceServerConfig {
            resource_uri: "https://mcp.example.com".to_string(),
            authorization_servers: vec!["https://auth.example.com".to_string()],
            jwks_url,
            allow_insecure_loopback: true,
            audience: AudienceConfig::Single("https://mcp.example.com".to_string()),
            issuer: Some("https://auth.example.com".to_string()),
            jwks_cache_ttl_secs: 300,
            scopes_supported: vec!["mcp:read".to_string()],
            access_token_algorithms: vec!["ES256".to_string()],
            resource_documentation: Some("https://mcp.example.com/docs".to_string()),
            metadata_path: default_metadata_path(),
            dpop_enforce_binding: false,
            dpop_max_clock_skew_secs: 30,
        }
    }

    // --- Config validation ---

    #[test]
    fn validate_rejects_missing_resource_uri() {
        let mut cfg = base_config("http://x".to_string());
        cfg.resource_uri = String::new();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("resource_uri"));
    }

    #[test]
    fn validate_rejects_empty_authorization_servers() {
        let mut cfg = base_config("http://x".to_string());
        cfg.authorization_servers.clear();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("authorization_servers"));
    }

    #[test]
    fn validate_rejects_empty_jwks_url() {
        let mut cfg = base_config("http://x".to_string());
        cfg.jwks_url = String::new();
        assert!(cfg.validate().unwrap_err().to_string().contains("jwks_url"));
    }

    #[test]
    fn validate_rejects_relative_or_mismatched_resource_configuration() {
        let mut relative = base_config("http://x".to_string());
        relative.resource_uri = "/mcp".to_string();
        assert!(relative.validate().is_err());

        let mut mismatch = base_config("http://x".to_string());
        mismatch.audience = AudienceConfig::Single("https://other.example".to_string());
        assert!(mismatch.validate().is_err());
    }

    #[test]
    fn audience_config_accepts_single_or_multi() {
        let single: AudienceConfig = serde_json::from_value(serde_json::json!("a")).unwrap();
        assert_eq!(single.as_list(), vec!["a"]);
        let multi: AudienceConfig = serde_json::from_value(serde_json::json!(["a", "b"])).unwrap();
        assert_eq!(multi.as_list(), vec!["a", "b"]);
    }

    // --- Metadata + challenge ---

    #[tokio::test]
    async fn metadata_document_has_rfc9728_shape() {
        let provider = McpResourceServerProvider::new(base_config("http://x".to_string())).unwrap();
        let doc = provider.metadata_document();
        assert_eq!(doc["resource"], "https://mcp.example.com");
        assert_eq!(doc["authorization_servers"][0], "https://auth.example.com");
        assert_eq!(doc["scopes_supported"][0], "mcp:read");
    }

    #[tokio::test]
    async fn www_authenticate_carries_resource_metadata() {
        let provider = McpResourceServerProvider::new(base_config("http://x".to_string())).unwrap();
        let header = provider.www_authenticate_header(&ResourceServerAuthError::MissingToken);
        assert!(header.starts_with("Bearer "));
        assert!(header.contains(
            "resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\""
        ));
        assert!(header.contains("error=\"invalid_request\""));
    }

    // --- Token verification ---

    #[tokio::test]
    async fn missing_token_is_rejected() {
        let provider = McpResourceServerProvider::new(base_config("http://x".to_string())).unwrap();
        let url = url::Url::parse("https://mcp.example.com/tools/call").unwrap();
        let err = provider
            .authenticate(None, None, "POST", &url)
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceServerAuthError::MissingToken));
    }

    #[tokio::test]
    async fn locally_revoked_token_is_rejected_before_jwks_validation() {
        let token = "resource-provider-revoked-token";
        let security = crate::McpSecurityContext::for_test("revoked-test");
        let revocations = crate::revoke::RevocationList::new(
            security.store.clone(),
            security.namespace.clone(),
            4,
            Duration::from_secs(60),
        );
        revocations
            .record_validated(token, now() + 60)
            .await
            .unwrap();
        let provider = McpResourceServerProvider::new_with_security_context(
            base_config("http://x".to_string()),
            security,
        )
        .unwrap();
        let err = provider
            .authenticate(
                Some(&format!("Bearer {token}")),
                None,
                "POST",
                &url::Url::parse("https://mcp.example/api").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");
    }

    #[tokio::test]
    async fn valid_token_bound_to_resource_is_accepted() {
        let addr = spawn_jwks_server().await;
        let cfg = base_config(format!("http://{addr}/jwks.json"));
        let provider = McpResourceServerProvider::new(cfg).unwrap();
        let token = issue_jwt(serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "aud": "https://mcp.example.com",
            "resource": "https://mcp.example.com",
            "exp": now() + 300,
        }));
        let url = url::Url::parse("https://mcp.example.com/tools/call").unwrap();
        let header = format!("Bearer {token}");
        let verified = provider
            .authenticate(Some(&header), None, "POST", &url)
            .await
            .expect("token should verify");
        assert_eq!(verified.sub, "user-1");
    }

    #[tokio::test]
    async fn authorization_scheme_is_case_insensitive() {
        let addr = spawn_jwks_server().await;
        let provider =
            McpResourceServerProvider::new(base_config(format!("http://{addr}/jwks.json")))
                .unwrap();
        let token = issue_jwt(serde_json::json!({}));
        let verified = provider
            .authenticate(
                Some(&format!("bEaReR {token}")),
                None,
                "POST",
                &url::Url::parse("https://mcp.example.com/tools/call").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verified.sub, "user-1");
    }

    #[tokio::test]
    async fn duplicate_dpop_proof_headers_are_rejected_before_crypto() {
        let provider = McpResourceServerProvider::new(base_config("http://x".to_string())).unwrap();
        let error = provider
            .authenticate_header_values(
                &["DPoP opaque"],
                &["proof-one", "proof-two"],
                "POST",
                &url::Url::parse("https://mcp.example.com/tools/call").unwrap(),
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("multiple DPoP"), "{error}");
    }

    #[tokio::test]
    async fn id_token_type_is_rejected_even_when_signature_and_audience_match() {
        let addr = spawn_jwks_server().await;
        let provider =
            McpResourceServerProvider::new(base_config(format!("http://{addr}/jwks.json")))
                .unwrap();
        let token = issue_jwt_with_type(complete_claims(serde_json::json!({})), Some("JWT"));
        let error = provider
            .authenticate(
                Some(&format!("Bearer {token}")),
                None,
                "POST",
                &url::Url::parse("https://mcp.example.com/tools/call").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("typ"), "{error}");
    }

    #[tokio::test]
    async fn missing_rfc9068_claim_is_rejected() {
        let addr = spawn_jwks_server().await;
        let provider =
            McpResourceServerProvider::new(base_config(format!("http://{addr}/jwks.json")))
                .unwrap();
        let mut claims = complete_claims(serde_json::json!({}));
        claims.as_object_mut().unwrap().remove("client_id");
        let token = issue_jwt_with_type(claims, Some("at+jwt"));
        let error = provider
            .authenticate(
                Some(&format!("Bearer {token}")),
                None,
                "POST",
                &url::Url::parse("https://mcp.example.com/tools/call").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, ResourceServerAuthError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn dpop_bound_token_is_rejected_under_bearer_scheme() {
        let addr = spawn_jwks_server().await;
        let provider =
            McpResourceServerProvider::new(base_config(format!("http://{addr}/jwks.json")))
                .unwrap();
        let token = issue_jwt(serde_json::json!({"cnf":{"jkt":"some-key"}}));
        let error = provider
            .authenticate(
                Some(&format!("Bearer {token}")),
                Some("not-needed-before-scheme-check"),
                "POST",
                &url::Url::parse("https://mcp.example.com/tools/call").unwrap(),
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("DPoP authorization scheme"),
            "{error}"
        );
    }

    #[test]
    fn public_challenge_never_reflects_transport_detail() {
        let provider = McpResourceServerProvider::new(base_config("http://x".to_string())).unwrap();
        let challenge =
            provider.www_authenticate_header(&ResourceServerAuthError::JwksUnavailable(
                "https://internal.example/jwks?sig=CANARY-SECRET".to_string(),
            ));
        assert!(!challenge.contains("CANARY-SECRET"), "{challenge}");
        assert!(!challenge.contains("internal.example"), "{challenge}");
    }

    #[tokio::test]
    async fn token_not_bound_to_resource_is_rejected() {
        // `aud` must also disagree with `resource_uri`, otherwise the
        // `resource`-claim mismatch is masked by the `aud` fallback
        // succeeding: this fixture is a token genuinely issued for a
        // different resource, not one that merely omits `resource`.
        let addr = spawn_jwks_server().await;
        let cfg = base_config(format!("http://{addr}/jwks.json"));
        // A validation audience wide enough to admit the mismatched
        // token past signature/claims decode, so the RFC 8707 binding
        // check (not `Validation::set_audience`) is what rejects it.
        let mut cfg = cfg;
        cfg.audience = AudienceConfig::Multi(vec![
            "https://mcp.example.com".to_string(),
            "https://other-mcp.example.com".to_string(),
        ]);
        let provider = McpResourceServerProvider::new(cfg).unwrap();
        let token = issue_jwt(serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "aud": "https://other-mcp.example.com",
            "resource": "https://other-mcp.example.com",
            "exp": now() + 300,
        }));
        let url = url::Url::parse("https://mcp.example.com/tools/call").unwrap();
        let header = format!("Bearer {token}");
        let err = provider
            .authenticate(Some(&header), None, "POST", &url)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ResourceServerAuthError::NotBoundToResource(_)
        ));
    }

    #[tokio::test]
    async fn wrong_issuer_is_rejected() {
        let addr = spawn_jwks_server().await;
        let cfg = base_config(format!("http://{addr}/jwks.json"));
        let provider = McpResourceServerProvider::new(cfg).unwrap();
        let token = issue_jwt(serde_json::json!({
            "iss": "https://attacker.example",
            "sub": "user-1",
            "aud": "https://mcp.example.com",
            "resource": "https://mcp.example.com",
            "exp": now() + 300,
        }));
        let url = url::Url::parse("https://mcp.example.com/tools/call").unwrap();
        let header = format!("Bearer {token}");
        let err = provider
            .authenticate(Some(&header), None, "POST", &url)
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceServerAuthError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let addr = spawn_jwks_server().await;
        let cfg = base_config(format!("http://{addr}/jwks.json"));
        let provider = McpResourceServerProvider::new(cfg).unwrap();
        let token = issue_jwt(serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "aud": "https://mcp.example.com",
            "resource": "https://mcp.example.com",
            "exp": now() - 300,
        }));
        let url = url::Url::parse("https://mcp.example.com/tools/call").unwrap();
        let header = format!("Bearer {token}");
        let err = provider
            .authenticate(Some(&header), None, "POST", &url)
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceServerAuthError::InvalidToken(_)));
    }

    // --- DPoP binding ---

    #[tokio::test]
    async fn dpop_bound_token_without_proof_is_rejected() {
        let addr = spawn_jwks_server().await;
        let mut cfg = base_config(format!("http://{addr}/jwks.json"));
        cfg.dpop_enforce_binding = true;
        let provider = McpResourceServerProvider::new(cfg).unwrap();
        let jkt = jwk_thumbprint(&serde_json::from_value(jwk_value()).unwrap()).unwrap();
        let token = issue_jwt(serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "aud": "https://mcp.example.com",
            "resource": "https://mcp.example.com",
            "exp": now() + 300,
            "cnf": {"jkt": jkt},
        }));
        let url = url::Url::parse("https://mcp.example.com/tools/call").unwrap();
        let header = format!("DPoP {token}");
        let err = provider
            .authenticate(Some(&header), None, "POST", &url)
            .await
            .unwrap_err();
        assert!(matches!(err, ResourceServerAuthError::DpopBindingFailed(_)));
    }

    #[tokio::test]
    async fn dpop_bound_token_with_matching_key_but_no_ath_is_rejected() {
        let addr = spawn_jwks_server().await;
        let mut cfg = base_config(format!("http://{addr}/jwks.json"));
        cfg.dpop_enforce_binding = true;
        let provider = McpResourceServerProvider::new(cfg).unwrap();
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_value()).unwrap();
        let jkt = jwk_thumbprint(&jwk).unwrap();
        let token = issue_jwt(serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "aud": "https://mcp.example.com",
            "resource": "https://mcp.example.com",
            "exp": now() + 300,
            "cnf": {"jkt": jkt},
        }));
        let url = url::Url::parse("https://mcp.example.com/tools/call").unwrap();
        let key = EncodingKey::from_ec_pem(ES256_PRIVATE_PEM.as_bytes()).unwrap();
        let mut proof_header = Header::new(jsonwebtoken::Algorithm::ES256);
        proof_header.typ = Some("dpop+jwt".to_string());
        proof_header.jwk = Some(jwk);
        let proof_claims = serde_json::json!({
            "htm": "POST",
            "htu": "https://mcp.example.com/tools/call",
            "iat": now(),
            "jti": "proof-1",
        });
        let proof = encode(&proof_header, &proof_claims, &key).unwrap();
        let auth_header = format!("DPoP {token}");
        let err = provider
            .authenticate(Some(&auth_header), Some(&proof), "POST", &url)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ath"));
    }

    #[tokio::test]
    async fn dpop_bound_token_requires_matching_ath_and_single_use_jti() {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let addr = spawn_jwks_server().await;
        let mut cfg = base_config(format!("http://{addr}/jwks.json"));
        cfg.dpop_enforce_binding = true;
        let provider = McpResourceServerProvider::new(cfg).unwrap();
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_value()).unwrap();
        let jkt = jwk_thumbprint(&jwk).unwrap();
        let token = issue_jwt(serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "aud": "https://mcp.example.com",
            "resource": "https://mcp.example.com",
            "exp": now() + 300,
            "cnf": {"jkt": jkt},
        }));
        let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(token.as_bytes()));
        let url = url::Url::parse("https://mcp.example.com/tools/call").unwrap();
        let key = EncodingKey::from_ec_pem(ES256_PRIVATE_PEM.as_bytes()).unwrap();
        let mut proof_header = Header::new(jsonwebtoken::Algorithm::ES256);
        proof_header.typ = Some("dpop+jwt".to_string());
        proof_header.jwk = Some(jwk);
        let proof = encode(
            &proof_header,
            &serde_json::json!({
                "htm": "POST",
                "htu": "https://mcp.example.com/tools/call",
                "iat": now(),
                "jti": "proof-single-use",
                "ath": ath,
            }),
            &key,
        )
        .unwrap();
        let auth_header = format!("DPoP {token}");

        let verified = provider
            .authenticate(Some(&auth_header), Some(&proof), "POST", &url)
            .await
            .expect("matching ath must verify once");
        assert_eq!(verified.sub, "user-1");
        let replay = provider
            .authenticate(Some(&auth_header), Some(&proof), "POST", &url)
            .await
            .unwrap_err();
        assert!(replay.to_string().contains("replay"));
    }

    #[tokio::test]
    async fn bearer_only_token_skips_dpop_check_even_when_enforced() {
        let addr = spawn_jwks_server().await;
        let mut cfg = base_config(format!("http://{addr}/jwks.json"));
        cfg.dpop_enforce_binding = true;
        let provider = McpResourceServerProvider::new(cfg).unwrap();
        // No cnf.jkt claim: this is a plain bearer token.
        let token = issue_jwt(serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "aud": "https://mcp.example.com",
            "resource": "https://mcp.example.com",
            "exp": now() + 300,
        }));
        let url = url::Url::parse("https://mcp.example.com/tools/call").unwrap();
        let header = format!("Bearer {token}");
        let verified = provider
            .authenticate(Some(&header), None, "POST", &url)
            .await
            .expect("bearer-only token needs no DPoP proof");
        assert_eq!(verified.sub, "user-1");
    }

    #[tokio::test]
    async fn mtls_bound_token_requires_verified_connection_identity_not_xfcc() {
        let addr = spawn_jwks_server().await;
        let cfg = base_config(format!("http://{addr}/jwks.json"));
        let provider = McpResourceServerProvider::new(cfg).unwrap();
        let token = issue_jwt(serde_json::json!({
            "iss": "https://auth.example.com",
            "sub": "user-1",
            "aud": "https://mcp.example.com",
            "resource": "https://mcp.example.com",
            "exp": now() + 300,
            "cnf": {"x5t#S256": "verified-thumbprint"},
        }));
        let url = url::Url::parse("https://mcp.example.com/tools/call").unwrap();
        let header = format!("Bearer {token}");

        let missing = provider
            .authenticate(Some(&header), None, "POST", &url)
            .await
            .unwrap_err();
        assert!(missing.to_string().contains("verified client certificate"));
        let verified = provider
            .authenticate_with_certificate(
                Some(&header),
                None,
                "POST",
                &url,
                Some("verified-thumbprint"),
            )
            .await
            .expect("direct verified certificate identity must satisfy cnf");
        assert_eq!(verified.sub, "user-1");
    }
}
