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
//! This crate does not attempt to register itself as an
//! `sbproxy_plugin::AuthProvider` inside `sbproxy-modules`. Doing so
//! would need an exhaustive match over every `Auth` enum variant in
//! `sbproxy-core`'s request dispatch (`dispatch.rs`, `server.rs`,
//! `server/request_phase.rs`) to grow a new arm, which is exactly the
//! kind of shared-file change this ticket was scoped to avoid making.
//! `McpResourceServerProvider` is instead a plain, dependency-free
//! async type: an integrator wires `McpResourceServerProvider::authenticate`
//! into whatever dispatch shim fronts their MCP origin, the same
//! posture the enterprise version of this file already documented for
//! its own engine ("until it grows [a per-provider hook], callers can
//! invoke `metadata_document()` ... from a startup-hook-installed
//! dispatch shim").

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::dpop::{jwk_thumbprint, parse_and_verify, DpopError};

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
#[derive(Debug, Clone, Deserialize)]
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

    /// Optional documentation URL (RFC 9728 `resource_documentation`).
    #[serde(default)]
    pub resource_documentation: Option<String>,

    /// Path the metadata document is served from.
    #[serde(default = "default_metadata_path")]
    pub metadata_path: String,

    /// When true, a token carrying a `cnf.jkt` claim MUST be
    /// accompanied by a matching RFC 9449 DPoP proof. Tokens without
    /// `cnf.jkt` are unaffected (they are bearer-style by the
    /// broker's own choice, not a downgrade the resource server
    /// forces).
    #[serde(default)]
    pub dpop_enforce_binding: bool,

    /// Maximum acceptable skew between a DPoP proof's `iat` and wall
    /// clock, in seconds. Honoured only when `dpop_enforce_binding` is
    /// true.
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

impl McpResourceServerConfig {
    /// Validate cross-field invariants.
    pub fn validate(&self) -> Result<()> {
        if self.resource_uri.trim().is_empty() {
            return Err(anyhow!("mcp_resource_server requires resource_uri"));
        }
        if self.authorization_servers.is_empty() {
            return Err(anyhow!(
                "mcp_resource_server requires at least one authorization_servers entry"
            ));
        }
        for as_url in &self.authorization_servers {
            if as_url.trim().is_empty() {
                return Err(anyhow!(
                    "mcp_resource_server authorization_servers entries must be non-empty"
                ));
            }
        }
        if self.jwks_url.trim().is_empty() {
            return Err(anyhow!("mcp_resource_server requires jwks_url"));
        }
        if self.audience.as_list().is_empty()
            || self.audience.as_list().iter().any(|s| s.trim().is_empty())
        {
            return Err(anyhow!(
                "mcp_resource_server audience must contain at least one non-empty value"
            ));
        }
        Ok(())
    }
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
        http: &reqwest::Client,
        url: &str,
        ttl: Duration,
    ) -> Result<Arc<JwkSet>> {
        {
            let guard = self.current.lock().await;
            if let Some((set, at)) = guard.as_ref() {
                if at.elapsed() < ttl {
                    return Ok(set.clone());
                }
            }
        }
        let resp = http
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("jwks fetch failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(anyhow!("jwks fetch returned status {}", resp.status()));
        }
        let set: JwkSet = resp
            .json()
            .await
            .map_err(|e| anyhow!("jwks parse failed: {e}"))?;
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
    http: reqwest::Client,
    jwks: JwksCache,
}

impl McpResourceServerProvider {
    /// Build a provider from validated config.
    pub fn new(config: McpResourceServerConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            http: sbproxy_httpkit::default_outbound(),
            jwks: JwksCache::new(),
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
        let metadata_url = format!(
            "{}{}",
            self.config.resource_uri.trim_end_matches('/'),
            self.config.metadata_path
        );
        let escape = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            "Bearer realm=\"{realm}\", resource_metadata=\"{md}\", error=\"{ec}\", error_description=\"{desc}\"",
            realm = escape(&self.config.resource_uri),
            md = escape(&metadata_url),
            ec = err.rfc6750_error_code(),
            desc = escape(&err.to_string()),
        )
    }

    /// Verify an inbound request against every check the resource
    /// server owns: signature + issuer + audience + expiry, RFC 8707
    /// resource binding, and (when configured) RFC 9449 DPoP binding.
    ///
    /// `authorization_header` is the raw `Authorization` header value.
    /// `dpop_header`, `method`, and `url` are needed only when
    /// `dpop_enforce_binding` is set and the presented token carries a
    /// `cnf.jkt` claim.
    pub async fn authenticate(
        &self,
        authorization_header: Option<&str>,
        dpop_header: Option<&str>,
        method: &str,
        url: &url::Url,
    ) -> Result<VerifiedToken, ResourceServerAuthError> {
        let token = authorization_header
            .and_then(|v| {
                v.strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("DPoP "))
            })
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(ResourceServerAuthError::MissingToken)?;

        let claims = self.verify_signature_and_claims(token).await?;
        self.enforce_resource_binding(&claims)?;
        if self.config.dpop_enforce_binding {
            self.enforce_dpop_binding(&claims, dpop_header, method, url)?;
        }

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
        let jwk_set = self
            .jwks
            .fetch_or_cached(
                &self.http,
                &self.config.jwks_url,
                Duration::from_secs(self.config.jwks_cache_ttl_secs.max(1)),
            )
            .await
            .map_err(|e| ResourceServerAuthError::JwksUnavailable(e.to_string()))?;

        let issuer = self
            .config
            .issuer
            .clone()
            .unwrap_or_else(|| self.config.authorization_servers[0].clone());
        let audience = self.config.audience.as_list();

        let mut last_error: Option<String> = None;
        for jwk in candidate_keys(&jwk_set, header.kid.as_deref()) {
            let Ok(key) = DecodingKey::from_jwk(jwk) else {
                continue;
            };
            let mut validation = Validation::new(header.alg);
            validation.set_issuer(&[issuer.as_str()]);
            validation.set_audience(&audience);
            match jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation) {
                Ok(data) => return Ok(data.claims),
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

    fn enforce_dpop_binding(
        &self,
        claims: &serde_json::Value,
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
        Ok(())
    }
}

/// Candidate JWKs to try, in preference order: an exact `kid` match
/// first (when the token carries one and a key advertises it), then
/// every remaining key. Trying every key rather than failing outright
/// on a `kid` miss tolerates an AS that publishes keys without `kid`
/// (uncommon but not spec-violating).
fn candidate_keys<'a>(
    set: &'a JwkSet,
    kid: Option<&str>,
) -> impl Iterator<Item = &'a jsonwebtoken::jwk::Jwk> {
    let kid = kid.map(str::to_string);
    let (matching, rest): (Vec<_>, Vec<_>) = set.keys.iter().partition(|k| match &kid {
        Some(k_id) => k.common.key_id.as_deref() == Some(k_id.as_str()),
        None => false,
    });
    matching.into_iter().chain(rest)
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

    fn issue_jwt(claims: serde_json::Value) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(TEST_KID.to_string());
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
            audience: AudienceConfig::Single("https://mcp.example.com".to_string()),
            issuer: Some("https://auth.example.com".to_string()),
            jwks_cache_ttl_secs: 300,
            scopes_supported: vec!["mcp:read".to_string()],
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
    async fn dpop_bound_token_with_matching_proof_is_accepted() {
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
        let verified = provider
            .authenticate(Some(&auth_header), Some(&proof), "POST", &url)
            .await
            .expect("dpop-bound token with matching proof must verify");
        assert_eq!(verified.sub, "user-1");
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
}
