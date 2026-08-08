//! Outbound credential resolver (WOR-802).
//!
//! Mints or resolves the credential SBproxy presents to an upstream, so
//! the agent or client never handles a per-upstream secret. Three modes,
//! selected per origin:
//!
//! - **`token_exchange`**: RFC 8693 OAuth token exchange. Exchanges the
//!   inbound subject token for a token scoped to the upstream's
//!   audience, enforcing the `subject_token_issuers` and
//!   `allowed_audiences` allowlists and an `act` delegation-chain depth
//!   cap. Both allowlists are required and must be non-empty: an empty
//!   list denies every token rather than accepting any, and a config
//!   that omits either one fails to compile.
//! - **`client_credentials`**: OAuth 2.0 client-credentials grant.
//! - **`vault_secret`**: a static secret resolved from the vault and
//!   formatted as an authorization header.
//!
//! See `docs/adr-outbound-credential-resolver.md` for the OSS vs
//! enterprise line and `docs/outbound-dpop.md` for RFC 9449 sender
//! constraint configuration.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use dashmap::DashMap;
use sbproxy_security::egress::{
    record_egress_refused, CachedSystemResolver, EgressAuthorizer, EgressDenied, EgressPurpose,
    HostResolver,
};
use serde::Deserialize;

use super::dpop_outbound::{validate_nonce, DpopOutboundConfig, DpopRuntime, DpopSignerError};

/// RFC 8693 grant type for token exchange.
const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693 token-type URI for an OAuth access token.
const TOKEN_TYPE_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";

fn default_act_depth_cap() -> usize {
    4
}
fn default_cred_header() -> String {
    "authorization".to_string()
}
fn default_cred_scheme() -> String {
    "Bearer".to_string()
}

/// Per-origin outbound credential configuration. The `type` tag selects
/// the mode; unknown modes fail config compilation (closed enum) rather
/// than silently falling back.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundCredentialConfig {
    /// RFC 8693 token exchange.
    TokenExchange(TokenExchangeConfig),
    /// OAuth 2.0 client-credentials grant.
    ClientCredentials(ClientCredentialsConfig),
    /// Static secret resolved from the vault.
    VaultSecret(VaultSecretConfig),
}

/// RFC 8693 token-exchange settings.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenExchangeConfig {
    /// Token endpoint that performs the exchange.
    pub token_endpoint: String,
    /// Audience requested for the exchanged token (the upstream).
    pub audience: String,
    /// Optional requested scope.
    #[serde(default)]
    pub scope: Option<String>,
    /// Allowlist of acceptable subject-token issuers (`iss`). Required
    /// and non-empty: an empty list denies every subject token, and
    /// [`OutboundCredentialConfig::validate_allowlists`] refuses the
    /// config before it can reach a running proxy.
    #[serde(default)]
    pub subject_token_issuers: Vec<String>,
    /// Allowlist of audiences this origin may request. Required and
    /// non-empty on the same terms as [`Self::subject_token_issuers`];
    /// the configured `audience` must appear here.
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    /// Maximum `act` delegation-chain depth on the subject token.
    /// Defaults to 4.
    #[serde(default = "default_act_depth_cap")]
    pub act_depth_cap: usize,
    /// Optional client id for authenticating to the token endpoint.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Optional client secret (a vault reference) for the token
    /// endpoint.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Optional RFC 9449 sender constraint for the minted token.
    #[serde(default)]
    pub dpop: Option<DpopOutboundConfig>,
}

/// OAuth 2.0 client-credentials settings.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientCredentialsConfig {
    /// Token endpoint that issues the client-credentials token.
    pub token_endpoint: String,
    /// OAuth client id.
    pub client_id: String,
    /// OAuth client secret (a vault reference).
    pub client_secret: String,
    /// Optional requested scope.
    #[serde(default)]
    pub scope: Option<String>,
    /// Optional requested audience.
    #[serde(default)]
    pub audience: Option<String>,
    /// Optional RFC 9449 sender constraint for the minted token.
    #[serde(default)]
    pub dpop: Option<DpopOutboundConfig>,
}

/// Static vault-resolved secret settings.
#[derive(Debug, Clone, Deserialize)]
pub struct VaultSecretConfig {
    /// Vault reference (or literal) for the secret.
    pub secret: String,
    /// Header to set. Defaults to `authorization`.
    #[serde(default = "default_cred_header")]
    pub header: String,
    /// Scheme prefix for the header value. Defaults to `Bearer`; set to
    /// an empty string to emit the bare secret.
    #[serde(default = "default_cred_scheme")]
    pub scheme: String,
    /// Optional RFC 9449 sender constraint for a pre-issued access token.
    #[serde(default)]
    pub dpop: Option<DpopOutboundConfig>,
}

impl OutboundCredentialConfig {
    /// Resolve provider-URI secret references (WOR-1784) in this credential's
    /// secret-bearing fields through the process secret resolver, so a
    /// `vault://` / `secret://` reference becomes the real secret at config
    /// load rather than being sent to the token endpoint verbatim. An
    /// unresolved reference is a hard error. No-op when no resolver is
    /// installed (the validate/plan subcommands, unit tests).
    pub fn resolve_secret_refs(&mut self) -> anyhow::Result<()> {
        let resolver = sbproxy_vault::process_resolver();
        match self {
            OutboundCredentialConfig::TokenExchange(c) => {
                if let (Some(resolver), Some(secret)) = (&resolver, c.client_secret.take()) {
                    c.client_secret = Some(
                        resolver
                            .resolve(&secret)
                            .map_err(|e| anyhow::anyhow!("token_exchange client_secret: {e}"))?,
                    );
                }
            }
            OutboundCredentialConfig::ClientCredentials(c) => {
                if let Some(resolver) = &resolver {
                    c.client_secret = resolver
                        .resolve(&c.client_secret)
                        .map_err(|e| anyhow::anyhow!("client_credentials client_secret: {e}"))?;
                }
            }
            OutboundCredentialConfig::VaultSecret(c) => {
                if let Some(resolver) = &resolver {
                    c.secret = resolver
                        .resolve(&c.secret)
                        .map_err(|e| anyhow::anyhow!("vault_secret secret: {e}"))?;
                }
            }
        }
        if let Some(resolver) = resolver {
            self.prepare_dpop(&|reference| resolver.resolve(reference))?;
        } else {
            self.validate_dpop()?;
        }
        Ok(())
    }

    /// Resolve every secret required for live request processing. Unlike
    /// [`Self::resolve_secret_refs`], this rejects an enabled DPoP
    /// configuration when runtime secret resolution is unavailable.
    pub fn resolve_runtime_secret_refs(&mut self) -> anyhow::Result<()> {
        let process_resolver = sbproxy_vault::process_resolver();
        if process_resolver.is_none() && !self.is_dpop_enabled() {
            return self.resolve_secret_refs();
        }
        // A process resolver is installed when `proxy.secrets` declares
        // backends. The local resolver still supports `file:` references
        // and fails provider URIs loud when no backend was configured.
        let fallback;
        let resolver: &sbproxy_vault::SecretResolver = match process_resolver.as_deref() {
            Some(resolver) => resolver,
            None => {
                fallback = sbproxy_vault::SecretResolver::new();
                &fallback
            }
        };
        match self {
            OutboundCredentialConfig::TokenExchange(c) => {
                if let Some(secret) = c.client_secret.take() {
                    c.client_secret = Some(
                        resolver
                            .resolve(&secret)
                            .map_err(|e| anyhow::anyhow!("token_exchange client_secret: {e}"))?,
                    );
                }
            }
            OutboundCredentialConfig::ClientCredentials(c) => {
                c.client_secret = resolver
                    .resolve(&c.client_secret)
                    .map_err(|e| anyhow::anyhow!("client_credentials client_secret: {e}"))?;
            }
            OutboundCredentialConfig::VaultSecret(c) => {
                c.secret = resolver
                    .resolve(&c.secret)
                    .map_err(|e| anyhow::anyhow!("vault_secret secret: {e}"))?;
            }
        }
        self.prepare_dpop(&|reference| resolver.resolve(reference))
    }

    /// Refuse a token-exchange credential whose delegation allowlists
    /// are empty (WOR-2316).
    ///
    /// Token exchange is a delegation primitive: it takes the caller's
    /// inbound token and mints one the upstream will honor. An empty
    /// `subject_token_issuers` used to mean "accept any issuer" and an
    /// empty `allowed_audiences` "request any audience", so the default
    /// shape of the feature was a proxy that would delegate anything
    /// anywhere. The runtime now denies on an empty list, and this
    /// check turns that denial into a config-compile error so the flip
    /// surfaces at boot with a fix attached instead of as a wall of
    /// 5xx once traffic arrives.
    ///
    /// The lists are exact-match with no wildcard entry, so "allow
    /// everything" is deliberately not expressible: enumerate the
    /// issuers and audiences the origin actually delegates to.
    pub fn validate_allowlists(&self) -> anyhow::Result<()> {
        let Self::TokenExchange(config) = self else {
            return Ok(());
        };
        if config.subject_token_issuers.is_empty() {
            bail!(
                "token_exchange: `subject_token_issuers` is empty, which denies every subject \
                 token. List the issuer URLs (the subject token's `iss`) this origin accepts, \
                 for example `subject_token_issuers: [\"https://idp.example.com\"]`"
            );
        }
        if config.allowed_audiences.is_empty() {
            bail!(
                "token_exchange: `allowed_audiences` is empty, which denies every exchange. \
                 List the audiences this origin may request, including its own `audience` \
                 value {:?}",
                config.audience
            );
        }
        Ok(())
    }

    /// Validate DPoP configuration without dereferencing an external secret.
    pub fn validate_dpop(&self) -> anyhow::Result<()> {
        if let Self::VaultSecret(config) = self {
            if config.dpop.is_some() && !config.header.eq_ignore_ascii_case("authorization") {
                bail!("vault_secret with DPoP must use the authorization header");
            }
        }
        if let Some(dpop) = self.dpop() {
            dpop.validate().map_err(anyhow::Error::new)?;
        }
        Ok(())
    }

    /// Resolve and compile an enabled DPoP key.
    pub fn prepare_dpop(
        &mut self,
        key_lookup: &(dyn Fn(&str) -> Result<String> + Sync),
    ) -> anyhow::Result<()> {
        self.validate_dpop()?;
        let Some(dpop) = self.dpop_mut() else {
            return Ok(());
        };
        let pem = key_lookup(&dpop.key).context("resolve DPoP signing key")?;
        dpop.install_resolved_key(&pem).map_err(anyhow::Error::new)
    }

    /// Whether this credential opts into DPoP.
    pub fn is_dpop_enabled(&self) -> bool {
        self.dpop().is_some()
    }

    /// Compiled DPoP runtime for request processing.
    pub fn dpop_runtime(&self) -> Result<Option<Arc<DpopRuntime>>> {
        self.dpop()
            .map(DpopOutboundConfig::runtime)
            .transpose()
            .map_err(anyhow::Error::new)
    }

    fn dpop(&self) -> Option<&DpopOutboundConfig> {
        match self {
            Self::TokenExchange(config) => config.dpop.as_ref(),
            Self::ClientCredentials(config) => config.dpop.as_ref(),
            Self::VaultSecret(config) => config.dpop.as_ref(),
        }
    }

    fn dpop_mut(&mut self) -> Option<&mut DpopOutboundConfig> {
        match self {
            Self::TokenExchange(config) => config.dpop.as_mut(),
            Self::ClientCredentials(config) => config.dpop.as_mut(),
            Self::VaultSecret(config) => config.dpop.as_mut(),
        }
    }
}

/// A resolved outbound credential, ready to stamp on the upstream
/// request as a header.
#[derive(Clone, PartialEq, Eq)]
pub struct MintedCredential {
    /// Header name to set (lowercased).
    pub header_name: String,
    /// Header value.
    pub header_value: String,
    /// Token lifetime in seconds, when the token endpoint reported one.
    pub expires_in: Option<u64>,
}

impl std::fmt::Debug for MintedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedCredential")
            .field("header_name", &self.header_name)
            .field("header_value", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl MintedCredential {
    /// Access token carried by a DPoP authorization header.
    pub fn dpop_access_token(&self) -> Option<&str> {
        self.header_value.strip_prefix("DPoP ")
    }
}

/// Decode a JWT's payload (claims) without verifying its signature. The
/// upstream IdP verifies the token; here we only read `iss` and `act`
/// to enforce the allowlist and the delegation-depth cap. Returns
/// `None` when the token is not a well-formed JWT.
fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Depth of the `act` delegation chain in a claims object. A token with
/// no `act` claim has depth 0; each nested `act` adds one.
fn act_chain_depth(claims: &serde_json::Value) -> usize {
    let mut depth = 0;
    let mut cur = claims.get("act");
    while let Some(act) = cur {
        depth += 1;
        cur = act.get("act");
    }
    depth
}

/// Enforce the subject-token allowlist and delegation-depth cap before
/// an exchange. Returns an error (fail closed) when the token's issuer
/// is not allowlisted or the `act` chain is too deep.
///
/// An empty allowlist denies (WOR-2316). Config compilation rejects that
/// shape outright, so reaching this arm means a caller built the config
/// in code; deny rather than delegate on behalf of an unknown issuer.
fn validate_subject_token(
    token: &str,
    allowed_issuers: &[String],
    act_depth_cap: usize,
) -> Result<()> {
    let claims = decode_jwt_payload(token).context("subject token is not a decodable JWT")?;

    if allowed_issuers.is_empty() {
        bail!("subject_token_issuers is empty, so no subject-token issuer is accepted");
    }
    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .context("subject token has no `iss` claim to allowlist")?;
    if !allowed_issuers.iter().any(|a| a == iss) {
        bail!("subject token issuer {iss:?} is not in subject_token_issuers");
    }

    let depth = act_chain_depth(&claims);
    if depth > act_depth_cap {
        bail!("subject token act delegation chain depth {depth} exceeds cap {act_depth_cap}");
    }
    Ok(())
}

/// Enforce the requested-audience allowlist. An empty allowlist denies
/// every audience (WOR-2316); see [`validate_subject_token`].
fn validate_audience(audience: &str, allowed: &[String]) -> Result<()> {
    if allowed.is_empty() {
        bail!("allowed_audiences is empty, so no requested audience is accepted");
    }
    if !allowed.iter().any(|a| a == audience) {
        bail!("requested audience {audience:?} is not in allowed_audiences");
    }
    Ok(())
}

/// Parse `(access_token, expires_in)` from an OAuth token-endpoint JSON
/// response body.
fn parse_token_response(body: &[u8], require_dpop: bool) -> Result<(String, Option<u64>)> {
    let v: serde_json::Value =
        serde_json::from_slice(body).context("token endpoint returned non-JSON")?;
    let token = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .context("token endpoint response missing access_token")?
        .to_string();
    let expires_in = v.get("expires_in").and_then(|e| e.as_u64());
    if require_dpop {
        let token_type = v
            .get("token_type")
            .and_then(|value| value.as_str())
            .context("DPoP token endpoint response missing token_type")?;
        if !token_type.eq_ignore_ascii_case("DPoP") {
            bail!("DPoP token endpoint returned a non-DPoP token_type");
        }
    }
    Ok((token, expires_in))
}

fn canonical_dpop_htu(raw: &str) -> Result<String> {
    let mut url = url::Url::parse(raw).context("DPoP target is not an absolute URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("DPoP target must use an absolute HTTP or HTTPS URL");
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn dpop_nonce_header(
    headers: &reqwest::header::HeaderMap,
) -> Result<Option<String>, DpopSignerError> {
    let values: Vec<_> = headers.get_all("dpop-nonce").iter().collect();
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 1 {
        return Err(DpopSignerError::InvalidNonce);
    }
    let nonce = values[0]
        .to_str()
        .map_err(|_| DpopSignerError::InvalidNonce)?;
    validate_nonce(nonce)?;
    Ok(Some(nonce.to_string()))
}

fn token_nonce_challenge(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    body: &[u8],
) -> Option<String> {
    if status != reqwest::StatusCode::BAD_REQUEST {
        return None;
    }
    let error = serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("error")?
        .as_str()?
        .to_string();
    if error != "use_dpop_nonce" {
        return None;
    }
    dpop_nonce_header(headers).ok().flatten()
}

struct TokenEndpointResponse {
    status: reqwest::StatusCode,
    body: bytes::Bytes,
}

async fn send_token_request<F>(
    build: F,
    token_endpoint: &str,
    dpop: Option<&Arc<DpopRuntime>>,
) -> Result<TokenEndpointResponse>
where
    F: Fn() -> reqwest::RequestBuilder,
{
    let htu = dpop
        .map(|_| canonical_dpop_htu(token_endpoint))
        .transpose()?;
    for attempt in 0..=1 {
        let mut request = build();
        if let (Some(runtime), Some(htu)) = (dpop, htu.as_deref()) {
            let proof = runtime
                .mint_token_proof("POST", htu)
                .context("mint token-endpoint DPoP proof")?;
            request = request.header("DPoP", proof);
        }
        let response = request
            .send()
            .await
            .context("token endpoint request failed")?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .context("reading token endpoint response body")?;

        if let Some(runtime) = dpop {
            if let Some(nonce) = token_nonce_challenge(status, &headers, &body) {
                runtime
                    .set_authorization_nonce(&nonce)
                    .context("store authorization-server DPoP nonce")?;
                if attempt == 0 {
                    continue;
                }
            } else if status.is_success() {
                if let Some(nonce) =
                    dpop_nonce_header(&headers).context("read authorization-server DPoP nonce")?
                {
                    runtime
                        .set_authorization_nonce(&nonce)
                        .context("store authorization-server DPoP nonce")?;
                }
            }
        }
        return Ok(TokenEndpointResponse { status, body });
    }
    unreachable!("bounded DPoP token loop always returns")
}

fn credential_cache_identity_parts(
    mode: &str,
    endpoint: &str,
    audience: &str,
    client_id: &str,
    scope: &str,
    dpop_jkt: Option<&str>,
) -> String {
    use sha2::{Digest, Sha256};
    let material = format!(
        "{mode}\u{0}{endpoint}\u{0}{audience}\u{0}{client_id}\u{0}{scope}\u{0}{}",
        dpop_jkt.unwrap_or("")
    );
    hex::encode(Sha256::digest(material.as_bytes()))
}

fn credential_cache_identity(cfg: &OutboundCredentialConfig) -> Result<String> {
    let jkt = cfg
        .dpop_runtime()?
        .as_ref()
        .map(|runtime| runtime.key_thumbprint().to_string());
    Ok(match cfg {
        OutboundCredentialConfig::TokenExchange(config) => credential_cache_identity_parts(
            "token_exchange",
            &config.token_endpoint,
            &config.audience,
            config.client_id.as_deref().unwrap_or(""),
            config.scope.as_deref().unwrap_or(""),
            jkt.as_deref(),
        ),
        OutboundCredentialConfig::ClientCredentials(config) => credential_cache_identity_parts(
            "client_credentials",
            &config.token_endpoint,
            config.audience.as_deref().unwrap_or(""),
            &config.client_id,
            config.scope.as_deref().unwrap_or(""),
            jkt.as_deref(),
        ),
        OutboundCredentialConfig::VaultSecret(_) => {
            credential_cache_identity_parts("vault_secret", "", "", "", "", jkt.as_deref())
        }
    })
}

/// Authorize a token-endpoint URL when an authorizer is present.
/// `None` preserves legacy ungated token exchange (omitted config).
pub fn authorize_token_endpoint(
    authorizer: Option<&EgressAuthorizer>,
    url: &str,
    resolver: &dyn HostResolver,
) -> Result<(), EgressDenied> {
    let Some(auth) = authorizer else {
        return Ok(());
    };
    auth.authorize(EgressPurpose::TokenExchange, url, resolver)
        .map(|_| ())
}

/// Gate one token endpoint, attributing a refusal to `origin_id`
/// (WOR-2165).
///
/// The resolver is live. The fixed synthetic pin this gate used to run
/// against was public and resolvable for every hostname, so an IdP name
/// that resolves onto the pod network passed, and every recorded pin
/// described the fixture rather than DNS.
fn gate_token_endpoint(
    egress: Option<&EgressAuthorizer>,
    url: &str,
    origin_id: &str,
) -> Result<()> {
    authorize_token_endpoint(egress, url, &CachedSystemResolver).map_err(|denied| {
        record_egress_refused(EgressPurpose::TokenExchange, denied, "unset", origin_id);
        anyhow::anyhow!("egress denied: {denied:?}")
    })
}

/// Resolve the outbound credential for `cfg`.
///
/// `subject_token` is the inbound caller's token (required for
/// `token_exchange`). `secret_lookup` resolves vault references to
/// secret values; the request path passes the `sbproxy-vault`
/// resolver, and tests pass a stub. Network errors and allowlist
/// violations are returned as errors so the caller can fail the request
/// rather than present a wrong or unsafe credential.
pub async fn resolve(
    cfg: &OutboundCredentialConfig,
    http: &reqwest::Client,
    subject_token: Option<&str>,
    secret_lookup: &(dyn Fn(&str) -> Result<String> + Sync),
) -> Result<MintedCredential> {
    resolve_with_egress(cfg, http, subject_token, secret_lookup, None).await
}

/// Like [`resolve`], with an optional fail-closed egress authorizer for
/// token-endpoint HTTP (`EgressPurpose::TokenExchange`).
///
/// Refusals are attributed to `origin_id` when one is known;
/// [`resolve`] has no origin in scope and passes the empty string,
/// which the counter renders as `unset`.
pub async fn resolve_with_egress(
    cfg: &OutboundCredentialConfig,
    http: &reqwest::Client,
    subject_token: Option<&str>,
    secret_lookup: &(dyn Fn(&str) -> Result<String> + Sync),
    egress: Option<&EgressAuthorizer>,
) -> Result<MintedCredential> {
    resolve_with_egress_for_origin(cfg, http, subject_token, secret_lookup, egress, "").await
}

/// [`resolve_with_egress`] with an explicit origin id for refusal
/// attribution (WOR-2165). This deployment is multi-tenant, so an
/// egress refusal that cannot say whose origin it belongs to is not
/// actionable.
pub async fn resolve_with_egress_for_origin(
    cfg: &OutboundCredentialConfig,
    http: &reqwest::Client,
    subject_token: Option<&str>,
    secret_lookup: &(dyn Fn(&str) -> Result<String> + Sync),
    egress: Option<&EgressAuthorizer>,
    origin_id: &str,
) -> Result<MintedCredential> {
    match cfg {
        OutboundCredentialConfig::TokenExchange(c) => {
            gate_token_endpoint(egress, &c.token_endpoint, origin_id)?;
            let subject =
                subject_token.context("token_exchange requires an inbound subject token")?;
            validate_subject_token(subject, &c.subject_token_issuers, c.act_depth_cap)?;
            validate_audience(&c.audience, &c.allowed_audiences)?;

            let mut form: Vec<(&str, &str)> = vec![
                ("grant_type", GRANT_TOKEN_EXCHANGE),
                ("subject_token", subject),
                ("subject_token_type", TOKEN_TYPE_ACCESS),
                ("requested_token_type", TOKEN_TYPE_ACCESS),
                ("audience", c.audience.as_str()),
            ];
            if let Some(scope) = c.scope.as_deref() {
                form.push(("scope", scope));
            }
            let client_secret = c.client_secret.as_deref().map(secret_lookup).transpose()?;
            let dpop = cfg.dpop_runtime()?;
            let response = send_token_request(
                || {
                    let mut request = http.post(&c.token_endpoint).form(&form);
                    if let (Some(id), Some(secret)) =
                        (c.client_id.as_deref(), client_secret.as_deref())
                    {
                        request = request.basic_auth(id, Some(secret));
                    }
                    request
                },
                &c.token_endpoint,
                dpop.as_ref(),
            )
            .await
            .context("token exchange request failed")?;
            if !response.status.is_success() {
                bail!("token exchange returned status {}", response.status);
            }
            let (token, expires_in) = parse_token_response(&response.body, dpop.is_some())?;
            let scheme = if dpop.is_some() { "DPoP" } else { "Bearer" };
            Ok(MintedCredential {
                header_name: "authorization".to_string(),
                header_value: format!("{scheme} {token}"),
                expires_in,
            })
        }
        OutboundCredentialConfig::ClientCredentials(c) => {
            gate_token_endpoint(egress, &c.token_endpoint, origin_id)?;
            let secret = secret_lookup(&c.client_secret)?;
            let mut form: Vec<(&str, &str)> = vec![("grant_type", "client_credentials")];
            if let Some(scope) = c.scope.as_deref() {
                form.push(("scope", scope));
            }
            if let Some(audience) = c.audience.as_deref() {
                form.push(("audience", audience));
            }
            let dpop = cfg.dpop_runtime()?;
            let response = send_token_request(
                || {
                    http.post(&c.token_endpoint)
                        .basic_auth(&c.client_id, Some(secret.as_str()))
                        .form(&form)
                },
                &c.token_endpoint,
                dpop.as_ref(),
            )
            .await
            .context("client-credentials request failed")?;
            if !response.status.is_success() {
                bail!(
                    "client-credentials grant returned status {}",
                    response.status
                );
            }
            let (token, expires_in) = parse_token_response(&response.body, dpop.is_some())?;
            let scheme = if dpop.is_some() { "DPoP" } else { "Bearer" };
            Ok(MintedCredential {
                header_name: "authorization".to_string(),
                header_value: format!("{scheme} {token}"),
                expires_in,
            })
        }
        OutboundCredentialConfig::VaultSecret(c) => {
            let secret = secret_lookup(&c.secret)?;
            let dpop = cfg.dpop_runtime()?;
            let header_value = if dpop.is_some() {
                format!("DPoP {secret}")
            } else if c.scheme.is_empty() {
                secret
            } else {
                format!("{} {}", c.scheme, secret)
            };
            Ok(MintedCredential {
                header_name: c.header.to_ascii_lowercase(),
                header_value,
                expires_in: None,
            })
        }
    }
}

// --- Minted-token cache (WOR-802) ---

struct CachedCred {
    cred: MintedCredential,
    /// `None` for entries that should not be reused (no reported
    /// lifetime); otherwise the instant the entry goes stale.
    expires_at: Option<Instant>,
}

/// Process-wide cache of minted credentials, keyed by origin + subject
/// fingerprint so the proxy does not call the token endpoint on every
/// request. Bounded by each entry's TTL (derived from the token's
/// `expires_in` minus a safety margin).
static CRED_CACHE: OnceLock<DashMap<String, CachedCred>> = OnceLock::new();

fn cred_cache() -> &'static DashMap<String, CachedCred> {
    CRED_CACHE.get_or_init(DashMap::new)
}

/// Like [`resolve`], but caches minted tokens (token-exchange and
/// client-credentials modes) keyed by `origin_id` + a fingerprint of
/// the subject token, so repeated requests reuse a live token until it
/// nears expiry. `vault_secret` is resolved directly each call (a cheap
/// local format with no network round-trip, and caching a static secret
/// across config reloads would risk staleness). Tokens whose endpoint
/// reported no `expires_in` are not cached.
///
/// Prefer [`resolve_cached_isolated`] for run-as-user paths so tokens
/// for user A are never served to user B when subject tokens collide.
pub async fn resolve_cached(
    origin_id: &str,
    cfg: &OutboundCredentialConfig,
    http: &reqwest::Client,
    subject_token: Option<&str>,
    secret_lookup: &(dyn Fn(&str) -> Result<String> + Sync),
) -> Result<MintedCredential> {
    resolve_cached_isolated(origin_id, "", cfg, http, subject_token, secret_lookup, None).await
}

/// Like [`resolve_cached`], with an explicit non-secret `isolation_key`
/// (delegation subject id / principal `sub`) in the cache key so
/// distinct users never share a minted token entry. Also accepts an
/// optional egress authorizer for token-endpoint HTTP.
pub async fn resolve_cached_isolated(
    origin_id: &str,
    isolation_key: &str,
    cfg: &OutboundCredentialConfig,
    http: &reqwest::Client,
    subject_token: Option<&str>,
    secret_lookup: &(dyn Fn(&str) -> Result<String> + Sync),
    egress: Option<&EgressAuthorizer>,
) -> Result<MintedCredential> {
    if matches!(cfg, OutboundCredentialConfig::VaultSecret(_)) {
        return resolve_with_egress_for_origin(
            cfg,
            http,
            subject_token,
            secret_lookup,
            egress,
            origin_id,
        )
        .await;
    }

    let subject_fp = subject_token
        .map(|t| {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(t.as_bytes()))
        })
        .unwrap_or_default();
    // isolation_key is a subject id, never a secret. Including it
    // prevents cross-user cache hits when subject tokens collide.
    let credential_identity = credential_cache_identity(cfg)?;
    let key = format!("{origin_id}\u{0}{isolation_key}\u{0}{subject_fp}\u{0}{credential_identity}");

    if let Some(entry) = cred_cache().get(&key) {
        if entry
            .expires_at
            .map(|e| Instant::now() < e)
            .unwrap_or(false)
        {
            return Ok(entry.cred.clone());
        }
    }

    let cred =
        resolve_with_egress_for_origin(cfg, http, subject_token, secret_lookup, egress, origin_id)
            .await?;
    // Cache only when the endpoint reported a lifetime; reuse it until
    // 30s before expiry to avoid serving a token that dies in flight.
    if let Some(secs) = cred.expires_in {
        if let Some(ttl) = secs.checked_sub(30).filter(|&s| s > 0) {
            cred_cache().insert(
                key,
                CachedCred {
                    cred: cred.clone(),
                    expires_at: Some(Instant::now() + Duration::from_secs(ttl)),
                },
            );
        }
    }
    Ok(cred)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::dpop::DpopVerifier;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    const DPOP_PRIVATE_KEY: &str = include_str!("dpop_test_ec_p256.pem");

    fn dpop_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4",
            "y": "bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc"
        })
    }

    fn dpop_jkt() -> &'static str {
        "IeJTwmoSPsFMO6w48KpbHar6spW4kZZ9UvgEXQ0hOwA"
    }

    fn request_header(raw: &[u8], name: &str) -> Option<String> {
        let text = String::from_utf8_lossy(raw);
        text.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    fn proof_claims(proof: &str) -> serde_json::Value {
        let claims = proof.split('.').nth(1).expect("claims");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .expect("base64url");
        serde_json::from_slice(&decoded).expect("claims JSON")
    }

    /// Build an unsigned JWT (header.payload.sig) carrying `claims`.
    fn jwt(claims: serde_json::Value) -> String {
        let b64 = |v: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
        };
        format!(
            "{}.{}.sig",
            b64(&serde_json::json!({"alg": "none", "typ": "JWT"})),
            b64(&claims)
        )
    }

    fn no_secret() -> impl Fn(&str) -> Result<String> + Sync {
        |r: &str| Ok(r.to_string())
    }

    #[test]
    fn config_parses_all_three_modes() {
        let te: OutboundCredentialConfig = serde_json::from_value(serde_json::json!({
            "type": "token_exchange",
            "token_endpoint": "https://idp/token",
            "audience": "https://api.example.com",
            "subject_token_issuers": ["https://issuer"],
            "allowed_audiences": ["https://api.example.com"]
        }))
        .unwrap();
        assert!(matches!(te, OutboundCredentialConfig::TokenExchange(_)));

        let cc: OutboundCredentialConfig = serde_json::from_value(serde_json::json!({
            "type": "client_credentials",
            "token_endpoint": "https://idp/token",
            "client_id": "id",
            "client_secret": "vault:secret"
        }))
        .unwrap();
        assert!(matches!(cc, OutboundCredentialConfig::ClientCredentials(_)));

        let vs: OutboundCredentialConfig = serde_json::from_value(serde_json::json!({
            "type": "vault_secret",
            "secret": "vault:api-key"
        }))
        .unwrap();
        assert!(matches!(vs, OutboundCredentialConfig::VaultSecret(_)));
    }

    #[test]
    fn unknown_mode_fails_to_parse() {
        let r: Result<OutboundCredentialConfig, _> =
            serde_json::from_value(serde_json::json!({"type": "magic"}));
        assert!(r.is_err());
    }

    #[test]
    fn act_depth_counts_nesting() {
        assert_eq!(act_chain_depth(&serde_json::json!({"sub": "a"})), 0);
        assert_eq!(
            act_chain_depth(&serde_json::json!({"act": {"sub": "b"}})),
            1
        );
        assert_eq!(
            act_chain_depth(&serde_json::json!({"act": {"act": {"sub": "c"}}})),
            2
        );
    }

    #[test]
    fn issuer_allowlist_enforced() {
        let token = jwt(serde_json::json!({"iss": "https://evil", "sub": "x"}));
        let err = validate_subject_token(&token, &["https://good".to_string()], 4).unwrap_err();
        assert!(err.to_string().contains("subject_token_issuers"));
        // Allowlisted issuer passes.
        let ok = jwt(serde_json::json!({"iss": "https://good", "sub": "x"}));
        assert!(validate_subject_token(&ok, &["https://good".to_string()], 4).is_ok());
    }

    /// WOR-2316: an empty issuer allowlist denies instead of accepting
    /// any issuer, so a credential built in code cannot delegate on
    /// behalf of an issuer nobody named.
    #[test]
    fn empty_issuer_allowlist_denies_every_subject_token() {
        let token = jwt(serde_json::json!({"iss": "https://anyone", "sub": "x"}));
        let err = validate_subject_token(&token, &[], 4).unwrap_err();
        assert!(
            err.to_string().contains("subject_token_issuers is empty"),
            "empty allowlist must deny and say so, got: {err}"
        );
    }

    #[test]
    fn act_depth_cap_enforced() {
        let allowed = ["https://good".to_string()];
        let token = jwt(serde_json::json!({
            "iss": "https://good",
            "act": {"act": {"act": {"sub": "deep"}}}
        }));
        assert!(validate_subject_token(&token, &allowed, 2).is_err());
        assert!(validate_subject_token(&token, &allowed, 3).is_ok());
    }

    #[test]
    fn audience_allowlist_enforced() {
        let allowed = vec!["https://api.example.com".to_string()];
        assert!(validate_audience("https://api.example.com", &allowed).is_ok());
        assert!(validate_audience("https://other", &allowed).is_err());
    }

    /// WOR-2316: the audience allowlist fails closed the same way.
    #[test]
    fn empty_audience_allowlist_denies_every_exchange() {
        let err = validate_audience("https://anything", &[]).unwrap_err();
        assert!(
            err.to_string().contains("allowed_audiences is empty"),
            "empty allowlist must deny and say so, got: {err}"
        );
    }

    /// WOR-2316: the same empty lists are a config-compile error, so an
    /// operator meets the change at boot with the key named.
    #[test]
    fn empty_token_exchange_allowlists_fail_config_validation() {
        let missing_issuers: OutboundCredentialConfig = serde_json::from_value(serde_json::json!({
            "type": "token_exchange",
            "token_endpoint": "https://idp/token",
            "audience": "https://api.example.com",
            "allowed_audiences": ["https://api.example.com"]
        }))
        .expect("parses");
        let err = missing_issuers
            .validate_allowlists()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("subject_token_issuers"),
            "error must name the empty key, got: {err}"
        );

        let missing_audiences: OutboundCredentialConfig =
            serde_json::from_value(serde_json::json!({
                "type": "token_exchange",
                "token_endpoint": "https://idp/token",
                "audience": "https://api.example.com",
                "subject_token_issuers": ["https://issuer"]
            }))
            .expect("parses");
        let err = missing_audiences
            .validate_allowlists()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("allowed_audiences") && err.contains("https://api.example.com"),
            "error must name the empty key and the configured audience, got: {err}"
        );
    }

    /// The other two credential modes have no delegation allowlist, so
    /// the WOR-2316 check must leave them alone.
    #[test]
    fn explicit_allowlists_and_other_modes_validate_clean() {
        let explicit: OutboundCredentialConfig = serde_json::from_value(serde_json::json!({
            "type": "token_exchange",
            "token_endpoint": "https://idp/token",
            "audience": "https://api.example.com",
            "subject_token_issuers": ["https://issuer"],
            "allowed_audiences": ["https://api.example.com"]
        }))
        .expect("parses");
        explicit
            .validate_allowlists()
            .expect("an explicit allowlist pair compiles");

        let vault: OutboundCredentialConfig = serde_json::from_value(serde_json::json!({
            "type": "vault_secret",
            "secret": "vault:api-key"
        }))
        .expect("parses");
        vault.validate_allowlists().expect("vault_secret is exempt");
    }

    #[tokio::test]
    async fn vault_secret_formats_header() {
        let cfg = OutboundCredentialConfig::VaultSecret(VaultSecretConfig {
            secret: "vault:api-key".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            dpop: None,
        });
        let http = reqwest::Client::new();
        let lookup = |r: &str| Ok(format!("RESOLVED({r})"));
        let cred = resolve(&cfg, &http, None, &lookup).await.unwrap();
        assert_eq!(cred.header_name, "authorization");
        assert_eq!(cred.header_value, "Bearer RESOLVED(vault:api-key)");
    }

    #[tokio::test]
    async fn vault_secret_bare_scheme() {
        let cfg = OutboundCredentialConfig::VaultSecret(VaultSecretConfig {
            secret: "k".to_string(),
            header: "X-Api-Key".to_string(),
            scheme: String::new(),
            dpop: None,
        });
        let http = reqwest::Client::new();
        let cred = resolve(&cfg, &http, None, &no_secret()).await.unwrap();
        assert_eq!(cred.header_name, "x-api-key");
        assert_eq!(cred.header_value, "k");
    }

    #[tokio::test]
    async fn token_exchange_requires_subject_token() {
        let cfg = OutboundCredentialConfig::TokenExchange(TokenExchangeConfig {
            token_endpoint: "https://idp/token".to_string(),
            audience: "https://api".to_string(),
            scope: None,
            // The missing subject token is refused before the WOR-2316
            // allowlist check runs, so the empty lists are inert here.
            subject_token_issuers: vec![],
            allowed_audiences: vec![],
            act_depth_cap: 4,
            client_id: None,
            client_secret: None,
            dpop: None,
        });
        let http = reqwest::Client::new();
        let err = resolve(&cfg, &http, None, &no_secret()).await.unwrap_err();
        assert!(err.to_string().contains("subject token"));
    }

    #[tokio::test]
    async fn token_exchange_mints_against_mock_endpoint() {
        // Mock token endpoint: returns an access token for a valid
        // exchange form.
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "skipping outbound credential token-exchange test: loopback bind denied: {err}"
                );
                return;
            }
            Err(err) => panic!("failed to bind outbound credential test listener: {err}"),
        };
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let body =
                    r#"{"access_token":"minted-abc","token_type":"Bearer","expires_in":3600}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        let cfg = OutboundCredentialConfig::TokenExchange(TokenExchangeConfig {
            token_endpoint: format!("http://127.0.0.1:{port}/token"),
            audience: "https://api.example.com".to_string(),
            scope: Some("read".to_string()),
            subject_token_issuers: vec!["https://issuer".to_string()],
            allowed_audiences: vec!["https://api.example.com".to_string()],
            act_depth_cap: 4,
            client_id: Some("client".to_string()),
            client_secret: Some("vault:cs".to_string()),
            dpop: None,
        });
        let subject = jwt(serde_json::json!({"iss": "https://issuer", "sub": "user"}));
        let http = reqwest::Client::new();
        let cred = resolve(&cfg, &http, Some(&subject), &no_secret())
            .await
            .expect("exchange succeeds");
        assert_eq!(cred.header_value, "Bearer minted-abc");
        assert_eq!(cred.expires_in, Some(3600));
    }

    /// Test resolver mapping a host to fixed addresses. Production
    /// gates pass `CachedSystemResolver`.
    struct MapResolver {
        map: std::collections::HashMap<String, Vec<std::net::SocketAddr>>,
    }

    impl MapResolver {
        fn new(entries: Vec<(&str, Vec<std::net::SocketAddr>)>) -> Self {
            Self {
                map: entries
                    .into_iter()
                    .map(|(h, a)| (h.to_string(), a))
                    .collect(),
            }
        }
    }

    impl HostResolver for MapResolver {
        fn resolve(&self, host: &str, _port: u16) -> Result<Vec<std::net::SocketAddr>, ()> {
            self.map.get(host).cloned().ok_or(())
        }
    }

    fn public_addr(port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            port,
        )
    }

    fn enforce_token_exchange(hosts: &[&str]) -> EgressAuthorizer {
        use sbproxy_security::egress::{EgressConfig, PurposeAllowlist};
        use std::collections::HashMap;
        let mut allow = PurposeAllowlist::default();
        for h in hosts {
            allow.hosts.insert((*h).to_string());
        }
        allow.schemes.insert("https".to_string());
        allow.schemes.insert("http".to_string());
        allow.ports.insert(443);
        allow.ports.insert(80);
        let mut purposes = HashMap::new();
        purposes.insert(EgressPurpose::TokenExchange, allow);
        EgressAuthorizer::new(EgressConfig { purposes })
    }

    #[test]
    fn token_exchange_egress_denies_unlisted_host_with_shared_vocabulary() {
        let auth = enforce_token_exchange(&["idp.example.com"]);
        let resolver = MapResolver::new(vec![("evil.example", vec![public_addr(443)])]);
        let err = authorize_token_endpoint(Some(&auth), "https://evil.example/token", &resolver)
            .expect_err("unlisted token endpoint");
        assert_eq!(err, EgressDenied::UnlistedHost);
        assert!(!format!("{err:?}").contains("evil.example"));
    }

    #[test]
    fn token_exchange_egress_denies_a_listed_idp_that_resolves_internal() {
        // Unreachable under the old fixed synthetic pin, which reported
        // a public address for every hostname regardless of DNS.
        let auth = enforce_token_exchange(&["idp.internal"]);
        let resolver = MapResolver::new(vec![(
            "idp.internal",
            vec![std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 169, 254)),
                443,
            )],
        )]);
        assert_eq!(
            authorize_token_endpoint(Some(&auth), "https://idp.internal/token", &resolver)
                .unwrap_err(),
            EgressDenied::PrivateAddress
        );
    }

    #[test]
    fn omitted_egress_preserves_legacy_token_exchange_compatibility() {
        let resolver = MapResolver::new(vec![]);
        authorize_token_endpoint(None, "https://evil.example/token", &resolver)
            .expect("omitted egress must not deny, and must not even resolve");
    }

    #[tokio::test]
    async fn token_exchange_enforce_fails_closed_before_io() {
        let cfg = OutboundCredentialConfig::TokenExchange(TokenExchangeConfig {
            token_endpoint: "https://evil.example/token".to_string(),
            audience: "https://api.example.com".to_string(),
            scope: None,
            // The egress gate runs before the WOR-2316 allowlist check,
            // which is the point of this test: refuse before any I/O.
            subject_token_issuers: vec![],
            allowed_audiences: vec![],
            act_depth_cap: 4,
            client_id: None,
            client_secret: None,
            dpop: None,
        });
        let http = reqwest::Client::new();
        let auth = enforce_token_exchange(&["idp.example.com"]);
        let subject = jwt(serde_json::json!({"iss": "https://issuer", "sub": "user"}));
        let err = resolve_with_egress(&cfg, &http, Some(&subject), &no_secret(), Some(&auth))
            .await
            .expect_err("unlisted endpoint must fail closed");
        assert!(
            format!("{err:#}").contains("UnlistedHost"),
            "expected UnlistedHost, got: {err:#}"
        );
    }

    #[tokio::test]
    async fn cached_isolated_tokens_do_not_cross_users() {
        // Two users share the same inbound subject token string. Without
        // isolation_key in the cache key, user B would receive user A's
        // minted credential. Serve distinct tokens per accept.
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "skipping outbound credential cache isolation test: loopback bind denied: {err}"
                );
                return;
            }
            Err(err) => panic!("failed to bind outbound credential test listener: {err}"),
        };
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for token in ["minted-for-a", "minted-for-b"] {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let _ = s.read(&mut buf);
                    let body = format!(
                        r#"{{"access_token":"{token}","token_type":"Bearer","expires_in":3600}}"#
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = s.write_all(resp.as_bytes());
                }
            }
        });

        let cfg = OutboundCredentialConfig::TokenExchange(TokenExchangeConfig {
            token_endpoint: format!("http://127.0.0.1:{port}/token"),
            audience: "https://api.example.com".to_string(),
            scope: None,
            // WOR-2316: empty allowlists deny, so the cache-isolation
            // case has to name the issuer and audience it exercises.
            subject_token_issuers: vec!["https://issuer".to_string()],
            allowed_audiences: vec!["https://api.example.com".to_string()],
            act_depth_cap: 4,
            client_id: None,
            client_secret: None,
            dpop: None,
        });
        let shared_subject = jwt(serde_json::json!({"iss": "https://issuer", "sub": "shared"}));
        let http = reqwest::Client::new();
        let a = resolve_cached_isolated(
            "origin-1",
            "user-a",
            &cfg,
            &http,
            Some(&shared_subject),
            &no_secret(),
            None,
        )
        .await
        .expect("user a mint");
        let b = resolve_cached_isolated(
            "origin-1",
            "user-b",
            &cfg,
            &http,
            Some(&shared_subject),
            &no_secret(),
            None,
        )
        .await
        .expect("user b mint");
        assert_eq!(a.header_value, "Bearer minted-for-a");
        assert_eq!(b.header_value, "Bearer minted-for-b");
        assert_ne!(a.header_value, b.header_value);

        // Same isolation key must reuse the cached entry (no third accept).
        let a_again = resolve_cached_isolated(
            "origin-1",
            "user-a",
            &cfg,
            &http,
            Some(&shared_subject),
            &no_secret(),
            None,
        )
        .await
        .expect("user a cache hit");
        assert_eq!(a_again.header_value, a.header_value);
    }

    #[tokio::test]
    async fn dpop_token_request_uses_exact_target_and_retries_one_nonce_challenge() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let server_captured = captured.clone();
        let join = std::thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = vec![0; 16 * 1024];
                let count = stream.read(&mut bytes).unwrap();
                bytes.truncate(count);
                server_captured.lock().unwrap().push(bytes);
                let (status, headers, body) = if attempt == 0 {
                    (
                        "400 Bad Request",
                        "DPoP-Nonce: authorization-nonce\r\n",
                        r#"{"error":"use_dpop_nonce"}"#,
                    )
                } else {
                    (
                        "200 OK",
                        "",
                        r#"{"access_token":"bound-token","token_type":"DPoP","expires_in":3600}"#,
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let mut cfg: OutboundCredentialConfig = serde_json::from_value(serde_json::json!({
            "type": "client_credentials",
            "token_endpoint": format!("http://127.0.0.1:{port}/oauth/token?tenant=acme"),
            "client_id": "client",
            "client_secret": "client-secret",
            "dpop": {
                "key": "secret://prod/api-dpop-key",
                "alg": "ES256",
                "jwk": dpop_jwk()
            }
        }))
        .unwrap();
        cfg.prepare_dpop(&|_| Ok(DPOP_PRIVATE_KEY.to_string()))
            .unwrap();

        let minted = resolve(&cfg, &reqwest::Client::new(), None, &no_secret())
            .await
            .unwrap();
        join.join().unwrap();
        assert_eq!(minted.header_value, "DPoP bound-token");

        let requests = captured.lock().unwrap();
        assert_eq!(requests.len(), 2);
        let proofs: Vec<String> = requests
            .iter()
            .map(|request| request_header(request, "DPoP").expect("DPoP header"))
            .collect();
        assert_ne!(proofs[0], proofs[1]);
        for proof in &proofs {
            let claims = proof_claims(proof);
            assert_eq!(claims["htm"], "POST");
            assert_eq!(
                claims["htu"],
                format!("http://127.0.0.1:{port}/oauth/token")
            );
            assert!(claims.get("ath").is_none());
            DpopVerifier::default()
                .verify(
                    Some(proof),
                    "POST",
                    &format!("http://127.0.0.1:{port}/oauth/token"),
                    dpop_jkt(),
                    SystemTime::now(),
                )
                .unwrap();
        }
        assert!(proof_claims(&proofs[0]).get("nonce").is_none());
        assert_eq!(proof_claims(&proofs[1])["nonce"], "authorization-nonce");
    }

    #[test]
    fn token_nonce_challenge_requires_status_error_and_one_valid_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("dpop-nonce", "nonce-1".parse().unwrap());
        assert_eq!(
            token_nonce_challenge(
                reqwest::StatusCode::BAD_REQUEST,
                &headers,
                br#"{"error":"use_dpop_nonce"}"#
            )
            .as_deref(),
            Some("nonce-1")
        );
        assert!(token_nonce_challenge(
            reqwest::StatusCode::UNAUTHORIZED,
            &headers,
            br#"{"error":"use_dpop_nonce"}"#
        )
        .is_none());
        assert!(token_nonce_challenge(
            reqwest::StatusCode::BAD_REQUEST,
            &headers,
            br#"{"error":"invalid_dpop_proof"}"#
        )
        .is_none());

        headers.append("dpop-nonce", "nonce-2".parse().unwrap());
        assert!(token_nonce_challenge(
            reqwest::StatusCode::BAD_REQUEST,
            &headers,
            br#"{"error":"use_dpop_nonce"}"#
        )
        .is_none());
    }

    #[test]
    fn token_cache_identity_changes_with_dpop_key_or_endpoint() {
        let base = credential_cache_identity_parts(
            "client_credentials",
            "https://idp.example/token",
            "api",
            "client",
            "read",
            Some("jkt-a"),
        );
        assert_ne!(
            base,
            credential_cache_identity_parts(
                "client_credentials",
                "https://idp.example/token",
                "api",
                "client",
                "read",
                Some("jkt-b"),
            )
        );
        assert_ne!(
            base,
            credential_cache_identity_parts(
                "client_credentials",
                "https://other-idp.example/token",
                "api",
                "client",
                "read",
                Some("jkt-a"),
            )
        );
        assert_ne!(
            base,
            credential_cache_identity_parts(
                "client_credentials",
                "https://idp.example/token",
                "api",
                "client",
                "write",
                Some("jkt-a"),
            )
        );
    }

    #[test]
    fn vault_secret_dpop_requires_authorization_header() {
        let cfg: OutboundCredentialConfig = serde_json::from_value(serde_json::json!({
            "type": "vault_secret",
            "secret": "secret://prod/token",
            "header": "x-api-key",
            "dpop": {
                "key": "secret://prod/dpop-key",
                "alg": "ES256",
                "jwk": dpop_jwk()
            }
        }))
        .unwrap();

        assert!(cfg
            .validate_dpop()
            .unwrap_err()
            .to_string()
            .contains("authorization header"));
    }

    #[test]
    fn runtime_dpop_key_reference_must_be_available() {
        let mut cfg: OutboundCredentialConfig = serde_json::from_value(serde_json::json!({
            "type": "client_credentials",
            "token_endpoint": "https://idp.example/token",
            "client_id": "client",
            "client_secret": "client-secret",
            "dpop": {
                "key": "file:/definitely/not/a/real/dpop-key.pem",
                "alg": "ES256",
                "jwk": dpop_jwk()
            }
        }))
        .unwrap();

        cfg.validate_dpop()
            .expect("validation must not dereference the key");
        let error = cfg.resolve_runtime_secret_refs().unwrap_err();
        assert!(format!("{error:#}").contains("failed to read secret file"));
    }
}
