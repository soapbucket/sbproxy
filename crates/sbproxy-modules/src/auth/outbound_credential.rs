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
//!   cap.
//! - **`client_credentials`**: OAuth 2.0 client-credentials grant.
//! - **`vault_secret`**: a static secret resolved from the vault and
//!   formatted as an authorization header.
//!
//! See `docs/adr-outbound-credential-resolver.md` for the OSS vs
//! enterprise line. The advanced layers (stored per-user grants,
//! broker JWT re-sign, DPoP / mTLS binding, multi-source entitlements)
//! are deliberately out of this module.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use dashmap::DashMap;
use serde::Deserialize;

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
    /// Allowlist of acceptable subject-token issuers (`iss`). Empty
    /// means "accept any issuer" (not recommended).
    #[serde(default)]
    pub subject_token_issuers: Vec<String>,
    /// Allowlist of audiences this origin may request. Empty means
    /// "any audience" (not recommended). The configured `audience`
    /// must appear here when the list is non-empty.
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
}

impl OutboundCredentialConfig {
    /// Resolve provider-URI secret references (WOR-1784) in this credential's
    /// secret-bearing fields through the process secret resolver, so a
    /// `vault://` / `secret://` reference becomes the real secret at config
    /// load rather than being sent to the token endpoint verbatim. An
    /// unresolved reference is a hard error. No-op when no resolver is
    /// installed (the validate/plan subcommands, unit tests).
    pub fn resolve_secret_refs(&mut self) -> anyhow::Result<()> {
        let Some(resolver) = sbproxy_vault::process_resolver() else {
            return Ok(());
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
        Ok(())
    }
}

/// A resolved outbound credential, ready to stamp on the upstream
/// request as a header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedCredential {
    /// Header name to set (lowercased).
    pub header_name: String,
    /// Header value.
    pub header_value: String,
    /// Token lifetime in seconds, when the token endpoint reported one.
    pub expires_in: Option<u64>,
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
fn validate_subject_token(
    token: &str,
    allowed_issuers: &[String],
    act_depth_cap: usize,
) -> Result<()> {
    let claims = decode_jwt_payload(token).context("subject token is not a decodable JWT")?;

    if !allowed_issuers.is_empty() {
        let iss = claims
            .get("iss")
            .and_then(|v| v.as_str())
            .context("subject token has no `iss` claim to allowlist")?;
        if !allowed_issuers.iter().any(|a| a == iss) {
            bail!("subject token issuer {iss:?} is not in subject_token_issuers");
        }
    }

    let depth = act_chain_depth(&claims);
    if depth > act_depth_cap {
        bail!("subject token act delegation chain depth {depth} exceeds cap {act_depth_cap}");
    }
    Ok(())
}

/// Enforce the requested-audience allowlist.
fn validate_audience(audience: &str, allowed: &[String]) -> Result<()> {
    if !allowed.is_empty() && !allowed.iter().any(|a| a == audience) {
        bail!("requested audience {audience:?} is not in allowed_audiences");
    }
    Ok(())
}

/// Parse `(access_token, expires_in)` from an OAuth token-endpoint JSON
/// response body.
fn parse_token_response(body: &[u8]) -> Result<(String, Option<u64>)> {
    let v: serde_json::Value =
        serde_json::from_slice(body).context("token endpoint returned non-JSON")?;
    let token = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .context("token endpoint response missing access_token")?
        .to_string();
    let expires_in = v.get("expires_in").and_then(|e| e.as_u64());
    Ok((token, expires_in))
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
    match cfg {
        OutboundCredentialConfig::TokenExchange(c) => {
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
            let mut req = http.post(&c.token_endpoint).form(&form);
            if let (Some(id), Some(secret_ref)) =
                (c.client_id.as_deref(), c.client_secret.as_deref())
            {
                let secret = secret_lookup(secret_ref)?;
                req = req.basic_auth(id, Some(secret));
            }
            let resp = req.send().await.context("token exchange request failed")?;
            let status = resp.status();
            let body = resp.bytes().await.context("reading token exchange body")?;
            if !status.is_success() {
                bail!("token exchange returned status {status}");
            }
            let (token, expires_in) = parse_token_response(&body)?;
            Ok(MintedCredential {
                header_name: "authorization".to_string(),
                header_value: format!("Bearer {token}"),
                expires_in,
            })
        }
        OutboundCredentialConfig::ClientCredentials(c) => {
            let secret = secret_lookup(&c.client_secret)?;
            let mut form: Vec<(&str, &str)> = vec![("grant_type", "client_credentials")];
            if let Some(scope) = c.scope.as_deref() {
                form.push(("scope", scope));
            }
            if let Some(audience) = c.audience.as_deref() {
                form.push(("audience", audience));
            }
            let resp = http
                .post(&c.token_endpoint)
                .basic_auth(&c.client_id, Some(secret))
                .form(&form)
                .send()
                .await
                .context("client-credentials request failed")?;
            let status = resp.status();
            let body = resp
                .bytes()
                .await
                .context("reading client-credentials body")?;
            if !status.is_success() {
                bail!("client-credentials grant returned status {status}");
            }
            let (token, expires_in) = parse_token_response(&body)?;
            Ok(MintedCredential {
                header_name: "authorization".to_string(),
                header_value: format!("Bearer {token}"),
                expires_in,
            })
        }
        OutboundCredentialConfig::VaultSecret(c) => {
            let secret = secret_lookup(&c.secret)?;
            let header_value = if c.scheme.is_empty() {
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
pub async fn resolve_cached(
    origin_id: &str,
    cfg: &OutboundCredentialConfig,
    http: &reqwest::Client,
    subject_token: Option<&str>,
    secret_lookup: &(dyn Fn(&str) -> Result<String> + Sync),
) -> Result<MintedCredential> {
    if matches!(cfg, OutboundCredentialConfig::VaultSecret(_)) {
        return resolve(cfg, http, subject_token, secret_lookup).await;
    }

    let subject_fp = subject_token
        .map(|t| {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(t.as_bytes()))
        })
        .unwrap_or_default();
    let key = format!("{origin_id}\u{0}{subject_fp}");

    if let Some(entry) = cred_cache().get(&key) {
        if entry
            .expires_at
            .map(|e| Instant::now() < e)
            .unwrap_or(false)
        {
            return Ok(entry.cred.clone());
        }
    }

    let cred = resolve(cfg, http, subject_token, secret_lookup).await?;
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
        // Empty allowlist accepts any issuer.
        assert!(validate_subject_token(&token, &[], 4).is_ok());
    }

    #[test]
    fn act_depth_cap_enforced() {
        let token = jwt(serde_json::json!({
            "iss": "https://good",
            "act": {"act": {"act": {"sub": "deep"}}}
        }));
        assert!(validate_subject_token(&token, &[], 2).is_err());
        assert!(validate_subject_token(&token, &[], 3).is_ok());
    }

    #[test]
    fn audience_allowlist_enforced() {
        let allowed = vec!["https://api.example.com".to_string()];
        assert!(validate_audience("https://api.example.com", &allowed).is_ok());
        assert!(validate_audience("https://other", &allowed).is_err());
        assert!(validate_audience("https://anything", &[]).is_ok());
    }

    #[tokio::test]
    async fn vault_secret_formats_header() {
        let cfg = OutboundCredentialConfig::VaultSecret(VaultSecretConfig {
            secret: "vault:api-key".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
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
            subject_token_issuers: vec![],
            allowed_audiences: vec![],
            act_depth_cap: 4,
            client_id: None,
            client_secret: None,
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
        });
        let subject = jwt(serde_json::json!({"iss": "https://issuer", "sub": "user"}));
        let http = reqwest::Client::new();
        let cred = resolve(&cfg, &http, Some(&subject), &no_secret())
            .await
            .expect("exchange succeeds");
        assert_eq!(cred.header_value, "Bearer minted-abc");
        assert_eq!(cred.expires_in, Some(3600));
    }
}
