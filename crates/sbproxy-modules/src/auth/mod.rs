//! Auth module - enum dispatch for built-in auth providers.

/// Wave 7 / A7.2 A2A protocol envelope and feature-gated parsers.
pub mod a2a;
pub mod bot_auth;
/// Wave 1 / G1.7 dynamic Web Bot Auth directory cache.
pub mod bot_auth_directory;
/// Wave 6 / R6.1 Crawler Authorization Protocol (CAP) verifier.
pub mod cap;
pub mod jwks;

pub use bot_auth::{BotAuthAgent, BotAuthConfig, BotAuthProvider, BotAuthVerdict};
pub use bot_auth_directory::{
    DirectoryCache, DirectoryConfig, DirectoryKey, DEFAULT_DIRECTORY_TTL_SECS,
    DEFAULT_NEGATIVE_TTL_SECS, DEFAULT_STALE_GRACE_SECS, FETCH_DEADLINE, MAX_DIRECTORY_TTL_SECS,
    MIN_DIRECTORY_TTL_SECS,
};
pub use cap::{CapConfig, CapError, CapTokenView, CapVerdict, CapVerifier};

use base64::Engine;
use md5::{Digest as Md5Digest, Md5};
use sbproxy_plugin::AuthProvider;
use serde::Deserialize;
use std::collections::HashMap;

/// Constant-time byte equality.
///
/// Used for comparing any secret-equivalent material (API keys, bearer
/// tokens, passwords) so an attacker cannot learn the value by timing how
/// long the comparison takes. Branches on length only, which already leaks
/// the secret length. The secrets we compare here all have fixed lengths
/// per-user so this is acceptable.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[inline]
fn ct_str_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Returns true if any candidate equals `needle` in constant time.
///
/// The loop runs over every candidate so the total time depends on the
/// configured key set size, not on which (if any) entry matched.
#[inline]
fn ct_any_match(needle: &str, candidates: &[String]) -> bool {
    let mut matched = false;
    for c in candidates {
        matched |= ct_str_eq(c, needle);
    }
    matched
}

// --- Auth Enum ---

/// Auth provider - enum dispatch for built-in types.
/// Each variant holds its compiled config inline (no Box indirection).
pub enum Auth {
    /// API key authentication via header or query param.
    ApiKey(ApiKeyAuth),
    /// HTTP Basic Authentication.
    BasicAuth(BasicAuthProvider),
    /// Bearer token authentication.
    Bearer(BearerAuth),
    /// JWT validation (structure + expiry, signature check deferred).
    Jwt(JwtAuth),
    /// HTTP Digest Authentication (placeholder).
    Digest(DigestAuth),
    /// Forward auth to an external service.
    ForwardAuth(ForwardAuthProvider),
    /// Web Bot Auth: RFC 9421 message signature against an agent
    /// directory.
    BotAuth(crate::auth::bot_auth::BotAuthProvider),
    /// Wave 6 / R6.1 Crawler Authorization Protocol (CAP) verifier.
    Cap(crate::auth::cap::CapVerifier),
    /// No authentication required.
    Noop,
    /// Third-party plugin (only case using dynamic dispatch).
    Plugin(Box<dyn AuthProvider>),
}

impl Auth {
    /// Get the type name for this auth provider.
    pub fn auth_type(&self) -> &str {
        match self {
            Self::ApiKey(_) => "api_key",
            Self::BasicAuth(_) => "basic_auth",
            Self::Bearer(_) => "bearer",
            Self::Jwt(_) => "jwt",
            Self::Digest(_) => "digest",
            Self::ForwardAuth(_) => "forward_auth",
            Self::BotAuth(_) => "bot_auth",
            Self::Cap(_) => "cap",
            Self::Noop => "noop",
            Self::Plugin(p) => p.auth_type(),
        }
    }
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(a) => f.debug_tuple("ApiKey").field(a).finish(),
            Self::BasicAuth(a) => f.debug_tuple("BasicAuth").field(a).finish(),
            Self::Bearer(a) => f.debug_tuple("Bearer").field(a).finish(),
            Self::Jwt(a) => f.debug_tuple("Jwt").field(a).finish(),
            Self::Digest(a) => f.debug_tuple("Digest").field(a).finish(),
            Self::ForwardAuth(a) => f.debug_tuple("ForwardAuth").field(a).finish(),
            Self::BotAuth(a) => f.debug_tuple("BotAuth").field(a).finish(),
            Self::Cap(a) => f.debug_tuple("Cap").field(a).finish(),
            Self::Noop => write!(f, "Noop"),
            Self::Plugin(_) => write!(f, "Plugin(...)"),
        }
    }
}

// --- ApiKeyAuth ---

/// API key auth config - validates requests carry a known key
/// in a header or query parameter.
#[derive(Debug, Deserialize)]
pub struct ApiKeyAuth {
    /// HTTP header carrying the API key. Defaults to `X-Api-Key`.
    #[serde(default = "default_header")]
    pub header_name: String,
    /// List of accepted API keys.
    pub api_keys: Vec<String>,
    /// Optional query parameter name; when set, keys can also be supplied via the URL.
    #[serde(default)]
    pub query_param: Option<String>,
}

fn default_header() -> String {
    "X-Api-Key".to_string()
}

impl ApiKeyAuth {
    /// Build an ApiKeyAuth from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Check if the request has a valid API key in the header or query string.
    /// Returns true if a matching key is found.
    pub fn check_request(&self, headers: &http::HeaderMap, query: Option<&str>) -> bool {
        // Check header
        if let Some(key) = headers.get(&self.header_name).and_then(|v| v.to_str().ok()) {
            if ct_any_match(key, &self.api_keys) {
                return true;
            }
        }

        // Check query param if configured. Use url::form_urlencoded so
        // percent-encoded keys/values match correctly (e.g. a key sent as
        // %41bc decodes to Abc before comparison).
        if let (Some(param_name), Some(query_str)) = (&self.query_param, query) {
            for (name, value) in url::form_urlencoded::parse(query_str.as_bytes()) {
                if name.as_ref() == param_name && ct_any_match(value.as_ref(), &self.api_keys) {
                    return true;
                }
            }
        }

        false
    }
}

// --- BasicAuth ---

/// HTTP Basic Authentication provider.
/// Validates base64-encoded username:password from the Authorization header.
#[derive(Debug, Deserialize)]
pub struct BasicAuthProvider {
    /// Accepted username/password pairs.
    pub users: Vec<BasicAuthUser>,
    /// Optional realm shown in the `WWW-Authenticate` challenge.
    #[serde(default)]
    pub realm: Option<String>,
}

/// A username/password pair for basic auth.
#[derive(Debug, Deserialize, Clone)]
pub struct BasicAuthUser {
    /// Username portion of the credential.
    pub username: String,
    /// Password portion of the credential.
    pub password: String,
}

impl BasicAuthProvider {
    /// Build a BasicAuthProvider from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Check if the request has valid basic auth credentials.
    /// Decodes the Base64 value from `Authorization: Basic <base64>`,
    /// splits on `:`, and matches against the configured users list.
    pub fn check_request(&self, headers: &http::HeaderMap) -> bool {
        self.check_request_with_subject(headers).is_some()
    }

    /// Check basic auth credentials and, on success, return the
    /// matched username so callers can stamp it as the resolved
    /// subject on `AuthDecision::Allow`. The constant-time scan of
    /// the user table ensures total time depends only on
    /// `users.len()`, not on which entry matched (or if none did).
    pub fn check_request_with_subject(&self, headers: &http::HeaderMap) -> Option<String> {
        let auth_value = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())?;
        let encoded = auth_value.strip_prefix("Basic ")?;
        let decoded_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        let decoded = std::str::from_utf8(&decoded_bytes).ok()?;
        let (username, password) = decoded.split_once(':')?;

        let mut matched_username: Option<String> = None;
        for u in &self.users {
            let user_ok = ct_str_eq(&u.username, username) & ct_str_eq(&u.password, password);
            if user_ok && matched_username.is_none() {
                matched_username = Some(u.username.clone());
            }
        }
        matched_username
    }
}

// --- BearerAuth ---

/// Bearer token authentication.
/// Validates a token from the `Authorization: Bearer <token>` header.
#[derive(Debug, Deserialize)]
pub struct BearerAuth {
    /// Accepted bearer tokens.
    pub tokens: Vec<String>,
}

impl BearerAuth {
    /// Build a BearerAuth from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Check if the request carries a valid bearer token.
    pub fn check_request(&self, headers: &http::HeaderMap) -> bool {
        let Some(auth_value) = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };

        let Some(token) = auth_value.strip_prefix("Bearer ") else {
            return false;
        };

        ct_any_match(token, &self.tokens)
    }
}

// --- JwtAuth ---

/// JWT validation provider.
///
/// Verifies the token signature with `jsonwebtoken` and then checks
/// issuer / audience / required-claim constraints. If the provider is
/// instantiated without either a shared `secret` or a `jwks_url`, all
/// tokens are rejected: there is no configuration under which this
/// provider accepts an unsigned or unverified token.
#[derive(Debug, Deserialize)]
pub struct JwtAuth {
    /// Shared HMAC secret for verifying tokens (used with HS-family algorithms).
    #[serde(default)]
    pub secret: Option<String>,
    /// JWKS URL for fetching public keys when using asymmetric algorithms.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Claims that must be present and equal to the configured value.
    #[serde(default)]
    pub required_claims: HashMap<String, serde_json::Value>,
    /// Required `aud` claim value.
    #[serde(default)]
    pub audience: Option<String>,
    /// Required `iss` claim value.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Allowed signing algorithms. Defaults to HS256/HS384/HS512 when a
    /// `secret` is set; RS256 when `jwks_url` is set. Callers can override
    /// this when they know the issuer uses a different algorithm. The list
    /// must never be empty in practice. An empty list means no tokens will
    /// validate, which is the safe default if the config is malformed.
    #[serde(default)]
    pub algorithms: Vec<String>,
}

impl JwtAuth {
    /// Build a JwtAuth from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Validate the request's JWT: signature, standard claims, and any
    /// configured issuer / audience / required-claim constraints.
    ///
    /// Expects `Authorization: Bearer <jwt>`. Returns false on any
    /// validation failure (missing header, wrong scheme, bad signature,
    /// expired token, unmet claim, unconfigured verification key).
    pub fn check_request(&self, headers: &http::HeaderMap) -> bool {
        self.check_request_with_subject(headers).is_some()
    }

    /// Validate the request's JWT and, on success, return
    /// `Some(token_payload)` containing the resolved `sub` claim if
    /// present (or an empty string when the token validated but
    /// carried no `sub`). Returns `None` on any validation failure.
    /// The wrapper preserves [`Self::check_request`] semantics for
    /// callers that only need a yes/no answer.
    pub fn check_request_with_subject(&self, headers: &http::HeaderMap) -> Option<String> {
        let auth_value = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())?;
        let token = auth_value.strip_prefix("Bearer ")?;
        self.validate_token_extract_sub(token)
    }

    /// Return the `jsonwebtoken` algorithms that should be accepted for
    /// this provider, based on explicit config or sensible defaults.
    fn allowed_algorithms(&self) -> Vec<jsonwebtoken::Algorithm> {
        use jsonwebtoken::Algorithm;
        if !self.algorithms.is_empty() {
            return self
                .algorithms
                .iter()
                .filter_map(|a| a.parse::<Algorithm>().ok())
                .collect();
        }
        if self.secret.is_some() {
            vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512]
        } else if self.jwks_url.is_some() {
            vec![Algorithm::RS256]
        } else {
            // No verification material configured -> no algorithms allowed.
            Vec::new()
        }
    }

    /// Decode the JWT header without verifying the signature.
    ///
    /// Used to extract the `kid` and `alg` so the JWKS path can pick
    /// the right public key before running the cryptographic check.
    /// Failing here is treated as "not a JWT we can verify" and the
    /// caller falls back to deny.
    fn header(&self, token: &str) -> Option<jsonwebtoken::Header> {
        jsonwebtoken::decode_header(token).ok()
    }

    /// Validate JWT signature + standard / configured claims and
    /// return the resolved `sub` claim on success (empty string when
    /// the token validated but carried no `sub`). Returns `None` on
    /// any validation failure.
    fn validate_token_extract_sub(&self, token: &str) -> Option<String> {
        use jsonwebtoken::{decode, DecodingKey, Validation};

        let algorithms = self.allowed_algorithms();
        if algorithms.is_empty() {
            return None;
        }

        let mut validation = Validation::new(algorithms[0]);
        validation.algorithms = algorithms;
        if let Some(iss) = &self.issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(aud) = &self.audience {
            validation.set_audience(&[aud]);
        }

        let decoding_key = if let Some(secret) = &self.secret {
            DecodingKey::from_secret(secret.as_bytes())
        } else if let Some(jwks_url) = &self.jwks_url {
            let header = self.header(token)?;
            let cache = jwks::get_or_init_cache(jwks_url, jwks::DEFAULT_REFRESH_SECS);
            cache.lookup_decoding_key(header.kid.as_deref())?
        } else {
            return None;
        };

        let token_data = decode::<serde_json::Value>(token, &decoding_key, &validation).ok()?;

        for (key, expected_value) in &self.required_claims {
            match token_data.claims.get(key) {
                Some(actual) if actual == expected_value => {}
                _ => return None,
            }
        }

        // Pull the `sub` claim if present. Empty string when the
        // token validates but carries no `sub`; callers treat that as
        // "authenticated, no subject" and fall back to anonymous
        // user resolution.
        let sub = token_data
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_default();
        Some(sub)
    }
}

// --- DigestAuth ---

/// HTTP Digest Authentication provider.
///
/// Implements the subset of RFC 7616 the proxy actually exposes: MD5
/// digest with `qop=auth`. The provider also tracks, for each nonce we
/// have seen, the highest `nc` value that produced a valid response.
/// RFC 7616 §3.4 requires `nc` to strictly increase per nonce; any reuse
/// means a captured `Authorization` header is being replayed. Capturing
/// and replaying a valid header would otherwise succeed for the life of
/// the nonce because the digest response only binds method + URI.
pub struct DigestAuth {
    /// Realm string sent in the `WWW-Authenticate` challenge.
    pub realm: String,
    /// Accepted username/password pairs.
    pub users: Vec<DigestAuthUser>,
    /// `nonce -> max accepted nc` seen so far. Guarded by a `parking_lot`
    /// mutex for low contention and poison-free access. The map is
    /// bounded by `Self::MAX_TRACKED_NONCES`; when full, half the entries
    /// (those with the lowest `nc`, i.e. the least recently validated)
    /// are dropped to make room.
    seen_nc: parking_lot::Mutex<HashMap<String, u64>>,
}

impl std::fmt::Debug for DigestAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DigestAuth")
            .field("realm", &self.realm)
            .field("users", &self.users)
            .finish()
    }
}

impl<'de> Deserialize<'de> for DigestAuth {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            realm: String,
            #[serde(deserialize_with = "deserialize_digest_users")]
            users: Vec<DigestAuthUser>,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(DigestAuth {
            realm: raw.realm,
            users: raw.users,
            seen_nc: parking_lot::Mutex::new(HashMap::new()),
        })
    }
}

/// A username/password pair for digest auth.
#[derive(Debug, Deserialize, Clone)]
pub struct DigestAuthUser {
    /// Username portion of the credential.
    pub username: String,
    /// Password portion of the credential.
    pub password: String,
}

/// Deserialize digest users from either:
/// - A sequence of `{username, password}` objects (Rust format)
/// - A map of `{username: password_hash}` (Go format)
fn deserialize_digest_users<'de, D>(deserializer: D) -> Result<Vec<DigestAuthUser>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum UsersFormat {
        Seq(Vec<DigestAuthUser>),
        Map(HashMap<String, String>),
    }

    match UsersFormat::deserialize(deserializer)? {
        UsersFormat::Seq(users) => Ok(users),
        UsersFormat::Map(map) => Ok(map
            .into_iter()
            .map(|(username, password)| DigestAuthUser { username, password })
            .collect()),
    }
}

impl DigestAuth {
    /// Upper bound on tracked nonces. Each entry is ~40 bytes; 4096
    /// entries is ~160 KB of state, plenty for any realistic admin or
    /// small-tenant deployment.
    const MAX_TRACKED_NONCES: usize = 4096;

    /// Build a DigestAuth from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Construct a DigestAuth with an empty replay cache. Intended for
    /// tests and programmatic construction; regular use goes through
    /// `from_config`.
    pub fn new(realm: impl Into<String>, users: Vec<DigestAuthUser>) -> Self {
        Self {
            realm: realm.into(),
            users,
            seen_nc: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if `(nonce, nc)` has not been seen before for this
    /// provider. On success, records the new high-water mark so a later
    /// replay of the same or lower `nc` with the same nonce is rejected.
    fn record_fresh_nc(&self, nonce: &str, nc_hex: &str) -> bool {
        // RFC 7616: nc is 8-hex-digit count; we accept any hex length up
        // to u64 so we don't bounce legitimate clients that happen to
        // omit leading zeros (curl has historically done this).
        let Ok(nc) = u64::from_str_radix(nc_hex, 16) else {
            return false;
        };
        if nc == 0 {
            // RFC 7616 requires nc to start at 1.
            return false;
        }

        let mut seen = self.seen_nc.lock();

        // If the map has grown too large, drop the least-recently-used
        // half (those with the lowest nc). This is an approximation of
        // LRU; the goal is to keep memory bounded without a full LRU
        // crate dependency.
        if seen.len() >= Self::MAX_TRACKED_NONCES {
            let mut counts: Vec<u64> = seen.values().copied().collect();
            counts.sort_unstable();
            let cutoff = counts[counts.len() / 2];
            seen.retain(|_, v| *v > cutoff);
        }

        match seen.get_mut(nonce) {
            Some(existing) => {
                if nc > *existing {
                    *existing = nc;
                    true
                } else {
                    // Replay or out-of-order reuse: reject.
                    false
                }
            }
            None => {
                seen.insert(nonce.to_string(), nc);
                true
            }
        }
    }

    /// Generate a WWW-Authenticate challenge header value.
    pub fn challenge(&self, nonce: &str) -> String {
        format!(
            "Digest realm=\"{}\", nonce=\"{}\", qop=\"auth\", algorithm=MD5",
            self.realm, nonce
        )
    }

    /// Generate an unpredictable nonce for a Digest challenge.
    ///
    /// RFC 7616 requires that the nonce "be constructed so that it is
    /// unique and not easily replicable". The prior implementation used
    /// `md5(now_ns || const)` which an attacker who can observe one nonce
    /// can step through in one-nanosecond increments to predict future
    /// ones. We now draw 16 bytes from the OS CSPRNG (`rand::rngs::OsRng`)
    /// so the output is uniformly random and not affected by the
    /// process-local thread-rng implementation.
    ///
    /// Note: MD5 remains here only for the digest response computation
    /// because RFC 2617 hard-codes it (and RFC 7616's SHA-256 variant is
    /// not yet negotiated by many clients). The nonce itself has no such
    /// constraint, so it does not go through MD5.
    pub fn generate_nonce() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Check if the request has a valid digest authorization.
    /// Returns true if the digest response is valid.
    pub fn check_request(&self, headers: &http::HeaderMap, method: &str) -> bool {
        self.check_request_with_subject(headers, method).is_some()
    }

    /// Validate the digest response and, on success, return the
    /// matched username (the resolved subject). Returns `None` on
    /// any validation failure or replay rejection.
    pub fn check_request_with_subject(
        &self,
        headers: &http::HeaderMap,
        method: &str,
    ) -> Option<String> {
        let auth_value = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())?;
        let digest_str = auth_value.strip_prefix("Digest ")?;

        let params = Self::parse_digest_params(digest_str);
        let username = params.get("username")?.as_str();
        let nonce = params.get("nonce")?.as_str();
        let uri = params.get("uri")?.as_str();
        let response = params.get("response")?.as_str();

        // Constant-time scan over the user table so mere existence of
        // a user does not leak via timing.
        let mut matched_user: Option<&DigestAuthUser> = None;
        for u in &self.users {
            if ct_str_eq(&u.username, username) {
                matched_user = Some(u);
                // Intentionally do not break: keeps per-request cost O(N).
            }
        }
        let user = matched_user?;
        let ha1 = &user.password;

        let qop = params.get("qop").map(|s| s.as_str());
        if qop == Some("auth") {
            let nc = params.get("nc").map(|s| s.as_str()).unwrap_or("");
            if !self.record_fresh_nc(nonce, nc) {
                return None;
            }
        }

        let ha2 = Self::md5_hex(&format!("{}:{}", method, uri));
        let expected = if qop == Some("auth") {
            let nc = params.get("nc").map(|s| s.as_str()).unwrap_or("");
            let cnonce = params.get("cnonce").map(|s| s.as_str()).unwrap_or("");
            Self::md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2))
        } else {
            Self::md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2))
        };

        if ct_str_eq(response, &expected) {
            Some(user.username.clone())
        } else {
            None
        }
    }

    /// Parse digest auth parameters from the header value.
    fn parse_digest_params(s: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        for part in s.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim().to_lowercase();
                let value = value.trim().trim_matches('"').to_string();
                params.insert(key, value);
            }
        }
        params
    }

    /// Compute MD5 hex digest of a string.
    fn md5_hex(input: &str) -> String {
        let mut hasher = Md5::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }
}

// --- ForwardAuth ---

/// Forward auth provider. Delegates authentication to an external
/// HTTP service. The proxy sends a subrequest and uses the response
/// status to accept or reject the original request.
#[derive(Debug)]
pub struct ForwardAuthProvider {
    /// URL of the external auth subrequest endpoint.
    pub url: String,
    /// HTTP method used for the subrequest (defaults to GET).
    pub method: Option<String>,
    /// Headers from the original request to copy onto the subrequest.
    pub headers_to_forward: Vec<String>,
    /// Headers from the auth response to copy onto the upstream request.
    pub trust_headers: Vec<String>,
    /// Status code returned by the auth service that signals success (defaults to 200).
    pub success_status: Option<u16>,
    /// Subrequest timeout in milliseconds.
    pub timeout: Option<u64>,
    /// Override the `Host` header sent on the auth subrequest. Defaults to
    /// the auth URL's hostname.
    pub host_override: Option<String>,
    /// When true, suppress the `X-Forwarded-Host` header that the proxy
    /// would otherwise set to the client's original `Host`.
    pub disable_forwarded_host_header: bool,
}

impl ForwardAuthProvider {
    /// Build a ForwardAuthProvider from a generic JSON config value.
    ///
    /// Accepts Go-compat fields:
    /// - `forward_headers` as alias for `headers_to_forward`
    /// - `success_status` as either `200` or `[200, 201]` (takes first)
    /// - `trust_headers` for headers to trust from the auth response
    /// - `timeout` in seconds
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct RawConfig {
            url: String,
            #[serde(default)]
            method: Option<String>,
            #[serde(default)]
            headers_to_forward: Vec<String>,
            #[serde(default)]
            forward_headers: Vec<String>,
            #[serde(default)]
            trust_headers: Vec<String>,
            #[serde(default, deserialize_with = "deserialize_success_status")]
            success_status: Option<u16>,
            #[serde(default)]
            timeout: Option<u64>,
            #[serde(default)]
            host_override: Option<String>,
            #[serde(default)]
            disable_forwarded_host_header: bool,
        }

        let raw: RawConfig = serde_json::from_value(value)?;

        // Merge headers_to_forward and forward_headers (Go alias)
        let mut headers = raw.headers_to_forward;
        if headers.is_empty() && !raw.forward_headers.is_empty() {
            headers = raw.forward_headers;
        }

        Ok(Self {
            url: raw.url,
            method: raw.method,
            headers_to_forward: headers,
            trust_headers: raw.trust_headers,
            success_status: raw.success_status,
            timeout: raw.timeout,
            host_override: raw.host_override,
            disable_forwarded_host_header: raw.disable_forwarded_host_header,
        })
    }
}

/// Deserialize success_status from either a single u16 or a list of u16.
/// If a list is provided, takes the first element.
fn deserialize_success_status<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StatusFormat {
        Single(u16),
        List(Vec<u16>),
    }

    let opt: Option<StatusFormat> = Option::deserialize(deserializer)?;
    Ok(match opt {
        Some(StatusFormat::Single(s)) => Some(s),
        Some(StatusFormat::List(list)) => list.first().copied(),
        None => None,
    })
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- Auth enum tests ---

    #[test]
    fn api_key_auth_type() {
        let auth = Auth::ApiKey(ApiKeyAuth {
            header_name: "X-Api-Key".to_string(),
            api_keys: vec!["secret123".to_string()],
            query_param: None,
        });
        assert_eq!(auth.auth_type(), "api_key");
    }

    #[test]
    fn noop_auth_type() {
        let auth = Auth::Noop;
        assert_eq!(auth.auth_type(), "noop");
    }

    #[test]
    fn basic_auth_type() {
        let auth = Auth::BasicAuth(BasicAuthProvider {
            users: vec![],
            realm: None,
        });
        assert_eq!(auth.auth_type(), "basic_auth");
    }

    #[test]
    fn bearer_auth_type() {
        let auth = Auth::Bearer(BearerAuth {
            tokens: vec!["tok".to_string()],
        });
        assert_eq!(auth.auth_type(), "bearer");
    }

    #[test]
    fn jwt_auth_type() {
        let auth = Auth::Jwt(JwtAuth {
            secret: None,
            jwks_url: None,
            required_claims: HashMap::new(),
            audience: None,
            issuer: None,
            algorithms: Vec::new(),
        });
        assert_eq!(auth.auth_type(), "jwt");
    }

    #[test]
    fn digest_auth_type() {
        let auth = Auth::Digest(DigestAuth::new("test", vec![]));
        assert_eq!(auth.auth_type(), "digest");
    }

    #[test]
    fn forward_auth_type() {
        let auth = Auth::ForwardAuth(ForwardAuthProvider {
            url: "http://auth-svc/check".to_string(),
            method: None,
            headers_to_forward: vec![],
            trust_headers: vec![],
            success_status: None,
            timeout: None,
            host_override: None,
            disable_forwarded_host_header: false,
        });
        assert_eq!(auth.auth_type(), "forward_auth");
    }

    #[test]
    fn auth_debug_api_key() {
        let auth = Auth::ApiKey(ApiKeyAuth {
            header_name: "Authorization".to_string(),
            api_keys: vec!["key1".to_string()],
            query_param: None,
        });
        let debug = format!("{:?}", auth);
        assert!(debug.contains("ApiKey"));
    }

    #[test]
    fn auth_debug_noop() {
        assert_eq!(format!("{:?}", Auth::Noop), "Noop");
    }

    #[test]
    fn auth_debug_basic_auth() {
        let auth = Auth::BasicAuth(BasicAuthProvider {
            users: vec![],
            realm: Some("test".to_string()),
        });
        let debug = format!("{:?}", auth);
        assert!(debug.contains("BasicAuth"));
    }

    #[test]
    fn auth_debug_bearer() {
        let auth = Auth::Bearer(BearerAuth {
            tokens: vec!["tok".to_string()],
        });
        let debug = format!("{:?}", auth);
        assert!(debug.contains("Bearer"));
    }

    #[test]
    fn auth_debug_jwt() {
        let auth = Auth::Jwt(JwtAuth {
            secret: None,
            jwks_url: None,
            required_claims: HashMap::new(),
            audience: None,
            issuer: None,
            algorithms: Vec::new(),
        });
        let debug = format!("{:?}", auth);
        assert!(debug.contains("Jwt"));
    }

    #[test]
    fn auth_debug_digest() {
        let auth = Auth::Digest(DigestAuth::new("r", vec![]));
        let debug = format!("{:?}", auth);
        assert!(debug.contains("Digest"));
    }

    #[test]
    fn auth_debug_forward_auth() {
        let auth = Auth::ForwardAuth(ForwardAuthProvider {
            url: "http://x".to_string(),
            method: None,
            headers_to_forward: vec![],
            trust_headers: vec![],
            success_status: None,
            timeout: None,
            host_override: None,
            disable_forwarded_host_header: false,
        });
        let debug = format!("{:?}", auth);
        assert!(debug.contains("ForwardAuth"));
    }

    // --- ApiKeyAuth deserialization tests ---

    #[test]
    fn api_key_from_config() {
        let json = serde_json::json!({
            "type": "api_key",
            "header_name": "Authorization",
            "api_keys": ["key-abc", "key-def"],
            "query_param": "token"
        });
        let auth = ApiKeyAuth::from_config(json).unwrap();
        assert_eq!(auth.header_name, "Authorization");
        assert_eq!(auth.api_keys, vec!["key-abc", "key-def"]);
        assert_eq!(auth.query_param.as_deref(), Some("token"));
    }

    #[test]
    fn api_key_from_config_defaults() {
        let json = serde_json::json!({
            "type": "api_key",
            "api_keys": ["secret"]
        });
        let auth = ApiKeyAuth::from_config(json).unwrap();
        assert_eq!(auth.header_name, "X-Api-Key");
        assert!(auth.query_param.is_none());
    }

    #[test]
    fn api_key_from_config_missing_keys() {
        let json = serde_json::json!({"type": "api_key"});
        assert!(ApiKeyAuth::from_config(json).is_err());
    }

    // --- ApiKeyAuth check_request tests ---

    #[test]
    fn check_request_valid_header() {
        let auth = ApiKeyAuth {
            header_name: "X-Api-Key".to_string(),
            api_keys: vec!["secret123".to_string(), "secret456".to_string()],
            query_param: None,
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("X-Api-Key", "secret456".parse().unwrap());
        assert!(auth.check_request(&headers, None));
    }

    #[test]
    fn check_request_invalid_header() {
        let auth = ApiKeyAuth {
            header_name: "X-Api-Key".to_string(),
            api_keys: vec!["secret123".to_string()],
            query_param: None,
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("X-Api-Key", "wrong-key".parse().unwrap());
        assert!(!auth.check_request(&headers, None));
    }

    #[test]
    fn check_request_missing_header() {
        let auth = ApiKeyAuth {
            header_name: "X-Api-Key".to_string(),
            api_keys: vec!["secret123".to_string()],
            query_param: None,
        };
        let headers = http::HeaderMap::new();
        assert!(!auth.check_request(&headers, None));
    }

    #[test]
    fn check_request_valid_query_param() {
        let auth = ApiKeyAuth {
            header_name: "X-Api-Key".to_string(),
            api_keys: vec!["secret123".to_string()],
            query_param: Some("token".to_string()),
        };
        let headers = http::HeaderMap::new();
        assert!(auth.check_request(&headers, Some("foo=bar&token=secret123")));
    }

    #[test]
    fn check_request_invalid_query_param() {
        let auth = ApiKeyAuth {
            header_name: "X-Api-Key".to_string(),
            api_keys: vec!["secret123".to_string()],
            query_param: Some("token".to_string()),
        };
        let headers = http::HeaderMap::new();
        assert!(!auth.check_request(&headers, Some("token=wrong")));
    }

    #[test]
    fn check_request_no_query_param_configured() {
        let auth = ApiKeyAuth {
            header_name: "X-Api-Key".to_string(),
            api_keys: vec!["secret123".to_string()],
            query_param: None,
        };
        let headers = http::HeaderMap::new();
        assert!(!auth.check_request(&headers, Some("token=secret123")));
    }

    #[test]
    fn check_request_header_takes_precedence() {
        let auth = ApiKeyAuth {
            header_name: "X-Api-Key".to_string(),
            api_keys: vec!["secret123".to_string()],
            query_param: Some("token".to_string()),
        };
        let mut headers = http::HeaderMap::new();
        headers.insert("X-Api-Key", "secret123".parse().unwrap());
        // Valid header means we return true even without query
        assert!(auth.check_request(&headers, None));
    }

    // --- BasicAuth deserialization tests ---

    #[test]
    fn basic_auth_from_config() {
        let json = serde_json::json!({
            "type": "basic_auth",
            "users": [
                {"username": "admin", "password": "pass123"},
                {"username": "user", "password": "hello"}
            ],
            "realm": "My Realm"
        });
        let auth = BasicAuthProvider::from_config(json).unwrap();
        assert_eq!(auth.users.len(), 2);
        assert_eq!(auth.users[0].username, "admin");
        assert_eq!(auth.realm.as_deref(), Some("My Realm"));
    }

    #[test]
    fn basic_auth_from_config_no_realm() {
        let json = serde_json::json!({
            "users": [{"username": "u", "password": "p"}]
        });
        let auth = BasicAuthProvider::from_config(json).unwrap();
        assert!(auth.realm.is_none());
    }

    #[test]
    fn basic_auth_from_config_missing_users() {
        let json = serde_json::json!({"realm": "test"});
        assert!(BasicAuthProvider::from_config(json).is_err());
    }

    // --- BasicAuth check_request tests ---

    fn make_basic_auth() -> BasicAuthProvider {
        BasicAuthProvider {
            users: vec![
                BasicAuthUser {
                    username: "admin".to_string(),
                    password: "secret".to_string(),
                },
                BasicAuthUser {
                    username: "user".to_string(),
                    password: "pass".to_string(),
                },
            ],
            realm: Some("Test".to_string()),
        }
    }

    #[test]
    fn basic_auth_valid_credentials() {
        let auth = make_basic_auth();
        let mut headers = http::HeaderMap::new();
        // "admin:secret" in base64
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:secret");
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        assert!(auth.check_request(&headers));
    }

    #[test]
    fn basic_auth_second_user() {
        let auth = make_basic_auth();
        let mut headers = http::HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        assert!(auth.check_request(&headers));
    }

    #[test]
    fn basic_auth_wrong_password() {
        let auth = make_basic_auth();
        let mut headers = http::HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:wrong");
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        assert!(!auth.check_request(&headers));
    }

    #[test]
    fn basic_auth_unknown_user() {
        let auth = make_basic_auth();
        let mut headers = http::HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("nobody:secret");
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        assert!(!auth.check_request(&headers));
    }

    #[test]
    fn basic_auth_missing_header() {
        let auth = make_basic_auth();
        let headers = http::HeaderMap::new();
        assert!(!auth.check_request(&headers));
    }

    #[test]
    fn basic_auth_wrong_scheme() {
        let auth = make_basic_auth();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer some-token".parse().unwrap(),
        );
        assert!(!auth.check_request(&headers));
    }

    #[test]
    fn basic_auth_invalid_base64() {
        let auth = make_basic_auth();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Basic !!!not-base64!!!".parse().unwrap(),
        );
        assert!(!auth.check_request(&headers));
    }

    #[test]
    fn basic_auth_no_colon_separator() {
        let auth = make_basic_auth();
        let mut headers = http::HeaderMap::new();
        // base64 of "nocolon"
        let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        assert!(!auth.check_request(&headers));
    }

    // --- BearerAuth deserialization tests ---

    #[test]
    fn bearer_from_config() {
        let json = serde_json::json!({
            "type": "bearer",
            "tokens": ["tok-abc", "tok-def"]
        });
        let auth = BearerAuth::from_config(json).unwrap();
        assert_eq!(auth.tokens, vec!["tok-abc", "tok-def"]);
    }

    #[test]
    fn bearer_from_config_missing_tokens() {
        let json = serde_json::json!({"type": "bearer"});
        assert!(BearerAuth::from_config(json).is_err());
    }

    // --- BearerAuth check_request tests ---

    #[test]
    fn bearer_valid_token() {
        let auth = BearerAuth {
            tokens: vec!["valid-token".to_string(), "also-valid".to_string()],
        };
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer also-valid".parse().unwrap(),
        );
        assert!(auth.check_request(&headers));
    }

    #[test]
    fn bearer_invalid_token() {
        let auth = BearerAuth {
            tokens: vec!["valid-token".to_string()],
        };
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer wrong-token".parse().unwrap(),
        );
        assert!(!auth.check_request(&headers));
    }

    #[test]
    fn bearer_missing_header() {
        let auth = BearerAuth {
            tokens: vec!["tok".to_string()],
        };
        let headers = http::HeaderMap::new();
        assert!(!auth.check_request(&headers));
    }

    #[test]
    fn bearer_wrong_scheme() {
        let auth = BearerAuth {
            tokens: vec!["tok".to_string()],
        };
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Basic dG9rOg==".parse().unwrap(),
        );
        assert!(!auth.check_request(&headers));
    }

    // --- JwtAuth deserialization tests ---

    #[test]
    fn jwt_from_config_full() {
        let json = serde_json::json!({
            "type": "jwt",
            "secret": "my-secret",
            "issuer": "auth.example.com",
            "audience": "api.example.com",
            "required_claims": {"role": "admin"}
        });
        let auth = JwtAuth::from_config(json).unwrap();
        assert_eq!(auth.secret.as_deref(), Some("my-secret"));
        assert_eq!(auth.issuer.as_deref(), Some("auth.example.com"));
        assert_eq!(auth.audience.as_deref(), Some("api.example.com"));
        assert_eq!(
            auth.required_claims.get("role"),
            Some(&serde_json::json!("admin"))
        );
    }

    #[test]
    fn jwt_from_config_minimal() {
        let json = serde_json::json!({"type": "jwt"});
        let auth = JwtAuth::from_config(json).unwrap();
        assert!(auth.secret.is_none());
        assert!(auth.required_claims.is_empty());
    }

    // --- JwtAuth check_request tests ---

    /// Sign a JWT with HS256 using the given shared secret so the test can
    /// exercise the real verification path rather than an unsigned token.
    fn sign_jwt(payload: &serde_json::Value, secret: &str) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            payload,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("jwt encode")
    }

    fn jwt_auth(secret: Option<&str>) -> JwtAuth {
        JwtAuth {
            secret: secret.map(str::to_string),
            jwks_url: None,
            required_claims: HashMap::new(),
            audience: None,
            issuer: None,
            algorithms: Vec::new(),
        }
    }

    fn jwt_headers(token: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
        headers
    }

    /// A far-future epoch that is still a plausible JWT `exp` value.
    fn future_epoch() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    #[test]
    fn jwt_valid_token_with_matching_secret() {
        let secret = "shared-secret-abc";
        let auth = jwt_auth(Some(secret));
        let token = sign_jwt(
            &serde_json::json!({"sub": "user1", "exp": future_epoch()}),
            secret,
        );
        assert!(auth.check_request(&jwt_headers(&token)));
    }

    #[test]
    fn jwt_rejected_when_no_secret_configured() {
        // Previously the provider accepted any well-formed JWT; with real
        // signature verification, lack of configured key material means
        // "no token is trusted". Fail-closed is the correct default.
        let auth = jwt_auth(None);
        let token = sign_jwt(
            &serde_json::json!({"sub": "user1", "exp": future_epoch()}),
            "irrelevant",
        );
        assert!(!auth.check_request(&jwt_headers(&token)));
    }

    #[test]
    fn jwt_rejected_with_wrong_secret() {
        let auth = jwt_auth(Some("server-secret"));
        let token = sign_jwt(
            &serde_json::json!({"sub": "user1", "exp": future_epoch()}),
            "attacker-secret",
        );
        assert!(!auth.check_request(&jwt_headers(&token)));
    }

    #[test]
    fn jwt_expired_token() {
        let secret = "shared-secret-abc";
        let auth = jwt_auth(Some(secret));
        let token = sign_jwt(
            &serde_json::json!({"sub": "user1", "exp": 1000_u64}),
            secret,
        );
        assert!(!auth.check_request(&jwt_headers(&token)));
    }

    #[test]
    fn jwt_wrong_issuer() {
        let secret = "k";
        let mut auth = jwt_auth(Some(secret));
        auth.issuer = Some("expected-issuer".to_string());
        let token = sign_jwt(
            &serde_json::json!({"iss": "wrong-issuer", "exp": future_epoch()}),
            secret,
        );
        assert!(!auth.check_request(&jwt_headers(&token)));
    }

    #[test]
    fn jwt_correct_issuer() {
        let secret = "k";
        let mut auth = jwt_auth(Some(secret));
        auth.issuer = Some("my-issuer".to_string());
        let token = sign_jwt(
            &serde_json::json!({"iss": "my-issuer", "exp": future_epoch()}),
            secret,
        );
        assert!(auth.check_request(&jwt_headers(&token)));
    }

    #[test]
    fn jwt_wrong_audience() {
        let secret = "k";
        let mut auth = jwt_auth(Some(secret));
        auth.audience = Some("my-api".to_string());
        let token = sign_jwt(
            &serde_json::json!({"aud": "other-api", "exp": future_epoch()}),
            secret,
        );
        assert!(!auth.check_request(&jwt_headers(&token)));
    }

    #[test]
    fn jwt_missing_required_claim() {
        let secret = "k";
        let mut claims = HashMap::new();
        claims.insert("role".to_string(), serde_json::json!("admin"));
        let mut auth = jwt_auth(Some(secret));
        auth.required_claims = claims;
        let token = sign_jwt(
            &serde_json::json!({"sub": "user1", "exp": future_epoch()}),
            secret,
        );
        assert!(!auth.check_request(&jwt_headers(&token)));
    }

    #[test]
    fn jwt_matching_required_claim() {
        let secret = "k";
        let mut claims = HashMap::new();
        claims.insert("role".to_string(), serde_json::json!("admin"));
        let mut auth = jwt_auth(Some(secret));
        auth.required_claims = claims;
        let token = sign_jwt(
            &serde_json::json!({"role": "admin", "exp": future_epoch()}),
            secret,
        );
        assert!(auth.check_request(&jwt_headers(&token)));
    }

    #[test]
    fn jwt_malformed_not_three_parts() {
        let auth = jwt_auth(Some("k"));
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer not.a.valid.jwt.token".parse().unwrap(),
        );
        assert!(!auth.check_request(&headers));
    }

    #[test]
    fn jwt_malformed_bad_base64() {
        let auth = jwt_auth(Some("k"));
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer !!!.!!!.!!!".parse().unwrap(),
        );
        assert!(!auth.check_request(&headers));
    }

    #[test]
    fn jwt_missing_header() {
        let auth = jwt_auth(Some("k"));
        let headers = http::HeaderMap::new();
        assert!(!auth.check_request(&headers));
    }

    // --- DigestAuth deserialization tests ---

    #[test]
    fn digest_from_config() {
        let json = serde_json::json!({
            "type": "digest",
            "realm": "Restricted",
            "users": [
                {"username": "admin", "password": "pass"}
            ]
        });
        let auth = DigestAuth::from_config(json).unwrap();
        assert_eq!(auth.realm, "Restricted");
        assert_eq!(auth.users.len(), 1);
        assert_eq!(auth.users[0].username, "admin");
    }

    #[test]
    fn digest_from_config_missing_realm() {
        let json = serde_json::json!({
            "users": [{"username": "u", "password": "p"}]
        });
        assert!(DigestAuth::from_config(json).is_err());
    }

    // --- ForwardAuth deserialization tests ---

    #[test]
    fn forward_auth_from_config_full() {
        let json = serde_json::json!({
            "type": "forward_auth",
            "url": "http://auth-service/verify",
            "method": "POST",
            "headers_to_forward": ["Authorization", "Cookie"],
            "success_status": 200
        });
        let auth = ForwardAuthProvider::from_config(json).unwrap();
        assert_eq!(auth.url, "http://auth-service/verify");
        assert_eq!(auth.method.as_deref(), Some("POST"));
        assert_eq!(auth.headers_to_forward, vec!["Authorization", "Cookie"]);
        assert_eq!(auth.success_status, Some(200));
    }

    #[test]
    fn forward_auth_from_config_minimal() {
        let json = serde_json::json!({
            "url": "http://auth-service/check"
        });
        let auth = ForwardAuthProvider::from_config(json).unwrap();
        assert_eq!(auth.url, "http://auth-service/check");
        assert!(auth.method.is_none());
        assert!(auth.headers_to_forward.is_empty());
        assert!(auth.success_status.is_none());
    }

    #[test]
    fn forward_auth_from_config_missing_url() {
        let json = serde_json::json!({"method": "GET"});
        assert!(ForwardAuthProvider::from_config(json).is_err());
    }

    #[test]
    fn forward_auth_from_config_go_compat() {
        let json = serde_json::json!({
            "type": "forward",
            "url": "http://127.0.0.1:18888/auth/forward",
            "method": "GET",
            "forward_headers": ["X-Auth-Token"],
            "trust_headers": ["X-User-ID", "X-User-Role"],
            "timeout": 5,
            "success_status": [200]
        });
        let auth = ForwardAuthProvider::from_config(json).unwrap();
        assert_eq!(auth.url, "http://127.0.0.1:18888/auth/forward");
        assert_eq!(auth.method.as_deref(), Some("GET"));
        assert_eq!(auth.headers_to_forward, vec!["X-Auth-Token"]);
        assert_eq!(auth.trust_headers, vec!["X-User-ID", "X-User-Role"]);
        assert_eq!(auth.timeout, Some(5));
        assert_eq!(auth.success_status, Some(200));
    }

    // --- DigestAuth challenge generation tests ---

    #[test]
    fn digest_challenge_contains_realm() {
        let auth = DigestAuth::new("test-realm", vec![]);
        let nonce = DigestAuth::generate_nonce();
        let challenge = auth.challenge(&nonce);
        assert!(
            challenge.contains("Digest"),
            "challenge should start with Digest"
        );
        assert!(
            challenge.contains("realm=\"test-realm\""),
            "challenge should contain realm"
        );
        assert!(challenge.contains(&nonce), "challenge should contain nonce");
        assert!(
            challenge.contains("qop=\"auth\""),
            "challenge should contain qop"
        );
    }

    #[test]
    fn digest_nonce_is_unique() {
        let nonce1 = DigestAuth::generate_nonce();
        // Sleep briefly to ensure different timestamp.
        std::thread::sleep(std::time::Duration::from_millis(1));
        let nonce2 = DigestAuth::generate_nonce();
        assert_ne!(nonce1, nonce2, "nonces should be unique");
    }

    fn digest_test_user() -> DigestAuthUser {
        DigestAuthUser {
            username: "testuser".to_string(),
            password: "a08a2d645fc2bc82dfd69fd8b9c41f79".to_string(),
        }
    }

    #[test]
    fn digest_check_request_no_auth_header() {
        let auth = DigestAuth::new("test-realm", vec![digest_test_user()]);
        let headers = http::HeaderMap::new();
        assert!(!auth.check_request(&headers, "GET"));
    }

    #[test]
    fn digest_check_request_wrong_scheme() {
        let auth = DigestAuth::new("test-realm", vec![digest_test_user()]);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Basic dGVzdDp0ZXN0".parse().unwrap(),
        );
        assert!(!auth.check_request(&headers, "GET"));
    }

    #[test]
    fn digest_check_request_valid_response() {
        // HA1 = MD5(testuser:test-realm:testpass) = a08a2d645fc2bc82dfd69fd8b9c41f79
        let auth = DigestAuth::new("test-realm", vec![digest_test_user()]);

        let ha1 = "a08a2d645fc2bc82dfd69fd8b9c41f79";
        let nonce = "testnonce123";
        let nc = "00000001";
        let cnonce = "clientnonce";
        let uri = "/echo";
        let method = "GET";

        // HA2 = MD5(GET:/echo)
        let ha2 = DigestAuth::md5_hex(&format!("{}:{}", method, uri));
        // response = MD5(HA1:nonce:nc:cnonce:auth:HA2)
        let response =
            DigestAuth::md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2));

        let auth_header = format!(
            "Digest username=\"testuser\", realm=\"test-realm\", nonce=\"{}\", uri=\"{}\", qop=auth, nc={}, cnonce=\"{}\", response=\"{}\"",
            nonce, uri, nc, cnonce, response
        );

        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::AUTHORIZATION, auth_header.parse().unwrap());

        assert!(auth.check_request(&headers, method));
    }

    #[test]
    fn digest_check_request_wrong_password() {
        let auth = DigestAuth::new("test-realm", vec![digest_test_user()]);

        // Use a completely wrong response value.
        let auth_header = "Digest username=\"testuser\", realm=\"test-realm\", nonce=\"testnonce\", uri=\"/echo\", qop=auth, nc=00000001, cnonce=\"cn\", response=\"0000000000000000000000000000dead\"";

        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::AUTHORIZATION, auth_header.parse().unwrap());

        assert!(!auth.check_request(&headers, "GET"));
    }

    #[test]
    fn digest_from_config_go_format() {
        // Go format uses a map of username: ha1_hash.
        let json = serde_json::json!({
            "type": "digest",
            "realm": "test-realm",
            "users": {
                "testuser": "a08a2d645fc2bc82dfd69fd8b9c41f79"
            }
        });
        let auth = DigestAuth::from_config(json).unwrap();
        assert_eq!(auth.realm, "test-realm");
        assert_eq!(auth.users.len(), 1);
        assert_eq!(auth.users[0].username, "testuser");
        assert_eq!(auth.users[0].password, "a08a2d645fc2bc82dfd69fd8b9c41f79");
    }

    /// Build a valid digest `Authorization` header for `(nonce, nc)`.
    fn digest_auth_header(
        ha1: &str,
        method: &str,
        uri: &str,
        nonce: &str,
        nc: &str,
        cnonce: &str,
    ) -> String {
        let ha2 = DigestAuth::md5_hex(&format!("{}:{}", method, uri));
        let response =
            DigestAuth::md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2));
        format!(
            "Digest username=\"testuser\", realm=\"test-realm\", nonce=\"{}\", uri=\"{}\", qop=auth, nc={}, cnonce=\"{}\", response=\"{}\"",
            nonce, uri, nc, cnonce, response
        )
    }

    #[test]
    fn digest_replay_of_same_nonce_nc_is_rejected() {
        let auth = DigestAuth::new("test-realm", vec![digest_test_user()]);
        let ha1 = "a08a2d645fc2bc82dfd69fd8b9c41f79";
        let header = digest_auth_header(ha1, "GET", "/echo", "replay-nonce", "00000001", "cn-a");

        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::AUTHORIZATION, header.parse().unwrap());

        // First submission: accepted.
        assert!(auth.check_request(&headers, "GET"));
        // Same (nonce, nc): replay, must be rejected.
        assert!(!auth.check_request(&headers, "GET"));
    }

    #[test]
    fn digest_monotonic_nc_across_requests_is_accepted() {
        let auth = DigestAuth::new("test-realm", vec![digest_test_user()]);
        let ha1 = "a08a2d645fc2bc82dfd69fd8b9c41f79";

        let header1 = digest_auth_header(ha1, "GET", "/echo", "rotating-nonce", "00000001", "cn-a");
        let header2 = digest_auth_header(ha1, "GET", "/echo", "rotating-nonce", "00000002", "cn-b");

        let mut h1 = http::HeaderMap::new();
        h1.insert(http::header::AUTHORIZATION, header1.parse().unwrap());
        let mut h2 = http::HeaderMap::new();
        h2.insert(http::header::AUTHORIZATION, header2.parse().unwrap());

        assert!(auth.check_request(&h1, "GET"));
        assert!(auth.check_request(&h2, "GET"));
    }

    #[test]
    fn digest_out_of_order_nc_is_rejected() {
        let auth = DigestAuth::new("test-realm", vec![digest_test_user()]);
        let ha1 = "a08a2d645fc2bc82dfd69fd8b9c41f79";

        let header_high =
            digest_auth_header(ha1, "GET", "/echo", "reorder-nonce", "00000005", "cn-a");
        let header_low =
            digest_auth_header(ha1, "GET", "/echo", "reorder-nonce", "00000003", "cn-b");

        let mut h_high = http::HeaderMap::new();
        h_high.insert(http::header::AUTHORIZATION, header_high.parse().unwrap());
        let mut h_low = http::HeaderMap::new();
        h_low.insert(http::header::AUTHORIZATION, header_low.parse().unwrap());

        assert!(auth.check_request(&h_high, "GET"));
        // A lower nc arriving after a higher one means either a reorder
        // or an attempted replay; RFC 7616 says reject.
        assert!(!auth.check_request(&h_low, "GET"));
    }
}
