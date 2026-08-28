//! WOR-2667: `oauth_introspection` provider, RFC 7662 token introspection.
//!
//! Validates an opaque bearer token by asking the authorization server
//! that issued it. The proxy POSTs the token to the server's
//! introspection endpoint, authenticating itself with the configured
//! client credentials, and reads back `{"active": true, ...}`.
//!
//! # Why this exists next to `jwt`
//!
//! [`crate::auth::JwtAuth`] verifies a token locally against a signing key, so
//! it costs nothing per request and cannot know that a token was
//! revoked five seconds ago. Introspection is the opposite trade: the
//! authorization server is asked about every token, so a revoked token
//! stops working immediately, and the price is a network round trip on
//! the request path. Opaque tokens (the reference tokens Okta,
//! Keycloak, and Auth0 hand out when a client does not ask for a JWT)
//! carry no claims at all, so introspection is the only way to learn
//! anything about them.
//!
//! # The verdict cache is what makes it affordable
//!
//! A verdict is cached for `cache_ttl` seconds, keyed on the SHA-256 of
//! the token so the map never holds a plaintext credential, and capped
//! at `MAX_CACHED_VERDICTS` (10,000) entries. Three properties follow from
//! the shape:
//!
//! * **The cache shortens, never lengthens, a token's life.** When the
//!   introspection response carries `exp`, the entry expires at
//!   `min(exp, now + cache_ttl)`, so a token with 30 seconds left is not
//!   accepted for the full minute the default TTL would allow.
//! * **The cache is bounded.** Without a cap, a flood of distinct
//!   invented tokens grows the map for the life of the process; with
//!   one, the flood evicts itself. The enterprise implementation this
//!   replaces used an unbounded map.
//! * **Only the authorization server's own answers are cached.** A
//!   transport failure is never cached, so an outage does not pin a
//!   refusal in place after the server comes back.
//!
//! `cache_ttl: 0` disables the cache, which is the right setting when a
//! revocation has to take effect on the very next request rather than
//! within a minute.
//!
//! # Security posture
//!
//! * **The introspection call fails closed.** RFC 7662 section 2.3 says
//!   a resource server should refuse when it cannot introspect, and a
//!   failure here answers `503` rather than `401`: the caller's
//!   credential is not what is in question.
//! * **The client secret never reaches a log line.** It is read once
//!   into the `Authorization: Basic` header of the outbound call and is
//!   not part of `Debug`, any error string, or any metric label.
//! * **The outbound client refuses redirects.** The call carries the
//!   proxy's own client credentials; a redirect would forward them to
//!   whatever host the authorization server named.
//! * **The response is bounded** at `MAX_INTROSPECTION_RESPONSE_BYTES`
//!   before it is parsed.

use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::warn;

/// Default verdict-cache lifetime in seconds.
const DEFAULT_CACHE_TTL_SECS: u64 = 60;

/// Default introspection timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Shortest token the provider will introspect.
///
/// Anything shorter is refused without a round trip. A one-character
/// `Authorization: Bearer x` is not a credential any issuer minted, and
/// forwarding it would turn the proxy into a way to make an
/// authorization server work on request.
const MIN_TOKEN_LEN: usize = 8;

/// Largest introspection response the provider will parse.
const MAX_INTROSPECTION_RESPONSE_BYTES: usize = 64 * 1024;

/// Verdict-cache capacity, in tokens.
///
/// Each entry is a hash, a small verdict, and an instant, so the cap is
/// about bounding an attacker-controlled key space rather than about
/// bytes. Past it, the least recently used entry is dropped, which
/// costs a fresh introspection rather than an admission.
const MAX_CACHED_VERDICTS: usize = 10_000;

/// What the authorization server said about a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntrospectionOutcome {
    /// The token is active and satisfies every required scope.
    Active {
        /// Subject the server named, when it named one. Some servers
        /// return `sub`, some return `username`, client-credentials
        /// grants often return neither.
        subject: Option<String>,
    },
    /// The server said the token is not active.
    Inactive,
    /// The token is active but is missing a required scope.
    InsufficientScope {
        /// The first required scope the token did not carry. Safe to
        /// return to the caller: it is operator config, not credential
        /// material.
        missing: String,
    },
    /// The introspection call did not complete. Fails closed.
    Unavailable,
}

impl IntrospectionOutcome {
    /// Stable metric label for this outcome.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::Active { .. } => "active",
            Self::Inactive => "inactive",
            Self::InsufficientScope { .. } => "insufficient_scope",
            Self::Unavailable => "unavailable",
        }
    }

    /// True when the outcome may be cached.
    ///
    /// A transport failure is deliberately excluded: caching it would
    /// keep refusing after the authorization server recovered.
    fn is_cacheable(&self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}

/// A cached verdict and the instant it stops being usable.
#[derive(Debug, Clone)]
struct CachedVerdict {
    outcome: IntrospectionOutcome,
    expires_at: Instant,
}

/// RFC 7662 introspection response, the subset this provider reads.
#[derive(Debug, Deserialize, Default)]
struct IntrospectionResponse {
    active: bool,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    sub: Option<String>,
    /// Auth0 and Okta return `username` instead of `sub` for
    /// resource-owner flows.
    #[serde(default)]
    username: Option<String>,
}

/// `oauth_introspection` provider.
pub struct OauthIntrospectionProvider {
    /// RFC 7662 introspection endpoint.
    pub introspection_url: String,
    /// Client identifier the proxy authenticates to the endpoint with.
    pub client_id: String,
    /// Client secret. Empty for a public client.
    client_secret: String,
    /// Optional RFC 7662 `token_type_hint`.
    pub token_type_hint: Option<String>,
    /// Verdict-cache lifetime. Zero disables the cache.
    pub cache_ttl: Duration,
    /// Scopes a token must carry to be admitted.
    pub required_scopes: Vec<String>,
    client: reqwest::Client,
    cache: Mutex<lru::LruCache<[u8; 32], CachedVerdict>>,
}

impl std::fmt::Debug for OauthIntrospectionProvider {
    /// Renders without the client secret. A `Debug` that carried it
    /// would put a credential into every error chain that formats a
    /// compiled origin.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthIntrospectionProvider")
            .field(
                "introspection_url",
                &sbproxy_security::url_redact::redacted_url(&self.introspection_url),
            )
            .field("client_id", &self.client_id)
            .field("client_secret_configured", &!self.client_secret.is_empty())
            .field("cache_ttl", &self.cache_ttl)
            .field("required_scopes", &self.required_scopes)
            .finish()
    }
}

impl OauthIntrospectionProvider {
    /// Build a provider from its `authentication:` block.
    ///
    /// Unknown keys are refused (WOR-2181): `required_scopes` is the
    /// key worth misspelling here, because its default admits any
    /// active token.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawConfig {
            introspection_url: String,
            client_id: String,
            #[serde(default)]
            client_secret: Option<String>,
            #[serde(default)]
            token_type_hint: Option<String>,
            #[serde(default = "default_cache_ttl")]
            cache_ttl: u64,
            #[serde(default = "default_timeout_secs")]
            timeout_secs: u64,
            #[serde(default)]
            required_scopes: Vec<String>,
        }
        fn default_cache_ttl() -> u64 {
            DEFAULT_CACHE_TTL_SECS
        }
        fn default_timeout_secs() -> u64 {
            DEFAULT_TIMEOUT_SECS
        }

        let raw: RawConfig = super::provider_config_from_value(value)?;
        if !raw.introspection_url.starts_with("https://")
            && !raw.introspection_url.starts_with("http://")
        {
            anyhow::bail!(
                "oauth_introspection introspection_url must start with https:// \
                 (http:// is accepted for a loopback development endpoint)"
            );
        }
        if raw.client_id.trim().is_empty() {
            anyhow::bail!(
                "oauth_introspection requires a client_id; RFC 7662 section 2.1 \
                 requires the caller to authenticate to the introspection endpoint"
            );
        }
        if raw.timeout_secs == 0 {
            anyhow::bail!(
                "oauth_introspection timeout_secs must be at least 1; a zero \
                 timeout means no timeout"
            );
        }
        // No redirects: the request carries the proxy's own client
        // credentials in an `Authorization: Basic` header.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(raw.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| anyhow::anyhow!("oauth_introspection client build failed: {e}"))?;
        // WOR-1784: resolve a provider-URI secret reference before the
        // secret is used, so `env:`, `file:`, and `vault://` reach the
        // authorization server as the credential they name rather than
        // verbatim. `${VAR}` works without this because the config
        // layer rewrites the raw YAML, which is exactly why the other
        // three forms are easy to miss: `sbproxy validate` passes them,
        // the proxy boots, and every introspection call then sends the
        // reference as the password and gets a 401 the operator reads
        // as an outage.
        let client_secret = match raw.client_secret {
            Some(reference) => {
                // WOR-2673 review F1, same shape one crate over: the
                // config layer leaves an unset `${VAR}` as its own
                // literal text, and without this the literal became the
                // password. `sbproxy validate` passes it, the proxy
                // boots, and the authorization server answers 401 on
                // every request.
                if let Some(name) = sbproxy_vault::unexpanded_env_placeholder(&reference) {
                    anyhow::bail!(
                        "oauth_introspection client_secret still reads '${{{name}}}': the \
                         environment variable is not set, so the placeholder itself would have \
                         been sent as the client secret"
                    );
                }
                match sbproxy_vault::process_resolver() {
                    Some(resolver) => resolver.resolve(&reference).map_err(|e| {
                        // The error names the backend and the key, never
                        // the value; the reference itself is operator
                        // config and is safe in the message.
                        anyhow::anyhow!("oauth_introspection: resolving client_secret: {e}")
                    })?,
                    None => reference,
                }
            }
            None => String::new(),
        };
        let capacity = NonZeroUsize::new(MAX_CACHED_VERDICTS)
            .ok_or_else(|| anyhow::anyhow!("verdict cache capacity must be non-zero"))?;
        Ok(Self {
            introspection_url: raw.introspection_url,
            client_id: raw.client_id,
            client_secret,
            token_type_hint: raw.token_type_hint,
            cache_ttl: Duration::from_secs(raw.cache_ttl),
            required_scopes: raw.required_scopes,
            client,
            cache: Mutex::new(lru::LruCache::new(capacity)),
        })
    }

    /// Pull the bearer token out of the request's `Authorization`
    /// header. Returns `None` when the header is absent, carries
    /// another scheme, or holds something too short to be a credential.
    pub fn extract_token(headers: &http::HeaderMap) -> Option<&str> {
        let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
        // RFC 6750 section 2.1: the scheme is case-insensitive.
        let (scheme, token) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let token = token.trim();
        (token.len() >= MIN_TOKEN_LEN).then_some(token)
    }

    /// Introspect one request's token.
    ///
    /// Records the outcome on
    /// `sbproxy_oauth_introspection_results_total` before returning, so
    /// the metric cannot disagree with what the request did. Two label
    /// values are not verdicts: a cache hit records `cached` rather
    /// than the verdict it replays, and a request carrying no bearer
    /// token at all records `no_token`, because nothing was asked. That
    /// keeps "what did the server say" and "how often did we have to
    /// ask" separable.
    pub async fn authenticate(&self, headers: &http::HeaderMap) -> IntrospectionOutcome {
        let Some(token) = Self::extract_token(headers) else {
            // Nothing was presented, so nothing was asked of the
            // authorization server. Still recorded: the rustdoc above
            // promises every call records, and a provider seeing only
            // credential-less requests is a real thing an operator
            // wants to see rather than an absence on every series.
            sbproxy_observe::metrics::record_oauth_introspection_result("no_token");
            return IntrospectionOutcome::Inactive;
        };
        let key = token_hash(token);
        if let Some(cached) = self.cache_get(&key) {
            sbproxy_observe::metrics::record_oauth_introspection_result("cached");
            return cached;
        }
        let (outcome, exp) = self.introspect(token).await;
        sbproxy_observe::metrics::record_oauth_introspection_result(outcome.metric_label());
        if outcome.is_cacheable() {
            self.cache_put(key, &outcome, exp);
        }
        outcome
    }

    fn cache_get(&self, key: &[u8; 32]) -> Option<IntrospectionOutcome> {
        if self.cache_ttl.is_zero() {
            return None;
        }
        let mut guard = self.cache.lock();
        let entry = guard.get(key)?;
        if entry.expires_at > Instant::now() {
            return Some(entry.outcome.clone());
        }
        // Expired: drop it so a stale verdict cannot be replayed by a
        // later clock read.
        guard.pop(key);
        None
    }

    fn cache_put(&self, key: [u8; 32], outcome: &IntrospectionOutcome, exp: Option<u64>) {
        if self.cache_ttl.is_zero() {
            return;
        }
        let ttl = effective_ttl(self.cache_ttl, exp, SystemTime::now());
        if ttl.is_zero() {
            return;
        }
        self.cache.lock().put(
            key,
            CachedVerdict {
                outcome: outcome.clone(),
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// POST the token to the introspection endpoint and interpret the
    /// answer. Returns the outcome plus the response's `exp` so the
    /// caller can shorten the cache entry to the token's own lifetime.
    async fn introspect(&self, token: &str) -> (IntrospectionOutcome, Option<u64>) {
        let mut form: Vec<(&str, &str)> = vec![("token", token)];
        if let Some(hint) = self.token_type_hint.as_deref() {
            form.push(("token_type_hint", hint));
        }
        // RFC 7662 section 2.1: the caller authenticates to the
        // endpoint. Client-secret-basic is the form every server in the
        // confirmed target set accepts.
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.client_id, self.client_secret));

        // Joined to the ambient `sbproxy.intake.authenticate` span the
        // caller opened, so a slow authorization server shows up as its
        // own bar rather than as unexplained admission latency.
        let request = sbproxy_observe::telemetry::inject_reqwest_trace_context(
            self.client
                .post(&self.introspection_url)
                .header(http::header::ACCEPT, "application/json")
                .header(http::header::AUTHORIZATION, format!("Basic {credentials}"))
                .form(&form),
            None,
        );
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                // The summary, not the error: reqwest's Display ends
                // with the full URL (WOR-2629).
                warn!(
                    error = %sbproxy_httpkit::request_error_summary(&error),
                    url = %sbproxy_security::url_redact::redacted_url(&self.introspection_url),
                    "oauth_introspection call failed; failing closed"
                );
                return (IntrospectionOutcome::Unavailable, None);
            }
        };

        let status = response.status();
        if !status.is_success() {
            warn!(
                url = %sbproxy_security::url_redact::redacted_url(&self.introspection_url),
                status = status.as_u16(),
                "oauth_introspection endpoint answered a non-success status; failing closed"
            );
            return (IntrospectionOutcome::Unavailable, None);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_INTROSPECTION_RESPONSE_BYTES as u64)
        {
            warn!(
                url = %sbproxy_security::url_redact::redacted_url(&self.introspection_url),
                limit = MAX_INTROSPECTION_RESPONSE_BYTES,
                "oauth_introspection response is larger than the parse limit"
            );
            return (IntrospectionOutcome::Unavailable, None);
        }
        let body = match response.bytes().await {
            Ok(body) if body.len() <= MAX_INTROSPECTION_RESPONSE_BYTES => body,
            Ok(_) => {
                warn!(
                    url = %sbproxy_security::url_redact::redacted_url(&self.introspection_url),
                    limit = MAX_INTROSPECTION_RESPONSE_BYTES,
                    "oauth_introspection response exceeded the parse limit"
                );
                return (IntrospectionOutcome::Unavailable, None);
            }
            Err(error) => {
                warn!(
                    error = %sbproxy_httpkit::request_error_summary(&error),
                    url = %sbproxy_security::url_redact::redacted_url(&self.introspection_url),
                    "oauth_introspection response could not be read"
                );
                return (IntrospectionOutcome::Unavailable, None);
            }
        };
        let parsed: IntrospectionResponse = match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(error) => {
                // The serde error names a position, never the payload,
                // so an endpoint answering with a token-bearing page
                // does not log one.
                warn!(
                    url = %sbproxy_security::url_redact::redacted_url(&self.introspection_url),
                    error = %error,
                    "oauth_introspection response is not an RFC 7662 document"
                );
                return (IntrospectionOutcome::Unavailable, None);
            }
        };
        let exp = parsed.exp;
        (self.decide(&parsed), exp)
    }

    /// Interpret a parsed introspection response. Split out so the
    /// decision is testable without a live authorization server.
    fn decide(&self, parsed: &IntrospectionResponse) -> IntrospectionOutcome {
        if !parsed.active {
            return IntrospectionOutcome::Inactive;
        }
        if !self.required_scopes.is_empty() {
            let granted: HashSet<&str> = parsed
                .scope
                .as_deref()
                .unwrap_or("")
                .split_ascii_whitespace()
                .collect();
            for required in &self.required_scopes {
                if !granted.contains(required.as_str()) {
                    return IntrospectionOutcome::InsufficientScope {
                        missing: required.clone(),
                    };
                }
            }
        }
        let subject = parsed
            .sub
            .as_deref()
            .or(parsed.username.as_deref())
            .map(str::trim)
            .filter(|subject| !subject.is_empty())
            .map(str::to_string);
        IntrospectionOutcome::Active { subject }
    }
}

/// Cache key for a token: its SHA-256, so the map holds no credential.
fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// How long a verdict may be cached, given the configured TTL and the
/// token's own `exp`.
///
/// Split out and taking `now` so the shortening rule is testable
/// without waiting on a clock.
fn effective_ttl(configured: Duration, exp: Option<u64>, now: SystemTime) -> Duration {
    let Some(exp) = exp else {
        return configured;
    };
    let Ok(since_epoch) = now.duration_since(UNIX_EPOCH) else {
        // A clock before the epoch cannot be reasoned about; keep the
        // configured bound rather than inventing a longer one.
        return configured;
    };
    let remaining = Duration::from_secs(exp.saturating_sub(since_epoch.as_secs()));
    remaining.min(configured)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(required_scopes: &[&str], cache_ttl: u64) -> OauthIntrospectionProvider {
        OauthIntrospectionProvider::from_config(serde_json::json!({
            "type": "oauth_introspection",
            "introspection_url": "https://idp.internal/introspect",
            "client_id": "sbproxy",
            "client_secret": "s3cret",
            "cache_ttl": cache_ttl,
            "required_scopes": required_scopes,
        }))
        .expect("provider compiles")
    }

    fn response(json: serde_json::Value) -> IntrospectionResponse {
        serde_json::from_value(json).expect("introspection response parses")
    }

    fn bearer(value: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(value).expect("header value"),
        );
        headers
    }

    /// WOR-2667 review M1. `${VAR}` works by accident because the
    /// config layer rewrites the raw YAML; `env:`, `file:`, and every
    /// provider URI reach the provider verbatim unless it resolves
    /// them. Before the fix, `vault://...` was sent to the
    /// authorization server as the password, which answers 401, which
    /// the provider reports as an outage.
    #[test]
    fn a_provider_uri_client_secret_is_resolved_not_sent_verbatim() {
        sbproxy_vault::reset_process_resolver_for_test();
        let vault = sbproxy_vault::LocalVault::new();
        vault
            .set_secret("introspection", "resolved-client-secret")
            .expect("fixture secret");
        let mut manager = sbproxy_vault::VaultManager::new();
        manager.register("fixture", Box::new(vault));
        sbproxy_vault::install_process_resolver(std::sync::Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(std::sync::Arc::new(manager)),
        ));

        let provider = OauthIntrospectionProvider::from_config(serde_json::json!({
            "type": "oauth_introspection",
            "introspection_url": "https://idp.internal/introspect",
            "client_id": "sbproxy",
            "client_secret": "secret://fixture/introspection",
        }))
        .expect("provider compiles");
        assert_eq!(provider.client_secret, "resolved-client-secret");
        sbproxy_vault::reset_process_resolver_for_test();
    }

    /// An unresolvable reference refuses at config compile rather than
    /// becoming the credential. The failure an operator sees is the
    /// config error, not a 503 on every request.
    #[test]
    fn an_unresolvable_client_secret_reference_refuses_to_compile() {
        sbproxy_vault::reset_process_resolver_for_test();
        let manager = sbproxy_vault::VaultManager::new();
        sbproxy_vault::install_process_resolver(std::sync::Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(std::sync::Arc::new(manager)),
        ));

        let error = OauthIntrospectionProvider::from_config(serde_json::json!({
            "type": "oauth_introspection",
            "introspection_url": "https://idp.internal/introspect",
            "client_id": "sbproxy",
            "client_secret": "secret://missing-backend/key",
        }))
        .expect_err("an unresolvable reference must not become the credential");
        assert!(error.to_string().contains("client_secret"), "{error:#}");
        sbproxy_vault::reset_process_resolver_for_test();
    }

    /// WOR-2673 review F1, checked across every secret field the ports
    /// added. An unset variable must not become the credential.
    #[test]
    fn an_unexpanded_placeholder_client_secret_refuses_to_compile() {
        let error = OauthIntrospectionProvider::from_config(serde_json::json!({
            "type": "oauth_introspection",
            "introspection_url": "https://idp.internal/introspect",
            "client_id": "sbproxy",
            "client_secret": "${SB_INTROSPECTION_SECRET}",
        }))
        .expect_err("an unset variable must not become the client secret");
        let message = format!("{error:#}");
        assert!(message.contains("SB_INTROSPECTION_SECRET"), "{message}");
    }

    #[test]
    fn from_config_refuses_an_unknown_key() {
        let error = OauthIntrospectionProvider::from_config(serde_json::json!({
            "type": "oauth_introspection",
            "introspection_url": "https://idp.internal/introspect",
            "client_id": "sbproxy",
            "required_scope": ["read"],
        }))
        .expect_err("a misspelled scope key must not compile");
        assert!(error.to_string().contains("required_scope"), "{error:#}");
    }

    #[test]
    fn from_config_requires_a_client_id() {
        let error = OauthIntrospectionProvider::from_config(serde_json::json!({
            "type": "oauth_introspection",
            "introspection_url": "https://idp.internal/introspect",
            "client_id": "   ",
        }))
        .expect_err("a blank client_id must not compile");
        assert!(error.to_string().contains("client_id"), "{error:#}");
    }

    #[test]
    fn debug_does_not_render_the_client_secret() {
        let rendered = format!("{:?}", provider(&[], 60));
        assert!(!rendered.contains("s3cret"), "{rendered}");
        assert!(
            rendered.contains("client_secret_configured: true"),
            "{rendered}"
        );
    }

    #[test]
    fn extract_token_is_scheme_insensitive_and_length_bounded() {
        assert_eq!(
            OauthIntrospectionProvider::extract_token(&bearer("bearer abcdefgh")),
            Some("abcdefgh")
        );
        assert_eq!(
            OauthIntrospectionProvider::extract_token(&bearer("Bearer short")),
            None,
            "a token below the minimum length must not reach the endpoint"
        );
        assert_eq!(
            OauthIntrospectionProvider::extract_token(&bearer("Basic abcdefghij")),
            None
        );
        assert_eq!(
            OauthIntrospectionProvider::extract_token(&http::HeaderMap::new()),
            None
        );
    }

    #[test]
    fn an_inactive_token_is_refused() {
        let provider = provider(&[], 60);
        assert_eq!(
            provider.decide(&response(serde_json::json!({"active": false}))),
            IntrospectionOutcome::Inactive
        );
    }

    #[test]
    fn an_active_token_resolves_sub_then_username() {
        let provider = provider(&[], 60);
        assert_eq!(
            provider.decide(&response(
                serde_json::json!({"active": true, "sub": "alice"})
            )),
            IntrospectionOutcome::Active {
                subject: Some("alice".to_string())
            }
        );
        assert_eq!(
            provider.decide(&response(
                serde_json::json!({"active": true, "username": "bob"})
            )),
            IntrospectionOutcome::Active {
                subject: Some("bob".to_string())
            }
        );
        assert_eq!(
            provider.decide(&response(serde_json::json!({"active": true}))),
            IntrospectionOutcome::Active { subject: None },
            "a client-credentials token with no subject is still active"
        );
    }

    #[test]
    fn a_missing_required_scope_refuses_an_active_token() {
        let provider = provider(&["read", "write"], 60);
        assert_eq!(
            provider.decide(&response(
                serde_json::json!({"active": true, "scope": "read profile"})
            )),
            IntrospectionOutcome::InsufficientScope {
                missing: "write".to_string()
            }
        );
        assert_eq!(
            provider.decide(&response(
                serde_json::json!({"active": true, "scope": "write read"})
            )),
            IntrospectionOutcome::Active { subject: None },
            "scope order must not matter"
        );
    }

    #[test]
    fn exp_shortens_the_cache_entry_but_never_lengthens_it() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        // A token expiring in 30s under a 60s TTL caches for 30s.
        assert_eq!(
            effective_ttl(Duration::from_secs(60), Some(1_030), now),
            Duration::from_secs(30)
        );
        // A token expiring in an hour under a 60s TTL still caches for
        // 60s.
        assert_eq!(
            effective_ttl(Duration::from_secs(60), Some(4_600), now),
            Duration::from_secs(60)
        );
        // An already-expired token caches for nothing at all.
        assert_eq!(
            effective_ttl(Duration::from_secs(60), Some(900), now),
            Duration::ZERO
        );
        // No `exp` leaves the configured bound in place.
        assert_eq!(
            effective_ttl(Duration::from_secs(60), None, now),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn a_cached_verdict_is_replayed_and_a_zero_ttl_disables_the_cache() {
        let cached = provider(&[], 60);
        let uncached = provider(&[], 0);
        let key = token_hash("token-abcdefgh");
        cached.cache_put(key, &IntrospectionOutcome::Inactive, None);
        assert_eq!(cached.cache_get(&key), Some(IntrospectionOutcome::Inactive));

        uncached.cache_put(key, &IntrospectionOutcome::Inactive, None);
        assert_eq!(
            uncached.cache_get(&key),
            None,
            "cache_ttl: 0 must reach the authorization server every time"
        );
    }

    #[test]
    fn an_unavailable_verdict_is_never_cached() {
        assert!(!IntrospectionOutcome::Unavailable.is_cacheable());
        assert!(IntrospectionOutcome::Inactive.is_cacheable());
        assert!(IntrospectionOutcome::Active { subject: None }.is_cacheable());
    }

    #[test]
    fn the_verdict_cache_is_bounded() {
        let provider = provider(&[], 60);
        for index in 0..(MAX_CACHED_VERDICTS + 100) {
            provider.cache_put(
                token_hash(&format!("token-{index}")),
                &IntrospectionOutcome::Inactive,
                None,
            );
        }
        assert_eq!(
            provider.cache.lock().len(),
            MAX_CACHED_VERDICTS,
            "a flood of distinct tokens must not grow the cache without bound"
        );
    }

    #[test]
    fn the_cache_key_is_a_hash_rather_than_the_token() {
        let token = "super-secret-token";
        let key = token_hash(token);
        assert_ne!(&key[..], token.as_bytes());
        assert_eq!(key, token_hash(token), "hashing must be stable");
    }
}
