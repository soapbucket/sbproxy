//! Run-as-user upstream credential minting (WOR-1792 / G3).
//!
//! Produces Authorization credentials for MCP upstream calls from a
//! typed [`McpUpstreamAuthConfig`] and an [`McpExecutionContext`].
//! Identity and tokens never enter tool arguments; anonymous and
//! shared-key callers fail closed when run-as-user is enabled; stdio
//! plus run-as-user is a config error until a safe secret-delivery
//! path exists.
//!
//! Wire path: mint via [`mint_upstream_authorization`], then pass
//! `(header_name, header_value)` through
//! [`crate::mcp::federation::McpFederation::call_tool_with_upstream_headers`]
//! so [`crate::mcp::streamable::send_request`] attaches them on the
//! outbound POST. Never put credentials in tool arguments.
//!
//! # The token-exchange POST is a governed dial
//!
//! Token exchange is the one mode here that leaves the process, and it
//! leaves carrying two credentials: the caller's inbound bearer as the
//! `subject_token` form field, and (when configured) a client secret in
//! HTTP Basic. It goes out through
//! [`sbproxy_security::governed_egress`], the workspace's one bounded
//! redirect loop, which authorizes the endpoint, pins the dial to the
//! addresses that authorization resolved, re-authorizes any redirect
//! before a second connect, refuses to replay a body off-origin, and
//! caps the reply. None of that held before WOR-2620: the endpoint was
//! authorized, the pin set was discarded, and a shared client resolved
//! the host again and replayed the form body at whatever `Location`
//! came back.
//!
//! # The token cache is keyed by the host, and bounded
//!
//! Exchanged credentials are cached, and a cache on a credential path
//! is two questions rather than one. What identifies an entry is
//! `cache_key`, which mixes in the tenant the request pipeline resolved
//! along with every other input that changes what a successful exchange
//! returns (WOR-2619). How large it may get is `TOKEN_CACHE_CAPACITY`
//! and the expiry sweep beside it, because the key hashes a rotating
//! inbound bearer and the map it replaced had no bound and deleted
//! nothing (WOR-2621).

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use sbproxy_plugin::{McpExecutionContext, Principal, PrincipalSource};
use sbproxy_security::egress::{
    CachedSystemResolver, EgressAuthorizer, EgressPurpose, HostResolver,
};
use sbproxy_security::governed_egress::{GovernedEgress, GovernedEgressError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// How the MCP upstream expects credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpUpstreamAuthConfig {
    /// Shared service credential resolved by reference (vault / env).
    ServiceCredential {
        /// Credential reference resolved through the secret lookup.
        credential_ref: String,
    },
    /// RFC 8693-style token exchange for the inbound / delegated subject.
    TokenExchange {
        /// Token endpoint URL. Gated by [`EgressPurpose::TokenExchange`].
        token_endpoint: url::Url,
        /// Audience requested for the exchanged token.
        audience: String,
        /// Optional OAuth scope.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        /// Optional client credential reference for the token endpoint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_credential_ref: Option<String>,
    },
    /// Per-user credential; `{subject_id}` in the template is replaced
    /// with the delegation (or principal) subject before lookup.
    PerUserCredential {
        /// Template such as `vault://users/{subject_id}/mcp-token`.
        credential_template: String,
    },
}

/// MCP transport used to reach the upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTransportKind {
    /// Streamable HTTP / SSE-over-HTTP.
    Http,
    /// Legacy SSE client transport.
    Sse,
    /// Local supervised stdio child process.
    Stdio,
}

/// Closed error vocabulary for run-as-user credential minting.
///
/// Display / Debug strings never embed secrets, tokens, or raw DSNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamAuthError {
    /// Caller has no subject and no attribution surface.
    AnonymousCaller,
    /// Shared bearer / API-key credential without a bound subject.
    SharedKeyCaller,
    /// stdio transport cannot safely deliver per-user secrets yet.
    StdioRunAsUserUnsupported,
    /// Run-as-user modes that need a subject but none was provided.
    MissingSubject,
    /// Secret lookup failed (reference identity only; never the secret).
    SecretLookup,
    /// Token exchange failed without echoing response bodies.
    TokenExchangeFailed,
    /// Token-endpoint egress denied.
    EgressDenied,
    /// Authorization header value could not be constructed.
    InvalidHeader,
}

impl std::fmt::Display for UpstreamAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AnonymousCaller => write!(f, "run-as-user requires an authenticated subject"),
            Self::SharedKeyCaller => {
                write!(
                    f,
                    "run-as-user rejects shared-key callers without a subject"
                )
            }
            Self::StdioRunAsUserUnsupported => {
                write!(f, "stdio transport cannot use run-as-user credentials")
            }
            Self::MissingSubject => {
                write!(f, "run-as-user requires a delegation or principal subject")
            }
            Self::SecretLookup => write!(f, "credential secret lookup failed"),
            Self::TokenExchangeFailed => write!(f, "token exchange failed"),
            Self::EgressDenied => write!(f, "token exchange egress denied"),
            Self::InvalidHeader => write!(f, "authorization header is invalid"),
        }
    }
}

impl std::error::Error for UpstreamAuthError {}

/// Minted upstream Authorization credential (header only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamAuthorization {
    /// Header name, lowercased (`authorization`).
    pub header_name: String,
    /// Header value (`Bearer …`). Never logged by this module.
    pub header_value: String,
}

/// Validate that run-as-user auth is compatible with the transport.
///
/// `stdio` + any run-as-user auth config is a hard config error until a
/// safe secret-delivery mechanism exists for local child processes.
pub fn validate_run_as_user_config(
    _config: &McpUpstreamAuthConfig,
    transport: McpTransportKind,
) -> Result<(), UpstreamAuthError> {
    if matches!(transport, McpTransportKind::Stdio) {
        return Err(UpstreamAuthError::StdioRunAsUserUnsupported);
    }
    Ok(())
}

/// True when the principal is a shared-key caller (bearer / API key
/// with no bound subject).
pub fn is_shared_key_caller(principal: &Principal) -> bool {
    principal.sub.is_empty()
        && matches!(
            principal.source,
            PrincipalSource::Bearer | PrincipalSource::ApiKey
        )
}

/// Resolve the subject id used for per-user minting and cache isolation.
fn subject_id_for(ctx: &McpExecutionContext<'_>) -> Option<String> {
    if let Some(d) = ctx.delegation {
        if !d.subject_id.is_empty() {
            return Some(d.subject_id.clone());
        }
    }
    if !ctx.principal.sub.is_empty() {
        return Some(ctx.principal.sub.clone());
    }
    if let Some(user) = ctx.principal.attrs.user.as_ref() {
        if !user.is_empty() {
            return Some(user.clone());
        }
    }
    None
}

fn require_identifiable_caller(ctx: &McpExecutionContext<'_>) -> Result<String, UpstreamAuthError> {
    if ctx.principal.is_anonymous() {
        return Err(UpstreamAuthError::AnonymousCaller);
    }
    if is_shared_key_caller(ctx.principal) {
        return Err(UpstreamAuthError::SharedKeyCaller);
    }
    subject_id_for(ctx).ok_or(UpstreamAuthError::MissingSubject)
}

/// Mint an Authorization credential for `ctx` under `config`.
///
/// Never mutates tool arguments. Token exchange is gated by
/// [`EgressPurpose::TokenExchange`] when an authorizer is supplied.
pub async fn mint_upstream_authorization(
    config: &McpUpstreamAuthConfig,
    ctx: &McpExecutionContext<'_>,
    secret_lookup: &(dyn Fn(&str) -> Result<String, ()> + Sync),
    http: &reqwest::Client,
    egress: Option<&EgressAuthorizer>,
    subject_token: Option<&str>,
) -> Result<UpstreamAuthorization, UpstreamAuthError> {
    let subject = require_identifiable_caller(ctx)?;
    match config {
        McpUpstreamAuthConfig::ServiceCredential { credential_ref } => {
            let secret =
                secret_lookup(credential_ref).map_err(|_| UpstreamAuthError::SecretLookup)?;
            Ok(bearer_auth(secret))
        }
        McpUpstreamAuthConfig::PerUserCredential {
            credential_template,
        } => {
            let resolved_ref = credential_template.replace("{subject_id}", &subject);
            let secret =
                secret_lookup(&resolved_ref).map_err(|_| UpstreamAuthError::SecretLookup)?;
            Ok(bearer_auth(secret))
        }
        McpUpstreamAuthConfig::TokenExchange {
            token_endpoint,
            audience,
            scope,
            client_credential_ref,
        } => {
            mint_token_exchange(
                token_endpoint,
                audience,
                scope.as_deref(),
                client_credential_ref.as_deref(),
                &subject,
                subject_token,
                secret_lookup,
                http,
                egress,
                // The tenant comes off the principal the request
                // pipeline resolved, never off anything the caller
                // sent, which is what makes the cache key's tenant
                // mixing a host decision rather than a caller one.
                ctx.principal.tenant_id.as_str(),
                // A live, short-TTL-cached resolver, so the pins
                // describe DNS rather than a fixture and
                // `allow_private` can refuse an IdP hostname that
                // resolves onto the pod network.
                &CachedSystemResolver,
            )
            .await
        }
    }
}

fn bearer_auth(secret: String) -> UpstreamAuthorization {
    UpstreamAuthorization {
        header_name: "authorization".to_string(),
        header_value: format!("Bearer {secret}"),
    }
}

/// Attach a minted credential to outbound HTTP headers.
///
/// Tool argument maps are never touched by this helper.
pub fn attach_authorization(
    headers: &mut http::HeaderMap,
    auth: &UpstreamAuthorization,
) -> Result<(), UpstreamAuthError> {
    let name = http::HeaderName::from_bytes(auth.header_name.as_bytes())
        .map_err(|_| UpstreamAuthError::InvalidHeader)?;
    let value = http::HeaderValue::from_str(&auth.header_value)
        .map_err(|_| UpstreamAuthError::InvalidHeader)?;
    headers.insert(name, value);
    Ok(())
}

/// Invariant helper: run-as-user must not inject identity into tool args.
pub fn assert_args_unmutated(before: &serde_json::Value, after: &serde_json::Value) -> bool {
    before == after
        && before
            .as_object()
            .map(|o| !o.contains_key("_sbproxy_run_as_user"))
            .unwrap_or(true)
}

/// Timeout for one token-exchange hop.
const TOKEN_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on the bytes read from a token endpoint's reply.
///
/// An RFC 8693 token response is a small JSON object. Reading it with
/// `bytes()` buffered whatever the endpoint chose to send, on a
/// connection opened because operator config named that host, so a
/// compromised or merely broken IdP could hand this process an
/// allocation bounded by nothing at all. 64 KiB is orders of magnitude
/// past any real response and small enough that the worst case is not
/// worth measuring.
const TOKEN_RESPONSE_MAX_BYTES: usize = 64 * 1024;

/// One cached exchanged credential.
///
/// `header_value` is [`Zeroizing`] so an LRU eviction, a replacement, or
/// a clear wipes the bearer material instead of leaving it in a freed
/// allocation for the rest of the process's life.
struct CachedToken {
    header_value: Zeroizing<String>,
    expires_at: Instant,
}

/// Entry ceiling for [`TOKEN_CACHE`] (WOR-2621).
///
/// A const rather than a config key on purpose. [`cache_key`] hashes
/// the caller's inbound bearer, so every rotation mints a distinct
/// entry; the map this replaced was a plain `HashMap` with no bound and
/// no deletion anywhere, which made a normal token-rotation cadence a
/// slow leak of `Bearer …` strings. What that needs is a bound, and
/// 4096 live exchanged credentials is well past any real working set. A
/// config key would drag in the config types, the compiler, schema
/// regeneration, and a number no operator has the information to pick.
const TOKEN_CACHE_CAPACITY: usize = 4096;

/// [`TOKEN_CACHE_CAPACITY`] in the shape `lru::LruCache::new` wants.
///
/// Written as a `const` match rather than an `unwrap` or an `expect` so
/// the branch that cannot happen is settled at compile time instead of
/// becoming a panic site on a credential path.
const TOKEN_CACHE_BOUND: NonZeroUsize = match NonZeroUsize::new(TOKEN_CACHE_CAPACITY) {
    Some(bound) => bound,
    None => NonZeroUsize::MIN,
};

/// How many expired rows one insert reclaims before it stores.
///
/// Bounded so a mint never pays for a scan of the whole map. The LRU
/// bound already caps memory; this only returns an expired credential's
/// bytes early rather than leaving it to sit until eviction pressure
/// happens to reach it.
const TOKEN_CACHE_SWEEP_PER_INSERT: usize = 16;

/// Bounded, self-expiring store for exchanged credentials.
///
/// Three properties the `HashMap` behind it had none of: a capacity, so
/// a rotating subject token cannot grow it without limit; removal of an
/// expired row on the read that finds it, rather than stepping over it
/// forever; and zeroized values, so eviction does not leave bearer
/// material behind.
///
/// `now` is a parameter on both methods rather than read inside, so a
/// test drives expiry deterministically without a clock trait.
struct TokenCache {
    entries: lru::LruCache<String, CachedToken>,
}

impl TokenCache {
    fn new() -> Self {
        Self {
            entries: lru::LruCache::new(TOKEN_CACHE_BOUND),
        }
    }

    /// The live credential for `key`, if there is one.
    fn get(&mut self, key: &str, now: Instant) -> Option<Zeroizing<String>> {
        let live = match self.entries.get(key) {
            Some(entry) if now < entry.expires_at => Some(entry.header_value.clone()),
            Some(_) => None,
            None => return None,
        };
        if live.is_none() {
            // Expired. Remove it rather than falling through: nothing in
            // this module ever deleted a row, so stepping over an
            // expired one is what let the map keep every credential it
            // had ever minted.
            self.entries.pop(key);
        }
        live
    }

    /// Store `header_value` under `key`, evicting as needed.
    fn insert(
        &mut self,
        key: String,
        header_value: Zeroizing<String>,
        expires_at: Instant,
        now: Instant,
    ) {
        self.sweep_expired(now);
        self.entries.put(
            key,
            CachedToken {
                header_value,
                expires_at,
            },
        );
    }

    /// Drop up to [`TOKEN_CACHE_SWEEP_PER_INSERT`] expired rows.
    ///
    /// `iter` walks most-recently-used first and does not promote what
    /// it touches, so a sweep cannot reorder the eviction queue it is
    /// walking. A full cache of live entries makes the walk cost
    /// [`TOKEN_CACHE_CAPACITY`] pointer hops and find nothing, which is
    /// the worst case and is fine: this runs once per cache miss, and a
    /// cache miss is already an HTTP round trip to an identity
    /// provider.
    fn sweep_expired(&mut self, now: Instant) {
        let stale: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| now >= entry.expires_at)
            .take(TOKEN_CACHE_SWEEP_PER_INSERT)
            .map(|(key, _)| key.clone())
            .collect();
        for key in stale {
            self.entries.pop(&key);
        }
    }
}

static TOKEN_CACHE: Lazy<Mutex<TokenCache>> = Lazy::new(|| Mutex::new(TokenCache::new()));

/// Identity of one cached exchanged credential (WOR-2619).
///
/// Every input that changes which credential a successful exchange
/// returns is in the digest, and the host supplies all of them. `tenant`
/// comes off `ctx.principal.tenant_id`, which the request pipeline
/// derived from the matched origin rather than from anything the caller
/// sent; no policy, script, or tool argument reaches this function, so
/// nothing a caller controls can widen a key past its own tenant.
///
/// What used to be missing was not academic. `scope` and
/// `client_credential_ref` are read only on a cache miss, so two
/// federated servers sharing a `token_endpoint` and `audience` and
/// differing only in `scope` produced one key: the first server's
/// `read` token was then served to the second server's `admin` request.
/// And because the tenant is decided by the origin the request matched,
/// not by the token, the same inbound bearer arriving at two origins
/// collided across tenants.
///
/// `v2` leads the digest so no pre-existing entry can be read back
/// under the new scheme. The `None`/`Some("")` discriminator matters
/// for the same reason the separators do: without it an absent scope
/// and an empty one hash alike, and the fields either side of an
/// unseparated boundary can be slid into each other.
fn cache_key(
    tenant: &str,
    endpoint: &str,
    audience: &str,
    scope: Option<&str>,
    client_credential_ref: Option<&str>,
    subject_id: &str,
    subject_token: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"v2");
    hasher.update([0]);
    // Tenant first, so a digest can never be read as another tenant's
    // however the fields after it happen to line up.
    hasher.update(tenant.as_bytes());
    hasher.update([0]);
    hasher.update(endpoint.as_bytes());
    hasher.update([0]);
    hasher.update(audience.as_bytes());
    hasher.update([0]);
    hash_optional(&mut hasher, canonical_scope(scope).as_deref());
    hash_optional(&mut hasher, client_credential_ref);
    // Subject id is mandatory for isolation: tokens for user A must
    // never be served to user B even when subject tokens collide.
    hasher.update(subject_id.as_bytes());
    hasher.update([0]);
    if let Some(t) = subject_token {
        hasher.update(Sha256::digest(t.as_bytes()));
    }
    hex::encode(hasher.finalize())
}

/// Feed one optional field, distinguishing absent from empty.
fn hash_optional(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.as_bytes());
        }
        None => hasher.update([2]),
    }
    hasher.update([0]);
}

/// An RFC 6749 scope is a set, not a string.
///
/// `"a b"` and `"b a"` request the same thing, so hashing the raw
/// string would mint and cache two credentials for one grant. Split on
/// whitespace, deduplicate, sort.
fn canonical_scope(scope: Option<&str>) -> Option<String> {
    let scope = scope?;
    let mut parts: Vec<&str> = scope.split_whitespace().collect();
    parts.sort_unstable();
    parts.dedup();
    Some(parts.join(" "))
}

/// Exchange the caller's subject token for an upstream credential.
///
/// The POST carries the caller's inbound bearer as a form field and, if
/// the operator configured one, a client secret in HTTP Basic. Both
/// travel on a dial that [`GovernedEgress`] authorized, pinned, and
/// will not redirect off its origin (WOR-2620). Before that loop
/// existed this function authorized the endpoint, threw away the pin
/// set, and handed the URL to a shared client that resolved the host
/// again and replayed the form body at whatever `Location` came back.
///
/// `resolver` is a parameter so a test can make the authorize-time and
/// dial-time answers disagree the way a rebinding DNS server does.
/// Production passes [`CachedSystemResolver`], which is the same
/// 30-second answer both calls read, so the pin check reports a real
/// change rather than a race between two lookups.
#[allow(clippy::too_many_arguments)] // mint needs exchange + subject + egress seams together
async fn mint_token_exchange(
    token_endpoint: &url::Url,
    audience: &str,
    scope: Option<&str>,
    client_credential_ref: Option<&str>,
    subject_id: &str,
    subject_token: Option<&str>,
    secret_lookup: &(dyn Fn(&str) -> Result<String, ()> + Sync),
    http: &reqwest::Client,
    egress: Option<&EgressAuthorizer>,
    tenant: &str,
    resolver: &dyn HostResolver,
) -> Result<UpstreamAuthorization, UpstreamAuthError> {
    let endpoint = token_endpoint.as_str();
    let endpoint_host = token_endpoint.host_str().unwrap_or("unset").to_string();

    // The cache read comes before authorization, deliberately. The
    // allowlist decides where this process may send a credential; it is
    // not a license check on one already minted. A hit dials nothing,
    // resolves nothing, and reaches no host, so there is no destination
    // for the gate to have an opinion about, and stamping a sighting
    // for it would put a row in `GET /api/egress` for a destination
    // that was not reached. Every miss goes through `GovernedEgress`
    // below, which authorizes and pins before the connect, so no
    // ungoverned dial is possible on either path.
    let key = cache_key(
        tenant,
        endpoint,
        audience,
        scope,
        client_credential_ref,
        subject_id,
        subject_token,
    );
    if let Ok(mut guard) = TOKEN_CACHE.lock() {
        if let Some(header_value) = guard.get(&key, Instant::now()) {
            return Ok(UpstreamAuthorization {
                header_name: "authorization".to_string(),
                header_value: header_value.to_string(),
            });
        }
    }

    let subject = subject_token.ok_or(UpstreamAuthError::TokenExchangeFailed)?;
    let mut form: Vec<(&str, &str)> = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", subject),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("audience", audience),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }

    let mut req = http.post(endpoint).form(&form);
    if let Some(client_ref) = client_credential_ref {
        let secret = secret_lookup(client_ref).map_err(|_| UpstreamAuthError::SecretLookup)?;
        req = req.basic_auth(client_ref, Some(secret));
    }

    let request = req
        .build()
        .map_err(|_| UpstreamAuthError::TokenExchangeFailed)?;

    let governed = GovernedEgress {
        purpose: EgressPurpose::TokenExchange,
        authorizer: egress,
        resolver,
        // Configuration-scoped: the token endpoint's host is operator
        // config, not a request-scoped value, and it is what an
        // operator reading a refusal needs to recognize.
        origin: &endpoint_host,
        tenant,
        // Nothing extra to declare. The client credential rides in
        // `Authorization`, which the loop always strips, and the
        // subject token is in the body, which is why a cross-origin hop
        // is refused outright rather than replayed without it.
        sensitive_headers: &[],
        max_response_bytes: TOKEN_RESPONSE_MAX_BYTES,
        no_redirect_client: http,
        timeout: TOKEN_EXCHANGE_TIMEOUT,
    };
    let response = governed.send(request).await.map_err(|error| match error {
        GovernedEgressError::Denied(_) => UpstreamAuthError::EgressDenied,
        // Everything else is a transport, ceiling, or client-construction
        // failure. None of them says anything about the caller, and the
        // closed reason is already on the egress log line, so the typed
        // error stays the one the caller can act on.
        _ => UpstreamAuthError::TokenExchangeFailed,
    })?;
    if !(200u16..300).contains(&response.status) {
        return Err(UpstreamAuthError::TokenExchangeFailed);
    }
    let parsed: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|_| UpstreamAuthError::TokenExchangeFailed)?;
    let token = parsed
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or(UpstreamAuthError::TokenExchangeFailed)?;
    let expires_in = parsed
        .get("expires_in")
        .and_then(|e| e.as_u64())
        .unwrap_or(60);
    let header_value = Zeroizing::new(format!("Bearer {token}"));

    if let Some(ttl) = expires_in.checked_sub(30).filter(|&s| s > 0) {
        if let Ok(mut guard) = TOKEN_CACHE.lock() {
            let now = Instant::now();
            guard.insert(
                key,
                header_value.clone(),
                now + Duration::from_secs(ttl),
                now,
            );
        }
    }

    Ok(UpstreamAuthorization {
        header_name: "authorization".to_string(),
        header_value: header_value.to_string(),
    })
}

/// Test-only: clear the process token cache between isolation tests.
#[cfg(test)]
pub fn clear_token_cache_for_tests() {
    if let Ok(mut guard) = TOKEN_CACHE.lock() {
        guard.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_plugin::{DelegationSubject, PrincipalAttrs, TenantId};
    use sbproxy_security::egress::{EgressConfig, PurposeAllowlist};
    use std::collections::HashMap as StdHashMap;

    fn identified_principal() -> Principal {
        Principal {
            tenant_id: TenantId::from("acme"),
            sub: "user-a".to_string(),
            source: PrincipalSource::Jwt,
            virtual_key: None,
            attrs: PrincipalAttrs::default(),
        }
    }

    fn ctx_for<'a>(
        principal: &'a Principal,
        delegation: Option<&'a DelegationSubject>,
    ) -> McpExecutionContext<'a> {
        McpExecutionContext {
            principal,
            request_id: "req-1",
            session_id: None,
            audit_cause: None,
            delegation,
        }
    }

    fn lookup_ok(map: StdHashMap<String, String>) -> impl Fn(&str) -> Result<String, ()> + Sync {
        move |r: &str| map.get(r).cloned().ok_or(())
    }

    fn enforce_token_exchange(hosts: &[&str], ports: &[u16]) -> EgressAuthorizer {
        let mut allow = PurposeAllowlist::default();
        for h in hosts {
            allow.hosts.insert((*h).to_string());
        }
        allow.schemes.insert("https".to_string());
        allow.schemes.insert("http".to_string());
        for p in ports {
            allow.ports.insert(*p);
        }
        if ports.is_empty() {
            allow.ports.insert(443);
            allow.ports.insert(80);
        }
        // WOR-2165: the gate resolves for real now, and these tests point
        // at a loopback fixture. Under the old fixed synthetic pin every
        // host looked public; a live answer for 127.0.0.1 is private, so
        // the allowlist has to say so explicitly.
        allow.allow_private = true;
        let mut purposes = StdHashMap::new();
        purposes.insert(EgressPurpose::TokenExchange, allow);
        EgressAuthorizer::new(EgressConfig { purposes })
    }

    #[test]
    fn stdio_plus_run_as_user_is_config_error() {
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc".to_string(),
        };
        let err = validate_run_as_user_config(&cfg, McpTransportKind::Stdio)
            .expect_err("stdio + run-as-user must be a config error");
        assert_eq!(err, UpstreamAuthError::StdioRunAsUserUnsupported);
        assert!(!format!("{err}").contains("vault://"));
        assert!(!format!("{err:?}").contains("vault://"));
    }

    #[test]
    fn http_transport_accepts_run_as_user_config() {
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc".to_string(),
        };
        validate_run_as_user_config(&cfg, McpTransportKind::Http).expect("http ok");
        validate_run_as_user_config(&cfg, McpTransportKind::Sse).expect("sse ok");
    }

    #[tokio::test]
    async fn service_credential_passthrough_attaches_header_not_args() {
        let principal = identified_principal();
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc-token".to_string(),
        };
        let map = StdHashMap::from([("vault://svc-token".to_string(), "svc-secret".to_string())]);
        let lookup = lookup_ok(map);
        let http = reqwest::Client::new();
        let auth = mint_upstream_authorization(&cfg, &ctx, &lookup, &http, None, None)
            .await
            .expect("passthrough");
        assert_eq!(auth.header_name, "authorization");
        assert_eq!(auth.header_value, "Bearer svc-secret");

        let mut headers = http::HeaderMap::new();
        attach_authorization(&mut headers, &auth).expect("attach");
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer svc-secret")
        );

        let before = serde_json::json!({"query": "hello"});
        let after = before.clone();
        assert!(assert_args_unmutated(&before, &after));
        assert!(before
            .as_object()
            .unwrap()
            .get("_sbproxy_run_as_user")
            .is_none());
    }

    #[tokio::test]
    async fn per_user_credential_resolves_subject_template() {
        let principal = identified_principal();
        let delegation = DelegationSubject {
            subject_id: "user-42".to_string(),
            subject_type: "user".to_string(),
        };
        let ctx = ctx_for(&principal, Some(&delegation));
        let cfg = McpUpstreamAuthConfig::PerUserCredential {
            credential_template: "vault://users/{subject_id}/token".to_string(),
        };
        let map = StdHashMap::from([(
            "vault://users/user-42/token".to_string(),
            "user-42-secret".to_string(),
        )]);
        let lookup = lookup_ok(map);
        let http = reqwest::Client::new();
        let auth = mint_upstream_authorization(&cfg, &ctx, &lookup, &http, None, None)
            .await
            .expect("per-user");
        assert_eq!(auth.header_value, "Bearer user-42-secret");
    }

    #[tokio::test]
    async fn anonymous_caller_fails_closed() {
        let principal = Principal::anonymous();
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc".to_string(),
        };
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();
        let err = mint_upstream_authorization(&cfg, &ctx, &lookup, &http, None, None)
            .await
            .expect_err("anonymous must fail closed");
        assert_eq!(err, UpstreamAuthError::AnonymousCaller);
    }

    #[tokio::test]
    async fn shared_key_caller_fails_closed() {
        let principal = Principal {
            tenant_id: TenantId::from("acme"),
            sub: String::new(),
            source: PrincipalSource::ApiKey,
            virtual_key: None,
            attrs: PrincipalAttrs {
                key_id: Some("sk_abcd".to_string()),
                project: Some("platform".to_string()),
                ..PrincipalAttrs::default()
            },
        };
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc".to_string(),
        };
        let lookup = lookup_ok(StdHashMap::from([(
            "vault://svc".to_string(),
            "secret".to_string(),
        )]));
        let http = reqwest::Client::new();
        let err = mint_upstream_authorization(&cfg, &ctx, &lookup, &http, None, None)
            .await
            .expect_err("shared-key must fail closed");
        assert_eq!(err, UpstreamAuthError::SharedKeyCaller);
    }

    #[tokio::test]
    async fn mint_never_injects_run_as_user_into_tool_arguments() {
        let principal = identified_principal();
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::ServiceCredential {
            credential_ref: "vault://svc".to_string(),
        };
        let lookup = lookup_ok(StdHashMap::from([(
            "vault://svc".to_string(),
            "secret".to_string(),
        )]));
        let http = reqwest::Client::new();
        let mut args = serde_json::json!({"path": "/tmp"});
        let before = args.clone();
        let _auth = mint_upstream_authorization(&cfg, &ctx, &lookup, &http, None, None)
            .await
            .expect("mint");
        assert!(assert_args_unmutated(&before, &args));
        assert!(args
            .as_object_mut()
            .unwrap()
            .get("_sbproxy_run_as_user")
            .is_none());
    }

    #[tokio::test]
    async fn token_exchange_mints_via_egress_purpose() {
        clear_token_cache_for_tests();
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping token-exchange test: loopback bind denied: {err}");
                return;
            }
            Err(err) => panic!("bind failed: {err}"),
        };
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let body =
                    r#"{"access_token":"exchanged-xyz","token_type":"Bearer","expires_in":3600}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });

        let principal = identified_principal();
        let ctx = ctx_for(&principal, None);
        let endpoint = url::Url::parse(&format!("http://127.0.0.1:{port}/token")).unwrap();
        let cfg = McpUpstreamAuthConfig::TokenExchange {
            token_endpoint: endpoint,
            audience: "https://mcp.example".to_string(),
            scope: Some("tools".to_string()),
            client_credential_ref: None,
        };
        let egress = enforce_token_exchange(&["127.0.0.1"], &[port]);
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();
        let auth = mint_upstream_authorization(
            &cfg,
            &ctx,
            &lookup,
            &http,
            Some(&egress),
            Some("inbound-subject-token"),
        )
        .await
        .expect("exchange");
        assert_eq!(auth.header_value, "Bearer exchanged-xyz");
    }

    #[tokio::test]
    async fn token_exchange_egress_denies_unlisted_host() {
        clear_token_cache_for_tests();
        let principal = identified_principal();
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::TokenExchange {
            token_endpoint: url::Url::parse("https://evil.example/token").unwrap(),
            audience: "https://mcp.example".to_string(),
            scope: None,
            client_credential_ref: None,
        };
        let egress = enforce_token_exchange(&["idp.example.com"], &[443]);
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();
        let err = mint_upstream_authorization(
            &cfg,
            &ctx,
            &lookup,
            &http,
            Some(&egress),
            Some("inbound-subject-token"),
        )
        .await
        .expect_err("unlisted host");
        assert_eq!(err, UpstreamAuthError::EgressDenied);
        assert!(!format!("{err}").contains("evil.example"));
        assert!(!format!("{err:?}").contains("evil.example"));
    }

    #[tokio::test]
    async fn token_cache_isolates_users() {
        clear_token_cache_for_tests();
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping cache isolation test: loopback bind denied: {err}");
                return;
            }
            Err(err) => panic!("bind failed: {err}"),
        };
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for token in ["token-for-a", "token-for-b"] {
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

        let endpoint = url::Url::parse(&format!("http://127.0.0.1:{port}/token")).unwrap();
        let cfg = McpUpstreamAuthConfig::TokenExchange {
            token_endpoint: endpoint,
            audience: "https://mcp.example".to_string(),
            scope: None,
            client_credential_ref: None,
        };
        let egress = enforce_token_exchange(&["127.0.0.1"], &[port]);
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();

        let principal_a = Principal {
            tenant_id: TenantId::from("acme"),
            sub: "user-a".to_string(),
            source: PrincipalSource::Jwt,
            virtual_key: None,
            attrs: PrincipalAttrs::default(),
        };
        let principal_b = Principal {
            tenant_id: TenantId::from("acme"),
            sub: "user-b".to_string(),
            source: PrincipalSource::Jwt,
            virtual_key: None,
            attrs: PrincipalAttrs::default(),
        };
        let ctx_a = ctx_for(&principal_a, None);
        let ctx_b = ctx_for(&principal_b, None);
        let shared_subject_token = "shared-inbound-token";

        let auth_a = mint_upstream_authorization(
            &cfg,
            &ctx_a,
            &lookup,
            &http,
            Some(&egress),
            Some(shared_subject_token),
        )
        .await
        .expect("user a");
        let auth_b = mint_upstream_authorization(
            &cfg,
            &ctx_b,
            &lookup,
            &http,
            Some(&egress),
            Some(shared_subject_token),
        )
        .await
        .expect("user b");

        assert_eq!(auth_a.header_value, "Bearer token-for-a");
        assert_eq!(auth_b.header_value, "Bearer token-for-b");
        assert_ne!(
            auth_a.header_value, auth_b.header_value,
            "user A token must never be served to user B"
        );
    }

    #[test]
    fn errors_never_embed_secrets() {
        let errs = [
            UpstreamAuthError::AnonymousCaller,
            UpstreamAuthError::SharedKeyCaller,
            UpstreamAuthError::StdioRunAsUserUnsupported,
            UpstreamAuthError::MissingSubject,
            UpstreamAuthError::SecretLookup,
            UpstreamAuthError::TokenExchangeFailed,
            UpstreamAuthError::EgressDenied,
            UpstreamAuthError::InvalidHeader,
        ];
        for err in errs {
            let s = format!("{err}");
            let d = format!("{err:?}");
            assert!(!s.contains("Bearer"));
            assert!(!d.to_lowercase().contains("password"));
        }
    }

    /// One-shot loopback fixture serving `response` verbatim. The flag
    /// latches on connect and the string keeps whatever the request
    /// carried, so a test can prove a credential did not travel rather
    /// than only that a socket was quiet.
    fn dial_fixture(
        response: String,
    ) -> Option<(
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::sync::Arc<std::sync::Mutex<String>>,
    )> {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let addr = listener.local_addr().ok()?;
        let hit = std::sync::Arc::new(AtomicBool::new(false));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let hit_writer = std::sync::Arc::clone(&hit);
        let seen_writer = std::sync::Arc::clone(&seen);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                hit_writer.store(true, Ordering::SeqCst);
                let mut scratch = [0u8; 8192];
                let read = stream.read(&mut scratch).unwrap_or(0);
                if let Ok(mut slot) = seen_writer.lock() {
                    *slot = String::from_utf8_lossy(&scratch[..read]).to_string();
                }
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Some((addr, hit, seen))
    }

    /// A loopback fixture that answers `bodies` in order, one
    /// connection each, so a test can tell a cache hit from a fresh
    /// exchange by which token came back.
    fn issuer_fixture(bodies: Vec<String>) -> Option<u16> {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let port = listener.local_addr().ok()?.port();
        std::thread::spawn(move || {
            for body in bodies {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut scratch = [0u8; 8192];
                let _ = stream.read(&mut scratch);
                let _ = stream.write_all(ok_json(&body).as_bytes());
                let _ = stream.flush();
            }
        });
        Some(port)
    }

    fn token_body(token: &str) -> String {
        format!(r#"{{"access_token":"{token}","token_type":"Bearer","expires_in":3600}}"#)
    }

    /// A complete `200 OK` response carrying `body` as JSON.
    fn ok_json(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// A resolver that answers each call from a fixed sequence, so a
    /// test can make authorize time and dial time disagree the way a
    /// rebinding DNS server does.
    struct SequenceResolver {
        answers: std::sync::Mutex<Vec<Vec<std::net::SocketAddr>>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl HostResolver for SequenceResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<std::net::SocketAddr>, ()> {
            let index = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let answers = self.answers.lock().map_err(|_| ())?;
            answers
                .get(index)
                .or_else(|| answers.last())
                .cloned()
                .ok_or(())
        }
    }

    /// WOR-2620: the endpoint is authorized, its pin set is kept, and a
    /// dial-time answer outside that set refuses the exchange instead of
    /// being dialed.
    ///
    /// Red before the fix in the only way that matters: `mint_token_exchange`
    /// took `Ok(_)` from `authorize`, dropped the `pinned_addrs` it had
    /// just resolved, and POSTed through a shared client that looked the
    /// host up again, so the rebound address got the subject token.
    #[tokio::test]
    async fn token_exchange_never_dials_an_address_the_pin_set_excludes() {
        use std::sync::atomic::Ordering;
        clear_token_cache_for_tests();
        let Some((authorized, authorized_hit, _)) = dial_fixture(ok_json(&token_body("pinned")))
        else {
            return;
        };
        let Some((rebound, rebound_hit, rebound_seen)) =
            dial_fixture(ok_json(&token_body("stolen")))
        else {
            return;
        };

        // Authorization sees the allowed address; the dial-time
        // re-resolve answers with the other one.
        let resolver = SequenceResolver {
            answers: std::sync::Mutex::new(vec![vec![authorized], vec![rebound]]),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let egress = enforce_token_exchange(&["idp.test"], &[authorized.port()]);
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();
        let endpoint =
            url::Url::parse(&format!("http://idp.test:{}/token", authorized.port())).unwrap();

        let err = mint_token_exchange(
            &endpoint,
            "https://mcp.example",
            None,
            None,
            "user-a",
            Some("inbound-subject-token"),
            &lookup,
            &http,
            Some(&egress),
            "acme",
            &resolver,
        )
        .await
        .expect_err("a rebound answer must refuse the exchange");

        assert_eq!(err, UpstreamAuthError::EgressDenied);
        assert!(
            !rebound_hit.load(Ordering::SeqCst),
            "the rebound address must never be dialed"
        );
        assert!(
            !authorized_hit.load(Ordering::SeqCst),
            "nothing is dialed at all once the pin check fails"
        );
        assert!(
            !rebound_seen
                .lock()
                .expect("fixture lock")
                .contains("inbound-subject-token"),
            "the subject token must not reach an unpinned address"
        );
    }

    /// WOR-2620: the whole `mint_upstream_authorization` path refuses a
    /// cross-origin redirect rather than replaying the form body, and
    /// the target never sees the subject token.
    #[tokio::test]
    async fn token_exchange_refuses_a_cross_origin_redirect_hop() {
        use std::sync::atomic::Ordering;
        clear_token_cache_for_tests();
        // The IdP 307s the exchange at another origin. The subject token
        // is in the form body, which a 307 replays verbatim and no
        // client-side credential stripping would touch, so the hop must
        // be refused and the target never contacted.
        let Some((sink_addr, sink_hit, sink_seen)) = dial_fixture(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_string(),
        ) else {
            return;
        };
        let redirect = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{}/token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            sink_addr.port()
        );
        let Some((idp_addr, idp_hit, _)) = dial_fixture(redirect) else {
            return;
        };

        let principal = identified_principal();
        let ctx = ctx_for(&principal, None);
        let cfg = McpUpstreamAuthConfig::TokenExchange {
            token_endpoint: url::Url::parse(&format!("http://{idp_addr}/token")).unwrap(),
            audience: "https://mcp.example".to_string(),
            scope: None,
            client_credential_ref: None,
        };
        // Both origins on the allowlist. This is exactly the hop
        // `evaluate_hop` alone would follow, because with an authorizer
        // armed it treats the allowlist as the authority for a
        // cross-origin target; the credential rule is what refuses it.
        let egress = enforce_token_exchange(&["127.0.0.1"], &[idp_addr.port(), sink_addr.port()]);
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();

        let err = mint_upstream_authorization(
            &cfg,
            &ctx,
            &lookup,
            &http,
            Some(&egress),
            Some("user-secret-token"),
        )
        .await
        .expect_err("a cross-origin hop must be refused, not followed");
        assert_eq!(err, UpstreamAuthError::EgressDenied);
        assert!(
            idp_hit.load(Ordering::SeqCst),
            "the configured token endpoint must have served the redirect"
        );
        assert!(
            !sink_hit.load(Ordering::SeqCst),
            "the redirect target must never receive the subject token"
        );
        assert!(
            !sink_seen
                .lock()
                .expect("fixture lock")
                .contains("user-secret-token"),
            "the form body must not leave the authorized origin"
        );
    }

    /// WOR-2620: an identity provider that answers with an unbounded
    /// body does not get to size this process's allocation.
    #[tokio::test]
    async fn token_exchange_refuses_an_oversized_token_response() {
        clear_token_cache_for_tests();
        let payload = "x".repeat(TOKEN_RESPONSE_MAX_BYTES + 1);
        let Some((idp_addr, _, _)) = dial_fixture(ok_json(&payload)) else {
            return;
        };

        let egress = enforce_token_exchange(&["127.0.0.1"], &[idp_addr.port()]);
        let lookup = lookup_ok(StdHashMap::new());
        let http = reqwest::Client::new();
        let endpoint = url::Url::parse(&format!("http://{idp_addr}/token")).unwrap();

        let err = mint_token_exchange(
            &endpoint,
            "https://mcp.example",
            None,
            None,
            "user-a",
            Some("inbound-subject-token"),
            &lookup,
            &http,
            Some(&egress),
            "acme",
            &CachedSystemResolver,
        )
        .await
        .expect_err("a reply past the ceiling must not be buffered whole");
        assert_eq!(err, UpstreamAuthError::TokenExchangeFailed);
    }

    /// WOR-2619: scope, client credential reference, and tenant are all
    /// part of a cache entry's identity.
    ///
    /// Red before the fix three times over. `cache_key` hashed only
    /// endpoint, audience, subject id, and subject token, so two
    /// federated servers sharing an endpoint and audience and differing
    /// only in `scope` shared one entry; so did two differing only in
    /// `client_credential_ref`; and because the tenant comes from the
    /// matched origin rather than from the token, one inbound bearer
    /// arriving at two origins collided across tenants. Each of the
    /// three second mints below returned the first mint's token.
    #[tokio::test]
    async fn token_cache_isolates_scope_tenant_and_client() {
        clear_token_cache_for_tests();
        let Some(port) = issuer_fixture(vec![
            token_body("token-1"),
            token_body("token-2"),
            token_body("token-3"),
            token_body("token-4"),
        ]) else {
            return;
        };
        let endpoint = url::Url::parse(&format!("http://127.0.0.1:{port}/token")).unwrap();
        let egress = enforce_token_exchange(&["127.0.0.1"], &[port]);
        let lookup = lookup_ok(StdHashMap::from([(
            "vault://client".to_string(),
            "client-secret".to_string(),
        )]));
        let http = reqwest::Client::new();
        let subject = "shared-inbound-token";

        let base =
            |scope: Option<&str>, client: Option<&str>| McpUpstreamAuthConfig::TokenExchange {
                token_endpoint: endpoint.clone(),
                audience: "https://mcp.example".to_string(),
                scope: scope.map(str::to_string),
                client_credential_ref: client.map(str::to_string),
            };
        let acme = identified_principal();
        let ctx_acme = ctx_for(&acme, None);

        let read = mint_upstream_authorization(
            &base(Some("read"), None),
            &ctx_acme,
            &lookup,
            &http,
            Some(&egress),
            Some(subject),
        )
        .await
        .expect("scope read");
        let admin = mint_upstream_authorization(
            &base(Some("admin"), None),
            &ctx_acme,
            &lookup,
            &http,
            Some(&egress),
            Some(subject),
        )
        .await
        .expect("scope admin");
        assert_ne!(
            read.header_value, admin.header_value,
            "a `read` token must never be served to an `admin` request"
        );

        let with_client = mint_upstream_authorization(
            &base(Some("read"), Some("vault://client")),
            &ctx_acme,
            &lookup,
            &http,
            Some(&egress),
            Some(subject),
        )
        .await
        .expect("client credential");
        assert_ne!(
            read.header_value, with_client.header_value,
            "a token minted without client authentication must not be reused with it"
        );

        let other_tenant = Principal {
            tenant_id: TenantId::from("globex"),
            sub: "user-a".to_string(),
            source: PrincipalSource::Jwt,
            virtual_key: None,
            attrs: PrincipalAttrs::default(),
        };
        let ctx_globex = ctx_for(&other_tenant, None);
        let crossed = mint_upstream_authorization(
            &base(Some("read"), None),
            &ctx_globex,
            &lookup,
            &http,
            Some(&egress),
            Some(subject),
        )
        .await
        .expect("other tenant");
        assert_ne!(
            read.header_value, crossed.header_value,
            "one tenant's exchanged credential must never be served to another"
        );
    }

    /// A scope is a set: reordering it must not mint a second entry.
    #[test]
    fn cache_key_canonicalizes_scope_and_separates_absent_from_empty() {
        let key = |scope: Option<&str>| {
            cache_key(
                "acme",
                "https://idp.test/token",
                "https://mcp.example",
                scope,
                None,
                "user-a",
                Some("subject"),
            )
        };
        assert_eq!(key(Some("a b")), key(Some("b  a")));
        assert_eq!(key(Some("a b")), key(Some("a b a")));
        assert_ne!(
            key(None),
            key(Some("")),
            "an absent scope and an empty one are different requests"
        );
        assert_ne!(key(Some("read")), key(Some("admin")));
    }

    /// WOR-2621: the cache has a ceiling and an expired row leaves it.
    ///
    /// Red before the fix on both counts. The `HashMap` behind this grew
    /// past any capacity, because it had none, and an expired hit fell
    /// through to a fresh exchange without ever removing the row it had
    /// just found dead.
    #[test]
    fn token_cache_bounds_and_expires() {
        let mut cache = TokenCache::new();
        let now = Instant::now();
        let ttl = Duration::from_secs(60);
        for index in 0..=TOKEN_CACHE_CAPACITY {
            cache.insert(
                format!("key-{index}"),
                Zeroizing::new(format!("Bearer token-{index}")),
                now + ttl,
                now,
            );
        }
        assert!(
            cache.entries.len() <= TOKEN_CACHE_CAPACITY,
            "the cache grew past its ceiling: {}",
            cache.entries.len()
        );

        let live = format!("key-{TOKEN_CACHE_CAPACITY}");
        assert!(
            cache.get(&live, now).is_some(),
            "the most recent entry must still be served"
        );
        let after_expiry = now + ttl + Duration::from_secs(1);
        assert!(
            cache.get(&live, after_expiry).is_none(),
            "an expired entry must not be served"
        );
        assert!(
            cache.get(&live, now).is_none(),
            "an expired entry must be removed on the read that finds it, not stepped over"
        );
    }
}
