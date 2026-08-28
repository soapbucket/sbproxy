// Configuration for the MCP OAuth 2.1 broker.
//
// 4B.1 shipped the minimum the /authorize and /callback handlers need.
// 4B.2 extends this with upstream /token and dynamic-client-registration
// (RFC 7591) endpoints plus the five client-authentication methods. The
// `.well-known/oauth-authorization-server` discovery doc lands in 4B.3.

use serde::{Deserialize, Serialize};

// --- Startup validation ---

/// Errors a deployment can hit when validating an
/// [`McpGatewayConfig`] against the surrounding process environment
/// at startup.
#[derive(Debug, thiserror::Error)]
pub enum StartupConfigError {
    /// A `base_path` of `/` or empty would mount the broker's routes
    /// over every path on the origin, capturing traffic the operator
    /// meant for something else.
    #[error("MCP OAuth base_path must not be root or empty")]
    InvalidBrokerPath,
    /// Device approval cannot mint an access token without an
    /// operator-provided asymmetric broker key.
    #[error("device authorization requires broker_signing_key")]
    DeviceAuthorizationRequiresSigningKey,
    /// Metadata must not advertise a client-authentication method the
    /// broker cannot parse and forward at every applicable endpoint.
    #[error("unsupported token endpoint client authentication method: {0}")]
    UnsupportedClientAuthenticationMethod(String),
    /// DPoP is enabled in config but the broker has no externally
    /// visible base URL, so the proof's `htu` claim cannot be matched
    /// against the canonical /token URL.
    #[error(
        "DPoP is enabled (dpop_supported or dpop_require_nonce) but \
         neither external_base_url nor MCP_GATEWAY_BASE_URL is a canonical HTTP(S) origin; \
         refusing to boot. Set external_base_url to the broker's externally visible \
         origin without credentials, path, query, or fragment (e.g. https://broker.example). DPoP htu validation \
         composes the canonical token endpoint URL from it, and the device-code consent page compares the \
         browser's Origin header against it."
    )]
    DpopRequiresBaseUrl,
    /// The `/authorize` limiter admits more requests over one session
    /// lifetime than the session store can hold, so a stream of
    /// anonymous requests inside the rate limit still wedges every new
    /// authorization until the oldest entries expire.
    #[error(
        "authorize_requests_per_minute ({rate}) over session_ttl_secs ({ttl}) admits {admitted} \
         sessions, more than the store holds ({capacity}); lower either key so their product \
         stays under the capacity, or the limiter does not protect the store it was added for"
    )]
    AuthorizeRateExceedsSessionCapacity {
        /// Sessions admitted over one full TTL at this rate.
        admitted: u64,
        /// What the store holds.
        capacity: u64,
        /// Configured rate.
        rate: u64,
        /// Configured session lifetime.
        ttl: u64,
    },
    /// Replay entries would expire while an otherwise fresh proof can
    /// still be accepted.
    #[error("dpop_jti_ttl_secs ({ttl}) is shorter than the required replay window ({minimum})")]
    DpopReplayWindowTooShort {
        /// Configured replay TTL.
        ttl: u64,
        /// Minimum safe replay TTL.
        minimum: u64,
    },
    /// A lifetime the broker builds a bounded store from was set to
    /// zero. Every row in such a store expires before the round trip
    /// that would read it, so the flow it backs can never complete.
    #[error("{field} must be greater than zero; a zero lifetime expires every entry before it can be read")]
    ZeroLifetime {
        /// Name of the configuration key that was set to zero.
        field: &'static str,
    },
    /// The broker mints tokens with a PEM signing key and publishes no
    /// public half, so `/.well-known/jwks.json` serves an empty key set
    /// while the AS metadata advertises that URL as the place to find
    /// the key. Every verifier that follows the discovery document,
    /// including this crate's own resource server, rejects every token
    /// the broker issues.
    #[error(
        "broker_signing_key is a PEM with no public_jwk, so {base_path}/.well-known/jwks.json \
         would serve an empty key set while AS metadata advertises it; set \
         broker_signing_key.public_jwk to the public half of the same key (same kid, same alg), \
         or supply the key as a JWK instead of a PEM"
    )]
    SigningKeyHasNoPublicHalf {
        /// The broker's configured base path, so the message names the
        /// endpoint that would be empty.
        base_path: String,
    },
}

/// Run startup-time validation against the broker config and process
/// environment. Callers should run this before binding the listener
/// so misconfiguration fails fast rather than at first request. The
/// validator is conservative: it errors only on configurations that
/// would silently downgrade security at runtime.
///
/// The validator rejects route capture, enabled flows with missing
/// signing collaborators, unsupported advertised client-auth methods,
/// and unsafe DPoP replay/base-URL settings before a listener binds.
pub fn validate_startup(cfg: &McpGatewayConfig) -> Result<(), StartupConfigError> {
    if cfg.base_path.is_empty() || cfg.base_path == "/" {
        return Err(StartupConfigError::InvalidBrokerPath);
    }
    if cfg.device_code_enabled && cfg.broker_signing_key.is_none() {
        return Err(StartupConfigError::DeviceAuthorizationRequiresSigningKey);
    }
    // A signing key with no publishable public half is a broker whose
    // own JWKS endpoint is empty. The metadata document advertises that
    // endpoint as soon as a signing key exists, so this is not a
    // colocated-only problem: any verifier that discovers the broker
    // finds no key at all.
    if let Some(JwkKey::Pem { public_jwk, .. }) = cfg.broker_signing_key.as_ref() {
        if public_jwk.is_none() {
            return Err(StartupConfigError::SigningKeyHasNoPublicHalf {
                base_path: cfg.base_path.clone(),
            });
        }
    }
    // A zero lifetime is refused here rather than clamped at the store,
    // because the store's floor keeps the process alive without telling
    // anyone the flow is dead. `cimd_cache_ttl_secs` is only judged when
    // CIMD is on: an operator who never enabled it should not have to
    // explain a key the broker never reads.
    if cfg.session_ttl_secs == 0 {
        return Err(StartupConfigError::ZeroLifetime {
            field: "session_ttl_secs",
        });
    }
    if cfg.cimd_enabled && cfg.cimd_cache_ttl_secs == 0 {
        return Err(StartupConfigError::ZeroLifetime {
            field: "cimd_cache_ttl_secs",
        });
    }
    const SUPPORTED_CLIENT_AUTH_METHODS: &[&str] = &[
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "none",
    ];
    if let Some(unsupported) = cfg
        .accepted_client_auth_methods
        .iter()
        .find(|method| !SUPPORTED_CLIENT_AUTH_METHODS.contains(&method.as_str()))
    {
        return Err(StartupConfigError::UnsupportedClientAuthenticationMethod(
            unsupported.clone(),
        ));
    }
    if cfg.dpop_supported || cfg.dpop_require_nonce {
        let minimum = cfg.dpop_max_clock_skew_secs.saturating_mul(2);
        if cfg.dpop_jti_ttl_secs < minimum {
            return Err(StartupConfigError::DpopReplayWindowTooShort {
                ttl: cfg.dpop_jti_ttl_secs,
                minimum,
            });
        }
    }
    // A canonical origin is needed by DPoP (to compose `htu`) and by
    // the device-code consent page (to compare against the browser's
    // `Origin`). It used to be checked only for DPoP, so
    // `device_code_enabled: true` with `dpop_supported: false` and no
    // base URL booted cleanly and then refused every consent POST as
    // cross-origin, because the expected origin was the relative path
    // `/mcp/oauth/verify` and `Url::parse` on it fails.
    if cfg.dpop_supported || cfg.dpop_require_nonce || cfg.device_code_enabled {
        let base = std::env::var("MCP_GATEWAY_BASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| cfg.external_base_url.clone());
        let valid = url::Url::parse(&base).ok().is_some_and(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.has_host()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none()
        });
        if !valid {
            return Err(StartupConfigError::DpopRequiresBaseUrl);
        }
    }
    // The pairing `authorize_requests_per_minute` documents. The
    // limiter and the store are separate keys, and only the pair is
    // safe: either alone can be reasonable while the product wedges
    // every new authorization for a full TTL.
    let admitted_per_ttl = cfg
        .authorize_requests_per_minute
        .saturating_mul(cfg.session_ttl_secs)
        / 60;
    let capacity = crate::session::DEFAULT_SESSION_CAPACITY as u64;
    if admitted_per_ttl > capacity {
        return Err(StartupConfigError::AuthorizeRateExceedsSessionCapacity {
            admitted: admitted_per_ttl,
            capacity,
            rate: cfg.authorize_requests_per_minute,
            ttl: cfg.session_ttl_secs,
        });
    }
    Ok(())
}

// --- Defaults ---

/// Default refresh interval for the AS metadata document, in seconds.
/// 5 minutes balances freshness against load on the upstream.
pub const DEFAULT_METADATA_REFRESH_SECS: u64 = 300;

/// Maximum allowable staleness before fail-closed behavior kicks in.
/// 1 hour leaves headroom for short upstream outages without grounding
/// the broker.
pub const DEFAULT_METADATA_MAX_STALENESS_SECS: u64 = 3600;

/// Default maximum size of a Client ID Metadata Document (4C).
/// 16 KiB is generous for the RFC 7591 + parecki-draft fields any
/// real client would publish, and keeps a single bad actor from
/// wedging the broker with a multi-megabyte JSON blob.
pub const DEFAULT_CIMD_MAX_DOC_BYTES: usize = 16 * 1024;

/// Maximum length of a URL-shaped `client_id` the broker will treat as
/// a CIMD identifier.
///
/// The `client_id` on `/authorize` is unauthenticated caller input, and
/// it becomes the cache key verbatim in
/// [`crate::cimd::EphemeralKvCimdCache`], so an unbounded value is an
/// unbounded key on the shared store.
///
/// The value is set by the tightest consumer rather than by the URL
/// ceiling. `LocalStore`'s key budget is 1024 bytes and the cache
/// prefixes the URL with `cimd:doc:`, so a 2048-byte bound was inert
/// on that backend: the store's own `KeyTooLarge` fired first, at
/// roughly 1015 bytes, and surfaced to the caller as "client_id
/// metadata document could not be resolved", which names the wrong
/// cause. 900 leaves headroom under the prefix and is still far past
/// any real client id.
///
/// Raising this means raising `LocalStore`'s key budget with it, or
/// the refusal moves back into the store and stops naming what is
/// wrong.
pub const MAX_CIMD_CLIENT_ID_LEN: usize = 900;

/// The cache-key prefix `MAX_CIMD_CLIENT_ID_LEN` has to leave room
/// for, plus a margin. Compile-time so the pair cannot drift.
const _: () = assert!(
    MAX_CIMD_CLIENT_ID_LEN + "cimd:doc:".len() < 1_024,
    "MAX_CIMD_CLIENT_ID_LEN plus the cimd:doc: prefix must fit LocalStore's 1024-byte key budget, \
     or an over-length client_id is refused by the store with a message naming the wrong cause"
);

/// Default TTL applied to a cached CIMD entry when the response has no
/// `Cache-Control: max-age` header. 1 hour matches the AS metadata
/// cache default; CIMD docs are expected to change rarely.
pub const DEFAULT_CIMD_CACHE_TTL_SECS: u64 = 3600;

/// Default maximum DPoP proof clock skew. RFC 9449 §11.1 recommends a
/// short window; 30 seconds matches well-known IdP defaults
/// (Curity, ForgeRock) and rejects the most common replay scenarios.
pub const DEFAULT_DPOP_MAX_CLOCK_SKEW_SECS: u64 = 30;

/// Default TTL the broker keeps a jti in the replay cache. Set to a
/// safe multiple of the clock-skew window so a proof can never be
/// replayed inside its acceptable freshness band.
pub const DEFAULT_DPOP_JTI_TTL_SECS: u64 = 300;

/// Default TTL applied to issued DPoP nonces. Matches the jti TTL; the
/// nonce binds the proof to a specific challenge round-trip.
pub const DEFAULT_DPOP_NONCE_TTL_SECS: u64 = 300;

/// Default lifetime for an in-flight device-code authorization (Wave
/// 4D.2). RFC 8628 recommends a value between 5 and 30 minutes; 10
/// minutes balances "user has time to walk to a browser" against
/// "abandoned codes do not pile up in the KV backend".
pub const DEFAULT_DEVICE_CODE_LIFETIME_SECS: u64 = 600;

/// Default polling interval the broker advertises in the
/// /device_authorization response. Clients MUST wait at least this
/// many seconds between /token polls.
pub const DEFAULT_DEVICE_CODE_POLLING_INTERVAL_SECS: u64 = 5;

/// Maximum local denylist retention for one validated broker token.
pub const DEFAULT_REVOCATION_MAX_TTL_SECS: u64 = 24 * 60 * 60;
/// Per-runtime bounded denylist capacity.
pub const DEFAULT_REVOCATION_MAX_ENTRIES: usize = 4_096;
/// Per-runtime revocation request budget in one minute.
pub const DEFAULT_REVOCATION_REQUESTS_PER_MINUTE: u64 = 120;

/// Default `/authorize` and `/par` admission rate, per minute, per
/// runtime.
///
/// Chosen against the session store rather than against traffic: 300
/// per minute times the 600-second default session TTL is 3000 live
/// rows, below the store's 4096 capacity, so a stream of anonymous
/// requests inside the limit cannot reach the capacity refusal. Five
/// authorization starts a second is far above what a real MCP
/// deployment does.
pub const DEFAULT_AUTHORIZE_REQUESTS_PER_MINUTE: u64 = 300;

/// Default chain depth limit for nested `act` claims emitted by token
/// exchange. Five hops covers every realistic delegation chain
/// (client to broker to upstream to downstream to data layer) without
/// inviting unbounded recursion.
pub const DEFAULT_TOKEN_EXCHANGE_MAX_CHAIN_DEPTH: usize = 5;

/// Algorithms the broker advertises in
/// `dpop_signing_alg_values_supported`. Mirrors the asymmetric
/// allow-list inside `dpop::is_alg_allowed`.
pub fn default_dpop_signing_algs() -> Vec<String> {
    vec![
        "ES256".to_string(),
        "ES384".to_string(),
        "PS256".to_string(),
        "PS384".to_string(),
        "PS512".to_string(),
        "EdDSA".to_string(),
    ]
}

/// Returns the default acceptable client-authentication methods. We
/// accept everything except the rarely-used jwt-bearer family by
/// default so deployers can pick down rather than up.
pub fn default_accepted_client_auth_methods() -> Vec<String> {
    vec![
        "client_secret_basic".to_string(),
        "client_secret_post".to_string(),
        "client_secret_jwt".to_string(),
        "private_key_jwt".to_string(),
        "none".to_string(),
    ]
}

// --- Client JWT signing key ---

/// Material the broker uses when it has to sign a `client_assertion`
/// itself (for example, to authenticate to a downstream upstream when
/// the broker acts as a confidential client). 4B.2 does not yet emit
/// these; the field is present so `private_key_jwt` callers can
/// pre-register the public side and the broker holds the matching
/// private side. The variants are kept structural rather than tagged
/// so deployers can paste either a PEM string or a JWK JSON document
/// straight from their AS console.
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JwkKey {
    /// PEM-encoded private key (RSA or EC).
    Pem {
        /// The raw PEM body, including BEGIN/END lines.
        pem: String,
        /// Algorithm to advertise in the JWS header (e.g. `RS256`,
        /// `ES256`).
        alg: String,
        /// Optional `kid` to publish in the JWS header.
        #[serde(default)]
        kid: Option<String>,
        /// Public JWK matching the private PEM. Required when this process
        /// must verify or publish its own broker-minted tokens.
        #[serde(default)]
        public_jwk: Option<serde_json::Value>,
    },
    /// Inline JWK JSON document. The raw value is kept as
    /// `serde_json::Value` so deployers can paste any JWK shape; the
    /// signer parses it lazily.
    Jwk {
        /// Raw JWK JSON. Must contain `kty` and the algorithm-specific
        /// key parameters per RFC 7517.
        jwk: serde_json::Value,
    },
}

impl std::fmt::Debug for JwkKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pem { alg, kid, .. } => f
                .debug_struct("Pem")
                .field("pem", &"[REDACTED]")
                .field("alg", alg)
                .field("kid", kid)
                .finish(),
            Self::Jwk { jwk } => {
                let kty = jwk.get("kty").and_then(serde_json::Value::as_str);
                let alg = jwk.get("alg").and_then(serde_json::Value::as_str);
                let kid = jwk.get("kid").and_then(serde_json::Value::as_str);
                f.debug_struct("Jwk")
                    .field("private_material", &"[REDACTED]")
                    .field("kty", &kty)
                    .field("alg", &alg)
                    .field("kid", &kid)
                    .finish()
            }
        }
    }
}

// --- Config ---

/// Broker-side configuration loaded from sb.yml or constructed in
/// tests. Fields are grouped by lifecycle: the first block is consulted
/// at /authorize time, the next block at /token and /register time,
/// and the last block by the AS metadata cache.
/// Unknown keys are refused. This struct is unusually security-flag
/// dense: a misspelled `dpop_require_nonce` would otherwise boot the
/// broker with the nonce challenge off and `validate_startup`'s DPoP
/// checks skipped, silently, and the operator would have no signal at
/// all that the flag they wrote is not the flag the broker read.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpGatewayConfig {
    /// URL prefix the broker mounts under, for example `/mcp/oauth`.
    /// Used for log context and (in 4B.3) the metadata document; the
    /// router itself receives the prefix at construction time.
    pub base_path: String,

    /// Development-only override permitting plaintext HTTP to literal or
    /// DNS-resolved loopback OAuth endpoints. It never permits private,
    /// link-local, or public HTTP destinations.
    #[serde(default)]
    pub allow_insecure_loopback: bool,

    /// Externally visible absolute origin for this in-process broker.
    /// Used to publish metadata and validate DPoP `htu`; the legacy
    /// `MCP_GATEWAY_BASE_URL` environment variable remains an override.
    #[serde(default)]
    pub external_base_url: String,

    /// Upstream Authorization Server URL. The broker redirects the
    /// user agent here after validating the inbound /authorize
    /// request. Stored as a string and parsed at request time so
    /// config loading does not depend on the URL crate's Result type.
    pub upstream_authorization_server_url: String,

    /// Absolute redirect URI registered with the upstream AS for the
    /// broker callback. This same value is sent on both authorization
    /// and authorization-code token requests; relative paths are
    /// rejected rather than relying on an AS-specific base URL.
    #[serde(default)]
    pub upstream_redirect_uri: String,

    /// RFC 8414 metadata document URL for the upstream AS. When set,
    /// the ordinary in-process router builds its metadata cache from
    /// this URL and RFC 9207 callback `iss` checks use the document's
    /// declared issuer.
    #[serde(default)]
    pub upstream_metadata_url: Option<String>,

    /// Resource indicator (RFC 8707) the broker requires every
    /// inbound /authorize request to carry. The broker forwards the
    /// value verbatim to the upstream AS.
    pub resource_uri: String,

    /// Optional allowlist of additional acceptable resource indicators
    /// (RFC 8707) the broker will accept on inbound /authorize and
    /// PAR-backed authorize requests. When empty (the default), the
    /// broker requires `resource` to exact-match `resource_uri`. When
    /// populated, the broker accepts `resource_uri` OR any value in
    /// this list. Mismatches return RFC 8707 §2 `invalid_target`.
    #[serde(default)]
    pub resource_uri_allowlist: Vec<String>,

    /// The scopes supported by this broker.
    #[serde(default)]
    pub scopes_supported: Vec<String>,

    /// Exact-match allowlist of client redirect URIs. RFC 6749
    /// §3.1.2.4 mandates exact matching for security; we never do
    /// prefix or pattern matching here.
    pub allowed_redirect_uris: Vec<String>,

    /// Time-to-live for an in-flight authorization session, in
    /// seconds. Defaults to 600 (10 minutes) when constructed via
    /// `Default`.
    pub session_ttl_secs: u64,

    // --- 4B.2 token endpoint ---
    /// Upstream token endpoint URL. The broker forwards
    /// authorization-code, refresh-token, and client-credentials
    /// grants here.
    #[serde(default)]
    pub upstream_token_endpoint_url: String,

    /// Upstream dynamic-client-registration (RFC 7591) endpoint URL.
    /// `None` disables /register entirely; the broker returns HTTP 501
    /// in that mode.
    #[serde(default)]
    pub upstream_registration_endpoint_url: Option<String>,

    /// Upstream OAuth 2.0 Token Revocation (RFC 7009) endpoint URL.
    /// `None` disables `/revoke` on the broker side; the endpoint
    /// returns HTTP 501. When set, the broker accepts /revoke,
    /// invalidates any cached state for the token, and forwards the
    /// revocation to the upstream.
    #[serde(default)]
    pub upstream_revocation_endpoint_url: Option<String>,

    /// Upstream OAuth 2.0 Token Introspection (RFC 7662) endpoint
    /// URL. `None` disables `/introspect` on the broker side
    /// (HTTP 501). When set, the broker forwards introspection
    /// requests to the upstream verbatim and proxies the response.
    /// The broker does not introspect tokens itself; the upstream
    /// is the source of truth.
    #[serde(default)]
    pub upstream_introspection_endpoint_url: Option<String>,

    /// Maximum number of validated local access tokens retained in this
    /// runtime's revocation denylist.
    #[serde(default = "McpGatewayConfig::default_revocation_max_entries")]
    pub revocation_max_entries: usize,

    /// Maximum denylist retention even when a token advertises a longer
    /// lifetime.
    #[serde(default = "McpGatewayConfig::default_revocation_max_ttl_secs")]
    pub revocation_max_ttl_secs: u64,

    /// Maximum revocation calls accepted by one runtime per minute.
    #[serde(default = "McpGatewayConfig::default_revocation_requests_per_minute")]
    pub revocation_requests_per_minute: u64,

    /// Maximum `/authorize` and `/par` requests one runtime admits per
    /// minute.
    ///
    /// This exists to keep the session store out of its capacity
    /// refusal. The store holds at most `session_ttl_secs` worth of
    /// admitted requests, so the steady-state ceiling is
    /// `authorize_requests_per_minute / 60 * session_ttl_secs`. At the
    /// defaults that is 3000 against a 4096-row store, which means no
    /// stream of anonymous requests inside the limit can wedge new
    /// authorizations.
    ///
    /// `validate_startup` refuses a pair that breaks it rather than
    /// leaving the arithmetic in this doc comment: raising
    /// `session_ttl_secs` to an hour at the default rate admits 18000
    /// per TTL against that store, which is the wedge the limiter was
    /// added to remove.
    #[serde(default = "McpGatewayConfig::default_authorize_requests_per_minute")]
    pub authorize_requests_per_minute: u64,

    /// RFC 9068 broker-signed access token signing key. When set,
    /// the broker mints access tokens it issues itself (e.g. on
    /// token-exchange paths) as JWTs with typ="at+jwt" using this
    /// key, and exposes the public half at `/.well-known/jwks.json`.
    /// When None the broker forwards upstream tokens unchanged.
    /// Re-signing of upstream-issued tokens is opt-in per the
    /// integration site. DPoP, mTLS, and token-exchange mutations
    /// require this key so the resulting claims are integrity bound.
    #[serde(default)]
    pub broker_signing_key: Option<JwkKey>,

    /// AS metadata refresh interval. Defaults to 5 minutes.
    #[serde(default = "McpGatewayConfig::default_metadata_refresh_secs")]
    pub metadata_refresh_secs: u64,

    /// Maximum allowable staleness before the broker fails closed.
    /// Defaults to 1 hour.
    #[serde(default = "McpGatewayConfig::default_metadata_max_staleness_secs")]
    pub max_metadata_staleness_secs: u64,

    /// Subset of `client_secret_basic`, `client_secret_post`,
    /// `client_secret_jwt`, `private_key_jwt`, `none`. The broker
    /// rejects /token requests authenticated with a method that is not
    /// in this list. Defaults to all five.
    #[serde(default = "default_accepted_client_auth_methods")]
    pub accepted_client_auth_methods: Vec<String>,

    /// Optional broker-held signing key for `client_secret_jwt` and
    /// `private_key_jwt`. Held even when the broker is not currently
    /// signing assertions, so operators can rotate the key in advance.
    #[serde(default)]
    pub client_jwt_signing_key: Option<JwkKey>,

    /// Selects the upstream registration shape the /register handler
    /// translates outbound metadata into. Accepted values: `rfc7591`
    /// (default, pass-through) and `auth0` (Auth0 v2 Management API).
    #[serde(default)]
    pub dcr_upstream_shape: Option<String>,

    // --- 4C: Client ID Metadata Documents (CIMD) ---
    /// Whether the broker recognizes CIMD-shaped `client_id` values
    /// (https URLs) at the /authorize and /token endpoints.
    /// Defaults to true; deployers locked to a server-side-registered
    /// client list can flip this off to fail closed on any URL-shaped
    /// client_id.
    #[serde(default = "McpGatewayConfig::default_cimd_enabled")]
    pub cimd_enabled: bool,

    /// Maximum size of a fetched CIMD JSON document, in bytes. Bodies
    /// larger than this are rejected before parsing.
    #[serde(default = "McpGatewayConfig::default_cimd_max_doc_bytes")]
    pub cimd_max_doc_bytes: usize,

    /// Default TTL applied to cached CIMD entries when the upstream
    /// response carries no explicit Cache-Control max-age directive.
    #[serde(default = "McpGatewayConfig::default_cimd_cache_ttl_secs")]
    pub cimd_cache_ttl_secs: u64,

    /// When true, the broker DCR-registers CIMD clients with the
    /// upstream Authorization Server on first use. This is for upstreams
    /// that speak RFC 7591 but not the parecki CIMD draft (Auth0,
    /// Okta, Keycloak). Off by default; only useful when the upstream
    /// AS does not understand a URL-shaped client_id natively.
    #[serde(default)]
    pub dcr_translate_cimd_clients: bool,

    // --- 4D.1: DPoP (RFC 9449) ---
    /// Whether the broker advertises DPoP support in its
    /// well-known/oauth-authorization-server document. Defaults to
    /// true; deployers that have no clients capable of minting DPoP
    /// proofs can flip this off so the metadata stays clean.
    #[serde(default = "McpGatewayConfig::default_dpop_supported")]
    pub dpop_supported: bool,

    /// When true, the broker rejects /token requests that arrive
    /// without a `DPoP-Nonce`-bound proof. The 401 response carries
    /// `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a fresh
    /// nonce in the `DPoP-Nonce` header so the client can retry.
    /// Defaults to false because some clients cannot easily handle
    /// the round-trip; flip on for high-assurance deployments.
    #[serde(default)]
    pub dpop_require_nonce: bool,

    /// Maximum acceptable skew between the proof's `iat` claim and the
    /// broker's wall clock, in seconds.
    #[serde(default = "McpGatewayConfig::default_dpop_max_clock_skew_secs")]
    pub dpop_max_clock_skew_secs: u64,

    /// Time-to-live for jti entries in the DPoP replay cache. Should
    /// be at least `2 * dpop_max_clock_skew_secs` so a proof cannot
    /// be replayed inside its freshness window.
    #[serde(default = "McpGatewayConfig::default_dpop_jti_ttl_secs")]
    pub dpop_jti_ttl_secs: u64,

    /// Time-to-live for issued DPoP nonces.
    #[serde(default = "McpGatewayConfig::default_dpop_nonce_ttl_secs")]
    pub dpop_nonce_ttl_secs: u64,

    // --- 4D.2: Device authorization grant (RFC 8628) ---
    /// Master switch for the RFC 8628 device-code grant. When false the
    /// `/device_authorization` and `/verify` routes return 404 and the
    /// /token endpoint rejects `urn:ietf:params:oauth:grant-type:device_code`
    /// with `unsupported_grant_type`.
    #[serde(default)]
    pub device_code_enabled: bool,

    /// How long an issued device_code remains valid before the /token
    /// poll returns `expired_token`. Defaults to 10 minutes.
    #[serde(default = "McpGatewayConfig::default_device_code_lifetime_secs")]
    pub device_code_lifetime_secs: u64,

    /// Minimum polling interval (in seconds) advertised in the
    /// /device_authorization response. Clients that poll faster trip
    /// the `slow_down` rate limiter, doubling their effective interval
    /// up to 60 seconds.
    #[serde(default = "McpGatewayConfig::default_device_code_polling_interval_secs")]
    pub device_code_polling_interval_secs: u64,

    /// Verification URI displayed to the end user. When empty the
    /// broker falls back to `<MCP_GATEWAY_BASE_URL><base_path>/verify`,
    /// derived from the same env knob the well-known doc reads.
    #[serde(default)]
    pub device_code_verification_uri: String,

    // --- 4D.2: Token exchange (RFC 8693) ---
    /// Master switch for the RFC 8693 token-exchange grant. When false
    /// the /token endpoint rejects
    /// `urn:ietf:params:oauth:grant-type:token-exchange` with
    /// `unsupported_grant_type`.
    #[serde(default)]
    pub token_exchange_enabled: bool,

    /// Maximum nested `act` chain depth. Tokens whose subject_token
    /// already carries an `act` chain at or above this depth are
    /// rejected with `invalid_request`. Defaults to 5.
    #[serde(default = "McpGatewayConfig::default_token_exchange_max_chain_depth")]
    pub token_exchange_max_chain_depth: usize,

    /// Allowlist of acceptable `iss` values on the inbound
    /// `subject_token`. Empty means "deny everything" so deployers
    /// must explicitly enroll an upstream issuer before exchange will
    /// work. Required by RFC 8693 §2.1: the AS MUST validate the
    /// subject token before honoring the exchange.
    #[serde(default)]
    pub subject_token_issuers: Vec<String>,

    /// Allowlist of acceptable `audience` values that callers can
    /// request when exchanging tokens. Empty means "deny everything";
    /// every audience must be enrolled. Prevents a compromised inbound
    /// token from being silently retargeted at an unrelated resource
    /// server.
    #[serde(default)]
    pub allowed_token_exchange_audiences: Vec<String>,
}

impl McpGatewayConfig {
    fn default_metadata_refresh_secs() -> u64 {
        DEFAULT_METADATA_REFRESH_SECS
    }

    fn default_metadata_max_staleness_secs() -> u64 {
        DEFAULT_METADATA_MAX_STALENESS_SECS
    }

    fn default_cimd_enabled() -> bool {
        true
    }

    fn default_cimd_max_doc_bytes() -> usize {
        DEFAULT_CIMD_MAX_DOC_BYTES
    }

    fn default_cimd_cache_ttl_secs() -> u64 {
        DEFAULT_CIMD_CACHE_TTL_SECS
    }

    fn default_dpop_supported() -> bool {
        true
    }

    fn default_dpop_max_clock_skew_secs() -> u64 {
        DEFAULT_DPOP_MAX_CLOCK_SKEW_SECS
    }

    fn default_dpop_jti_ttl_secs() -> u64 {
        DEFAULT_DPOP_JTI_TTL_SECS
    }

    fn default_dpop_nonce_ttl_secs() -> u64 {
        DEFAULT_DPOP_NONCE_TTL_SECS
    }

    fn default_device_code_lifetime_secs() -> u64 {
        DEFAULT_DEVICE_CODE_LIFETIME_SECS
    }

    fn default_device_code_polling_interval_secs() -> u64 {
        DEFAULT_DEVICE_CODE_POLLING_INTERVAL_SECS
    }

    fn default_revocation_max_entries() -> usize {
        DEFAULT_REVOCATION_MAX_ENTRIES
    }

    fn default_revocation_max_ttl_secs() -> u64 {
        DEFAULT_REVOCATION_MAX_TTL_SECS
    }

    fn default_revocation_requests_per_minute() -> u64 {
        DEFAULT_REVOCATION_REQUESTS_PER_MINUTE
    }

    fn default_authorize_requests_per_minute() -> u64 {
        DEFAULT_AUTHORIZE_REQUESTS_PER_MINUTE
    }

    fn default_token_exchange_max_chain_depth() -> usize {
        DEFAULT_TOKEN_EXCHANGE_MAX_CHAIN_DEPTH
    }
}

impl Default for McpGatewayConfig {
    fn default() -> Self {
        Self {
            base_path: "/mcp/oauth".to_string(),
            allow_insecure_loopback: false,
            external_base_url: String::new(),
            upstream_authorization_server_url: String::new(),
            upstream_redirect_uri: String::new(),
            upstream_metadata_url: None,
            resource_uri: String::new(),
            resource_uri_allowlist: Vec::new(),
            scopes_supported: Vec::new(),
            allowed_redirect_uris: Vec::new(),
            session_ttl_secs: 600,
            upstream_token_endpoint_url: String::new(),
            upstream_registration_endpoint_url: None,
            upstream_revocation_endpoint_url: None,
            upstream_introspection_endpoint_url: None,
            revocation_max_entries: DEFAULT_REVOCATION_MAX_ENTRIES,
            revocation_max_ttl_secs: DEFAULT_REVOCATION_MAX_TTL_SECS,
            revocation_requests_per_minute: DEFAULT_REVOCATION_REQUESTS_PER_MINUTE,
            authorize_requests_per_minute: DEFAULT_AUTHORIZE_REQUESTS_PER_MINUTE,
            metadata_refresh_secs: DEFAULT_METADATA_REFRESH_SECS,
            max_metadata_staleness_secs: DEFAULT_METADATA_MAX_STALENESS_SECS,
            accepted_client_auth_methods: default_accepted_client_auth_methods(),
            client_jwt_signing_key: None,
            broker_signing_key: None,
            dcr_upstream_shape: None,
            cimd_enabled: true,
            cimd_max_doc_bytes: DEFAULT_CIMD_MAX_DOC_BYTES,
            cimd_cache_ttl_secs: DEFAULT_CIMD_CACHE_TTL_SECS,
            dcr_translate_cimd_clients: false,
            dpop_supported: true,
            dpop_require_nonce: false,
            dpop_max_clock_skew_secs: DEFAULT_DPOP_MAX_CLOCK_SKEW_SECS,
            dpop_jti_ttl_secs: DEFAULT_DPOP_JTI_TTL_SECS,
            dpop_nonce_ttl_secs: DEFAULT_DPOP_NONCE_TTL_SECS,
            device_code_enabled: false,
            device_code_lifetime_secs: DEFAULT_DEVICE_CODE_LIFETIME_SECS,
            device_code_polling_interval_secs: DEFAULT_DEVICE_CODE_POLLING_INTERVAL_SECS,
            device_code_verification_uri: String::new(),
            token_exchange_enabled: false,
            token_exchange_max_chain_depth: DEFAULT_TOKEN_EXCHANGE_MAX_CHAIN_DEPTH,
            subject_token_issuers: Vec::new(),
            allowed_token_exchange_audiences: Vec::new(),
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_metadata_defaults() {
        let cfg = McpGatewayConfig::default();
        assert_eq!(cfg.metadata_refresh_secs, DEFAULT_METADATA_REFRESH_SECS);
        assert_eq!(
            cfg.max_metadata_staleness_secs,
            DEFAULT_METADATA_MAX_STALENESS_SECS
        );
        assert_eq!(cfg.accepted_client_auth_methods.len(), 5);
        assert!(cfg.client_jwt_signing_key.is_none());
        assert!(cfg.dcr_upstream_shape.is_none());
    }

    #[test]
    fn validate_startup_rejects_root_and_empty_broker_paths() {
        for base_path in ["", "/"] {
            let cfg = McpGatewayConfig {
                base_path: base_path.to_string(),
                ..McpGatewayConfig::default()
            };
            assert!(matches!(
                validate_startup(&cfg),
                Err(StartupConfigError::InvalidBrokerPath)
            ));
        }
    }

    #[test]
    fn validate_startup_rejects_device_flow_without_a_signing_key() {
        let cfg = McpGatewayConfig {
            device_code_enabled: true,
            broker_signing_key: None,
            dpop_supported: false,
            dpop_require_nonce: false,
            ..McpGatewayConfig::default()
        };

        assert!(
            validate_startup(&cfg).is_err(),
            "a device flow that can never mint its token must fail at startup"
        );
    }

    #[test]
    fn validate_startup_rejects_unimplemented_client_auth_methods() {
        let cfg = McpGatewayConfig {
            accepted_client_auth_methods: vec!["not-a-real-oauth-auth-method".to_string()],
            dpop_supported: false,
            dpop_require_nonce: false,
            ..McpGatewayConfig::default()
        };

        assert!(
            validate_startup(&cfg).is_err(),
            "metadata must not advertise an auth method the broker cannot process"
        );
    }

    #[test]
    fn private_signing_material_is_redacted_from_debug() {
        let key = JwkKey::Pem {
            pem: "PRIVATE-PEM-SENTINEL".to_string(),
            alg: "ES256".to_string(),
            kid: Some("kid-1".to_string()),
            public_jwk: None,
        };
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("PRIVATE-PEM-SENTINEL"));
        assert!(rendered.contains("[REDACTED]"));

        let cfg = McpGatewayConfig {
            broker_signing_key: Some(key),
            ..McpGatewayConfig::default()
        };
        assert!(!format!("{cfg:?}").contains("PRIVATE-PEM-SENTINEL"));
    }

    #[test]
    fn deserialise_minimal_config_picks_defaults() {
        let yaml = r#"
            base_path: "/mcp"
            upstream_authorization_server_url: "https://idp.example.com/auth"
            resource_uri: "https://mcp.example/api"
            allowed_redirect_uris: ["https://client.example/cb"]
            session_ttl_secs: 600
        "#;
        // Use serde_json instead of serde_yaml to avoid an extra dep.
        // The shape is identical for our purposes.
        let json = serde_json::json!({
            "base_path": "/mcp",
            "upstream_authorization_server_url": "https://idp.example.com/auth",
            "resource_uri": "https://mcp.example/api",
            "allowed_redirect_uris": ["https://client.example/cb"],
            "session_ttl_secs": 600
        });
        let _ = yaml; // anchor for readers; we deserialise json.
        let cfg: McpGatewayConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.metadata_refresh_secs, DEFAULT_METADATA_REFRESH_SECS);
        assert_eq!(cfg.accepted_client_auth_methods.len(), 5);
    }

    #[test]
    fn jwk_key_pem_roundtrip() {
        let json = serde_json::json!({
            "pem": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
            "alg": "RS256",
            "kid": "key-1"
        });
        let key: JwkKey = serde_json::from_value(json).unwrap();
        match key {
            JwkKey::Pem { alg, kid, .. } => {
                assert_eq!(alg, "RS256");
                assert_eq!(kid.as_deref(), Some("key-1"));
            }
            _ => panic!("expected Pem variant"),
        }
    }

    #[test]
    fn jwk_key_jwk_variant_roundtrip() {
        let json = serde_json::json!({
            "jwk": {
                "kty": "RSA",
                "n": "abc",
                "e": "AQAB"
            }
        });
        let key: JwkKey = serde_json::from_value(json).unwrap();
        assert!(matches!(key, JwkKey::Jwk { .. }));
    }

    /// WOR-47: when DPoP is on and `MCP_GATEWAY_BASE_URL` is unset,
    /// startup MUST fail closed so the broker cannot accept proofs
    /// it has no canonical URL to validate.
    #[test]
    fn validate_startup_fails_when_dpop_on_and_base_url_missing() {
        let _env = crate::test_env::EnvVarGuard::set(&[("MCP_GATEWAY_BASE_URL", None)]);
        let cfg = McpGatewayConfig {
            dpop_supported: true,
            ..Default::default()
        };
        let err = validate_startup(&cfg).expect_err("startup should fail closed");
        assert!(matches!(err, StartupConfigError::DpopRequiresBaseUrl));
    }

    /// WOR-47: with `MCP_GATEWAY_BASE_URL` set, startup succeeds even
    /// when DPoP is fully enabled.
    #[test]
    fn validate_startup_succeeds_when_base_url_set() {
        let _env = crate::test_env::EnvVarGuard::set(&[(
            "MCP_GATEWAY_BASE_URL",
            Some("https://broker.example"),
        )]);
        let cfg = McpGatewayConfig {
            dpop_supported: true,
            dpop_require_nonce: true,
            ..Default::default()
        };
        validate_startup(&cfg).expect("base url present, validation should succeed");
    }

    #[test]
    fn validate_startup_accepts_the_single_process_config_base_url() {
        let _env = crate::test_env::EnvVarGuard::set(&[("MCP_GATEWAY_BASE_URL", None)]);
        let cfg = McpGatewayConfig {
            external_base_url: "https://broker.example".to_string(),
            dpop_supported: true,
            ..Default::default()
        };
        validate_startup(&cfg).expect("configured external base URL should be sufficient");
    }

    #[test]
    fn validate_startup_rejects_a_non_origin_or_credentialed_public_base_url() {
        let _env = crate::test_env::EnvVarGuard::set(&[("MCP_GATEWAY_BASE_URL", None)]);
        for external_base_url in [
            "https://broker.example/path",
            "https://broker.example?tenant=one",
            "https://user:secret@broker.example",
        ] {
            let cfg = McpGatewayConfig {
                external_base_url: external_base_url.to_string(),
                dpop_supported: true,
                ..Default::default()
            };
            assert!(validate_startup(&cfg).is_err(), "{external_base_url}");
        }
    }

    #[test]
    fn validate_startup_rejects_a_pem_signing_key_with_no_public_half() {
        // The documented colocated configuration walked into this: the
        // broker minted ES256 tokens, `/.well-known/jwks.json` served
        // `{"keys":[]}`, AS metadata advertised that URL anyway, and
        // every verifier that followed discovery rejected every token.
        let cfg = McpGatewayConfig {
            external_base_url: "https://broker.example".to_string(),
            broker_signing_key: Some(JwkKey::Pem {
                pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----".to_string(),
                alg: "ES256".to_string(),
                kid: Some("broker-2026-08".to_string()),
                public_jwk: None,
            }),
            ..Default::default()
        };
        let error = validate_startup(&cfg).unwrap_err();
        assert!(
            matches!(error, StartupConfigError::SigningKeyHasNoPublicHalf { .. }),
            "got {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains("public_jwk"),
            "the refusal must name the key to set: {message}"
        );
    }

    #[test]
    fn validate_startup_accepts_a_pem_signing_key_carrying_its_public_half() {
        let cfg = McpGatewayConfig {
            external_base_url: "https://broker.example".to_string(),
            broker_signing_key: Some(JwkKey::Pem {
                pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----".to_string(),
                alg: "ES256".to_string(),
                kid: Some("broker-2026-08".to_string()),
                public_jwk: Some(serde_json::json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "broker-2026-08",
                    "alg": "ES256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                })),
            }),
            ..Default::default()
        };
        validate_startup(&cfg).expect("a published public half is what the verifier needs");
    }

    #[test]
    fn a_misspelled_security_flag_is_refused_rather_than_silently_ignored() {
        // `deny_unknown_fields`: without it, `dpop_require_nonces` (note
        // the s) booted the broker with the nonce challenge off.
        let json = serde_json::json!({
            "resource_uri": "https://mcp.example",
            "dpop_require_nonces": true
        });
        let error = serde_json::from_value::<McpGatewayConfig>(json)
            .expect_err("an unknown key must be refused");
        assert!(
            error.to_string().contains("dpop_require_nonces"),
            "the error must name the key: {error}"
        );
    }

    #[test]
    fn validate_startup_rejects_a_replay_ttl_shorter_than_the_proof_window() {
        let cfg = McpGatewayConfig {
            external_base_url: "https://broker.example".to_string(),
            dpop_supported: true,
            dpop_max_clock_skew_secs: 30,
            dpop_jti_ttl_secs: 59,
            ..Default::default()
        };
        let error = validate_startup(&cfg).unwrap_err();
        assert!(matches!(
            error,
            StartupConfigError::DpopReplayWindowTooShort {
                ttl: 59,
                minimum: 60
            }
        ));
    }

    /// A zero lifetime builds a store whose every row expires before
    /// the round trip that reads it, so the flow it backs can never
    /// complete. Startup refuses it instead of booting a broker that
    /// rejects every callback.
    #[test]
    fn validate_startup_rejects_a_zero_session_lifetime() {
        let cfg = McpGatewayConfig {
            session_ttl_secs: 0,
            dpop_supported: false,
            dpop_require_nonce: false,
            ..McpGatewayConfig::default()
        };
        assert!(matches!(
            validate_startup(&cfg),
            Err(StartupConfigError::ZeroLifetime {
                field: "session_ttl_secs"
            })
        ));
    }

    /// The CIMD cache lifetime is only judged when CIMD is enabled:
    /// an operator who never turned it on should not have to explain a
    /// key the broker never reads.
    #[test]
    fn validate_startup_rejects_a_zero_cimd_cache_lifetime_only_when_cimd_is_on() {
        let disabled = McpGatewayConfig {
            cimd_enabled: false,
            cimd_cache_ttl_secs: 0,
            dpop_supported: false,
            dpop_require_nonce: false,
            ..McpGatewayConfig::default()
        };
        validate_startup(&disabled).expect("a key CIMD never reads is not a startup failure");

        let enabled = McpGatewayConfig {
            cimd_enabled: true,
            cimd_cache_ttl_secs: 0,
            ..disabled
        };
        assert!(matches!(
            validate_startup(&enabled),
            Err(StartupConfigError::ZeroLifetime {
                field: "cimd_cache_ttl_secs"
            })
        ));
    }

    /// WOR-47: when DPoP is fully disabled in config, the missing env
    /// var is fine. Operators that do not need sender-constrained
    /// tokens should not be forced to set the base URL.
    #[test]
    fn validate_startup_ignores_base_url_when_dpop_off() {
        let _env = crate::test_env::EnvVarGuard::set(&[("MCP_GATEWAY_BASE_URL", None)]);
        let cfg = McpGatewayConfig {
            dpop_supported: false,
            dpop_require_nonce: false,
            ..Default::default()
        };
        validate_startup(&cfg).expect("DPoP off, validation should succeed");
    }

    /// Device code needs a canonical origin, and used to boot without
    /// one whenever DPoP was off.
    ///
    /// The consent POST compares the browser's `Origin` against the
    /// broker's own. With no base URL, `resolve_verification_uri`
    /// returns the relative `/mcp/oauth/verify`, `Url::parse` fails,
    /// and `verify_same_origin` returns false unconditionally, so every
    /// legitimate approval was a 403 on a config that validated clean.
    #[test]
    fn validate_startup_requires_a_base_url_when_device_code_is_enabled() {
        let cfg = McpGatewayConfig {
            external_base_url: String::new(),
            device_code_enabled: true,
            // The combination that used to slip through: the base-URL
            // check ran only under DPoP.
            dpop_supported: false,
            dpop_require_nonce: false,
            broker_signing_key: Some(JwkKey::Pem {
                pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----".to_string(),
                alg: "ES256".to_string(),
                kid: Some("broker-2026-08".to_string()),
                public_jwk: Some(serde_json::json!({
                    "kty": "EC", "crv": "P-256", "kid": "broker-2026-08",
                    "alg": "ES256", "use": "sig", "x": "a", "y": "b"
                })),
            }),
            ..McpGatewayConfig::default()
        };
        let err = validate_startup(&cfg).expect_err("device code with no base URL must be refused");
        assert!(
            matches!(err, StartupConfigError::DpopRequiresBaseUrl),
            "got {err:?}"
        );
    }

    /// The same config with a base URL is accepted, so the refusal is
    /// about the missing origin and not about device code itself.
    #[test]
    fn validate_startup_accepts_device_code_with_a_base_url() {
        let cfg = McpGatewayConfig {
            external_base_url: "https://broker.example".to_string(),
            device_code_enabled: true,
            dpop_supported: false,
            dpop_require_nonce: false,
            broker_signing_key: Some(JwkKey::Pem {
                pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----".to_string(),
                alg: "ES256".to_string(),
                kid: Some("broker-2026-08".to_string()),
                public_jwk: Some(serde_json::json!({
                    "kty": "EC", "crv": "P-256", "kid": "broker-2026-08",
                    "alg": "ES256", "use": "sig", "x": "a", "y": "b"
                })),
            }),
            ..McpGatewayConfig::default()
        };
        assert!(validate_startup(&cfg).is_ok(), "a base URL satisfies it");
    }

    /// The limiter and the store are separate keys and only the pair is
    /// safe. This was asserted for the two default constants and
    /// nowhere else, so an hour-long session TTL at the default rate
    /// reopened the wedge the limiter was added to close.
    #[test]
    fn validate_startup_rejects_a_rate_that_can_fill_the_session_store() {
        let cfg = McpGatewayConfig {
            external_base_url: "https://broker.example".to_string(),
            // 50/min over 3600s admits 3000... raise the TTL and it is
            // 18000 against a 4096-row store.
            session_ttl_secs: 3600,
            ..McpGatewayConfig::default()
        };
        let admitted = cfg.authorize_requests_per_minute.saturating_mul(3600) / 60;
        assert!(
            admitted > crate::session::DEFAULT_SESSION_CAPACITY as u64,
            "fixture must actually exceed the store, got {admitted}"
        );
        let err = validate_startup(&cfg).expect_err("the pairing must be refused");
        assert!(
            matches!(
                err,
                StartupConfigError::AuthorizeRateExceedsSessionCapacity { .. }
            ),
            "got {err:?}"
        );
    }

    /// The defaults are the pairing the doc comment describes, and they
    /// pass. Without this the test above would also pass on a build
    /// that refused everything.
    #[test]
    fn the_default_rate_and_session_lifetime_are_a_valid_pair() {
        let cfg = McpGatewayConfig {
            external_base_url: "https://broker.example".to_string(),
            ..McpGatewayConfig::default()
        };
        assert!(
            validate_startup(&cfg).is_ok(),
            "the shipped defaults must satisfy their own documented arithmetic"
        );
    }

    /// The CIMD client-id bound has to fit under the store's key budget
    /// once the cache prefix is prepended, or the refusal moves into
    /// the store and names the wrong cause. Asserted at compile time
    /// too; this is the message a reader gets.
    #[test]
    fn the_cimd_client_id_bound_fits_the_local_store_key_budget() {
        assert!(
            MAX_CIMD_CLIENT_ID_LEN + "cimd:doc:".len() < 1_024,
            "MAX_CIMD_CLIENT_ID_LEN ({MAX_CIMD_CLIENT_ID_LEN}) plus the cache prefix must fit \
             LocalStore's 1024-byte key budget"
        );
    }
}
