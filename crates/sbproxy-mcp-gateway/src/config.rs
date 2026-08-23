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
    /// DPoP is enabled in config but the broker has no externally
    /// visible base URL, so the proof's `htu` claim cannot be matched
    /// against the canonical /token URL.
    #[error(
        "DPoP is enabled (dpop_supported or dpop_require_nonce) but \
         neither external_base_url nor MCP_GATEWAY_BASE_URL is a canonical HTTP(S) origin; \
         refusing to boot. Set external_base_url to the broker's externally visible \
         origin without credentials, path, query, or fragment (e.g. https://broker.example) so DPoP htu validation \
         can compose the canonical token endpoint URL."
    )]
    DpopRequiresBaseUrl,
    /// Replay entries would expire while an otherwise fresh proof can
    /// still be accepted.
    #[error("dpop_jti_ttl_secs ({ttl}) is shorter than the required replay window ({minimum})")]
    DpopReplayWindowTooShort {
        /// Configured replay TTL.
        ttl: u64,
        /// Minimum safe replay TTL.
        minimum: u64,
    },
}

/// Run startup-time validation against the broker config and process
/// environment. Callers should run this before binding the listener
/// so misconfiguration fails fast rather than at first request. The
/// validator is conservative: it errors only on configurations that
/// would silently downgrade security at runtime.
///
/// Today the only enforced rule is the DPoP base-URL requirement
/// (WOR-47): when DPoP is advertised or required, the broker must
/// know its own canonical /token URL to validate the proof's `htu`
/// claim. The URL comes from `external_base_url`; the
/// `MCP_GATEWAY_BASE_URL` environment variable remains a backwards-
/// compatible override.
pub fn validate_startup(cfg: &McpGatewayConfig) -> Result<(), StartupConfigError> {
    if cfg.dpop_supported || cfg.dpop_require_nonce {
        let minimum = cfg.dpop_max_clock_skew_secs.saturating_mul(2);
        if cfg.dpop_jti_ttl_secs < minimum {
            return Err(StartupConfigError::DpopReplayWindowTooShort {
                ttl: cfg.dpop_jti_ttl_secs,
                minimum,
            });
        }
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
    Ok(())
}

// --- Defaults ---

/// Default refresh interval for the AS metadata document, in seconds.
/// 5 minutes balances freshness against load on the upstream.
pub const DEFAULT_METADATA_REFRESH_SECS: u64 = 300;

/// Maximum allowable staleness before fail-closed behaviour kicks in.
/// 1 hour leaves headroom for short upstream outages without grounding
/// the broker.
pub const DEFAULT_METADATA_MAX_STALENESS_SECS: u64 = 3600;

/// Default maximum size of a Client ID Metadata Document (4C).
/// 16 KiB is generous for the RFC 7591 + parecki-draft fields any
/// real client would publish, and keeps a single bad actor from
/// wedging the broker with a multi-megabyte JSON blob.
pub const DEFAULT_CIMD_MAX_DOC_BYTES: usize = 16 * 1024;

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpGatewayConfig {
    /// URL prefix the broker mounts under, for example `/mcp/oauth`.
    /// Used for log context and (in 4B.3) the metadata document; the
    /// router itself receives the prefix at construction time.
    pub base_path: String,

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
    /// Whether the broker recognises CIMD-shaped `client_id` values
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

    fn default_token_exchange_max_chain_depth() -> usize {
        DEFAULT_TOKEN_EXCHANGE_MAX_CHAIN_DEPTH
    }
}

impl Default for McpGatewayConfig {
    fn default() -> Self {
        Self {
            base_path: "/mcp/oauth".to_string(),
            external_base_url: String::new(),
            upstream_authorization_server_url: String::new(),
            upstream_redirect_uri: String::new(),
            upstream_metadata_url: None,
            resource_uri: String::new(),
            resource_uri_allowlist: Vec::new(),
            allowed_redirect_uris: Vec::new(),
            session_ttl_secs: 600,
            upstream_token_endpoint_url: String::new(),
            upstream_registration_endpoint_url: None,
            upstream_revocation_endpoint_url: None,
            upstream_introspection_endpoint_url: None,
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
    fn private_signing_material_is_redacted_from_debug() {
        let key = JwkKey::Pem {
            pem: "PRIVATE-PEM-SENTINEL".to_string(),
            alg: "ES256".to_string(),
            kid: Some("kid-1".to_string()),
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
}
