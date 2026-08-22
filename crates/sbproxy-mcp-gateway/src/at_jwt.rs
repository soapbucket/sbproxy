//! JWT Profile for OAuth 2.0 Access Tokens (RFC 9068).
//!
//! When the broker mints an access token it issues itself (e.g. on
//! the token-exchange path), the resulting JWT must follow the RFC
//! 9068 shape so any RFC 9068-aware resource server can validate it
//! by JWKS lookup alone, without out-of-band metadata.
//!
//! ## Header
//!
//! ```text
//! { "typ": "at+jwt", "alg": "<broker-signing-alg>", "kid": "<broker-key-id>" }
//! ```
//!
//! `typ="at+jwt"` is the load-bearing claim. RFC 9068 sec 2.1
//! mandates it so a verifier can distinguish access tokens from ID
//! tokens, refresh tokens, or other JWT shapes the same JWKS might
//! sign.
//!
//! ## Claims
//!
//! Required: iss, exp, aud, sub, client_id, iat, jti.
//! Optional: scope, auth_time, acr, amr, plus optional `act`
//! (delegation chain) per RFC 8693.
//!
//! ## Scope of this module
//!
//! Ships:
//! - [`AtJwtClaims`] struct.
//! - [`mint_at_jwt`] helper to sign claims with a configured key.
//! - [`broker_jwks`] helper to render the broker's public keys for
//!   the `/.well-known/jwks.json` endpoint.
//!
//! Does NOT ship (separate slice):
//! - The actual integration with `token_exchange.rs` so the broker
//!   re-signs upstream tokens. That flips a behavioral bit (today
//!   token_exchange preserves the upstream signature unchanged) and
//!   needs its own design discussion + e2e coverage.

use anyhow::{anyhow, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::config::JwkKey;

// --- Claim set ---

/// RFC 9068 access-token claim set. Fields appear in the JWT in the
/// order serde renders the struct; the order is informational only
/// because JWT verification happens by claim name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtJwtClaims {
    /// Issuer URL. Same value the broker advertises in AS metadata.
    pub iss: String,
    /// Subject. The end-user's stable identifier (typically the
    /// upstream `sub` claim) when an authorization code grant is in
    /// play; the client_id when the grant is client_credentials.
    pub sub: String,
    /// Audience. Single-value or array; we render whatever the
    /// caller passes through.
    pub aud: serde_json::Value,
    /// Expiry, seconds since UNIX epoch.
    pub exp: i64,
    /// Issued-at, seconds since UNIX epoch.
    pub iat: i64,
    /// JWT ID. Random 128-bit value, hex-encoded; required by RFC
    /// 9068 sec 2.2 to defeat replay across resource servers.
    pub jti: String,
    /// OAuth client_id. Required per RFC 9068 sec 2.2.
    pub client_id: String,
    /// Optional space-separated scope string. Skip on the wire when
    /// absent so resource servers that look for the field do not
    /// see an empty scope claim and reject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Optional auth_time (seconds since epoch when the user
    /// authenticated). Forwarded from the upstream when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Optional Authentication Context Class Reference per RFC 6711.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Optional Authentication Methods References array per RFC 8176.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Optional `act` envelope per RFC 8693 sec 4.1 for tokens
    /// produced by the token-exchange flow. The shape is open per
    /// the RFC; we round-trip whatever the caller passes through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<serde_json::Value>,

    // --- draft-oauth-transaction-tokens-for-agents-04 (WOR-521) ---
    //
    // The agent profile carries the agent + human identities and the
    // per-tool-call transaction binding directly on the token, so a
    // resource server can attribute a single intended action to both
    // the agent that drove it and the human it acted for. Minted only
    // when the exchange requests the agent-profile token type; absent
    // (and skipped on the wire) on classic access tokens.
    /// Agent identity: the OAuth client that drove the tool call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Human identity: the `sub` of the original user-authenticated
    /// token the agent is acting on behalf of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Transaction id the gateway assigns per tool call. Binds this
    /// token to one intended action so it cannot be replayed against a
    /// different call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tnx: Option<String>,
    /// Natural-language purpose of the call, truncated. Mirrors the
    /// prompt-linked audit envelope's intent capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// Max length of the [`AtJwtClaims::purpose`] claim, in characters.
/// Keeps the token compact and bounds what a caller-supplied purpose
/// string can do to token size.
pub const MAX_PURPOSE_CHARS: usize = 256;

/// Canonical `requested_token_type` URN for the agent-profile token
/// (draft-oauth-transaction-tokens-for-agents). A token-exchange
/// request naming this type gets the agent-profile claim set above.
pub const REQUESTED_TOKEN_TYPE_AGENT: &str = "urn:ietf:params:oauth:token-type:txn-token-agent";

// --- Sign ---

/// Sign `claims` with the broker's configured signing key, emitting
/// an RFC 9068 JWT (`typ="at+jwt"`). The header `alg` is read from
/// the [`JwkKey`]; the `kid` (when present) is included in the
/// header so verifiers can pick the right entry from the JWKS.
pub fn mint_at_jwt(claims: &AtJwtClaims, key: &JwkKey) -> Result<String> {
    let (encoding, alg, kid) = build_encoding_key(key)?;
    let mut header = Header::new(alg);
    header.typ = Some("at+jwt".to_string());
    header.kid = kid;
    encode(&header, claims, &encoding).map_err(|e| anyhow!("at+jwt sign failed: {e}"))
}

/// Truncate a purpose string to [`MAX_PURPOSE_CHARS`] characters on a
/// UTF-8 boundary (a naive byte slice would panic mid-codepoint).
pub fn truncate_purpose(s: &str) -> String {
    if s.chars().count() <= MAX_PURPOSE_CHARS {
        return s.to_string();
    }
    let end = s
        .char_indices()
        .nth(MAX_PURPOSE_CHARS)
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    s[..end].to_string()
}

impl AtJwtClaims {
    /// Stamp the draft-oauth-transaction-tokens-for-agents claim set:
    /// the agent (`actor`), the human (`principal`), the per-call
    /// transaction id (`tnx`), and the truncated `purpose`. Returns
    /// `self` for chaining at the mint site.
    pub fn with_agent_profile(
        mut self,
        actor: impl Into<String>,
        principal: impl Into<String>,
        tnx: impl Into<String>,
        purpose: Option<&str>,
    ) -> Self {
        self.actor = Some(actor.into());
        self.principal = Some(principal.into());
        self.tnx = Some(tnx.into());
        self.purpose = purpose.map(truncate_purpose);
        self
    }
}

/// Decode the broker's JwkKey config into a jsonwebtoken
/// EncodingKey + algorithm + optional kid. PEM-shaped keys parse
/// directly; JWK-shaped keys round-trip through the JWK -> PEM
/// conversion path that jsonwebtoken offers via from_jwk.
fn build_encoding_key(key: &JwkKey) -> Result<(EncodingKey, Algorithm, Option<String>)> {
    match key {
        JwkKey::Pem { pem, alg, kid } => {
            let algorithm = parse_alg(alg)?;
            let encoding = match algorithm {
                Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512 => EncodingKey::from_rsa_pem(pem.as_bytes())
                    .map_err(|e| anyhow!("rsa pem parse failed: {e}"))?,
                Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(pem.as_bytes())
                    .map_err(|e| anyhow!("ec pem parse failed: {e}"))?,
                Algorithm::EdDSA => EncodingKey::from_ed_pem(pem.as_bytes())
                    .map_err(|e| anyhow!("ed pem parse failed: {e}"))?,
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                    return Err(anyhow!("HS* algorithms cannot be PEM-encoded"))
                }
            };
            Ok((encoding, algorithm, kid.clone()))
        }
        JwkKey::Jwk { .. } => {
            // jsonwebtoken 9 does not expose a JWK -> EncodingKey
            // path. Operators with JWK-shaped private keys must
            // convert to PEM (e.g. via `jwk-to-pem` in node, or
            // `openssl ec -in jwk.json -out priv.pem` after a manual
            // EC parameter extraction) and use the JwkKey::Pem
            // variant. The /jwks.json endpoint can still serve a
            // JWK-shaped public document; only the private signing
            // path requires PEM.
            Err(anyhow!(
                "broker_signing_key as JWK is not supported in the signer; \
                 use JwkKey::Pem and publish the matching JWK separately"
            ))
        }
    }
}

fn parse_alg(s: &str) -> Result<Algorithm> {
    match s {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        other => Err(anyhow!("unsupported alg {other:?}")),
    }
}

// --- JWKS export ---

/// JWKS document shape for the `/.well-known/jwks.json` endpoint.
/// Renders just the public side of every configured signing key.
#[derive(Debug, Serialize)]
pub struct JwksDocument {
    /// Array of public JWKs. Empty when the broker has no signing
    /// key configured (the endpoint still serves an empty array
    /// rather than 404 so RFC 9068 verifiers do not retry forever).
    pub keys: Vec<serde_json::Value>,
}

/// Build the public JWKS for the broker. When the configured key is
/// PEM-shaped we cannot trivially convert it back to a JWK without
/// extra dependencies, so we emit an empty array and rely on the
/// operator to also publish a JWK-shaped key (or front the broker
/// with a JWKS host that does the conversion). When the configured
/// key is JWK-shaped we strip the private fields and emit the
/// public half.
pub fn broker_jwks(key: Option<&JwkKey>) -> JwksDocument {
    let Some(key) = key else {
        return JwksDocument { keys: vec![] };
    };
    match key {
        JwkKey::Pem { .. } => JwksDocument { keys: vec![] },
        JwkKey::Jwk { jwk } => {
            let public = strip_private_jwk_fields(jwk.clone());
            JwksDocument { keys: vec![public] }
        }
    }
}

/// Remove every private JWK parameter from `jwk`. Per RFC 7517 the
/// private parameters are: `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`,
/// and `k` (for symmetric keys). Anything else is public.
fn strip_private_jwk_fields(jwk: serde_json::Value) -> serde_json::Value {
    const PRIVATE_FIELDS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    let serde_json::Value::Object(mut map) = jwk else {
        return jwk;
    };
    for field in PRIVATE_FIELDS {
        map.remove(*field);
    }
    serde_json::Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_es256_pem() -> JwkKey {
        // Test-only ES256 private key. Generated for the existing
        // dpop module's test fixtures; reused here so we do not need
        // a fresh one. This is a public-test-vector key, never used
        // outside tests.
        const PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
-----END PRIVATE KEY-----";
        JwkKey::Pem {
            pem: PEM.to_string(),
            alg: "ES256".to_string(),
            kid: Some("test-key-1".to_string()),
        }
    }

    fn fixture_claims() -> AtJwtClaims {
        AtJwtClaims {
            iss: "https://broker.example".to_string(),
            sub: "user_42".to_string(),
            aud: serde_json::Value::String("https://api.example".to_string()),
            exp: 1_700_000_900,
            iat: 1_700_000_000,
            jti: "f47ac10b58cc4372a5670e02b2c3d479".to_string(),
            client_id: "client-abc".to_string(),
            scope: Some("read write".to_string()),
            auth_time: Some(1_699_999_900),
            acr: None,
            amr: Some(vec!["pwd".to_string()]),
            act: None,
            actor: None,
            principal: None,
            tnx: None,
            purpose: None,
        }
    }

    #[test]
    fn with_agent_profile_sets_and_truncates_claims() {
        let claims = fixture_claims().with_agent_profile(
            "agent-client",
            "user_42",
            "txn-abc",
            Some("a".repeat(MAX_PURPOSE_CHARS + 50).as_str()),
        );
        assert_eq!(claims.actor.as_deref(), Some("agent-client"));
        assert_eq!(claims.principal.as_deref(), Some("user_42"));
        assert_eq!(claims.tnx.as_deref(), Some("txn-abc"));
        // Purpose is truncated to the cap.
        assert_eq!(
            claims.purpose.as_ref().unwrap().chars().count(),
            MAX_PURPOSE_CHARS
        );
    }

    #[test]
    fn agent_profile_claims_skip_the_wire_when_absent() {
        // A classic token (no agent profile) must not emit empty
        // actor/principal/tnx/purpose claims.
        let json = serde_json::to_value(fixture_claims()).unwrap();
        assert!(json.get("actor").is_none());
        assert!(json.get("principal").is_none());
        assert!(json.get("tnx").is_none());
        assert!(json.get("purpose").is_none());
    }

    #[test]
    fn mint_at_jwt_emits_typ_at_jwt_header() {
        let key = fixture_es256_pem();
        let token = mint_at_jwt(&fixture_claims(), &key).expect("mint");

        // Parse the JWT header (first segment) and confirm typ is set.
        let header_b64 = token.split('.').next().unwrap();
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            header_b64,
        )
        .expect("base64 decode header");
        let header_json: serde_json::Value =
            serde_json::from_slice(&bytes).expect("json parse header");
        assert_eq!(header_json["typ"], "at+jwt");
        assert_eq!(header_json["alg"], "ES256");
        assert_eq!(header_json["kid"], "test-key-1");
    }

    #[test]
    fn mint_at_jwt_round_trips_claims() {
        let key = fixture_es256_pem();
        let claims = fixture_claims();
        let token = mint_at_jwt(&claims, &key).expect("mint");

        // Decode payload (no signature verification: we trust mint
        // worked because the test above pinned the header).
        let payload_b64 = token.split('.').nth(1).unwrap();
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload_b64,
        )
        .expect("base64 decode payload");
        let payload: serde_json::Value =
            serde_json::from_slice(&bytes).expect("json parse payload");
        assert_eq!(payload["iss"], "https://broker.example");
        assert_eq!(payload["sub"], "user_42");
        assert_eq!(payload["client_id"], "client-abc");
        assert_eq!(payload["scope"], "read write");
        assert_eq!(payload["jti"], "f47ac10b58cc4372a5670e02b2c3d479");
    }

    #[test]
    fn mint_at_jwt_omits_optional_scope_when_none() {
        let key = fixture_es256_pem();
        let mut claims = fixture_claims();
        claims.scope = None;
        claims.auth_time = None;
        claims.amr = None;
        let token = mint_at_jwt(&claims, &key).expect("mint");
        let payload_b64 = token.split('.').nth(1).unwrap();
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload_b64,
        )
        .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Required fields still present.
        assert!(payload["iss"].is_string());
        assert!(payload["client_id"].is_string());
        // Optional fields absent (skip_serializing_if).
        assert!(payload.get("scope").is_none());
        assert!(payload.get("auth_time").is_none());
        assert!(payload.get("amr").is_none());
        assert!(payload.get("act").is_none());
    }

    #[test]
    fn mint_at_jwt_supports_array_audience() {
        let key = fixture_es256_pem();
        let mut claims = fixture_claims();
        claims.aud = serde_json::json!(["https://api1.example", "https://api2.example"]);
        let token = mint_at_jwt(&claims, &key).expect("mint");
        let payload_b64 = token.split('.').nth(1).unwrap();
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload_b64,
        )
        .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(payload["aud"].is_array());
    }

    #[test]
    fn broker_jwks_empty_when_no_key() {
        let doc = broker_jwks(None);
        assert!(doc.keys.is_empty());
    }

    #[test]
    fn broker_jwks_empty_for_pem_key() {
        // PEM keys cannot trivially round-trip to JWK without extra
        // crypto work; we emit empty rather than half-render. The
        // alternative would be to require operators to also publish
        // a JWK-shaped key alongside the PEM private one.
        let doc = broker_jwks(Some(&fixture_es256_pem()));
        assert!(doc.keys.is_empty());
    }

    #[test]
    fn broker_jwks_strips_private_fields_from_jwk() {
        let key = JwkKey::Jwk {
            jwk: serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x",
                "y": "public-y",
                "d": "PRIVATE-MUST-NOT-LEAK",
                "kid": "k1",
                "alg": "ES256"
            }),
        };
        let doc = broker_jwks(Some(&key));
        assert_eq!(doc.keys.len(), 1);
        let k = &doc.keys[0];
        assert_eq!(k["kty"], "EC");
        assert_eq!(k["x"], "public-x");
        assert_eq!(k["y"], "public-y");
        assert!(
            k.get("d").is_none(),
            "private d field MUST be stripped: got {k}"
        );
    }

    #[test]
    fn broker_jwks_strips_rsa_private_fields() {
        let key = JwkKey::Jwk {
            jwk: serde_json::json!({
                "kty": "RSA",
                "n": "public-n",
                "e": "AQAB",
                "d": "private-d",
                "p": "private-p",
                "q": "private-q",
                "dp": "private-dp",
                "dq": "private-dq",
                "qi": "private-qi"
            }),
        };
        let doc = broker_jwks(Some(&key));
        let k = &doc.keys[0];
        assert_eq!(k["n"], "public-n");
        assert_eq!(k["e"], "AQAB");
        for private in &["d", "p", "q", "dp", "dq", "qi"] {
            assert!(
                k.get(*private).is_none(),
                "private RSA field {private} MUST be stripped"
            );
        }
    }

    #[test]
    fn broker_jwks_strips_symmetric_k() {
        let key = JwkKey::Jwk {
            jwk: serde_json::json!({"kty": "oct", "k": "PRIVATE-SYMMETRIC", "alg": "HS256"}),
        };
        let doc = broker_jwks(Some(&key));
        assert!(doc.keys[0].get("k").is_none());
    }
}
