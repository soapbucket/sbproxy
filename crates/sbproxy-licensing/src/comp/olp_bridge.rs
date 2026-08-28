//! Redeem-time bridge into the OSS OLP license-token wire format.
//!
//! The CoMP redeem endpoint's whole job is "a buyer paid, hand them a
//! license token." Rather than mint a bespoke, disconnected token
//! format nothing else in the workspace understands, this module
//! reproduces the exact wire shape `crates/sbproxy-modules/src/olp.rs`
//! already ships (compact JWS, `alg=EdDSA`,
//! `typ="olp-license+jws"`, and the claim set documented on
//! [`OlpBridgeClaims`]). An operator points [`OlpBridgeSigner`] at the
//! *same* signing key their origin's `olp:` config block uses
//! (`signing_key` hex seed, `key_id`, `issuer`, `default_scope`,
//! `default_ttl_secs` all name-for-name match `OlpConfig`'s fields),
//! and a token minted here verifies against that origin's own
//! `POST /.well-known/olp/introspect` and is honored by anything else
//! in the deployment that already trusts OLP license tokens.
//!
//! This crate does not depend on `sbproxy-modules` to get that
//! compatibility. `sbproxy-modules` sits above the storage/protocol
//! layer in the dependency graph (only `sbproxy-core` and the
//! `sbproxy` binary depend on it; see `crates/sbproxy-billing/Cargo.toml`
//! for the same boundary spelled out for a sibling leaf crate), and a
//! license-minting bridge has no business pulling in the WAF,
//! transform, and callback machinery that lives there. Independently
//! reproducing a small, stable wire format is the cheaper and more
//! honest coupling.
//!
//! One claim from the OSS format is deliberately not reproduced here:
//! the WOR-808 PR8 `cnf.jwk` Encrypted Media Standard content-key
//! binding. A marketplace buyer redeeming a quote has not gone
//! through the origin's own EMS key-seed configuration, so there is
//! no content key to bind; a token from this bridge is a plain
//! license token, exactly as the OSS issuer emits when no
//! `content_key_seed` is configured.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::LicensingError;

/// JWS `typ` header value. Matches
/// `sbproxy_modules::olp::OLP_JWS_TYP` exactly so a token minted here
/// and one minted by the live proxy are wire-indistinguishable.
pub const OLP_JWS_TYP: &str = "olp-license+jws";

/// JWS protected header. Field set and order matches the OSS issuer's
/// internal `OlpHeader` (the header is not part of any public OSS
/// API; the shape is reproduced from the JSON it serialises to).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct OlpBridgeHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// Decoded JWS payload for a bridged OLP license token.
///
/// Field names and semantics match
/// `sbproxy_modules::olp::OlpLicenseClaims` exactly (`cnf` omitted;
/// see module docs). A verifier built against the OSS claims struct
/// deserialises this payload without modification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OlpBridgeClaims {
    /// Issuer URL. Matches `OlpConfig::issuer`.
    pub iss: String,
    /// Subject the license is issued to. This bridge derives it from
    /// the buyer's signing kid and legal-entity attestation (see
    /// [`super::marketplace::CompMarketplace::redeem`]).
    pub sub: String,
    /// Audience: the protected origin's hostname (the manifest
    /// publisher's domain).
    pub aud: String,
    /// Issued-at, unix seconds.
    pub iat: u64,
    /// Expiry, unix seconds.
    pub exp: u64,
    /// Space-separated RFC 8693 scope tokens. Always the bridge's
    /// configured `default_scope`; this crate has no per-tier scope
    /// override, matching how the OSS issuer's own
    /// `POST /.well-known/olp/token` handler mints today (it never
    /// sets `IssueRequest::scope_override` either).
    pub scope: String,
    /// URN of the RSL `/licenses.xml` document this license operates
    /// under (the tier's `license` field).
    pub license_urn: String,
    /// Unique token id (ULID).
    pub jti: String,
}

/// Mints OLP-wire-compatible license tokens for the CoMP redeem step.
///
/// Configuration mirrors `sbproxy_config::OlpConfig` field-for-field
/// on purpose: an operator who already runs the OSS `olp:` block on
/// the origin these tokens will be presented to can copy those same
/// four values in.
pub struct OlpBridgeSigner {
    signing_key: SigningKey,
    kid: String,
    issuer: String,
    default_scope: String,
    default_ttl_secs: u64,
}

impl std::fmt::Debug for OlpBridgeSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OlpBridgeSigner")
            .field("signing_key", &"<redacted>")
            .field("kid", &self.kid)
            .field("issuer", &self.issuer)
            .field("default_scope", &self.default_scope)
            .field("default_ttl_secs", &self.default_ttl_secs)
            .finish()
    }
}

impl OlpBridgeSigner {
    /// Build a signer from a raw 32-byte Ed25519 seed. `kid` should
    /// match the `key_id` the target origin's `olp:` config block
    /// advertises so a downstream introspector resolves the same key.
    pub fn new(
        seed: [u8; 32],
        kid: impl Into<String>,
        issuer: impl Into<String>,
        default_scope: impl Into<String>,
        default_ttl_secs: u64,
    ) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
            kid: kid.into(),
            issuer: issuer.into(),
            default_scope: default_scope.into(),
            default_ttl_secs,
        }
    }

    /// Build a signer from a hex-encoded 32-byte seed, the same
    /// encoding `OlpConfig::signing_key` uses.
    pub fn from_hex_seed(
        seed_hex: &str,
        kid: impl Into<String>,
        issuer: impl Into<String>,
        default_scope: impl Into<String>,
        default_ttl_secs: u64,
    ) -> Result<Self, LicensingError> {
        let bytes = hex::decode(seed_hex.trim())
            .map_err(|e| LicensingError::Encode(format!("olp bridge seed hex decode: {e}")))?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| LicensingError::Encode("olp bridge seed must be 32 bytes".into()))?;
        Ok(Self::new(
            seed,
            kid,
            issuer,
            default_scope,
            default_ttl_secs,
        ))
    }

    /// Mint a license token for `sub` bound to `aud` and
    /// `license_urn`, using the configured default scope and TTL.
    pub fn mint(&self, sub: &str, aud: &str, license_urn: &str) -> Result<String, LicensingError> {
        let now = unix_now();
        let claims = OlpBridgeClaims {
            iss: self.issuer.clone(),
            sub: sub.to_string(),
            aud: aud.to_string(),
            iat: now,
            exp: now.saturating_add(self.default_ttl_secs),
            scope: self.default_scope.clone(),
            license_urn: license_urn.to_string(),
            jti: ulid::Ulid::new().to_string(),
        };
        self.sign(&claims)
    }

    fn sign(&self, claims: &OlpBridgeClaims) -> Result<String, LicensingError> {
        let header = OlpBridgeHeader {
            alg: "EdDSA".into(),
            typ: OLP_JWS_TYP.into(),
            kid: self.kid.clone(),
        };
        let header_b64 = B64URL.encode(serde_json::to_vec(&header)?);
        let payload_b64 = B64URL.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = ed25519_dalek::Signer::sign(&self.signing_key, signing_input.as_bytes());
        let sig_b64 = B64URL.encode(signature.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn signer() -> OlpBridgeSigner {
        OlpBridgeSigner::new(
            [0x22u8; 32],
            "olp-2026-q2-001",
            "https://api.example.com",
            "ai-input",
            3600,
        )
    }

    #[test]
    fn mint_produces_three_segment_jws() {
        let s = signer();
        let token = s
            .mint("agent_acme", "api.example.com", "urn:rsl:x:default")
            .unwrap();
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn header_and_claims_round_trip() {
        let s = signer();
        let token = s
            .mint("agent_acme", "api.example.com", "urn:rsl:x:default")
            .unwrap();
        let mut parts = token.split('.');
        let header_b64 = parts.next().unwrap();
        let payload_b64 = parts.next().unwrap();
        let sig_b64 = parts.next().unwrap();

        let header: OlpBridgeHeader =
            serde_json::from_slice(&B64URL.decode(header_b64).unwrap()).unwrap();
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, OLP_JWS_TYP);
        assert_eq!(header.kid, "olp-2026-q2-001");

        let claims: OlpBridgeClaims =
            serde_json::from_slice(&B64URL.decode(payload_b64).unwrap()).unwrap();
        assert_eq!(claims.sub, "agent_acme");
        assert_eq!(claims.aud, "api.example.com");
        assert_eq!(claims.license_urn, "urn:rsl:x:default");
        assert_eq!(claims.scope, "ai-input");
        assert_eq!(claims.exp - claims.iat, 3600);

        // Signature verifies against the signer's own public key,
        // proving the signing input is exactly `header.payload`.
        let verifying = s.signing_key.verifying_key();
        let sig_bytes = B64URL.decode(sig_b64).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let signing_input = format!("{header_b64}.{payload_b64}");
        verifying
            .verify(signing_input.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn from_hex_seed_matches_raw_seed() {
        let hex_seed = "22".repeat(32);
        let s = OlpBridgeSigner::from_hex_seed(
            &hex_seed,
            "olp-2026-q2-001",
            "https://api.example.com",
            "ai-input",
            3600,
        )
        .unwrap();
        assert_eq!(s.signing_key.to_bytes(), [0x22u8; 32]);
    }

    #[test]
    fn from_hex_seed_rejects_wrong_length() {
        let err = OlpBridgeSigner::from_hex_seed(
            "aabb",
            "olp-2026-q2-001",
            "https://api.example.com",
            "ai-input",
            3600,
        )
        .unwrap_err();
        assert!(matches!(err, LicensingError::Encode(_)));
    }
}
