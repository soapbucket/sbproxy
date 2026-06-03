// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! RFC 9449 outbound DPoP proof minting (WOR-1071).
//!
//! The companion to `auth::dpop` (inbound verifier). When the proxy
//! talks to an upstream that requires DPoP-bound access tokens, the
//! outbound HTTP client mints a fresh proof per request and attaches
//! it as the `DPoP:` header. The proof binds the request URL +
//! method + an optional server-issued nonce so a captured proof
//! cannot be reused against a different upstream call.
//!
//! ## What this module does
//!
//! 1. Load a DPoP signing key (PKCS#8 PEM) once per origin via
//!    `DpopSigner::from_pem`.
//! 2. Mint a fresh proof per call via `DpopSigner::mint_proof`:
//!    the header carries `alg`, `typ=dpop+jwt`, and the public JWK;
//!    the claims carry `jti` (UUIDv4), `htm` (method), `htu` (URI),
//!    `iat` (current epoch), and `nonce` when the upstream's last
//!    response carried a `DPoP-Nonce` header (RFC 9449 §8).
//! 3. Cache the signer per origin so the parsed key + the JWK
//!    serialisation are reused across requests.
//!
//! ## What this module does NOT do
//!
//! * Fetch the access token. The upstream credential resolver
//!   (`outbound_credential.rs`) drives the token-acquisition flow;
//!   this module signs the proof that travels alongside the token.
//! * Decide WHEN to mint. The credential resolver inspects the
//!   per-upstream config (`require_dpop: true`) and calls
//!   `mint_proof` only when the proof is required.
//! * Retry on a 401 `DPoP-Nonce` challenge. The HTTP layer that
//!   handles 401 retries threads the new nonce back into
//!   `mint_proof`'s `nonce` argument on the second attempt.

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors `DpopSigner::from_pem` can return when parsing the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopSignerError {
    /// The PEM did not decode as a supported private key shape.
    InvalidKeyFormat,
    /// The algorithm is not in the inbound verifier's allowlist.
    /// (We mirror the inbound allowlist exactly so a proxy that
    /// signs outbound proofs always produces something the same
    /// proxy could verify inbound.)
    AlgorithmNotAllowed {
        /// Algorithm name as configured.
        found: String,
    },
}

impl std::fmt::Display for DpopSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyFormat => f.write_str("DPoP signing key PEM did not parse"),
            Self::AlgorithmNotAllowed { found } => {
                write!(f, "algorithm `{found}` not in the DPoP allowlist")
            }
        }
    }
}

impl std::error::Error for DpopSignerError {}

/// Outbound DPoP signer. One signer per (origin, key) pair; the
/// upstream credential resolver caches a `DpopSigner` per upstream
/// so the parsed key + the JWK serialisation are reused across
/// requests.
pub struct DpopSigner {
    alg: Algorithm,
    key: EncodingKey,
    jwk: serde_json::Value,
}

impl DpopSigner {
    /// Build a signer from a PKCS#8 PEM + the matching JWK + the
    /// algorithm slug. The JWK is the public-key half; it ships in
    /// the proof's header and lets the upstream verify the proof
    /// without an out-of-band key fetch.
    ///
    /// Validates the algorithm against the same allowlist as the
    /// inbound verifier (ES256/ES384, RS256/RS384/RS512,
    /// PS256/PS384/PS512, EdDSA) so a proxy that signs outbound
    /// proofs always produces something the same proxy could verify
    /// inbound.
    pub fn from_pem(
        pem: &[u8],
        jwk: serde_json::Value,
        alg: &str,
    ) -> Result<Self, DpopSignerError> {
        let alg_parsed =
            alg.parse::<Algorithm>()
                .map_err(|_| DpopSignerError::AlgorithmNotAllowed {
                    found: alg.to_string(),
                })?;
        if !crate::auth::dpop_outbound::is_allowed(alg_parsed) {
            return Err(DpopSignerError::AlgorithmNotAllowed {
                found: alg.to_string(),
            });
        }
        let key = match alg_parsed {
            Algorithm::ES256 | Algorithm::ES384 => {
                EncodingKey::from_ec_pem(pem).map_err(|_| DpopSignerError::InvalidKeyFormat)?
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                EncodingKey::from_rsa_pem(pem).map_err(|_| DpopSignerError::InvalidKeyFormat)?
            }
            Algorithm::EdDSA => {
                EncodingKey::from_ed_pem(pem).map_err(|_| DpopSignerError::InvalidKeyFormat)?
            }
            _ => return Err(DpopSignerError::InvalidKeyFormat),
        };
        Ok(Self {
            alg: alg_parsed,
            key,
            jwk,
        })
    }

    /// Mint a fresh DPoP proof for the given `(method, url)` pair.
    /// Pass `nonce` only when the upstream's last response carried a
    /// `DPoP-Nonce` header per RFC 9449 §8. The proof's `iat` is the
    /// current Unix time; the `jti` is a fresh UUIDv4 so the inbound
    /// replay cache on the upstream cannot collide across calls.
    pub fn mint_proof(
        &self,
        method: &str,
        url: &str,
        nonce: Option<&str>,
    ) -> Result<String, DpopSignerError> {
        let mut header = Header::new(self.alg);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(
            serde_json::from_value(self.jwk.clone())
                .map_err(|_| DpopSignerError::InvalidKeyFormat)?,
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let jti = format!("dpop-{:016x}-{:016x}", now, rand::random::<u64>());
        let mut claims = serde_json::Map::new();
        claims.insert("jti".to_string(), serde_json::Value::String(jti));
        claims.insert(
            "htm".to_string(),
            serde_json::Value::String(method.to_ascii_uppercase()),
        );
        claims.insert(
            "htu".to_string(),
            serde_json::Value::String(url.to_string()),
        );
        claims.insert("iat".to_string(), serde_json::Value::Number(now.into()));
        if let Some(n) = nonce {
            claims.insert(
                "nonce".to_string(),
                serde_json::Value::String(n.to_string()),
            );
        }
        jsonwebtoken::encode(&header, &claims, &self.key)
            .map_err(|_| DpopSignerError::InvalidKeyFormat)
    }
}

/// Per-origin signer cache. The credential resolver registers one
/// signer per upstream at config-load time; the per-request mint
/// path looks the signer up by origin key.
#[derive(Default)]
pub struct DpopSignerCache {
    signers: Mutex<std::collections::HashMap<String, std::sync::Arc<DpopSigner>>>,
}

impl DpopSignerCache {
    /// Insert (or replace) the signer for a given origin key.
    pub fn install(&self, origin: impl Into<String>, signer: std::sync::Arc<DpopSigner>) {
        self.signers
            .lock()
            .expect("dpop signer cache mutex poisoned")
            .insert(origin.into(), signer);
    }

    /// Look up the signer for an origin. `None` when no signer was
    /// installed (the upstream does not require DPoP).
    pub fn get(&self, origin: &str) -> Option<std::sync::Arc<DpopSigner>> {
        self.signers
            .lock()
            .expect("dpop signer cache mutex poisoned")
            .get(origin)
            .cloned()
    }
}

/// Configuration for an outbound DPoP-bound credential. Mirrors the
/// proxy's existing outbound credential block shape so it slots in
/// under the same `outbound_credential:` config key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopOutboundConfig {
    /// PEM-encoded PKCS#8 private key the proxy signs proofs with.
    /// Resolved via the existing `vault://` URI scheme.
    pub key_pem: String,
    /// Public JWK matching `key_pem`. Ships in every minted proof's
    /// header so the upstream verifies without an out-of-band fetch.
    pub jwk: serde_json::Value,
    /// Algorithm slug: `ES256` / `ES384` / `RS256` / `RS384` /
    /// `RS512` / `PS256` / `PS384` / `PS512` / `EdDSA`.
    pub alg: String,
}

/// Mirror of the inbound verifier's allowlist. Kept in a private
/// module function so the two stay in lockstep: a proof we mint is
/// always a proof we would accept.
pub(crate) fn is_allowed(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::EdDSA
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::dpop::DpopVerifier;
    use std::time::SystemTime;

    /// Reuse the fixture PEM + JWK from the inbound DPoP test
    /// module so the outbound signer + inbound verifier can be
    /// exercised against each other (round-trip).
    const TEST_PRIVATE_KEY_PEM: &str = include_str!("dpop_test_ec_p256.pem");

    fn test_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4",
            "y": "bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc"
        })
    }

    fn test_jkt() -> String {
        // SHA-256 thumbprint per RFC 7638 of the test JWK. Pinned
        // once via `crate::auth::dpop::tests::test_jkt()`; computing
        // it here avoids a cross-module test dep on a `pub(crate)`
        // helper.
        let canonical = format!(
            r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#,
            crv = "P-256",
            x = "DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4",
            y = "bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc",
        );
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(canonical.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    #[test]
    fn mint_round_trip_through_inbound_verifier() {
        let signer = DpopSigner::from_pem(TEST_PRIVATE_KEY_PEM.as_bytes(), test_jwk(), "ES256")
            .expect("signer constructs");
        let proof = signer
            .mint_proof("POST", "https://api.example/resource", None)
            .expect("mint");

        let v = DpopVerifier::default();
        let result = v.verify(
            Some(&proof),
            "POST",
            "https://api.example/resource",
            &test_jkt(),
            SystemTime::now(),
        );
        assert!(
            result.is_ok(),
            "minted proof should round-trip through the inbound verifier: {result:?}"
        );
    }

    #[test]
    fn mint_with_nonce_carries_nonce_claim() {
        let signer = DpopSigner::from_pem(TEST_PRIVATE_KEY_PEM.as_bytes(), test_jwk(), "ES256")
            .expect("signer constructs");
        let proof = signer
            .mint_proof("GET", "https://api.example/n", Some("server-nonce-123"))
            .expect("mint");

        // Decode the proof's claims segment + assert the nonce is
        // present. We do not re-verify here; the round-trip test
        // covers the signature path.
        use base64::Engine;
        let segments: Vec<&str> = proof.split('.').collect();
        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[1])
            .expect("base64");
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).expect("json");
        assert_eq!(
            claims.get("nonce").and_then(|v| v.as_str()),
            Some("server-nonce-123")
        );
    }

    #[test]
    fn unsupported_algorithm_rejected_at_construction() {
        // `DpopSigner` does not implement Debug (it wraps a private
        // key); pattern match instead of `expect_err`.
        match DpopSigner::from_pem(TEST_PRIVATE_KEY_PEM.as_bytes(), test_jwk(), "HS256") {
            Err(DpopSignerError::AlgorithmNotAllowed { .. }) => {}
            other => panic!("HS256 must be rejected, got {:?}", other.err()),
        }
    }

    #[test]
    fn malformed_pem_rejected_at_construction() {
        match DpopSigner::from_pem(
            b"-----BEGIN NOT-A-KEY-----\n-----END NOT-A-KEY-----",
            test_jwk(),
            "ES256",
        ) {
            Err(DpopSignerError::InvalidKeyFormat) => {}
            other => panic!("garbage PEM must be rejected, got {:?}", other.err()),
        }
    }

    #[test]
    fn signer_cache_stores_and_retrieves() {
        let signer = std::sync::Arc::new(
            DpopSigner::from_pem(TEST_PRIVATE_KEY_PEM.as_bytes(), test_jwk(), "ES256")
                .expect("signer constructs"),
        );
        let cache = DpopSignerCache::default();
        cache.install("api.example", signer.clone());
        let pulled = cache.get("api.example").expect("retrieved");
        // Pointer identity: the cache returned the same Arc.
        assert!(std::sync::Arc::ptr_eq(&signer, &pulled));
        assert!(cache.get("unknown.example").is_none());
    }

    #[test]
    fn nonce_rotation_remints_correctly() {
        // Simulate the upstream returning a fresh DPoP-Nonce on
        // every 401: the second mint MUST carry the new nonce, not
        // the old one.
        let signer = DpopSigner::from_pem(TEST_PRIVATE_KEY_PEM.as_bytes(), test_jwk(), "ES256")
            .expect("signer constructs");
        let first = signer
            .mint_proof("GET", "https://api.example/r", Some("nonce-A"))
            .expect("first mint");
        let second = signer
            .mint_proof("GET", "https://api.example/r", Some("nonce-B"))
            .expect("second mint");

        use base64::Engine;
        for (proof, expected) in [(first, "nonce-A"), (second, "nonce-B")] {
            let segments: Vec<&str> = proof.split('.').collect();
            let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(segments[1])
                .unwrap();
            let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
            assert_eq!(claims.get("nonce").and_then(|v| v.as_str()), Some(expected));
        }
    }
}
