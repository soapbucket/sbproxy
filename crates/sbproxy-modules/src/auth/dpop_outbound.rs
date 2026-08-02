// SPDX-License-Identifier: Apache-2.0
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
//!    the claims carry a random 128-bit `jti`, `htm` (method), `htu` (URI),
//!    `iat` (current epoch), and `nonce` when the upstream's last
//!    response carried a `DPoP-Nonce` header (RFC 9449 §8).
//! 3. Reuse the parsed signer per origin while minting a new proof for
//!    every token and protected-resource attempt.
//!
//! Token acquisition and the bounded nonce retry loops are driven by
//! `outbound_credential.rs` and the Pingora resource-request seam.

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Deserialize;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_NONCE_BYTES: usize = 1024;

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
    /// The configured JWK is malformed, incompatible with the selected
    /// algorithm, or contains private key members.
    InvalidPublicJwk,
    /// The public JWK does not correspond to the configured private key.
    KeyPairMismatch,
    /// DPoP private keys must use the existing secret-reference surface.
    KeyReferenceRequired,
    /// A server nonce was empty, too large, or outside RFC 9449 syntax.
    InvalidNonce,
    /// A protected-resource target did not have an HTTP(S) origin.
    InvalidTargetUri,
    /// Internal nonce state could not be accessed.
    NonceStateUnavailable,
}

impl std::fmt::Display for DpopSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyFormat => f.write_str("DPoP signing key PEM did not parse"),
            Self::AlgorithmNotAllowed { found } => {
                write!(f, "algorithm `{found}` not in the DPoP allowlist")
            }
            Self::InvalidPublicJwk => {
                f.write_str("DPoP public JWK is malformed or contains private key material")
            }
            Self::KeyPairMismatch => {
                f.write_str("DPoP public JWK does not match the configured private key")
            }
            Self::KeyReferenceRequired => {
                f.write_str("DPoP signing key must be an existing secret reference")
            }
            Self::InvalidNonce => f.write_str("DPoP nonce is malformed"),
            Self::InvalidTargetUri => f.write_str("DPoP target URI is malformed"),
            Self::NonceStateUnavailable => f.write_str("DPoP nonce state is unavailable"),
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
        validate_public_jwk(&jwk, alg_parsed)?;
        let signer = Self {
            alg: alg_parsed,
            key,
            jwk,
        };
        signer.validate_key_pair()?;
        Ok(signer)
    }

    /// Mint a fresh DPoP proof for the given `(method, url)` pair.
    /// Pass `nonce` only when the upstream's last response carried a
    /// `DPoP-Nonce` header per RFC 9449 §8. The proof's `iat` is the
    /// current Unix time; the `jti` carries 128 fresh random bits so the inbound
    /// replay cache on the upstream cannot collide across calls.
    pub(crate) fn mint_proof(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
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
        let jti = format!(
            "{:016x}{:016x}",
            rand::random::<u64>(),
            rand::random::<u64>()
        );
        let mut claims = serde_json::Map::new();
        claims.insert("jti".to_string(), serde_json::Value::String(jti));
        claims.insert(
            "htm".to_string(),
            serde_json::Value::String(method.to_string()),
        );
        claims.insert(
            "htu".to_string(),
            serde_json::Value::String(url.to_string()),
        );
        claims.insert("iat".to_string(), serde_json::Value::Number(now.into()));
        if let Some(token) = access_token {
            use base64::Engine;
            use sha2::{Digest, Sha256};
            let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(token.as_bytes()));
            claims.insert("ath".to_string(), serde_json::Value::String(ath));
        }
        if let Some(n) = nonce {
            claims.insert(
                "nonce".to_string(),
                serde_json::Value::String(n.to_string()),
            );
        }
        jsonwebtoken::encode(&header, &claims, &self.key)
            .map_err(|_| DpopSignerError::InvalidKeyFormat)
    }

    fn validate_key_pair(&self) -> Result<(), DpopSignerError> {
        let jkt = crate::auth::dpop::jwk_thumbprint(&self.jwk)
            .ok_or(DpopSignerError::InvalidPublicJwk)?;
        let proof = self.mint_proof(
            "POST",
            "https://dpop-key-validation.invalid/token",
            None,
            None,
        )?;
        crate::auth::dpop::DpopVerifier::default()
            .verify(
                Some(&proof),
                "POST",
                "https://dpop-key-validation.invalid/token",
                &jkt,
                SystemTime::now(),
            )
            .map(|_| ())
            .map_err(|rejection| match rejection {
                crate::auth::dpop::DpopRejection::BadSignature => DpopSignerError::KeyPairMismatch,
                _ => DpopSignerError::InvalidPublicJwk,
            })
    }
}

fn validate_public_jwk(jwk: &serde_json::Value, alg: Algorithm) -> Result<(), DpopSignerError> {
    let object = jwk.as_object().ok_or(DpopSignerError::InvalidPublicJwk)?;
    const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| object.contains_key(*member))
    {
        return Err(DpopSignerError::InvalidPublicJwk);
    }
    let kty = object
        .get("kty")
        .and_then(serde_json::Value::as_str)
        .ok_or(DpopSignerError::InvalidPublicJwk)?;
    let compatible = match alg {
        Algorithm::ES256 => {
            kty == "EC" && object.get("crv").and_then(serde_json::Value::as_str) == Some("P-256")
        }
        Algorithm::ES384 => {
            kty == "EC" && object.get("crv").and_then(serde_json::Value::as_str) == Some("P-384")
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => kty == "RSA",
        Algorithm::EdDSA => {
            kty == "OKP" && object.get("crv").and_then(serde_json::Value::as_str) == Some("Ed25519")
        }
        _ => false,
    };
    if !compatible || crate::auth::dpop::jwk_thumbprint(jwk).is_none() {
        return Err(DpopSignerError::InvalidPublicJwk);
    }
    Ok(())
}

/// Check that a private key is named through the repository's existing
/// secret-reference surface. HTTP URLs and inline PEM are never accepted.
pub fn validate_key_reference(reference: &str) -> Result<(), DpopSignerError> {
    let reference = reference.trim();
    let file_reference = reference
        .strip_prefix("file:")
        .is_some_and(|path| !path.is_empty());
    if file_reference || sbproxy_vault::looks_like_secret_reference_uri(reference) {
        return Ok(());
    }
    Err(DpopSignerError::KeyReferenceRequired)
}

/// Validate the bounded RFC 9449 nonce syntax accepted from token and
/// protected-resource responses.
pub fn validate_nonce(nonce: &str) -> Result<(), DpopSignerError> {
    let valid = !nonce.is_empty()
        && nonce.len() <= MAX_NONCE_BYTES
        && nonce.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        });
    if valid {
        Ok(())
    } else {
        Err(DpopSignerError::InvalidNonce)
    }
}

/// Parsed per-origin DPoP key and nonce state.
///
/// Authorization-server and resource-server nonces intentionally occupy
/// different slots because RFC 9449 limits each nonce to its issuing server.
pub struct DpopRuntime {
    signer: DpopSigner,
    jkt: String,
    authorization_nonce: Mutex<Option<String>>,
    resource_nonces: Mutex<std::collections::HashMap<String, String>>,
}

impl std::fmt::Debug for DpopRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopRuntime")
            .field("jkt", &self.jkt)
            .field(
                "authorization_nonce",
                &self.authorization_nonce.lock().map(|n| n.is_some()),
            )
            .field(
                "resource_nonce_origins",
                &self.resource_nonces.lock().map(|nonces| nonces.len()),
            )
            .finish()
    }
}

impl DpopRuntime {
    /// Parse and validate one origin's configured signing key.
    pub fn new(pem: &[u8], jwk: serde_json::Value, alg: &str) -> Result<Self, DpopSignerError> {
        let signer = DpopSigner::from_pem(pem, jwk.clone(), alg)?;
        let jkt =
            crate::auth::dpop::jwk_thumbprint(&jwk).ok_or(DpopSignerError::InvalidPublicJwk)?;
        Ok(Self {
            signer,
            jkt,
            authorization_nonce: Mutex::new(None),
            resource_nonces: Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Non-secret stable identity used to partition the minted-token cache.
    pub fn key_thumbprint(&self) -> &str {
        &self.jkt
    }

    /// Mint a proof for the token endpoint without an `ath` claim.
    pub fn mint_token_proof(&self, method: &str, htu: &str) -> Result<String, DpopSignerError> {
        let nonce = self
            .authorization_nonce
            .lock()
            .map_err(|_| DpopSignerError::NonceStateUnavailable)?
            .clone();
        self.signer.mint_proof(method, htu, None, nonce.as_deref())
    }

    /// Mint a protected-resource proof bound to `access_token`.
    pub fn mint_resource_proof(
        &self,
        method: &str,
        htu: &str,
        access_token: &str,
    ) -> Result<String, DpopSignerError> {
        let nonce_key = resource_nonce_key(htu)?;
        let nonce = self
            .resource_nonces
            .lock()
            .map_err(|_| DpopSignerError::NonceStateUnavailable)?
            .get(&nonce_key)
            .cloned();
        self.signer
            .mint_proof(method, htu, Some(access_token), nonce.as_deref())
    }

    /// Replace the authorization-server nonce after validating its syntax.
    pub fn set_authorization_nonce(&self, nonce: &str) -> Result<(), DpopSignerError> {
        validate_nonce(nonce)?;
        *self
            .authorization_nonce
            .lock()
            .map_err(|_| DpopSignerError::NonceStateUnavailable)? = Some(nonce.to_string());
        Ok(())
    }

    /// Replace the resource-server nonce after validating its syntax.
    pub fn set_resource_nonce(&self, htu: &str, nonce: &str) -> Result<(), DpopSignerError> {
        validate_nonce(nonce)?;
        let nonce_key = resource_nonce_key(htu)?;
        let mut nonces = self
            .resource_nonces
            .lock()
            .map_err(|_| DpopSignerError::NonceStateUnavailable)?;
        if nonces.len() >= 128 && !nonces.contains_key(&nonce_key) {
            nonces.clear();
        }
        nonces.insert(nonce_key, nonce.to_string());
        Ok(())
    }
}

fn resource_nonce_key(htu: &str) -> Result<String, DpopSignerError> {
    let target = url::Url::parse(htu).map_err(|_| DpopSignerError::InvalidTargetUri)?;
    if !matches!(target.scheme(), "http" | "https") || target.host_str().is_none() {
        return Err(DpopSignerError::InvalidTargetUri);
    }
    Ok(target.origin().ascii_serialization())
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
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopOutboundConfig {
    /// Existing secret-provider or `file:` reference to a PKCS#8 PEM.
    pub key: String,
    /// Public JWK matching `key_pem`. Ships in every minted proof's
    /// header so the upstream verifies without an out-of-band fetch.
    pub jwk: serde_json::Value,
    /// Algorithm slug: `ES256` / `ES384` / `RS256` / `RS384` /
    /// `RS512` / `PS256` / `PS384` / `PS512` / `EdDSA`.
    pub alg: String,
    /// Parsed signer installed during runtime pipeline construction.
    #[serde(skip)]
    runtime: Option<Arc<DpopRuntime>>,
}

impl std::fmt::Debug for DpopOutboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopOutboundConfig")
            .field("key", &"[SECRET REFERENCE]")
            .field("alg", &self.alg)
            .field(
                "jkt",
                &crate::auth::dpop::jwk_thumbprint(&self.jwk).as_deref(),
            )
            .field("runtime", &self.runtime.is_some())
            .finish()
    }
}

impl DpopOutboundConfig {
    /// Validate reference and public-key fields without resolving the secret.
    pub fn validate(&self) -> Result<(), DpopSignerError> {
        validate_key_reference(&self.key)?;
        let alg =
            self.alg
                .parse::<Algorithm>()
                .map_err(|_| DpopSignerError::AlgorithmNotAllowed {
                    found: self.alg.clone(),
                })?;
        if !is_allowed(alg) {
            return Err(DpopSignerError::AlgorithmNotAllowed {
                found: self.alg.clone(),
            });
        }
        validate_public_jwk(&self.jwk, alg)
    }

    /// Install the resolved private key after boot-time secret resolution.
    pub fn install_resolved_key(&mut self, pem: &str) -> Result<(), DpopSignerError> {
        self.validate()?;
        self.runtime = Some(Arc::new(DpopRuntime::new(
            pem.as_bytes(),
            self.jwk.clone(),
            &self.alg,
        )?));
        Ok(())
    }

    /// Return the compiled runtime. Runtime requests fail closed if absent.
    pub fn runtime(&self) -> Result<Arc<DpopRuntime>, DpopSignerError> {
        self.runtime
            .clone()
            .ok_or(DpopSignerError::InvalidKeyFormat)
    }
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
            .mint_proof("POST", "https://api.example/resource", None, None)
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
            .mint_proof(
                "GET",
                "https://api.example/n",
                None,
                Some("server-nonce-123"),
            )
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
            .mint_proof("GET", "https://api.example/r", None, Some("nonce-A"))
            .expect("first mint");
        let second = signer
            .mint_proof("GET", "https://api.example/r", None, Some("nonce-B"))
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

    fn proof_claims(proof: &str) -> serde_json::Value {
        use base64::Engine;
        let claims = proof.split('.').nth(1).expect("claims segment");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .expect("base64url claims");
        serde_json::from_slice(&decoded).expect("JSON claims")
    }

    #[test]
    fn resource_proof_binds_the_access_token_with_ath() {
        let runtime =
            DpopRuntime::new(TEST_PRIVATE_KEY_PEM.as_bytes(), test_jwk(), "ES256").unwrap();
        let proof = runtime
            .mint_resource_proof(
                "PATCH",
                "https://api.example/resource",
                "access-token-value",
            )
            .unwrap();

        assert_eq!(
            proof_claims(&proof)["ath"],
            "iJgTy-uvL4oMlW_aBkwnk0nI686296RGFKrgcDJXTpo"
        );
    }

    #[test]
    fn proof_preserves_extension_method_case() {
        let signer = DpopSigner::from_pem(TEST_PRIVATE_KEY_PEM.as_bytes(), test_jwk(), "ES256")
            .expect("signer constructs");
        let proof = signer
            .mint_proof("customMethod", "https://api.example/resource", None, None)
            .expect("mint");

        assert_eq!(proof_claims(&proof)["htm"], "customMethod");
    }

    #[test]
    fn every_mint_has_a_fresh_jti_and_signature() {
        let runtime =
            DpopRuntime::new(TEST_PRIVATE_KEY_PEM.as_bytes(), test_jwk(), "ES256").unwrap();
        let first = runtime
            .mint_resource_proof("GET", "https://api.example/items", "token")
            .unwrap();
        let second = runtime
            .mint_resource_proof("GET", "https://api.example/items", "token")
            .unwrap();

        assert_ne!(first, second);
        assert_ne!(proof_claims(&first)["jti"], proof_claims(&second)["jti"]);
    }

    #[test]
    fn public_jwk_with_private_member_is_rejected() {
        let mut jwk = test_jwk();
        jwk["d"] = serde_json::Value::String("private-material".to_string());
        let result = DpopRuntime::new(TEST_PRIVATE_KEY_PEM.as_bytes(), jwk, "ES256");

        assert!(matches!(result, Err(DpopSignerError::InvalidPublicJwk)));
    }

    #[test]
    fn public_jwk_must_match_private_key() {
        let mut jwk = test_jwk();
        jwk["x"] =
            serde_json::Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
        let result = DpopRuntime::new(TEST_PRIVATE_KEY_PEM.as_bytes(), jwk, "ES256");

        assert!(matches!(result, Err(DpopSignerError::KeyPairMismatch)));
    }

    #[test]
    fn authorization_and_resource_nonces_are_separate() {
        let runtime =
            DpopRuntime::new(TEST_PRIVATE_KEY_PEM.as_bytes(), test_jwk(), "ES256").unwrap();
        runtime.set_authorization_nonce("as-nonce").unwrap();
        runtime
            .set_resource_nonce("https://api.example/resource", "rs-nonce")
            .unwrap();

        let token = runtime
            .mint_token_proof("POST", "https://idp.example/token")
            .unwrap();
        let resource = runtime
            .mint_resource_proof("GET", "https://api.example/items", "token")
            .unwrap();
        assert_eq!(proof_claims(&token)["nonce"], "as-nonce");
        assert_eq!(proof_claims(&resource)["nonce"], "rs-nonce");
    }

    #[test]
    fn resource_nonce_is_scoped_to_its_issuing_origin() {
        let runtime =
            DpopRuntime::new(TEST_PRIVATE_KEY_PEM.as_bytes(), test_jwk(), "ES256").unwrap();
        runtime
            .set_resource_nonce("https://one.example/resource", "one-nonce")
            .unwrap();

        let other = runtime
            .mint_resource_proof("GET", "https://two.example/resource", "token")
            .unwrap();
        assert!(proof_claims(&other).get("nonce").is_none());
    }

    #[test]
    fn dpop_private_key_must_be_an_existing_secret_reference() {
        for reference in [
            "secret://prod/dpop-key",
            "vault://primary/apps/api?key=dpop",
            "file:/run/secrets/api-dpop.pem",
        ] {
            validate_key_reference(reference).expect(reference);
        }

        let inline = validate_key_reference(TEST_PRIVATE_KEY_PEM).unwrap_err();
        assert!(matches!(inline, DpopSignerError::KeyReferenceRequired));
        assert!(!inline.to_string().contains("PRIVATE KEY"));
    }
}
