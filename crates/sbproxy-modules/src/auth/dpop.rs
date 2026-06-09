// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! RFC 9449 inbound DPoP proof verification (WOR-1070).
//!
//! A DPoP-bound access token carries a `cnf.jkt` claim — the JWK
//! thumbprint of the public key the legitimate client controls. On
//! every request, the client presents a fresh DPoP proof (a JWS
//! signed by the matching private key) in the `DPoP:` header. The
//! proof binds the request to the URL + method + a per-proof unique
//! `jti` so a captured Bearer token cannot be replayed by a passive
//! eavesdropper or a downstream service.
//!
//! ## What this module does
//!
//! 1. Parse the `DPoP:` header as a compact JWS.
//! 2. Validate the proof's algorithm against an explicit allowlist
//!    (ES256/ES384/ES512, RS256/RS384/RS512, EdDSA).
//! 3. Verify the proof's signature with the public key carried in the
//!    proof's `jwk` header.
//! 4. Confirm the proof's `htm` (HTTP method) and `htu` (HTTP target
//!    URI) match the request.
//! 5. Reject proofs whose `iat` is outside the configured window
//!    (default 60 seconds either side per RFC 9449 §11.2).
//! 6. Track the proof's `jti` per `jkt` in a sliding-window so a
//!    captured proof cannot be replayed within the validity window.
//! 7. Confirm the JWK thumbprint matches the access token's
//!    `cnf.jkt` claim.
//!
//! ## What this module does NOT do
//!
//! * Token introspection. The access token is opaque to the
//!   verifier; the caller (the JWT or Bearer auth provider) is
//!   responsible for extracting the `cnf.jkt` claim from the access
//!   token and passing it in.
//! * Nonce challenges (RFC 9449 §8). The proxy never returns a
//!   `DPoP-Nonce`; outbound nonce handling lives in
//!   `outbound_credential.rs` (see WOR-1071).
//! * Per-tenant key rotation. The verifier accepts whatever key the
//!   proof's `jwk` header carries; rotation is an access-token
//!   concern.

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Maximum age of a DPoP proof, measured in seconds from `iat`. Per
/// RFC 9449 §11.2 the default is 60 seconds either side. Operators
/// who want a tighter window can pin this lower; widening past 300
/// seconds defeats the replay-protection guarantee.
pub const DEFAULT_IAT_WINDOW_SECS: u64 = 60;

/// Number of recent `jti` values tracked per `jkt`. A captured proof
/// cannot be replayed within this window. Sized to handle a
/// reasonable burst (10 RPS per client for the validity window) plus
/// slack.
pub const REPLAY_CACHE_PER_JKT: usize = 1024;

/// Algorithms the verifier accepts. Matches the OAuth WG security
/// BCP (RFC 9449 §5.3 + IANA registry).
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::EdDSA,
];

/// RFC 9449 §4 DPoP proof header. The verifier reads `alg` to pick
/// the algorithm and `jwk` to extract the public key.
#[derive(Debug, Clone, Deserialize)]
struct DpopHeader {
    /// Algorithm; must be in [`ALLOWED_ALGORITHMS`].
    alg: String,
    /// `"dpop+jwt"` per RFC 9449 §4.2.
    #[serde(rename = "typ")]
    _typ: String,
    /// Public key the client controls. Used to verify the proof's
    /// signature AND to compute the `jkt` thumbprint that gets
    /// matched against the access token's `cnf.jkt` claim.
    jwk: serde_json::Value,
}

/// RFC 9449 §4 DPoP proof claims.
#[derive(Debug, Clone, Deserialize)]
struct DpopClaims {
    /// Unique identifier for this proof. The replay cache keys on
    /// `(jkt, jti)`.
    jti: String,
    /// HTTP method the proof is bound to (upper-case).
    htm: String,
    /// HTTP target URI the proof is bound to (full URL, no fragment).
    htu: String,
    /// Issued-at timestamp in seconds since the Unix epoch.
    iat: u64,
}

/// Verifier configuration. The verifier itself is a singleton per
/// proxy process; the config is applied at construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopVerifierConfig {
    /// Maximum acceptable proof age in seconds (clock-skew window
    /// is applied symmetrically: a proof with `iat` more than this
    /// many seconds in the future is also rejected). Default 60.
    #[serde(default = "default_iat_window")]
    pub iat_window_secs: u64,
}

fn default_iat_window() -> u64 {
    DEFAULT_IAT_WINDOW_SECS
}

impl Default for DpopVerifierConfig {
    fn default() -> Self {
        Self {
            iat_window_secs: DEFAULT_IAT_WINDOW_SECS,
        }
    }
}

/// Reasons the verifier rejects a proof. Carried up to the auth
/// dispatcher so the deny reason landing on the security audit log
/// distinguishes a missing proof from an algorithm mismatch from a
/// replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopRejection {
    /// The `DPoP:` header was absent.
    MissingHeader,
    /// The header value did not parse as a compact JWS.
    MalformedHeader,
    /// The proof's `alg` was not in the allowlist.
    AlgorithmNotAllowed {
        /// The disallowed algorithm name as it appeared in the proof.
        found: String,
    },
    /// The proof's `htm` did not match the request method.
    MethodMismatch {
        /// HTTP method on the inbound request.
        expected: String,
        /// `htm` value the proof carried.
        found: String,
    },
    /// The proof's `htu` did not match the request URI.
    UriMismatch {
        /// HTTP target URI of the inbound request.
        expected: String,
        /// `htu` value the proof carried.
        found: String,
    },
    /// The proof's `iat` was outside the configured window.
    IatOutsideWindow {
        /// Issued-at timestamp the proof carried (seconds since epoch).
        iat: u64,
        /// Verifier's current time (seconds since epoch).
        now: u64,
        /// Configured allowed window (seconds either side of `now`).
        window_secs: u64,
    },
    /// The proof's signature did not verify against the embedded
    /// `jwk`.
    BadSignature,
    /// The proof's `jti` was already seen within the validity
    /// window; the proof is being replayed.
    Replay {
        /// The `jti` value the replay cache had already recorded.
        jti: String,
    },
    /// The JWK thumbprint did not match the access token's `cnf.jkt`
    /// claim.
    CnfJktMismatch {
        /// Thumbprint the access token's `cnf.jkt` claim expects.
        expected: String,
        /// Thumbprint computed from the proof's `jwk` header.
        found: String,
    },
}

impl std::fmt::Display for DpopRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHeader => f.write_str("missing DPoP header"),
            Self::MalformedHeader => f.write_str("malformed DPoP header"),
            Self::AlgorithmNotAllowed { found } => {
                write!(f, "algorithm `{found}` not in DPoP allowlist")
            }
            Self::MethodMismatch { expected, found } => {
                write!(f, "htm mismatch: expected `{expected}`, proof has `{found}`")
            }
            Self::UriMismatch { expected, found } => {
                write!(f, "htu mismatch: expected `{expected}`, proof has `{found}`")
            }
            Self::IatOutsideWindow {
                iat,
                now,
                window_secs,
            } => write!(
                f,
                "iat {iat} outside window: now {now}, window {window_secs}s"
            ),
            Self::BadSignature => f.write_str("DPoP proof signature did not verify"),
            Self::Replay { jti } => write!(f, "DPoP proof replayed: jti `{jti}`"),
            Self::CnfJktMismatch { expected, found } => write!(
                f,
                "cnf.jkt mismatch: access token expects `{expected}`, proof key thumbprints to `{found}`"
            ),
        }
    }
}

impl std::error::Error for DpopRejection {}

/// Process-wide replay cache. Keyed on the JWK thumbprint so two
/// distinct clients with different keys do not collide; per-key the
/// cache is a small ring buffer of the most recent `jti` values.
#[derive(Debug, Default)]
struct ReplayCache {
    seen: HashMap<String, VecDeque<(String, Instant)>>,
}

impl ReplayCache {
    /// Returns `true` when the `(jkt, jti)` pair has been seen within
    /// the cache window AND is still fresh. Side-effect: prunes
    /// entries whose `Instant` is older than the configured window so
    /// the cache does not grow unbounded.
    fn check_and_record(
        &mut self,
        jkt: &str,
        jti: &str,
        window: Duration,
    ) -> Result<(), DpopRejection> {
        let entry = self.seen.entry(jkt.to_string()).or_default();
        // Drop stale entries from the front (we record at the back).
        let cutoff = Instant::now() - window;
        while let Some((_, ts)) = entry.front() {
            if *ts < cutoff {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.iter().any(|(j, _)| j == jti) {
            return Err(DpopRejection::Replay {
                jti: jti.to_string(),
            });
        }
        entry.push_back((jti.to_string(), Instant::now()));
        // Cap the ring buffer so a noisy client cannot exhaust memory.
        while entry.len() > REPLAY_CACHE_PER_JKT {
            entry.pop_front();
        }
        Ok(())
    }
}

/// Inbound DPoP proof verifier. Cheap to clone (everything sits
/// behind an `Arc`).
pub struct DpopVerifier {
    config: DpopVerifierConfig,
    replay: Mutex<ReplayCache>,
}

impl Default for DpopVerifier {
    fn default() -> Self {
        Self::new(DpopVerifierConfig::default())
    }
}

impl DpopVerifier {
    /// Build a verifier with the given config.
    pub fn new(config: DpopVerifierConfig) -> Self {
        Self {
            config,
            replay: Mutex::new(ReplayCache::default()),
        }
    }

    /// Verify the proof in `dpop_header` against the request method +
    /// URI + the access token's `cnf.jkt` thumbprint. Returns the
    /// proof's JWK thumbprint on success (so the caller can stamp it
    /// onto the resolved `Principal`).
    pub fn verify(
        &self,
        dpop_header: Option<&str>,
        method: &str,
        uri: &str,
        access_token_cnf_jkt: &str,
        now: SystemTime,
    ) -> Result<String, DpopRejection> {
        let proof = dpop_header.ok_or(DpopRejection::MissingHeader)?;
        let (header, claims) = decode_proof(proof)?;

        // 1. Algorithm allowlist.
        let alg =
            header
                .alg
                .parse::<Algorithm>()
                .map_err(|_| DpopRejection::AlgorithmNotAllowed {
                    found: header.alg.clone(),
                })?;
        if !ALLOWED_ALGORITHMS.contains(&alg) {
            return Err(DpopRejection::AlgorithmNotAllowed { found: header.alg });
        }

        // 2. Method + URI bind.
        if !claims.htm.eq_ignore_ascii_case(method) {
            return Err(DpopRejection::MethodMismatch {
                expected: method.to_string(),
                found: claims.htm,
            });
        }
        if claims.htu != uri {
            return Err(DpopRejection::UriMismatch {
                expected: uri.to_string(),
                found: claims.htu,
            });
        }

        // 3. iat window.
        let now_secs = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window = self.config.iat_window_secs;
        let drift = claims.iat.abs_diff(now_secs);
        if drift > window {
            return Err(DpopRejection::IatOutsideWindow {
                iat: claims.iat,
                now: now_secs,
                window_secs: window,
            });
        }

        // 4. Signature.
        verify_signature(proof, alg, &header.jwk)?;

        // 5. Replay cache (after signature so a forged proof does not
        // burn a cache slot for the legitimate client).
        let jkt = jwk_thumbprint(&header.jwk).ok_or(DpopRejection::MalformedHeader)?;
        {
            let mut cache = self.replay.lock().expect("replay cache mutex poisoned");
            cache.check_and_record(&jkt, &claims.jti, Duration::from_secs(window))?;
        }

        // 6. cnf.jkt match.
        if jkt != access_token_cnf_jkt {
            return Err(DpopRejection::CnfJktMismatch {
                expected: access_token_cnf_jkt.to_string(),
                found: jkt,
            });
        }

        Ok(jkt)
    }
}

/// Decode a compact-JWS DPoP proof into its header + claims. The
/// signature segment is NOT verified here; the caller runs
/// [`verify_signature`] separately.
fn decode_proof(proof: &str) -> Result<(DpopHeader, DpopClaims), DpopRejection> {
    use base64::Engine;
    let segments: Vec<&str> = proof.split('.').collect();
    if segments.len() != 3 {
        return Err(DpopRejection::MalformedHeader);
    }
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[0])
        .map_err(|_| DpopRejection::MalformedHeader)?;
    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[1])
        .map_err(|_| DpopRejection::MalformedHeader)?;
    let header: DpopHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| DpopRejection::MalformedHeader)?;
    let claims: DpopClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| DpopRejection::MalformedHeader)?;
    Ok((header, claims))
}

/// Verify the compact-JWS signature against the public key embedded
/// in the proof's `jwk` header. Uses `jsonwebtoken::decode` with the
/// allowlisted algorithms so an attacker cannot smuggle a `none` alg
/// or an HMAC algorithm.
fn verify_signature(
    proof: &str,
    alg: Algorithm,
    jwk: &serde_json::Value,
) -> Result<(), DpopRejection> {
    let decoding_key = decoding_key_from_jwk(jwk, alg).ok_or(DpopRejection::MalformedHeader)?;
    let mut validation = Validation::new(alg);
    validation.algorithms = vec![alg];
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.validate_nbf = false;
    // The proof claims are decoded as a raw Value because they do
    // not conform to the standard `Claims` shape; we only need the
    // signature to verify here.
    jsonwebtoken::decode::<serde_json::Value>(proof, &decoding_key, &validation)
        .map(|_| ())
        .map_err(|_| DpopRejection::BadSignature)
}

/// Build a `DecodingKey` from a JWK. Only supports the algorithms in
/// [`ALLOWED_ALGORITHMS`]; an `oct` key (HMAC) is intentionally
/// rejected because RFC 9449 §5.3 forbids symmetric algorithms.
fn decoding_key_from_jwk(jwk: &serde_json::Value, alg: Algorithm) -> Option<DecodingKey> {
    let kty = jwk.get("kty")?.as_str()?;
    match (kty, alg) {
        ("EC", Algorithm::ES256 | Algorithm::ES384) => {
            let x = jwk.get("x")?.as_str()?;
            let y = jwk.get("y")?.as_str()?;
            DecodingKey::from_ec_components(x, y).ok()
        }
        (
            "RSA",
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512,
        ) => {
            let n = jwk.get("n")?.as_str()?;
            let e = jwk.get("e")?.as_str()?;
            DecodingKey::from_rsa_components(n, e).ok()
        }
        ("OKP", Algorithm::EdDSA) => {
            let x = jwk.get("x")?.as_str()?;
            DecodingKey::from_ed_components(x).ok()
        }
        _ => None,
    }
}

/// Compute the RFC 7638 JWK thumbprint (SHA-256) of a public key.
/// Returns the base64url-no-pad encoding so it matches the shape of
/// the access token's `cnf.jkt` claim.
fn jwk_thumbprint(jwk: &serde_json::Value) -> Option<String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    // RFC 7638 §3.2: canonical members per key type, sorted
    // lexicographically, serialised as compact JSON.
    let kty = jwk.get("kty")?.as_str()?;
    let canonical = match kty {
        "EC" => {
            let crv = jwk.get("crv")?.as_str()?;
            let x = jwk.get("x")?.as_str()?;
            let y = jwk.get("y")?.as_str()?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        "RSA" => {
            let e = jwk.get("e")?.as_str()?;
            let n = jwk.get("n")?.as_str()?;
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        "OKP" => {
            let crv = jwk.get("crv")?.as_str()?;
            let x = jwk.get("x")?.as_str()?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        _ => return None,
    };
    let digest = Sha256::digest(canonical.as_bytes());
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture EC P-256 keypair (test key only; do not use in
    /// production). The JWK is in the proof; the matching PKCS#8
    /// private key signs the proof.
    const TEST_PRIVATE_KEY_PEM: &str = include_str!("dpop_test_ec_p256.pem");

    /// Mint a fresh proof signed by the fixture key. The caller picks
    /// the `iat` so tests can exercise window edges; setting `iat` to
    /// `None` uses the current clock.
    fn mint_proof(method: &str, uri: &str, jti: &str, iat: Option<u64>) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let now = iat.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(serde_json::from_str(test_jwk_json()).expect("test JWK is well-formed"));
        let claims = serde_json::json!({
            "jti": jti,
            "htm": method,
            "htu": uri,
            "iat": now,
        });
        let key =
            EncodingKey::from_ec_pem(TEST_PRIVATE_KEY_PEM.as_bytes()).expect("test PEM is valid");
        encode(&header, &claims, &key).expect("encode")
    }

    /// The JWK derived from the fixture private key. Hard-coded so
    /// tests do not have to re-derive on every run; the `cnf.jkt`
    /// thumbprint below is also hard-coded for the same reason.
    fn test_jwk_json() -> &'static str {
        // Derived from `dpop_test_ec_p256.pem` once; the X / Y
        // coordinates are the public point uncompressed. If the
        // fixture key rotates, regenerate via:
        //   openssl ec -in dpop_test_ec_p256.pem -text -noout
        // and base64url-encode the X / Y byte halves of the
        // uncompressed (`04 || X || Y`) point.
        r#"{"kty":"EC","crv":"P-256","x":"DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4","y":"bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc"}"#
    }

    /// The RFC 7638 thumbprint of the fixture JWK. Computed once and
    /// pinned; if the fixture key changes, regenerate via
    /// `jwk_thumbprint(&serde_json::from_str(test_jwk_json()).unwrap()).unwrap()`.
    fn test_jkt() -> String {
        let jwk: serde_json::Value = serde_json::from_str(test_jwk_json()).unwrap();
        jwk_thumbprint(&jwk).expect("thumbprint computes")
    }

    #[test]
    fn fresh_proof_accepted() {
        let v = DpopVerifier::default();
        let proof = mint_proof("POST", "https://api.example/resource", "fresh-1", None);
        let result = v.verify(
            Some(&proof),
            "POST",
            "https://api.example/resource",
            &test_jkt(),
            SystemTime::now(),
        );
        assert!(result.is_ok(), "fresh proof should verify: {result:?}");
    }

    #[test]
    fn replayed_proof_rejected() {
        let v = DpopVerifier::default();
        let proof = mint_proof("GET", "https://api.example/x", "replay-1", None);
        // First call: accept.
        v.verify(
            Some(&proof),
            "GET",
            "https://api.example/x",
            &test_jkt(),
            SystemTime::now(),
        )
        .expect("first proof");
        // Second call with the same proof bytes: replay.
        let result = v.verify(
            Some(&proof),
            "GET",
            "https://api.example/x",
            &test_jkt(),
            SystemTime::now(),
        );
        assert!(matches!(result, Err(DpopRejection::Replay { .. })));
    }

    #[test]
    fn cnf_jkt_mismatch_rejected() {
        let v = DpopVerifier::default();
        let proof = mint_proof("GET", "https://api.example/y", "cnf-1", None);
        let result = v.verify(
            Some(&proof),
            "GET",
            "https://api.example/y",
            "different-thumbprint-deadbeef",
            SystemTime::now(),
        );
        assert!(matches!(result, Err(DpopRejection::CnfJktMismatch { .. })));
    }

    #[test]
    fn method_mismatch_rejected() {
        let v = DpopVerifier::default();
        let proof = mint_proof("POST", "https://api.example/m", "method-1", None);
        let result = v.verify(
            Some(&proof),
            "GET",
            "https://api.example/m",
            &test_jkt(),
            SystemTime::now(),
        );
        assert!(matches!(result, Err(DpopRejection::MethodMismatch { .. })));
    }

    #[test]
    fn uri_mismatch_rejected() {
        let v = DpopVerifier::default();
        let proof = mint_proof("GET", "https://api.example/u", "uri-1", None);
        let result = v.verify(
            Some(&proof),
            "GET",
            "https://api.example/other",
            &test_jkt(),
            SystemTime::now(),
        );
        assert!(matches!(result, Err(DpopRejection::UriMismatch { .. })));
    }

    #[test]
    fn iat_outside_window_rejected() {
        let v = DpopVerifier::default();
        let stale_iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600; // 10 minutes ago, well outside default 60s window.
        let proof = mint_proof("GET", "https://api.example/i", "iat-1", Some(stale_iat));
        let result = v.verify(
            Some(&proof),
            "GET",
            "https://api.example/i",
            &test_jkt(),
            SystemTime::now(),
        );
        assert!(matches!(
            result,
            Err(DpopRejection::IatOutsideWindow { .. })
        ));
    }

    #[test]
    fn missing_header_rejected() {
        let v = DpopVerifier::default();
        let result = v.verify(
            None,
            "GET",
            "https://api.example/m",
            &test_jkt(),
            SystemTime::now(),
        );
        assert!(matches!(result, Err(DpopRejection::MissingHeader)));
    }

    #[test]
    fn malformed_header_rejected() {
        let v = DpopVerifier::default();
        let result = v.verify(
            Some("not-a-jws"),
            "GET",
            "https://api.example/m",
            &test_jkt(),
            SystemTime::now(),
        );
        assert!(matches!(result, Err(DpopRejection::MalformedHeader)));
    }

    #[test]
    fn jkt_thumbprint_matches_rfc7638_appendix_a() {
        // RFC 7638 Appendix A.1: a worked example RSA JWK with the
        // expected thumbprint
        // `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`. We use the
        // exact JWK from the appendix.
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        let got = jwk_thumbprint(&jwk).expect("thumbprint computes");
        assert_eq!(got, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn algorithm_not_allowed_rejected_for_none() {
        // Hand-roll a JWS-shaped string with `"alg":"none"` so we
        // can exercise the explicit reject path without producing a
        // signature.
        use base64::Engine;
        let header =
            r#"{"alg":"none","typ":"dpop+jwt","jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y"}}"#;
        let claims = r#"{"jti":"none-1","htm":"GET","htu":"https://x","iat":0}"#;
        let proof = format!(
            "{}.{}.",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims)
        );
        let v = DpopVerifier::default();
        let result = v.verify(
            Some(&proof),
            "GET",
            "https://x",
            &test_jkt(),
            SystemTime::now(),
        );
        assert!(matches!(
            result,
            Err(DpopRejection::AlgorithmNotAllowed { .. })
        ));
    }
}
