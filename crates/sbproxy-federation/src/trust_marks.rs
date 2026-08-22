//! OpenID Federation 1.0 §7 trust marks.
//!
//! A trust mark is a signed JWS asserting that a *trust-mark
//! issuer* certifies an entity for some property (e.g. "this
//! provider supports MFA", "this RP belongs to the eduGAIN
//! research-and-scholarship category"). The mark is a separate
//! signed document from the entity statement: it is signed by the
//! trust-mark issuer, not by the entity that claims it, and a peer
//! verifies it against the trust-mark issuer's published JWKS.
//!
//! The JWS `typ` header MUST be `trust-mark+jwt` (§7.2.1). Each
//! claim set carries:
//!
//! * `iss` - the trust-mark issuer's entity URL.
//! * `sub` - the entity URL the mark applies to.
//! * `iat` - issued at.
//! * `id` - URI identifying the trust-mark type (the "kind" of
//!   certification, distinct from the issuer URL).
//! * Optional: `exp` (expiry), `logo_uri`, `ref`, `delegation`,
//!   any free-form extension claims.
//!
//! ## What this module ships
//!
//! * [`TrustMarkClaims`]: strongly-typed claim shape.
//! * [`sign_trust_mark`]: produce the compact JWS with the
//!   mandatory `typ = "trust-mark+jwt"` header and a caller-supplied
//!   `kid`.
//! * [`verify_trust_mark`]: decode + verify against a supplied
//!   trust-mark-issuer JWKS, checking `typ`, `kid`, `iat`, `exp`,
//!   plus required claims (`iss`, `sub`, `id`).
//! * [`SignedTrustMark`]: the verified wrapper returned on success.
//!
//! ## What this module does NOT do
//!
//! * Fetch the trust-mark issuer's JWKS over HTTP. The caller is
//!   expected to have resolved the issuer's federation entity
//!   configuration through [`crate::TrustChainResolver`] already and
//!   pass its `jwks` in.
//! * Query the `/.well-known/federation-trust-mark-status` endpoint
//!   (§7.5) to see if the issuer has revoked the mark. That is a live
//!   HTTP check a consumer performs separately; this module verifies
//!   the mark's signature, which is the offline half of the §7 check.

use jsonwebtoken::{Algorithm, EncodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::errors::{FederationError, FederationResult};
use crate::jwk::FederationKeySet;

/// OIDF media type for a trust mark. The JWS header MUST set
/// `typ = "trust-mark+jwt"` per §7.2.1.
pub const TRUST_MARK_TYP: &str = "trust-mark+jwt";

/// HTTP `Content-Type` an OIDF responder MUST stamp on a
/// trust-mark JWS (e.g. when the trust-mark issuer's status
/// endpoint returns the active mark inline). Mirrors `typ` with the
/// `application/` prefix.
pub const TRUST_MARK_CONTENT_TYPE: &str = "application/trust-mark+jwt";

/// Algorithms allowed on a trust-mark signing key. Symmetric
/// algorithms are rejected on principle: a trust mark MUST be
/// verifiable by any peer holding the trust-mark issuer's public
/// key.
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::EdDSA,
];

/// §7.2 trust-mark claim set. Field names match the wire shape so
/// serde round-trips without a translation layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustMarkClaims {
    /// Entity URL of the trust-mark issuer (distinct from the
    /// federation entity hierarchy: trust-mark issuers are
    /// independent operators of trust marks).
    pub iss: String,
    /// Entity URL the mark applies to.
    pub sub: String,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: i64,
    /// Trust-mark identifier (a URI naming the "kind" of mark,
    /// e.g. `https://refeds.org/category/research-and-scholarship`).
    /// Distinct from `iss`: an issuer can issue many marks; an
    /// `id` value identifies the certification semantics.
    pub id: String,
    /// Optional expiry. Marks without an `exp` are valid until the
    /// issuer's status endpoint says otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Optional URI of a logo / icon a UI can display alongside the
    /// mark. Per §7.2 this is informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    /// Optional human-readable reference (a URL pointing at the
    /// trust framework's documentation, for example).
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
    /// Optional delegation chain claim. Trust-mark issuers can
    /// delegate authority to a downstream issuer; the chain
    /// payload is opaque JSON here pending a future stage that
    /// strongly types it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<serde_json::Value>,
}

impl TrustMarkClaims {
    /// True when the mark carries an `exp` and it is in the past
    /// relative to the supplied `now` (seconds since epoch). The
    /// verifier already checks `exp` against current time inside
    /// `jsonwebtoken`; this helper exists for callers that want to
    /// surface "expired" as an explicit UI state outside the
    /// verify path.
    pub fn is_expired_at(&self, now: i64) -> bool {
        self.exp.is_some_and(|e| e <= now)
    }
}

/// Verified trust mark + the original compact-JWS bytes for cache /
/// replay. Returned by [`verify_trust_mark`] on success.
#[derive(Debug, Clone)]
pub struct SignedTrustMark {
    /// Parsed claims.
    pub claims: TrustMarkClaims,
    /// On-the-wire compact-JWS bytes.
    pub compact_jws: String,
}

/// Sign a trust mark with the given trust-mark-issuer key.
///
/// Produces a compact-JWS string suitable for embedding in an
/// entity statement's `trust_marks` claim (each entry is a JWS
/// per §7.3) or for returning from the trust-mark issuer's status
/// endpoint.
///
/// Validates `algorithm` against the OIDF allowlist on every call;
/// symmetric algorithms are rejected up-front.
pub fn sign_trust_mark(
    claims: &TrustMarkClaims,
    key: &EncodingKey,
    alg: Algorithm,
    kid: impl Into<String>,
) -> FederationResult<String> {
    if !ALLOWED_ALGORITHMS.contains(&alg) {
        return Err(FederationError::AlgorithmNotAllowed(format!("{alg:?}")));
    }
    let mut header = jsonwebtoken::Header::new(alg);
    header.typ = Some(TRUST_MARK_TYP.to_string());
    header.kid = Some(kid.into());
    jsonwebtoken::encode(&header, claims, key)
        .map_err(|e| FederationError::EncodeFailed(e.to_string()))
}

/// Verify a trust mark against the trust-mark issuer's published
/// JWKS.
///
/// Verification steps:
/// 1. Decode the header (no signature check yet) to read `typ`
///    and `kid`.
/// 2. Reject when `typ != "trust-mark+jwt"`.
/// 3. Reject when `kid` is missing.
/// 4. Pick the matching key from `issuer_jwks` by `kid`; reject
///    when no key matches.
/// 5. Verify the signature with the picked key.
/// 6. Validate the required-field set (`iss`, `sub`, `id`).
///    Missing fields surface as typed
///    [`FederationError::MissingClaim`].
/// 7. Standard `iat` + `exp` validation runs inside
///    `jsonwebtoken` with a 5-minute leeway for clock skew.
///
/// The caller is responsible for picking the right `issuer_jwks`:
/// it is the JWKS the trust-mark issuer publishes in its own
/// entity configuration (resolved through
/// [`crate::TrustChainResolver`] against the configured trust
/// anchors).
///
/// Every call emits a `sbproxy_federation_trust_mark_verifications_total`
/// counter tick and a structured decision-event log line (target
/// `sbproxy_federation::decision`, `event =
/// "federation_trust_mark_decision"`).
pub fn verify_trust_mark(
    compact_jws: &str,
    issuer_jwks: &FederationKeySet,
) -> FederationResult<SignedTrustMark> {
    let result = verify_trust_mark_inner(compact_jws, issuer_jwks);
    match &result {
        Ok(mark) => {
            crate::metrics::record_trust_mark_verification("verified");
            tracing::info!(
                target: "sbproxy_federation::decision",
                event = "federation_trust_mark_decision",
                outcome = "verified",
                iss = %mark.claims.iss,
                sub = %mark.claims.sub,
                id = %mark.claims.id,
                "trust mark verified"
            );
        }
        Err(err) => {
            crate::metrics::record_trust_mark_verification("rejected");
            tracing::warn!(
                target: "sbproxy_federation::decision",
                event = "federation_trust_mark_decision",
                outcome = "rejected",
                error = %err,
                "trust mark rejected"
            );
        }
    }
    result
}

fn verify_trust_mark_inner(
    compact_jws: &str,
    issuer_jwks: &FederationKeySet,
) -> FederationResult<SignedTrustMark> {
    // Step 1: header peek.
    let header = jsonwebtoken::decode_header(compact_jws)
        .map_err(|_| FederationError::VerificationFailed)?;
    // Step 2: typ check.
    if header.typ.as_deref() != Some(TRUST_MARK_TYP) {
        return Err(FederationError::WrongTyp(header.typ));
    }
    // Step 3: kid check.
    let kid = header.kid.ok_or(FederationError::MissingKid)?;
    // Step 4 + 5: lookup + verify.
    let key = issuer_jwks.decoding_key_for(&kid)?;
    let mut validation = Validation::new(header.alg);
    validation.algorithms = vec![header.alg];
    validation.leeway = 300;
    // Trust marks can be issued without an `exp` (perpetual until
    // the issuer's status endpoint revokes); enable validation when
    // the claim is present and skip otherwise. `jsonwebtoken`'s
    // `validate_exp` treats absent `exp` as invalid unless we tell
    // it the field is optional.
    validation.validate_exp = true;
    validation.required_spec_claims.clear();
    validation.validate_nbf = false;
    validation.validate_aud = false;
    // jsonwebtoken errors when `exp` is missing while validate_exp
    // is on; switch the toggle off when the claim is absent. Peek
    // at the payload first so we know whether to enforce it.
    let payload_has_exp = compact_payload_has_field(compact_jws, "exp");
    if !payload_has_exp {
        validation.validate_exp = false;
    }
    let decoded = jsonwebtoken::decode::<TrustMarkClaims>(compact_jws, &key, &validation)
        .map_err(|_| FederationError::VerificationFailed)?;
    let claims = decoded.claims;
    // Step 6: required-field checks (empty strings rejected even
    // though serde admits them).
    if claims.iss.is_empty() {
        return Err(FederationError::MissingClaim("iss"));
    }
    if claims.sub.is_empty() {
        return Err(FederationError::MissingClaim("sub"));
    }
    if claims.id.is_empty() {
        return Err(FederationError::MissingClaim("id"));
    }
    Ok(SignedTrustMark {
        claims,
        compact_jws: compact_jws.to_string(),
    })
}

/// Cheap "is field N present in the JWS payload" check. Avoids the
/// need to deserialise the payload twice when the verifier wants
/// to decide whether to enforce `exp` validation. Returns false on
/// any decode error (the caller's `jsonwebtoken::decode` call will
/// catch the malformed shape with its own typed error).
fn compact_payload_has_field(compact_jws: &str, field: &str) -> bool {
    use base64::Engine;
    let parts: Vec<&str> = compact_jws.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    value.get(field).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use jsonwebtoken::{Algorithm, EncodingKey};

    /// Mint an ES256 keypair + a matching JWK so the issuer can
    /// sign + the verifier can resolve a key by `kid` in one
    /// process.
    fn fixture_key_and_jwk(kid: &str) -> (EncodingKey, serde_json::Value) {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePrivateKey;
        let signing = SigningKey::random(&mut rand::thread_rng());
        let pem = signing.to_pkcs8_pem(Default::default()).unwrap();
        let encoding = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
        let verifying = signing.verifying_key();
        let point = verifying.to_encoded_point(false);
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            "kid": kid,
        });
        (encoding, jwk)
    }

    fn sample_claims() -> TrustMarkClaims {
        let now = chrono::Utc::now().timestamp();
        TrustMarkClaims {
            iss: "https://refeds.org".to_string(),
            sub: "https://leaf.example".to_string(),
            iat: now,
            id: "https://refeds.org/category/research-and-scholarship".to_string(),
            exp: Some(now + 86_400),
            logo_uri: Some("https://refeds.org/img/logo.png".to_string()),
            r#ref: None,
            delegation: None,
        }
    }

    /// Happy path: sign + verify round-trip with a fresh ES256
    /// keypair returns the original claims byte-for-byte.
    #[test]
    fn sign_verify_round_trip_es256() {
        let (key, jwk) = fixture_key_and_jwk("mark-key-1");
        let mut issuer_jwks = FederationKeySet::empty();
        issuer_jwks.push(jwk);
        let claims = sample_claims();
        let jws = sign_trust_mark(&claims, &key, Algorithm::ES256, "mark-key-1").expect("sign");
        let verified = verify_trust_mark(&jws, &issuer_jwks).expect("verify");
        assert_eq!(verified.claims.iss, claims.iss);
        assert_eq!(verified.claims.sub, claims.sub);
        assert_eq!(verified.claims.id, claims.id);
        assert_eq!(verified.compact_jws, jws);
    }

    /// Trust marks may legitimately omit `exp` (perpetual until
    /// the issuer's status endpoint revokes). The verifier MUST
    /// accept such a mark instead of falling through `jsonwebtoken`'s
    /// "missing exp" path.
    #[test]
    fn sign_verify_round_trip_without_exp() {
        let (key, jwk) = fixture_key_and_jwk("mark-key-1");
        let mut issuer_jwks = FederationKeySet::empty();
        issuer_jwks.push(jwk);
        let mut claims = sample_claims();
        claims.exp = None;
        let jws = sign_trust_mark(&claims, &key, Algorithm::ES256, "mark-key-1").unwrap();
        let verified = verify_trust_mark(&jws, &issuer_jwks).expect("verify exp-less mark");
        assert!(verified.claims.exp.is_none());
    }

    /// `typ` header missing: a regular access token wrapped in a
    /// trust-mark surface MUST be rejected.
    #[test]
    fn typ_missing_rejected() {
        let (key, jwk) = fixture_key_and_jwk("mark-key-1");
        let mut issuer_jwks = FederationKeySet::empty();
        issuer_jwks.push(jwk);
        let claims = sample_claims();
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.kid = Some("mark-key-1".to_string());
        let jws = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        let err = verify_trust_mark(&jws, &issuer_jwks).unwrap_err();
        assert!(matches!(err, FederationError::WrongTyp(_)));
    }

    /// `kid` header missing: the verifier cannot pick the right
    /// key from the issuer's jwks, so the JWS MUST be rejected.
    #[test]
    fn kid_missing_rejected() {
        let (key, jwk) = fixture_key_and_jwk("mark-key-1");
        let mut issuer_jwks = FederationKeySet::empty();
        issuer_jwks.push(jwk);
        let claims = sample_claims();
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.typ = Some(TRUST_MARK_TYP.to_string());
        let jws = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        let err = verify_trust_mark(&jws, &issuer_jwks).unwrap_err();
        assert!(matches!(err, FederationError::MissingKid));
    }

    /// `kid` does not match any key in the issuer's jwks: an
    /// attacker cannot smuggle a mark signed by a different key.
    #[test]
    fn unknown_kid_rejected() {
        let (key, jwk) = fixture_key_and_jwk("mark-key-1");
        let mut issuer_jwks = FederationKeySet::empty();
        issuer_jwks.push(jwk);
        let claims = sample_claims();
        let jws = sign_trust_mark(&claims, &key, Algorithm::ES256, "wrong-kid").unwrap();
        let err = verify_trust_mark(&jws, &issuer_jwks).unwrap_err();
        assert!(matches!(err, FederationError::UnknownKid(k) if k == "wrong-kid"));
    }

    /// Signature signed by one key does NOT verify against another
    /// key set: the catch-all opaque rejection.
    #[test]
    fn signature_mismatch_rejected() {
        let (key_a, _) = fixture_key_and_jwk("mark-key-1");
        let (_, jwk_b) = fixture_key_and_jwk("mark-key-1");
        let claims = sample_claims();
        let jws = sign_trust_mark(&claims, &key_a, Algorithm::ES256, "mark-key-1").unwrap();
        let mut other_jwks = FederationKeySet::empty();
        other_jwks.push(jwk_b);
        let err = verify_trust_mark(&jws, &other_jwks).unwrap_err();
        assert!(matches!(err, FederationError::VerificationFailed));
    }

    /// HS256 rejected at sign time. A trust mark MUST be verifiable
    /// by any peer holding the issuer's public key.
    #[test]
    fn symmetric_algorithm_rejected_at_sign() {
        let claims = sample_claims();
        let key = EncodingKey::from_secret(b"secret");
        let err = sign_trust_mark(&claims, &key, Algorithm::HS256, "mark-key-1").unwrap_err();
        assert!(matches!(err, FederationError::AlgorithmNotAllowed(_)));
    }

    /// `is_expired_at` returns true once `now` passes `exp` and
    /// returns false for marks without an `exp`.
    #[test]
    fn is_expired_at_predicate() {
        let mut claims = sample_claims();
        let now = chrono::Utc::now().timestamp();
        claims.exp = Some(now - 1);
        assert!(claims.is_expired_at(now));
        claims.exp = Some(now + 3600);
        assert!(!claims.is_expired_at(now));
        claims.exp = None;
        assert!(!claims.is_expired_at(now));
    }

    /// An expired mark is rejected by the verifier (jsonwebtoken
    /// returns Expired; the typed surface collapses it to the
    /// opaque VerificationFailed so a forger can't probe the
    /// expiry edge).
    #[test]
    fn expired_mark_rejected_by_verifier() {
        let (key, jwk) = fixture_key_and_jwk("mark-key-1");
        let mut issuer_jwks = FederationKeySet::empty();
        issuer_jwks.push(jwk);
        let now = chrono::Utc::now().timestamp();
        let mut claims = sample_claims();
        // Sit well outside the 5-minute leeway.
        claims.iat = now - 7200;
        claims.exp = Some(now - 3600);
        let jws = sign_trust_mark(&claims, &key, Algorithm::ES256, "mark-key-1").unwrap();
        let err = verify_trust_mark(&jws, &issuer_jwks).unwrap_err();
        assert!(matches!(err, FederationError::VerificationFailed));
    }

    /// Empty `iss` / `sub` / `id` surface as typed
    /// `MissingClaim` rather than passing through the
    /// permissive serde decode.
    #[test]
    fn empty_required_claim_rejected() {
        let (key, jwk) = fixture_key_and_jwk("mark-key-1");
        let mut issuer_jwks = FederationKeySet::empty();
        issuer_jwks.push(jwk);
        let mut claims = sample_claims();
        claims.id = String::new();
        let jws = sign_trust_mark(&claims, &key, Algorithm::ES256, "mark-key-1").unwrap();
        let err = verify_trust_mark(&jws, &issuer_jwks).unwrap_err();
        assert!(matches!(err, FederationError::MissingClaim("id")));
    }
}
