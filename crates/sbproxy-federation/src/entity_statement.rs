//! OpenID Federation 1.0 §3 Entity Statement model + sign / verify.
//!
//! An Entity Statement is a signed JWT carrying everything a peer
//! needs to participate in a federation: who the issuer is, what
//! entity-type metadata it publishes, which superior entities it
//! trusts (`authority_hints`), and which trust marks it claims. The
//! issuer signs with one of the keys it publishes under `jwks`; a
//! verifier reads the same `jwks` claim out of a trusted statement
//! (the issuer's own Entity Configuration at §9, or a Subordinate
//! Statement signed by a superior) and picks the right key by `kid`.
//!
//! ## What this module does NOT do
//!
//! * Trust-chain resolution. The verifier checks ONE statement against
//!   ONE key set. Walking `authority_hints` to a trust anchor lives in
//!   `trust_chain.rs`.
//! * Subordinate statements. The §3 model is identical, but the
//!   semantic difference (issuer != subject) shows up in trust-chain
//!   resolution; modelled as a normal `EntityStatement` here, the
//!   trust-chain resolver picks the right key set per statement.
//! * Trust marks. The `trust_marks` claim is present on the type but
//!   issue / verify lives in `trust_marks.rs`.
//! * Metadata policy operators. The `metadata_policy` claim is
//!   passed through as opaque JSON; the seven operators
//!   (`value` / `add` / `default` / `one_of` / `subset_of` /
//!   `superset_of` / `essential`) land in `metadata_policy.rs`.

use std::collections::HashMap;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::errors::{FederationError, FederationResult};
use crate::jwk::FederationKeySet;
use crate::ENTITY_STATEMENT_TYP;

/// Algorithms allowed on a federation signing key. Symmetric (`HS*`)
/// is rejected on principle: an entity statement MUST be verifiable
/// by any peer holding the issuer's public key.
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

/// Strongly-typed wrapper around a signed entity statement. Produced
/// by [`verify_entity_statement`] on a successful decode + signature
/// check; carries the parsed claims + the original compact-JWS bytes
/// so the caller can store the statement verbatim for cache replay.
#[derive(Clone)]
pub struct EntityStatement {
    /// Verified entity-statement claims.
    pub claims: EntityStatementClaims,
    /// Original compact JWS retained for cache replay.
    pub compact_jws: String,
}

impl std::fmt::Debug for EntityStatement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityStatement")
            .field("claims", &self.claims)
            .field("compact_jws", &"[REDACTED]")
            .finish()
    }
}

/// §3 entity statement claim set. Field names match the wire shape so
/// serde round-trips without a translation layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityStatementClaims {
    /// Entity URL of the issuer. Per §3 this is the URL at which the
    /// issuer publishes its entity configuration (`{iss}{WELL_KNOWN_FEDERATION_PATH}`).
    pub iss: String,
    /// Entity URL of the subject. For a self-signed Entity
    /// Configuration `iss == sub`. For a Subordinate Statement the
    /// superior signs a statement about its immediate subordinate, so
    /// `iss` is the superior and `sub` is the subordinate.
    pub sub: String,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: i64,
    /// Expires-at, seconds since the Unix epoch. The OIDF spec is
    /// silent on a maximum value; production deployments commonly
    /// pick 24 hours so a compromised key has a bounded blast radius.
    pub exp: i64,
    /// Public-key set the issuer signs subordinate statements with.
    /// The JWS verifier picks one key from this set by `kid`.
    pub jwks: FederationKeySet,
    /// Optional list of URLs pointing at the immediate superiors of
    /// the subject. The trust-chain resolver follows these to a
    /// configured trust anchor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_hints: Vec<String>,
    /// Entity-type metadata blocks. An issuer that plays multiple
    /// roles (OP + RP, both an OAuth AS and an MCP server) declares
    /// one block per role. Field is `metadata` in §3.
    #[serde(default, skip_serializing_if = "EntityMetadata::is_empty")]
    pub metadata: EntityMetadata,
    /// Metadata policy applied by a superior to its subordinates. The
    /// seven operators (§6.1) are applied via
    /// [`crate::apply_block_policy`]; here the field is passed
    /// through as opaque JSON so a trust-chain resolver can collect
    /// the policies along the chain for later application.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_policy: Option<MetadataPolicy>,
    /// Trust marks the subject claims. Each entry is a signed JWT
    /// from a trust-mark issuer, verified via
    /// [`crate::verify_trust_mark`]. Modelled as opaque JSON here so
    /// the trust-chain resolver can carry them through to the
    /// verifier without parsing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_marks: Vec<serde_json::Value>,
}

impl EntityStatementClaims {
    /// True when the statement is a self-signed Entity Configuration
    /// (§9): `iss == sub`. The trust-chain resolver uses this to
    /// distinguish a leaf's own statement from a Subordinate
    /// Statement signed by a superior.
    pub fn is_self_signed(&self) -> bool {
        self.iss == self.sub
    }
}

/// §3 metadata block. The wire shape is a JSON object keyed by entity
/// type slug; per OIDF the recognised slugs are
/// `openid_provider`, `openid_relying_party`,
/// `oauth_authorization_server`, `oauth_client`, and
/// `federation_entity`. Today we strongly-type the federation entity
/// block (every entity in a federation has one) and leave the others
/// as opaque JSON pending per-role wiring in the OAuth / MCP-adjacent
/// modules that consume this crate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityMetadata {
    /// `federation_entity` block: where to fetch subordinate
    /// statements, what trust marks the entity issues, and operator
    /// contact metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_entity: Option<FederationEntityMetadata>,
    /// All other entity-type blocks (`openid_provider`,
    /// `openid_relying_party`, `oauth_authorization_server`,
    /// `oauth_client`, ...) carried as opaque JSON.
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

impl EntityMetadata {
    /// True when no entity-type block is present.
    pub fn is_empty(&self) -> bool {
        self.federation_entity.is_none() && self.other.is_empty()
    }
}

/// §5.1.2 `federation_entity` metadata block. Captures the canonical
/// URLs an OIDF peer needs to traverse + administer the federation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FederationEntityMetadata {
    /// URL where the entity publishes Subordinate Statements about
    /// its immediate subordinates (§8.1). Required on superior
    /// entities; absent on leaves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_fetch_endpoint: Option<String>,
    /// URL where the entity lists its immediate subordinates' Entity
    /// IDs. Optional; present on superior entities that publish a
    /// listing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_list_endpoint: Option<String>,
    /// URL where the entity exposes its trust-mark status endpoint
    /// (§7.5). Present on trust-mark issuers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_trust_mark_status_endpoint: Option<String>,
    /// URL of the entity's resolve endpoint (§9.4). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_resolve_endpoint: Option<String>,
    /// Free-form organisation name shown in admin UIs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
    /// Free-form contact addresses for operator outreach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,
    /// URL of the entity's homepage / policy page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage_uri: Option<String>,
}

/// Opaque metadata-policy block. The seven operators are unpacked by
/// [`crate::apply_block_policy`] / [`crate::apply_field_policy`];
/// until then the policy travels through as JSON so a trust-chain
/// resolver can carry it for later application.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MetadataPolicy(pub serde_json::Value);

/// Sign an entity statement with the given key + algorithm. Produces
/// a compact-JWS string suitable for serving at
/// `/.well-known/openid-federation` or returning from the federation
/// fetch endpoint.
///
/// The JWS header is stamped with `typ = "entity-statement+jwt"`
/// (mandatory per §3) and the supplied `kid` (mandatory: the verifier
/// MUST resolve the right key from the issuer's jwks). The algorithm
/// is validated against the OIDF allowlist; symmetric algorithms are
/// rejected on principle.
pub fn sign_entity_statement(
    claims: &EntityStatementClaims,
    key: &EncodingKey,
    alg: Algorithm,
    kid: impl Into<String>,
) -> FederationResult<String> {
    if !ALLOWED_ALGORITHMS.contains(&alg) {
        return Err(FederationError::AlgorithmNotAllowed(format!("{alg:?}")));
    }
    let mut header = Header::new(alg);
    header.typ = Some(ENTITY_STATEMENT_TYP.to_string());
    header.kid = Some(kid.into());
    jsonwebtoken::encode(&header, claims, key)
        .map_err(|e| FederationError::EncodeFailed(e.to_string()))
}

/// Verify an entity statement against the supplied trust anchor's key
/// set. Returns the parsed [`EntityStatement`] on success.
///
/// Verification steps (in order):
/// 1. Decode the JWS header (no signature check yet) to read `typ` +
///    `kid`.
/// 2. Reject when `typ != "entity-statement+jwt"`.
/// 3. Reject when `kid` is missing.
/// 4. Pick the matching key from `verifier_keys` by `kid`; reject
///    when no key matches.
/// 5. Decode + verify the signature with the picked key.
/// 6. Read the claims and validate the required-field set (`iss`,
///    `sub`, `iat`, `exp`, `jwks`). Missing fields surface as typed
///    [`FederationError::MissingClaim`].
/// 7. Standard `iat` + `exp` validation runs inside `jsonwebtoken`
///    (5-minute leeway for clock skew).
///
/// The caller is responsible for picking the right `verifier_keys`:
/// * For a self-signed Entity Configuration (§9): pass the issuer's
///   own jwks (fetched from a trusted location or pre-configured as a
///   trust anchor).
/// * For a Subordinate Statement: pass the superior's jwks (resolved
///   one step up the trust chain).
///
/// Every call emits a `sbproxy_federation_entity_statement_verifications_total`
/// counter tick and a structured decision-event log line (target
/// `sbproxy_federation::decision`, `event =
/// "federation_entity_statement_decision"`) so an operator can audit
/// every verification this process performed without re-deriving it
/// from raw JWS traffic; see `docs/federation.md`.
pub fn verify_entity_statement(
    compact_jws: &str,
    verifier_keys: &FederationKeySet,
) -> FederationResult<EntityStatement> {
    let result = verify_entity_statement_inner(compact_jws, verifier_keys);
    match &result {
        Ok(stmt) => {
            crate::metrics::record_entity_statement_verification("verified");
            tracing::info!(
                target: "sbproxy_federation::decision",
                event = "federation_entity_statement_decision",
                outcome = "verified",
                iss = %stmt.claims.iss,
                sub = %stmt.claims.sub,
                self_signed = stmt.claims.is_self_signed(),
                "entity statement verified"
            );
        }
        Err(err) => {
            crate::metrics::record_entity_statement_verification("rejected");
            tracing::warn!(
                target: "sbproxy_federation::decision",
                event = "federation_entity_statement_decision",
                outcome = "rejected",
                error = %err,
                "entity statement rejected"
            );
        }
    }
    result
}

fn verify_entity_statement_inner(
    compact_jws: &str,
    verifier_keys: &FederationKeySet,
) -> FederationResult<EntityStatement> {
    // Step 1: header peek.
    let header = jsonwebtoken::decode_header(compact_jws)
        .map_err(|_| FederationError::VerificationFailed)?;
    if !ALLOWED_ALGORITHMS.contains(&header.alg) {
        return Err(FederationError::AlgorithmNotAllowed(format!(
            "{:?}",
            header.alg
        )));
    }
    // Step 2: typ check.
    if header.typ.as_deref() != Some(ENTITY_STATEMENT_TYP) {
        return Err(FederationError::WrongTyp(header.typ));
    }
    // Step 3: kid check.
    let kid = header.kid.ok_or(FederationError::MissingKid)?;
    // Step 4 + 5: key lookup + signature verification.
    let key = verifier_keys.decoding_key_for_algorithm(&kid, header.alg)?;
    let mut validation = Validation::new(header.alg);
    validation.algorithms = vec![header.alg];
    // OIDF does not mandate aud / iss validation on the JWS layer; the
    // trust-chain validator handles iss + sub semantics. Standard
    // exp / iat checks stay enabled with the jsonwebtoken default
    // 0s leeway widened to 5 minutes so a typical clock skew does
    // not invalidate a fresh statement.
    validation.leeway = 300;
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let decoded = jsonwebtoken::decode::<serde_json::Value>(compact_jws, &key, &validation)
        .map_err(|_| FederationError::VerificationFailed)?;
    for required in ["iss", "sub", "iat", "exp", "jwks"] {
        if decoded.claims.get(required).is_none() {
            return Err(FederationError::MissingClaim(required));
        }
    }
    let claims: EntityStatementClaims = serde_json::from_value(decoded.claims)
        .map_err(|_| FederationError::VerificationFailed)?;
    // Step 6: required-field checks. jsonwebtoken's serde decode
    // already enforces that the fields are present; the explicit
    // checks below surface typed errors for the empty-string edge
    // case which the type system allows but the spec rejects.
    if claims.iss.is_empty() {
        return Err(FederationError::MissingClaim("iss"));
    }
    if claims.sub.is_empty() {
        return Err(FederationError::MissingClaim("sub"));
    }
    if claims.jwks.keys.is_empty() {
        return Err(FederationError::MissingClaim("jwks"));
    }
    let now = chrono::Utc::now().timestamp();
    if claims.iat > now.saturating_add(validation.leeway as i64) || claims.exp <= claims.iat {
        return Err(FederationError::VerificationFailed);
    }
    Ok(EntityStatement {
        claims,
        compact_jws: compact_jws.to_string(),
    })
}

/// Inspect a compact-JWS entity statement and return its parsed
/// claims WITHOUT verifying the signature. The trust-chain
/// validator and the chain composer use this to peek at the
/// leaf's `iss` / `sub` / `jwks` / `authority_hints` so they can
/// verify against the right key set / pick the right superior
/// before paying the signature check.
///
/// Returns the opaque [`FederationError::VerificationFailed`]
/// when the JWS cannot be decoded; leaking the parse-step
/// distinction would help a forger tune the next attempt.
pub fn peek_claims_pub(compact_jws: &str) -> FederationResult<EntityStatementClaims> {
    use base64::Engine;
    let parts: Vec<&str> = compact_jws.split('.').collect();
    if parts.len() != 3 {
        return Err(FederationError::VerificationFailed);
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| FederationError::VerificationFailed)?;
    serde_json::from_slice::<EntityStatementClaims>(&payload_bytes)
        .map_err(|_| FederationError::VerificationFailed)
}

// The decoder uses jsonwebtoken's DecodingKey constructed in
// `FederationKeySet::decoding_key_for`. We do not need a separate
// constructor here.
#[allow(dead_code)]
fn _ensure_decoding_key_import_lives() -> Option<DecodingKey> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Mint a fresh ES256 keypair for the round-trip tests. p256 + the
    /// `pkcs8`/`pem` features give us a PKCS#8 PEM `jsonwebtoken` can
    /// load; the matching JWK is derived from the public point.
    fn mint_es256_keypair() -> (EncodingKey, serde_json::Value) {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePrivateKey;
        let signing = SigningKey::random(&mut rand::thread_rng());
        let pem = signing.to_pkcs8_pem(Default::default()).unwrap();
        let encoding = EncodingKey::from_ec_pem(pem.as_bytes()).expect("PKCS#8 EC PEM");
        let verifying = signing.verifying_key();
        let encoded_point = verifying.to_encoded_point(false);
        let x = encoded_point.x().unwrap().to_vec();
        let y = encoded_point.y().unwrap().to_vec();
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&y),
            "kid": "test-key-1",
        });
        (encoding, jwk)
    }

    /// Build a minimal valid claims set for an Entity Configuration
    /// (iss == sub) issued by a fixture entity.
    fn sample_claims(jwk: serde_json::Value) -> EntityStatementClaims {
        let mut keys = FederationKeySet::empty();
        keys.push(jwk);
        let now = chrono::Utc::now().timestamp();
        EntityStatementClaims {
            iss: "https://acme.example".to_string(),
            sub: "https://acme.example".to_string(),
            iat: now,
            exp: now + 86_400, // 24h
            jwks: keys,
            authority_hints: vec!["https://trust-anchor.example".to_string()],
            metadata: EntityMetadata {
                federation_entity: Some(FederationEntityMetadata {
                    organization_name: Some("Acme Corp".to_string()),
                    contacts: vec!["security@acme.example".to_string()],
                    ..Default::default()
                }),
                other: HashMap::new(),
            },
            metadata_policy: None,
            trust_marks: Vec::new(),
        }
    }

    /// Happy path: sign + verify round-trip with a freshly-minted
    /// ES256 keypair returns the original claims byte-for-byte.
    #[test]
    fn sign_verify_round_trip_es256() {
        let (key, jwk) = mint_es256_keypair();
        let claims = sample_claims(jwk.clone());
        let jws =
            sign_entity_statement(&claims, &key, Algorithm::ES256, "test-key-1").expect("sign");
        // Verifier key set: trust anchor publishes the same JWK.
        let mut trust_keys = FederationKeySet::empty();
        trust_keys.push(jwk);
        let verified = verify_entity_statement(&jws, &trust_keys).expect("verify");
        assert_eq!(verified.claims.iss, claims.iss);
        assert_eq!(verified.claims.sub, claims.sub);
        assert_eq!(verified.claims.iat, claims.iat);
        assert!(verified.claims.is_self_signed());
        assert_eq!(verified.compact_jws, jws);
    }

    /// `typ` header missing on the signed JWS: a regular access
    /// token wrapped in a federation surface MUST be rejected.
    #[test]
    fn typ_missing_rejected() {
        let (key, jwk) = mint_es256_keypair();
        let claims = sample_claims(jwk.clone());
        // Bypass `sign_entity_statement` so we can produce a JWS
        // without the typ header.
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("test-key-1".to_string());
        let jws = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        let mut trust_keys = FederationKeySet::empty();
        trust_keys.push(jwk);
        let err = verify_entity_statement(&jws, &trust_keys).unwrap_err();
        assert!(matches!(err, FederationError::WrongTyp(_)));
    }

    /// `kid` header missing: the verifier cannot pick the right key
    /// from the issuer's jwks, so the JWS MUST be rejected.
    #[test]
    fn kid_missing_rejected() {
        let (key, jwk) = mint_es256_keypair();
        let claims = sample_claims(jwk.clone());
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(ENTITY_STATEMENT_TYP.to_string());
        let jws = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        let mut trust_keys = FederationKeySet::empty();
        trust_keys.push(jwk);
        let err = verify_entity_statement(&jws, &trust_keys).unwrap_err();
        assert!(matches!(err, FederationError::MissingKid));
    }

    /// `kid` does not match any key in the trust-anchor jwks: an
    /// attacker cannot smuggle a statement signed by a different key.
    #[test]
    fn unknown_kid_rejected() {
        let (key, jwk) = mint_es256_keypair();
        let claims = sample_claims(jwk.clone());
        let jws = sign_entity_statement(&claims, &key, Algorithm::ES256, "wrong-kid").unwrap();
        let mut trust_keys = FederationKeySet::empty();
        trust_keys.push(jwk);
        let err = verify_entity_statement(&jws, &trust_keys).unwrap_err();
        assert!(matches!(err, FederationError::UnknownKid(k) if k == "wrong-kid"));
    }

    /// Signature mismatch: a statement signed by one key cannot be
    /// validated against a different key set.
    #[test]
    fn signature_mismatch_rejected() {
        let (key_a, _) = mint_es256_keypair();
        let (_, jwk_b) = mint_es256_keypair();
        let claims = sample_claims(jwk_b.clone());
        // Sign with key_a (its public half is NOT in the trust set).
        let jws = sign_entity_statement(&claims, &key_a, Algorithm::ES256, "test-key-1").unwrap();
        let mut trust_keys = FederationKeySet::empty();
        trust_keys.push(jwk_b);
        let err = verify_entity_statement(&jws, &trust_keys).unwrap_err();
        // The verifier rejects with the opaque "verification failed"
        // shape: leaking which step failed (signature vs alg vs kid)
        // would help an attacker tune their forgery.
        assert!(matches!(err, FederationError::VerificationFailed));
    }

    /// HS256 (symmetric) is rejected at sign time. An entity
    /// statement MUST be verifiable by any peer holding the issuer's
    /// public key; symmetric secrets break the federation trust model.
    #[test]
    fn symmetric_algorithm_rejected_at_sign() {
        let (_, jwk) = mint_es256_keypair();
        let claims = sample_claims(jwk);
        let key = EncodingKey::from_secret(b"secret");
        let err = sign_entity_statement(&claims, &key, Algorithm::HS256, "test-key-1").unwrap_err();
        assert!(matches!(err, FederationError::AlgorithmNotAllowed(_)));
    }

    /// `is_self_signed` distinguishes an Entity Configuration (iss ==
    /// sub) from a Subordinate Statement (iss != sub).
    #[test]
    fn is_self_signed_predicate() {
        let (_, jwk) = mint_es256_keypair();
        let mut claims = sample_claims(jwk);
        assert!(claims.is_self_signed());
        claims.sub = "https://subordinate.example".to_string();
        assert!(!claims.is_self_signed());
    }

    /// Empty jwks: the spec requires the issuer publish at least one
    /// key for downstream verifiers to use. An empty set is a
    /// misconfiguration the verifier MUST surface rather than allow
    /// through.
    #[test]
    fn empty_jwks_rejected() {
        let (key, jwk) = mint_es256_keypair();
        let mut claims = sample_claims(jwk.clone());
        claims.jwks = FederationKeySet::empty();
        let jws = sign_entity_statement(&claims, &key, Algorithm::ES256, "test-key-1").unwrap();
        let mut trust_keys = FederationKeySet::empty();
        trust_keys.push(jwk);
        let err = verify_entity_statement(&jws, &trust_keys).unwrap_err();
        assert!(matches!(err, FederationError::MissingClaim("jwks")));
    }

    /// The verifier owns the algorithm policy. It must reject a
    /// symmetric header before looking up the attacker-selected `kid`.
    #[test]
    fn security_boundary_entity_verifier_rejects_an_algorithm_outside_the_allowlist() {
        let (_, jwk) = mint_es256_keypair();
        let claims = sample_claims(jwk);
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some(ENTITY_STATEMENT_TYP.to_string());
        header.kid = Some("attacker-selected-kid".to_string());
        let jws = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(b"secret"))
            .expect("encode adversarial JWS");

        let err = verify_entity_statement(&jws, &FederationKeySet::empty())
            .expect_err("an attacker-selected algorithm must be rejected");
        assert!(matches!(err, FederationError::AlgorithmNotAllowed(_)));
    }

    /// A JWK that declares a different algorithm cannot be used merely
    /// because its curve happens to verify the header-selected algorithm.
    #[test]
    fn security_boundary_entity_verifier_binds_the_header_algorithm_to_the_jwk() {
        let (key, mut jwk) = mint_es256_keypair();
        let claims = sample_claims(jwk.clone());
        let jws = sign_entity_statement(&claims, &key, Algorithm::ES256, "test-key-1").unwrap();
        jwk["alg"] = serde_json::json!("ES384");
        let mut trust_keys = FederationKeySet::empty();
        trust_keys.push(jwk);

        verify_entity_statement(&jws, &trust_keys)
            .expect_err("a JWK alg/header alg mismatch must be rejected");
    }

    /// Encryption-only JWKs are not eligible to verify entity statements.
    #[test]
    fn security_boundary_entity_verifier_rejects_an_encryption_only_jwk() {
        let (key, mut jwk) = mint_es256_keypair();
        let claims = sample_claims(jwk.clone());
        let jws = sign_entity_statement(&claims, &key, Algorithm::ES256, "test-key-1").unwrap();
        jwk["use"] = serde_json::json!("enc");
        let mut trust_keys = FederationKeySet::empty();
        trust_keys.push(jwk);

        verify_entity_statement(&jws, &trust_keys)
            .expect_err("an encryption-only JWK must not verify a signature");
    }

    fn entity_jws_without_claim(claim: &'static str) -> (String, FederationKeySet) {
        let (key, jwk) = mint_es256_keypair();
        let claims = sample_claims(jwk.clone());
        let mut payload = serde_json::to_value(claims).unwrap();
        payload
            .as_object_mut()
            .expect("claims serialize as an object")
            .remove(claim);
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(ENTITY_STATEMENT_TYP.to_string());
        header.kid = Some("test-key-1".to_string());
        let jws = jsonwebtoken::encode(&header, &payload, &key).unwrap();
        let mut trust_keys = FederationKeySet::empty();
        trust_keys.push(jwk);
        (jws, trust_keys)
    }

    /// Missing temporal claims are typed protocol failures rather than
    /// opaque decode failures.
    #[test]
    fn security_boundary_entity_verifier_requires_iat() {
        let (jws, trust_keys) = entity_jws_without_claim("iat");
        let err = verify_entity_statement(&jws, &trust_keys).unwrap_err();
        assert!(matches!(err, FederationError::MissingClaim("iat")));
    }

    #[test]
    fn security_boundary_entity_verifier_requires_exp() {
        let (jws, trust_keys) = entity_jws_without_claim("exp");
        let err = verify_entity_statement(&jws, &trust_keys).unwrap_err();
        assert!(matches!(err, FederationError::MissingClaim("exp")));
    }

    /// A statement issued beyond the five-minute skew allowance is not
    /// valid yet, even when its expiry and signature are otherwise valid.
    #[test]
    fn security_boundary_entity_verifier_rejects_a_future_iat() {
        let (key, jwk) = mint_es256_keypair();
        let mut claims = sample_claims(jwk.clone());
        let now = chrono::Utc::now().timestamp();
        claims.iat = now + 3600;
        claims.exp = now + 7200;
        let jws = sign_entity_statement(&claims, &key, Algorithm::ES256, "test-key-1").unwrap();
        let mut trust_keys = FederationKeySet::empty();
        trust_keys.push(jwk);

        verify_entity_statement(&jws, &trust_keys)
            .expect_err("a future-issued statement must be rejected");
    }
}
