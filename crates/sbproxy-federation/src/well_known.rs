//! OpenID Federation 1.0 §9 well-known entity-configuration issuer.
//!
//! An entity that participates in a federation MUST publish a
//! self-signed Entity Configuration at
//! `/.well-known/openid-federation`. This is the same shape as a §3
//! Entity Statement, with `iss == sub`. Peers fetch this document to
//! pick up the entity's current keys, metadata, authority hints, and
//! trust marks before they can validate any subordinate statement
//! the entity signs.
//!
//! ## Why this lives in the crate, not the HTTP layer
//!
//! The HTTP layer's job is wire-up: parse the request, set the
//! response media type, return the bytes. The interesting work
//! (load the signing key, build the §3 claim set, sign with the
//! mandatory `typ` header, cache the result so concurrent requests
//! do not re-sign per call) is pure compute and belongs with the
//! rest of the federation primitives. By exposing the issuer here
//! as a self-contained `WellKnownIssuer::current()` call, a gateway,
//! a control-plane HTTP server, an operator CLI, or a test fixture
//! can all reuse the same code without pulling in axum / hyper /
//! Pingora through the rest of this crate (only [`crate::http_route`]
//! and [`crate::router`] pull in axum).
//!
//! ## Cache shape
//!
//! [`WellKnownIssuer`] keeps the current compact-JWS string in an
//! `RwLock<Option<EntityConfigurationDocument>>`, plain in-process
//! memory with no external cache service. `current()` returns the cached
//! value when it is still valid (i.e. more than the configured
//! refresh margin away from `exp`); otherwise it re-signs under a
//! write lock. Re-signing is cheap (a few millis for ES256) so the
//! lock contention is acceptable for a request rate any operator
//! would put behind a single proxy instance.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey};
use serde::{Deserialize, Serialize};

use crate::entity_statement::{
    sign_entity_statement, EntityMetadata, EntityStatementClaims, MetadataPolicy,
};
use crate::errors::{FederationError, FederationResult};
use crate::jwk::FederationKeySet;

/// Operator-supplied configuration for the well-known issuer.
///
/// This is the typed input the operator provides at startup (from
/// `sbproxy-config`, or from an admin API in a future revision). The
/// issuer takes this once at construction and re-signs from it on
/// every refresh.
#[derive(Debug, Clone)]
pub struct FederationServerConfig {
    /// Entity URL the issuer advertises as both `iss` and `sub` (§9
    /// entity configurations are self-signed). Operators set this to
    /// the externally-resolvable origin of the proxy, e.g.
    /// `https://gateway.acme.example`.
    pub entity_id: String,
    /// The signing key the issuer signs the entity configuration
    /// with. The same key MUST appear (as its public half) under
    /// `published_jwks` so peers can verify.
    pub signing_key: SigningKeyConfig,
    /// JWKS published in the `jwks` claim. The issuer signs with the
    /// private half of one of these keys; the verifier picks the
    /// right key by `kid`. Multiple keys are supported so an operator
    /// can publish both their current key and a roll-over key during
    /// a rotation window.
    pub published_jwks: FederationKeySet,
    /// Entity-type metadata blocks (federation_entity, openid_provider,
    /// openid_relying_party, oauth_authorization_server, oauth_client).
    /// Today only `federation_entity` is strongly typed; the others
    /// pass through as opaque JSON (see [`EntityMetadata::other`]).
    pub metadata: EntityMetadata,
    /// URLs of immediate superiors of this entity in the federation.
    /// [`crate::TrustChainResolver`] follows these (via
    /// [`crate::compose_trust_chain`]) to a configured trust anchor.
    /// Leaves keep this empty.
    pub authority_hints: Vec<String>,
    /// Trust marks this entity claims. Opaque JSON here; see
    /// [`crate::trust_marks`] for the strongly-typed sign/verify
    /// shape.
    pub trust_marks: Vec<serde_json::Value>,
    /// Opaque metadata policy block this entity imposes on its
    /// subordinates. `None` for non-intermediates. The seven
    /// operators are unpacked by [`crate::apply_block_policy`].
    pub metadata_policy: Option<MetadataPolicy>,
    /// Lifetime of each signed configuration. The spec is silent on
    /// a recommended value; production deployments commonly pick 24
    /// hours so a compromised key has a bounded blast radius. The
    /// issuer re-signs on the next `current()` call after the
    /// remaining lifetime drops below [`Self::refresh_margin`].
    pub lifetime: Duration,
    /// How early to re-sign before the cached configuration would
    /// expire. Picking ~10 percent of `lifetime` (e.g. ~2 h 24 m for
    /// a 24 h lifetime) gives every cache (peers, CDNs) a safe
    /// window to fetch the new document before the old one expires.
    pub refresh_margin: Duration,
}

/// Signing-key inputs the issuer needs to produce the compact JWS.
/// Split from the rest of the config so an operator can express
/// "I gave you the PEM bytes plus a `kid` to advertise" without
#[derive(Clone)]
pub struct SigningKeyConfig {
    /// The PEM-encoded private key. EC keys MUST be PKCS#8 (the
    /// `jsonwebtoken` loader rejects SEC1).
    pub pem: Vec<u8>,
    /// Algorithm slug for the JWS header.
    pub algorithm: Algorithm,
    /// `kid` stamped on the JWS header.
    pub kid: String,
}

impl std::fmt::Debug for SigningKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyConfig")
            .field("pem", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("kid", &self.kid)
            .finish()
    }
}

/// Result of a `current()` call: the cached compact JWS plus the
/// (parsed-once-at-sign-time) `exp` so the caller can stamp HTTP
/// `Cache-Control: max-age` without re-parsing the JWS.
#[derive(Clone)]
pub struct EntityConfigurationDocument {
    /// Original compact entity-statement JWS served on the wire.
    pub compact_jws: String,
    /// Wall-clock instant stamped into the JWS `iat` claim.
    pub issued_at: DateTime<Utc>,
    /// Wall-clock instant stamped into the JWS `exp` claim.
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for EntityConfigurationDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityConfigurationDocument")
            .field("compact_jws", &"[REDACTED]")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl EntityConfigurationDocument {
    /// Seconds remaining until expiry. Saturates to 0 when the
    /// document is already past `exp`.
    pub fn remaining_lifetime(&self, now: DateTime<Utc>) -> Duration {
        let secs = (self.expires_at - now).num_seconds();
        if secs <= 0 {
            Duration::ZERO
        } else {
            Duration::from_secs(secs as u64)
        }
    }

    /// HTTP `Cache-Control: max-age` value (in seconds) a responder
    /// should stamp on a response carrying this document. Computed
    /// off the document's remaining lifetime so a cache stops
    /// serving the value at the same instant the document expires.
    pub fn cache_max_age_secs(&self, now: DateTime<Utc>) -> u64 {
        self.remaining_lifetime(now).as_secs()
    }
}

/// Stateful issuer of the well-known entity configuration. Caches
/// the current compact JWS until shortly before `exp`, then re-signs
/// on the next `current()` call.
///
/// Thread-safe via [`std::sync::RwLock`]: concurrent readers go
/// through a shared lock; the one writer that crosses the
/// refresh-margin grabs the exclusive lock briefly to re-sign. Stale
/// reads inside the refresh margin are intentional: every cached
/// document is still cryptographically valid until `exp`, and a
/// short window of "old but valid" reduces lock contention under
/// load.
///
/// A poisoned cache is recovered with [`PoisonError::into_inner`]
/// rather than unwrapped. The guarded value is one whole
/// [`EntityConfigurationDocument`] replaced by a single assignment
/// under the write lock, so a panic in another thread cannot leave a
/// half-signed document behind, and the freshness check on the way
/// out rejects anything past its refresh margin regardless. Ending
/// the process instead would take the whole proxy down because one
/// request panicked while re-signing.
pub struct WellKnownIssuer {
    config: FederationServerConfig,
    cached: RwLock<Option<EntityConfigurationDocument>>,
    encoding_key: EncodingKey,
}

impl WellKnownIssuer {
    /// Build the issuer from operator config. Returns a typed error
    /// when the supplied PEM does not parse as the requested
    /// algorithm's key shape.
    /// Also verifies, once, that the key this issuer signs with is a
    /// key `published_jwks` actually publishes. The invariant was
    /// stated on [`SigningKeyConfig`] and enforced by nothing: an
    /// operator who rotated `kid` and forgot the JWKS served HTTP 200
    /// with a well-formed JWS that every peer rejected with
    /// `UnknownKid`, for the whole document lifetime, with nothing on
    /// this side going red. Signing a throwaway statement and running
    /// the crate's own verifier over it is the cheapest way to be sure,
    /// and it costs one signature at startup.
    pub fn new(config: FederationServerConfig) -> FederationResult<Self> {
        let encoding_key = load_encoding_key(&config.signing_key)?;
        let issuer = Self {
            config,
            cached: RwLock::new(None),
            encoding_key,
        };
        let document = issuer.current()?;
        crate::verify_entity_statement(&document.compact_jws, &issuer.config.published_jwks)?;
        Ok(issuer)
    }

    /// Borrow the operator-supplied config, mainly for tests that
    /// want to assert what was loaded.
    pub fn config(&self) -> &FederationServerConfig {
        &self.config
    }

    /// Return the current entity configuration. Re-signs when the
    /// cached document is None or its remaining lifetime has dropped
    /// below [`FederationServerConfig::refresh_margin`].
    ///
    /// Use this from the HTTP handler that serves
    /// `/.well-known/openid-federation` (see
    /// [`crate::entity_configuration_handler`]). The returned
    /// document's `compact_jws` is what the response body MUST be;
    /// the `expires_at` is what the response's `Cache-Control:
    /// max-age` should reflect.
    pub fn current(&self) -> FederationResult<Arc<EntityConfigurationDocument>> {
        self.current_at(Utc::now())
    }

    /// Test-only variant of [`Self::current`] that takes the
    /// observed "now" explicitly. Pinning the time keeps the
    /// refresh-boundary tests deterministic.
    pub fn current_at(
        &self,
        now: DateTime<Utc>,
    ) -> FederationResult<Arc<EntityConfigurationDocument>> {
        if let Some(doc) = self.peek_fresh(now) {
            return Ok(doc);
        }
        self.refresh(now)
    }

    /// Borrow the cached doc through a shared read lock. Returns
    /// `Some` only when the cached doc is still outside the refresh
    /// margin; `None` triggers a re-sign in `current_at`.
    fn peek_fresh(&self, now: DateTime<Utc>) -> Option<Arc<EntityConfigurationDocument>> {
        let guard = self.cached.read().unwrap_or_else(PoisonError::into_inner);
        let doc = guard.as_ref()?;
        let remaining = doc.remaining_lifetime(now);
        if remaining > self.config.refresh_margin {
            Some(Arc::new(doc.clone()))
        } else {
            None
        }
    }

    /// Re-sign and replace the cache. Held under the exclusive
    /// write lock; double-check the cache after acquiring the lock
    /// so two concurrent refresh requests only sign once.
    fn refresh(&self, now: DateTime<Utc>) -> FederationResult<Arc<EntityConfigurationDocument>> {
        let mut guard = self.cached.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(doc) = guard.as_ref() {
            if doc.remaining_lifetime(now) > self.config.refresh_margin {
                return Ok(Arc::new(doc.clone()));
            }
        }
        let lifetime_secs = self.config.lifetime.as_secs() as i64;
        let issued_at = now;
        let expires_at = issued_at + chrono::Duration::seconds(lifetime_secs);
        let claims = EntityStatementClaims {
            iss: self.config.entity_id.clone(),
            sub: self.config.entity_id.clone(),
            iat: issued_at.timestamp(),
            exp: expires_at.timestamp(),
            jwks: self.config.published_jwks.clone(),
            authority_hints: self.config.authority_hints.clone(),
            metadata: self.config.metadata.clone(),
            metadata_policy: self.config.metadata_policy.clone(),
            trust_marks: self.config.trust_marks.clone(),
        };
        let compact_jws = sign_entity_statement(
            &claims,
            &self.encoding_key,
            self.config.signing_key.algorithm,
            self.config.signing_key.kid.clone(),
        )?;
        let doc = EntityConfigurationDocument {
            compact_jws,
            issued_at,
            expires_at,
        };
        *guard = Some(doc.clone());
        Ok(Arc::new(doc))
    }
}

/// Lift the operator's PEM bytes to a `jsonwebtoken::EncodingKey`
/// for the requested algorithm. Returns a typed
/// [`FederationError::InvalidSigningKey`] when the PEM does not
/// match the algorithm family.
fn load_encoding_key(key: &SigningKeyConfig) -> FederationResult<EncodingKey> {
    match key.algorithm {
        Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(&key.pem),
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => EncodingKey::from_rsa_pem(&key.pem),
        Algorithm::EdDSA => EncodingKey::from_ed_pem(&key.pem),
        other => {
            return Err(FederationError::AlgorithmNotAllowed(format!("{other:?}")));
        }
    }
    .map_err(|e| FederationError::InvalidSigningKey(e.to_string()))
}

// The Cache-Control max-age value sits naturally as a `u64` (seconds)
// rather than a `Duration`; HTTP serialises it as an integer per
// RFC 9111. This serde-friendly shadow type keeps the integer
// representation when an operator wants to surface the value in
// telemetry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
#[allow(dead_code)]
struct MaxAgeSeconds(u64);

impl From<Duration> for MaxAgeSeconds {
    fn from(d: Duration) -> Self {
        MaxAgeSeconds(d.as_secs())
    }
}

impl From<SystemTime> for MaxAgeSeconds {
    fn from(t: SystemTime) -> Self {
        MaxAgeSeconds(
            t.duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_statement::FederationEntityMetadata;
    use crate::{verify_entity_statement, ENTITY_STATEMENT_TYP};
    use base64::Engine;

    /// Mint a fresh ES256 keypair + a matching JWK so the well-known
    /// issuer can sign + the test can verify in the same process.
    fn fixture_key_and_jwk(kid: &str) -> (Vec<u8>, serde_json::Value) {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePrivateKey;
        let signing = SigningKey::random(&mut rand::thread_rng());
        let pem = signing.to_pkcs8_pem(Default::default()).unwrap();
        let verifying = signing.verifying_key();
        let encoded_point = verifying.to_encoded_point(false);
        let x = encoded_point.x().unwrap().to_vec();
        let y = encoded_point.y().unwrap().to_vec();
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&y),
            "kid": kid,
        });
        (pem.as_bytes().to_vec(), jwk)
    }

    fn sample_config(
        kid: &str,
        lifetime: Duration,
        refresh_margin: Duration,
    ) -> FederationServerConfig {
        let (pem, jwk) = fixture_key_and_jwk(kid);
        let mut keys = FederationKeySet::empty();
        keys.push(jwk);
        FederationServerConfig {
            entity_id: "https://gateway.acme.example".to_string(),
            signing_key: SigningKeyConfig {
                pem,
                algorithm: Algorithm::ES256,
                kid: kid.to_string(),
            },
            published_jwks: keys,
            metadata: EntityMetadata {
                federation_entity: Some(FederationEntityMetadata {
                    organization_name: Some("Acme Corp".to_string()),
                    ..Default::default()
                }),
                other: Default::default(),
            },
            authority_hints: vec!["https://trust-anchor.example".to_string()],
            trust_marks: Vec::new(),
            metadata_policy: None,
            lifetime,
            refresh_margin,
        }
    }

    /// Happy path: `current()` produces a verifiable JWS with the
    /// operator's claims. The trust anchor's key set is the same
    /// `published_jwks` the issuer signed with, which mirrors the
    /// §9 self-signed-configuration trust model.
    #[test]
    fn current_returns_verifiable_jws() {
        let issuer = WellKnownIssuer::new(sample_config(
            "key-2026",
            Duration::from_secs(3600),
            Duration::from_secs(360),
        ))
        .expect("issuer");
        let doc = issuer.current().expect("current");
        // The cached compact JWS must parse + verify against the
        // issuer's own jwks (self-signed entity configuration).
        let parsed = verify_entity_statement(&doc.compact_jws, &issuer.config.published_jwks)
            .expect("verify");
        assert_eq!(parsed.claims.iss, issuer.config.entity_id);
        assert_eq!(parsed.claims.sub, issuer.config.entity_id);
        assert!(parsed.claims.is_self_signed());
        assert_eq!(
            parsed.claims.authority_hints,
            vec!["https://trust-anchor.example".to_string()]
        );
    }

    /// Successive `current()` calls within the refresh window
    /// return the SAME cached compact JWS, byte-for-byte. The cache
    /// holds the on-the-wire bytes so a peer fetching the well-known
    /// endpoint twice sees a stable Etag-equivalent value.
    #[test]
    fn current_returns_cached_value_within_window() {
        let issuer = WellKnownIssuer::new(sample_config(
            "key-2026",
            Duration::from_secs(3600),
            Duration::from_secs(360),
        ))
        .expect("issuer");
        let a = issuer.current().expect("first");
        let b = issuer.current().expect("second");
        assert_eq!(a.compact_jws, b.compact_jws);
        assert_eq!(a.issued_at, b.issued_at);
        assert_eq!(a.expires_at, b.expires_at);
    }

    /// Once the cached document's remaining lifetime drops below the
    /// refresh margin, `current_at` re-signs and returns a NEW
    /// compact JWS (different `iat`).
    #[test]
    fn current_resigns_at_refresh_margin() {
        let lifetime = Duration::from_secs(3600);
        let refresh_margin = Duration::from_secs(360);
        let issuer = WellKnownIssuer::new(sample_config("key-2026", lifetime, refresh_margin))
            .expect("issuer");
        let t0 = Utc::now();
        let first = issuer.current_at(t0).expect("first");
        // Step inside the refresh margin: lifetime - refresh_margin = 3240s.
        // Advance 3300s so remaining = 300s < 360s margin.
        let t1 = t0 + chrono::Duration::seconds(3300);
        let second = issuer.current_at(t1).expect("second");
        assert_ne!(
            first.compact_jws, second.compact_jws,
            "cached JWS should have been re-signed past the refresh margin"
        );
        assert!(
            second.issued_at > first.issued_at,
            "re-signed doc must have a later iat"
        );
    }

    /// `remaining_lifetime` saturates to zero past `exp`. Without
    /// this, an i64 subtraction across the boundary could underflow
    /// or surface as a wildly large unsigned value.
    #[test]
    fn remaining_lifetime_saturates_past_exp() {
        let issuer = WellKnownIssuer::new(sample_config(
            "key-2026",
            Duration::from_secs(60),
            Duration::from_secs(10),
        ))
        .expect("issuer");
        let t0 = Utc::now();
        let doc = issuer.current_at(t0).expect("doc");
        let way_past = t0 + chrono::Duration::seconds(3600);
        assert_eq!(doc.remaining_lifetime(way_past), Duration::ZERO);
        assert_eq!(doc.cache_max_age_secs(way_past), 0);
    }

    /// The signed JWS header MUST carry the OIDF-mandated `typ` so a
    /// peer that pre-inspects the header rejects it as anything other
    /// than an entity statement. Re-derive the header from the
    /// compact JWS bytes (not from the cached struct) to guarantee
    /// the on-the-wire shape is right.
    #[test]
    fn signed_jws_header_has_oidf_typ_and_kid() {
        let issuer = WellKnownIssuer::new(sample_config(
            "key-2026",
            Duration::from_secs(3600),
            Duration::from_secs(360),
        ))
        .expect("issuer");
        let doc = issuer.current().expect("doc");
        let header = jsonwebtoken::decode_header(&doc.compact_jws).expect("decode header");
        assert_eq!(header.typ.as_deref(), Some(ENTITY_STATEMENT_TYP));
        assert_eq!(header.kid.as_deref(), Some("key-2026"));
    }

    /// `cache_max_age_secs` lines up with the document's remaining
    /// lifetime. Returns seconds (the wire form) so the HTTP handler
    /// can stamp `Cache-Control: max-age=<value>` directly.
    #[test]
    fn cache_max_age_matches_remaining_lifetime() {
        let issuer = WellKnownIssuer::new(sample_config(
            "key-2026",
            Duration::from_secs(3600),
            Duration::from_secs(360),
        ))
        .expect("issuer");
        let t0 = Utc::now();
        let doc = issuer.current_at(t0).expect("doc");
        // Five minutes in, expect ~ 55 minutes remaining (3300s).
        let t1 = t0 + chrono::Duration::seconds(300);
        assert!(
            (doc.cache_max_age_secs(t1) as i64 - 3300).abs() <= 1,
            "cache max-age should be ~3300s, got {}",
            doc.cache_max_age_secs(t1)
        );
    }

    /// A bogus PEM surfaces as a typed `InvalidSigningKey` rather
    /// than a panic. The operator gets a useful error message
    /// instead of a backtrace when they paste in the wrong key.
    #[test]
    fn a_signing_kid_absent_from_published_jwks_is_refused_at_construction() {
        // The rotation mistake: `kid` moved, the JWKS did not. Nothing
        // on this side went red, the endpoint served HTTP 200, and
        // every peer got UnknownKid for a full document lifetime.
        let mut config = sample_config(
            "fed-2026q2",
            Duration::from_secs(3600),
            Duration::from_secs(360),
        );
        config.signing_key.kid = "fed-2026q3".to_string();
        let Err(error) = WellKnownIssuer::new(config) else {
            panic!("a key the JWKS does not publish must be refused");
        };
        assert!(
            matches!(error, FederationError::UnknownKid { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn invalid_pem_returns_typed_error() {
        let mut cfg = sample_config(
            "key-2026",
            Duration::from_secs(3600),
            Duration::from_secs(360),
        );
        cfg.signing_key.pem =
            b"-----BEGIN NOT A KEY-----\nGARBAGE\n-----END NOT A KEY-----\n".to_vec();
        let Err(err) = WellKnownIssuer::new(cfg) else {
            panic!("expected InvalidSigningKey for malformed PEM");
        };
        assert!(matches!(err, FederationError::InvalidSigningKey(_)));
    }

    /// An HS256 entry in the algorithm slot is rejected at issuer
    /// construction (the EncodingKey loader does not match), keeping
    /// symmetric-key configurations out of the federation surface.
    #[test]
    fn symmetric_algorithm_in_signing_key_rejected() {
        let mut cfg = sample_config(
            "key-2026",
            Duration::from_secs(3600),
            Duration::from_secs(360),
        );
        cfg.signing_key.algorithm = Algorithm::HS256;
        let Err(err) = WellKnownIssuer::new(cfg) else {
            panic!("expected AlgorithmNotAllowed for HS256 signing key");
        };
        assert!(matches!(err, FederationError::AlgorithmNotAllowed(_)));
    }
}
