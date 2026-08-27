//! OpenID Federation 1.0 §9.2 trust-chain validator.
//!
//! Given a sequence of compact-JWS entity statements that traces a
//! leaf entity up to a trust anchor, the validator confirms each
//! statement signs the next one in the chain and that the chain ends
//! at a configured trust anchor. The chain is the input the §9.2
//! algorithm expects after a fetcher (see [`crate::chain_composer`])
//! has walked `authority_hints` and downloaded each subordinate
//! statement.
//!
//! ## What this module ships
//!
//! * [`TrustAnchor`]: a single configured trust anchor (entity URL +
//!   the JWKS the operator trusts).
//! * [`TrustAnchorStore`]: typed collection of trust anchors keyed by
//!   entity URL. Plain in-memory `HashMap`; this crate has no
//!   database dependency.
//! * [`TrustChainResolver`]: validates a chain against the store and
//!   returns the [`ResolvedTrustChain`] with the parsed statements in
//!   leaf-to-anchor order.
//!
//! ## What this module does NOT do
//!
//! * Fetch statements over HTTP. [`crate::chain_composer`] and
//!   [`crate::http_fetcher`] own the HTTPS GET side (the leaf's own
//!   `/.well-known/openid-federation` document, and each superior's
//!   `federation_fetch_endpoint` for the subordinate statements that
//!   link the chain); this module only validates a chain it is
//!   handed.
//! * Apply metadata-policy operators. The policies travel through
//!   on each [`crate::EntityStatementClaims::metadata_policy`] claim
//!   and are returned verbatim on the resolved chain;
//!   [`crate::apply_block_policy`] and [`crate::compose_policies`]
//!   apply the seven operators.
//! * Decide WHICH trust anchor to pick when an operator configures
//!   several. The first one whose entity URL matches the chain's
//!   tail wins; OIDF leaves picking the right anchor as deployment
//!   policy.

use std::collections::HashMap;

use crate::entity_statement::{verify_entity_statement, EntityStatement, EntityStatementClaims};
use crate::errors::{FederationError, FederationResult};
use crate::jwk::FederationKeySet;

/// One trust anchor an operator has configured. The anchor is the
/// terminal authority a chain must end at: the validator never
/// proceeds past one of these, and it never trusts a chain whose
/// tail does not match any of them.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Entity URL of the anchor. MUST match the `iss` (and `sub`,
    /// since anchors are self-signed) of the chain's last statement.
    pub entity_id: String,
    /// The JWKS the operator trusts the anchor with. Pre-configured;
    /// the validator does not re-derive it from the anchor's
    /// statement (a self-signed statement can vouch for any key it
    /// likes, so an out-of-band key pin is required).
    pub jwks: FederationKeySet,
}

/// Collection of configured trust anchors. Lookups go through the
/// store rather than scanning the slice on every step so a deployment
/// with several anchors stays cheap. Held entirely in memory: this
/// crate has no Postgres/sqlx/Redis dependency, and an operator that
/// wants persistence across restarts re-supplies the anchor list at
/// startup from its own config source.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchorStore {
    by_entity_id: HashMap<String, FederationKeySet>,
}

impl TrustAnchorStore {
    /// Build an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a store from an iterator of anchors. Later entries
    /// overwrite earlier ones with the same `entity_id`, which
    /// matches how operators typically express "the most recent
    /// trust-anchor key for X overrides the older one".
    pub fn from_anchors(anchors: impl IntoIterator<Item = TrustAnchor>) -> Self {
        let mut store = Self::default();
        for a in anchors {
            store.insert(a);
        }
        store
    }

    /// Insert (or replace) a trust anchor.
    pub fn insert(&mut self, anchor: TrustAnchor) {
        self.by_entity_id.insert(anchor.entity_id, anchor.jwks);
    }

    /// Number of configured anchors.
    pub fn len(&self) -> usize {
        self.by_entity_id.len()
    }

    /// True when no anchors are configured. A resolver with an empty
    /// store rejects every chain.
    pub fn is_empty(&self) -> bool {
        self.by_entity_id.is_empty()
    }

    /// Look up the trusted JWKS for an entity URL. Returns `None`
    /// when no anchor matches.
    pub fn jwks_for(&self, entity_id: &str) -> Option<&FederationKeySet> {
        self.by_entity_id.get(entity_id)
    }
}

/// A fully-resolved trust chain, leaf-to-anchor.
#[derive(Debug, Clone)]
pub struct ResolvedTrustChain {
    /// The verified statements in leaf-to-anchor order. The first
    /// element is the leaf's self-signed Entity Configuration; the
    /// last is the anchor's self-signed configuration. Intermediate
    /// elements are Subordinate Statements signed by the next
    /// statement's issuer.
    pub statements: Vec<EntityStatement>,
    /// Entity URL of the trust anchor the chain ends at. Always
    /// matches `statements.last().claims.iss`.
    pub trust_anchor_id: String,
}

impl ResolvedTrustChain {
    /// The leaf statement (always present; a chain with zero
    /// statements would have been rejected during resolution).
    pub fn leaf(&self) -> &EntityStatement {
        &self.statements[0]
    }

    /// The anchor statement (always present).
    pub fn anchor(&self) -> &EntityStatement {
        self.statements.last().expect("non-empty chain")
    }

    /// Convenience iterator over the metadata-policy claims along
    /// the chain, in anchor-to-leaf order the policy applicator
    /// consumes to compose the seven operators.
    pub fn metadata_policies(&self) -> impl Iterator<Item = &crate::MetadataPolicy> {
        self.statements
            .iter()
            .rev()
            .filter_map(|s| s.claims.metadata_policy.as_ref())
    }
}

/// Resolver that turns a pre-fetched chain of compact-JWS entity
/// statements into a verified [`ResolvedTrustChain`].
///
/// The operator configures the resolver once with the trust-anchor
/// store + a depth cap; per-resolution input is just the chain
/// (typically built by [`crate::compose_trust_chain`]).
#[derive(Debug, Clone)]
pub struct TrustChainResolver {
    anchors: TrustAnchorStore,
    max_depth: usize,
}

impl TrustChainResolver {
    /// Build a resolver. The `max_depth` cap limits chain length
    /// including both the leaf's configuration and the anchor's
    /// configuration; OIDF deployments rarely exceed 4-5 (leaf →
    /// org → sector → root) and a much larger cap admits
    /// denial-of-service via runaway chains.
    pub fn new(anchors: TrustAnchorStore, max_depth: usize) -> Self {
        Self { anchors, max_depth }
    }

    /// Borrow the configured anchor store.
    pub fn anchors(&self) -> &TrustAnchorStore {
        &self.anchors
    }

    /// Depth cap the resolver enforces on each chain.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Validate a chain of compact-JWS statements supplied in
    /// leaf-to-anchor order.
    ///
    /// Validation walks the chain **anchor-down** even though the
    /// input is in leaf-to-anchor order: the trust always flows from
    /// the operator-pinned trust-anchor key set into each subsequent
    /// signature check.
    ///
    /// ## Validation steps
    ///
    /// 1. Reject when the chain is empty or longer than
    ///    [`Self::max_depth`].
    /// 2. Verify the anchor (last element) against the operator's
    ///    pinned trust-anchor jwks. Confirm `iss == sub` (anchors are
    ///    self-signed). Reject when the anchor's `iss` is not in
    ///    [`TrustAnchorStore`].
    /// 3. For each subordinate statement going down (from index
    ///    `chain.len() - 2` to `1`), verify the statement against
    ///    the **jwks the superior published** in the next-higher
    ///    step. The superior's published jwks comes from the
    ///    statement IMMEDIATELY ABOVE; this is the §9.2 trust-flow
    ///    direction.
    /// 4. Linkage: the subordinate's `iss` MUST equal the superior's
    ///    `sub` (i.e. the superior, which is `iss == sub` for the
    ///    anchor or for any chained statement, is who certified this
    ///    step). And the subordinate's `sub` MUST equal the next-down
    ///    statement's `iss`: the chain identifies the same entity at
    ///    every join.
    /// 5. Single-step chain: when `chain.len() == 1`, the leaf IS the
    ///    anchor: a single self-signed Entity Configuration pinned
    ///    by the operator.
    /// 6. Multi-step chain: verify the leaf (`chain[0]`) against the
    ///    jwks the first subordinate (`chain[1]`) certified for it.
    ///    The leaf MUST be self-signed.
    /// 7. Reject when the chain contains a cycle (same `sub`
    ///    appearing twice).
    ///
    /// Every call emits a `sbproxy_federation_trust_chain_resolutions_total`
    /// counter tick and a structured decision-event log line (target
    /// `sbproxy_federation::decision`, `event =
    /// "federation_trust_chain_decision"`) naming the leaf entity,
    /// the trust anchor reached (on success), and the failure reason
    /// (on rejection), so an operator can audit every trust decision
    /// this process made.
    pub fn resolve(&self, chain: &[String]) -> FederationResult<ResolvedTrustChain> {
        let leaf_entity_id = chain
            .first()
            .and_then(|c| peek_claims(c).ok().map(|c| c.sub));
        let result = self.resolve_inner(chain);
        match &result {
            Ok(resolved) => {
                crate::metrics::record_trust_chain_resolution("resolved");
                tracing::info!(
                    target: "sbproxy_federation::decision",
                    event = "federation_trust_chain_decision",
                    outcome = "resolved",
                    leaf_entity_id = leaf_entity_id.as_deref().unwrap_or("unknown"),
                    trust_anchor_id = %resolved.trust_anchor_id,
                    chain_len = resolved.statements.len(),
                    "trust chain resolved"
                );
            }
            Err(err) => {
                crate::metrics::record_trust_chain_resolution("rejected");
                tracing::warn!(
                    target: "sbproxy_federation::decision",
                    event = "federation_trust_chain_decision",
                    outcome = "rejected",
                    leaf_entity_id = leaf_entity_id.as_deref().unwrap_or("unknown"),
                    error = %err,
                    "trust chain rejected"
                );
            }
        }
        result
    }

    fn resolve_inner(&self, chain: &[String]) -> FederationResult<ResolvedTrustChain> {
        if chain.is_empty() {
            return Err(FederationError::ChainEmpty);
        }
        if chain.len() > self.max_depth {
            return Err(FederationError::ChainTooLong {
                got: chain.len(),
                max: self.max_depth,
            });
        }

        // --- Step 2: anchor binding. ---
        let anchor_idx = chain.len() - 1;
        let anchor_claims = peek_claims(&chain[anchor_idx])?;
        if !anchor_claims.is_self_signed() {
            return Err(FederationError::AnchorNotSelfSigned);
        }
        let trust_anchor_id = anchor_claims.iss.clone();
        let trusted_jwks = self.anchors.jwks_for(&trust_anchor_id).ok_or_else(|| {
            FederationError::UnknownTrustAnchor {
                entity_id: trust_anchor_id.clone(),
            }
        })?;
        let anchor_stmt = verify_entity_statement(&chain[anchor_idx], trusted_jwks)?;

        // Walk down: for each subordinate i from anchor-1 to 1,
        // verify against the jwks published one step up. The walk
        // collects statements into `down` in anchor-to-leaf order;
        // we reverse before returning so the public API stays in the
        // documented leaf-to-anchor order.
        let mut down: Vec<EntityStatement> = Vec::with_capacity(chain.len());
        // Cycle / loop-back guard: track the `sub` of each
        // intermediate STATEMENT as the validator walks down. The
        // anchor is recorded first because a chain that loops back
        // to the anchor identifier mid-walk is a forgery. A
        // legitimate subordinate's `sub` is the entity one step
        // further down the chain, so a re-appearance means the
        // forger looped back. Subordinate `sub` values are unique
        // per legitimate chain: each step is "about" a strictly
        // different entity.
        let mut seen_subjects: HashMap<String, ()> = HashMap::new();
        seen_subjects.insert(anchor_stmt.claims.sub.clone(), ());
        let mut superior_jwks = anchor_stmt.claims.jwks.clone();
        let mut superior_iss = anchor_stmt.claims.iss.clone();
        down.push(anchor_stmt);

        // Single-step chain: leaf is the anchor; return the anchor
        // statement as the only element of the resolved chain.
        if chain.len() == 1 {
            return Ok(ResolvedTrustChain {
                statements: down, // already [anchor]
                trust_anchor_id,
            });
        }

        // Multi-step chain: walk subordinate statements anchor-1 .. 1.
        for i in (1..anchor_idx).rev() {
            let subordinate = verify_entity_statement(&chain[i], &superior_jwks)?;
            // §9.2 linkage: the subordinate is signed BY the superior
            // (whose `sub`/`iss` is `superior_iss`); thus the
            // subordinate's `iss` MUST equal the superior's
            // identifier.
            if subordinate.claims.iss != superior_iss {
                return Err(FederationError::ChainLinkBroken {
                    expected_sub: superior_iss.clone(),
                    actual_sub: subordinate.claims.iss.clone(),
                });
            }
            // Cycle / loop-back check: the subordinate's `sub` (the
            // entity one step further down) MUST NOT have appeared
            // earlier in the chain. A re-appearance means the chain
            // looped back to a higher position.
            if seen_subjects.contains_key(&subordinate.claims.sub) {
                return Err(FederationError::ChainCycle {
                    entity_id: subordinate.claims.sub.clone(),
                });
            }
            seen_subjects.insert(subordinate.claims.sub.clone(), ());
            // The subordinate publishes the keys the superior
            // certifies for the entity one step further down. Carry
            // that jwks forward to the next iteration, and remember
            // this subordinate's `sub` as the identifier the NEXT
            // step's `iss` must match.
            superior_jwks = subordinate.claims.jwks.clone();
            superior_iss = subordinate.claims.sub.clone();
            down.push(subordinate);
        }

        // --- Step 6: leaf. ---
        let leaf_claims = peek_claims(&chain[0])?;
        if !leaf_claims.is_self_signed() {
            return Err(FederationError::LeafNotSelfSigned);
        }
        // Linkage: leaf's iss / sub MUST equal what the lowest
        // subordinate certified as its `sub`.
        if leaf_claims.iss != superior_iss {
            return Err(FederationError::ChainLinkBroken {
                expected_sub: superior_iss.clone(),
                actual_sub: leaf_claims.iss.clone(),
            });
        }
        // The leaf is `iss == sub`; it does not "sign" any further
        // statement in the chain, so it doesn't go into `signed_by`.
        // The depth cap + linkage checks are what guard against the
        // chain looping past the leaf.
        let leaf = verify_entity_statement(&chain[0], &superior_jwks)?;
        down.push(leaf);

        // Reverse so the public API returns leaf-to-anchor order.
        down.reverse();
        Ok(ResolvedTrustChain {
            statements: down,
            trust_anchor_id,
        })
    }
}

/// Inspect a compact-JWS entity statement and return its parsed
/// claims WITHOUT verifying the signature. The trust-chain validator
/// uses this to peek at the leaf's `iss` / `sub` / `jwks` so it can
/// verify against the right key set; the signature check happens
/// immediately afterwards inside [`verify_entity_statement`].
///
/// Returns an opaque [`FederationError::VerificationFailed`] when the
/// JWS cannot be decoded: leaking the parse step would help a
/// forger tune the next attempt.
fn peek_claims(compact_jws: &str) -> FederationResult<EntityStatementClaims> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_statement::{EntityMetadata, FederationEntityMetadata};
    use crate::{sign_entity_statement, FederationKeySet};
    use base64::Engine;
    use jsonwebtoken::{Algorithm, EncodingKey};

    /// Mint an ES256 keypair + its JWK. Each chain step needs its
    /// own keypair so the validator's "the superior's published jwks
    /// verifies the subordinate's signature" check has something to
    /// chew on.
    fn fresh_keypair(kid: &str) -> (EncodingKey, serde_json::Value) {
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

    fn claims(iss: &str, sub: &str, jwk: serde_json::Value) -> EntityStatementClaims {
        let now = chrono::Utc::now().timestamp();
        let mut keys = FederationKeySet::empty();
        keys.push(jwk);
        EntityStatementClaims {
            iss: iss.to_string(),
            sub: sub.to_string(),
            iat: now,
            exp: now + 3600,
            jwks: keys,
            authority_hints: vec![],
            metadata: EntityMetadata {
                federation_entity: Some(FederationEntityMetadata {
                    organization_name: Some(format!("{} org", iss)),
                    ..Default::default()
                }),
                other: Default::default(),
            },
            metadata_policy: None,
            trust_marks: vec![],
        }
    }

    /// Build a minimal 3-step chain: leaf signs leaf, anchor signs
    /// leaf-about-leaf subordinate, anchor signs anchor. Returns the
    /// chain (leaf → subordinate → anchor) plus the anchor's JWK so
    /// the test can pin it into the trust-anchor store.
    fn build_three_step_chain() -> (Vec<String>, serde_json::Value) {
        let (leaf_key, leaf_jwk) = fresh_keypair("leaf-key");
        let (anchor_key, anchor_jwk) = fresh_keypair("anchor-key");

        let leaf_claims = claims(
            "https://leaf.example",
            "https://leaf.example",
            leaf_jwk.clone(),
        );
        let leaf_jws =
            sign_entity_statement(&leaf_claims, &leaf_key, Algorithm::ES256, "leaf-key").unwrap();

        // Subordinate statement: the anchor signs a statement ABOUT
        // the leaf, declaring the LEAF's jwks (so when the validator
        // walks down it can verify the leaf's self-signed
        // configuration against keys the superior certified for the
        // leaf). iss=anchor, sub=leaf, jwks=[leaf_jwk].
        let mut leaf_jwks_set = FederationKeySet::empty();
        leaf_jwks_set.push(leaf_jwk.clone());
        let now = chrono::Utc::now().timestamp();
        let sub_claims = EntityStatementClaims {
            iss: "https://anchor.example".to_string(),
            sub: "https://leaf.example".to_string(),
            iat: now,
            exp: now + 3600,
            jwks: leaf_jwks_set,
            authority_hints: vec![],
            metadata: EntityMetadata::default(),
            metadata_policy: None,
            trust_marks: vec![],
        };
        let sub_jws =
            sign_entity_statement(&sub_claims, &anchor_key, Algorithm::ES256, "anchor-key")
                .unwrap();

        let anchor_claims = claims(
            "https://anchor.example",
            "https://anchor.example",
            anchor_jwk.clone(),
        );
        let anchor_jws =
            sign_entity_statement(&anchor_claims, &anchor_key, Algorithm::ES256, "anchor-key")
                .unwrap();

        (vec![leaf_jws, sub_jws, anchor_jws], anchor_jwk)
    }

    fn store_with_anchor(jwk: serde_json::Value) -> TrustAnchorStore {
        let mut keys = FederationKeySet::empty();
        keys.push(jwk);
        TrustAnchorStore::from_anchors([TrustAnchor {
            entity_id: "https://anchor.example".to_string(),
            jwks: keys,
        }])
    }

    /// Happy path: leaf → subordinate → anchor resolves.
    #[test]
    fn resolves_a_valid_three_step_chain() {
        let (chain, anchor_jwk) = build_three_step_chain();
        let resolver = TrustChainResolver::new(store_with_anchor(anchor_jwk), 5);
        let resolved = resolver.resolve(&chain).expect("resolve");
        assert_eq!(resolved.statements.len(), 3);
        assert_eq!(resolved.trust_anchor_id, "https://anchor.example");
        assert_eq!(resolved.leaf().claims.iss, "https://leaf.example");
        assert_eq!(resolved.anchor().claims.iss, "https://anchor.example");
    }

    /// Empty chain is a config error, surfaces as the typed variant
    /// so the operator sees something other than "verification failed".
    #[test]
    fn empty_chain_rejected() {
        let resolver = TrustChainResolver::new(TrustAnchorStore::new(), 5);
        let err = resolver.resolve(&[]).unwrap_err();
        assert!(matches!(err, FederationError::ChainEmpty));
    }

    /// Chain length over max_depth is rejected. The cap defends
    /// against denial-of-service via runaway chains.
    #[test]
    fn chain_over_max_depth_rejected() {
        let (chain, anchor_jwk) = build_three_step_chain();
        // max_depth = 2 means 3-element chain is rejected.
        let resolver = TrustChainResolver::new(store_with_anchor(anchor_jwk), 2);
        let err = resolver.resolve(&chain).unwrap_err();
        assert!(matches!(
            err,
            FederationError::ChainTooLong { got: 3, max: 2 }
        ));
    }

    /// Leaf with iss != sub in a multi-step chain is rejected
    /// with the `LeafNotSelfSigned` variant. A non-self-signed
    /// statement at the leaf position would be a Subordinate
    /// Statement, not an Entity Configuration. (Single-step chain
    /// where iss != sub surfaces as `AnchorNotSelfSigned`, since the
    /// single statement plays both roles: see
    /// `single_step_chain_with_self_anchor_resolves` for the happy
    /// path.)
    #[test]
    fn leaf_must_be_self_signed_in_multi_step_chain() {
        let (leaf_key, leaf_jwk) = fresh_keypair("leaf-key");
        let (anchor_key, anchor_jwk) = fresh_keypair("anchor-key");

        let now = chrono::Utc::now().timestamp();
        let mut leaf_jwks_set = FederationKeySet::empty();
        leaf_jwks_set.push(leaf_jwk.clone());
        let bad_leaf = EntityStatementClaims {
            iss: "https://other.example".to_string(),
            sub: "https://leaf.example".to_string(),
            iat: now,
            exp: now + 3600,
            jwks: leaf_jwks_set.clone(),
            authority_hints: vec![],
            metadata: EntityMetadata::default(),
            metadata_policy: None,
            trust_marks: vec![],
        };
        let bad_leaf_jws =
            sign_entity_statement(&bad_leaf, &leaf_key, Algorithm::ES256, "leaf-key").unwrap();

        let sub_claims = EntityStatementClaims {
            iss: "https://anchor.example".to_string(),
            sub: "https://leaf.example".to_string(),
            iat: now,
            exp: now + 3600,
            jwks: leaf_jwks_set,
            authority_hints: vec![],
            metadata: EntityMetadata::default(),
            metadata_policy: None,
            trust_marks: vec![],
        };
        let sub_jws =
            sign_entity_statement(&sub_claims, &anchor_key, Algorithm::ES256, "anchor-key")
                .unwrap();

        let anchor_claims = claims(
            "https://anchor.example",
            "https://anchor.example",
            anchor_jwk.clone(),
        );
        let anchor_jws =
            sign_entity_statement(&anchor_claims, &anchor_key, Algorithm::ES256, "anchor-key")
                .unwrap();

        let chain = vec![bad_leaf_jws, sub_jws, anchor_jws];
        let resolver = TrustChainResolver::new(store_with_anchor(anchor_jwk), 5);
        let err = resolver.resolve(&chain).unwrap_err();
        assert!(matches!(err, FederationError::LeafNotSelfSigned));
    }

    /// Anchor entity_id not in the configured store is rejected.
    /// Without the pinned key set the validator can not anchor the
    /// chain to anything trusted.
    #[test]
    fn unknown_anchor_rejected() {
        let (chain, _anchor_jwk) = build_three_step_chain();
        // Empty store: no anchor matches.
        let resolver = TrustChainResolver::new(TrustAnchorStore::new(), 5);
        let err = resolver.resolve(&chain).unwrap_err();
        assert!(matches!(
            err,
            FederationError::UnknownTrustAnchor { entity_id }
                if entity_id == "https://anchor.example"
        ));
    }

    /// Anchor verified against a DIFFERENT pinned key set fails the
    /// final signature check. A self-signed anchor can vouch for any
    /// key; only the operator's pin makes the trust real.
    #[test]
    fn anchor_pinned_to_wrong_key_rejected() {
        let (chain, _legit_anchor_jwk) = build_three_step_chain();
        // Pin the operator's "anchor" jwks to a freshly-minted key
        // (not the one the chain's anchor statement was signed with).
        let (_unused_key, wrong_jwk) = fresh_keypair("anchor-key");
        let resolver = TrustChainResolver::new(store_with_anchor(wrong_jwk), 5);
        let err = resolver.resolve(&chain).unwrap_err();
        assert!(matches!(err, FederationError::VerificationFailed));
    }

    /// Broken link: the subordinate statement names a different
    /// subject than the leaf claims as its own iss. The validator
    /// catches the mismatch via the leaf-vs-superior linkage check.
    #[test]
    fn broken_link_leaf_iss_does_not_match_subordinate_sub() {
        let (leaf_key, leaf_jwk) = fresh_keypair("leaf-key");
        let (anchor_key, anchor_jwk) = fresh_keypair("anchor-key");

        let leaf_claims = claims(
            "https://leaf.example",
            "https://leaf.example",
            leaf_jwk.clone(),
        );
        let leaf_jws =
            sign_entity_statement(&leaf_claims, &leaf_key, Algorithm::ES256, "leaf-key").unwrap();

        // Subordinate statement: signed correctly by the anchor
        // (so the upstream verify step succeeds) but with the wrong
        // `sub`, which fails the leaf-linkage check.
        let now = chrono::Utc::now().timestamp();
        let mut leaf_jwks_set = FederationKeySet::empty();
        leaf_jwks_set.push(leaf_jwk.clone());
        let bad_sub = EntityStatementClaims {
            iss: "https://anchor.example".to_string(),
            sub: "https://other-leaf.example".to_string(),
            iat: now,
            exp: now + 3600,
            jwks: leaf_jwks_set,
            authority_hints: vec![],
            metadata: EntityMetadata::default(),
            metadata_policy: None,
            trust_marks: vec![],
        };
        let sub_jws =
            sign_entity_statement(&bad_sub, &anchor_key, Algorithm::ES256, "anchor-key").unwrap();

        let anchor_claims = claims(
            "https://anchor.example",
            "https://anchor.example",
            anchor_jwk.clone(),
        );
        let anchor_jws =
            sign_entity_statement(&anchor_claims, &anchor_key, Algorithm::ES256, "anchor-key")
                .unwrap();

        let chain = vec![leaf_jws, sub_jws, anchor_jws];
        let resolver = TrustChainResolver::new(store_with_anchor(anchor_jwk), 5);
        let err = resolver.resolve(&chain).unwrap_err();
        assert!(matches!(err, FederationError::ChainLinkBroken { .. }));
    }

    /// Cycle detection: a chain in which a subordinate's `sub`
    /// re-appears (an entity certified at two different chain
    /// positions) is rejected. The seen-subjects set catches the
    /// loop-back shape a forger uses to extend a chain past
    /// `max_depth` by repeating an entity identifier.
    #[test]
    fn cycle_in_chain_rejected() {
        // 4-step chain: leaf -> sub-A(sub=anchor.example) -> sub-B
        // -> anchor. sub-A re-introduces the anchor's identifier as
        // its `sub`, which is already in the seen-subjects set (the
        // anchor was recorded when the walk started).
        let (leaf_key, leaf_jwk) = fresh_keypair("leaf-key");
        let (anchor_key, anchor_jwk) = fresh_keypair("anchor-key");

        let leaf_claims = claims(
            "https://leaf.example",
            "https://leaf.example",
            leaf_jwk.clone(),
        );
        let leaf_jws =
            sign_entity_statement(&leaf_claims, &leaf_key, Algorithm::ES256, "leaf-key").unwrap();

        let now = chrono::Utc::now().timestamp();
        let mut leaf_jwks_set = FederationKeySet::empty();
        leaf_jwks_set.push(leaf_jwk);
        let mut anchor_jwks_set = FederationKeySet::empty();
        anchor_jwks_set.push(anchor_jwk.clone());

        // sub-A: signed by anchor (so chain[2]→chain[3] verifies),
        // sub=anchor.example (loop back into the seen set), jwks
        // republishes anchor's own jwks.
        let sub_a = EntityStatementClaims {
            iss: "https://anchor.example".to_string(),
            sub: "https://anchor.example".to_string(),
            iat: now,
            exp: now + 3600,
            jwks: anchor_jwks_set.clone(),
            authority_hints: vec![],
            metadata: EntityMetadata::default(),
            metadata_policy: None,
            trust_marks: vec![],
        };
        let sub_a_jws =
            sign_entity_statement(&sub_a, &anchor_key, Algorithm::ES256, "anchor-key").unwrap();

        // sub-B: signed by anchor (jwks set above), sub=leaf,
        // certifies leaf's jwks for the leaf-verification step.
        let sub_b = EntityStatementClaims {
            iss: "https://anchor.example".to_string(),
            sub: "https://leaf.example".to_string(),
            iat: now,
            exp: now + 3600,
            jwks: leaf_jwks_set,
            authority_hints: vec![],
            metadata: EntityMetadata::default(),
            metadata_policy: None,
            trust_marks: vec![],
        };
        let sub_b_jws =
            sign_entity_statement(&sub_b, &anchor_key, Algorithm::ES256, "anchor-key").unwrap();

        let anchor_claims = claims(
            "https://anchor.example",
            "https://anchor.example",
            anchor_jwk.clone(),
        );
        let anchor_jws =
            sign_entity_statement(&anchor_claims, &anchor_key, Algorithm::ES256, "anchor-key")
                .unwrap();

        let chain = vec![leaf_jws, sub_b_jws, sub_a_jws, anchor_jws];
        let resolver = TrustChainResolver::new(store_with_anchor(anchor_jwk), 10);
        let err = resolver.resolve(&chain).unwrap_err();
        assert!(
            matches!(&err, FederationError::ChainCycle { entity_id } if entity_id == "https://anchor.example"),
            "got {:?}",
            err
        );
    }

    /// Single-step chain (just the leaf): the leaf's iss is also
    /// the trust anchor. This is a valid mode for a federation of
    /// one or for tests; the validator MUST handle it.
    #[test]
    fn single_step_chain_with_self_anchor_resolves() {
        let (leaf_key, leaf_jwk) = fresh_keypair("self-key");
        let leaf_claims = claims(
            "https://leaf.example",
            "https://leaf.example",
            leaf_jwk.clone(),
        );
        let leaf_jws =
            sign_entity_statement(&leaf_claims, &leaf_key, Algorithm::ES256, "self-key").unwrap();
        let resolver = TrustChainResolver::new(
            TrustAnchorStore::from_anchors([TrustAnchor {
                entity_id: "https://leaf.example".to_string(),
                jwks: leaf_claims.jwks.clone(),
            }]),
            5,
        );
        let resolved = resolver.resolve(&[leaf_jws]).expect("single-step resolve");
        assert_eq!(resolved.statements.len(), 1);
        assert_eq!(resolved.trust_anchor_id, "https://leaf.example");
    }

    /// `metadata_policies` iterates only the steps that declare one.
    /// The policy applicator uses this to walk anchor-to-leaf in
    /// reverse and apply the seven operators.
    #[test]
    fn metadata_policies_iterator_skips_none() {
        let (chain, anchor_jwk) = build_three_step_chain();
        let resolver = TrustChainResolver::new(store_with_anchor(anchor_jwk), 5);
        let resolved = resolver.resolve(&chain).unwrap();
        // The fixture chain has none. Empty iterator.
        assert_eq!(resolved.metadata_policies().count(), 0);
    }

    /// The policy iterator's public contract is anchor-to-leaf even
    /// though statements are stored leaf-to-anchor.
    #[test]
    fn security_boundary_metadata_policies_iterate_anchor_to_leaf() {
        fn statement(entity_id: &str, marker: &str) -> EntityStatement {
            let now = chrono::Utc::now().timestamp();
            EntityStatement {
                claims: EntityStatementClaims {
                    iss: entity_id.to_string(),
                    sub: entity_id.to_string(),
                    iat: now,
                    exp: now + 3600,
                    jwks: FederationKeySet::empty(),
                    authority_hints: vec![],
                    metadata: EntityMetadata::default(),
                    metadata_policy: Some(crate::MetadataPolicy(serde_json::json!({
                        "marker": marker
                    }))),
                    trust_marks: vec![],
                },
                compact_jws: "fixture".to_string(),
            }
        }

        let resolved = ResolvedTrustChain {
            statements: vec![
                statement("https://leaf.example", "leaf"),
                statement("https://intermediate.example", "intermediate"),
                statement("https://anchor.example", "anchor"),
            ],
            trust_anchor_id: "https://anchor.example".to_string(),
        };
        let markers: Vec<&str> = resolved
            .metadata_policies()
            .map(|policy| policy.0["marker"].as_str().unwrap())
            .collect();

        assert_eq!(markers, vec!["anchor", "intermediate", "leaf"]);
    }
}
