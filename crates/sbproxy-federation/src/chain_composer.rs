//! Trust-chain composer: walks `authority_hints` from a leaf
//! entity to a configured trust anchor, fetches each step, and
//! drives [`crate::TrustChainResolver`] on the resulting chain.
//!
//! ## §9.2 walk
//!
//! Given a leaf entity URL the composer:
//! 1. GETs the leaf's own Entity Configuration via the supplied
//!    [`crate::FederationFetcher`].
//! 2. Reads the configuration's `authority_hints` to find the
//!    immediate superior(s).
//! 3. For each superior:
//!    - GETs the superior's own Entity Configuration to learn its
//!      `federation_fetch_endpoint`.
//!    - GETs the Subordinate Statement the superior signed about
//!      the current entity via that endpoint.
//!    - If the superior is a configured trust anchor, terminates
//!      the walk and hands the assembled chain to
//!      [`crate::TrustChainResolver`].
//!    - Otherwise treats the superior as the new "current entity"
//!      and recurses.
//! 4. Spends every step from one [`FetchBudget`] shared by the whole
//!    walk, so a malicious upstream cannot trigger unbounded fetches.
//!
//! ## The budget, and why a depth cap is not one
//!
//! An earlier revision capped recursion **depth** and described that
//! as a fetch budget. It is not: `authority_hints` is an array, and a
//! single frame iterates all of it. One entity publishing five
//! thousand hints costs five thousand outbound GETs at depth 1, and
//! the depth cap never fires. Since the walk is reachable from an
//! unauthenticated request header, that made the proxy an
//! attacker-directed request amplifier.
//!
//! [`FetchBudget`] is the real bound and it is spent, not compared:
//! every fetch decrements a count, adds to a byte total, and is
//! checked against one wall-clock deadline for the entire walk. Each
//! is an operator-visible config key with a documented default. A
//! per-statement cap on `authority_hints` bounds the fan-out of any
//! single frame on top of that.
//!
//! ## Nothing is walked from an unverified document
//!
//! Every Entity Configuration is signature-checked before the walk
//! reads its `authority_hints`, so no fetch is ever driven by a
//! payload the composer has only base64-decoded. §9 requires an
//! Entity Configuration to be signed by a key in its own `jwks`, so
//! that check is available with no extra fetch. Where the entity is
//! a configured trust anchor, the pinned key set is used instead of
//! the embedded one, which is the stronger of the two. Self-signature
//! is not authentication and this module does not claim it is: it
//! proves the publisher holds the key it advertises, which is what
//! makes an unsigned blob cost one fetch instead of thousands. The
//! chain's authentication is [`TrustChainResolver::resolve`], which
//! still runs on every returned chain.
//!
//! ## What this module does NOT do
//!
//! * Pick which `authority_hints` entry to follow when several are
//!   present. Today the composer tries each in order and returns
//!   the first chain that anchors at a configured trust anchor;
//!   a future revision can apply preference rules (closest anchor
//!   wins, lowest-latency anchor wins).
//! * Cache fetched documents. Operators that want a fetch cache
//!   wrap the [`crate::FederationFetcher`] impl they hand the
//!   composer.
//! * Apply metadata-policy operators. The composer returns the
//!   verified chain; [`crate::apply_block_policy`] and
//!   [`crate::compose_policies`] are what the caller drives to
//!   produce the resolved metadata.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::entity_statement::{peek_claims_pub, verify_entity_statement, EntityStatementClaims};
use crate::errors::{FederationError, FederationResult};
use crate::http_fetcher::FederationFetcher;
use crate::trust_chain::{ResolvedTrustChain, TrustChainResolver};

/// Default cap on `authority_hints` traversal depth. Stops a
/// runaway walk against a federation that mis-publishes its
/// chain. OIDF deployments rarely exceed 4-5 levels; the cap is
/// the same shape as [`TrustChainResolver::max_depth`] but lives
/// independently so the composer can refuse to even FETCH past
/// the cap.
///
/// This is a **depth** cap. It is not a fetch budget and must not be
/// described as one; see [`FetchBudget`].
pub const DEFAULT_MAX_CHAIN_FETCHES: usize = 8;

/// Default total number of outbound fetches one walk may spend.
///
/// A well-formed chain costs roughly two fetches per level (the
/// superior's configuration, then the subordinate statement), so
/// sixteen covers a four-level federation that has to try a second
/// `authority_hints` entry at one level. A deployment that needs
/// more raises `max_chain_fetches`.
pub const DEFAULT_MAX_WALK_FETCHES: usize = 16;

/// Default total bytes one walk may read across every fetch.
///
/// Individual fetches are already capped by the fetcher (1 MiB), so
/// this bounds the aggregate: a peer that serves a maximum-size
/// document at every hop cannot make the walk hold sixteen of them.
pub const DEFAULT_MAX_WALK_BYTES: u64 = 2 * 1024 * 1024;

/// Default wall-clock budget for one walk, in milliseconds.
///
/// Each fetch has its own connect and read timeout, so without an
/// aggregate deadline a peer that answers just inside the per-fetch
/// timeout at every hop holds a request open for the product of the
/// two. Five seconds is well past a healthy chain and well short of
/// a client's patience.
pub const DEFAULT_WALK_DEADLINE_MS: u64 = 5_000;

/// Default cap on how many `authority_hints` a single entity
/// configuration may publish before the walk refuses it.
///
/// OpenID Federation deployments name one or two superiors. Eight is
/// generous; the value exists so one frame cannot fan out.
pub const DEFAULT_MAX_AUTHORITY_HINTS: usize = 8;

/// What one trust-chain walk is allowed to spend.
///
/// The unit is the whole walk, not the frame and not the fetch:
/// every recursion level draws from the same instance, which is what
/// makes it a budget rather than a per-step limit. Cloning it would
/// hand a frame its own allowance, so it is threaded by `&mut`.
///
/// # What this does not bound
///
/// The number of walks. One request drives at most one walk, and the
/// caller is responsible for not starting a walk per request from an
/// unauthenticated caller; [`crate::FederationFetcher`] implementors
/// are responsible for the per-fetch address checks. This type bounds
/// what a single walk can do once it has started.
#[derive(Debug)]
pub struct FetchBudget {
    /// Fetches still available to this walk.
    remaining_fetches: usize,
    /// Configured maximum, kept for the refusal message.
    max_fetches: usize,
    /// Bytes read so far across every fetch in this walk.
    bytes_read: u64,
    /// Configured maximum bytes.
    max_bytes: u64,
    /// When this walk must stop, whatever it has found.
    deadline: Instant,
    /// Configured wall-clock budget, kept for the refusal message.
    max_ms: u64,
    /// Cap on `authority_hints` per entity configuration.
    max_authority_hints: usize,
}

impl FetchBudget {
    /// Build a budget from operator-configured limits.
    ///
    /// A zero in any of the three spend limits is treated as "one",
    /// not as "unlimited": a budget that cannot refuse is the bug
    /// this type exists to remove, and an operator who writes zero
    /// meant to disable the feature rather than to uncap it.
    pub fn new(
        max_fetches: usize,
        max_bytes: u64,
        max_ms: u64,
        max_authority_hints: usize,
    ) -> Self {
        let max_fetches = max_fetches.max(1);
        let max_bytes = max_bytes.max(1);
        let max_ms = max_ms.max(1);
        Self {
            remaining_fetches: max_fetches,
            max_fetches,
            bytes_read: 0,
            max_bytes,
            deadline: Instant::now() + Duration::from_millis(max_ms),
            max_ms,
            max_authority_hints: max_authority_hints.max(1),
        }
    }

    /// The defaults, for a caller with no operator configuration.
    pub fn with_defaults() -> Self {
        Self::new(
            DEFAULT_MAX_WALK_FETCHES,
            DEFAULT_MAX_WALK_BYTES,
            DEFAULT_WALK_DEADLINE_MS,
            DEFAULT_MAX_AUTHORITY_HINTS,
        )
    }

    /// How many fetches this walk has spent so far.
    pub fn fetches_spent(&self) -> usize {
        self.max_fetches.saturating_sub(self.remaining_fetches)
    }

    /// Bytes this walk has read so far.
    pub fn bytes_spent(&self) -> u64 {
        self.bytes_read
    }

    /// Claim one fetch. Called immediately **before** the fetch, so a
    /// refusal costs no outbound request, and it checks the deadline
    /// in the same place so a walk cannot spend its whole allowance
    /// after its time is up.
    fn claim_fetch(&mut self) -> FederationResult<()> {
        if Instant::now() >= self.deadline {
            return Err(FederationError::ChainDeadlineExceeded {
                max_ms: self.max_ms,
            });
        }
        if self.remaining_fetches == 0 {
            return Err(FederationError::ChainFetchBudgetExhausted {
                max: self.max_fetches,
            });
        }
        self.remaining_fetches -= 1;
        Ok(())
    }

    /// Record what a fetch returned. Called after, because the size
    /// is not known before; the count and the deadline are what stop
    /// the walk before a request goes out, and this stops the next
    /// one.
    fn record_bytes(&mut self, len: usize) -> FederationResult<()> {
        self.bytes_read = self.bytes_read.saturating_add(len as u64);
        if self.bytes_read > self.max_bytes {
            return Err(FederationError::ChainByteBudgetExhausted {
                got: self.bytes_read,
                max: self.max_bytes,
            });
        }
        Ok(())
    }

    /// Refuse an entity configuration that publishes more superiors
    /// than the walk will follow.
    fn check_hints(&self, entity_id: &str, hints: &[String]) -> FederationResult<()> {
        if hints.len() > self.max_authority_hints {
            return Err(FederationError::TooManyAuthorityHints {
                entity_id: entity_id.to_string(),
                got: hints.len(),
                max: self.max_authority_hints,
            });
        }
        Ok(())
    }
}

/// Fetch an Entity Configuration and verify its signature before any
/// caller reads a claim out of it.
///
/// §9 requires an Entity Configuration to be signed by a key the same
/// document publishes in `jwks`, so this needs no extra fetch. When
/// `anchor_keys` is supplied the pinned set is used instead, which is
/// real authentication rather than self-attestation.
///
/// The `sub == entity_id` check is §9's other requirement and is what
/// stops a document served at one URL from being accepted as another
/// entity's, which matters because the walk writes the resolved `sub`
/// back as the caller's verified identity.
async fn fetch_and_self_verify(
    fetcher: &Arc<dyn FederationFetcher>,
    entity_id: &str,
    anchor_keys: Option<&crate::FederationKeySet>,
    budget: &mut FetchBudget,
) -> FederationResult<(String, EntityStatementClaims)> {
    budget.claim_fetch()?;
    let compact = fetcher.fetch_entity_configuration(entity_id).await?;
    budget.record_bytes(compact.len())?;

    // The embedded key set is only a candidate: it comes out of the
    // document it is about to check. That is the shape §9 defines,
    // and the walk treats the result as "well-formed and published by
    // whoever holds this key", never as "trusted".
    let peeked = peek_claims_pub(&compact)?;
    let keys = match anchor_keys {
        Some(pinned) => pinned,
        None => &peeked.jwks,
    };
    let verified = verify_entity_statement(&compact, keys).map_err(|e| {
        FederationError::EntityConfigurationNotSelfVerified {
            entity_id: entity_id.to_string(),
            reason: e.to_string(),
        }
    })?;
    if verified.claims.sub != entity_id {
        return Err(FederationError::EntityConfigurationSubjectMismatch {
            fetched_from: entity_id.to_string(),
            claims_to_be: verified.claims.sub.clone(),
        });
    }
    budget.check_hints(entity_id, &verified.claims.authority_hints)?;
    Ok((compact, verified.claims))
}

/// Walk `authority_hints` from a leaf entity URL to a configured
/// trust anchor and return the verified resolved chain.
///
/// Returns a typed `FederationError::ChainNoAnchorFound` when no
/// `authority_hints` path leads to a configured anchor before the
/// depth cap fires.
pub async fn compose_trust_chain(
    fetcher: Arc<dyn FederationFetcher>,
    resolver: &TrustChainResolver,
    leaf_entity_id: &str,
    max_depth: usize,
) -> FederationResult<ResolvedTrustChain> {
    compose_trust_chain_budgeted(
        fetcher,
        resolver,
        leaf_entity_id,
        max_depth,
        &mut FetchBudget::with_defaults(),
    )
    .await
}

/// [`compose_trust_chain`] with an operator-configured budget.
///
/// The budget is borrowed rather than owned so the caller can read
/// what the walk spent afterwards, which is what lets a refusal say
/// whether it ran out of fetches, bytes, or time.
pub async fn compose_trust_chain_budgeted(
    fetcher: Arc<dyn FederationFetcher>,
    resolver: &TrustChainResolver,
    leaf_entity_id: &str,
    max_depth: usize,
    budget: &mut FetchBudget,
) -> FederationResult<ResolvedTrustChain> {
    if max_depth == 0 {
        return Err(FederationError::ChainTooLong { got: 0, max: 0 });
    }

    // Fetch the leaf's own configuration and check its signature
    // before reading a single hint out of it. An unsigned document
    // costs exactly this one fetch.
    //
    // If the leaf is itself a pinned anchor its own key set is the
    // one used, so the strongest available check runs where it can.
    let anchor_keys = resolver.anchors().jwks_for(leaf_entity_id);
    let (leaf_compact, leaf_claims) =
        fetch_and_self_verify(&fetcher, leaf_entity_id, anchor_keys, budget).await?;
    if !leaf_claims.is_self_signed() {
        return Err(FederationError::LeafNotSelfSigned);
    }

    // The chain we accumulate is leaf-to-anchor order. The walker
    // uses `visited` to short-circuit on cycles before issuing an
    // HTTP fetch (vs. the resolver's seen-subjects guard which
    // catches the same case after the fact).
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(leaf_entity_id.to_string());

    // Recurse along the first authority_hints path that anchors.
    // Each frame fetches the current entity's superior's own
    // Entity Configuration (to learn its fetch endpoint + check
    // anchor membership) then the Subordinate Statement.
    walk_authority_hints(
        fetcher,
        resolver,
        &leaf_compact,
        leaf_entity_id,
        &leaf_claims.authority_hints,
        &mut visited,
        max_depth,
        1,
        budget,
    )
    .await
}

/// Recursive walker. Returns the first chain that anchors at a
/// configured trust anchor; bubbles up [`FederationError::ChainNoAnchorFound`]
/// when every path the current frame can follow either cycles
/// or fails to anchor.
#[allow(clippy::too_many_arguments)]
async fn walk_authority_hints(
    fetcher: Arc<dyn FederationFetcher>,
    resolver: &TrustChainResolver,
    current_compact: &str,
    current_entity_id: &str,
    authority_hints: &[String],
    visited: &mut HashSet<String>,
    max_depth: usize,
    depth: usize,
    budget: &mut FetchBudget,
) -> FederationResult<ResolvedTrustChain> {
    if depth > max_depth {
        return Err(FederationError::ChainTooLong {
            got: depth,
            max: max_depth,
        });
    }
    if authority_hints.is_empty() {
        return Err(FederationError::ChainNoAnchorFound {
            entity_id: current_entity_id.to_string(),
        });
    }

    let mut last_error: Option<FederationError> = None;
    for superior_url in authority_hints {
        if visited.contains(superior_url) {
            // Already on the walked-from-leaf list: skip to avoid
            // an HTTP-amplified cycle.
            continue;
        }
        // Fetch the superior's own Entity Configuration, signature
        // first. When the superior is a pinned anchor its own key set
        // is used, so the terminating hop of every successful walk is
        // authenticated against operator configuration rather than
        // against the document itself.
        let superior_anchor_keys = resolver.anchors().jwks_for(superior_url.as_str());
        let (superior_compact, superior_claims) =
            match fetch_and_self_verify(&fetcher, superior_url, superior_anchor_keys, budget).await
            {
                Ok(pair) => pair,
                Err(e) => {
                    // A spent budget ends the whole walk. Continuing to
                    // the next hint would let the loop keep calling a
                    // refusal that can never succeed, and would report
                    // the last per-hint error instead of the real cause.
                    if e.is_budget_exhausted() {
                        return Err(e);
                    }
                    last_error = Some(e);
                    continue;
                }
            };

        // Find the superior's fetch endpoint (in its
        // federation_entity metadata block).
        let fetch_endpoint = superior_claims
            .metadata
            .federation_entity
            .as_ref()
            .and_then(|fe| fe.federation_fetch_endpoint.clone());

        // Without a fetch endpoint we cannot collect the
        // subordinate statement for the current entity; skip.
        let Some(fetch_endpoint) = fetch_endpoint else {
            last_error = Some(FederationError::SuperiorMissingFetchEndpoint {
                entity_id: superior_url.clone(),
            });
            continue;
        };

        // Is the superior a configured trust anchor? If so we can
        // assemble + validate the chain right now.
        if resolver.anchors().jwks_for(superior_url.as_str()).is_some() {
            if let Err(e) = budget.claim_fetch() {
                return Err(e);
            }
            let subordinate_compact = match fetcher
                .fetch_subordinate_statement(&fetch_endpoint, current_entity_id)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };
            if let Err(e) = budget.record_bytes(subordinate_compact.len()) {
                return Err(e);
            }
            let chain = leaf_to_anchor_chain(
                visited,
                &subordinate_compact,
                &superior_compact,
                current_compact,
            );
            return resolver.resolve(&chain);
        }

        // Otherwise recurse: the superior becomes the new
        // "current entity", and we keep walking up.
        visited.insert(superior_url.clone());
        let recurse_result = Box::pin(walk_authority_hints(
            fetcher.clone(),
            resolver,
            &superior_compact,
            superior_url,
            &superior_claims.authority_hints,
            visited,
            max_depth,
            depth + 1,
            budget,
        ))
        .await;
        match recurse_result {
            Ok(child_chain) => {
                // Fetch the subordinate statement only AFTER the superior's chain is authenticated
                if let Err(e) = budget.claim_fetch() {
                    return Err(e);
                }
                let subordinate_compact = match fetcher
                    .fetch_subordinate_statement(&fetch_endpoint, current_entity_id)
                    .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        last_error = Some(e);
                        continue;
                    }
                };
                if let Err(e) = budget.record_bytes(subordinate_compact.len()) {
                    return Err(e);
                }

                // Splice this step's subordinate statement onto
                // the chain returned by the deeper walk. The
                // deeper walk yielded a chain starting with the
                // superior's own subordinate statement at the
                // bottom; we prepend the current entity's
                // subordinate statement to put us back in
                // leaf-to-anchor order.
                let mut spliced = Vec::with_capacity(child_chain.statements.len() + 1);
                spliced.push(current_compact.to_string());
                spliced.push(subordinate_compact);
                // Append the remaining JWS bytes from the
                // recursed chain (skip its leaf since we just
                // pushed the equivalent step).
                for s in child_chain.statements.iter().skip(1) {
                    spliced.push(s.compact_jws.clone());
                }
                return resolver.resolve(&spliced);
            }
            Err(e) => {
                if e.is_budget_exhausted() {
                    return Err(e);
                }
                last_error = Some(e);
                continue;
            }
        }
    }

    Err(
        last_error.unwrap_or_else(|| FederationError::ChainNoAnchorFound {
            entity_id: current_entity_id.to_string(),
        }),
    )
}

/// Build the chain Vec the [`TrustChainResolver`] expects:
/// `[leaf, subordinate-about-leaf, superior-config]`.
fn leaf_to_anchor_chain(
    _visited: &HashSet<String>,
    subordinate_compact: &str,
    superior_compact: &str,
    leaf_compact: &str,
) -> Vec<String> {
    vec![
        leaf_compact.to_string(),
        subordinate_compact.to_string(),
        superior_compact.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_statement::{EntityMetadata, FederationEntityMetadata};
    use crate::{
        sign_entity_statement, EntityStatementClaims, FederationKeySet, TrustAnchor,
        TrustAnchorStore,
    };
    use async_trait::async_trait;
    use base64::Engine;
    use jsonwebtoken::{Algorithm, EncodingKey};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory fetcher fixture: maps entity URL + (optional)
    /// subordinate id to a pre-signed compact JWS.
    struct StubFetcher {
        configs: HashMap<String, String>,
        sub_stmts: HashMap<(String, String), String>,
        log: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl FederationFetcher for StubFetcher {
        async fn fetch_entity_configuration(&self, entity_id: &str) -> FederationResult<String> {
            self.log.lock().unwrap().push(format!("EC:{entity_id}"));
            self.configs
                .get(entity_id)
                .cloned()
                .ok_or_else(|| FederationError::FetchFailed(format!("no fixture for {entity_id}")))
        }

        async fn fetch_subordinate_statement(
            &self,
            fetch_endpoint: &str,
            subordinate: &str,
        ) -> FederationResult<String> {
            self.log
                .lock()
                .unwrap()
                .push(format!("SUB:{fetch_endpoint}|{subordinate}"));
            self.sub_stmts
                .get(&(fetch_endpoint.to_string(), subordinate.to_string()))
                .cloned()
                .ok_or_else(|| {
                    FederationError::FetchFailed(format!(
                        "no fixture for sub {subordinate} at {fetch_endpoint}"
                    ))
                })
        }
    }

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

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// Happy path: leaf at https://leaf.example, anchor at
    /// https://anchor.example. The composer GETs the leaf's
    /// configuration, follows authority_hints to the anchor,
    /// fetches the subordinate statement, and resolves the chain.
    #[tokio::test]
    async fn composes_two_step_chain_to_anchor() {
        let (leaf_key, leaf_jwk) = fresh_keypair("leaf-key");
        let (anchor_key, anchor_jwk) = fresh_keypair("anchor-key");

        let mut leaf_jwks = FederationKeySet::empty();
        leaf_jwks.push(leaf_jwk.clone());
        let mut anchor_jwks = FederationKeySet::empty();
        anchor_jwks.push(anchor_jwk.clone());

        // Leaf's own configuration: lists anchor as authority hint.
        let leaf_claims = EntityStatementClaims {
            iss: "https://leaf.example".to_string(),
            sub: "https://leaf.example".to_string(),
            iat: now(),
            exp: now() + 3600,
            jwks: leaf_jwks.clone(),
            authority_hints: vec!["https://anchor.example".to_string()],
            metadata: EntityMetadata::default(),
            metadata_policy: None,
            trust_marks: vec![],
        };
        let leaf_jws =
            sign_entity_statement(&leaf_claims, &leaf_key, Algorithm::ES256, "leaf-key").unwrap();

        // Anchor's configuration: advertises its
        // federation_fetch_endpoint so the composer knows where to
        // GET the subordinate statement.
        let anchor_claims = EntityStatementClaims {
            iss: "https://anchor.example".to_string(),
            sub: "https://anchor.example".to_string(),
            iat: now(),
            exp: now() + 3600,
            jwks: anchor_jwks.clone(),
            authority_hints: vec![],
            metadata: EntityMetadata {
                federation_entity: Some(FederationEntityMetadata {
                    federation_fetch_endpoint: Some("https://anchor.example/fetch".to_string()),
                    ..Default::default()
                }),
                other: Default::default(),
            },
            metadata_policy: None,
            trust_marks: vec![],
        };
        let anchor_jws =
            sign_entity_statement(&anchor_claims, &anchor_key, Algorithm::ES256, "anchor-key")
                .unwrap();

        // Subordinate statement: anchor certifies leaf's jwks.
        let sub_claims = EntityStatementClaims {
            iss: "https://anchor.example".to_string(),
            sub: "https://leaf.example".to_string(),
            iat: now(),
            exp: now() + 3600,
            jwks: leaf_jwks,
            authority_hints: vec![],
            metadata: EntityMetadata::default(),
            metadata_policy: None,
            trust_marks: vec![],
        };
        let sub_jws =
            sign_entity_statement(&sub_claims, &anchor_key, Algorithm::ES256, "anchor-key")
                .unwrap();

        let mut configs = HashMap::new();
        configs.insert("https://leaf.example".to_string(), leaf_jws.clone());
        configs.insert("https://anchor.example".to_string(), anchor_jws.clone());
        let mut subs = HashMap::new();
        subs.insert(
            (
                "https://anchor.example/fetch".to_string(),
                "https://leaf.example".to_string(),
            ),
            sub_jws,
        );
        let fetcher = Arc::new(StubFetcher {
            configs,
            sub_stmts: subs,
            log: Mutex::new(vec![]),
        });

        let resolver = TrustChainResolver::new(
            TrustAnchorStore::from_anchors([TrustAnchor {
                entity_id: "https://anchor.example".to_string(),
                jwks: anchor_jwks,
            }]),
            5,
        );

        let resolved = compose_trust_chain(fetcher.clone(), &resolver, "https://leaf.example", 8)
            .await
            .expect("compose");
        assert_eq!(resolved.statements.len(), 3);
        assert_eq!(resolved.trust_anchor_id, "https://anchor.example");
        let log = fetcher.log.lock().unwrap();
        assert!(log.iter().any(|s| s == "EC:https://leaf.example"));
        assert!(log.iter().any(|s| s == "EC:https://anchor.example"));
    }

    /// Leaf with empty authority_hints + no configured anchor
    /// matching the leaf itself: bubbles up `ChainNoAnchorFound`.
    #[tokio::test]
    async fn no_anchor_found_when_authority_hints_empty() {
        let (leaf_key, leaf_jwk) = fresh_keypair("leaf-key");
        let mut leaf_jwks = FederationKeySet::empty();
        leaf_jwks.push(leaf_jwk);
        let leaf_claims = EntityStatementClaims {
            iss: "https://orphan.example".to_string(),
            sub: "https://orphan.example".to_string(),
            iat: now(),
            exp: now() + 3600,
            jwks: leaf_jwks,
            authority_hints: vec![],
            metadata: EntityMetadata::default(),
            metadata_policy: None,
            trust_marks: vec![],
        };
        let leaf_jws =
            sign_entity_statement(&leaf_claims, &leaf_key, Algorithm::ES256, "leaf-key").unwrap();

        let mut configs = HashMap::new();
        configs.insert("https://orphan.example".to_string(), leaf_jws);
        let fetcher = Arc::new(StubFetcher {
            configs,
            sub_stmts: HashMap::new(),
            log: Mutex::new(vec![]),
        });

        let resolver = TrustChainResolver::new(TrustAnchorStore::new(), 5);
        let err = compose_trust_chain(fetcher, &resolver, "https://orphan.example", 8)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FederationError::ChainNoAnchorFound { entity_id }
                if entity_id == "https://orphan.example"
        ));
    }

    /// `max_fetches = 0` is a misconfiguration; surfaces as a
    /// typed `ChainTooLong` before any HTTP call fires.
    #[tokio::test]
    async fn max_fetches_zero_rejects_eagerly() {
        let fetcher = Arc::new(StubFetcher {
            configs: HashMap::new(),
            sub_stmts: HashMap::new(),
            log: Mutex::new(vec![]),
        });
        let resolver = TrustChainResolver::new(TrustAnchorStore::new(), 5);
        let err = compose_trust_chain(fetcher.clone(), &resolver, "https://leaf.example", 0)
            .await
            .unwrap_err();
        assert!(matches!(err, FederationError::ChainTooLong { .. }));
        assert!(
            fetcher.log.lock().unwrap().is_empty(),
            "no HTTP fetch should fire when max_fetches == 0"
        );
    }

    /// Sign a self-signed entity configuration with the supplied
    /// hints. Used by the amplifier tests, which need many of them.
    fn hostile_config(
        entity: &str,
        hints: Vec<String>,
        key: &EncodingKey,
        jwk: &serde_json::Value,
        kid: &str,
    ) -> String {
        let mut jwks = FederationKeySet::empty();
        jwks.push(jwk.clone());
        let claims = EntityStatementClaims {
            iss: entity.to_string(),
            sub: entity.to_string(),
            iat: now(),
            exp: now() + 3600,
            jwks,
            authority_hints: hints,
            // Advertising a fetch endpoint is what lets the walk
            // recurse past this node. An attacker publishes one for
            // exactly that reason, so the fixture does too; without it
            // the walk stops at `SuperiorMissingFetchEndpoint` and the
            // depth half of the amplifier is never exercised.
            metadata: EntityMetadata {
                federation_entity: Some(FederationEntityMetadata {
                    federation_fetch_endpoint: Some(format!("{entity}/fetch")),
                    ..Default::default()
                }),
                other: Default::default(),
            },
            metadata_policy: None,
            trust_marks: vec![],
        };
        sign_entity_statement(&claims, key, Algorithm::ES256, kid).unwrap()
    }

    /// A resolver with one pinned anchor nothing in these fixtures
    /// reaches, so every hostile walk ends in a refusal rather than a
    /// chain, and the only question is how much it spent getting there.
    fn hostile_resolver() -> TrustChainResolver {
        let (_, anchor_jwk) = fresh_keypair("unreachable-anchor");
        let mut anchor_jwks = FederationKeySet::empty();
        anchor_jwks.push(anchor_jwk);
        TrustChainResolver::new(
            TrustAnchorStore::from_anchors([TrustAnchor {
                entity_id: "https://anchor.example".to_string(),
                jwks: anchor_jwks,
            }]),
            5,
        )
    }

    /// The amplifier, as the re-review described it: one entity that
    /// publishes a wide `authority_hints` array. Before the budget the
    /// depth cap never fired, because every hint sits at depth 1, and
    /// the walk issued one outbound GET per entry.
    ///
    /// Red without the fix: `authority_hints` is refused outright now,
    /// so the walk costs exactly one fetch. Revert
    /// `FetchBudget::check_hints` and the assertion on the log length
    /// jumps to 1 + the array size.
    #[tokio::test]
    async fn security_boundary_a_wide_authority_hints_array_is_refused_before_the_fan_out() {
        let (key, jwk) = fresh_keypair("evil-key");
        let hints: Vec<String> = (0..5000)
            .map(|i| format!("https://victim.example/{i}"))
            .collect();
        let mut configs = HashMap::new();
        configs.insert(
            "https://evil.example".to_string(),
            hostile_config("https://evil.example", hints, &key, &jwk, "evil-key"),
        );
        let fetcher = Arc::new(StubFetcher {
            configs,
            sub_stmts: HashMap::new(),
            log: Mutex::new(vec![]),
        });

        let err = compose_trust_chain(
            fetcher.clone(),
            &hostile_resolver(),
            "https://evil.example",
            8,
        )
        .await
        .expect_err("a 5000-entry authority_hints array must be refused");

        assert!(
            matches!(
                err,
                FederationError::TooManyAuthorityHints { got: 5000, .. }
            ),
            "expected the hints cap to fire, got {err:?}"
        );
        // One fetch: the leaf's own configuration. The fan-out never
        // happened. This is the assertion that makes the test about
        // the amplifier rather than about an error type.
        let log = fetcher.log.lock().unwrap().clone();
        assert_eq!(
            log.len(),
            1,
            "the walk must not dial a single hint from a refused document; log: {log:?}"
        );
    }

    /// The same amplifier spread under the hints cap: a chain that
    /// rotates entity ids so `visited` never short-circuits, with a
    /// legal-sized hint array at every level. Depth is capped high
    /// enough that only the fetch budget can stop it.
    ///
    /// Red without the fix: with `max_fetches` compared to `depth`,
    /// this walk issues one fetch per node across a fan-out of 8 per
    /// level and only stops when it runs out of fixtures.
    #[tokio::test]
    async fn security_boundary_a_rotating_fan_out_chain_stops_at_the_fetch_budget() {
        let (key, jwk) = fresh_keypair("evil-key");
        let mut configs = HashMap::new();
        // A tree: every node names 8 fresh children, four levels deep.
        // 1 + 8 + 64 + 512 nodes, all distinct URLs, so the cycle guard
        // never helps and the depth cap (set to 32 below) never fires.
        fn build(
            prefix: &str,
            level: usize,
            configs: &mut HashMap<String, String>,
            key: &EncodingKey,
            jwk: &serde_json::Value,
        ) {
            if level == 0 {
                configs.insert(
                    prefix.to_string(),
                    hostile_config(prefix, vec![], key, jwk, "evil-key"),
                );
                return;
            }
            let children: Vec<String> = (0..8).map(|i| format!("{prefix}/{i}")).collect();
            configs.insert(
                prefix.to_string(),
                hostile_config(prefix, children.clone(), key, jwk, "evil-key"),
            );
            for child in children {
                build(&child, level - 1, configs, key, jwk);
            }
        }
        build("https://evil.example", 3, &mut configs, &key, &jwk);
        let node_count = configs.len();
        assert!(
            node_count > 500,
            "fixture must be big enough to matter, got {node_count}"
        );

        let fetcher = Arc::new(StubFetcher {
            configs,
            sub_stmts: HashMap::new(),
            log: Mutex::new(vec![]),
        });

        let mut budget = FetchBudget::new(16, DEFAULT_MAX_WALK_BYTES, 30_000, 8);
        let err = compose_trust_chain_budgeted(
            fetcher.clone(),
            &hostile_resolver(),
            "https://evil.example",
            32,
            &mut budget,
        )
        .await
        .expect_err("an unanchored rotating fan-out must be refused");

        assert!(
            matches!(err, FederationError::ChainFetchBudgetExhausted { max: 16 }),
            "expected the fetch budget to fire, got {err:?}"
        );
        let log = fetcher.log.lock().unwrap().clone();
        assert_eq!(
            log.len(),
            16,
            "the walk must spend exactly its budget, not one fetch per node; log length {}",
            log.len()
        );
        assert!(
            log.len() < node_count,
            "the whole point is that the walk stops well short of the {node_count} nodes on offer"
        );
    }

    /// A document the walk cannot verify costs one fetch and drives no
    /// hints, so the cheapest amplifier (an unsigned blob carrying a
    /// large hint array) is refused before it fans out at all.
    ///
    /// Red without the fix: `peek_claims_pub` accepts any
    /// base64-decodable payload, so the hints were walked from a
    /// document with no valid signature.
    #[tokio::test]
    async fn security_boundary_an_unsigned_entity_configuration_drives_no_fetches() {
        // A well-formed three-segment JWS whose signature is garbage.
        let (key, jwk) = fresh_keypair("evil-key");
        let signed = hostile_config(
            "https://evil.example",
            vec![
                "https://victim.example/a".to_string(),
                "https://victim.example/b".to_string(),
            ],
            &key,
            &jwk,
            "evil-key",
        );
        let mut parts: Vec<&str> = signed.split('.').collect();
        assert_eq!(parts.len(), 3);
        let forged_sig = "AAAA".repeat(16);
        parts[2] = forged_sig.as_str();
        let forged = parts.join(".");

        let mut configs = HashMap::new();
        configs.insert("https://evil.example".to_string(), forged);
        let fetcher = Arc::new(StubFetcher {
            configs,
            sub_stmts: HashMap::new(),
            log: Mutex::new(vec![]),
        });

        let err = compose_trust_chain(
            fetcher.clone(),
            &hostile_resolver(),
            "https://evil.example",
            8,
        )
        .await
        .expect_err("a forged signature must be refused");

        assert!(
            matches!(
                err,
                FederationError::EntityConfigurationNotSelfVerified { .. }
            ),
            "expected the self-verification to fire, got {err:?}"
        );
        let log = fetcher.log.lock().unwrap().clone();
        assert_eq!(log.len(), 1, "no hint may be dialed; log: {log:?}");
    }

    /// A configuration served at one URL claiming to be another entity
    /// is refused. The verified `sub` is what the request path writes
    /// back as the caller's identity, so this is an identity check and
    /// not a hygiene one.
    #[tokio::test]
    async fn security_boundary_a_configuration_claiming_another_entity_is_refused() {
        let (key, jwk) = fresh_keypair("evil-key");
        let mut configs = HashMap::new();
        configs.insert(
            "https://evil.example".to_string(),
            hostile_config("https://bank.example", vec![], &key, &jwk, "evil-key"),
        );
        let fetcher = Arc::new(StubFetcher {
            configs,
            sub_stmts: HashMap::new(),
            log: Mutex::new(vec![]),
        });

        let err = compose_trust_chain(fetcher, &hostile_resolver(), "https://evil.example", 8)
            .await
            .expect_err("a subject mismatch must be refused");
        assert!(
            matches!(
                err,
                FederationError::EntityConfigurationSubjectMismatch { .. }
            ),
            "expected the subject check to fire, got {err:?}"
        );
    }

    /// The byte budget stops a peer that stays inside the fetch count
    /// by serving one very large document per hop.
    #[tokio::test]
    async fn security_boundary_the_walk_stops_on_the_byte_budget() {
        let (key, jwk) = fresh_keypair("evil-key");
        let mut configs = HashMap::new();
        configs.insert(
            "https://evil.example".to_string(),
            hostile_config(
                "https://evil.example",
                vec!["https://victim.example/a".to_string()],
                &key,
                &jwk,
                "evil-key",
            ),
        );
        let fetcher = Arc::new(StubFetcher {
            configs,
            sub_stmts: HashMap::new(),
            log: Mutex::new(vec![]),
        });

        // A budget of 16 bytes: the leaf's own configuration is larger
        // than that, so the very first read trips it.
        let mut budget = FetchBudget::new(16, 16, 30_000, 8);
        let err = compose_trust_chain_budgeted(
            fetcher.clone(),
            &hostile_resolver(),
            "https://evil.example",
            8,
            &mut budget,
        )
        .await
        .expect_err("the byte budget must refuse");
        assert!(
            matches!(
                err,
                FederationError::ChainByteBudgetExhausted { max: 16, .. }
            ),
            "expected the byte budget to fire, got {err:?}"
        );
    }

    /// The deadline stops a walk whose hops each answer quickly enough
    /// to stay inside their own timeout.
    #[tokio::test]
    async fn security_boundary_the_walk_stops_on_the_deadline() {
        let (key, jwk) = fresh_keypair("evil-key");
        let mut configs = HashMap::new();
        configs.insert(
            "https://evil.example".to_string(),
            hostile_config("https://evil.example", vec![], &key, &jwk, "evil-key"),
        );
        let fetcher = Arc::new(StubFetcher {
            configs,
            sub_stmts: HashMap::new(),
            log: Mutex::new(vec![]),
        });

        // An already-expired deadline: the first claim refuses before
        // any request goes out, which is the property that matters.
        let mut budget = FetchBudget::new(16, DEFAULT_MAX_WALK_BYTES, 1, 8);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let err = compose_trust_chain_budgeted(
            fetcher.clone(),
            &hostile_resolver(),
            "https://evil.example",
            8,
            &mut budget,
        )
        .await
        .expect_err("the deadline must refuse");
        assert!(
            matches!(err, FederationError::ChainDeadlineExceeded { max_ms: 1 }),
            "expected the deadline to fire, got {err:?}"
        );
        assert!(
            fetcher.log.lock().unwrap().is_empty(),
            "a walk past its deadline must not dial at all"
        );
    }

    /// A budget is spent, not compared: two walks sharing one instance
    /// see the second start where the first stopped. Pins the property
    /// that made the depth cap wrong.
    #[tokio::test]
    async fn the_budget_is_spent_rather_than_compared() {
        let mut budget = FetchBudget::new(3, 1024, 30_000, 8);
        assert_eq!(budget.fetches_spent(), 0);
        assert!(budget.claim_fetch().is_ok());
        assert!(budget.claim_fetch().is_ok());
        assert_eq!(budget.fetches_spent(), 2);
        assert!(budget.claim_fetch().is_ok());
        assert!(
            budget.claim_fetch().is_err(),
            "a fourth claim against a budget of three must refuse"
        );
    }
}
