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
//! 4. Enforces a depth cap on every step so a malicious upstream
//!    cannot trigger unbounded fetches.
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

use crate::entity_statement::peek_claims_pub;
use crate::errors::{FederationError, FederationResult};
use crate::http_fetcher::FederationFetcher;
use crate::trust_chain::{ResolvedTrustChain, TrustChainResolver};

/// Default cap on `authority_hints` traversal depth. Stops a
/// runaway walk against a federation that mis-publishes its
/// chain. OIDF deployments rarely exceed 4-5 levels; the cap is
/// the same shape as [`TrustChainResolver::max_depth`] but lives
/// independently so the composer can refuse to even FETCH past
/// the cap.
pub const DEFAULT_MAX_CHAIN_FETCHES: usize = 8;

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
    max_fetches: usize,
) -> FederationResult<ResolvedTrustChain> {
    if max_fetches == 0 {
        return Err(FederationError::ChainTooLong { got: 0, max: 0 });
    }

    // Fetch the leaf's own self-signed configuration.
    let leaf_compact = fetcher.fetch_entity_configuration(leaf_entity_id).await?;
    let leaf_claims = peek_claims_pub(&leaf_compact)?;
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
        max_fetches,
        1,
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
    max_fetches: usize,
    depth: usize,
) -> FederationResult<ResolvedTrustChain> {
    if depth > max_fetches {
        return Err(FederationError::ChainTooLong {
            got: depth,
            max: max_fetches,
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
        // Fetch the superior's own Entity Configuration.
        let superior_compact = match fetcher.fetch_entity_configuration(superior_url).await {
            Ok(c) => c,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        let superior_claims = match peek_claims_pub(&superior_compact) {
            Ok(c) => c,
            Err(e) => {
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
            max_fetches,
            depth + 1,
        ))
        .await;
        match recurse_result {
            Ok(child_chain) => {
                // Fetch the subordinate statement only AFTER the superior's chain is authenticated
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
}
