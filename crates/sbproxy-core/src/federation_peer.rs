//! OpenID Federation peer trust, on the proxy request path.
//!
//! `proxy.federation` publishes this proxy's own entity configuration.
//! This module is the other half: a caller names the entity it claims
//! to be in a header, and the proxy decides whether some anchor the
//! operator pinned vouches for that entity before the request goes any
//! further.
//!
//! The decision is the crate's own machinery, driven from here rather
//! than reimplemented:
//!
//! * [`sbproxy_federation::ReqwestFederationFetcher`] does every fetch,
//!   which puts them behind the unconditional SSRF refusal and, when
//!   the operator armed one, the `egress.federation` allowlist.
//! * [`sbproxy_federation::compose_trust_chain`] walks the peer's
//!   `authority_hints` up to a pinned anchor.
//! * [`sbproxy_federation::TrustChainResolver`] validates every
//!   signature and `iss`/`sub` linkage in the assembled chain.
//! * [`sbproxy_federation::compose_policies`] and
//!   [`sbproxy_federation::apply_block_policy`] apply the s6.1 metadata
//!   policy the chain's superiors imposed, so a peer cannot publish
//!   metadata its superior forbade.
//! * [`sbproxy_federation::verify_trust_mark`] checks each trust mark
//!   the operator requires, against the anchor's own published keys.
//!
//! Each of those steps writes its own `sbproxy_federation_*` counter
//! and emits the decision event `docs/federation.md` documents, so the
//! dashboard and the SIEM feed both move on real traffic.
//!
//! ## What this cannot see
//!
//! The header is a claim, not a credential. This check answers "is the
//! entity that name refers to vouched for by an anchor I pinned", which
//! is the trust-establishment question OpenID Federation exists to
//! answer. It does not answer "is this caller that entity": binding a
//! connection to an entity is mutual TLS or a signed request, and the
//! `authentication:` providers do that. An operator using this without
//! one of those has an allowlist keyed on an unauthenticated header.
//! `docs/federation.md` says so where the block is configured.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sbproxy_federation::{FederationKeySet, TrustAnchor, TrustAnchorStore, TrustChainResolver};

/// Maximum peers held in the decision cache.
///
/// The keys are entity ids taken from a request header, so an
/// unauthenticated caller picks them. Bounded, and full means the
/// oldest entry goes rather than the map growing.
const PEER_CACHE_CAPACITY: usize = 512;

/// Maximum source addresses tracked by the walk rate limiter.
///
/// Bounded for the same reason the decision cache is: the map is keyed
/// on something the network supplies. Full means the oldest window
/// goes, which costs that source its accounting rather than the
/// process its memory.
const WALK_RATE_SOURCES_CAPACITY: usize = 4096;

/// Maximum length of an entity id this verifier will act on. An entity
/// id is a URL; anything longer is not one, and refusing early keeps a
/// long header out of the cache key and the log line.
const MAX_ENTITY_ID_LEN: usize = 512;

/// What the verifier decided about one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerVerdict {
    /// The peer chained to a pinned anchor and satisfied every
    /// required trust mark.
    Trusted {
        /// The peer's entity id, as verified.
        entity_id: String,
        /// The anchor the chain terminated at.
        trust_anchor_id: String,
    },
    /// The peer named itself and could not be verified. Carries a
    /// fixed reason word for the metric label and the log line: the
    /// entity id is caller-supplied, so the refusal must not answer
    /// with what the fetch found.
    Refused(&'static str),
}

/// Compiled `proxy.federation.peer_trust`.
pub(crate) struct FederationPeerVerifier {
    /// Header the peer names itself in, lowercased.
    header: String,
    /// Refuse a request that names no peer at all.
    required: bool,
    resolver: TrustChainResolver,
    fetcher: Arc<dyn sbproxy_federation::FederationFetcher>,
    /// Trust-mark ids a verified peer must additionally carry.
    required_trust_marks: Vec<String>,
    /// Anchor entity id to published JWKS, for trust-mark verification.
    anchor_jwks: HashMap<String, FederationKeySet>,
    /// Depth cap handed to the composer.
    max_depth: usize,
    /// Total fetches one walk may spend.
    max_chain_fetches: usize,
    /// Total bytes one walk may read.
    max_chain_bytes: u64,
    /// Wall-clock budget for one walk.
    max_chain_duration_ms: u64,
    /// Cap on `authority_hints` per entity configuration.
    max_authority_hints: usize,
    /// Chain walks one source address may start per minute.
    walks_per_minute: u32,
    cache_ttl: Duration,
    /// Decision cache.
    ///
    /// Keyed on **(source address, entity id)**, not the entity id
    /// alone. The entity id is attacker-chosen on an unauthenticated
    /// request, so a single-key cache is defeated by rotating it, and
    /// the cache was being described as the thing that stopped a
    /// caller driving one chain walk per request. Including the
    /// source means a rotating caller pays its own rate limit rather
    /// than everyone's, and one peer's cached verdict cannot be
    /// evicted by another source's churn.
    cache: Mutex<HashMap<(String, String), (Instant, PeerVerdict)>>,
    /// Per-source fixed-window walk counter: source address to
    /// (window start, walks started in this window).
    walk_rate: Mutex<HashMap<String, (Instant, u32)>>,
}

impl FederationPeerVerifier {
    /// Build a verifier from compiled config.
    ///
    /// # Errors
    ///
    /// Returns an error when a pinned anchor's JWKS is not a JWK set
    /// this crate can read. The config compiler already refuses an
    /// empty one; this catches a malformed key.
    pub(crate) fn new(config: &sbproxy_config::FederationPeerTrustConfig) -> anyhow::Result<Self> {
        let mut anchors = Vec::with_capacity(config.trust_anchors.len());
        let mut anchor_jwks = HashMap::with_capacity(config.trust_anchors.len());
        for anchor in &config.trust_anchors {
            let jwks: FederationKeySet =
                serde_json::from_value(anchor.jwks.clone()).map_err(|error| {
                    anyhow::anyhow!(
                        "proxy.federation.peer_trust.trust_anchors[{}].jwks is not a JWK set: {error}",
                        anchor.entity_id
                    )
                })?;
            anchor_jwks.insert(anchor.entity_id.clone(), jwks.clone());
            anchors.push(TrustAnchor {
                entity_id: anchor.entity_id.clone(),
                jwks,
            });
        }
        Ok(Self {
            header: config.header.to_ascii_lowercase(),
            required: config.required,
            resolver: TrustChainResolver::new(
                TrustAnchorStore::from_anchors(anchors),
                config.max_chain_depth,
            ),
            fetcher: Arc::new(sbproxy_federation::ReqwestFederationFetcher::new()),
            required_trust_marks: config.required_trust_marks.clone(),
            anchor_jwks,
            max_depth: config.max_chain_depth,
            max_chain_fetches: config.max_chain_fetches,
            max_chain_bytes: config.max_chain_bytes,
            max_chain_duration_ms: config.max_chain_duration_ms,
            max_authority_hints: config.max_authority_hints,
            walks_per_minute: config.walks_per_minute,
            cache_ttl: Duration::from_secs(config.cache_ttl_secs),
            cache: Mutex::new(HashMap::new()),
            walk_rate: Mutex::new(HashMap::new()),
        })
    }

    /// The header name a peer names itself in.
    pub(crate) fn header(&self) -> &str {
        &self.header
    }

    /// Whether a request that names no peer is refused.
    pub(crate) fn required(&self) -> bool {
        self.required
    }

    /// How many peers are currently cached, for the admin surface.
    pub(crate) fn cached_peers(&self) -> usize {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Number of pinned anchors, for the admin surface.
    pub(crate) fn anchor_count(&self) -> usize {
        self.anchor_jwks.len()
    }

    /// Decide about `entity_id`.
    ///
    /// A cached verdict inside the TTL is reused, refusals included: a
    /// peer that just failed to chain would otherwise get a fresh set
    /// of outbound fetches on every request it sends, which is a way
    /// for an unverified caller to make this proxy generate traffic.
    /// `source` is the peer address the request arrived from. It is
    /// half of the cache key and the whole of the rate-limit key, so
    /// a caller that rotates the entity id it claims is limited by
    /// where it is calling from rather than by what it calls itself.
    pub(crate) async fn verify(&self, source: &str, entity_id: &str) -> PeerVerdict {
        if entity_id.len() > MAX_ENTITY_ID_LEN || !entity_id.starts_with("https://") {
            return PeerVerdict::Refused("malformed_entity_id");
        }
        if let Some(cached) = self.cached(source, entity_id) {
            return cached;
        }
        // Only a cache miss reaches the walk, so the limit counts
        // walks rather than requests. A refusal is cached too, which
        // is what keeps a repeat caller off this path entirely.
        if !self.claim_walk(source) {
            return PeerVerdict::Refused("walk_rate_limited");
        }
        let verdict = self.resolve(entity_id).await;
        self.store(source, entity_id, verdict.clone());
        verdict
    }

    /// Claim one walk for `source` in the current fixed window.
    ///
    /// Fixed window rather than a token bucket, matching
    /// `RevocationRateLimiter` in the broker: the burst at a window
    /// edge is bounded by twice the rate, and the walks this guards
    /// are already bounded individually by [`FetchBudget`].
    fn claim_walk(&self, source: &str) -> bool {
        let mut rates = self
            .walk_rate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let window = Duration::from_secs(60);
        rates.retain(|_, (at, _)| at.elapsed() < window);
        // The map is keyed on the source address, which is bounded by
        // the connection table rather than by anything a single caller
        // picks, but a proxy behind a wide NAT range still sees many.
        if rates.len() >= WALK_RATE_SOURCES_CAPACITY && !rates.contains_key(source) {
            if let Some(oldest) = rates
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| key.clone())
            {
                rates.remove(&oldest);
            }
        }
        let entry = rates
            .entry(source.to_string())
            .or_insert_with(|| (Instant::now(), 0));
        if entry.0.elapsed() >= window {
            *entry = (Instant::now(), 0);
        }
        if entry.1 >= self.walks_per_minute {
            return false;
        }
        entry.1 += 1;
        true
    }

    fn cached(&self, source: &str, entity_id: &str) -> Option<PeerVerdict> {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (source.to_string(), entity_id.to_string());
        let (at, verdict) = cache.get(&key)?;
        if at.elapsed() < self.cache_ttl {
            return Some(verdict.clone());
        }
        cache.remove(&key);
        None
    }

    fn store(&self, source: &str, entity_id: &str, verdict: PeerVerdict) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache.retain(|_, (at, _)| at.elapsed() < self.cache_ttl);
        let key = (source.to_string(), entity_id.to_string());
        if cache.len() >= PEER_CACHE_CAPACITY && !cache.contains_key(&key) {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(key, (Instant::now(), verdict));
    }

    async fn resolve(&self, entity_id: &str) -> PeerVerdict {
        let mut budget = sbproxy_federation::FetchBudget::new(
            self.max_chain_fetches,
            self.max_chain_bytes,
            self.max_chain_duration_ms,
            self.max_authority_hints,
        );
        let chain = match sbproxy_federation::compose_trust_chain_budgeted(
            self.fetcher.clone(),
            &self.resolver,
            entity_id,
            self.max_depth,
            &mut budget,
        )
        .await
        {
            Ok(chain) => chain,
            // The error names the peer URL, the resolved address, or
            // the transport failure, all of which are answers to a
            // probe the caller chose the question for. The crate
            // already logged the detail on its own decision event.
            Err(_) => return PeerVerdict::Refused("chain_unresolved"),
        };
        let Some(leaf) = chain.leaf() else {
            return PeerVerdict::Refused("chain_unresolved");
        };
        if !self.metadata_satisfies_policy(&chain, leaf) {
            return PeerVerdict::Refused("metadata_policy");
        }
        if !self.trust_marks_satisfied(leaf, &chain.trust_anchor_id) {
            return PeerVerdict::Refused("trust_mark");
        }
        PeerVerdict::Trusted {
            entity_id: leaf.claims.sub.clone(),
            trust_anchor_id: chain.trust_anchor_id.clone(),
        }
    }

    /// Apply the composed s6.1 metadata policy to the leaf's published
    /// metadata. A policy the leaf violates (an `essential` field it
    /// omitted, a `one_of` it stepped outside) refuses the peer.
    fn metadata_satisfies_policy(
        &self,
        chain: &sbproxy_federation::ResolvedTrustChain,
        leaf: &sbproxy_federation::EntityStatement,
    ) -> bool {
        let mut composed: Option<serde_json::Value> = None;
        // Superiors only. The leaf is the subject of this policy, not
        // one of its authors: composing the leaf's own
        // `metadata_policy` in would let it insert an operator its
        // superior never named and satisfy a constraint its published
        // metadata does not meet.
        for policy in chain.metadata_policies_from_superiors() {
            composed = Some(match composed {
                None => policy.0.clone(),
                Some(superior) => {
                    match sbproxy_federation::compose_policies(&superior, &policy.0) {
                        Ok(merged) => merged,
                        Err(error) => {
                            tracing::warn!(
                                target: "sbproxy_federation::decision",
                                event = "federation_peer_decision",
                                outcome = "refused",
                                reason = "metadata_policy",
                                %error,
                                "peer chain carries metadata policies that do not compose"
                            );
                            return false;
                        }
                    }
                }
            });
        }
        let Some(composed) = composed else {
            // No superior imposed a policy. Nothing to check.
            return true;
        };
        let Ok(leaf_metadata) = serde_json::to_value(&leaf.claims.metadata) else {
            return false;
        };
        let Some(policy_object) = composed.as_object() else {
            return false;
        };
        for (entity_type, block_policy) in policy_object {
            let block = leaf_metadata
                .get(entity_type)
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            if let Err(error) = sbproxy_federation::apply_block_policy(&block, block_policy) {
                tracing::warn!(
                    target: "sbproxy_federation::decision",
                    event = "federation_peer_decision",
                    outcome = "refused",
                    reason = "metadata_policy",
                    entity_type = %entity_type,
                    %error,
                    "peer metadata violates the policy its superior imposed"
                );
                return false;
            }
        }
        true
    }

    /// Every configured trust-mark id must appear on the leaf, signed
    /// by a key the pinned anchor publishes.
    fn trust_marks_satisfied(
        &self,
        leaf: &sbproxy_federation::EntityStatement,
        trust_anchor_id: &str,
    ) -> bool {
        if self.required_trust_marks.is_empty() {
            return true;
        }
        let Some(anchor_jwks) = self.anchor_jwks.get(trust_anchor_id) else {
            return false;
        };
        for required in &self.required_trust_marks {
            let satisfied = leaf.claims.trust_marks.iter().any(|entry| {
                let compact = entry
                    .get("trust_mark")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| entry.as_str());
                let Some(compact) = compact else {
                    return false;
                };
                match sbproxy_federation::verify_trust_mark(compact, anchor_jwks) {
                    Ok(mark) => &mark.claims.id == required && mark.claims.sub == leaf.claims.sub,
                    Err(_) => false,
                }
            });
            if !satisfied {
                tracing::warn!(
                    target: "sbproxy_federation::decision",
                    event = "federation_peer_decision",
                    outcome = "refused",
                    reason = "trust_mark",
                    trust_mark = %required,
                    "peer does not carry a required trust mark signed by the anchor"
                );
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor_config(entity_id: &str) -> sbproxy_config::FederationTrustAnchorConfig {
        sbproxy_config::FederationTrustAnchorConfig {
            entity_id: entity_id.to_string(),
            jwks: serde_json::json!({"keys": [{
                "kty": "EC",
                "crv": "P-256",
                "kid": "anchor-1",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            }]}),
        }
    }

    fn peer_config() -> sbproxy_config::FederationPeerTrustConfig {
        sbproxy_config::FederationPeerTrustConfig {
            required: true,
            header: "X-Federation-Entity-Id".to_string(),
            trust_anchors: vec![anchor_config("https://anchor.example")],
            required_trust_marks: Vec::new(),
            max_chain_depth: 3,
            cache_ttl_secs: 600,
        }
    }

    #[tokio::test]
    async fn a_peer_that_is_not_an_https_entity_url_is_refused_without_a_fetch() {
        let verifier = FederationPeerVerifier::new(&peer_config()).expect("verifier");
        for bad in [
            "http://peer.example",
            "peer.example",
            "",
            "https://peer.example/../../etc",
        ] {
            let verdict = verifier.verify(bad).await;
            if bad == "https://peer.example/../../etc" {
                // A syntactically valid https URL still goes to the
                // fetcher; the refusal there is what covers it.
                assert!(matches!(verdict, PeerVerdict::Refused(_)), "{bad}");
            } else {
                assert_eq!(
                    verdict,
                    PeerVerdict::Refused("malformed_entity_id"),
                    "{bad}"
                );
            }
        }
    }

    #[tokio::test]
    async fn an_over_long_entity_id_is_refused_before_it_becomes_a_cache_key() {
        let verifier = FederationPeerVerifier::new(&peer_config()).expect("verifier");
        let long = format!("https://{}.example", "a".repeat(MAX_ENTITY_ID_LEN));
        assert_eq!(
            verifier.verify(&long).await,
            PeerVerdict::Refused("malformed_entity_id")
        );
        assert_eq!(verifier.cached_peers(), 0);
    }

    #[tokio::test]
    async fn a_refusal_is_cached_so_an_unverified_caller_cannot_drive_repeat_fetches() {
        let verifier = FederationPeerVerifier::new(&peer_config()).expect("verifier");
        // `anchor.invalid` does not resolve, so the chain walk fails
        // and the refusal is what gets cached.
        let first = verifier.verify("https://peer.invalid").await;
        assert!(matches!(first, PeerVerdict::Refused(_)));
        assert_eq!(verifier.cached_peers(), 1);
        let second = verifier.verify("https://peer.invalid").await;
        assert_eq!(first, second);
        assert_eq!(verifier.cached_peers(), 1);
    }

    #[test]
    fn the_header_name_is_matched_case_insensitively() {
        let verifier = FederationPeerVerifier::new(&peer_config()).expect("verifier");
        assert_eq!(verifier.header(), "x-federation-entity-id");
        assert!(verifier.required());
        assert_eq!(verifier.anchor_count(), 1);
    }
}
