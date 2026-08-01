//! Backend-neutral async contract for the OSS semantic cache.
//!
//! Every semantic-cache backend (memory, Redis, mesh) implements the one
//! [`SemanticCacheStore`] trait defined here. The trait is async so a
//! distributed backend never has to be wrapped in a blocking pool, and it is
//! deliberately narrow: candidate lookup, write, scoped purge, health, and a
//! counter snapshot.
//!
//! Locality-sensitive hashing only ever generates candidates. Every candidate
//! a backend produces is revalidated by [`SemanticExactSelector`] against the
//! wire schema version, the requested namespace, its expiry, its dimensions,
//! vector finiteness, and an exact normalized cosine score before it can be
//! replayed. A malformed or incompatible candidate is counted and skipped, so
//! one bad distributed record can never fail an otherwise healthy lookup and
//! can never produce a false hit.
//!
//! Values held by this contract are sensitive operator data. No type in this
//! module renders a prompt, a response body, a header value, an embedding, a
//! namespace digest, or a generated key through `Debug`, `Display`, or
//! `Serialize`.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::config::{SemanticCacheBackend, MAX_EMBEDDING_DIMENSIONS};
use super::identity::{semantic_entry_key, SemanticEntryKeys, SemanticNamespace};
use super::wire::SEMANTIC_CACHE_SCHEMA_VERSION;
use super::CachedHttpResponse;

/// Fixed root of the generated semantic keyspace. Every purge prefix starts
/// here, so an operator string can never reach a backend key.
const SEMANTIC_KEY_ROOT_PREFIX: &str = "sbproxy:semcache:v2:";

/// One semantic-cache record exactly as a backend holds it.
///
/// The response is shared so a hit clones a reference count rather than the
/// body bytes and header strings.
#[derive(Clone)]
pub struct StoredSemanticEntry {
    /// Wire schema version this record was written under.
    pub schema_version: u16,
    /// Isolation namespace the record belongs to.
    pub namespace: SemanticNamespace,
    /// Digest of the semantic prompt text that produced the record.
    pub prompt_digest: [u8; 32],
    /// L2-normalized prompt embedding.
    pub embedding: Vec<f32>,
    /// Cached upstream response replayed on a hit.
    pub response: Arc<CachedHttpResponse>,
    /// Unix milliseconds when the record was written.
    pub stored_at_unix_ms: u64,
    /// Unix milliseconds after which the record must not be replayed.
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for StoredSemanticEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredSemanticEntry")
            .field("schema_version", &self.schema_version)
            .field("status", &self.response.status)
            .field("body_len", &self.response.body.len())
            .field("header_count", &self.response.headers.len())
            .field("embedding_dimensions", &self.embedding.len())
            .field("stored_at_unix_ms", &self.stored_at_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}

/// One candidate lookup addressed to a backend.
#[derive(Clone)]
pub struct SemanticStoreLookupQuery {
    /// Namespace the caller is allowed to read.
    pub namespace: SemanticNamespace,
    /// Generated entry and bucket-index keys for this prompt.
    pub keys: SemanticEntryKeys,
    /// L2-normalized query embedding.
    pub embedding: Arc<[f32]>,
    /// Minimum exact cosine score a candidate must reach to be replayed.
    pub threshold: f32,
    /// Maximum candidate members a backend reads from one bucket.
    pub maximum_per_bucket: usize,
}

impl fmt::Debug for SemanticStoreLookupQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticStoreLookupQuery")
            .field("embedding_dimensions", &self.embedding.len())
            .field("bucket_count", &self.keys.bucket_indexes.len())
            .field("threshold", &self.threshold)
            .field("maximum_per_bucket", &self.maximum_per_bucket)
            .finish()
    }
}

/// A candidate that passed every revalidation check and met the threshold.
#[derive(Clone)]
pub struct SemanticExactMatch {
    /// The winning record.
    pub entry: Arc<StoredSemanticEntry>,
    /// Exact normalized cosine score of the winning record.
    pub score: f32,
}

impl fmt::Debug for SemanticExactMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticExactMatch")
            .field("status", &self.entry.response.status)
            .field("body_len", &self.entry.response.body.len())
            .field("embedding_dimensions", &self.entry.embedding.len())
            .field("score", &self.score)
            .finish()
    }
}

/// Result of one backend lookup after exact reranking.
#[derive(Clone, Default)]
pub struct SemanticStoreLookup {
    /// The winning candidate, when one met the threshold.
    pub exact_hit: Option<SemanticExactMatch>,
    /// Highest exact score seen among valid candidates, hit or not.
    pub best_score: Option<f32>,
    /// Sum of `expired` and `incompatible`.
    pub rejected: u64,
    /// Candidates skipped because they were past their expiry.
    pub expired: u64,
    /// Candidates skipped because they failed a schema, namespace,
    /// dimension, or finite-vector check.
    pub incompatible: u64,
    /// Whether a backend stopped reading candidates at its bucket bound.
    pub truncated: bool,
}

impl fmt::Debug for SemanticStoreLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticStoreLookup")
            .field("hit", &self.exact_hit.is_some())
            .field("best_score", &self.best_score)
            .field("rejected", &self.rejected)
            .field("expired", &self.expired)
            .field("incompatible", &self.incompatible)
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// One record a backend is asked to admit.
#[derive(Clone)]
pub struct SemanticStoreWrite {
    /// The record to admit.
    pub entry: Arc<StoredSemanticEntry>,
    /// Generated entry and bucket-index keys for this record.
    pub keys: SemanticEntryKeys,
    /// Operator time-to-live in seconds, applied by distributed backends.
    pub ttl_secs: u64,
    /// Maximum members a distributed backend keeps in one bucket manifest.
    pub maximum_per_bucket: usize,
}

impl fmt::Debug for SemanticStoreWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SemanticStoreWrite")
            .field("status", &self.entry.response.status)
            .field("body_len", &self.entry.response.body.len())
            .field("header_count", &self.entry.response.headers.len())
            .field("embedding_dimensions", &self.entry.embedding.len())
            .field("bucket_count", &self.keys.bucket_indexes.len())
            .field("ttl_secs", &self.ttl_secs)
            .field("maximum_per_bucket", &self.maximum_per_bucket)
            .finish()
    }
}

/// How much of the semantic keyspace an admin purge covers.
#[derive(Clone, PartialEq, Eq)]
pub enum SemanticPurgeScope {
    /// Every semantic record this process can reach.
    All,
    /// Every record whose namespace derives from one compiled origin route.
    Origin {
        /// Origin-route digest to remove.
        origin_digest: [u8; 32],
    },
    /// Every record in one exact namespace.
    Namespace {
        /// Namespace to remove.
        namespace: SemanticNamespace,
    },
    /// One prompt inside one namespace.
    Entry {
        /// Namespace holding the record.
        namespace: SemanticNamespace,
        /// Prompt digest of the record to remove.
        prompt_digest: [u8; 32],
    },
}

impl fmt::Debug for SemanticPurgeScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::All => "All",
            Self::Origin { .. } => "Origin",
            Self::Namespace { .. } => "Namespace",
            Self::Entry { .. } => "Entry",
        };
        f.write_str(label)
    }
}

/// What one purge actually removed.
///
/// A distributed purge may be partial. `complete` is the only field an
/// operator should treat as success.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticPurgeReport {
    /// Backend records removed.
    pub removed: u64,
    /// Nodes or stores the purge was sent to.
    pub nodes_attempted: u64,
    /// Nodes or stores that failed or were unreachable.
    pub nodes_failed: u64,
    /// Whether every attempted target reported success.
    pub complete: bool,
}

/// Coarse operational state of one backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticHealthState {
    /// The backend answered a probe normally.
    Healthy,
    /// The backend answered, but part of the fleet or keyspace is impaired.
    Degraded,
    /// The backend cannot serve lookups or writes right now.
    Unavailable,
}

/// Health of one backend, safe to return through admin.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticStoreHealth {
    /// Which backend reported.
    pub backend: SemanticCacheBackend,
    /// Coarse state.
    pub state: SemanticHealthState,
    /// Fixed reason label when the state is not healthy.
    pub reason: Option<&'static str>,
}

/// Counter snapshot for one backend, safe to return through admin.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SemanticStoreStats {
    /// Candidate reads attempted.
    pub candidate_reads: u64,
    /// Candidate reads that failed at the backend.
    pub candidate_read_errors: u64,
    /// Writes attempted.
    pub writes: u64,
    /// Writes that failed at the backend.
    pub write_errors: u64,
    /// Candidate records rejected during revalidation.
    pub rejected_records: u64,
    /// Purges attempted.
    pub purges: u64,
    /// Purges that reported an incomplete result.
    pub purge_errors: u64,
    /// Backend records removed by purges.
    pub purged_entries: u64,
    /// Live local record count, when the backend can count cheaply.
    pub local_entries: Option<usize>,
}

/// Relaxed atomic counters shared by every backend implementation.
#[derive(Default)]
pub struct SemanticStoreCounters {
    candidate_reads: AtomicU64,
    candidate_read_errors: AtomicU64,
    writes: AtomicU64,
    write_errors: AtomicU64,
    rejected_records: AtomicU64,
    purges: AtomicU64,
    purge_errors: AtomicU64,
    purged_entries: AtomicU64,
}

impl fmt::Debug for SemanticStoreCounters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.snapshot(None), f)
    }
}

impl SemanticStoreCounters {
    /// Record one candidate read and whether the backend answered it.
    pub fn record_candidate_read(&self, success: bool) {
        self.candidate_reads.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.candidate_read_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record one write and whether the backend accepted it.
    pub fn record_write(&self, success: bool) {
        self.writes.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.write_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record `count` candidate records that failed revalidation.
    pub fn record_rejected(&self, count: u64) {
        if count > 0 {
            self.rejected_records.fetch_add(count, Ordering::Relaxed);
        }
    }

    /// Record one purge. An incomplete report also counts as a purge error.
    pub fn record_purge(&self, report: &SemanticPurgeReport) {
        self.purges.fetch_add(1, Ordering::Relaxed);
        if !report.complete {
            self.purge_errors.fetch_add(1, Ordering::Relaxed);
        }
        if report.removed > 0 {
            self.purged_entries
                .fetch_add(report.removed, Ordering::Relaxed);
        }
    }

    /// Take a consistent-enough snapshot for admin and metrics.
    pub fn snapshot(&self, local_entries: Option<usize>) -> SemanticStoreStats {
        SemanticStoreStats {
            candidate_reads: self.candidate_reads.load(Ordering::Relaxed),
            candidate_read_errors: self.candidate_read_errors.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            rejected_records: self.rejected_records.load(Ordering::Relaxed),
            purges: self.purges.load(Ordering::Relaxed),
            purge_errors: self.purge_errors.load(Ordering::Relaxed),
            purged_entries: self.purged_entries.load(Ordering::Relaxed),
            local_entries,
        }
    }
}

/// Wall-clock seam shared by the orchestrator and every backend.
///
/// Production code uses [`SystemSemanticClock`]. Tests inject a controlled
/// implementation so expiry is deterministic.
pub trait SemanticClock: Send + Sync {
    /// Current wall-clock time in Unix milliseconds.
    fn now_unix_ms(&self) -> u64;
}

/// Production clock backed by `SystemTime`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSemanticClock;

impl SemanticClock for SystemSemanticClock {
    fn now_unix_ms(&self) -> u64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        u64::try_from(millis).unwrap_or(u64::MAX)
    }
}

/// Shared handle to the production clock.
pub fn system_semantic_clock() -> Arc<dyn SemanticClock> {
    Arc::new(SystemSemanticClock)
}

/// Closed backend failure classes.
///
/// Every `Display` string is a fixed label. A backend must never attach a
/// source error that could carry a DSN, peer address, key, prompt, response,
/// or embedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SemanticStoreError {
    /// The backend could not be reached or is not usable right now.
    #[error("semantic cache backend unavailable")]
    Unavailable,
    /// The record offered for admission failed a structural check.
    #[error("semantic cache write rejected")]
    InvalidWrite,
    /// The backend answered, but its answer was not usable.
    #[error("semantic cache backend returned invalid state")]
    InvalidState,
    /// The operation failed for any other backend reason.
    #[error("semantic cache operation failed")]
    OperationFailed,
}

/// Closed lookup failure classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SemanticLookupError {
    /// The query embedding was empty, oversized, non-finite, or zero-norm.
    #[error("semantic cache embedding is invalid")]
    InvalidEmbedding,
    /// The backend failed the lookup.
    #[error("{0}")]
    Store(#[from] SemanticStoreError),
}

/// The one async contract every semantic-cache backend implements.
#[async_trait::async_trait]
pub trait SemanticCacheStore: Send + Sync {
    /// Which backend this store is.
    fn backend(&self) -> SemanticCacheBackend;

    /// Generate candidates, revalidate them, and return the exact winner.
    async fn lookup(
        &self,
        query: &SemanticStoreLookupQuery,
    ) -> Result<SemanticStoreLookup, SemanticStoreError>;

    /// Admit one record.
    async fn put(&self, write: &SemanticStoreWrite) -> Result<(), SemanticStoreError>;

    /// Remove every record covered by `scope`.
    async fn purge(
        &self,
        scope: &SemanticPurgeScope,
    ) -> Result<SemanticPurgeReport, SemanticStoreError>;

    /// Probe the backend.
    async fn health(&self) -> SemanticStoreHealth;

    /// Snapshot this store's counters.
    fn stats(&self) -> SemanticStoreStats;
}

/// Literal generated key prefix for one purge scope.
///
/// The returned string contains only fixed ASCII labels and lowercase hex,
/// never a Redis glob character and never an operator-supplied string. The
/// Redis adapter alone appends `*` to the three prefix scopes for `SCAN
/// MATCH`; mesh passes the literal prefix through unchanged.
pub fn semantic_purge_prefix(scope: &SemanticPurgeScope) -> String {
    match scope {
        SemanticPurgeScope::All => SEMANTIC_KEY_ROOT_PREFIX.to_string(),
        SemanticPurgeScope::Origin { origin_digest } => {
            format!(
                "{SEMANTIC_KEY_ROOT_PREFIX}o:{}:",
                hex::encode(origin_digest)
            )
        }
        SemanticPurgeScope::Namespace { namespace } => namespace.namespace_prefix(),
        SemanticPurgeScope::Entry {
            namespace,
            prompt_digest,
        } => semantic_entry_key(namespace, prompt_digest),
    }
}

/// L2-normalize a semantic vector, rejecting an unusable one.
///
/// Returns `None` for an empty vector, a vector above the common dimension
/// limit, a vector containing a non-finite element, or a zero-norm vector.
pub(crate) fn normalize_semantic_vector(values: &[f32]) -> Option<Vec<f32>> {
    if values.is_empty() || values.len() > MAX_EMBEDDING_DIMENSIONS {
        return None;
    }
    let mut sum_of_squares = 0f64;
    for value in values {
        if !value.is_finite() {
            return None;
        }
        sum_of_squares += f64::from(*value) * f64::from(*value);
    }
    let norm = sum_of_squares.sqrt();
    if !norm.is_finite() || norm <= 0.0 {
        return None;
    }
    Some(
        values
            .iter()
            .map(|value| (f64::from(*value) / norm) as f32)
            .collect(),
    )
}

/// Dot product of two equal-length normalized vectors.
fn dot_product(left: &[f32], right: &[f32]) -> f32 {
    left.iter().zip(right).map(|(a, b)| a * b).sum()
}

/// Streaming exact reranker for semantic candidates.
///
/// Backends feed decoded candidates in as their bounded fetch yields them.
/// The selector retains only the current winner, one score, and closed
/// rejection counts, so it never materializes every decoded response body at
/// once. It deliberately does not implement `Debug`, because it holds the
/// normalized query vector and the current winning response.
pub struct SemanticExactSelector {
    query: Vec<f32>,
    threshold: f32,
    expected_namespace: SemanticNamespace,
    now_unix_ms: u64,
    winner: Option<Arc<StoredSemanticEntry>>,
    winner_score: f32,
    best_score: Option<f32>,
    expired: u64,
    incompatible: u64,
}

impl SemanticExactSelector {
    /// Build a selector for one lookup.
    ///
    /// `now_unix_ms` is snapshot once per lookup and reused for every
    /// candidate, so a record cannot change classification halfway through
    /// one operation. An unusable query vector fails the whole lookup.
    pub fn new(
        query: Arc<[f32]>,
        threshold: f32,
        expected_namespace: SemanticNamespace,
        now_unix_ms: u64,
    ) -> Result<Self, SemanticLookupError> {
        let normalized =
            normalize_semantic_vector(&query).ok_or(SemanticLookupError::InvalidEmbedding)?;
        Ok(Self {
            query: normalized,
            threshold,
            expected_namespace,
            now_unix_ms,
            winner: None,
            winner_score: f32::NEG_INFINITY,
            best_score: None,
            expired: 0,
            incompatible: 0,
        })
    }

    /// Revalidate one candidate and keep it if it is the new best hit.
    ///
    /// An invalid candidate is counted and skipped so one malformed
    /// distributed record cannot fail the lookup.
    pub fn consider(&mut self, candidate: Arc<StoredSemanticEntry>) {
        if candidate.schema_version != SEMANTIC_CACHE_SCHEMA_VERSION
            || candidate.namespace != self.expected_namespace
            || candidate.expires_at_unix_ms <= candidate.stored_at_unix_ms
            || candidate.embedding.len() != self.query.len()
        {
            self.incompatible += 1;
            return;
        }
        if candidate.expires_at_unix_ms <= self.now_unix_ms {
            self.expired += 1;
            return;
        }
        let Some(normalized) = normalize_semantic_vector(&candidate.embedding) else {
            self.incompatible += 1;
            return;
        };
        let score = dot_product(&self.query, &normalized);
        if !score.is_finite() {
            self.incompatible += 1;
            return;
        }
        if self.best_score.map(|best| score > best).unwrap_or(true) {
            self.best_score = Some(score);
        }
        if score < self.threshold {
            return;
        }
        let replaces_winner = match self.winner.as_ref() {
            None => true,
            Some(current) => {
                score > self.winner_score
                    || (score == self.winner_score
                        && candidate.prompt_digest < current.prompt_digest)
            }
        };
        if replaces_winner {
            self.winner_score = score;
            self.winner = Some(candidate);
        }
    }

    /// Finish reranking and report the outcome.
    pub fn finish(self) -> SemanticStoreLookup {
        let rejected = self.expired.saturating_add(self.incompatible);
        let winner_score = self.winner_score;
        SemanticStoreLookup {
            exact_hit: self.winner.map(|entry| SemanticExactMatch {
                entry,
                score: winner_score,
            }),
            best_score: self.best_score,
            rejected,
            expired: self.expired,
            incompatible: self.incompatible,
            truncated: false,
        }
    }
}

/// Synchronous convenience wrapper over [`SemanticExactSelector`].
///
/// Used by the memory backend, which scans an iterator of live entries it
/// already holds. Distributed backends drive the selector directly instead so
/// they never hold every decoded candidate at once.
pub fn select_exact_hit<'a, I>(
    query: &[f32],
    candidates: I,
    threshold: f32,
    expected_namespace: &SemanticNamespace,
    now_unix_ms: u64,
) -> Result<SemanticStoreLookup, SemanticLookupError>
where
    I: IntoIterator<Item = &'a Arc<StoredSemanticEntry>>,
{
    let mut selector = SemanticExactSelector::new(
        Arc::from(query),
        threshold,
        expected_namespace.clone(),
        now_unix_ms,
    )?;
    for candidate in candidates {
        selector.consider(Arc::clone(candidate));
    }
    Ok(selector.finish())
}

#[cfg(test)]
pub(crate) mod contract {
    //! Shared assertion table every backend in this crate must satisfy.
    //!
    //! This harness is deliberately `#[cfg(test)]` and crate-private. A
    //! dependent crate cannot see it, so `sbproxy-core` mirrors the same
    //! table in its own private helper for the Redis and mesh adapters.

    use super::*;
    use crate::semantic_cache::config::SemanticLshConfig;
    use crate::semantic_cache::identity::{
        semantic_entry_keys, semantic_prompt_digest, SemanticNamespaceInput,
    };
    use crate::semantic_cache::lsh::RandomProjectionLsh;
    use crate::semantic_cache::CachedHttpResponse;

    /// Candidate bound used by every harness lookup.
    pub(crate) const CONTRACT_MAX_PER_BUCKET: usize = 32;

    /// Threshold used by every harness lookup.
    pub(crate) const CONTRACT_THRESHOLD: f32 = 0.99;

    /// Build a deterministic namespace for one tenant and origin route.
    pub(crate) fn contract_namespace(tenant: &str, origin_route: &str) -> SemanticNamespace {
        SemanticNamespace::derive(SemanticNamespaceInput {
            origin_route,
            request_host: "api.example.com",
            tenant_id: tenant,
            credential_identity: "api-key:contract",
            requested_model: "gpt-4o-mini",
            api_surface: "openai.chat",
            request_context_digest: &[7u8; 32],
            embedding_identity: "provider/openai/text-embedding-3-small",
            embedding_dimensions: 3,
            semantic_config_digest: &[9u8; 32],
            response_policy_digest: &[11u8; 32],
            schema_version: SEMANTIC_CACHE_SCHEMA_VERSION,
        })
    }

    /// Build generated keys for one prompt and embedding.
    pub(crate) fn contract_keys(
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
    ) -> SemanticEntryKeys {
        let lsh = RandomProjectionLsh::from_config(&SemanticLshConfig::default())
            .expect("default lsh configuration builds");
        let buckets = lsh.buckets(embedding).expect("fixture vector projects");
        semantic_entry_keys(namespace, &semantic_prompt_digest(prompt), &buckets)
    }

    /// Build one record ready for admission.
    pub(crate) fn contract_entry(
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
        body: &str,
        stored_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Arc<StoredSemanticEntry> {
        let normalized = normalize_semantic_vector(embedding).expect("fixture vector normalizes");
        Arc::new(StoredSemanticEntry {
            schema_version: SEMANTIC_CACHE_SCHEMA_VERSION,
            namespace: namespace.clone(),
            prompt_digest: semantic_prompt_digest(prompt),
            embedding: normalized,
            response: Arc::new(CachedHttpResponse {
                status: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: bytes::Bytes::from(body.as_bytes().to_vec()),
            }),
            stored_at_unix_ms,
            expires_at_unix_ms,
        })
    }

    /// Admit one record through the contract.
    pub(crate) async fn contract_put(
        store: &Arc<dyn SemanticCacheStore>,
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
        body: &str,
        stored_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) {
        let entry = contract_entry(
            namespace,
            prompt,
            embedding,
            body,
            stored_at_unix_ms,
            expires_at_unix_ms,
        );
        let write = SemanticStoreWrite {
            entry,
            keys: contract_keys(namespace, prompt, embedding),
            ttl_secs: 600,
            maximum_per_bucket: CONTRACT_MAX_PER_BUCKET,
        };
        store.put(&write).await.expect("contract write is accepted");
    }

    /// Run one lookup through the contract.
    pub(crate) async fn contract_lookup(
        store: &Arc<dyn SemanticCacheStore>,
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
    ) -> SemanticStoreLookup {
        let query = SemanticStoreLookupQuery {
            namespace: namespace.clone(),
            keys: contract_keys(namespace, prompt, embedding),
            embedding: Arc::from(
                normalize_semantic_vector(embedding)
                    .expect("fixture vector normalizes")
                    .as_slice(),
            ),
            threshold: CONTRACT_THRESHOLD,
            maximum_per_bucket: CONTRACT_MAX_PER_BUCKET,
        };
        store.lookup(&query).await.expect("contract lookup answers")
    }

    /// Assert the full backend-neutral assertion table against one store.
    pub(crate) async fn assert_semantic_store_contract(store: Arc<dyn SemanticCacheStore>) {
        let now = SystemSemanticClock.now_unix_ms();
        let live_until = now + 600_000;
        let namespace_a = contract_namespace("tenant-secret-a", "origin-a.example");
        let namespace_b = contract_namespace("tenant-secret-b", "origin-a.example");
        let namespace_c = contract_namespace("tenant-secret-a", "origin-c.example");

        // empty store misses
        let empty = contract_lookup(&store, &namespace_a, "refund policy", &[1.0, 0.0, 0.0]).await;
        assert!(empty.exact_hit.is_none(), "empty store must miss");

        // put then load returns the stored entry
        contract_put(
            &store,
            &namespace_a,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "alpha-body",
            now,
            live_until,
        )
        .await;
        let loaded = contract_lookup(&store, &namespace_a, "refund policy", &[1.0, 0.0, 0.0]).await;
        let hit = loaded.exact_hit.expect("stored entry is returned");
        assert_eq!(hit.entry.response.body.as_ref(), b"alpha-body");
        assert!(hit.score >= CONTRACT_THRESHOLD);

        // namespace lookup cannot see another tenant scope
        let cross = contract_lookup(&store, &namespace_b, "refund policy", &[1.0, 0.0, 0.0]).await;
        assert!(cross.exact_hit.is_none(), "another tenant must not read");

        // TTL expiry removes the entry
        store
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("purge all");
        contract_put(
            &store,
            &namespace_a,
            "stale prompt",
            &[1.0, 0.0, 0.0],
            "stale-body",
            now.saturating_sub(120_000),
            now.saturating_sub(1),
        )
        .await;
        let expired = contract_lookup(&store, &namespace_a, "stale prompt", &[1.0, 0.0, 0.0]).await;
        assert!(expired.exact_hit.is_none(), "expired entry must not hit");

        // origin purge removes only one origin
        store
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("purge all");
        contract_put(
            &store,
            &namespace_a,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "origin-a",
            now,
            live_until,
        )
        .await;
        contract_put(
            &store,
            &namespace_c,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "origin-c",
            now,
            live_until,
        )
        .await;
        let report = store
            .purge(&SemanticPurgeScope::Origin {
                origin_digest: namespace_a.origin_digest(),
            })
            .await
            .expect("origin purge");
        assert!(report.complete, "origin purge must complete");
        assert!(
            contract_lookup(&store, &namespace_a, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .exact_hit
                .is_none()
        );
        assert!(
            contract_lookup(&store, &namespace_c, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .exact_hit
                .is_some()
        );

        // namespace purge removes only one namespace
        store
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("purge all");
        contract_put(
            &store,
            &namespace_a,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "scope-a",
            now,
            live_until,
        )
        .await;
        contract_put(
            &store,
            &namespace_b,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "scope-b",
            now,
            live_until,
        )
        .await;
        store
            .purge(&SemanticPurgeScope::Namespace {
                namespace: namespace_a.clone(),
            })
            .await
            .expect("namespace purge");
        assert!(
            contract_lookup(&store, &namespace_a, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .exact_hit
                .is_none()
        );
        assert!(
            contract_lookup(&store, &namespace_b, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .exact_hit
                .is_some()
        );

        // entry purge removes only one prompt
        store
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("purge all");
        contract_put(
            &store,
            &namespace_a,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "prompt-one",
            now,
            live_until,
        )
        .await;
        contract_put(
            &store,
            &namespace_a,
            "shipping policy",
            &[0.0, 1.0, 0.0],
            "prompt-two",
            now,
            live_until,
        )
        .await;
        store
            .purge(&SemanticPurgeScope::Entry {
                namespace: namespace_a.clone(),
                prompt_digest: semantic_prompt_digest("refund policy"),
            })
            .await
            .expect("entry purge");
        assert!(
            contract_lookup(&store, &namespace_a, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .exact_hit
                .is_none()
        );
        assert!(
            contract_lookup(&store, &namespace_a, "shipping policy", &[0.0, 1.0, 0.0])
                .await
                .exact_hit
                .is_some()
        );

        // all purge removes every semantic key
        let purged = store
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("purge all");
        assert!(purged.complete);
        assert!(
            contract_lookup(&store, &namespace_a, "shipping policy", &[0.0, 1.0, 0.0])
                .await
                .exact_hit
                .is_none()
        );

        // health is healthy after successful operations
        let health = store.health().await;
        assert_eq!(health.state, SemanticHealthState::Healthy);
        assert_eq!(health.backend, store.backend());

        // stats count reads, writes, and purges without raw labels
        let stats = store.stats();
        assert!(stats.candidate_reads > 0);
        assert!(stats.writes > 0);
        assert!(stats.purges > 0);
        let rendered = serde_json::to_string(&stats).expect("stats serialize");
        for sentinel in [
            "tenant-secret-a",
            "refund policy",
            "alpha-body",
            "origin-a.example",
            "sbproxy:semcache",
        ] {
            assert!(
                !rendered.contains(sentinel),
                "stats must not carry {sentinel}"
            );
        }

        // store errors have fixed Display text and no leaking source
        for error in [
            SemanticStoreError::Unavailable,
            SemanticStoreError::InvalidWrite,
            SemanticStoreError::InvalidState,
            SemanticStoreError::OperationFailed,
        ] {
            let text = error.to_string();
            assert!(text.starts_with("semantic cache"));
            assert!(std::error::Error::source(&error).is_none());
            for sentinel in [
                "redis://",
                "127.0.0.1",
                "tenant-secret-a",
                "refund policy",
                "alpha-body",
            ] {
                assert!(!text.contains(sentinel), "error must not carry {sentinel}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::contract::{contract_entry, contract_namespace};
    use super::*;

    fn entry_at(
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
        expires_at_unix_ms: u64,
    ) -> Arc<StoredSemanticEntry> {
        contract_entry(
            namespace,
            prompt,
            embedding,
            "body",
            1_000,
            expires_at_unix_ms,
        )
    }

    #[test]
    fn invalid_query_vectors_fail_the_lookup() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let empty: Vec<Arc<StoredSemanticEntry>> = Vec::new();
        for query in [
            Vec::new(),
            vec![0.0, 0.0, 0.0],
            vec![f32::NAN, 1.0, 0.0],
            vec![f32::INFINITY, 1.0, 0.0],
        ] {
            let error = select_exact_hit(&query, empty.iter(), 0.9, &namespace, 2_000)
                .expect_err("invalid query fails");
            assert_eq!(error, SemanticLookupError::InvalidEmbedding);
        }
    }

    #[test]
    fn a_bucket_collision_below_threshold_misses() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let stored = entry_at(&namespace, "refund policy", &[0.0, 1.0, 0.0], 9_000);
        let candidates = [stored];
        let result = select_exact_hit(&[1.0, 0.0, 0.0], candidates.iter(), 0.9, &namespace, 2_000)
            .expect("valid query");
        assert!(result.exact_hit.is_none());
        assert_eq!(result.best_score, Some(0.0));
        assert_eq!(result.rejected, 0);
    }

    #[test]
    fn expired_and_incompatible_candidates_are_counted_not_fatal() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let other = contract_namespace("tenant-secret-b", "origin-a.example");
        let expired = entry_at(&namespace, "old", &[1.0, 0.0, 0.0], 1_500);
        let wrong_namespace = entry_at(&other, "other", &[1.0, 0.0, 0.0], 9_000);
        let wrong_dimensions = entry_at(&namespace, "wide", &[1.0, 0.0, 0.0, 0.0], 9_000);
        let good = entry_at(&namespace, "good", &[1.0, 0.0, 0.0], 9_000);
        let candidates = [expired, wrong_namespace, wrong_dimensions, good];
        let result = select_exact_hit(&[1.0, 0.0, 0.0], candidates.iter(), 0.9, &namespace, 2_000)
            .expect("valid query");
        assert!(result.exact_hit.is_some());
        assert_eq!(result.expired, 1);
        assert_eq!(result.incompatible, 2);
        assert_eq!(result.rejected, 3);
    }

    #[test]
    fn equal_scores_break_by_lexicographic_prompt_digest() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let left = entry_at(&namespace, "prompt-one", &[1.0, 0.0, 0.0], 9_000);
        let right = entry_at(&namespace, "prompt-two", &[1.0, 0.0, 0.0], 9_000);
        let expected = left.prompt_digest.min(right.prompt_digest);
        for candidates in [
            vec![left.clone(), right.clone()],
            vec![right.clone(), left.clone()],
        ] {
            let result =
                select_exact_hit(&[1.0, 0.0, 0.0], candidates.iter(), 0.9, &namespace, 2_000)
                    .expect("valid query");
            let hit = result.exact_hit.expect("one winner");
            assert_eq!(hit.entry.prompt_digest, expected);
        }
    }

    #[test]
    fn purge_prefixes_contain_only_fixed_labels_and_hex() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let scopes = [
            SemanticPurgeScope::All,
            SemanticPurgeScope::Origin {
                origin_digest: namespace.origin_digest(),
            },
            SemanticPurgeScope::Namespace {
                namespace: namespace.clone(),
            },
            SemanticPurgeScope::Entry {
                namespace: namespace.clone(),
                prompt_digest: [3u8; 32],
            },
        ];
        for scope in &scopes {
            let prefix = semantic_purge_prefix(scope);
            assert!(prefix.starts_with(SEMANTIC_KEY_ROOT_PREFIX));
            assert!(!prefix.contains('*'));
            assert!(!prefix.contains("tenant-secret-a"));
            assert!(!prefix.contains("origin-a.example"));
            assert!(prefix
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == ':'));
        }
        assert_eq!(
            semantic_purge_prefix(&SemanticPurgeScope::All),
            "sbproxy:semcache:v2:"
        );
        assert_eq!(
            semantic_purge_prefix(&scopes[1]),
            namespace.origin_prefix(),
            "origin scope matches the namespace origin prefix"
        );
    }

    #[test]
    fn purge_scope_debug_never_prints_a_digest() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let rendered = format!(
            "{:?} {:?} {:?} {:?}",
            SemanticPurgeScope::All,
            SemanticPurgeScope::Origin {
                origin_digest: namespace.origin_digest()
            },
            SemanticPurgeScope::Namespace {
                namespace: namespace.clone()
            },
            SemanticPurgeScope::Entry {
                namespace,
                prompt_digest: [3u8; 32]
            }
        );
        assert_eq!(rendered, "All Origin Namespace Entry");
    }

    #[test]
    fn entry_and_write_debug_redact_values() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let entry = contract_entry(
            &namespace,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "sentinel-body",
            1_000,
            9_000,
        );
        let write = SemanticStoreWrite {
            entry: Arc::clone(&entry),
            keys: super::contract::contract_keys(&namespace, "refund policy", &[1.0, 0.0, 0.0]),
            ttl_secs: 60,
            maximum_per_bucket: 32,
        };
        let rendered = format!("{entry:?} {write:?}");
        for sentinel in [
            "sentinel-body",
            "refund policy",
            "tenant-secret-a",
            "sbproxy:semcache",
            "content-type",
        ] {
            assert!(
                !rendered.contains(sentinel),
                "debug output must not carry {sentinel}"
            );
        }
    }

    #[test]
    fn counters_snapshot_reads_writes_and_purges() {
        let counters = SemanticStoreCounters::default();
        counters.record_candidate_read(true);
        counters.record_candidate_read(false);
        counters.record_write(true);
        counters.record_write(false);
        counters.record_rejected(3);
        counters.record_purge(&SemanticPurgeReport {
            removed: 5,
            nodes_attempted: 1,
            nodes_failed: 0,
            complete: true,
        });
        counters.record_purge(&SemanticPurgeReport {
            removed: 1,
            nodes_attempted: 2,
            nodes_failed: 1,
            complete: false,
        });
        let stats = counters.snapshot(Some(4));
        assert_eq!(stats.candidate_reads, 2);
        assert_eq!(stats.candidate_read_errors, 1);
        assert_eq!(stats.writes, 2);
        assert_eq!(stats.write_errors, 1);
        assert_eq!(stats.rejected_records, 3);
        assert_eq!(stats.purges, 2);
        assert_eq!(stats.purge_errors, 1);
        assert_eq!(stats.purged_entries, 6);
        assert_eq!(stats.local_entries, Some(4));
    }
}
