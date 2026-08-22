//! Semantic cache for AI responses.
//!
//! Caches responses keyed by a hash of the input messages so that
//! identical (or near-identical) prompts can be served from cache,
//! saving latency and provider cost.

use lru::LruCache;
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// How many recent lookup decisions the embedding cache keeps for the
/// admin debug inspector (WOR-1756).
const RECENT_DECISIONS_CAP: usize = 100;

/// One semantic-cache lookup outcome, recorded for the admin debug
/// inspector so an operator can see why a request did or did not hit.
///
/// A decision is deliberately identity-free: it keeps no scope, namespace,
/// prompt, key, model, origin, credential, response, embedding, or backend
/// error text.
#[derive(Debug, Clone, Serialize)]
pub struct CacheDecision {
    /// One of `hit`, `no_entry`, `expired`, `below_threshold`,
    /// `incompatible`, or `backend_error`.
    pub reason: &'static str,
    /// The matched cosine score on a hit, or the closest candidate's score
    /// on a `below_threshold` miss; `None` otherwise.
    pub score: Option<f32>,
    /// The similarity threshold the lookup was gated on.
    pub threshold: f32,
    /// Unix seconds when the lookup happened.
    pub at_unix: u64,
}

/// Thread-safe exact-match cache for AI responses.
///
/// Entries are evicted when they exceed the configured TTL. When the
/// cache is full, the least-recently-used entry is evicted in O(1).
pub struct SemanticCache {
    exact_cache: Mutex<LruCache<String, CachedAiResponse>>,
    ttl_secs: u64,
}

/// A cached AI response with hit-count tracking.
#[derive(Debug, Clone)]
pub struct CachedAiResponse {
    /// The cached response body as JSON.
    pub response: serde_json::Value,
    /// Unix timestamp (seconds) when the entry was inserted.
    pub cached_at: u64,
    /// Number of times this entry has been served from cache.
    pub hit_count: u64,
}

impl SemanticCache {
    /// Create a new cache with a maximum number of entries and a TTL.
    pub fn new(max_entries: usize, ttl_secs: u64) -> Self {
        let cap = NonZeroUsize::new(max_entries.max(1)).expect("max_entries clamped to at least 1");
        Self {
            exact_cache: Mutex::new(LruCache::new(cap)),
            ttl_secs,
        }
    }

    /// Look up a cached response by prompt hash.
    ///
    /// Returns `None` if the entry is missing or expired. Increments
    /// the hit counter on a successful lookup.
    pub fn lookup(&self, prompt_hash: &str) -> Option<CachedAiResponse> {
        let mut cache = self.exact_cache.lock();
        let now = Self::now_secs();

        if let Some(entry) = cache.get_mut(prompt_hash) {
            if now.saturating_sub(entry.cached_at) > self.ttl_secs {
                cache.pop(prompt_hash);
                return None;
            }
            entry.hit_count += 1;
            return Some(entry.clone());
        }
        None
    }

    /// Store a response in the cache. Evicts the least-recently-used entry when full.
    pub fn store(&self, prompt_hash: &str, response: serde_json::Value) {
        let mut cache = self.exact_cache.lock();
        cache.put(
            prompt_hash.to_string(),
            CachedAiResponse {
                response,
                cached_at: Self::now_secs(),
                hit_count: 0,
            },
        );
    }

    /// Compute a deterministic hash for a list of messages.
    ///
    /// Uses SHA-256 over the RFC 8785 canonical JSON form of the
    /// messages to produce a hex-encoded digest suitable as a cache
    /// key.
    ///
    /// Canonicalizing (rather than `serde_json::to_string` directly)
    /// matters because [`crate::types::Message::content`] is a raw
    /// `serde_json::Value`: multimodal content is a client-supplied
    /// array of objects, and this workspace's `serde_json/preserve_order`
    /// feature (forced on transitively by `cedar-policy-core`; see
    /// `sbproxy-extension/Cargo.toml`'s comment) means an object's keys
    /// now serialize in whatever order the client's JSON happened to
    /// use, not a normalized order. Two semantically identical
    /// multimodal messages differing only in key order would otherwise
    /// hash differently and silently miss this cache's exact-match
    /// lookup instead of hitting it. `serde_json_canonicalizer` sorts
    /// object keys before hashing, matching the same pattern
    /// `sbproxy_config::cache_identity` already uses for exactly this
    /// reason.
    pub fn compute_hash(messages: &[crate::types::Message]) -> String {
        use sha2::{Digest, Sha256};
        let value = serde_json::to_value(messages).unwrap_or(serde_json::Value::Null);
        let canonical = serde_json_canonicalizer::to_vec(&value).unwrap_or_default();
        let hash = Sha256::digest(&canonical);
        hex::encode(hash)
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

// --- WOR-796: embedding-similarity cache (OSS) ---

pub mod config;
pub mod identity;
pub mod lsh;
pub mod memory;
pub mod store;
pub mod wire;

pub use identity::*;
pub use lsh::*;
pub use memory::MemorySemanticCacheStore;
pub use store::{
    select_exact_hit, semantic_purge_prefix, system_semantic_clock, SemanticCacheStore,
    SemanticClock, SemanticExactMatch, SemanticExactSelector, SemanticHealthState,
    SemanticLookupError, SemanticPurgeReport, SemanticPurgeScope, SemanticStoreCounters,
    SemanticStoreError, SemanticStoreHealth, SemanticStoreLookup, SemanticStoreLookupQuery,
    SemanticStoreStats, SemanticStoreWrite, StoredSemanticEntry, SystemSemanticClock,
};
pub use wire::{
    decode_entry, encode_entry, WireError, MAX_SEMANTIC_HEADER_NAME_BYTES,
    MAX_SEMANTIC_HEADER_VALUE_BYTES, MAX_SEMANTIC_RESPONSE_HEADERS,
    MAX_SEMANTIC_TOTAL_HEADER_BYTES, SEMANTIC_CACHE_SCHEMA_VERSION,
};

// The configuration surface lives in `config.rs`. It is re-exported as a
// glob so every typed field, default, and bound stays reachable under the
// historical `sbproxy_ai::semantic_cache::` paths.
pub use config::*;

use std::sync::atomic::{AtomicU64, Ordering};
use store::normalize_semantic_vector;

/// A cached HTTP response retained for replay on a semantic hit.
///
/// The body is a `Bytes` handle, so admitting a response and replaying it
/// both clone a reference count instead of copying the buffered bytes.
#[derive(Clone)]
pub struct CachedHttpResponse {
    /// Upstream status code. Only 200 is cacheable.
    pub status: u16,
    /// Safe response headers, already stripped of hop-by-hop, framing,
    /// cookie, authentication, correlation, and rate-limit fields.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: bytes::Bytes,
}

impl std::fmt::Debug for CachedHttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedHttpResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Outcome of a successful semantic lookup: the cached response plus
/// the cosine similarity score that matched it.
#[derive(Clone)]
pub struct EmbeddingHit {
    /// The cached response to replay. Shared with the stored record, so
    /// obtaining it off a hit is a refcount bump, not a body copy.
    pub response: Arc<CachedHttpResponse>,
    /// Exact normalized cosine similarity of the query against the match.
    pub score: f32,
}

impl std::fmt::Debug for EmbeddingHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingHit")
            .field("status", &self.response.status)
            .field("header_count", &self.response.headers.len())
            .field("body_len", &self.response.body.len())
            .field("score", &self.score)
            .finish()
    }
}

/// One semantic lookup against an already derived namespace.
///
/// The namespace is built at the request boundary so the cache never sees a
/// tenant id, credential, model name, host, or policy value directly.
pub struct SemanticLookupRequest<'a> {
    /// Isolation namespace the caller is allowed to read and write.
    pub namespace: SemanticNamespace,
    /// Semantic prompt text used for the prompt digest.
    pub prompt: &'a str,
    /// Query embedding for this prompt.
    pub embedding: &'a [f32],
}

/// What one semantic lookup decided.
pub enum SemanticLookupOutcome {
    /// A stored response met the threshold and may be replayed.
    Hit(EmbeddingHit),
    /// Nothing matched. The token admits the provider response later.
    ///
    /// Boxed because the token carries the namespace and every bucket key,
    /// which is about 760 bytes against 16 for a hit. Returning that
    /// inline would move it on every lookup, hit or miss; a lookup already
    /// costs an embedding and a backend round trip, so one allocation on
    /// the miss path is not measurable next to that.
    Miss(Box<SemanticWriteToken>),
}

/// Private admission ticket produced by a miss.
///
/// It carries the derived namespace, prompt digest, normalized embedding,
/// and generated keys so the eventual write cannot drift from the lookup
/// that produced it. Its fields are private and it has no `Debug`.
pub struct SemanticWriteToken {
    namespace: SemanticNamespace,
    prompt_digest: [u8; 32],
    embedding: Vec<f32>,
    keys: SemanticEntryKeys,
}

/// Orchestration counters for the admin surface.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct EmbeddingCacheStats {
    /// Lookups attempted.
    pub lookups: u64,
    /// Lookups that replayed a stored response.
    pub hits: u64,
    /// Lookups that found nothing to replay.
    pub misses: u64,
    /// Lookups that failed at the backend or on an unusable query vector.
    pub lookup_errors: u64,
    /// Responses admitted.
    pub writes: u64,
    /// Admissions rejected by the operator cap or by the backend.
    pub write_errors: u64,
    /// Candidates skipped because they were past their expiry.
    pub expired: u64,
    /// Candidates skipped because they failed revalidation.
    pub incompatible: u64,
    /// Misses where the closest candidate scored below the threshold.
    pub below_threshold: u64,
}

/// Relaxed atomic counters behind [`EmbeddingCacheStats`].
#[derive(Default)]
struct EmbeddingCacheCounters {
    lookups: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    lookup_errors: AtomicU64,
    writes: AtomicU64,
    write_errors: AtomicU64,
    expired: AtomicU64,
    incompatible: AtomicU64,
    below_threshold: AtomicU64,
}

impl EmbeddingCacheCounters {
    fn snapshot(&self) -> EmbeddingCacheStats {
        EmbeddingCacheStats {
            lookups: self.lookups.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            lookup_errors: self.lookup_errors.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            incompatible: self.incompatible.load(Ordering::Relaxed),
            below_threshold: self.below_threshold.load(Ordering::Relaxed),
        }
    }
}

impl std::fmt::Debug for EmbeddingCacheCounters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.snapshot(), f)
    }
}

/// Canonical embedding semantic cache.
///
/// The cache owns orchestration only: it validates and normalizes the query
/// vector, derives the prompt digest and locality-sensitive hashing buckets,
/// builds the generated keys, and asks one [`SemanticCacheStore`] for an
/// already exactly reranked answer. Memory, Redis, and mesh all satisfy that
/// one contract, so the request path is identical for every backend.
pub struct EmbeddingCache {
    threshold: f32,
    ttl_secs: u64,
    /// Optional operator cap on an admitted response body.
    max_response_bytes: Option<usize>,
    /// Maximum candidate members a distributed backend reads per bucket.
    candidates_per_bucket: usize,
    /// Which backend this cache runs on.
    backend: SemanticCacheBackend,
    /// Secret-free compatibility digest of the compiled semantic block.
    configuration_digest: [u8; 32],
    /// Safe embedding source and model label used in namespace identity.
    embedding_identity: String,
    /// Where prompt embeddings come from.
    source: EmbeddingSource,
    /// Embedding provider name (for `source: provider`; empty otherwise).
    provider: String,
    /// Embedding model id (for `source: provider`; empty otherwise).
    model: String,
    /// Sidecar endpoint config (for `source: sidecar`).
    sidecar: Option<SidecarEmbeddingConfig>,
    /// In-process embedder config (for `source: inprocess`).
    inprocess: Option<InprocessEmbeddingConfig>,
    /// Standalone OpenAI-compatible endpoint config (for `source: openai`).
    openai: Option<OpenAiEmbeddingConfig>,
    store: Arc<dyn SemanticCacheStore>,
    lsh: RandomProjectionLsh,
    clock: Arc<dyn SemanticClock>,
    stats: EmbeddingCacheCounters,
    /// Recent lookup decisions for the admin debug inspector (WOR-1756),
    /// bounded to the most recent `RECENT_DECISIONS_CAP`.
    recent: Mutex<VecDeque<CacheDecision>>,
}

impl std::fmt::Debug for EmbeddingCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingCache")
            .field("backend", &self.backend)
            .field("source", &self.source)
            .field("model", &self.model)
            .field("threshold", &self.threshold)
            .field("ttl_secs", &self.ttl_secs)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("candidates_per_bucket", &self.candidates_per_bucket)
            .field("stats", &self.stats)
            .finish()
    }
}

/// Safe embedding-source label fed into namespace compatibility identity.
///
/// It carries the source kind, the provider name where one applies, and the
/// model id. Endpoints, base URLs, local paths, and credentials stay out; the
/// separate configuration digest already covers those.
fn embedding_identity_label(source: EmbeddingSource, provider: &str, model: &str) -> String {
    match source {
        EmbeddingSource::Provider => format!("provider/{provider}/{model}"),
        EmbeddingSource::Sidecar => format!("sidecar/{model}"),
        EmbeddingSource::Inprocess => format!("inprocess/{model}"),
        EmbeddingSource::Openai => format!("openai/{model}"),
    }
}

impl EmbeddingCache {
    /// Build the memory compatibility cache from a validated config.
    ///
    /// Returns `None` when the config is disabled, when it selects a backend
    /// other than memory, or when the selected embedding source has no
    /// config block to vectorize with. An explicit Redis or mesh selection
    /// must never silently run on a memory adapter, so it stays inert here
    /// and is built through [`EmbeddingCache::with_store`] instead.
    pub fn from_config(cfg: &EmbeddingCacheConfig) -> Option<Self> {
        if cfg.backend != SemanticCacheBackend::Memory {
            return None;
        }
        let store = Arc::new(MemorySemanticCacheStore::new(cfg.max_entries));
        Self::with_store(cfg, store).ok().flatten()
    }

    /// Build a cache over an explicit backend store.
    ///
    /// Fails when the store's backend does not match the configured backend,
    /// or when the locality-sensitive hashing settings cannot be compiled.
    /// Returns `Ok(None)` when the config is disabled or inert.
    pub fn with_store(
        cfg: &EmbeddingCacheConfig,
        store: Arc<dyn SemanticCacheStore>,
    ) -> anyhow::Result<Option<Self>> {
        Self::build(cfg, store, system_semantic_clock())
    }

    /// Build a cache over an explicit backend store and clock.
    ///
    /// Reserved for tests that need deterministic expiry. The same clock must
    /// be given to the store so both agree on time.
    #[cfg(test)]
    pub fn with_store_and_clock(
        cfg: &EmbeddingCacheConfig,
        store: Arc<dyn SemanticCacheStore>,
        clock: Arc<dyn SemanticClock>,
    ) -> anyhow::Result<Option<Self>> {
        Self::build(cfg, store, clock)
    }

    fn build(
        cfg: &EmbeddingCacheConfig,
        store: Arc<dyn SemanticCacheStore>,
        clock: Arc<dyn SemanticClock>,
    ) -> anyhow::Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }
        if store.backend() != cfg.backend {
            anyhow::bail!("semantic cache store does not match the configured backend");
        }
        // Each source needs its own config block to be usable. A missing
        // block means there is nothing to vectorize with, so the cache
        // stays inert rather than half-built.
        let (provider, model, sidecar, inprocess, openai) = match cfg.source {
            EmbeddingSource::Provider => match cfg.embedding.as_ref() {
                Some(e) => (e.provider.clone(), e.model.clone(), None, None, None),
                None => return Ok(None),
            },
            EmbeddingSource::Sidecar => match cfg.sidecar.as_ref() {
                Some(s) => (String::new(), s.model.clone(), Some(s.clone()), None, None),
                None => return Ok(None),
            },
            EmbeddingSource::Inprocess => match cfg.inprocess.as_ref() {
                // The embedder is built and held by sbproxy-core (which can
                // depend on the tract engine without a dependency cycle). The
                // cache carries the config so core can load it.
                Some(p) => (String::new(), p.model.clone(), None, Some(p.clone()), None),
                None => return Ok(None),
            },
            EmbeddingSource::Openai => match cfg.openai.as_ref() {
                // Standalone OpenAI-compatible endpoint, decoupled from the
                // origin's chat providers.
                Some(o) => (String::new(), o.model.clone(), None, None, Some(o.clone())),
                None => return Ok(None),
            },
        };
        let lsh = RandomProjectionLsh::from_config(&cfg.lsh)
            .map_err(|_| anyhow::anyhow!("semantic cache lsh settings are invalid"))?;
        let embedding_identity = embedding_identity_label(cfg.source, &provider, &model);
        Ok(Some(Self {
            threshold: cfg.threshold,
            ttl_secs: cfg.ttl_secs,
            max_response_bytes: cfg.max_response_bytes,
            candidates_per_bucket: cfg.lsh.candidates_per_bucket,
            backend: cfg.backend,
            configuration_digest: semantic_configuration_digest(cfg),
            embedding_identity,
            source: cfg.source,
            provider,
            model,
            sidecar,
            inprocess,
            openai,
            store,
            lsh,
            clock,
            stats: EmbeddingCacheCounters::default(),
            recent: Mutex::new(VecDeque::new()),
        }))
    }

    /// Where this cache gets prompt embeddings.
    pub fn source(&self) -> EmbeddingSource {
        self.source
    }
    /// Sidecar endpoint config, when `source` is `sidecar`.
    pub fn sidecar_config(&self) -> Option<&SidecarEmbeddingConfig> {
        self.sidecar.as_ref()
    }
    /// In-process embedder config, when `source` is `inprocess`.
    pub fn inprocess_config(&self) -> Option<&InprocessEmbeddingConfig> {
        self.inprocess.as_ref()
    }
    /// Standalone OpenAI-compatible endpoint config, when `source` is `openai`.
    pub fn openai_config(&self) -> Option<&OpenAiEmbeddingConfig> {
        self.openai.as_ref()
    }
    /// Embedding provider name to vectorize prompts with (provider source).
    pub fn provider(&self) -> &str {
        &self.provider
    }
    /// Embedding model id (provider source).
    pub fn model(&self) -> &str {
        &self.model
    }
    /// Configured similarity threshold.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }
    /// Which backend this cache runs on.
    pub fn backend(&self) -> SemanticCacheBackend {
        self.backend
    }
    /// Secret-free compatibility digest of the compiled semantic block.
    pub fn configuration_digest(&self) -> &[u8; 32] {
        &self.configuration_digest
    }
    /// Safe embedding source and model label for namespace identity.
    ///
    /// It never contains an endpoint, base URL, local path, header, or
    /// credential.
    pub fn embedding_identity(&self) -> &str {
        &self.embedding_identity
    }
    /// Orchestration counter snapshot.
    pub fn stats(&self) -> EmbeddingCacheStats {
        self.stats.snapshot()
    }
    /// Backend counter snapshot.
    pub fn store_stats(&self) -> SemanticStoreStats {
        self.store.stats()
    }

    /// Look one prompt up in its namespace.
    ///
    /// On a miss the caller receives a private write token that admits the
    /// eventual provider response under exactly the identity this lookup
    /// used. A backend failure returns an error; the request path treats
    /// that as a miss and routes to the provider.
    pub async fn lookup(
        &self,
        request: SemanticLookupRequest<'_>,
    ) -> Result<SemanticLookupOutcome, SemanticLookupError> {
        let now = self.clock.now_unix_ms();
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);

        let Some(normalized) = normalize_semantic_vector(request.embedding) else {
            self.stats.lookup_errors.fetch_add(1, Ordering::Relaxed);
            self.record_decision("incompatible", None, now);
            return Err(SemanticLookupError::InvalidEmbedding);
        };
        let prompt_digest = semantic_prompt_digest(request.prompt);
        let Ok(buckets) = self.lsh.buckets(&normalized) else {
            self.stats.lookup_errors.fetch_add(1, Ordering::Relaxed);
            self.record_decision("incompatible", None, now);
            return Err(SemanticLookupError::InvalidEmbedding);
        };
        let keys = semantic_entry_keys(&request.namespace, &prompt_digest, &buckets);
        let query = SemanticStoreLookupQuery {
            namespace: request.namespace.clone(),
            keys: keys.clone(),
            embedding: Arc::from(normalized.as_slice()),
            threshold: self.threshold,
            maximum_per_bucket: self.candidates_per_bucket,
        };

        let result = match self.store.lookup(&query).await {
            Ok(result) => result,
            Err(error) => {
                self.stats.lookup_errors.fetch_add(1, Ordering::Relaxed);
                self.record_decision("backend_error", None, now);
                return Err(SemanticLookupError::Store(error));
            }
        };
        self.stats
            .expired
            .fetch_add(result.expired, Ordering::Relaxed);
        self.stats
            .incompatible
            .fetch_add(result.incompatible, Ordering::Relaxed);

        if let Some(hit) = result.exact_hit {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            self.record_decision("hit", Some(hit.score), now);
            return Ok(SemanticLookupOutcome::Hit(EmbeddingHit {
                response: Arc::clone(&hit.entry.response),
                score: hit.score,
            }));
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        let reason = if result.best_score.is_some() {
            self.stats.below_threshold.fetch_add(1, Ordering::Relaxed);
            "below_threshold"
        } else if result.expired > 0 {
            "expired"
        } else if result.incompatible > 0 {
            "incompatible"
        } else {
            "no_entry"
        };
        self.record_decision(reason, result.best_score, now);
        Ok(SemanticLookupOutcome::Miss(Box::new(SemanticWriteToken {
            namespace: request.namespace,
            prompt_digest,
            embedding: normalized,
            keys,
        })))
    }

    /// Admit a provider response under a token from an earlier miss.
    ///
    /// The stored timestamp is taken here, after the provider response and
    /// output guardrails complete, so provider latency never consumes the
    /// operator time-to-live. Expiry uses checked arithmetic; a time-to-live
    /// that would overflow is rejected instead of saturating into a
    /// practically immortal record.
    pub async fn store(
        &self,
        token: SemanticWriteToken,
        response: CachedHttpResponse,
    ) -> Result<(), SemanticStoreError> {
        if self
            .max_response_bytes
            .is_some_and(|cap| response.body.len() > cap)
        {
            self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
            return Err(SemanticStoreError::InvalidWrite);
        }
        let stored_at_unix_ms = self.clock.now_unix_ms();
        let Some(expires_at_unix_ms) = self
            .ttl_secs
            .checked_mul(1_000)
            .and_then(|ttl_ms| stored_at_unix_ms.checked_add(ttl_ms))
        else {
            self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
            return Err(SemanticStoreError::InvalidWrite);
        };
        let write = SemanticStoreWrite {
            entry: Arc::new(StoredSemanticEntry {
                schema_version: SEMANTIC_CACHE_SCHEMA_VERSION,
                namespace: token.namespace,
                prompt_digest: token.prompt_digest,
                embedding: token.embedding,
                response: Arc::new(response),
                stored_at_unix_ms,
                expires_at_unix_ms,
            }),
            keys: token.keys,
            ttl_secs: self.ttl_secs,
            maximum_per_bucket: self.candidates_per_bucket,
        };
        match self.store.put(&write).await {
            Ok(()) => {
                self.stats.writes.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(error) => {
                self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    /// Remove every record covered by `scope` from this cache's backend.
    pub async fn purge(
        &self,
        scope: &SemanticPurgeScope,
    ) -> Result<SemanticPurgeReport, SemanticStoreError> {
        self.store.purge(scope).await
    }

    /// Probe this cache's backend.
    pub async fn health(&self) -> SemanticStoreHealth {
        self.store.health().await
    }

    /// Record a lookup outcome in the bounded recent-decisions buffer for
    /// the admin debug inspector (WOR-1756).
    ///
    /// A decision retains no scope, namespace, prompt, key, model, origin,
    /// credential, response, embedding, or backend error text.
    fn record_decision(&self, reason: &'static str, score: Option<f32>, at_unix_ms: u64) {
        let mut recent = self.recent.lock();
        if recent.len() >= RECENT_DECISIONS_CAP {
            recent.pop_front();
        }
        recent.push_back(CacheDecision {
            reason,
            score,
            threshold: self.threshold,
            at_unix: at_unix_ms / 1_000,
        });
    }

    /// The most recent lookup decisions, newest first, for the admin
    /// debug inspector.
    pub fn recent_decisions(&self, limit: usize) -> Vec<CacheDecision> {
        let recent = self.recent.lock();
        recent.iter().rev().take(limit).cloned().collect()
    }
}

/// Compute an embedding via the local classifier sidecar's `Embed` RPC.
///
/// Used when `source: sidecar`. No provider API call, no prompt egress.
pub async fn compute_embedding_sidecar(
    cfg: &SidecarEmbeddingConfig,
    text: &str,
) -> anyhow::Result<Vec<f32>> {
    let client = sbproxy_classifier_client::ClassifierClient::connect_lazy(
        &cfg.endpoint,
        std::time::Duration::from_millis(cfg.timeout_ms),
    )
    .map_err(|e| anyhow::anyhow!("sidecar connect: {e}"))?;
    let mut out = client
        .embed(&cfg.model, &[text.to_string()])
        .await
        .map_err(|e| anyhow::anyhow!("sidecar embed: {e}"))?;
    out.pop()
        .ok_or_else(|| anyhow::anyhow!("sidecar returned no embedding"))
}

/// Compute an embedding vector for `text` by POSTing `/v1/embeddings`
/// to `provider` with `model` (WOR-796). Used by the dispatcher to
/// vectorize a prompt for the semantic-cache lookup. Returns the first
/// embedding vector (one input string in, one vector out).
pub async fn compute_embedding(
    client: &crate::client::AiClient,
    provider: &crate::provider::ProviderConfig,
    model: &str,
    text: &str,
) -> anyhow::Result<Vec<f32>> {
    let body = serde_json::json!({ "model": model, "input": text });
    let response = client
        .forward_request(provider, "/v1/embeddings", &body)
        .await?;
    parse_embedding_response(response, &format!("embedding provider {}", provider.name)).await
}

/// Compute a provider-backed embedding with settlement at the HTTP send seam.
pub async fn compute_embedding_with_quota(
    client: &crate::client::AiClient,
    provider: &crate::provider::ProviderConfig,
    model: &str,
    text: &str,
    quota_attempt: crate::quota_pool::QuotaPoolAttemptGuard,
) -> anyhow::Result<Vec<f32>> {
    let body = serde_json::json!({ "model": model, "input": text });
    let response = client
        .forward_request_with_quota(provider, "/v1/embeddings", &body, quota_attempt)
        .await?;
    parse_embedding_response(response, &format!("embedding provider {}", provider.name)).await
}

async fn parse_embedding_response(
    response: reqwest::Response,
    endpoint: &str,
) -> anyhow::Result<Vec<f32>> {
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("{endpoint} returned status {status}");
    }
    let parsed: crate::types::EmbeddingResponse = response
        .json()
        .await
        .map_err(|error| anyhow::anyhow!("{endpoint} response parse failed: {error}"))?;
    let first = parsed
        .data
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("{endpoint} response contained no vectors"))?;
    Ok(first.embedding.into_iter().map(|x| x as f32).collect())
}

/// Build the request headers for a standalone OpenAI-compatible embedding
/// call (WOR-1520): the auth header from `api_key` + `auth_header` +
/// `auth_prefix` (when a key is set), then the extra `headers` on top.
fn openai_request_headers(
    cfg: &OpenAiEmbeddingConfig,
) -> anyhow::Result<reqwest::header::HeaderMap> {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut headers = HeaderMap::new();
    if let Some(key) = cfg.api_key.as_deref().filter(|k| !k.is_empty()) {
        let name = HeaderName::from_bytes(cfg.auth_header.as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid auth_header {:?}: {e}", cfg.auth_header))?;
        // The error from an invalid value does not echo the value, so a bad
        // key never lands in logs; still mark it sensitive for good measure.
        let mut value = HeaderValue::from_str(&format!("{}{}", cfg.auth_prefix, key))
            .map_err(|_| anyhow::anyhow!("api_key produced an invalid auth header value"))?;
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    // Extra headers apply after the auth header (insert replaces on a name
    // collision), so a custom auth header can be carried here when api_key
    // is omitted, or override the default.
    for (raw_name, raw_value) in &cfg.headers {
        let name = HeaderName::from_bytes(raw_name.as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid header name {raw_name:?}: {e}"))?;
        let value = HeaderValue::from_str(raw_value)
            .map_err(|e| anyhow::anyhow!("invalid value for header {raw_name:?}: {e}"))?;
        headers.insert(name, value);
    }
    Ok(headers)
}

/// Compute an embedding via a standalone OpenAI-compatible `/v1/embeddings`
/// endpoint (WOR-1520). Used when `source: openai`. Not tied to the origin's
/// chat providers: carries its own base URL + auth.
pub async fn compute_embedding_openai(
    cfg: &OpenAiEmbeddingConfig,
    text: &str,
) -> anyhow::Result<Vec<f32>> {
    compute_embedding_openai_impl(cfg, text, None).await
}

/// Compute a standalone OpenAI-compatible embedding with quota settlement at send.
pub async fn compute_embedding_openai_with_quota(
    cfg: &OpenAiEmbeddingConfig,
    text: &str,
    quota_attempt: crate::quota_pool::QuotaPoolAttemptGuard,
) -> anyhow::Result<Vec<f32>> {
    compute_embedding_openai_impl(cfg, text, Some(quota_attempt)).await
}

async fn compute_embedding_openai_impl(
    cfg: &OpenAiEmbeddingConfig,
    text: &str,
    quota_attempt: Option<crate::quota_pool::QuotaPoolAttemptGuard>,
) -> anyhow::Result<Vec<f32>> {
    let url_string = crate::client::build_url(cfg.base_url.trim_end_matches('/'), "/v1/embeddings");
    let url = reqwest::Url::parse(&url_string)
        .map_err(|error| anyhow::anyhow!("openai embed URL: {error}"))?;
    let headers = openai_request_headers(cfg)?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .build()
        .map_err(|e| anyhow::anyhow!("openai embed client build: {e}"))?;
    let body = serde_json::json!({ "model": cfg.model, "input": text });
    let request = http.post(url).headers(headers).json(&body);
    if let Some(attempt) = quota_attempt {
        attempt.commit().await.map_err(anyhow::Error::new)?;
    }
    let response = request
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("openai embed request: {e}"))?;
    parse_embedding_response(response, "openai embedding endpoint").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Message;
    use std::sync::Arc;

    #[derive(Default)]
    struct RecordingQuotaStore {
        settled: tokio::sync::Mutex<Vec<String>>,
        released: tokio::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl crate::quota_pool::QuotaPoolStore for RecordingQuotaStore {
        async fn reserve(
            &self,
            pool: &str,
            member: &str,
            units: u64,
            reservation_id: &str,
        ) -> Result<crate::quota_pool::QuotaReservation, crate::quota_pool::PoolError> {
            Ok(crate::quota_pool::QuotaReservation {
                pool: pool.to_string(),
                member: member.to_string(),
                units,
                reservation_id: reservation_id.to_string(),
            })
        }

        async fn reconcile(
            &self,
            reservation: crate::quota_pool::QuotaReservation,
            _actual: crate::quota_pool::PoolUsage,
        ) -> Result<(), crate::quota_pool::PoolError> {
            self.settled.lock().await.push(reservation.reservation_id);
            Ok(())
        }

        async fn release(
            &self,
            reservation: crate::quota_pool::QuotaReservation,
        ) -> Result<(), crate::quota_pool::PoolError> {
            self.released.lock().await.push(reservation.reservation_id);
            Ok(())
        }
    }

    fn quota_config() -> crate::quota_pool::QuotaPoolConfig {
        serde_json::from_value(serde_json::json!({
            "name": "semantic",
            "total_limit": 10,
            "weights": {"virtual-key-a": 1},
            "policy": "burst"
        }))
        .expect("quota fixture")
    }

    #[test]
    fn store_and_lookup() {
        let cache = SemanticCache::new(10, 3600);
        cache.store("hash1", serde_json::json!({"text": "hello"}));
        let hit = cache.lookup("hash1");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().response["text"], "hello");
    }

    #[test]
    fn lookup_miss_returns_none() {
        let cache = SemanticCache::new(10, 3600);
        assert!(cache.lookup("nonexistent").is_none());
    }

    #[test]
    fn evicts_lru_when_full() {
        let cache = SemanticCache::new(2, 3600);
        cache.store("a", serde_json::json!("first"));
        cache.store("b", serde_json::json!("second"));
        // Touch "a" so it becomes more-recently-used than "b".
        let _ = cache.lookup("a");
        cache.store("c", serde_json::json!("third"));
        // "b" was the LRU and should be evicted.
        assert!(cache.lookup("a").is_some());
        assert!(cache.lookup("b").is_none());
        assert!(cache.lookup("c").is_some());
    }

    #[test]
    fn evicts_oldest_without_access() {
        let cache = SemanticCache::new(2, 3600);
        cache.store("a", serde_json::json!("first"));
        cache.store("b", serde_json::json!("second"));
        cache.store("c", serde_json::json!("third"));
        // No touches: "a" is LRU and should be evicted.
        assert!(cache.lookup("a").is_none());
        assert!(cache.lookup("b").is_some());
        assert!(cache.lookup("c").is_some());
    }

    #[test]
    fn compute_hash_deterministic() {
        let msgs = vec![Message {
            role: "user".to_string(),
            content: serde_json::json!("hello"),
        }];
        let h1 = SemanticCache::compute_hash(&msgs);
        let h2 = SemanticCache::compute_hash(&msgs);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    /// WOR-2587 review: guards against the exact-match cache silently
    /// degrading to an always-miss for multimodal content under the
    /// workspace-wide `preserve_order` feature, which makes
    /// `serde_json::Value` serialize in source key order rather than a
    /// normalized order. Two messages carrying the same multimodal
    /// content but different JSON key order must hash the same.
    #[test]
    fn compute_hash_is_key_order_independent_for_multimodal_content() {
        let a = vec![Message {
            role: "user".to_string(),
            content: serde_json::json!([{"type": "text", "text": "hi"}]),
        }];
        let b = vec![Message {
            role: "user".to_string(),
            content: serde_json::json!([{"text": "hi", "type": "text"}]),
        }];
        assert_eq!(
            SemanticCache::compute_hash(&a),
            SemanticCache::compute_hash(&b),
            "two semantically identical multimodal messages that differ only in JSON key \
             order must hash the same, or the exact-match cache silently degrades to \
             always-miss for them"
        );
    }

    // --- WOR-796: embedding cache ---

    use crate::semantic_cache::store::contract::{
        contract_entry, contract_keys, contract_namespace,
    };

    /// Clock the orchestration tests advance by hand.
    struct TestClock(AtomicU64);

    impl TestClock {
        fn new(now_unix_ms: u64) -> Self {
            Self(AtomicU64::new(now_unix_ms))
        }

        fn advance(&self, millis: u64) {
            self.0.fetch_add(millis, Ordering::Relaxed);
        }
    }

    impl SemanticClock for TestClock {
        fn now_unix_ms(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    /// A backend that fails every operation, used to prove fail-open behavior.
    struct FailingStore;

    #[async_trait::async_trait]
    impl SemanticCacheStore for FailingStore {
        fn backend(&self) -> SemanticCacheBackend {
            SemanticCacheBackend::Memory
        }
        async fn lookup(
            &self,
            _query: &SemanticStoreLookupQuery,
        ) -> Result<SemanticStoreLookup, SemanticStoreError> {
            Err(SemanticStoreError::Unavailable)
        }
        async fn put(&self, _write: &SemanticStoreWrite) -> Result<(), SemanticStoreError> {
            Err(SemanticStoreError::Unavailable)
        }
        async fn purge(
            &self,
            _scope: &SemanticPurgeScope,
        ) -> Result<SemanticPurgeReport, SemanticStoreError> {
            Err(SemanticStoreError::Unavailable)
        }
        async fn health(&self) -> SemanticStoreHealth {
            SemanticStoreHealth {
                backend: SemanticCacheBackend::Memory,
                state: SemanticHealthState::Unavailable,
                reason: Some("probe failed"),
            }
        }
        fn stats(&self) -> SemanticStoreStats {
            SemanticStoreStats::default()
        }
    }

    fn embed_config(threshold: f32, ttl: u64, max: usize) -> EmbeddingCacheConfig {
        serde_json::from_value(serde_json::json!({
            "enabled": true,
            "threshold": threshold,
            "ttl_secs": ttl,
            "max_entries": max,
            "embedding": { "provider": "openai", "model": "text-embedding-3-small" }
        }))
        .expect("embedding cache fixture parses")
    }

    fn embed_cache(threshold: f32, ttl: u64, max: usize) -> EmbeddingCache {
        EmbeddingCache::from_config(&embed_config(threshold, ttl, max))
            .expect("enabled config builds")
    }

    fn embed_cache_with_store(
        cfg: &EmbeddingCacheConfig,
    ) -> (EmbeddingCache, Arc<MemorySemanticCacheStore>) {
        let store = Arc::new(MemorySemanticCacheStore::new(cfg.max_entries));
        let cache = EmbeddingCache::with_store(cfg, store.clone())
            .expect("store matches the configured backend")
            .expect("enabled config builds");
        (cache, store)
    }

    fn clocked_cache(cfg: &EmbeddingCacheConfig, clock: Arc<TestClock>) -> EmbeddingCache {
        let store = Arc::new(MemorySemanticCacheStore::with_clock(
            cfg.max_entries,
            clock.clone(),
        ));
        EmbeddingCache::with_store_and_clock(cfg, store, clock)
            .expect("store matches the configured backend")
            .expect("enabled config builds")
    }

    fn resp(body: &str) -> CachedHttpResponse {
        CachedHttpResponse {
            status: 200,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: bytes::Bytes::from(body.as_bytes().to_vec()),
        }
    }

    async fn expect_miss(
        cache: &EmbeddingCache,
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
    ) -> SemanticWriteToken {
        match cache
            .lookup(SemanticLookupRequest {
                namespace: namespace.clone(),
                prompt,
                embedding,
            })
            .await
        {
            Ok(SemanticLookupOutcome::Miss(token)) => *token,
            Ok(SemanticLookupOutcome::Hit(_)) => panic!("expected a miss"),
            Err(error) => panic!("expected a miss, got {error}"),
        }
    }

    async fn maybe_hit(
        cache: &EmbeddingCache,
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
    ) -> Option<EmbeddingHit> {
        match cache
            .lookup(SemanticLookupRequest {
                namespace: namespace.clone(),
                prompt,
                embedding,
            })
            .await
        {
            Ok(SemanticLookupOutcome::Hit(hit)) => Some(hit),
            _ => None,
        }
    }

    /// Admit a response for `prompt` through the ordinary miss-then-store path.
    async fn admit(
        cache: &EmbeddingCache,
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
        body: &str,
    ) {
        let token = expect_miss(cache, namespace, prompt, embedding).await;
        cache
            .store(token, resp(body))
            .await
            .expect("memory admission succeeds");
    }

    /// Seed a record straight into the backend, bypassing orchestration, so a
    /// test can plant a candidate the orchestrator would never write.
    // Deliberate: the fixture needs the record vector and the index vector to
    // differ, which is exactly the eighth argument.
    #[allow(clippy::too_many_arguments)]
    async fn seed(
        store: &Arc<MemorySemanticCacheStore>,
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
        index_vector: &[f32],
        body: &str,
        stored_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) {
        let write = SemanticStoreWrite {
            entry: contract_entry(
                namespace,
                prompt,
                embedding,
                body,
                stored_at_unix_ms,
                expires_at_unix_ms,
            ),
            keys: contract_keys(namespace, prompt, index_vector),
            ttl_secs: 600,
            maximum_per_bucket: 32,
        };
        store.put(&write).await.expect("seed is accepted");
    }

    #[test]
    fn disabled_config_builds_no_cache() {
        let cfg: EmbeddingCacheConfig = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "embedding": { "provider": "openai", "model": "m" }
        }))
        .expect("fixture parses");
        assert!(EmbeddingCache::from_config(&cfg).is_none());
    }

    #[test]
    fn enabled_without_embedding_block_builds_no_cache() {
        let cfg: EmbeddingCacheConfig =
            serde_json::from_value(serde_json::json!({ "enabled": true })).expect("fixture parses");
        assert!(EmbeddingCache::from_config(&cfg).is_none());
    }

    #[test]
    fn with_store_rejects_a_backend_mismatch() {
        let cfg: EmbeddingCacheConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "backend": "redis",
            "embedding": { "provider": "openai", "model": "m" }
        }))
        .expect("fixture parses");
        let memory: Arc<dyn SemanticCacheStore> = Arc::new(MemorySemanticCacheStore::new(8));
        assert!(EmbeddingCache::with_store(&cfg, memory).is_err());
        // The memory compatibility constructor stays inert for a distributed
        // backend rather than silently running on process-local storage.
        assert!(EmbeddingCache::from_config(&cfg).is_none());
    }

    #[tokio::test]
    async fn lookup_miss_returns_a_write_token() {
        let cache = embed_cache(0.85, 3600, 16);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let token = expect_miss(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0]).await;
        cache
            .store(token, resp("cached"))
            .await
            .expect("token admits the response");
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().writes, 1);
    }

    #[tokio::test]
    async fn store_with_the_token_then_lookup_hits() {
        let cache = embed_cache(0.85, 3600, 16);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        admit(
            &cache,
            &namespace,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "cached",
        )
        .await;
        let hit = maybe_hit(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0])
            .await
            .expect("stored response replays");
        assert_eq!(hit.response.body.as_ref(), b"cached");
    }

    #[tokio::test]
    async fn embedding_hit_reuses_the_stored_response_arc_without_copying_the_body() {
        let cache = embed_cache(0.85, 3600, 16);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        admit(
            &cache,
            &namespace,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "cached",
        )
        .await;
        let first = maybe_hit(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0])
            .await
            .expect("first hit");
        let second = maybe_hit(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0])
            .await
            .expect("second hit");
        assert!(
            Arc::ptr_eq(&first.response, &second.response),
            "a hit shares the stored response allocation"
        );
        assert_eq!(
            first.response.body.as_ptr(),
            second.response.body.as_ptr(),
            "a hit does not copy the body bytes"
        );
    }

    #[tokio::test]
    async fn exact_vector_hits() {
        let cache = embed_cache(0.85, 3600, 16);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        admit(
            &cache,
            &namespace,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "cached",
        )
        .await;
        let hit = maybe_hit(&cache, &namespace, "same direction", &[2.0, 0.0, 0.0])
            .await
            .expect("same direction hits");
        assert_eq!(hit.response.body.as_ref(), b"cached");
        assert!((hit.score - 1.0).abs() < 1e-5, "score {}", hit.score);
    }

    #[tokio::test]
    async fn near_duplicate_hits() {
        let cache = embed_cache(0.9, 3600, 16);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        admit(
            &cache,
            &namespace,
            "photosynthesis",
            &[1.0, 1.0, 0.0],
            "photosynthesis",
        )
        .await;
        // Cosine of roughly 0.97 clears the threshold.
        assert!(maybe_hit(&cache, &namespace, "near", &[1.0, 0.9, 0.05])
            .await
            .is_some());
    }

    #[tokio::test]
    async fn dissimilar_vector_misses_after_exact_rerank() {
        let cache = embed_cache(0.9, 3600, 16);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        admit(
            &cache,
            &namespace,
            "photosynthesis",
            &[1.0, 1.0, 0.0],
            "photosynthesis",
        )
        .await;
        assert!(maybe_hit(&cache, &namespace, "unrelated", &[0.0, 0.0, 1.0])
            .await
            .is_none());
        assert_eq!(cache.stats().below_threshold, 1);
    }

    #[tokio::test]
    async fn same_bucket_collision_below_threshold_misses() {
        let cfg = embed_config(0.9, 3600, 16);
        let (cache, store) = embed_cache_with_store(&cfg);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let now = SystemSemanticClock.now_unix_ms();
        // Index an orthogonal record under the query's own buckets so the
        // candidate set collides. Exact reranking must still miss.
        seed(
            &store,
            &namespace,
            "collision",
            &[0.0, 1.0, 0.0],
            &[1.0, 0.0, 0.0],
            "collision",
            now,
            now + 600_000,
        )
        .await;
        assert!(
            maybe_hit(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn best_exact_score_wins_across_multiple_tables() {
        let cfg = embed_config(0.5, 3600, 16);
        let (cache, store) = embed_cache_with_store(&cfg);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let now = SystemSemanticClock.now_unix_ms();
        // Two records that land in different bucket tables. Only exact
        // reranking can decide which one actually wins.
        seed(
            &store,
            &namespace,
            "far",
            &[1.0, 1.0, 0.0],
            &[1.0, 1.0, 0.0],
            "far",
            now,
            now + 600_000,
        )
        .await;
        seed(
            &store,
            &namespace,
            "near",
            &[1.0, 0.05, 0.0],
            &[1.0, 0.05, 0.0],
            "near",
            now,
            now + 600_000,
        )
        .await;
        let hit = maybe_hit(&cache, &namespace, "query", &[1.0, 0.0, 0.0])
            .await
            .expect("the best exact score wins");
        assert_eq!(hit.response.body.as_ref(), b"near");
    }

    #[tokio::test]
    async fn equal_score_tie_breaks_by_prompt_digest() {
        let cfg = embed_config(0.9, 3600, 16);
        let (cache, store) = embed_cache_with_store(&cfg);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let now = SystemSemanticClock.now_unix_ms();
        let left = contract_entry(
            &namespace,
            "prompt-one",
            &[1.0, 0.0, 0.0],
            "prompt-one",
            now,
            now + 600_000,
        );
        let right = contract_entry(
            &namespace,
            "prompt-two",
            &[1.0, 0.0, 0.0],
            "prompt-two",
            now,
            now + 600_000,
        );
        let expected: &[u8] = if left.prompt_digest < right.prompt_digest {
            b"prompt-one"
        } else {
            b"prompt-two"
        };
        for prompt in ["prompt-one", "prompt-two"] {
            seed(
                &store,
                &namespace,
                prompt,
                &[1.0, 0.0, 0.0],
                &[1.0, 0.0, 0.0],
                prompt,
                now,
                now + 600_000,
            )
            .await;
        }
        let hit = maybe_hit(&cache, &namespace, "query", &[1.0, 0.0, 0.0])
            .await
            .expect("one deterministic winner");
        assert_eq!(hit.response.body.as_ref(), expected);
    }

    #[tokio::test]
    async fn expired_candidate_misses() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = clocked_cache(&embed_config(0.85, 60, 16), clock.clone());
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        admit(
            &cache,
            &namespace,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "cached",
        )
        .await;
        assert!(
            maybe_hit(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .is_some()
        );
        clock.advance(120_000);
        assert!(
            maybe_hit(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .is_none()
        );
        assert_eq!(cache.stats().expired, 1);
    }

    #[tokio::test]
    async fn wrong_namespace_candidate_is_rejected() {
        let cache = embed_cache(0.85, 3600, 16);
        let mine = contract_namespace("tenant-secret-a", "origin-a.example");
        let theirs = contract_namespace("tenant-secret-b", "origin-a.example");
        admit(&cache, &mine, "refund policy", &[1.0, 0.0, 0.0], "secret-a").await;
        assert!(maybe_hit(&cache, &mine, "refund policy", &[1.0, 0.0, 0.0])
            .await
            .is_some());
        assert!(
            maybe_hit(&cache, &theirs, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn wrong_dimension_candidate_is_rejected() {
        let cfg = embed_config(0.85, 3600, 16);
        let (cache, store) = embed_cache_with_store(&cfg);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let now = SystemSemanticClock.now_unix_ms();
        seed(
            &store,
            &namespace,
            "wide",
            &[1.0, 0.0, 0.0, 0.0],
            &[1.0, 0.0, 0.0, 0.0],
            "wide",
            now,
            now + 600_000,
        )
        .await;
        assert!(
            maybe_hit(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .is_none()
        );
        assert_eq!(cache.stats().incompatible, 1);
    }

    #[tokio::test]
    async fn explicit_max_response_bytes_rejects_an_oversized_memory_response() {
        let cfg: EmbeddingCacheConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "max_response_bytes": 16,
            "embedding": { "provider": "openai", "model": "m" }
        }))
        .expect("fixture parses");
        let cache = EmbeddingCache::from_config(&cfg).expect("enabled config builds");
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let token = expect_miss(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0]).await;
        let oversized = "x".repeat(64);
        assert_eq!(
            cache.store(token, resp(&oversized)).await.unwrap_err(),
            SemanticStoreError::InvalidWrite
        );
        assert_eq!(cache.stats().write_errors, 1);
    }

    #[test]
    fn distributed_wire_rejects_a_response_above_7_mib() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let entry = StoredSemanticEntry {
            schema_version: SEMANTIC_CACHE_SCHEMA_VERSION,
            namespace,
            prompt_digest: [1u8; 32],
            embedding: vec![1.0, 0.0, 0.0],
            response: Arc::new(CachedHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: bytes::Bytes::from(vec![0u8; 7 * 1024 * 1024 + 1]),
            }),
            stored_at_unix_ms: 1_000,
            expires_at_unix_ms: 9_000,
        };
        assert_eq!(
            encode_entry(&entry).unwrap_err(),
            WireError::ResponseTooLarge
        );
    }

    #[tokio::test]
    async fn store_error_is_returned_without_losing_the_client_response() {
        let cfg = embed_config(0.85, 3600, 16);
        let failing: Arc<dyn SemanticCacheStore> = Arc::new(FailingStore);
        let cache = EmbeddingCache::with_store(&cfg, failing)
            .expect("backend matches")
            .expect("enabled config builds");
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        // Matched rather than `expect_err`, which would need `Debug` on the
        // success value. `SemanticLookupOutcome` deliberately has none: it
        // carries a cached response body, and deriving `Debug` to satisfy a
        // test assertion would put that body one `{:?}` away from a log line.
        let error = match cache
            .lookup(SemanticLookupRequest {
                namespace: namespace.clone(),
                prompt: "refund policy",
                embedding: &[1.0, 0.0, 0.0],
            })
            .await
        {
            Ok(_) => panic!("a backend failure surfaces"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            SemanticLookupError::Store(SemanticStoreError::Unavailable)
        );
        assert_eq!(cache.stats().lookup_errors, 1);
        // The caller keeps serving: nothing about the client response depends
        // on the cache having answered.
        assert_eq!(cache.health().await.state, SemanticHealthState::Unavailable);
    }

    #[tokio::test]
    async fn recent_decisions_never_retain_scope_namespace_prompt_or_backend_error() {
        let cache = embed_cache(0.85, 3600, 16);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        admit(
            &cache,
            &namespace,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "cached",
        )
        .await;
        let _ = maybe_hit(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0]).await;
        let _ = maybe_hit(&cache, &namespace, "unrelated", &[0.0, 0.0, 1.0]).await;

        let failing: Arc<dyn SemanticCacheStore> = Arc::new(FailingStore);
        let broken = EmbeddingCache::with_store(&embed_config(0.85, 3600, 16), failing)
            .expect("backend matches")
            .expect("enabled config builds");
        let _ = broken
            .lookup(SemanticLookupRequest {
                namespace: namespace.clone(),
                prompt: "refund policy",
                embedding: &[1.0, 0.0, 0.0],
            })
            .await;

        let mut decisions = cache.recent_decisions(10);
        decisions.extend(broken.recent_decisions(10));
        assert!(decisions.iter().any(|d| d.reason == "hit"));
        assert!(decisions.iter().any(|d| d.reason == "backend_error"));
        for decision in &decisions {
            assert!(
                matches!(
                    decision.reason,
                    "hit"
                        | "no_entry"
                        | "expired"
                        | "below_threshold"
                        | "incompatible"
                        | "backend_error"
                ),
                "unexpected reason {}",
                decision.reason
            );
        }
        let rendered = serde_json::to_string(&decisions).expect("decisions serialize");
        for sentinel in [
            "tenant-secret-a",
            "origin-a.example",
            "refund policy",
            "cached",
            "sbproxy:semcache",
            "unavailable",
        ] {
            assert!(
                !rendered.contains(sentinel),
                "recent decisions must not carry {sentinel}"
            );
        }
    }

    #[tokio::test]
    async fn slow_provider_time_does_not_reduce_ttl_before_store() {
        let clock = Arc::new(TestClock::new(1_000_000));
        let cache = clocked_cache(&embed_config(0.85, 60, 16), clock.clone());
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let token = expect_miss(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0]).await;
        // The provider takes longer than the whole time-to-live to answer.
        clock.advance(300_000);
        cache
            .store(token, resp("cached"))
            .await
            .expect("admission succeeds");
        // The record is fresh because expiry is anchored at write time.
        assert!(
            maybe_hit(&cache, &namespace, "refund policy", &[1.0, 0.0, 0.0])
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn threshold_is_enforced() {
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let strict = embed_cache(0.99, 3600, 16);
        admit(&strict, &namespace, "stored", &[1.0, 0.0, 0.0], "x").await;
        // Cosine of roughly 0.707 at 45 degrees is below 0.99.
        assert!(maybe_hit(&strict, &namespace, "query", &[1.0, 1.0, 0.0])
            .await
            .is_none());
        let loose = embed_cache(0.5, 3600, 16);
        admit(&loose, &namespace, "stored", &[1.0, 0.0, 0.0], "x").await;
        assert!(maybe_hit(&loose, &namespace, "query", &[1.0, 1.0, 0.0])
            .await
            .is_some());
    }

    #[tokio::test]
    async fn lru_evicts_when_full() {
        let cache = embed_cache(0.99, 3600, 2);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        admit(&cache, &namespace, "a", &[1.0, 0.0, 0.0], "a").await;
        admit(&cache, &namespace, "b", &[0.0, 1.0, 0.0], "b").await;
        admit(&cache, &namespace, "c", &[0.0, 0.0, 1.0], "c").await;
        // "a" was least recently used and evicted; its vector no longer matches.
        assert!(maybe_hit(&cache, &namespace, "a", &[1.0, 0.0, 0.0])
            .await
            .is_none());
        assert!(maybe_hit(&cache, &namespace, "c", &[0.0, 0.0, 1.0])
            .await
            .is_some());
    }

    #[test]
    fn config_parses_from_opaque_json() {
        let v = serde_json::json!({
            "enabled": true,
            "threshold": 0.8,
            "ttl_secs": 120,
            "max_entries": 256,
            "embedding": { "provider": "openai", "model": "text-embedding-3-small" }
        });
        let cfg: EmbeddingCacheConfig = serde_json::from_value(v).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.threshold, 0.8);
        let cache = EmbeddingCache::from_config(&cfg).unwrap();
        assert_eq!(cache.provider(), "openai");
        assert_eq!(cache.model(), "text-embedding-3-small");
        // Default source is provider so existing configs are unchanged.
        assert_eq!(cache.source(), EmbeddingSource::Provider);
        // Default backend is memory so existing configs keep process-local LRU.
        assert_eq!(cache.backend(), SemanticCacheBackend::Memory);
        assert_eq!(
            cache.embedding_identity(),
            "provider/openai/text-embedding-3-small"
        );
    }

    #[test]
    fn embedding_cache_debug_redacts_endpoints_paths_keys_and_entries() {
        let cfg: EmbeddingCacheConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "source": "openai",
            "openai": {
                "base_url": "https://private.example/v1",
                "model": "text-embedding-3-small",
                "api_key": "sk-secret-value",
                "auth_header": "X-Secret-Embedding-Route",
                "headers": [["X-Secret-Embedding-Route", "header-secret-value"]]
            }
        }))
        .expect("fixture parses");
        let cache = EmbeddingCache::from_config(&cfg).expect("enabled config builds");
        let rendered = format!("{cache:?}");
        for sentinel in [
            "https://private.example/v1",
            "sk-secret-value",
            "X-Secret-Embedding-Route",
            "header-secret-value",
        ] {
            assert!(
                !rendered.contains(sentinel),
                "cache debug must not carry {sentinel}"
            );
        }
    }

    #[test]
    fn source_defaults_to_provider() {
        let cfg: EmbeddingCacheConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "embedding": { "provider": "openai", "model": "text-embedding-3-small" }
        }))
        .unwrap();
        assert_eq!(cfg.source, EmbeddingSource::Provider);
    }

    #[test]
    fn sidecar_source_parses_and_builds() {
        let cfg: EmbeddingCacheConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "source": "sidecar",
            "sidecar": { "endpoint": "http://127.0.0.1:9440", "model": "all-MiniLM-L6-v2", "timeout_ms": 750 }
        }))
        .unwrap();
        assert_eq!(cfg.source, EmbeddingSource::Sidecar);
        let cache =
            EmbeddingCache::from_config(&cfg).expect("sidecar cache builds without a provider");
        assert_eq!(cache.source(), EmbeddingSource::Sidecar);
        let sc = cache.sidecar_config().expect("sidecar config present");
        assert_eq!(sc.endpoint, "http://127.0.0.1:9440");
        assert_eq!(sc.timeout_ms, 750);
    }

    #[test]
    fn sidecar_source_without_block_is_inert() {
        let cfg: EmbeddingCacheConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "source": "sidecar"
        }))
        .unwrap();
        // No sidecar block: nothing to vectorize with, so the cache stays inert.
        assert!(EmbeddingCache::from_config(&cfg).is_none());
    }

    #[test]
    fn eviction_is_constant_time_at_capacity() {
        // Sanity check: with a small capacity, repeated overflow inserts
        // must not blow up. LRU guarantees O(1) per operation.
        let cache = SemanticCache::new(8, 3600);
        for i in 0..10_000u32 {
            cache.store(&format!("k{i}"), serde_json::json!(i));
        }
        // Only the last 8 keys should remain.
        let mut present = 0;
        for i in (10_000u32 - 8)..10_000u32 {
            if cache.lookup(&format!("k{i}")).is_some() {
                present += 1;
            }
        }
        assert_eq!(present, 8);
    }

    // --- WOR-1520: standalone OpenAI-compatible embedding endpoint source ---

    #[test]
    fn openai_source_parses_and_builds_with_defaults() {
        let cfg: EmbeddingCacheConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "source": "openai",
            "openai": {
                "base_url": "https://openrouter.ai/api/v1",
                "model": "text-embedding-3-small",
                "api_key": "sk-test"
            }
        }))
        .unwrap();
        assert_eq!(cfg.source, EmbeddingSource::Openai);
        let cache =
            EmbeddingCache::from_config(&cfg).expect("openai cache builds without a provider");
        assert_eq!(cache.source(), EmbeddingSource::Openai);
        let oc = cache.openai_config().expect("openai config present");
        assert_eq!(oc.base_url, "https://openrouter.ai/api/v1");
        assert_eq!(oc.model, "text-embedding-3-small");
        // Auth defaults: Authorization: Bearer <key>.
        assert_eq!(oc.auth_header, "Authorization");
        assert_eq!(oc.auth_prefix, "Bearer ");
        assert_eq!(oc.timeout_ms, 2000);
    }

    #[test]
    fn openai_source_without_block_is_inert() {
        let cfg: EmbeddingCacheConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "source": "openai"
        }))
        .unwrap();
        // No openai block: nothing to vectorize with, so the cache stays inert.
        assert!(EmbeddingCache::from_config(&cfg).is_none());
    }

    #[test]
    fn openai_headers_default_to_bearer_authorization() {
        let cfg: OpenAiEmbeddingConfig = serde_json::from_value(serde_json::json!({
            "base_url": "https://api.openai.com/v1",
            "model": "text-embedding-3-small",
            "api_key": "sk-secret"
        }))
        .unwrap();
        let headers = openai_request_headers(&cfg).expect("headers build");
        assert_eq!(headers.get("authorization").unwrap(), "Bearer sk-secret");
    }

    #[test]
    fn openai_headers_support_custom_header_without_prefix() {
        let cfg: OpenAiEmbeddingConfig = serde_json::from_value(serde_json::json!({
            "base_url": "https://host/openai",
            "model": "m",
            "api_key": "sk-secret",
            "auth_header": "api-key",
            "auth_prefix": ""
        }))
        .unwrap();
        let headers = openai_request_headers(&cfg).expect("headers build");
        assert_eq!(headers.get("api-key").unwrap(), "sk-secret");
        assert!(headers.get("authorization").is_none());
    }

    #[test]
    fn openai_headers_include_extra_static_headers() {
        let cfg: OpenAiEmbeddingConfig = serde_json::from_value(serde_json::json!({
            "base_url": "https://openrouter.ai/api/v1",
            "model": "m",
            "api_key": "sk",
            "headers": [["HTTP-Referer", "https://sbproxy.dev"], ["X-Title", "sbproxy"]]
        }))
        .unwrap();
        let headers = openai_request_headers(&cfg).expect("headers build");
        assert_eq!(headers.get("http-referer").unwrap(), "https://sbproxy.dev");
        assert_eq!(headers.get("x-title").unwrap(), "sbproxy");
        assert_eq!(headers.get("authorization").unwrap(), "Bearer sk");
    }

    #[test]
    fn openai_headers_allow_header_only_auth_without_api_key() {
        let cfg: OpenAiEmbeddingConfig = serde_json::from_value(serde_json::json!({
            "base_url": "https://host/v1",
            "model": "m",
            "headers": [["X-API-Key", "raw-secret"]]
        }))
        .unwrap();
        let headers = openai_request_headers(&cfg).expect("headers build");
        assert_eq!(headers.get("x-api-key").unwrap(), "raw-secret");
        assert!(headers.get("authorization").is_none());
    }

    #[tokio::test]
    async fn compute_embedding_openai_returns_vector_and_sends_auth() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"model":"m","usage":{"prompt_tokens":1,"completion_tokens":0,"total_tokens":1}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
            req
        });
        let cfg: OpenAiEmbeddingConfig = serde_json::from_value(serde_json::json!({
            "base_url": format!("http://{addr}/v1"),
            "model": "m",
            "api_key": "sk-secret"
        }))
        .unwrap();
        let vec = compute_embedding_openai(&cfg, "hello")
            .await
            .expect("embedding");
        assert_eq!(vec.len(), 3);
        let req = server.await.unwrap();
        assert!(
            req.starts_with("POST /v1/embeddings "),
            "unexpected request line: {req}"
        );
        assert!(
            req.to_lowercase()
                .contains("authorization: bearer sk-secret"),
            "auth header not sent: {req}"
        );
    }

    #[tokio::test]
    async fn compute_embedding_openai_errors_when_endpoint_unreachable() {
        // Nothing listening here: the call must error so the dispatcher
        // fails open (treats the lookup as a miss).
        let cfg: OpenAiEmbeddingConfig = serde_json::from_value(serde_json::json!({
            "base_url": "http://127.0.0.1:1/v1",
            "model": "m",
            "api_key": "sk",
            "timeout_ms": 200
        }))
        .unwrap();
        assert!(compute_embedding_openai(&cfg, "hello").await.is_err());
    }

    #[tokio::test]
    async fn quota_aware_openai_embedding_releases_on_local_header_failure() {
        let cfg: OpenAiEmbeddingConfig = serde_json::from_value(serde_json::json!({
            "base_url": "http://127.0.0.1:1/v1",
            "model": "m",
            "headers": [["invalid header", "value"]]
        }))
        .expect("embedding fixture");
        let recording = Arc::new(RecordingQuotaStore::default());
        let store: Arc<dyn crate::quota_pool::QuotaPoolStore> = recording.clone();
        let admission = crate::quota_pool::QuotaPoolAdmission::new(
            Some(quota_config()),
            Ok(Some(store)),
            Ok("virtual-key-a".to_string()),
        );
        let attempt = admission
            .reserve_attempt("semantic-local-header")
            .await
            .expect("quota reservation");

        compute_embedding_openai_with_quota(&cfg, "hello", attempt)
            .await
            .expect_err("invalid local header must stop before send");

        for _ in 0..16 {
            if !recording.released.lock().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            recording.released.lock().await.as_slice(),
            ["semantic-local-header"]
        );
        assert!(recording.settled.lock().await.is_empty());
    }
}
