//! Semantic cache for AI responses.
//!
//! Caches responses keyed by a hash of the input messages so that
//! identical (or near-identical) prompts can be served from cache,
//! saving latency and provider cost.

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;

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
    /// Uses SHA-256 over the JSON-serialized messages to produce a
    /// hex-encoded digest suitable as a cache key.
    pub fn compute_hash(messages: &[crate::types::Message]) -> String {
        use sha2::{Digest, Sha256};
        let serialized = serde_json::to_string(messages).unwrap_or_default();
        let hash = Sha256::digest(serialized.as_bytes());
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

/// Operator config for the OSS embedding semantic cache, parsed from
/// the opaque `ai.semantic_cache` YAML block. Unknown keys (e.g. the
/// enterprise `streaming` sub-block) are ignored so the two
/// implementations can share one config value.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EmbeddingCacheConfig {
    /// Opt-in switch. The cache is inert unless this is `true`.
    #[serde(default)]
    pub enabled: bool,
    /// Minimum cosine similarity (`0.0..=1.0`) for a near-duplicate
    /// prompt to be served from cache. Defaults to 0.85.
    #[serde(default = "default_threshold")]
    pub threshold: f32,
    /// Entry time-to-live in seconds. Defaults to 3600.
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
    /// Maximum cached entries (LRU eviction). Defaults to 1024.
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    /// Embedding provider + model used to vectorize prompts.
    #[serde(default)]
    pub embedding: Option<EmbeddingProviderConfig>,
}

/// Which provider + model computes prompt embeddings.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EmbeddingProviderConfig {
    /// Provider name (must match an entry in the handler's `providers`).
    pub provider: String,
    /// Embedding model id, e.g. `text-embedding-3-small`.
    pub model: String,
}

fn default_threshold() -> f32 {
    0.85
}
fn default_ttl_secs() -> u64 {
    3600
}
fn default_max_entries() -> usize {
    1024
}

/// A cached HTTP response retained for replay on a semantic hit.
#[derive(Debug, Clone)]
pub struct CachedHttpResponse {
    /// Upstream status code.
    pub status: u16,
    /// Response headers (name, value), as captured from the upstream.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

#[derive(Debug)]
struct EmbeddingEntry {
    /// L2-normalized embedding vector.
    embedding: Vec<f32>,
    response: CachedHttpResponse,
    cached_at: u64,
    /// Per-caller scope (hashed tenant + credential). A lookup only
    /// matches an entry with the same scope so one caller's cached
    /// response is never replayed to another (WOR-1142).
    scope: String,
}

/// Embedding-similarity response cache.
///
/// Layered over (and consulted after) the exact-match path: the
/// dispatcher computes the prompt's embedding once on a miss, scans the
/// stored entries for the closest vector, and replays the cached
/// response when cosine similarity meets the configured threshold.
/// Vectors are L2-normalized at insert time, so the similarity scan is
/// a dot product. Eviction is LRU; entries past their TTL are dropped
/// lazily on lookup.
#[derive(Debug)]
pub struct EmbeddingCache {
    threshold: f32,
    ttl_secs: u64,
    provider: String,
    model: String,
    entries: Mutex<LruCache<String, EmbeddingEntry>>,
}

/// Outcome of a successful semantic lookup: the cached response plus
/// the cosine similarity score that matched it.
#[derive(Debug, Clone)]
pub struct EmbeddingHit {
    /// The cached response to replay.
    pub response: CachedHttpResponse,
    /// Cosine similarity of the query against the matched entry.
    pub score: f32,
}

impl EmbeddingCache {
    /// Build a cache from a validated, enabled config. Returns `None`
    /// when the config is disabled or missing the embedding provider
    /// block (nothing to vectorize with).
    pub fn from_config(cfg: &EmbeddingCacheConfig) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        let embedding = cfg.embedding.as_ref()?;
        let cap = NonZeroUsize::new(cfg.max_entries.max(1)).expect("max_entries clamped to >= 1");
        Some(Self {
            threshold: cfg.threshold,
            ttl_secs: cfg.ttl_secs,
            provider: embedding.provider.clone(),
            model: embedding.model.clone(),
            entries: Mutex::new(LruCache::new(cap)),
        })
    }

    /// Embedding provider name to vectorize prompts with.
    pub fn provider(&self) -> &str {
        &self.provider
    }
    /// Embedding model id.
    pub fn model(&self) -> &str {
        &self.model
    }
    /// Configured similarity threshold.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Find the closest stored entry to `query` whose cosine
    /// similarity meets the threshold and is not expired. Returns the
    /// cached response and the matching score. Expired entries
    /// encountered during the scan are removed.
    pub fn lookup(&self, query: &[f32], scope: &str) -> Option<EmbeddingHit> {
        let q = normalize(query);
        if q.is_empty() {
            return None;
        }
        let now = Self::now_secs();
        let mut cache = self.entries.lock();
        // Collect expired keys to evict after the scan (can't mutate
        // while iterating the LRU).
        let mut expired: Vec<String> = Vec::new();
        let mut best: Option<(String, f32)> = None;
        for (key, entry) in cache.iter() {
            if now.saturating_sub(entry.cached_at) > self.ttl_secs {
                expired.push(key.clone());
                continue;
            }
            // WOR-1142: never match across callers. An entry stored by
            // one tenant/credential is invisible to a different one.
            if entry.scope != scope {
                continue;
            }
            let score = dot(&q, &entry.embedding);
            if score >= self.threshold && best.as_ref().map(|(_, s)| score > *s).unwrap_or(true) {
                best = Some((key.clone(), score));
            }
        }
        for k in expired {
            cache.pop(&k);
        }
        let (key, score) = best?;
        // `get` marks the entry most-recently-used.
        let entry = cache.get(&key)?;
        Some(EmbeddingHit {
            response: entry.response.clone(),
            score,
        })
    }

    /// Store a response under `key` with its prompt `embedding`. The
    /// vector is L2-normalized before storage. Evicts the LRU entry
    /// when at capacity.
    pub fn store(
        &self,
        key: String,
        embedding: &[f32],
        response: CachedHttpResponse,
        scope: String,
    ) {
        let normalized = normalize(embedding);
        if normalized.is_empty() {
            return;
        }
        self.entries.lock().put(
            key,
            EmbeddingEntry {
                embedding: normalized,
                response,
                cached_at: Self::now_secs(),
                scope,
            },
        );
    }

    /// SHA-256 hex digest of the prompt, namespaced by the caller scope,
    /// used as the LRU key so an exact repeat from the SAME caller
    /// overwrites rather than accumulating duplicates, while the same
    /// prompt from different callers does not collide (WOR-1142).
    pub fn prompt_key(scope: &str, prompt: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(scope.as_bytes());
        h.update([0u8]);
        h.update(prompt.as_bytes());
        hex::encode(h.finalize())
    }

    /// Derive the per-caller cache scope from the resolved tenant and the
    /// raw authorization header. Hashed so the stored key does not retain
    /// the credential. Two requests share cache entries only when this
    /// value matches (WOR-1142).
    pub fn scope_key(tenant_id: &str, authorization: Option<&str>) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(tenant_id.as_bytes());
        h.update([0u8]);
        h.update(authorization.unwrap_or("").as_bytes());
        hex::encode(h.finalize())
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
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
    let resp = client
        .forward_request(provider, "/v1/embeddings", &body)
        .await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!(
            "embedding provider {} returned status {}",
            provider.name,
            status
        );
    }
    let parsed: crate::types::EmbeddingResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("embedding response parse failed: {e}"))?;
    let first = parsed
        .data
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("embedding response contained no vectors"))?;
    Ok(first.embedding.into_iter().map(|x| x as f32).collect())
}

/// L2-normalize a vector. Returns an empty vec for a zero or empty
/// vector (which then never matches).
fn normalize(v: &[f32]) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm == 0.0 || !norm.is_finite() {
        return Vec::new();
    }
    v.iter().map(|x| x / norm).collect()
}

/// Dot product of two equal-length vectors (cosine similarity when
/// both are L2-normalized). Mismatched lengths score 0.
fn dot(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Message;

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

    // --- WOR-796: embedding cache ---

    fn embed_cache(threshold: f32, ttl: u64, max: usize) -> EmbeddingCache {
        EmbeddingCache::from_config(&EmbeddingCacheConfig {
            enabled: true,
            threshold,
            ttl_secs: ttl,
            max_entries: max,
            embedding: Some(EmbeddingProviderConfig {
                provider: "openai".to_string(),
                model: "text-embedding-3-small".to_string(),
            }),
        })
        .expect("enabled config builds")
    }

    fn resp(body: &str) -> CachedHttpResponse {
        CachedHttpResponse {
            status: 200,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn disabled_config_builds_no_cache() {
        let cfg = EmbeddingCacheConfig {
            enabled: false,
            threshold: 0.85,
            ttl_secs: 60,
            max_entries: 8,
            embedding: Some(EmbeddingProviderConfig {
                provider: "openai".to_string(),
                model: "m".to_string(),
            }),
        };
        assert!(EmbeddingCache::from_config(&cfg).is_none());
    }

    #[test]
    fn enabled_without_embedding_block_builds_no_cache() {
        let cfg = EmbeddingCacheConfig {
            enabled: true,
            threshold: 0.85,
            ttl_secs: 60,
            max_entries: 8,
            embedding: None,
        };
        assert!(EmbeddingCache::from_config(&cfg).is_none());
    }

    #[test]
    fn exact_vector_is_a_hit() {
        let cache = embed_cache(0.85, 3600, 16);
        cache.store(
            "k1".to_string(),
            &[1.0, 0.0, 0.0],
            resp("cached"),
            "s".to_string(),
        );
        let hit = cache
            .lookup(&[2.0, 0.0, 0.0], "s")
            .expect("same direction hits");
        assert_eq!(hit.response.body, b"cached");
        assert!((hit.score - 1.0).abs() < 1e-5, "score {}", hit.score);
    }

    #[test]
    fn near_duplicate_hits_dissimilar_misses() {
        let cache = embed_cache(0.9, 3600, 16);
        // Stored vector.
        cache.store(
            "k1".to_string(),
            &[1.0, 1.0, 0.0],
            resp("photosynthesis"),
            "s".to_string(),
        );
        // Near-duplicate (cosine ~0.97) -> hit.
        assert!(cache.lookup(&[1.0, 0.9, 0.05], "s").is_some());
        // Orthogonal (cosine 0) -> miss.
        assert!(cache.lookup(&[0.0, 0.0, 1.0], "s").is_none());
    }

    #[test]
    fn cross_scope_entries_are_isolated() {
        // WOR-1142: an entry stored by caller "a" must never be returned
        // to caller "b", even for an identical vector.
        let cache = embed_cache(0.85, 3600, 16);
        cache.store(
            "k".to_string(),
            &[1.0, 0.0, 0.0],
            resp("secret-a"),
            "a".to_string(),
        );
        // Same scope -> hit.
        assert!(cache.lookup(&[1.0, 0.0, 0.0], "a").is_some());
        // Different scope, identical vector -> miss.
        assert!(cache.lookup(&[1.0, 0.0, 0.0], "b").is_none());
    }

    #[test]
    fn threshold_is_enforced() {
        let strict = embed_cache(0.99, 3600, 16);
        strict.store("k".to_string(), &[1.0, 0.0], resp("x"), "s".to_string());
        // cosine(45 deg) ~= 0.707 < 0.99 -> miss.
        assert!(strict.lookup(&[1.0, 1.0], "s").is_none());
        let loose = embed_cache(0.5, 3600, 16);
        loose.store("k".to_string(), &[1.0, 0.0], resp("x"), "s".to_string());
        assert!(loose.lookup(&[1.0, 1.0], "s").is_some());
    }

    #[test]
    fn expired_entry_is_not_returned() {
        let cache = embed_cache(0.5, 0, 16); // ttl 0 -> immediately stale
        cache.store("k".to_string(), &[1.0, 0.0], resp("x"), "s".to_string());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(cache.lookup(&[1.0, 0.0], "s").is_none());
    }

    #[test]
    fn lru_evicts_when_full() {
        let cache = embed_cache(0.99, 3600, 2);
        cache.store(
            "a".to_string(),
            &[1.0, 0.0, 0.0],
            resp("a"),
            "s".to_string(),
        );
        cache.store(
            "b".to_string(),
            &[0.0, 1.0, 0.0],
            resp("b"),
            "s".to_string(),
        );
        cache.store(
            "c".to_string(),
            &[0.0, 0.0, 1.0],
            resp("c"),
            "s".to_string(),
        );
        // "a" was LRU and evicted; its vector no longer matches.
        assert!(cache.lookup(&[1.0, 0.0, 0.0], "s").is_none());
        assert!(cache.lookup(&[0.0, 0.0, 1.0], "s").is_some());
    }

    #[test]
    fn config_parses_from_opaque_json() {
        let v = serde_json::json!({
            "enabled": true,
            "threshold": 0.8,
            "ttl_secs": 120,
            "max_entries": 256,
            "embedding": { "provider": "openai", "model": "text-embedding-3-small" },
            "streaming": { "enabled": true }  // enterprise key, ignored
        });
        let cfg: EmbeddingCacheConfig = serde_json::from_value(v).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.threshold, 0.8);
        let cache = EmbeddingCache::from_config(&cfg).unwrap();
        assert_eq!(cache.provider(), "openai");
        assert_eq!(cache.model(), "text-embedding-3-small");
    }

    #[test]
    fn prompt_key_is_deterministic_sha256() {
        let a = EmbeddingCache::prompt_key("s", "hello world");
        let b = EmbeddingCache::prompt_key("s", "hello world");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert_ne!(a, EmbeddingCache::prompt_key("s", "different"));
        // WOR-1142: same prompt under a different scope is a distinct key.
        assert_ne!(a, EmbeddingCache::prompt_key("other", "hello world"));
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
}
