//! Semantic cache for AI responses.
//!
//! Caches responses keyed by a hash of the input messages so that
//! identical (or near-identical) prompts can be served from cache,
//! saving latency and provider cost.

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;

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
    /// Where prompt embeddings come from. Defaults to `provider` so
    /// existing configs are unchanged.
    #[serde(default)]
    pub source: EmbeddingSource,
    /// Embedding provider + model used to vectorize prompts (for
    /// `source: provider`).
    #[serde(default)]
    pub embedding: Option<EmbeddingProviderConfig>,
    /// Local classifier-sidecar embedding endpoint (for `source: sidecar`).
    #[serde(default)]
    pub sidecar: Option<SidecarEmbeddingConfig>,
    /// In-process embedder (for `source: inprocess`).
    #[serde(default)]
    pub inprocess: Option<InprocessEmbeddingConfig>,
    /// Standalone OpenAI-compatible endpoint (for `source: openai`).
    #[serde(default)]
    pub openai: Option<OpenAiEmbeddingConfig>,
}

/// Where the semantic cache gets prompt embeddings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmbeddingSource {
    /// Call an AI embedding provider's `/v1/embeddings` API (default,
    /// back-compat). Costs money and egresses the prompt.
    #[default]
    Provider,
    /// Call the local classifier sidecar's `Embed` RPC. Free, no egress.
    Sidecar,
    /// Run an in-process tract embedder. Single-binary, but loads a model
    /// into the proxy address space (opt-in).
    Inprocess,
    /// Call a standalone OpenAI-compatible `/v1/embeddings` endpoint that is
    /// not one of the origin's chat providers (another sbproxy, OpenRouter,
    /// ...). Decoupled from `providers`; carries its own URL + auth.
    Openai,
}

/// Which provider + model computes prompt embeddings.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EmbeddingProviderConfig {
    /// Provider name (must match an entry in the handler's `providers`).
    pub provider: String,
    /// Embedding model id, e.g. `text-embedding-3-small`.
    pub model: String,
}

/// Sidecar embedding endpoint config (for `source: sidecar`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SidecarEmbeddingConfig {
    /// gRPC endpoint, e.g. `http://127.0.0.1:9440`.
    pub endpoint: String,
    /// Embedding model id (empty selects the sidecar default).
    #[serde(default)]
    pub model: String,
    /// Per-call timeout in milliseconds. Defaults to 500.
    #[serde(default = "default_sidecar_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_sidecar_timeout_ms() -> u64 {
    500
}

/// In-process embedder config (for `source: inprocess`).
///
/// Provide explicit `model_path` + `tokenizer_path`. Known-model
/// auto-download for the in-process embedder is a follow-up; until then
/// the operator points at on-disk ONNX + tokenizer files.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct InprocessEmbeddingConfig {
    /// Logical model id (informational; e.g. `all-MiniLM-L6-v2`).
    #[serde(default)]
    pub model: String,
    /// Path to the ONNX model file.
    #[serde(default)]
    pub model_path: Option<String>,
    /// Path to the tokenizer.json file.
    #[serde(default)]
    pub tokenizer_path: Option<String>,
    /// Max model size in bytes (guard). None uses the engine default.
    #[serde(default)]
    pub max_model_bytes: Option<u64>,
}

/// Standalone OpenAI-compatible embedding endpoint config (for `source: openai`).
///
/// Unlike `source: provider`, this is not tied to the origin's chat
/// `providers`: point `base_url` at any OpenAI-compatible `/v1/embeddings`
/// route (another sbproxy, OpenRouter, ...). Auth defaults to
/// `Authorization: Bearer <api_key>`; set `auth_header` / `auth_prefix` for
/// `api-key` / `x-api-key` style endpoints, or omit `api_key` and carry the
/// auth in `headers`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OpenAiEmbeddingConfig {
    /// OpenAI-compatible base URL, e.g. `https://api.openai.com/v1`.
    /// `/v1/embeddings` is appended (an overlapping trailing `/v1` is
    /// collapsed, matching the chat-provider path join).
    pub base_url: String,
    /// Embedding model id, e.g. `text-embedding-3-small`.
    #[serde(default)]
    pub model: String,
    /// Per-call timeout in milliseconds. Defaults to 2000.
    #[serde(default = "default_openai_timeout_ms")]
    pub timeout_ms: u64,
    /// API key. Interpolated (`${VAR}` / vault) by the config layer. When
    /// set, sent as `{auth_header}: {auth_prefix}{api_key}`.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Auth header name. Defaults to `Authorization`.
    #[serde(default = "default_auth_header")]
    pub auth_header: String,
    /// Prefix prepended to the key in the auth header. Defaults to `Bearer `;
    /// set to `""` for raw-key headers like `api-key` / `x-api-key`.
    #[serde(default = "default_auth_prefix")]
    pub auth_prefix: String,
    /// Extra static headers, sent verbatim and applied after the auth header
    /// (e.g. OpenRouter `HTTP-Referer` / `X-Title`, or a custom auth header
    /// when `api_key` is omitted). Interpolated by the config layer.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

fn default_openai_timeout_ms() -> u64 {
    2000
}
fn default_auth_header() -> String {
    "Authorization".to_string()
}
fn default_auth_prefix() -> String {
    "Bearer ".to_string()
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
    /// Shared so a lookup hit clones an `Arc` pointer rather than the
    /// whole response (body bytes + header strings) under the entries
    /// mutex (WOR-1703).
    response: Arc<CachedHttpResponse>,
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
    entries: Mutex<LruCache<String, EmbeddingEntry>>,
}

/// Outcome of a successful semantic lookup: the cached response plus
/// the cosine similarity score that matched it.
#[derive(Debug, Clone)]
pub struct EmbeddingHit {
    /// The cached response to replay. Shared with the cache entry, so
    /// obtaining it off a hit is a refcount bump, not a body copy
    /// (WOR-1703).
    pub response: Arc<CachedHttpResponse>,
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
        // Each source needs its own config block to be usable. A missing
        // block means there is nothing to vectorize with, so the cache
        // stays inert (None) rather than half-built.
        let (provider, model, sidecar, inprocess, openai) = match cfg.source {
            EmbeddingSource::Provider => {
                let e = cfg.embedding.as_ref()?;
                (e.provider.clone(), e.model.clone(), None, None, None)
            }
            EmbeddingSource::Sidecar => {
                let s = cfg.sidecar.as_ref()?;
                (String::new(), s.model.clone(), Some(s.clone()), None, None)
            }
            EmbeddingSource::Inprocess => {
                // The embedder is built and held by sbproxy-core (which can
                // depend on the tract engine without a dependency cycle). The
                // cache carries the config so core can load it. Require the
                // block so a typo'd config does not silently fall back.
                let p = cfg.inprocess.as_ref()?;
                (String::new(), p.model.clone(), None, Some(p.clone()), None)
            }
            EmbeddingSource::Openai => {
                // Standalone OpenAI-compatible endpoint, decoupled from the
                // origin's chat providers. Require the block so a typo'd
                // config stays inert rather than silently disabled.
                let o = cfg.openai.as_ref()?;
                (String::new(), o.model.clone(), None, None, Some(o.clone()))
            }
        };
        let cap = NonZeroUsize::new(cfg.max_entries.max(1)).expect("max_entries clamped to >= 1");
        Some(Self {
            threshold: cfg.threshold,
            ttl_secs: cfg.ttl_secs,
            source: cfg.source,
            provider,
            model,
            sidecar,
            inprocess,
            openai,
            entries: Mutex::new(LruCache::new(cap)),
        })
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
                response: Arc::new(response),
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
    let url = crate::client::build_url(cfg.base_url.trim_end_matches('/'), "/v1/embeddings");
    let headers = openai_request_headers(cfg)?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .build()
        .map_err(|e| anyhow::anyhow!("openai embed client build: {e}"))?;
    let body = serde_json::json!({ "model": cfg.model, "input": text });
    let resp = http
        .post(&url)
        .headers(headers)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("openai embed request: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("openai embedding endpoint returned status {status}");
    }
    let parsed: crate::types::EmbeddingResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("openai embedding response parse failed: {e}"))?;
    let first = parsed
        .data
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("openai embedding response contained no vectors"))?;
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
            source: EmbeddingSource::Provider,
            embedding: Some(EmbeddingProviderConfig {
                provider: "openai".to_string(),
                model: "text-embedding-3-small".to_string(),
            }),
            sidecar: None,
            inprocess: None,
            openai: None,
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
            source: EmbeddingSource::Provider,
            embedding: Some(EmbeddingProviderConfig {
                provider: "openai".to_string(),
                model: "m".to_string(),
            }),
            sidecar: None,
            inprocess: None,
            openai: None,
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
            source: EmbeddingSource::Provider,
            embedding: None,
            sidecar: None,
            inprocess: None,
            openai: None,
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
        // Default source is provider so existing configs are unchanged.
        assert_eq!(cache.source(), EmbeddingSource::Provider);
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
}
