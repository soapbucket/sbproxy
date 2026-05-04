//! Two-tier caching: exact match + semantic similarity fallback.
//!
//! - **L1** is a SHA-256 hash map keyed on a whitespace-normalised
//!   prompt. O(1) hits.
//! - **L2** is a cosine-similarity scan over tokenised prompts. We
//!   build an L2-normalised term-frequency vector for each stored
//!   prompt and, on an L1 miss, return the entry whose vector
//!   exceeds the configured `similarity_threshold`. No external
//!   classifier required; full embedding-based caching (real
//!   embeddings + LSH ring + cluster-wide replication) is provided
//!   by an out-of-tree semantic-cache backend.
//!
//! Eviction: once `max_entries` is reached, the oldest inserted
//! entry is removed from both L1 and the L2 vector list (FIFO).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

// --- Types ---

/// A cached AI response with metadata.
#[derive(Debug, Clone)]
pub struct AiCachedResponse {
    /// Cached response body content.
    pub content: String,
    /// AI provider identifier (e.g. "openai", "anthropic").
    pub provider: String,
    /// Model identifier used to generate the response.
    pub model: String,
    /// Token count consumed by the original request.
    pub tokens: u64,
    /// Unix timestamp (seconds) when the entry was created.
    pub created_at: u64,
}

// --- Stats ---

/// Cache statistics collected across all get/put operations.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of exact-match (L1) hits served.
    pub l1_hits: u64,
    /// Number of L1 lookups that did not find a match.
    pub l1_misses: u64,
    /// Number of semantic (L2) hits served.
    pub l2_hits: u64,
    /// Number of L2 lookups that did not find a match.
    pub l2_misses: u64,
    /// Current number of entries stored in L1.
    pub entries: usize,
}

// --- Internal store ---

struct L1Store {
    map: HashMap<String, AiCachedResponse>,
    /// Per-key L2 term-frequency vector. Empty when semantic L2 is
    /// disabled. Stored alongside the response so similarity scans
    /// do not re-tokenise the prompt on every lookup.
    tf_vectors: HashMap<String, Vec<(u64, f32)>>,
    /// Insertion order queue for FIFO eviction.
    order: VecDeque<String>,
    max_entries: usize,
}

impl L1Store {
    fn new(max_entries: usize) -> Self {
        Self {
            map: HashMap::new(),
            tf_vectors: HashMap::new(),
            order: VecDeque::new(),
            max_entries,
        }
    }

    fn get(&self, key: &str) -> Option<&AiCachedResponse> {
        self.map.get(key)
    }

    fn put(&mut self, key: String, value: AiCachedResponse, tf: Option<Vec<(u64, f32)>>) {
        if let Some(slot) = self.map.get_mut(&key) {
            // Update in place without changing insertion order.
            *slot = value;
            if let Some(v) = tf {
                self.tf_vectors.insert(key.clone(), v);
            }
            return;
        }
        // Evict oldest entry if at capacity.
        if self.map.len() >= self.max_entries {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
                self.tf_vectors.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        if let Some(v) = tf {
            self.tf_vectors.insert(key.clone(), v);
        }
        self.map.insert(key, value);
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    /// Iterate every (key, tf_vector) pair where the vector is
    /// non-empty. Used by the L2 similarity scan.
    fn iter_tf(&self) -> impl Iterator<Item = (&String, &Vec<(u64, f32)>)> {
        self.tf_vectors.iter().filter(|(_, v)| !v.is_empty())
    }
}

// --- TwoTierCache ---

/// Default cosine-similarity threshold for L2 hits. 0.85 catches
/// paraphrases without false-matching unrelated prompts; tune up
/// for legal / medical domains where false hits are expensive.
pub const DEFAULT_SIMILARITY_THRESHOLD: f32 = 0.85;

/// Two-tier cache: exact hash match (L1) + cosine-similarity (L2).
///
/// Thread-safe; share via `Arc`.
pub struct TwoTierCache {
    /// L1: exact match by SHA-256 hash of normalised prompt.
    exact: Mutex<L1Store>,
    /// Whether L2 semantic matching is enabled.
    semantic_enabled: bool,
    /// Cosine threshold above which an L2 candidate counts as a hit.
    similarity_threshold: f32,
    /// Cap on the number of entries scanned per L2 lookup. Keeps
    /// the worst-case lookup bounded as the cache fills.
    max_l2_candidates: usize,
    /// Stats counters.
    stats: Mutex<CacheStats>,
}

impl TwoTierCache {
    /// Create a two-tier cache with default L2 tuning.
    ///
    /// - `max_entries`: maximum L1 entries before FIFO eviction.
    /// - `semantic_enabled`: when `true`, L1 misses run a cosine
    ///   similarity scan against stored entries and return the
    ///   highest-scoring entry above [`DEFAULT_SIMILARITY_THRESHOLD`].
    pub fn new(max_entries: usize, semantic_enabled: bool) -> Self {
        Self::with_threshold(max_entries, semantic_enabled, DEFAULT_SIMILARITY_THRESHOLD)
    }

    /// Variant of [`Self::new`] with an explicit similarity threshold
    /// and candidate cap. Use when default 0.85 / 256 do not match
    /// the workload.
    pub fn with_threshold(
        max_entries: usize,
        semantic_enabled: bool,
        similarity_threshold: f32,
    ) -> Self {
        Self {
            exact: Mutex::new(L1Store::new(max_entries)),
            semantic_enabled,
            similarity_threshold,
            max_l2_candidates: 256,
            stats: Mutex::new(CacheStats::default()),
        }
    }

    /// Look up a response by prompt. L1 first; on miss, L2 if enabled.
    pub fn get(&self, prompt: &str) -> Option<AiCachedResponse> {
        let key = Self::exact_key(prompt);

        // --- L1 lookup ---
        let l1 = self.exact.lock().expect("two-tier cache l1 mutex poisoned");
        if let Some(entry) = l1.get(&key) {
            let result = entry.clone();
            drop(l1);
            let mut s = self.stats.lock().expect("stats mutex poisoned");
            s.l1_hits += 1;
            return Some(result);
        }

        // --- L2 (semantic): scan stored TF vectors for best cosine ---
        if self.semantic_enabled {
            let q_vec = build_tf_vector(prompt);
            if !q_vec.is_empty() {
                let mut best: Option<(f32, AiCachedResponse)> = None;
                for (entry_key, tf) in l1.iter_tf().take(self.max_l2_candidates) {
                    let score = cosine_similarity(&q_vec, tf);
                    if score >= self.similarity_threshold {
                        let candidate = match l1.get(entry_key) {
                            Some(r) => r.clone(),
                            None => continue,
                        };
                        match &best {
                            Some((cur, _)) if *cur >= score => {}
                            _ => best = Some((score, candidate)),
                        }
                    }
                }
                drop(l1);
                let mut s = self.stats.lock().expect("stats mutex poisoned");
                s.l1_misses += 1;
                if let Some((_, hit)) = best {
                    s.l2_hits += 1;
                    return Some(hit);
                }
                s.l2_misses += 1;
                return None;
            }
        }

        drop(l1);
        let mut s = self.stats.lock().expect("stats mutex poisoned");
        s.l1_misses += 1;
        if self.semantic_enabled {
            s.l2_misses += 1;
        }
        None
    }

    /// Store a response for the given prompt.
    ///
    /// When semantic matching is enabled, also pre-computes the TF
    /// vector so subsequent L2 lookups do not need to re-tokenise
    /// stored entries.
    pub fn put(&self, prompt: &str, response: AiCachedResponse) {
        let key = Self::exact_key(prompt);
        let tf = if self.semantic_enabled {
            Some(build_tf_vector(prompt))
        } else {
            None
        };
        let mut l1 = self.exact.lock().expect("two-tier cache l1 mutex poisoned");
        l1.put(key, response, tf);
        let entry_count = l1.len();
        drop(l1);

        let mut s = self.stats.lock().expect("stats mutex poisoned");
        s.entries = entry_count;
    }

    /// Generate an exact-match cache key: lowercase-normalised SHA-256 hex of
    /// the prompt.
    ///
    /// Normalisation collapses leading/trailing whitespace and consecutive
    /// internal whitespace to a single space so that minor formatting
    /// differences in the same prompt resolve to the same key.
    pub fn exact_key(prompt: &str) -> String {
        let normalised = prompt.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut hasher = Sha256::new();
        hasher.update(normalised.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Return a snapshot of current cache statistics.
    pub fn stats(&self) -> CacheStats {
        let mut s = self.stats.lock().expect("stats mutex poisoned").clone();
        // Refresh live entry count.
        let l1 = self.exact.lock().expect("two-tier cache l1 mutex poisoned");
        s.entries = l1.len();
        s
    }
}

// --- Helpers ---

/// Current unix timestamp in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build an L2-normalised term-frequency vector from a prompt.
///
/// Tokens are runs of ASCII alphanumerics, lowercased; the trivial
/// English stop-word set is dropped.
fn build_tf_vector(text: &str) -> Vec<(u64, f32)> {
    let mut counts: HashMap<u64, u32> = HashMap::new();
    let mut total = 0u32;
    let mut current = String::new();
    let process = |buf: &mut String, counts: &mut HashMap<u64, u32>, total: &mut u32| {
        if buf.is_empty() {
            return;
        }
        let lower = buf.to_ascii_lowercase();
        buf.clear();
        if is_stop_word(&lower) {
            return;
        }
        let mut hasher = Sha256::new();
        hasher.update(lower.as_bytes());
        let digest = hasher.finalize();
        let mut h_bytes = [0u8; 8];
        h_bytes.copy_from_slice(&digest[..8]);
        let h = u64::from_le_bytes(h_bytes);
        *counts.entry(h).or_insert(0) += 1;
        *total += 1;
    };
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else {
            process(&mut current, &mut counts, &mut total);
        }
    }
    process(&mut current, &mut counts, &mut total);
    if total == 0 {
        return Vec::new();
    }
    let total_f = total as f32;
    let mut vec: Vec<(u64, f32)> = counts
        .into_iter()
        .map(|(k, c)| (k, c as f32 / total_f))
        .collect();
    let norm: f32 = vec.iter().map(|(_, w)| w * w).sum::<f32>().sqrt();
    if norm > 0.0 {
        for (_, w) in vec.iter_mut() {
            *w /= norm;
        }
    }
    vec.sort_unstable_by_key(|(k, _)| *k);
    vec
}

fn is_stop_word(token: &str) -> bool {
    matches!(
        token,
        "the" | "a" | "an" | "is" | "are" | "was" | "were" | "to" | "of" | "and" | "or"
    )
}

fn cosine_similarity(a: &[(u64, f32)], b: &[(u64, f32)]) -> f32 {
    let mut i = 0;
    let mut j = 0;
    let mut dot = 0.0f32;
    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                dot += a[i].1 * b[j].1;
                i += 1;
                j += 1;
            }
        }
    }
    dot
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_response(content: &str) -> AiCachedResponse {
        AiCachedResponse {
            content: content.to_string(),
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            tokens: 42,
            created_at: now_secs(),
        }
    }

    // --- Exact match ---

    #[test]
    fn exact_match_hit() {
        let cache = TwoTierCache::new(100, false);
        cache.put("hello world", sample_response("hi there"));
        let result = cache.get("hello world");
        assert!(result.is_some());
        assert_eq!(result.unwrap().content, "hi there");
    }

    #[test]
    fn exact_match_miss() {
        let cache = TwoTierCache::new(100, false);
        cache.put("hello world", sample_response("hi there"));
        let result = cache.get("goodbye world");
        assert!(result.is_none());
    }

    #[test]
    fn put_and_get_roundtrip() {
        let cache = TwoTierCache::new(100, false);
        let resp = AiCachedResponse {
            content: "The answer is 42.".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-3-5-sonnet".to_string(),
            tokens: 7,
            created_at: 1_700_000_000,
        };
        cache.put("What is the meaning of life?", resp.clone());
        let got = cache.get("What is the meaning of life?").unwrap();
        assert_eq!(got.content, resp.content);
        assert_eq!(got.provider, resp.provider);
        assert_eq!(got.model, resp.model);
        assert_eq!(got.tokens, resp.tokens);
        assert_eq!(got.created_at, resp.created_at);
    }

    // --- Cache key ---

    #[test]
    fn deterministic_cache_key() {
        let k1 = TwoTierCache::exact_key("hello world");
        let k2 = TwoTierCache::exact_key("hello world");
        assert_eq!(k1, k2);
    }

    #[test]
    fn same_prompt_produces_same_key() {
        let prompt = "What is the capital of France?";
        assert_eq!(
            TwoTierCache::exact_key(prompt),
            TwoTierCache::exact_key(prompt),
        );
    }

    #[test]
    fn different_prompts_produce_different_keys() {
        let k1 = TwoTierCache::exact_key("prompt one");
        let k2 = TwoTierCache::exact_key("prompt two");
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_normalises_whitespace() {
        // Extra internal spaces and trailing whitespace collapse to the same key.
        let k1 = TwoTierCache::exact_key("hello   world");
        let k2 = TwoTierCache::exact_key("hello world");
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_is_hex_string() {
        let key = TwoTierCache::exact_key("test");
        // SHA-256 hex is always 64 lowercase hex characters.
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --- Stats ---

    #[test]
    fn stats_tracking_l1_hit() {
        let cache = TwoTierCache::new(100, false);
        cache.put("prompt", sample_response("answer"));
        cache.get("prompt");
        let s = cache.stats();
        assert_eq!(s.l1_hits, 1);
        assert_eq!(s.l1_misses, 0);
    }

    #[test]
    fn stats_tracking_l1_miss() {
        let cache = TwoTierCache::new(100, false);
        cache.get("nonexistent");
        let s = cache.stats();
        assert_eq!(s.l1_hits, 0);
        assert_eq!(s.l1_misses, 1);
    }

    #[test]
    fn stats_tracking_l2_miss_when_enabled() {
        let cache = TwoTierCache::new(100, true);
        cache.get("nonexistent");
        let s = cache.stats();
        assert_eq!(s.l1_misses, 1);
        assert_eq!(s.l2_misses, 1);
    }

    #[test]
    fn stats_no_l2_when_disabled() {
        let cache = TwoTierCache::new(100, false);
        cache.get("nonexistent");
        let s = cache.stats();
        assert_eq!(s.l2_misses, 0);
        assert_eq!(s.l2_hits, 0);
    }

    #[test]
    fn stats_entry_count() {
        let cache = TwoTierCache::new(100, false);
        cache.put("p1", sample_response("r1"));
        cache.put("p2", sample_response("r2"));
        let s = cache.stats();
        assert_eq!(s.entries, 2);
    }

    // --- Eviction ---

    // --- L2 semantic match ---

    #[test]
    fn l2_semantic_finds_paraphrase() {
        let cache = TwoTierCache::with_threshold(100, true, 0.4);
        cache.put("What is the capital of France", sample_response("Paris"));
        // Different phrasing, same vocabulary - L1 misses, L2 hits.
        let got = cache.get("What is France capital city");
        assert!(got.is_some(), "expected L2 hit on similar phrasing");
        assert_eq!(got.unwrap().content, "Paris");
        let s = cache.stats();
        assert_eq!(s.l1_misses, 1);
        assert_eq!(s.l2_hits, 1);
    }

    #[test]
    fn l2_misses_when_semantic_disabled() {
        let cache = TwoTierCache::new(100, false);
        cache.put("hello world", sample_response("hi"));
        // Disabled L2 must not promote a similar prompt.
        assert!(cache.get("hello there").is_none());
    }

    #[test]
    fn l2_respects_threshold() {
        // Threshold 0.99 is too strict for casual paraphrases.
        let cache = TwoTierCache::with_threshold(100, true, 0.99);
        cache.put("What is the capital of France", sample_response("Paris"));
        assert!(cache.get("What is France capital city").is_none());
    }

    #[test]
    fn l2_unrelated_query_misses() {
        let cache = TwoTierCache::with_threshold(100, true, 0.4);
        cache.put("What is the capital of France", sample_response("Paris"));
        assert!(cache
            .get("explain quantum entanglement to a child")
            .is_none());
    }

    #[test]
    fn max_entries_eviction() {
        let cache = TwoTierCache::new(3, false);
        cache.put("a", sample_response("ra"));
        cache.put("b", sample_response("rb"));
        cache.put("c", sample_response("rc"));
        // Exceeds capacity - oldest ("a") should be evicted.
        cache.put("d", sample_response("rd"));

        assert!(cache.get("a").is_none(), "oldest entry should be evicted");
        assert!(cache.get("b").is_some());
        assert!(cache.get("c").is_some());
        assert!(cache.get("d").is_some());

        let s = cache.stats();
        assert_eq!(s.entries, 3);
    }
}
