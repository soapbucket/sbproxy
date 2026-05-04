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
