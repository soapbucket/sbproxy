//! In-memory LRU cache for judge verdicts.
//!
//! Cache key is `(prompt_hash, payload_hash)` where each `u128` is
//! the leading 16 bytes of `SHA-256(text)`. SHA-256 is collision-
//! resistant well past the 128-bit truncation point for any volume
//! of cache entries we plausibly hold; the truncation halves key
//! storage at no realistic accuracy cost.
//!
//! The cache holds `PolicyDecision` values directly so a hit returns
//! the verdict without touching the upstream provider. Cache hits
//! charge zero tokens against the [`BudgetTracker`].
//!
//! The struct is `pub` so the enterprise crate can wrap or replace
//! the in-memory backing with a Redis layer for cross-instance
//! sharing without re-implementing the LRU semantics.
//!
//! [`BudgetTracker`]: super::BudgetTracker

use std::num::NonZeroUsize;
use std::sync::Mutex;

use sbproxy_plugin::PolicyDecision;
use sha2::{Digest, Sha256};

/// Compose a 128-bit key from `(prompt, payload)`.
///
/// Both inputs are SHA-256 hashed and the leading 16 bytes
/// reinterpreted as a big-endian `u128`. Same input -> same key
/// across processes and architectures.
pub fn cache_key(prompt: &str, payload: &serde_json::Value) -> (u128, u128) {
    let prompt_hash = truncated_sha256_u128(prompt.as_bytes());
    // serde_json::to_string is deterministic for any serde_json::Value
    // because Map iteration order is preserved (the BTreeMap-backed
    // `preserve_order` feature is on by default in the workspace).
    // For values built directly with the json! macro the field order
    // is the source-code order, which matches the typical caller.
    let payload_str = serde_json::to_string(payload).unwrap_or_default();
    let payload_hash = truncated_sha256_u128(payload_str.as_bytes());
    (prompt_hash, payload_hash)
}

fn truncated_sha256_u128(bytes: &[u8]) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    // Leading 16 bytes (128 bits) interpreted big-endian. Big-endian
    // is conventional for hash truncation and round-trips cleanly
    // through hex if anyone wants to log it.
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&digest[..16]);
    u128::from_be_bytes(buf)
}

/// LRU-backed verdict cache.
///
/// Interior mutability is via `Mutex<lru::LruCache<...>>`. The lock
/// is held only across the LRU's own `O(1)` get/put operations, so
/// the critical section is microscopic compared to a model call.
/// Holding `Mutex` rather than `RwLock` is deliberate: every
/// successful get also moves the entry to the head of the LRU,
/// which is a write under the hood.
#[derive(Debug)]
pub struct JudgeCache {
    inner: Mutex<lru::LruCache<(u128, u128), PolicyDecision>>,
}

impl JudgeCache {
    /// Build a new cache with the given capacity. A capacity of zero
    /// is treated as one (the [`lru`] crate requires `NonZeroUsize`).
    pub fn new(capacity: usize) -> Self {
        let nz = NonZeroUsize::new(capacity.max(1)).expect("capacity coerced to >= 1");
        Self {
            inner: Mutex::new(lru::LruCache::new(nz)),
        }
    }

    /// Look up an entry. Returns the stored verdict on hit.
    /// A successful lookup also touches the LRU so the entry is
    /// promoted to the head.
    pub fn get(&self, key: (u128, u128)) -> Option<PolicyDecision> {
        self.inner
            .lock()
            .expect("judge cache lock poisoned")
            .get(&key)
            .cloned()
    }

    /// Insert or replace an entry. Existing entries with the same
    /// key are overwritten; the LRU promotes the entry to the head
    /// regardless.
    pub fn put(&self, key: (u128, u128), verdict: PolicyDecision) {
        self.inner
            .lock()
            .expect("judge cache lock poisoned")
            .put(key, verdict);
    }

    /// Current number of entries. Snapshot value.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("judge cache lock poisoned").len()
    }

    /// Reports `true` when the cache contains zero entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn allow() -> PolicyDecision {
        PolicyDecision::Allow
    }

    fn deny(message: &str) -> PolicyDecision {
        PolicyDecision::Deny {
            status: 403,
            message: message.to_string(),
        }
    }

    #[test]
    fn cache_key_is_deterministic_and_distinguishes_inputs() {
        let k1 = cache_key("prompt-A", &json!({"x": 1}));
        let k2 = cache_key("prompt-A", &json!({"x": 1}));
        assert_eq!(k1, k2, "same input must produce same key");

        let k3 = cache_key("prompt-B", &json!({"x": 1}));
        assert_ne!(k1, k3, "different prompt must produce different key");

        let k4 = cache_key("prompt-A", &json!({"x": 2}));
        assert_ne!(k1, k4, "different payload must produce different key");
    }

    #[test]
    fn hit_returns_stored_verdict_without_provider_call() {
        let cache = JudgeCache::new(8);
        let key = cache_key("hello", &json!({"a": 1}));
        assert!(cache.get(key).is_none(), "miss expected on empty cache");
        cache.put(key, allow());
        // The whole point of this test: a hit is the only thing the
        // caller needs in order to skip the provider entirely. The
        // subsequent code paths in client.rs assert this contract.
        assert_eq!(cache.get(key), Some(allow()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn miss_returns_none_for_unseen_key() {
        let cache = JudgeCache::new(4);
        let stored_key = cache_key("known", &json!({}));
        cache.put(stored_key, allow());

        let unknown_key = cache_key("unknown", &json!({}));
        assert!(cache.get(unknown_key).is_none());
    }

    #[test]
    fn lru_evicts_oldest_at_capacity() {
        let cache = JudgeCache::new(2);
        let k1 = cache_key("p1", &json!({}));
        let k2 = cache_key("p2", &json!({}));
        let k3 = cache_key("p3", &json!({}));
        cache.put(k1, allow());
        cache.put(k2, deny("blocked"));
        // Touching k1 promotes it; k2 becomes the LRU candidate.
        let _ = cache.get(k1);
        cache.put(k3, allow());
        assert_eq!(
            cache.get(k1),
            Some(allow()),
            "promoted entry survives eviction"
        );
        assert!(
            cache.get(k2).is_none(),
            "least-recently-used entry was evicted"
        );
        assert_eq!(cache.get(k3), Some(allow()));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn put_overwrites_existing_entry() {
        let cache = JudgeCache::new(4);
        let key = cache_key("p", &json!({}));
        cache.put(key, allow());
        cache.put(key, deny("blocked"));
        assert_eq!(cache.get(key), Some(deny("blocked")));
        assert_eq!(cache.len(), 1);
    }
}
