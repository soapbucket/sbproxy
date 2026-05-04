//! Idempotency key support for AI requests.
//!
//! Clients can include an idempotency key header so that retried requests
//! receive the original response without re-invoking the upstream provider.
//! `IdempotencyCache` stores responses keyed by that identifier and expires
//! entries after a configurable TTL.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// In-memory cache mapping idempotency keys to cached responses.
///
/// Entries older than `ttl` are treated as absent and will be evicted lazily
/// on the next access.
pub struct IdempotencyCache {
    cache: Mutex<HashMap<String, (Instant, serde_json::Value)>>,
    ttl: Duration,
}

impl IdempotencyCache {
    /// Create a new cache where entries expire after `ttl_secs` seconds.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Look up `key`.  Returns the cached response if present and not expired,
    /// otherwise `None`.
    ///
    /// Expired entries are lazily removed on lookup.
    pub fn check(&self, key: &str) -> Option<serde_json::Value> {
        let mut cache = self.cache.lock().unwrap();
        match cache.get(key) {
            Some((stored_at, _)) if stored_at.elapsed() >= self.ttl => {
                // Entry has expired - remove it.
                cache.remove(key);
                None
            }
            Some((_, response)) => Some(response.clone()),
            None => None,
        }
    }

    /// Store `response` under `key`, recording the current time as the
    /// insertion timestamp.
    pub fn store(&self, key: &str, response: serde_json::Value) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(key.to_string(), (Instant::now(), response));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn store_and_retrieve() {
        let cache = IdempotencyCache::new(60);
        let response = json!({"id": "resp-1", "choices": []});
        cache.store("key-abc", response.clone());
        let retrieved = cache.check("key-abc").expect("should be present");
        assert_eq!(retrieved, response);
    }

    #[test]
    fn missing_key_returns_none() {
        let cache = IdempotencyCache::new(60);
        assert!(cache.check("nonexistent").is_none());
    }

    #[test]
    fn expired_entry_returns_none() {
        // TTL = 0 means entries expire immediately.
        let cache = IdempotencyCache::new(0);
        cache.store("key-exp", json!({"result": "ok"}));
        // Sleep for 1ms to ensure elapsed > 0.
        std::thread::sleep(Duration::from_millis(1));
        assert!(cache.check("key-exp").is_none());
    }

    #[test]
    fn different_keys_are_independent() {
        let cache = IdempotencyCache::new(60);
        cache.store("key-1", json!({"n": 1}));
        cache.store("key-2", json!({"n": 2}));
        assert_eq!(cache.check("key-1").unwrap()["n"], 1);
        assert_eq!(cache.check("key-2").unwrap()["n"], 2);
    }

    #[test]
    fn storing_again_overwrites_existing() {
        let cache = IdempotencyCache::new(60);
        cache.store("key-ow", json!({"v": "first"}));
        cache.store("key-ow", json!({"v": "second"}));
        assert_eq!(cache.check("key-ow").unwrap()["v"], "second");
    }

    #[test]
    fn valid_entry_not_removed_before_expiry() {
        let cache = IdempotencyCache::new(3600); // 1 hour TTL
        cache.store("long-lived", json!({"data": "preserved"}));
        assert!(cache.check("long-lived").is_some());
    }
}
