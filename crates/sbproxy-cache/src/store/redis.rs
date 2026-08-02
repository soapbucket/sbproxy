//! Redis-backed CacheStore.
//!
//! Serialises a [`CachedResponse`] as JSON (via serde_json) and stores it in
//! the attached [`KVStore`] with `SET key value EX ttl`. Reads deserialise
//! and honour local `is_expired()` as a belt-and-braces check in case Redis
//! returns an entry that is still physically present but past its proxy TTL
//! (for example, if Redis is configured with longer key TTLs than the
//! proxy wants).
//!
//! The concrete KV backend is typically `RedisKVStore`, but any store that
//! implements `KVStore` with `put_with_ttl` will work.

use std::sync::Arc;

use anyhow::{Context, Result};
use sbproxy_platform::storage::KVStore;

use super::{CacheStore, CachedResponse};

/// CacheStore backed by a [`KVStore`] (usually Redis) so multiple proxy
/// replicas can share cached responses.
pub struct RedisCacheStore {
    store: Arc<dyn KVStore>,
    /// Static key namespace prefix added to every key before it's sent to
    /// the backend. Keeps rate-limit counters and cache entries in distinct
    /// key spaces even though they share a Redis instance.
    prefix: String,
}

impl RedisCacheStore {
    /// Build a new Redis-backed response cache.
    pub fn new(store: Arc<dyn KVStore>) -> Self {
        Self {
            store,
            prefix: "sbproxy:cache:".to_string(),
        }
    }

    fn full_key(&self, key: &str) -> Vec<u8> {
        let mut full = String::with_capacity(self.prefix.len() + key.len());
        full.push_str(&self.prefix);
        full.push_str(key);
        full.into_bytes()
    }
}

impl CacheStore for RedisCacheStore {
    fn get(&self, key: &str) -> Result<Option<CachedResponse>> {
        let full = self.full_key(key);
        match self.store.get(&full)? {
            Some(bytes) => {
                let entry: CachedResponse = serde_json::from_slice(&bytes)
                    .context("deserialize cached response from redis")?;
                if entry.is_expired() {
                    // Best-effort cleanup; ignore errors.
                    let _ = self.store.delete(&full);
                    Ok(None)
                } else {
                    Ok(Some(entry))
                }
            }
            None => Ok(None),
        }
    }

    fn put(&self, key: &str, value: &CachedResponse) -> Result<()> {
        let full = self.full_key(key);
        let encoded = serde_json::to_vec(value).context("serialize cached response for redis")?;
        // +1 on the Redis TTL so we don't race expiry between Redis's clock
        // and the local `is_expired()` check.
        let ttl = value.ttl_secs.saturating_add(1);
        self.store.put_with_ttl(&full, &encoded, ttl)
    }

    fn compare_and_swap(
        &self,
        key: &str,
        expected: &CachedResponse,
        replacement: &CachedResponse,
    ) -> Result<bool> {
        let full = self.full_key(key);
        let expected =
            serde_json::to_vec(expected).context("serialize expected cached response for redis")?;
        let ttl = replacement.ttl_secs.saturating_add(1);
        let replacement = serde_json::to_vec(replacement)
            .context("serialize replacement cached response for redis")?;
        self.store
            .compare_and_swap_with_ttl(&full, &expected, &replacement, ttl)
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.store.delete(&self.full_key(key))
    }

    fn delete_prefix(&self, prefix: &str) -> Result<usize> {
        // Scan our namespace for keys under `prefix` and delete each. The
        // scan is scoped to `sbproxy:cache:<prefix>` so it never touches
        // rate-limit counters or other key spaces sharing the Redis.
        let full = self.full_key(prefix);
        let entries = self.store.scan_prefix(&full)?;
        let mut removed = 0usize;
        for (k, _) in entries {
            if self.store.delete(&k).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn clear(&self) -> Result<()> {
        // SCAN our cache namespace and DEL each entry. Scoped to
        // `sbproxy:cache:` so it leaves other key spaces (rate-limit
        // counters, sessions) on a shared Redis untouched. This is an
        // operator-initiated purge (admin API), not a hot-path call.
        let entries = self.store.scan_prefix(self.prefix.as_bytes())?;
        for (k, _) in entries {
            let _ = self.store.delete(&k);
        }
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "redis"
    }

    fn durability(&self) -> crate::at_rest::CacheDurability {
        // Entries live on a shared server that other replicas read.
        crate::at_rest::CacheDurability::Replicated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_platform::storage::MemoryKVStore;

    fn entry(generation: u64, body: &[u8]) -> CachedResponse {
        CachedResponse {
            generation,
            status: 200,
            headers: Vec::new(),
            body: body.to_vec(),
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ttl_secs: 300,
        }
    }

    #[test]
    fn conditional_replace_rejects_a_newer_shared_entry() {
        let store = RedisCacheStore::new(Arc::new(MemoryKVStore::new(0)));
        let stale = entry(1, b"stale");
        store.put("key", &stale).unwrap();
        store.put("key", &entry(2, b"foreground")).unwrap();

        assert!(!store
            .compare_and_swap("key", &stale, &entry(3, b"background"))
            .unwrap());
        assert_eq!(
            store.get("key").unwrap().expect("foreground entry").body,
            b"foreground"
        );
    }
}
