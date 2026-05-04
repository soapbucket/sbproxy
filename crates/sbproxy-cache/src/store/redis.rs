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

    fn delete(&self, key: &str) -> Result<()> {
        self.store.delete(&self.full_key(key))
    }

    fn clear(&self) -> Result<()> {
        // A `SCAN MATCH prefix*` + DEL would work, but on a shared Redis this
        // can be destructive and slow. Callers that need a clean slate in
        // tests should use `MemoryCacheStore` instead. Treat `clear()` as a
        // best-effort no-op for Redis.
        Ok(())
    }
}
