//! Cache storage trait and backends.

mod file;
mod memcached;
mod memory;
mod redis;

pub use file::{FileCacheConfig, FileCacheStore};
pub use memcached::{MemcachedConfig, MemcachedStore};
pub use memory::MemoryCacheStore;
pub use redis::RedisCacheStore;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A cached HTTP response with TTL metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResponse {
    /// HTTP status code of the cached response.
    pub status: u16,
    /// Response headers as ordered name/value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// Unix timestamp (seconds) when this entry was cached.
    pub cached_at: u64,
    /// Time-to-live in seconds from `cached_at`.
    pub ttl_secs: u64,
}

impl CachedResponse {
    /// Returns true if this entry has exceeded its TTL.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.cached_at + self.ttl_secs
    }
}

/// Cache storage trait. All implementations must be thread-safe.
pub trait CacheStore: Send + Sync + 'static {
    /// Look up a cached response by key. Returns None if missing or expired.
    fn get(&self, key: &str) -> Result<Option<CachedResponse>>;

    /// Look up a cached response, including expired entries.
    ///
    /// Used by the stale-while-revalidate path: the live `get` would
    /// throw away an expired entry (and trigger a backend roundtrip)
    /// even when the SWR window says we should serve it stale and
    /// revalidate in the background. The default impl falls back to
    /// `get` for backends that have no separate "include expired" path.
    fn get_including_expired(&self, key: &str) -> Result<Option<CachedResponse>> {
        self.get(key)
    }

    /// Store a cached response.
    fn put(&self, key: &str, value: &CachedResponse) -> Result<()>;

    /// Remove a cached response by key.
    fn delete(&self, key: &str) -> Result<()>;

    /// Remove every entry whose key starts with `prefix`.
    ///
    /// Used by the `invalidate_on_mutation` path: a `POST /users/42`
    /// removes every cached `GET /users/42` variant regardless of
    /// query string or Vary fingerprint. Backends that cannot
    /// efficiently scan keys (Redis, memcached) may return
    /// `Ok(0)` and rely on TTL expiry instead. Returns the number
    /// of entries removed.
    fn delete_prefix(&self, _prefix: &str) -> Result<usize> {
        Ok(0)
    }

    /// Remove all entries.
    fn clear(&self) -> Result<()>;
}
