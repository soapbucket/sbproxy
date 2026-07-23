//! Cache storage trait and backends.

mod encrypted;
mod file;
mod memcached;
mod memory;
mod redis;

pub use encrypted::{CacheKeyMaterial, EncryptedCacheStore};
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
    ///
    /// The expiry sum saturates rather than wrapping. `cached_at` and
    /// `ttl_secs` come off the backing store, and a shared Redis or
    /// memcached is exactly the place someone can write a record with
    /// `ttl_secs` set to `u64::MAX`; an unchecked add would panic in a
    /// debug build. Saturating matches what the file and memcached
    /// stores already do for the same computation.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.cached_at.saturating_add(self.ttl_secs)
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

    /// Short backend name (`"memory"`, `"file"`, `"redis"`, ...) for
    /// operator surfaces like the admin cache manager, which uses it to
    /// explain which purge operations the backend actually supports.
    fn backend_name(&self) -> &'static str {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::CachedResponse;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[test]
    fn an_absurd_ttl_does_not_panic_on_the_expiry_check() {
        // `ttl_secs` is attacker-writable on a shared backing store, so
        // the expiry sum must saturate. An unchecked add here panics in
        // a debug build and takes the request with it.
        let entry = CachedResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            cached_at: now_secs(),
            ttl_secs: u64::MAX,
        };
        assert!(!entry.is_expired(), "a saturated expiry is still future");

        let pinned = CachedResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            cached_at: u64::MAX,
            ttl_secs: u64::MAX,
        };
        assert!(!pinned.is_expired(), "both fields at the maximum saturate");
    }

    #[test]
    fn a_lapsed_ttl_still_reports_expired() {
        let entry = CachedResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            cached_at: now_secs().saturating_sub(600),
            ttl_secs: 60,
        };
        assert!(entry.is_expired());
    }
}
