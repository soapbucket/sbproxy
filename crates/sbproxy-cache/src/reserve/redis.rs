//! Redis [`CacheReserveBackend`].
//!
//! Stores body and metadata as a single hash per key:
//!   `HSET {prefix}{key} body <bytes> meta <json>`
//! and applies the TTL via `PEXPIREAT` so the entry self-evicts when
//! `metadata.expires_at` is reached. Connection pooling is handled by
//! [`redis::aio::ConnectionManager`], which transparently reconnects
//! on transient failures.
//!
//! Redis is the obvious shared cold tier when a deployment already has
//! a Redis cluster on hand. For larger long-tail working sets, an
//! object-store-backed reserve can be wired over the same trait.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use redis::{aio::ConnectionManager, AsyncCommands, Client};
use tokio::sync::Mutex;

use super::{CacheReserveBackend, ReserveMetadata};

/// Redis-backed reserve.
pub struct RedisReserve {
    /// Underlying redis client. Held for reconnect attempts.
    client: Client,
    /// Async connection manager. Lazily initialised on first use so
    /// constructing a `RedisReserve` does not require a live Redis.
    conn: Mutex<Option<ConnectionManager>>,
    /// Static prefix prepended to every key. Lets the reserve coexist
    /// with `RedisCacheStore` (`sbproxy:cache:`) and rate-limit
    /// counters in the same Redis instance.
    pub key_prefix: String,
}

impl std::fmt::Debug for RedisReserve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisReserve")
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
}

impl RedisReserve {
    /// Build a new reserve from a `redis://...` URL.
    pub fn new(url: &str, key_prefix: impl Into<String>) -> Result<Self> {
        let client = Client::open(url).with_context(|| format!("invalid redis url '{url}'"))?;
        Ok(Self {
            client,
            conn: Mutex::new(None),
            key_prefix: key_prefix.into(),
        })
    }

    /// Build a reserve using the default `sbproxy:reserve:` prefix.
    pub fn with_default_prefix(url: &str) -> Result<Self> {
        Self::new(url, "sbproxy:reserve:")
    }

    fn full_key(&self, key: &str) -> String {
        let mut full = String::with_capacity(self.key_prefix.len() + key.len());
        full.push_str(&self.key_prefix);
        full.push_str(key);
        full
    }

    async fn conn(&self) -> Result<ConnectionManager> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let cm = ConnectionManager::new(self.client.clone())
            .await
            .context("connecting redis ConnectionManager")?;
        *guard = Some(cm.clone());
        Ok(cm)
    }
}

#[async_trait]
impl CacheReserveBackend for RedisReserve {
    async fn put(&self, key: &str, value: Bytes, metadata: ReserveMetadata) -> Result<()> {
        let mut conn = self.conn().await?;
        let full = self.full_key(key);
        let meta_bytes = serde_json::to_vec(&metadata)?;
        // HSET body + meta atomically so a partial write is not
        // observable. The pipeline trip is cheaper than two RTTs.
        let _: () = redis::pipe()
            .atomic()
            .hset(&full, "body", value.as_ref())
            .hset(&full, "meta", meta_bytes.as_slice())
            .query_async(&mut conn)
            .await
            .context("redis HSET reserve entry")?;
        // Translate `expires_at` to milliseconds since epoch and
        // hand it to PEXPIREAT so Redis takes care of eviction once
        // the deadline passes.
        let expires_ms = metadata
            .expires_at
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        if expires_ms > 0 {
            let _: () = conn
                .pexpire_at(&full, expires_ms)
                .await
                .context("redis PEXPIREAT reserve entry")?;
        }
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<(Bytes, ReserveMetadata)>> {
        let mut conn = self.conn().await?;
        let full = self.full_key(key);
        // HGETALL returns an empty map for an absent key.
        let pairs: Vec<(String, Vec<u8>)> = conn
            .hgetall(&full)
            .await
            .context("redis HGETALL reserve entry")?;
        if pairs.is_empty() {
            return Ok(None);
        }
        let mut body: Option<Vec<u8>> = None;
        let mut meta: Option<Vec<u8>> = None;
        for (k, v) in pairs {
            match k.as_str() {
                "body" => body = Some(v),
                "meta" => meta = Some(v),
                _ => {}
            }
        }
        let (Some(body), Some(meta)) = (body, meta) else {
            // Half-written entry; treat as miss and let the caller
            // fall through to origin. The next put() will overwrite
            // the partial state.
            return Ok(None);
        };
        let metadata: ReserveMetadata =
            serde_json::from_slice(&meta).context("decode reserve metadata")?;
        Ok(Some((Bytes::from(body), metadata)))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut conn = self.conn().await?;
        let full = self.full_key(key);
        let _: i64 = conn.del(&full).await.context("redis DEL reserve entry")?;
        Ok(())
    }

    async fn evict_expired(&self, _before: SystemTime) -> Result<u64> {
        // Redis evicts via the PEXPIREAT applied at put time. A
        // SCAN-and-delete sweep would duplicate that work and risks
        // tripping cluster-mode key-space scans, so we treat this as
        // a no-op and trust the server-side deadline.
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Redis backend is hard to unit-test without a live server.
    // The full request-path coverage lives in the cache_reserve e2e
    // tests against a MemoryReserve, which exercises the trait path.
    // What we *can* check here is the cheap stuff: prefix handling
    // and constructor wiring.

    #[test]
    fn full_key_prepends_prefix() {
        let r = RedisReserve::new("redis://127.0.0.1:6379", "p:").unwrap();
        assert_eq!(r.full_key("abc"), "p:abc");
    }

    #[test]
    fn default_prefix_is_namespaced() {
        let r = RedisReserve::with_default_prefix("redis://127.0.0.1:6379").unwrap();
        assert_eq!(r.full_key("abc"), "sbproxy:reserve:abc");
    }

    #[test]
    fn invalid_url_errors_at_construction() {
        // No scheme - the redis crate parses this lazily, so the
        // failure mode here is "Client::open returned an Err". Any
        // Err is fine for the test; just confirming the surface
        // doesn't silently swallow a malformed URL.
        let res = RedisReserve::new("not a url", "p:");
        assert!(res.is_err());
    }
}
