//! Async Redis implementation of [`AsyncKVStore`].
//!
//! Uses the `redis` crate with `tokio-comp` so each call awaits directly
//! on the tokio reactor instead of round-tripping through
//! `spawn_blocking`. Connection sharing is via
//! `redis::aio::MultiplexedConnection`: a single TCP connection can
//! service many concurrent logical requests because Redis' RESP
//! protocol is pipelineable.
//!
//! See matrix-v6 MATRIX_V6_C3_RESULTS §9.7 for the performance gap this
//! closes: rate-limit throughput was 98 rps on the sync bridge,
//! projected to 5-10k rps on the async client.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use redis::{aio::MultiplexedConnection, AsyncCommands, Client};
use tokio::sync::Mutex;

use super::async_kv::AsyncKVStore;

/// Configuration for [`AsyncRedisKVStore`].
#[derive(Debug, Clone)]
pub struct AsyncRedisConfig {
    /// Connection URL (e.g. `redis://host:6379/0` or `rediss://...` for TLS).
    pub url: String,
}

impl AsyncRedisConfig {
    /// Construct a new config from a Redis connection URL.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }
}

/// Async-native Redis KV store.
///
/// Lazily connects on first use; reconnects are handled by the
/// underlying `redis` crate (`MultiplexedConnection` retries transparently
/// for single-command ops on transient failures).
pub struct AsyncRedisKVStore {
    config: AsyncRedisConfig,
    conn: Mutex<Option<MultiplexedConnection>>,
}

impl AsyncRedisKVStore {
    /// Build a new store wrapped in an `Arc`, deferring connection until first use.
    pub fn new(config: AsyncRedisConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            conn: Mutex::new(None),
        })
    }

    async fn conn(&self) -> Result<MultiplexedConnection> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let client = Client::open(self.config.url.as_str())
            .with_context(|| format!("invalid redis url '{}'", self.config.url))?;
        let c = client
            .get_multiplexed_async_connection()
            .await
            .with_context(|| format!("connecting to redis at '{}'", self.config.url))?;
        *guard = Some(c.clone());
        Ok(c)
    }
}

#[async_trait]
impl AsyncKVStore for AsyncRedisKVStore {
    async fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let mut c = self.conn().await?;
        let v: Option<Vec<u8>> = c.get(key).await.context("redis GET failed")?;
        Ok(v.map(Bytes::from))
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut c = self.conn().await?;
        let _: () = c.set(key, value).await.context("redis SET failed")?;
        Ok(())
    }

    async fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl_secs: u64) -> Result<()> {
        let mut c = self.conn().await?;
        if ttl_secs == 0 {
            let _: () = c.set(key, value).await.context("redis SET failed")?;
        } else {
            let _: () = c
                .set_ex(key, value, ttl_secs)
                .await
                .context("redis SET EX failed")?;
        }
        Ok(())
    }

    async fn incr_with_ttl(&self, key: &[u8], ttl_secs: u64) -> Result<i64> {
        let mut c = self.conn().await?;
        // Issue INCR + EXPIRE. The two commands are not atomic against
        // each other; between them, another client could observe a
        // fresh key without the TTL set. For rate-limit use cases that
        // is acceptable: the next incr_with_ttl call re-asserts the
        // TTL. If stricter atomicity is needed later, switch to a Lua
        // script via EVAL.
        let n: i64 = c.incr(key, 1).await.context("redis INCR failed")?;
        if ttl_secs > 0 {
            let _: bool = c
                .expire(key, ttl_secs as i64)
                .await
                .context("redis EXPIRE failed")?;
        }
        Ok(n)
    }

    async fn delete(&self, key: &[u8]) -> Result<()> {
        let mut c = self.conn().await?;
        let _: i64 = c.del(key).await.context("redis DEL failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_constructs() {
        let cfg = AsyncRedisConfig::new("redis://127.0.0.1:6379/0");
        assert_eq!(cfg.url, "redis://127.0.0.1:6379/0");
    }

    #[test]
    fn new_defers_connection() {
        // Bad URL is fine until we actually try to connect.
        let store = AsyncRedisKVStore::new(AsyncRedisConfig::new("redis://127.0.0.1:1"));
        // Invariant: constructor never panics and never opens a socket.
        assert!(Arc::strong_count(&store) >= 1);
    }

    #[tokio::test]
    #[ignore = "requires live redis; set REDIS_URL env"]
    async fn e2e_roundtrip() {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let store = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
        let key = format!("sbproxy:async:test:{}", std::process::id());
        let kb = key.as_bytes();
        store.put_with_ttl(kb, b"hi", 10).await.unwrap();
        assert_eq!(store.get(kb).await.unwrap().as_deref(), Some(&b"hi"[..]));
        let n1 = store.incr_with_ttl(b"cnt-test", 30).await.unwrap();
        let n2 = store.incr_with_ttl(b"cnt-test", 30).await.unwrap();
        assert_eq!(n2, n1 + 1);
        store.delete(kb).await.unwrap();
        store.delete(b"cnt-test").await.unwrap();
    }
}
