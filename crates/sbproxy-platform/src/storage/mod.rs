//! Key-value storage trait and backends.

mod async_kv;
mod async_redis;
mod file;
mod memory;
mod redb_store;
mod redis;
mod sqlite;

#[cfg(feature = "postgres-store")]
mod postgres;

pub use async_kv::AsyncKVStore;
pub use async_redis::{AsyncRedisConfig, AsyncRedisKVStore};
pub use file::FileKVStore;
pub use memory::MemoryKVStore;
pub use redb_store::RedbKVStore;
pub use redis::{RedisConfig, RedisKVStore};
pub use sqlite::SqliteKVStore;

#[cfg(feature = "postgres-store")]
pub use postgres::PostgresKVStore;

use anyhow::Result;
use bytes::Bytes;

/// Low-level key-value storage. All implementations must be thread-safe.
pub trait KVStore: Send + Sync + 'static {
    /// Get a value by key. Returns None if the key does not exist.
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>>;

    /// Insert or update a key-value pair.
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;

    /// Delete a key. No-op if the key does not exist.
    fn delete(&self, key: &[u8]) -> Result<()>;

    /// Return all key-value pairs whose key starts with `prefix`.
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>>;

    /// Insert or update a key-value pair with an expiry in seconds.
    ///
    /// Backends that cannot support TTLs should return the default
    /// `not supported` error so callers can fall back.
    fn put_with_ttl(&self, _key: &[u8], _value: &[u8], _ttl_secs: u64) -> Result<()> {
        anyhow::bail!("put_with_ttl: not supported by this backend")
    }

    /// Atomically increment the integer counter stored at `key` and ensure
    /// the key's TTL is at least `ttl_secs` seconds. Returns the post-increment
    /// value.
    ///
    /// Backends that cannot guarantee atomicity should return the default
    /// `not supported` error; callers can then fall back to a local counter.
    fn incr_with_ttl(&self, _key: &[u8], _ttl_secs: u64) -> Result<i64> {
        anyhow::bail!("incr_with_ttl: not supported by this backend")
    }
}

/// Async helper: invoke `KVStore::incr_with_ttl` inside `spawn_blocking`
/// so it can be called from an async (tokio) context without blocking
/// the runtime thread pool.
///
/// The concrete `KVStore` implementation may issue blocking network I/O
/// (e.g. `RedisKVStore` uses a blocking `TcpStream`). Using
/// `tokio::task::spawn_blocking` keeps the async scheduler responsive.
pub async fn incr_with_ttl_async(
    store: std::sync::Arc<dyn KVStore>,
    key: Vec<u8>,
    ttl_secs: u64,
) -> Result<i64> {
    tokio::task::spawn_blocking(move || store.incr_with_ttl(&key, ttl_secs))
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking join failed: {}", e))?
}

/// Async helper: invoke `KVStore::put_with_ttl` inside `spawn_blocking`.
pub async fn put_with_ttl_async(
    store: std::sync::Arc<dyn KVStore>,
    key: Vec<u8>,
    value: Vec<u8>,
    ttl_secs: u64,
) -> Result<()> {
    tokio::task::spawn_blocking(move || store.put_with_ttl(&key, &value, ttl_secs))
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking join failed: {}", e))?
}

/// Async helper: invoke `KVStore::get` inside `spawn_blocking`.
pub async fn get_async(store: std::sync::Arc<dyn KVStore>, key: Vec<u8>) -> Result<Option<Bytes>> {
    tokio::task::spawn_blocking(move || store.get(&key))
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking join failed: {}", e))?
}
