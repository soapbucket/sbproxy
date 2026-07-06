//! Async-native KV store trait for hot-path consumers.
//!
//! The existing synchronous [`super::KVStore`] trait works for callers
//! that don't care about per-request latency. On the request path,
//! however, wrapping every Redis op in `tokio::task::spawn_blocking`
//! adds 80-170 ms per call under concurrent load (observed in the
//! matrix-v6 clustered rate-limit scenario: 112k rps without
//! coordination → 98 rps once the sync-Redis bridge became active).
//!
//! `AsyncKVStore` gives consumers a first-class async API that can be
//! backed by a non-blocking Redis client. Existing callers that use
//! the sync trait keep working; new hot-path callers (rate-limit,
//! response cache) can migrate to this trait to eliminate the
//! spawn_blocking bridge.
//!
//! **When to use which trait:**
//!
//! - Storage operations on the request path that run per-request
//!   (rate-limit lookups, cache reads/writes, semantic-cache
//!   embeddings) should use [`AsyncKVStore`].
//! - Storage operations that run once at startup or infrequently
//!   (cert reload, config snapshot, mesh persistence) can continue
//!   to use the sync [`super::KVStore`] without meaningful penalty.
//!
//! A single backend implementation may implement both traits. The
//! provided `AsyncRedisKVStore` is async-native (via the `redis` crate
//! with `tokio-comp`); we do NOT auto-adapt the sync trait to the
//! async one because that reintroduces the spawn_blocking overhead.

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;

/// Async-native key-value storage.
///
/// All implementations must be thread-safe.
#[async_trait]
pub trait AsyncKVStore: Send + Sync + 'static {
    /// Get a value by key. Returns None on miss.
    async fn get(&self, key: &[u8]) -> Result<Option<Bytes>>;

    /// Insert or update a key-value pair.
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;

    /// Insert or update a key-value pair with an expiry in seconds.
    /// `ttl_secs == 0` means no expiry.
    async fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl_secs: u64) -> Result<()>;

    /// Atomically increment the integer counter at `key` and ensure the key's
    /// TTL is at least `ttl_secs` seconds. Returns the post-increment value.
    ///
    /// Backends that cannot guarantee atomicity (e.g. file / memory) may
    /// return a `not supported` error; hot-path callers can fall back to
    /// a local counter or the sync trait.
    async fn incr_with_ttl(&self, key: &[u8], ttl_secs: u64) -> Result<i64>;

    /// Atomically add `amount` to the integer counter at `key` (Redis
    /// `INCRBY`) and ensure the key's TTL is at least `ttl_secs`. Returns
    /// the post-increment value. Like [`incr_with_ttl`](Self::incr_with_ttl)
    /// but by an arbitrary amount, so callers can accumulate spend
    /// (tokens, micro-USD) into a shared counter across replicas.
    ///
    /// The default returns a `not supported` error; backends that can do
    /// it atomically (Redis) override this. Callers should fail open.
    async fn incr_by_with_ttl(&self, _key: &[u8], _amount: i64, _ttl_secs: u64) -> Result<i64> {
        anyhow::bail!("incr_by_with_ttl not supported by this backend")
    }

    /// Delete a key. No-op if absent.
    async fn delete(&self, key: &[u8]) -> Result<()>;
}
