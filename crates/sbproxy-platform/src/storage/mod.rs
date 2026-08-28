//! Key-value storage trait and backends.

mod async_kv;
mod async_redis;
pub mod embedded;
mod embedded_metrics;
mod file;
mod memory;
mod redb_store;
mod redis;
mod redis_connection;
mod sqlite;

pub use async_kv::AsyncKVStore;
pub use async_redis::{AsyncRedisConfig, AsyncRedisKVStore, RedisScanPage};
#[cfg(feature = "redb-store")]
pub use embedded::EmbeddedKvStore;
pub use embedded::{CasOutcome, EphemeralKv, KvEntry, KvNamespace, MemoryKv, PersistentKv};
pub use file::FileKVStore;
pub use memory::MemoryKVStore;
pub use redb_store::RedbKVStore;
pub use redis::{RedisConfig, RedisKVStore};
pub use redis_connection::{RedisTlsConfig, ValidatedRedisConnection};
pub use sqlite::SqliteKVStore;

use anyhow::Result;
use bytes::Bytes;

/// Low-level key-value storage. All implementations must be thread-safe.
pub trait KVStore: Send + Sync + 'static {
    /// Clone the already-validated Redis connection snapshot, when this store
    /// is Redis-backed.
    ///
    /// Runtime consumers use this internal seam to share one compiled DSN and
    /// TLS identity without reopening configuration files. Other backends
    /// retain the default `None` implementation.
    #[doc(hidden)]
    fn validated_redis_connection(&self) -> Option<ValidatedRedisConnection> {
        None
    }

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

    /// Atomically replace `expected` with `value` and set a TTL.
    ///
    /// The byte comparison and replacement must be one indivisible backend
    /// operation. Unsupported backends return an error so callers never
    /// degrade a conditional update into an unsafe unconditional write.
    fn compare_and_swap_with_ttl(
        &self,
        _key: &[u8],
        _expected: &[u8],
        _value: &[u8],
        _ttl_secs: u64,
    ) -> Result<bool> {
        anyhow::bail!("compare_and_swap_with_ttl: not supported by this backend")
    }

    /// Atomically create `key` with `value` and a TTL, only if `key` is
    /// absent. Returns `true` when this caller created it (WOR-2609).
    ///
    /// Redis's `SET NX EX`. The default is an error rather than an
    /// unconditional success, which is the opposite of [`Self::try_lock`]
    /// and deliberately so: a caller reaching for an atomic create is
    /// building single-flight on it, in one process as much as across a
    /// fleet, and a backend that quietly says yes to every caller turns
    /// that into no single-flight at all while every single-request test
    /// still passes. An error lets the caller degrade on purpose and say
    /// so.
    fn put_if_absent_with_ttl(&self, _key: &[u8], _value: &[u8], _ttl_secs: u64) -> Result<bool> {
        anyhow::bail!("put_if_absent_with_ttl: not supported by this backend")
    }

    /// Whether [`Self::put_if_absent_with_ttl`] is implemented on this
    /// backend, asked without writing anything.
    ///
    /// A caller building single-flight has to know which mode it is in
    /// *before* the first request, and it cannot learn that from a
    /// failed write: a command timeout and an unimplemented primitive
    /// both arrive as `Err`, and a caller that reads the first as the
    /// second disarms itself permanently on one dropped packet. Support
    /// is a property of the backend, so it is answered by the backend
    /// rather than inferred from one request's luck.
    ///
    /// Overriding [`Self::put_if_absent_with_ttl`] without overriding
    /// this leaves the caller in the degraded mode it would have used
    /// anyway, which is the safe direction for a mistake to point.
    fn supports_atomic_create(&self) -> bool {
        false
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

    /// Try to acquire a lock: set `key` to the caller's unique `token`
    /// only if `key` is absent, expiring after `ttl_secs`. Returns `true`
    /// when acquired, `false` when another holder has it (WOR-1774).
    ///
    /// The default acquires unconditionally: a local, single-node backend
    /// (memory / redb / file on one host) has no cross-node contention, so
    /// there is nothing to serialize against. A shared backend (redis)
    /// overrides this with an atomic `SET NX PX` lease so a fleet issues a
    /// cert once instead of stampeding the ACME CA.
    fn try_lock(&self, _key: &[u8], _token: &[u8], _ttl_secs: u64) -> Result<bool> {
        Ok(true)
    }

    /// Acquire a lock and return the *fencing generation* that goes with it
    /// (WOR-2633). `Ok(None)` means another holder has it.
    ///
    /// The generation strictly increases across every successful acquisition
    /// of the same key on a given backend, including a takeover of an expired
    /// lease. That is what makes a lock safe to build on: mutual exclusion
    /// alone cannot survive a holder that pauses past its lease, but a
    /// publication that refuses any generation it has already seen can. A
    /// superseded owner is fenced out at the write rather than trusted to
    /// notice it was superseded.
    ///
    /// The default pairs [`Self::try_lock`] with a counter persisted in the
    /// store itself under `<key>:fence`, which is the honest answer for a
    /// single-node backend (memory, redb, sqlite): there is no cross-node
    /// contention to fence, so the read-increment-write below cannot race,
    /// and persisting the counter next to the data keeps it monotonic across
    /// a process restart. A process-local counter would restart at one while
    /// the material it fences persisted at seven, and every later
    /// acquisition would look superseded by history. A shared backend must
    /// override this with an atomic generation the whole fleet agrees on, or
    /// it is not cluster-safe.
    fn try_lock_fenced(&self, key: &[u8], token: &[u8], ttl_secs: u64) -> Result<Option<u64>> {
        if !self.try_lock(key, token, ttl_secs)? {
            return Ok(None);
        }
        let mut fence_key = key.to_vec();
        fence_key.extend_from_slice(b":fence");
        let next = self
            .get(&fence_key)?
            .and_then(|bytes| std::str::from_utf8(&bytes).ok()?.parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_add(1);
        self.put(&fence_key, next.to_string().as_bytes())?;
        Ok(Some(next))
    }

    /// Extend a lease this caller already holds under `token`, returning
    /// `false` once the lease is no longer ours (WOR-2633).
    ///
    /// An ACME order can legitimately outlive any TTL short enough to release
    /// a crashed holder promptly, so the holder heartbeats instead of picking
    /// a TTL that has to cover the worst case. A backend that cannot renew
    /// conditionally must return `false` rather than `true`, so the caller
    /// stops rather than continuing on an assumption.
    ///
    /// The default is `true`: a single-node backend has no peer that could
    /// have taken the lease away.
    fn renew_lock(&self, _key: &[u8], _token: &[u8], _ttl_secs: u64) -> Result<bool> {
        Ok(true)
    }

    /// Release a lock previously acquired via [`Self::try_lock`] with the
    /// same `token`. An implementation must delete the key only when the
    /// stored value still matches `token`, so a node never releases a lock
    /// another node acquired after this one's lease expired. The default is
    /// a no-op (pairs with the always-acquire default).
    fn unlock(&self, _key: &[u8], _token: &[u8]) -> Result<()> {
        Ok(())
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
