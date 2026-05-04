//! Cache Reserve: long-tail cold tier for the response cache.
//!
//! Two surfaces ship in this module:
//!
//! 1. The legacy synchronous [`ReserveCacheStore`] composer, which wraps
//!    two [`CacheStore`](crate::CacheStore) implementations into a hot/cold
//!    pair. It remains the in-process building block when both tiers are
//!    cheap (memory + filesystem).
//! 2. The async [`CacheReserveBackend`] trait plus three OSS
//!    implementations ([`MemoryReserve`], [`FsReserve`], [`RedisReserve`]).
//!    The trait is the integration point for backends that need to
//!    perform real I/O (object storage, KMS-wrapped writes). Enterprise
//!    crates ship their own `impl CacheReserveBackend` (S3 + KMS, GCS,
//!    Azure Blob) without re-vendoring the OSS data plane.
//!
//! The async trait is independent of `CacheStore`. It carries explicit
//! [`ReserveMetadata`] so backends can persist content type, vary
//! fingerprint, status, and expiry without re-deriving them from a
//! serialised `CachedResponse`.

mod composer;
pub mod filesystem;
pub mod memory;
pub mod redis;

pub use composer::{ReserveCacheStore, ReserveConfig, ReserveStats};
pub use filesystem::FsReserve;
pub use memory::MemoryReserve;
pub use redis::RedisReserve;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Metadata persisted alongside a reserve entry.
///
/// Mirrors the response-shape fields a hot-cache entry needs to be
/// re-served verbatim. Backends should treat the metadata as opaque
/// once written: every field is round-tripped exactly through
/// [`CacheReserveBackend::get`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveMetadata {
    /// Wall-clock time the entry was admitted.
    pub created_at: SystemTime,
    /// Wall-clock time the entry should be considered expired.
    pub expires_at: SystemTime,
    /// HTTP `Content-Type` header from the cached response.
    pub content_type: Option<String>,
    /// Hash of the request headers named in the origin's `vary:`
    /// list, so two variants of the same path do not collide.
    pub vary_fingerprint: Option<String>,
    /// Body length in bytes.
    pub size: u64,
    /// HTTP status code the cached response replied with.
    pub status: u16,
}

impl ReserveMetadata {
    /// Returns true when `now >= expires_at`.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }
}

/// Async backend abstraction for the cold reserve tier.
///
/// Implementations must be `Send + Sync` so a single instance can back
/// every origin in a multi-tenant proxy. The trait is intentionally
/// minimal: callers compose admission control, sampling, and metric
/// emission outside the backend so the backend itself only has to
/// answer "store this", "fetch this", "drop this".
///
/// Enterprise note: the OSS proxy never imports an enterprise crate.
/// Enterprise builds register their backend through
/// `Arc<dyn CacheReserveBackend>` so this trait is the only stable
/// surface between the two trees. Renaming or breaking it is a
/// semver-major change.
#[async_trait]
pub trait CacheReserveBackend: Send + Sync {
    /// Persist `value` (and its metadata) under `key`. Returning `Ok`
    /// promises the entry is durable up to the backend's own
    /// guarantees: filesystem flushes, Redis acks, S3 PUT response,
    /// etc. The reserve is best-effort, so callers may swallow the
    /// error; failures should still be returned faithfully so
    /// metrics and alerting can pick them up.
    async fn put(&self, key: &str, value: Bytes, metadata: ReserveMetadata) -> anyhow::Result<()>;

    /// Look up the entry stored under `key`. Returns `Ok(None)` when
    /// the key is absent; an `Err` indicates a backend failure
    /// (network, decode, permissions). Callers may degrade to a hot
    /// miss on either of those.
    async fn get(&self, key: &str) -> anyhow::Result<Option<(Bytes, ReserveMetadata)>>;

    /// Remove the entry at `key`. A missing key is not an error.
    async fn delete(&self, key: &str) -> anyhow::Result<()>;

    /// Drop every entry whose `expires_at` is older than `before`.
    /// Returns the number of entries removed. Backends that cannot
    /// efficiently scan their key space (e.g. S3 list-and-delete) may
    /// implement this as a periodic batch sweep; in-process backends
    /// can do it inline. Returning `Ok(0)` is always safe.
    async fn evict_expired(&self, before: SystemTime) -> anyhow::Result<u64>;
}

#[async_trait]
impl<T: CacheReserveBackend + ?Sized> CacheReserveBackend for std::sync::Arc<T> {
    async fn put(&self, key: &str, value: Bytes, metadata: ReserveMetadata) -> anyhow::Result<()> {
        (**self).put(key, value, metadata).await
    }
    async fn get(&self, key: &str) -> anyhow::Result<Option<(Bytes, ReserveMetadata)>> {
        (**self).get(key).await
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        (**self).delete(key).await
    }
    async fn evict_expired(&self, before: SystemTime) -> anyhow::Result<u64> {
        (**self).evict_expired(before).await
    }
}
