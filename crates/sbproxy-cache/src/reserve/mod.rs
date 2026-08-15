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
    /// Ordered response headers needed to replay and promote the entry.
    ///
    /// `serde(default)` keeps metadata written before validator
    /// persistence readable. New entries carry the complete storable
    /// header set, including `ETag` and `Last-Modified`.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
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

    /// Capture the response metadata needed by a reserve backend.
    pub fn from_cached_response(
        response: &crate::store::CachedResponse,
        created_at: SystemTime,
        expires_at: SystemTime,
    ) -> Self {
        let content_type = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.clone());
        Self {
            created_at,
            expires_at,
            content_type,
            headers: response.headers.clone(),
            vary_fingerprint: None,
            size: response.body.len() as u64,
            status: response.status,
        }
    }

    /// Rebuild a hot-cache entry from a reserve hit.
    pub fn to_cached_response(
        &self,
        body: Bytes,
        cached_at: u64,
        ttl_secs: u64,
    ) -> crate::store::CachedResponse {
        crate::store::CachedResponse {
            generation: crate::store::new_cache_generation(),
            status: self.status,
            headers: self.headers.clone(),
            body: body.to_vec(),
            cached_at,
            ttl_secs,
            // The manifest does not carry the window either, and a
            // recomposed entry has no admit decision behind it, so the
            // origin's configured default applies.
            swr_secs: None,
            // The reserve manifest carries no fingerprint. The key this
            // entry is recomposed under already does, so unstamped is
            // the honest value rather than a guess.
            config_fp: String::new(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CachedResponse;
    use std::time::Duration;

    #[test]
    fn cache_entry_roundtrip_preserves_validators_for_promotion() {
        let now = SystemTime::now();
        let cached = CachedResponse {
            generation: 0,
            status: 200,
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("etag".to_string(), r#"W/"reserve-v1""#.to_string()),
                (
                    "last-modified".to_string(),
                    "Sun, 06 Nov 1994 08:49:37 GMT".to_string(),
                ),
            ],
            body: br#"{"version":1}"#.to_vec(),
            cached_at: 10,
            ttl_secs: 60,
            swr_secs: None,
            config_fp: String::new(),
        };

        let metadata =
            ReserveMetadata::from_cached_response(&cached, now, now + Duration::from_secs(60));
        let promoted = metadata.to_cached_response(Bytes::from(cached.body.clone()), 20, 50);

        assert_eq!(promoted.status, 200);
        assert_eq!(promoted.headers, cached.headers);
        assert_eq!(promoted.body, cached.body);
        assert_eq!(promoted.cached_at, 20);
        assert_eq!(promoted.ttl_secs, 50);
    }

    #[test]
    fn metadata_written_before_header_persistence_remains_readable() {
        let old_record = r#"{
            "created_at":{"secs_since_epoch":1,"nanos_since_epoch":0},
            "expires_at":{"secs_since_epoch":2,"nanos_since_epoch":0},
            "content_type":"text/plain",
            "vary_fingerprint":null,
            "size":4,
            "status":200
        }"#;

        let metadata: ReserveMetadata = serde_json::from_str(old_record).expect("old metadata");

        assert!(metadata.headers.is_empty());
    }
}
