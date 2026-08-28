//! Per-id revocation denylist.
//!
//! A CoMP `quote_id` lands on this denylist when an operator revokes
//! it before redeem. The denylist row has a TTL bounded by the
//! quote's remaining validity window
//! ([`crate::comp::COMP_QUOTE_VALIDITY_SECS`]), so the storage cost
//! stays negligible even at high revocation rates.
//!
//! This module exposes the [`crate::revocation::Revocation`] trait
//! plus an in-memory adapter and a storage-trait-backed adapter
//! ([`crate::revocation::RedisRevocation`])
//! that composes with any [`sbproxy_storage::EphemeralKv`] backend
//! (Redis, mesh, in-memory). Single-host deployments use the
//! in-memory adapter; multi-host deployments wire a storage trait so
//! revocations propagate cross-process. Per the epic's no-external-
//! store rule, the in-memory adapter is the default and the Redis
//! adapter is opt-in.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use sbproxy_storage::EphemeralKv;

use crate::error::LicensingError;

/// Per-id revocation backend.
///
/// `is_revoked` is on the redeem hot path; backends should answer in
/// microseconds (in-memory hashmap, Redis `EXISTS`, or a bloom filter
/// that fronts the durable store).
#[async_trait]
pub trait Revocation: Send + Sync {
    /// Mark `id` revoked. `expires_at_unix` is the wall-clock second
    /// after which the entry can be swept; backends MUST honour the
    /// TTL so denylist storage stays bounded.
    async fn revoke(&self, id: &str, expires_at_unix: u64) -> Result<(), LicensingError>;

    /// Returns `true` if `id` is on the denylist and has not yet
    /// expired. Returns `false` for an unknown id or for an entry
    /// whose TTL has elapsed.
    async fn is_revoked(&self, id: &str) -> Result<bool, LicensingError>;
}

// --- In-memory adapter ---

/// In-memory revocation store. Suitable for single-host deployments
/// and unit tests. Sweeps expired entries on every `is_revoked` call;
/// the sweep is O(n) but n is bounded by the operator's revocation
/// rate over the quote-validity window.
///
/// A poisoned denylist is recovered with
/// [`PoisonError::into_inner`] rather than unwrapped. The guarded
/// state is a plain `id -> expiry` map whose every write is a single
/// `insert` or `retain`, so a panic in another thread cannot leave a
/// half-written row: the map either holds the id or it does not.
/// Refusing every later redeem because one earlier request panicked
/// would be a worse failure than continuing to answer from the map
/// that survived.
#[derive(Default)]
pub struct InMemoryRevocation {
    entries: Mutex<HashMap<String, u64>>,
}

impl InMemoryRevocation {
    /// Build an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries currently held (including expired entries
    /// that have not been swept yet).
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

#[async_trait]
impl Revocation for InMemoryRevocation {
    async fn revoke(&self, id: &str, expires_at_unix: u64) -> Result<(), LicensingError> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.to_string(), expires_at_unix);
        Ok(())
    }

    async fn is_revoked(&self, id: &str) -> Result<bool, LicensingError> {
        let now = Self::now_unix();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        // Sweep expired entries lazily.
        entries.retain(|_, exp| *exp > now);
        Ok(entries.contains_key(id))
    }
}

// --- Storage-trait-backed adapter ---

/// Storage-trait-backed revocation store.
///
/// Accepts any [`Arc<dyn EphemeralKv>`] so deployments can back the
/// denylist with Redis, mesh, or the in-memory store, picked at
/// config time. Wire-level semantics: `revoke` writes a 1-byte
/// sentinel under `licensing:revoked:<id>` with the remaining TTL,
/// and `is_revoked` probes for key presence (Redis `EXISTS`,
/// in-memory `contains_key`).
pub struct RedisRevocation {
    kv: Arc<dyn EphemeralKv>,
    key_prefix: String,
}

impl RedisRevocation {
    /// Build a revocation store from a Redis URL. Internally
    /// constructs a [`sbproxy_storage::RedisStore`] and wraps it in an
    /// `Arc<dyn EphemeralKv>`. Deployments that already hold an
    /// `EphemeralKv` from their bootstrap should reach for
    /// [`Self::with_storage`] instead.
    pub fn new(url: &str) -> Result<Self, LicensingError> {
        use sbproxy_storage::RedisStore;
        let store = RedisStore::new(url, "licensing".to_string())
            .map_err(|e| LicensingError::RevocationBackend(format!("redis open: {e}")))?;
        Ok(Self {
            kv: Arc::new(store),
            key_prefix: "licensing:revoked".into(),
        })
    }

    /// Build a revocation store from any [`EphemeralKv`] backend.
    /// Bootstrap code that already owns an `Arc<dyn EphemeralKv>`
    /// should use this rather than passing a URL through [`Self::new`].
    pub fn with_storage(kv: Arc<dyn EphemeralKv>) -> Self {
        Self {
            kv,
            key_prefix: "licensing:revoked".into(),
        }
    }

    /// Override the key prefix. Defaults to `licensing:revoked`. The
    /// prefix is folded into every `EphemeralKv` key the adapter
    /// issues.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    fn key(&self, id: &str) -> String {
        format!("{}:{}", self.key_prefix, id)
    }
}

#[async_trait]
impl Revocation for RedisRevocation {
    async fn revoke(&self, id: &str, expires_at_unix: u64) -> Result<(), LicensingError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let ttl_secs = expires_at_unix.saturating_sub(now);
        // Skip writes for already-expired entries; the key would be
        // immediately swept anyway and Redis SETEX rejects ttl == 0.
        if ttl_secs == 0 {
            return Ok(());
        }
        let key = self.key(id);
        // 1-byte sentinel; the value is never read, only key presence
        // is consulted via `exists`.
        let value = Bytes::from_static(&[1u8]);
        self.kv
            .put(&key, value, Duration::from_secs(ttl_secs))
            .await
            .map_err(|e| LicensingError::RevocationBackend(format!("kv put: {e}")))?;
        Ok(())
    }

    async fn is_revoked(&self, id: &str) -> Result<bool, LicensingError> {
        let key = self.key(id);
        self.kv
            .exists(&key)
            .await
            .map_err(|e| LicensingError::RevocationBackend(format!("kv exists: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_storage::mock::MockEphemeralKv;

    #[tokio::test]
    async fn revoked_entry_round_trips() {
        let r = InMemoryRevocation::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        r.revoke("quote-1", now + 600).await.unwrap();
        assert!(r.is_revoked("quote-1").await.unwrap());
        assert!(!r.is_revoked("quote-2").await.unwrap());
    }

    #[tokio::test]
    async fn expired_entry_sweeps() {
        let r = InMemoryRevocation::new();
        // Set expiry in the past so the sweep removes it immediately.
        r.revoke("quote-old", 1).await.unwrap();
        assert!(!r.is_revoked("quote-old").await.unwrap());
        assert_eq!(r.len(), 0);
    }

    #[tokio::test]
    async fn redis_revocation_round_trips_via_ephemeral_kv() {
        let kv = MockEphemeralKv::new();
        let kv_arc: Arc<dyn EphemeralKv> = Arc::new(kv.clone());
        let r = RedisRevocation::with_storage(kv_arc);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        r.revoke("quote-A", now + 600).await.unwrap();
        assert!(r.is_revoked("quote-A").await.unwrap());
        assert!(!r.is_revoked("quote-B").await.unwrap());
        // Two `is_revoked` probes -> two `exists` calls (the
        // override, not the `get` fallback).
        assert_eq!(kv.exists_call_count(), 2);
    }

    #[tokio::test]
    async fn redis_revocation_skips_already_expired_writes() {
        // expires_at in the past -> ttl = 0 -> no write issued.
        let kv = MockEphemeralKv::new();
        let kv_arc: Arc<dyn EphemeralKv> = Arc::new(kv.clone());
        let r = RedisRevocation::with_storage(kv_arc);
        r.revoke("quote-stale", 1).await.unwrap();
        assert!(!r.is_revoked("quote-stale").await.unwrap());
    }

    #[tokio::test]
    async fn redis_revocation_with_prefix_is_namespaced() {
        let kv = MockEphemeralKv::new();
        let kv_arc: Arc<dyn EphemeralKv> = Arc::new(kv.clone());
        let r = RedisRevocation::with_storage(kv_arc).with_prefix("custom:revoked");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        r.revoke("quote-Z", now + 60).await.unwrap();
        assert!(r.is_revoked("quote-Z").await.unwrap());
    }
}
