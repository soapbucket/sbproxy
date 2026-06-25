//! Fail-closed TTL cache in front of a [`KeyStore`].
//!
//! Per-request key resolution must be fast and must not hammer the store, so a
//! small in-memory cache (L1) sits in front of it with a configurable TTL
//! (default 60s). The cache is the operator's requested "configurable in-memory
//! policy cache". An optional second tier ([`CacheTier`], for example Redis or
//! the mesh distributed cache) is consulted between L1 and the store.
//!
//! Resolution order on an L1 miss: L2 tier (if any) -> store. A positive result
//! is cached in L1 (and pushed to L2); a known-absent result is negatively
//! cached for a shorter window so a flood of unknown keys cannot stampede the
//! store. A store error is never cached.
//!
//! Fail-closed: when the store cannot be reached, [`TtlCache::resolve_key`]
//! returns `Err`. The caller maps that to a denial when [`TtlCacheConfig::fail_closed`]
//! is set (the default); only an operator who explicitly opted into
//! `failure_mode_allow` treats an unreachable store as allow.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::record::{CredentialRecord, KeyRecord};
use crate::KeyStore;

/// Tunables for the [`TtlCache`].
#[derive(Debug, Clone)]
pub struct TtlCacheConfig {
    /// How long a positive (found) entry stays fresh.
    pub ttl: Duration,
    /// How long a negative (known-absent) entry stays fresh. Kept short so a
    /// stream of unknown keys cannot stampede the store, but long enough to
    /// absorb a burst.
    pub negative_ttl: Duration,
    /// Soft cap on entries per map; over it, expired entries are purged and then
    /// the least-recently-used entry is evicted.
    pub max_entries: usize,
    /// When the store is unreachable, deny (the default). Set false only via an
    /// explicit `failure_mode_allow`.
    pub fail_closed: bool,
}

impl Default for TtlCacheConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(60),
            negative_ttl: Duration::from_secs(5),
            max_entries: 10_000,
            fail_closed: true,
        }
    }
}

/// An optional second cache tier (Redis, mesh distributed cache). Best-effort:
/// every method swallows its own errors and a miss simply falls through to the
/// store. The store, not the tier, is the source of truth.
#[async_trait]
pub trait CacheTier: Send + Sync {
    /// Look up a key record in the tier.
    async fn get_key(&self, key_id: &str) -> Option<KeyRecord>;
    /// Publish a key record to the tier.
    async fn put_key(&self, record: &KeyRecord, ttl: Duration);
    /// Look up a credential record in the tier.
    async fn get_credential(&self, id: &str) -> Option<CredentialRecord>;
    /// Publish a credential record to the tier.
    async fn put_credential(&self, record: &CredentialRecord, ttl: Duration);
    /// Drop a single id from the tier (key or credential).
    async fn invalidate(&self, id: &str);
    /// Drop everything from the tier.
    async fn invalidate_all(&self);
}

struct Entry<V> {
    /// `None` is a negatively cached "known absent".
    value: Option<V>,
    expires_at: Instant,
    stamp: u64,
}

/// A fail-closed TTL cache wrapping a [`KeyStore`].
pub struct TtlCache {
    store: Arc<dyn KeyStore>,
    tier: Option<Arc<dyn CacheTier>>,
    keys: Mutex<HashMap<String, Entry<KeyRecord>>>,
    creds: Mutex<HashMap<String, Entry<CredentialRecord>>>,
    cfg: TtlCacheConfig,
    stamp: AtomicU64,
}

impl TtlCache {
    /// Wrap `store` with the given config and no second tier.
    pub fn new(store: Arc<dyn KeyStore>, cfg: TtlCacheConfig) -> Self {
        Self {
            store,
            tier: None,
            keys: Mutex::new(HashMap::new()),
            creds: Mutex::new(HashMap::new()),
            cfg,
            stamp: AtomicU64::new(0),
        }
    }

    /// Attach a second cache tier (consulted between L1 and the store).
    pub fn with_tier(mut self, tier: Arc<dyn CacheTier>) -> Self {
        self.tier = Some(tier);
        self
    }

    /// The wrapped store. Admin mutations go through the store, then call
    /// [`Self::invalidate`] so the next resolve reloads.
    pub fn store(&self) -> &Arc<dyn KeyStore> {
        &self.store
    }

    /// Whether the cache is configured to fail closed (deny) on store errors.
    pub fn fail_closed(&self) -> bool {
        self.cfg.fail_closed
    }

    fn next_stamp(&self) -> u64 {
        self.stamp.fetch_add(1, Ordering::Relaxed)
    }

    /// Resolve a key record by its public `key_id`, going L1 -> L2 -> store.
    /// `Ok(None)` means the key is genuinely absent; `Err` means the store
    /// could not be reached (the caller fails closed).
    pub async fn resolve_key(&self, key_id: &str) -> Result<Option<KeyRecord>> {
        let now = Instant::now();
        // L1.
        if let Some(hit) = self.peek_key(key_id, now) {
            return Ok(hit);
        }
        // L2.
        if let Some(tier) = &self.tier {
            if let Some(rec) = tier.get_key(key_id).await {
                self.insert_key(key_id, Some(rec.clone()), now);
                return Ok(Some(rec));
            }
        }
        // Store.
        let loaded = self.store.get_key(key_id).await?;
        self.insert_key(key_id, loaded.clone(), now);
        if let (Some(tier), Some(rec)) = (&self.tier, loaded.as_ref()) {
            tier.put_key(rec, self.cfg.ttl).await;
        }
        Ok(loaded)
    }

    /// Resolve a credential record by id, going L1 -> L2 -> store.
    pub async fn resolve_credential(&self, id: &str) -> Result<Option<CredentialRecord>> {
        let now = Instant::now();
        if let Some(hit) = self.peek_credential(id, now) {
            return Ok(hit);
        }
        if let Some(tier) = &self.tier {
            if let Some(rec) = tier.get_credential(id).await {
                self.insert_credential(id, Some(rec.clone()), now);
                return Ok(Some(rec));
            }
        }
        let loaded = self.store.get_credential(id).await?;
        self.insert_credential(id, loaded.clone(), now);
        if let (Some(tier), Some(rec)) = (&self.tier, loaded.as_ref()) {
            tier.put_credential(rec, self.cfg.ttl).await;
        }
        Ok(loaded)
    }

    /// Drop a single id from L1 and the tier. Call after any mutation of that
    /// id so the next resolve reflects it immediately (instant revoke).
    pub async fn invalidate(&self, id: &str) {
        self.keys.lock().remove(id);
        self.creds.lock().remove(id);
        if let Some(tier) = &self.tier {
            tier.invalidate(id).await;
        }
    }

    /// Drop everything from L1 and the tier.
    pub async fn invalidate_all(&self) {
        self.keys.lock().clear();
        self.creds.lock().clear();
        if let Some(tier) = &self.tier {
            tier.invalidate_all().await;
        }
    }

    /// L1 lookup. Returns `Some(value)` (possibly a negatively cached `None`)
    /// when a fresh entry exists, or `None` when there is no fresh entry.
    fn peek_key(&self, key_id: &str, now: Instant) -> Option<Option<KeyRecord>> {
        let mut map = self.keys.lock();
        match map.get_mut(key_id) {
            Some(entry) if entry.expires_at > now => {
                entry.stamp = self.next_stamp();
                Some(entry.value.clone())
            }
            _ => None,
        }
    }

    fn peek_credential(&self, id: &str, now: Instant) -> Option<Option<CredentialRecord>> {
        let mut map = self.creds.lock();
        match map.get_mut(id) {
            Some(entry) if entry.expires_at > now => {
                entry.stamp = self.next_stamp();
                Some(entry.value.clone())
            }
            _ => None,
        }
    }

    fn insert_key(&self, key_id: &str, value: Option<KeyRecord>, now: Instant) {
        let ttl = if value.is_some() {
            self.cfg.ttl
        } else {
            self.cfg.negative_ttl
        };
        let entry = Entry {
            value,
            expires_at: now + ttl,
            stamp: self.next_stamp(),
        };
        let mut map = self.keys.lock();
        map.insert(key_id.to_string(), entry);
        evict_if_needed(&mut map, self.cfg.max_entries, now);
    }

    fn insert_credential(&self, id: &str, value: Option<CredentialRecord>, now: Instant) {
        let ttl = if value.is_some() {
            self.cfg.ttl
        } else {
            self.cfg.negative_ttl
        };
        let entry = Entry {
            value,
            expires_at: now + ttl,
            stamp: self.next_stamp(),
        };
        let mut map = self.creds.lock();
        map.insert(id.to_string(), entry);
        evict_if_needed(&mut map, self.cfg.max_entries, now);
    }
}

/// Enforce the soft cap: purge expired entries first, then evict the
/// least-recently-used (lowest stamp) until under the cap.
fn evict_if_needed<V>(map: &mut HashMap<String, Entry<V>>, max_entries: usize, now: Instant) {
    if map.len() <= max_entries {
        return;
    }
    map.retain(|_, e| e.expires_at > now);
    while map.len() > max_entries {
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, e)| e.stamp)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::KeyRecord;
    use crate::MemoryKeyStore;
    use chrono::{DateTime, Utc};

    fn ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    /// A store that counts how many times the underlying store was read, so we
    /// can assert the cache actually serves hits without touching the store.
    struct CountingStore {
        inner: MemoryKeyStore,
        key_loads: AtomicU64,
    }

    impl CountingStore {
        fn new() -> Self {
            Self {
                inner: MemoryKeyStore::new(),
                key_loads: AtomicU64::new(0),
            }
        }
        fn loads(&self) -> u64 {
            self.key_loads.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl KeyStore for CountingStore {
        async fn get_key(&self, key_id: &str) -> Result<Option<KeyRecord>> {
            self.key_loads.fetch_add(1, Ordering::Relaxed);
            self.inner.get_key(key_id).await
        }
        async fn list_keys(&self) -> Result<Vec<KeyRecord>> {
            self.inner.list_keys().await
        }
        async fn put_key(&self, record: KeyRecord) -> Result<()> {
            self.inner.put_key(record).await
        }
        async fn delete_key(&self, key_id: &str) -> Result<()> {
            self.inner.delete_key(key_id).await
        }
        async fn get_credential(&self, id: &str) -> Result<Option<CredentialRecord>> {
            self.inner.get_credential(id).await
        }
        async fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
            self.inner.list_credentials().await
        }
        async fn put_credential(&self, record: CredentialRecord) -> Result<()> {
            self.inner.put_credential(record).await
        }
        async fn delete_credential(&self, id: &str) -> Result<()> {
            self.inner.delete_credential(id).await
        }
        async fn revision(&self) -> Result<u64> {
            self.inner.revision().await
        }
    }

    /// A store that always errors, to exercise fail-closed behavior.
    struct BrokenStore;

    #[async_trait]
    impl KeyStore for BrokenStore {
        async fn get_key(&self, _: &str) -> Result<Option<KeyRecord>> {
            anyhow::bail!("store down")
        }
        async fn list_keys(&self) -> Result<Vec<KeyRecord>> {
            anyhow::bail!("store down")
        }
        async fn put_key(&self, _: KeyRecord) -> Result<()> {
            anyhow::bail!("store down")
        }
        async fn delete_key(&self, _: &str) -> Result<()> {
            anyhow::bail!("store down")
        }
        async fn get_credential(&self, _: &str) -> Result<Option<CredentialRecord>> {
            anyhow::bail!("store down")
        }
        async fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
            anyhow::bail!("store down")
        }
        async fn put_credential(&self, _: CredentialRecord) -> Result<()> {
            anyhow::bail!("store down")
        }
        async fn delete_credential(&self, _: &str) -> Result<()> {
            anyhow::bail!("store down")
        }
        async fn revision(&self) -> Result<u64> {
            anyhow::bail!("store down")
        }
    }

    #[tokio::test]
    async fn second_resolve_is_served_from_cache() {
        let store = Arc::new(CountingStore::new());
        store
            .put_key(KeyRecord::new("k1", "h", ts()))
            .await
            .unwrap();
        let cache = TtlCache::new(store.clone(), TtlCacheConfig::default());

        assert!(cache.resolve_key("k1").await.unwrap().is_some());
        assert!(cache.resolve_key("k1").await.unwrap().is_some());
        // Two resolves, one store load.
        assert_eq!(store.loads(), 1);
    }

    #[tokio::test]
    async fn invalidate_forces_reload() {
        let store = Arc::new(CountingStore::new());
        store
            .put_key(KeyRecord::new("k1", "h", ts()))
            .await
            .unwrap();
        let cache = TtlCache::new(store.clone(), TtlCacheConfig::default());

        cache.resolve_key("k1").await.unwrap();
        cache.invalidate("k1").await;
        cache.resolve_key("k1").await.unwrap();
        assert_eq!(store.loads(), 2, "invalidate forces a fresh store load");
    }

    #[tokio::test]
    async fn unknown_key_is_negatively_cached() {
        let store = Arc::new(CountingStore::new());
        let cache = TtlCache::new(store.clone(), TtlCacheConfig::default());

        assert!(cache.resolve_key("missing").await.unwrap().is_none());
        assert!(cache.resolve_key("missing").await.unwrap().is_none());
        assert_eq!(store.loads(), 1, "negative result is cached");
    }

    #[tokio::test]
    async fn expired_entry_reloads() {
        let store = Arc::new(CountingStore::new());
        store
            .put_key(KeyRecord::new("k1", "h", ts()))
            .await
            .unwrap();
        // Zero TTL => every lookup is stale and must reload.
        let cfg = TtlCacheConfig {
            ttl: Duration::from_secs(0),
            negative_ttl: Duration::from_secs(0),
            ..TtlCacheConfig::default()
        };
        let cache = TtlCache::new(store.clone(), cfg);
        cache.resolve_key("k1").await.unwrap();
        cache.resolve_key("k1").await.unwrap();
        assert_eq!(store.loads(), 2);
    }

    #[tokio::test]
    async fn fail_closed_propagates_store_error() {
        let cache = TtlCache::new(Arc::new(BrokenStore), TtlCacheConfig::default());
        assert!(cache.fail_closed());
        assert!(
            cache.resolve_key("k1").await.is_err(),
            "store error surfaces so the caller can deny"
        );
    }
}
