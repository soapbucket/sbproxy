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
//! Store errors are never swallowed: when the store cannot be reached,
//! [`TtlCache::resolve_key`] and [`TtlCache::resolve_credential`] return
//! `Err`. What that means for the request is not this cache's decision.
//! The caller owns it, reading `proxy.key_management.failure_posture`
//! through `KeyManagementConfig::failure_posture()`, and denies (503) or
//! falls through to the origin's configured auth accordingly.
//!
//! This module used to carry its own `fail_closed: bool` alongside that
//! posture, populated as `!failure_mode_allow`. It was one operator knob
//! spelled twice with opposite polarity, and only the other spelling was
//! ever consulted: nothing outside a test read it, and neither resolve
//! path branched on it. It is gone rather than migrated (WOR-2121). This
//! crate deliberately does not depend on `sbproxy-config`, so importing
//! the shared `FailureMode` here would drag the whole config schema into
//! a lean crate to hold a value it does not act on.

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
}

impl Default for TtlCacheConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(60),
            negative_ttl: Duration::from_secs(5),
            max_entries: 10_000,
        }
    }
}

/// An optional second cache tier (Redis, mesh distributed cache).
///
/// Lookups and publishes are best-effort: they swallow their own errors and a
/// miss falls through to the store, which is the source of truth.
///
/// Invalidation is not in that bucket, and used to be. A lookup that fails
/// best-effort is a cache miss; a revocation that fails best-effort is a
/// credential that every replica keeps accepting until the TTL lapses, while
/// the admin console reports it revoked. So the two invalidation methods
/// return `Result` and the caller decides. Returning `Ok` means the tier's
/// copy is gone and, where the tier broadcasts, that peers were told.
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
    ///
    /// # Errors
    ///
    /// Returns `Err` when the tier's copy may still be readable: the backend
    /// was unreachable, the delete failed, or a broadcast the tier owes its
    /// peers did not go out.
    async fn invalidate(&self, id: &str) -> Result<()>;
    /// Drop everything from the tier.
    ///
    /// # Errors
    ///
    /// Returns `Err` when any part of the purge did not land.
    async fn invalidate_all(&self) -> Result<()>;
}

struct Entry<V> {
    /// `None` is a negatively cached "known absent".
    value: Option<V>,
    expires_at: Instant,
    stamp: u64,
}

/// Which layer answered one [`TtlCache`] lookup, reported to the
/// [`LookupObserver`] with the record kind (`"key"` or `"credential"`)
/// as the first argument (WOR-2572).
///
/// The outcome vocabulary, a closed set the observer can rely on:
/// `"hit"` (fresh L1 record), `"negative_hit"` (fresh L1 known-absent),
/// `"tier_hit"` (the L2 tier answered), `"miss"` (the store was
/// consulted and answered, present or absent), `"error"` (the store was
/// consulted and could not answer). A `negative_hit` is a hit in cache
/// terms - it saved a store round trip - but it is not folded into
/// `hit`, because "we know it is absent" and "we have it" are different
/// answers and a stampede of unknown keys should be visible as itself.
pub type LookupObserver = fn(kind: &'static str, outcome: &'static str);

/// A TTL cache wrapping a [`KeyStore`] that never swallows a store error.
pub struct TtlCache {
    store: Arc<dyn KeyStore>,
    tier: Option<Arc<dyn CacheTier>>,
    keys: Mutex<HashMap<String, Entry<KeyRecord>>>,
    creds: Mutex<HashMap<String, Entry<CredentialRecord>>>,
    cfg: TtlCacheConfig,
    stamp: AtomicU64,
    /// Per-instance lookup observer (WOR-2572). A plain `fn` pointer and
    /// not a boxed closure, because the one production install site
    /// (`key_plane::build_cache`) feeds a Prometheus counter and this
    /// crate deliberately depends on no metrics stack; `None` (the
    /// default) costs one branch per lookup and nothing else.
    lookup_observer: Option<LookupObserver>,
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
            lookup_observer: None,
        }
    }

    /// Attach a second cache tier (consulted between L1 and the store).
    pub fn with_tier(mut self, tier: Arc<dyn CacheTier>) -> Self {
        self.tier = Some(tier);
        self
    }

    /// Attach a lookup observer, called once per [`Self::resolve_key`] /
    /// [`Self::resolve_credential`] with the record kind and which layer
    /// answered. See [`LookupObserver`] for the outcome vocabulary.
    pub fn with_lookup_observer(mut self, observer: LookupObserver) -> Self {
        self.lookup_observer = Some(observer);
        self
    }

    /// Report one lookup outcome to the observer, if one is attached.
    fn observe_lookup(&self, kind: &'static str, outcome: &'static str) {
        if let Some(observer) = self.lookup_observer {
            observer(kind, outcome);
        }
    }

    /// The wrapped store. Admin mutations go through the store, then call
    /// [`Self::invalidate`] so the next resolve reloads.
    pub fn store(&self) -> &Arc<dyn KeyStore> {
        &self.store
    }

    fn next_stamp(&self) -> u64 {
        self.stamp.fetch_add(1, Ordering::Relaxed)
    }

    /// Resolve a key record by its public `key_id`, going L1 -> L2 -> store.
    /// `Ok(None)` means the key is genuinely absent; `Err` means the store
    /// could not be reached. The caller decides what an unreachable store
    /// means for the request, from its configured failure posture.
    pub async fn resolve_key(&self, key_id: &str) -> Result<Option<KeyRecord>> {
        let now = Instant::now();
        // L1.
        if let Some(hit) = self.peek_key(key_id, now) {
            self.observe_lookup("key", if hit.is_some() { "hit" } else { "negative_hit" });
            return Ok(hit);
        }
        // L2.
        if let Some(tier) = &self.tier {
            if let Some(rec) = tier.get_key(key_id).await {
                self.observe_lookup("key", "tier_hit");
                self.insert_key(key_id, Some(rec.clone()), now);
                return Ok(Some(rec));
            }
        }
        // Store.
        let loaded = match self.store.get_key(key_id).await {
            Ok(loaded) => {
                self.observe_lookup("key", "miss");
                loaded
            }
            Err(error) => {
                self.observe_lookup("key", "error");
                return Err(error);
            }
        };
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
            self.observe_lookup(
                "credential",
                if hit.is_some() { "hit" } else { "negative_hit" },
            );
            return Ok(hit);
        }
        if let Some(tier) = &self.tier {
            if let Some(rec) = tier.get_credential(id).await {
                self.observe_lookup("credential", "tier_hit");
                self.insert_credential(id, Some(rec.clone()), now);
                return Ok(Some(rec));
            }
        }
        let loaded = match self.store.get_credential(id).await {
            Ok(loaded) => {
                self.observe_lookup("credential", "miss");
                loaded
            }
            Err(error) => {
                self.observe_lookup("credential", "error");
                return Err(error);
            }
        };
        self.insert_credential(id, loaded.clone(), now);
        if let (Some(tier), Some(rec)) = (&self.tier, loaded.as_ref()) {
            // Never publish a raw secret to the second tier. Every tier is a
            // shared surface: the mesh tier replicates into a node-wide
            // distributed cache that every peer can hold a copy of, and the
            // Redis tier writes to an external server outside this process
            // entirely. Serialising a `CredentialMaterial::Plaintext` record
            // would put the secret in both, in the clear, which is not
            // something the keystore ever agreed to.
            //
            // Skipping the publish needs no fallback: this tier is best-effort
            // by contract and a miss falls through to the store, which is the
            // system of record. The only cost is one store read per resolve for
            // config-seeded plaintext credentials, which are the discouraged
            // path anyway.
            //
            // L1 above is deliberately still populated. It is process-local
            // heap, and an attacker who can read it can already read whatever
            // key would have sealed it, so sealing it would buy nothing. See
            // the guardrail about not encrypting memory-only caches.
            // The record, not the field. `prev_material` is a second slot
            // that can hold plaintext after a rotation, and this guard
            // predates it (WOR-2567).
            if rec.carries_plaintext() {
                tracing::debug!(
                    credential_id = %rec.id,
                    "not publishing a plaintext credential to the second cache tier; \
                     resolves will read through to the keystore"
                );
            } else {
                tier.put_credential(rec, self.cfg.ttl).await;
            }
        }
        Ok(loaded)
    }

    /// Drop a single id from L1 and the tier. Call after any mutation of that
    /// id so the next resolve reflects it immediately (instant revoke).
    ///
    /// L1 is always cleared, including on the error path: this replica's own
    /// copy is the one thing that can always be dropped, and dropping it is
    /// strictly better than not.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the shared tier could not be told. The mutation
    /// itself already landed in the store, so this is not "the revoke
    /// failed": it is "the revoke has not reached the other replicas, and
    /// they will keep serving the old record until their TTL lapses". The
    /// caller has to surface that rather than report a clean revoke.
    pub async fn invalidate(&self, id: &str) -> Result<()> {
        self.keys.lock().remove(id);
        self.creds.lock().remove(id);
        match &self.tier {
            Some(tier) => tier.invalidate(id).await,
            None => Ok(()),
        }
    }

    /// Drop everything from L1 and the tier.
    ///
    /// # Errors
    ///
    /// As [`Self::invalidate`], for the whole cache rather than one id.
    pub async fn invalidate_all(&self) -> Result<()> {
        self.keys.lock().clear();
        self.creds.lock().clear();
        match &self.tier {
            Some(tier) => tier.invalidate_all().await,
            None => Ok(()),
        }
    }

    /// Drop a single id from L1 only, touching neither the shared tier nor
    /// any broadcast channel behind it.
    ///
    /// This is the *receiving* half of cross-replica invalidation, and it
    /// exists because the two halves are not the same operation.
    /// [`Self::invalidate`] is what the replica that made the mutation
    /// calls: it drops the local copy, deletes the shared tier's copy, and
    /// announces the id to every peer. A replica that is merely reacting to
    /// that announcement must do only the first of those three. If it
    /// announced in turn, every peer would answer the announcement with
    /// another announcement and the channel would sustain itself forever.
    pub fn invalidate_local(&self, id: &str) {
        self.keys.lock().remove(id);
        self.creds.lock().remove(id);
    }

    /// Drop everything from L1 only, touching neither the shared tier nor
    /// any broadcast channel behind it.
    ///
    /// Two callers, both of them reactive: the invalidation subscriber's
    /// resync on every (re)subscription, and a received "drop everything"
    /// sentinel. See [`Self::invalidate_local`] for why a reaction must not
    /// re-broadcast.
    pub fn invalidate_all_local(&self) {
        self.keys.lock().clear();
        self.creds.lock().clear();
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
    use crate::{KeyPolicyCasResult, MemoryKeyStore};
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
        async fn put_key_if_revision(
            &self,
            record: KeyRecord,
            expected_revision: u64,
        ) -> Result<KeyPolicyCasResult> {
            self.inner
                .put_key_if_revision(record, expected_revision)
                .await
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
        async fn put_key_if_revision(&self, _: KeyRecord, _: u64) -> Result<KeyPolicyCasResult> {
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
        cache
            .invalidate("k1")
            .await
            .expect("no tier attached, so nothing can fail");
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

    /// A store error always surfaces to the caller, on both resolve paths.
    ///
    /// This is the cache's whole contract around an unreachable store, and
    /// it holds no matter what the operator's failure posture is: the
    /// cache never decides admission, it only refuses to invent an answer.
    /// A silent `Ok(None)` here would be indistinguishable from "that key
    /// does not exist", which is a 401 rather than a 503 and would make an
    /// outage look like a bad credential.
    #[tokio::test]
    async fn store_error_propagates_to_the_caller_that_owns_the_decision() {
        let cache = TtlCache::new(Arc::new(BrokenStore), TtlCacheConfig::default());
        assert!(
            cache.resolve_key("k1").await.is_err(),
            "store error surfaces so the caller can apply its failure posture"
        );
        assert!(
            cache.resolve_credential("c1").await.is_err(),
            "the credential path surfaces the same error for the same reason"
        );
    }

    /// A tier that records every credential published to it, so a test can
    /// assert on what would have left the process.
    #[derive(Default)]
    struct RecordingTier {
        published: Mutex<Vec<CredentialRecord>>,
    }

    impl RecordingTier {
        fn published_ids(&self) -> Vec<String> {
            self.published
                .lock()
                .iter()
                .map(|record| record.id.clone())
                .collect()
        }
    }

    #[async_trait]
    impl CacheTier for RecordingTier {
        async fn get_key(&self, _: &str) -> Option<KeyRecord> {
            None
        }
        async fn put_key(&self, _: &KeyRecord, _: Duration) {}
        async fn get_credential(&self, _: &str) -> Option<CredentialRecord> {
            None
        }
        async fn put_credential(&self, record: &CredentialRecord, _: Duration) {
            self.published.lock().push(record.clone());
        }
        async fn invalidate(&self, _: &str) -> Result<()> {
            Ok(())
        }
        async fn invalidate_all(&self) -> Result<()> {
            Ok(())
        }
    }

    /// A tier that counts the calls that would have reached a shared,
    /// broadcasting backend. Nothing else about it matters.
    #[derive(Default)]
    struct CountingTier {
        invalidations: AtomicU64,
        full_invalidations: AtomicU64,
    }

    #[async_trait]
    impl CacheTier for CountingTier {
        async fn get_key(&self, _: &str) -> Option<KeyRecord> {
            None
        }
        async fn put_key(&self, _: &KeyRecord, _: Duration) {}
        async fn get_credential(&self, _: &str) -> Option<CredentialRecord> {
            None
        }
        async fn put_credential(&self, _: &CredentialRecord, _: Duration) {}
        async fn invalidate(&self, _: &str) -> Result<()> {
            self.invalidations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn invalidate_all(&self) -> Result<()> {
            self.full_invalidations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A tier whose invalidation always fails, standing in for an
    /// unreachable Redis or a mesh peer that will not answer.
    struct UnreachableTier;

    #[async_trait]
    impl CacheTier for UnreachableTier {
        async fn get_key(&self, _: &str) -> Option<KeyRecord> {
            None
        }
        async fn put_key(&self, _: &KeyRecord, _: Duration) {}
        async fn get_credential(&self, _: &str) -> Option<CredentialRecord> {
            None
        }
        async fn put_credential(&self, _: &CredentialRecord, _: Duration) {}
        async fn invalidate(&self, _: &str) -> Result<()> {
            anyhow::bail!("tier unreachable")
        }
        async fn invalidate_all(&self) -> Result<()> {
            anyhow::bail!("tier unreachable")
        }
    }

    /// The seam: `TtlCache::invalidate` reporting whether the shared tier
    /// was actually told.
    ///
    /// It used to return `()`, folding a failed revocation into the same
    /// best-effort bucket as a failed lookup. A failed lookup is a cache
    /// miss the store covers for. A failed revocation is a credential the
    /// rest of the fleet keeps accepting for a full TTL while the admin
    /// console reports it revoked, and nothing anywhere said so.
    #[tokio::test]
    async fn a_tier_that_could_not_be_told_is_reported_and_l1_is_still_dropped() {
        let store = Arc::new(MemoryKeyStore::new());
        store
            .put_key(KeyRecord::new("k1", "h1", ts()))
            .await
            .unwrap();
        let cache = TtlCache::new(store.clone(), TtlCacheConfig::default())
            .with_tier(Arc::new(UnreachableTier) as Arc<dyn CacheTier>);
        assert!(cache.resolve_key("k1").await.unwrap().is_some());

        store.delete_key("k1").await.unwrap();
        let outcome = cache.invalidate("k1").await;
        assert!(
            outcome.is_err(),
            "an invalidation the shared tier never received must not report success"
        );

        // The local copy goes regardless: this replica can always drop its
        // own entry, and doing so is strictly better than not.
        assert!(
            cache.resolve_key("k1").await.unwrap().is_none(),
            "L1 must be dropped even when the tier could not be reached"
        );

        assert!(
            cache.invalidate_all().await.is_err(),
            "the same holds for a whole-tier purge"
        );
    }

    /// A reaction to a peer's invalidation must not become another
    /// invalidation.
    ///
    /// The Redis tier's `invalidate` and `invalidate_all` both publish on
    /// the channel the subscriber is listening to. A subscriber that
    /// answered a received message by calling back into the tier would
    /// publish the message it just received, every peer would do the same
    /// with that one, and the channel would never go quiet: an endless
    /// storm at every boot and every reconnect. The local-only forms are
    /// what a receiver calls, and this pins that they reach nothing shared.
    #[tokio::test]
    async fn a_local_only_invalidation_clears_l1_and_never_touches_the_tier() {
        let store = Arc::new(MemoryKeyStore::new());
        store
            .put_key(KeyRecord::new("k1", "h1", ts()))
            .await
            .unwrap();
        store
            .put_key(KeyRecord::new("k2", "h2", ts()))
            .await
            .unwrap();
        let tier = Arc::new(CountingTier::default());
        let cache = TtlCache::new(store.clone(), TtlCacheConfig::default())
            .with_tier(tier.clone() as Arc<dyn CacheTier>);
        assert!(cache.resolve_key("k1").await.unwrap().is_some());
        assert!(cache.resolve_key("k2").await.unwrap().is_some());
        store.delete_key("k1").await.unwrap();
        store.delete_key("k2").await.unwrap();

        cache.invalidate_local("k1");
        assert!(
            cache.resolve_key("k1").await.unwrap().is_none(),
            "a local invalidation still drops the L1 entry"
        );
        assert!(
            cache.resolve_key("k2").await.unwrap().is_some(),
            "and drops only the one named"
        );

        cache.invalidate_all_local();
        assert!(
            cache.resolve_key("k2").await.unwrap().is_none(),
            "a local full invalidation still clears L1"
        );

        assert_eq!(
            tier.invalidations.load(Ordering::SeqCst),
            0,
            "a received invalidation must not be republished"
        );
        assert_eq!(
            tier.full_invalidations.load(Ordering::SeqCst),
            0,
            "a received drop-everything must not be republished"
        );

        // The originating forms still do reach the tier: local-only is the
        // receiver's operation, not a replacement for the mutator's.
        cache
            .invalidate("k1")
            .await
            .expect("the counting tier always succeeds");
        cache
            .invalidate_all()
            .await
            .expect("the counting tier always succeeds");
        assert_eq!(tier.invalidations.load(Ordering::SeqCst), 1);
        assert_eq!(tier.full_invalidations.load(Ordering::SeqCst), 1);
    }

    fn credential(id: &str, material: serde_json::Value) -> CredentialRecord {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": id,
            "material": material,
            "created_at": "2023-11-14T22:13:20Z",
            "updated_at": "2023-11-14T22:13:20Z"
        }))
        .expect("credential fixture")
    }

    /// A plaintext secret must never reach the second tier.
    ///
    /// The tier is a shared surface: the mesh tier replicates into a node-wide
    /// distributed cache and the Redis tier writes to an external server. A
    /// `CredentialMaterial::Plaintext` record serialized into either puts the
    /// raw secret somewhere the keystore never agreed to put it.
    #[tokio::test]
    async fn plaintext_credentials_are_never_published_to_the_second_tier() {
        let store = MemoryKeyStore::new();
        store
            .put_credential(credential(
                "sealed",
                serde_json::json!({"kind": "vault_ref", "reference": "vault://x"}),
            ))
            .await
            .expect("put vault_ref credential");
        store
            .put_credential(credential(
                "raw",
                serde_json::json!({"kind": "plaintext", "value": "sk-super-secret"}),
            ))
            .await
            .expect("put plaintext credential");

        let tier = Arc::new(RecordingTier::default());
        let cache = TtlCache::new(Arc::new(store), TtlCacheConfig::default())
            .with_tier(tier.clone() as Arc<dyn CacheTier>);

        // Both resolve correctly. Skipping the publish must not change what the
        // caller gets back, only where the record is allowed to travel.
        let sealed = cache
            .resolve_credential("sealed")
            .await
            .expect("resolve sealed")
            .expect("sealed present");
        assert!(!sealed.material.is_plaintext());
        let raw = cache
            .resolve_credential("raw")
            .await
            .expect("resolve raw")
            .expect("raw present");
        assert!(
            raw.material.is_plaintext(),
            "the caller still receives usable plaintext material"
        );

        assert_eq!(
            tier.published_ids(),
            vec!["sealed".to_string()],
            "only the non-plaintext credential may be published to the tier"
        );

        // And nothing resembling the secret was serialized into the tier.
        let published = tier.published.lock();
        let encoded = serde_json::to_string(&*published).expect("encode published records");
        assert!(
            !encoded.contains("sk-super-secret"),
            "the raw secret must not appear anywhere in what reached the tier: {encoded}"
        );
    }

    /// Seam M, replaced, half one: the enforcer, not the predicate.
    ///
    /// The original proof for the plaintext-slot defect asserted
    /// `carries_plaintext()` on a hand-built record and never drove one
    /// through either guard, so reverting this call site to
    /// `record.material.is_plaintext()` left it green. That is the same
    /// detector-narrower-than-the-enforcer shape the fix was written to
    /// close, one level up.
    ///
    /// This one puts a *rotated* record through the real second-tier
    /// publish: current material is a harmless vault reference, and the
    /// plaintext the rotation retired is sitting in `prev_material`. A
    /// guard reading only `material` sees nothing wrong and ships the
    /// secret to a shared surface.
    #[tokio::test]
    async fn a_rotated_records_retired_plaintext_never_reaches_the_second_tier() {
        let store = MemoryKeyStore::new();
        let mut rotated = credential(
            "rotated",
            serde_json::json!({"kind": "vault_ref", "reference": "vault://new"}),
        );
        rotated.prev_material = Some(crate::record::CredentialMaterial::Plaintext {
            value: "sk-retired-but-still-on-disk".to_string(),
        });
        rotated.prev_material_expires_at =
            Some(chrono::Utc::now() + chrono::Duration::try_seconds(300).expect("representable"));
        assert!(
            !rotated.material.is_plaintext(),
            "the current slot must look clean, or this test cannot tell the two guards apart"
        );
        store
            .put_credential(rotated)
            .await
            .expect("put rotated credential");

        let tier = Arc::new(RecordingTier::default());
        let cache = TtlCache::new(Arc::new(store), TtlCacheConfig::default())
            .with_tier(tier.clone() as Arc<dyn CacheTier>);

        let resolved = cache
            .resolve_credential("rotated")
            .await
            .expect("resolve rotated")
            .expect("rotated present");
        assert!(
            resolved.carries_plaintext(),
            "the caller still receives the whole record, overlap included"
        );

        assert!(
            tier.published_ids().is_empty(),
            "a record whose retired material is plaintext must not reach the tier: {:?}",
            tier.published_ids()
        );
        let published = tier.published.lock();
        let encoded = serde_json::to_string(&*published).expect("encode published records");
        assert!(
            !encoded.contains("sk-retired-but-still-on-disk"),
            "the retired secret must not appear anywhere in what reached the tier: {encoded}"
        );
    }

    /// WOR-2572: the lookup observer sees which layer answered, with the
    /// full outcome vocabulary, in the order the lookups happened. The
    /// observer is a per-instance `fn` pointer, so this test accumulates
    /// into its own static and no other test's cache can write here.
    #[tokio::test]
    async fn lookups_report_hit_negative_tier_miss_and_error_to_the_observer() {
        static EVENTS: Mutex<Vec<(&'static str, &'static str)>> = Mutex::new(Vec::new());
        fn observe(kind: &'static str, outcome: &'static str) {
            EVENTS.lock().push((kind, outcome));
        }
        fn drain() -> Vec<(&'static str, &'static str)> {
            std::mem::take(&mut *EVENTS.lock())
        }

        let store = Arc::new(CountingStore::new());
        store
            .put_key(KeyRecord::new("k1", "h", ts()))
            .await
            .unwrap();
        let cache =
            TtlCache::new(store.clone(), TtlCacheConfig::default()).with_lookup_observer(observe);

        // Store answers (present), then L1 answers.
        cache.resolve_key("k1").await.unwrap();
        cache.resolve_key("k1").await.unwrap();
        assert_eq!(drain(), vec![("key", "miss"), ("key", "hit")]);

        // Store answers (absent), then the negative cache answers. A
        // negative hit is reported as itself, never folded into `hit`.
        cache.resolve_key("missing").await.unwrap();
        cache.resolve_key("missing").await.unwrap();
        assert_eq!(drain(), vec![("key", "miss"), ("key", "negative_hit")]);

        // The credential path reports under its own kind.
        cache.resolve_credential("absent-cred").await.unwrap();
        assert_eq!(drain(), vec![("credential", "miss")]);

        // A tier answer is a tier_hit, not a miss: the store was never
        // consulted.
        struct AnsweringTier;
        #[async_trait]
        impl CacheTier for AnsweringTier {
            async fn get_key(&self, key_id: &str) -> Option<KeyRecord> {
                Some(KeyRecord::new(key_id, "h", ts()))
            }
            async fn put_key(&self, _: &KeyRecord, _: Duration) {}
            async fn get_credential(&self, _: &str) -> Option<CredentialRecord> {
                None
            }
            async fn put_credential(&self, _: &CredentialRecord, _: Duration) {}
            async fn invalidate(&self, _: &str) -> Result<()> {
                Ok(())
            }
            async fn invalidate_all(&self) -> Result<()> {
                Ok(())
            }
        }
        let tiered = TtlCache::new(store, TtlCacheConfig::default())
            .with_tier(Arc::new(AnsweringTier))
            .with_lookup_observer(observe);
        tiered.resolve_key("k2").await.unwrap();
        assert_eq!(drain(), vec![("key", "tier_hit")]);

        // An unreachable store is an error, not a miss, on both paths.
        let broken = TtlCache::new(Arc::new(BrokenStore), TtlCacheConfig::default())
            .with_lookup_observer(observe);
        broken.resolve_key("k3").await.unwrap_err();
        broken.resolve_credential("c3").await.unwrap_err();
        assert_eq!(drain(), vec![("key", "error"), ("credential", "error")]);
    }
}
