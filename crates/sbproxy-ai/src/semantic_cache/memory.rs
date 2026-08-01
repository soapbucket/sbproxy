//! Process-local LRU semantic-cache backend.
//!
//! This backend deliberately preserves the behavior existing memory
//! deployments already have. It ignores the locality-sensitive hashing bucket
//! indexes entirely and scans every live entry in the requested namespace, so
//! adding distributed backends does not reduce the recall of a configuration
//! that never asked for one. Locality-sensitive hashing narrows candidates
//! only for Redis and mesh.
//!
//! Eviction is LRU on the generated entry key. Entries past their expiry are
//! removed lazily during lookup and when statistics are taken.

use std::sync::Arc;

use lru::LruCache;
use parking_lot::Mutex;

use super::config::SemanticCacheBackend;
use super::identity::{semantic_entry_key, SemanticNamespace};
use super::store::{
    select_exact_hit, system_semantic_clock, SemanticCacheStore, SemanticClock,
    SemanticHealthState, SemanticPurgeReport, SemanticPurgeScope, SemanticStoreCounters,
    SemanticStoreError, SemanticStoreHealth, SemanticStoreLookup, SemanticStoreLookupQuery,
    SemanticStoreStats, SemanticStoreWrite, StoredSemanticEntry,
};

/// Guarded LRU state of the memory backend.
struct MemoryState {
    entries: LruCache<String, Arc<StoredSemanticEntry>>,
}

/// Full-scan LRU semantic-cache backend.
pub struct MemorySemanticCacheStore {
    state: Mutex<MemoryState>,
    counters: SemanticStoreCounters,
    clock: Arc<dyn SemanticClock>,
    capacity: usize,
}

impl std::fmt::Debug for MemorySemanticCacheStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemorySemanticCacheStore")
            .field("backend", &SemanticCacheBackend::Memory)
            .field("capacity", &self.capacity)
            .field("entries", &self.state.lock().entries.len())
            .field("counters", &self.counters)
            .finish()
    }
}

impl MemorySemanticCacheStore {
    /// Build a memory backend with the operator's LRU capacity.
    ///
    /// A capacity of zero is clamped to one so the cache is always usable.
    pub fn new(max_entries: usize) -> Self {
        Self::build(max_entries, system_semantic_clock())
    }

    /// Build a memory backend driven by an injected clock.
    ///
    /// Reserved for tests that need deterministic expiry. Production code
    /// uses [`MemorySemanticCacheStore::new`].
    #[cfg(test)]
    pub fn with_clock(max_entries: usize, clock: Arc<dyn SemanticClock>) -> Self {
        Self::build(max_entries, clock)
    }

    fn build(max_entries: usize, clock: Arc<dyn SemanticClock>) -> Self {
        let capacity = max_entries.max(1);
        let bound = std::num::NonZeroUsize::new(capacity).expect("capacity clamped to at least 1");
        Self {
            state: Mutex::new(MemoryState {
                entries: LruCache::new(bound),
            }),
            counters: SemanticStoreCounters::default(),
            clock,
            capacity,
        }
    }

    /// Drop every entry past its expiry and report how many were in
    /// `namespace`.
    fn remove_expired(
        state: &mut MemoryState,
        now_unix_ms: u64,
        namespace: Option<&SemanticNamespace>,
    ) -> u64 {
        let mut expired_keys: Vec<String> = Vec::new();
        let mut in_namespace = 0u64;
        for (key, entry) in state.entries.iter() {
            if entry.expires_at_unix_ms <= now_unix_ms {
                expired_keys.push(key.clone());
                if namespace.is_some_and(|wanted| &entry.namespace == wanted) {
                    in_namespace += 1;
                }
            }
        }
        for key in &expired_keys {
            state.entries.pop(key);
        }
        in_namespace
    }

    /// Collect the generated keys covered by one purge scope.
    fn scoped_keys(state: &MemoryState, scope: &SemanticPurgeScope) -> Vec<String> {
        state
            .entries
            .iter()
            .filter(|(_, entry)| match scope {
                SemanticPurgeScope::All => true,
                SemanticPurgeScope::Origin { origin_digest } => {
                    entry.namespace.origin_digest() == *origin_digest
                }
                SemanticPurgeScope::Namespace { namespace } => &entry.namespace == namespace,
                SemanticPurgeScope::Entry {
                    namespace,
                    prompt_digest,
                } => &entry.namespace == namespace && &entry.prompt_digest == prompt_digest,
            })
            .map(|(key, _)| key.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl SemanticCacheStore for MemorySemanticCacheStore {
    fn backend(&self) -> SemanticCacheBackend {
        SemanticCacheBackend::Memory
    }

    async fn lookup(
        &self,
        query: &SemanticStoreLookupQuery,
    ) -> Result<SemanticStoreLookup, SemanticStoreError> {
        let now = self.clock.now_unix_ms();
        let mut state = self.state.lock();
        let expired = Self::remove_expired(&mut state, now, Some(&query.namespace));

        // The full same-namespace scan is the point of this backend: the
        // bucket indexes in the query are deliberately unused so a near
        // vector in a different bucket is still found.
        let selected = select_exact_hit(
            &query.embedding,
            state
                .entries
                .iter()
                .filter(|(_, entry)| entry.namespace == query.namespace)
                .map(|(_, entry)| entry),
            query.threshold,
            &query.namespace,
            now,
        );
        let mut result = match selected {
            Ok(result) => result,
            Err(_) => {
                drop(state);
                self.counters.record_candidate_read(false);
                return Err(SemanticStoreError::InvalidState);
            }
        };
        result.expired = result.expired.saturating_add(expired);
        result.rejected = result.rejected.saturating_add(expired);

        if let Some(hit) = result.exact_hit.as_ref() {
            // `get` marks the winning entry most recently used.
            let key = semantic_entry_key(&hit.entry.namespace, &hit.entry.prompt_digest);
            let _ = state.entries.get(&key);
        }
        drop(state);

        self.counters.record_candidate_read(true);
        self.counters.record_rejected(result.rejected);
        Ok(result)
    }

    async fn put(&self, write: &SemanticStoreWrite) -> Result<(), SemanticStoreError> {
        if write.entry.expires_at_unix_ms <= write.entry.stored_at_unix_ms
            || write.entry.embedding.is_empty()
            || write.entry.embedding.iter().any(|v| !v.is_finite())
        {
            self.counters.record_write(false);
            return Err(SemanticStoreError::InvalidWrite);
        }
        self.state
            .lock()
            .entries
            .put(write.keys.entry_key.clone(), Arc::clone(&write.entry));
        self.counters.record_write(true);
        Ok(())
    }

    async fn purge(
        &self,
        scope: &SemanticPurgeScope,
    ) -> Result<SemanticPurgeReport, SemanticStoreError> {
        let removed = {
            let mut state = self.state.lock();
            if matches!(scope, SemanticPurgeScope::All) {
                let removed = state.entries.len() as u64;
                state.entries.clear();
                removed
            } else {
                let keys = Self::scoped_keys(&state, scope);
                for key in &keys {
                    state.entries.pop(key);
                }
                keys.len() as u64
            }
        };
        let report = SemanticPurgeReport {
            removed,
            nodes_attempted: 1,
            nodes_failed: 0,
            complete: true,
        };
        self.counters.record_purge(&report);
        Ok(report)
    }

    async fn health(&self) -> SemanticStoreHealth {
        SemanticStoreHealth {
            backend: SemanticCacheBackend::Memory,
            state: SemanticHealthState::Healthy,
            reason: None,
        }
    }

    fn stats(&self) -> SemanticStoreStats {
        let live = {
            let mut state = self.state.lock();
            let now = self.clock.now_unix_ms();
            Self::remove_expired(&mut state, now, None);
            state.entries.len()
        };
        self.counters.snapshot(Some(live))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_cache::store::contract::{
        assert_semantic_store_contract, contract_entry, contract_keys, contract_namespace,
        CONTRACT_MAX_PER_BUCKET,
    };
    use crate::semantic_cache::store::{normalize_semantic_vector, SystemSemanticClock};

    /// Clock the tests advance by hand.
    struct FixedClock(std::sync::atomic::AtomicU64);

    impl FixedClock {
        fn new(now_unix_ms: u64) -> Self {
            Self(std::sync::atomic::AtomicU64::new(now_unix_ms))
        }

        fn advance(&self, millis: u64) {
            self.0
                .fetch_add(millis, std::sync::atomic::Ordering::Relaxed);
        }
    }

    impl SemanticClock for FixedClock {
        fn now_unix_ms(&self) -> u64 {
            self.0.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    async fn put(
        store: &MemorySemanticCacheStore,
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
        body: &str,
        stored_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) {
        let write = SemanticStoreWrite {
            entry: contract_entry(
                namespace,
                prompt,
                embedding,
                body,
                stored_at_unix_ms,
                expires_at_unix_ms,
            ),
            keys: contract_keys(namespace, prompt, embedding),
            ttl_secs: 600,
            maximum_per_bucket: CONTRACT_MAX_PER_BUCKET,
        };
        store.put(&write).await.expect("write is accepted");
    }

    async fn lookup(
        store: &MemorySemanticCacheStore,
        namespace: &SemanticNamespace,
        prompt: &str,
        embedding: &[f32],
        threshold: f32,
    ) -> SemanticStoreLookup {
        let query = SemanticStoreLookupQuery {
            namespace: namespace.clone(),
            keys: contract_keys(namespace, prompt, embedding),
            embedding: Arc::from(
                normalize_semantic_vector(embedding)
                    .expect("fixture normalizes")
                    .as_slice(),
            ),
            threshold,
            maximum_per_bucket: CONTRACT_MAX_PER_BUCKET,
        };
        store.lookup(&query).await.expect("lookup answers")
    }

    #[tokio::test]
    async fn memory_satisfies_the_common_store_contract() {
        let store: Arc<dyn SemanticCacheStore> = Arc::new(MemorySemanticCacheStore::new(64));
        assert_semantic_store_contract(store).await;
    }

    #[tokio::test]
    async fn near_vector_in_a_different_lsh_bucket_is_still_a_memory_hit() {
        let store = MemorySemanticCacheStore::new(16);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let now = SystemSemanticClock.now_unix_ms();
        // Deliberately index the record under an unrelated vector's buckets.
        // Memory must ignore those buckets and still find the near vector.
        let write = SemanticStoreWrite {
            entry: contract_entry(
                &namespace,
                "refund policy",
                &[1.0, 1.0, 0.0],
                "photosynthesis",
                now,
                now + 600_000,
            ),
            keys: contract_keys(&namespace, "refund policy", &[0.0, 0.0, 1.0]),
            ttl_secs: 600,
            maximum_per_bucket: CONTRACT_MAX_PER_BUCKET,
        };
        store.put(&write).await.expect("write is accepted");
        let result = lookup(&store, &namespace, "refund policy", &[1.0, 0.9, 0.05], 0.9).await;
        assert!(
            result.exact_hit.is_some(),
            "memory must not narrow candidates by bucket"
        );
    }

    #[tokio::test]
    async fn lru_access_refreshes_recency() {
        let store = MemorySemanticCacheStore::new(2);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let now = SystemSemanticClock.now_unix_ms();
        let expires = now + 600_000;
        put(&store, &namespace, "a", &[1.0, 0.0, 0.0], "a", now, expires).await;
        put(&store, &namespace, "b", &[0.0, 1.0, 0.0], "b", now, expires).await;
        // Touch "a" so "b" becomes least recently used.
        assert!(lookup(&store, &namespace, "a", &[1.0, 0.0, 0.0], 0.99)
            .await
            .exact_hit
            .is_some());
        put(&store, &namespace, "c", &[0.0, 0.0, 1.0], "c", now, expires).await;
        assert!(lookup(&store, &namespace, "a", &[1.0, 0.0, 0.0], 0.99)
            .await
            .exact_hit
            .is_some());
        assert!(lookup(&store, &namespace, "b", &[0.0, 1.0, 0.0], 0.99)
            .await
            .exact_hit
            .is_none());
    }

    #[tokio::test]
    async fn insert_at_capacity_evicts_the_least_recently_used_logical_entry() {
        let store = MemorySemanticCacheStore::new(2);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let now = SystemSemanticClock.now_unix_ms();
        let expires = now + 600_000;
        put(&store, &namespace, "a", &[1.0, 0.0, 0.0], "a", now, expires).await;
        put(&store, &namespace, "b", &[0.0, 1.0, 0.0], "b", now, expires).await;
        put(&store, &namespace, "c", &[0.0, 0.0, 1.0], "c", now, expires).await;
        assert!(lookup(&store, &namespace, "a", &[1.0, 0.0, 0.0], 0.99)
            .await
            .exact_hit
            .is_none());
        assert!(lookup(&store, &namespace, "c", &[0.0, 0.0, 1.0], 0.99)
            .await
            .exact_hit
            .is_some());
    }

    #[tokio::test]
    async fn eviction_removes_every_index_reference() {
        let store = MemorySemanticCacheStore::new(1);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let now = SystemSemanticClock.now_unix_ms();
        let expires = now + 600_000;
        put(&store, &namespace, "a", &[1.0, 0.0, 0.0], "a", now, expires).await;
        put(&store, &namespace, "b", &[0.0, 1.0, 0.0], "b", now, expires).await;
        assert_eq!(store.stats().local_entries, Some(1));
        let evicted = lookup(&store, &namespace, "a", &[1.0, 0.0, 0.0], 0.99).await;
        assert!(evicted.exact_hit.is_none());
        assert_eq!(evicted.rejected, 0, "an evicted key leaves no stale index");
    }

    #[tokio::test]
    async fn expired_entries_are_removed_lazily() {
        let clock = Arc::new(FixedClock::new(1_000_000));
        let store = MemorySemanticCacheStore::with_clock(16, clock.clone());
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        put(
            &store,
            &namespace,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "cached",
            1_000_000,
            1_060_000,
        )
        .await;
        assert!(
            lookup(&store, &namespace, "refund policy", &[1.0, 0.0, 0.0], 0.99)
                .await
                .exact_hit
                .is_some()
        );
        clock.advance(120_000);
        let after = lookup(&store, &namespace, "refund policy", &[1.0, 0.0, 0.0], 0.99).await;
        assert!(after.exact_hit.is_none());
        assert_eq!(after.expired, 1);
        assert_eq!(after.rejected, 1);
        assert_eq!(store.stats().local_entries, Some(0));
    }

    #[tokio::test]
    async fn same_scope_full_scan_preserves_the_existing_nearest_vector_fixture() {
        let store = MemorySemanticCacheStore::new(16);
        let namespace = contract_namespace("tenant-secret-a", "origin-a.example");
        let now = SystemSemanticClock.now_unix_ms();
        let expires = now + 600_000;
        put(
            &store,
            &namespace,
            "photosynthesis",
            &[1.0, 1.0, 0.0],
            "photosynthesis",
            now,
            expires,
        )
        .await;
        // Near duplicate (cosine ~0.97) hits.
        assert!(lookup(&store, &namespace, "near", &[1.0, 0.9, 0.05], 0.9)
            .await
            .exact_hit
            .is_some());
        // Orthogonal vector misses after exact reranking.
        let miss = lookup(&store, &namespace, "far", &[0.0, 0.0, 1.0], 0.9).await;
        assert!(miss.exact_hit.is_none());
        assert!(miss.best_score.is_some(), "the near miss score is reported");
    }

    #[tokio::test]
    async fn cross_scope_entries_never_enter_exact_selection() {
        let store = MemorySemanticCacheStore::new(16);
        let mine = contract_namespace("tenant-secret-a", "origin-a.example");
        let theirs = contract_namespace("tenant-secret-b", "origin-a.example");
        let now = SystemSemanticClock.now_unix_ms();
        let expires = now + 600_000;
        put(
            &store,
            &mine,
            "refund policy",
            &[1.0, 0.0, 0.0],
            "secret-a",
            now,
            expires,
        )
        .await;
        assert!(
            lookup(&store, &mine, "refund policy", &[1.0, 0.0, 0.0], 0.99)
                .await
                .exact_hit
                .is_some()
        );
        let cross = lookup(&store, &theirs, "refund policy", &[1.0, 0.0, 0.0], 0.99).await;
        assert!(cross.exact_hit.is_none());
        assert_eq!(
            cross.incompatible, 0,
            "another tenant's entry is filtered, not reranked"
        );
    }

    #[tokio::test]
    async fn memory_purge_always_reports_one_complete_local_store() {
        let store = MemorySemanticCacheStore::new(16);
        let report = store
            .purge(&SemanticPurgeScope::All)
            .await
            .expect("purge answers");
        assert_eq!(report.nodes_attempted, 1);
        assert_eq!(report.nodes_failed, 0);
        assert!(report.complete);
    }

    #[test]
    fn memory_debug_reports_bounds_and_counts_only() {
        let store = MemorySemanticCacheStore::new(8);
        let rendered = format!("{store:?}");
        assert!(rendered.contains("capacity"));
        assert!(rendered.contains("entries"));
        for sentinel in ["tenant-secret-a", "refund policy", "sbproxy:semcache"] {
            assert!(!rendered.contains(sentinel));
        }
    }
}
