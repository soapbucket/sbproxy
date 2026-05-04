//! Cache Reserve composer: a long-term cold tier composed under a hot
//! `CacheStore`.
//!
//! Wraps two stores. On `get` the reserve is consulted only after the
//! primary misses; on a reserve hit the entry is optionally promoted
//! back into the primary so subsequent requests serve from the hot
//! path. On `put` the entry always lands in the primary; writes to
//! the reserve are gated by an admission filter (`min_size_bytes`)
//! and a sampling rate so cold-only one-offs don't churn through the
//! larger backing store.
//!
//! Mirrors the Cloudflare "Cache Reserve" pattern. OSS pairs an
//! in-memory primary with a `FileCacheStore` reserve; enterprise
//! builds layer an object-store-backed reserve over the same trait.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use parking_lot::Mutex;
use rand::Rng;

use crate::store::{CacheStore, CachedResponse};

/// Configuration for [`ReserveCacheStore`].
#[derive(Debug, Clone)]
pub struct ReserveConfig {
    /// 0.0 to 1.0 fraction of `put` calls that mirror to the reserve.
    /// `1.0` writes every entry; `0.05` writes one in twenty. The
    /// primary always sees every write regardless.
    pub sample_rate: f64,
    /// Skip mirroring entries whose body is smaller than this in
    /// bytes. Tiny payloads tend to dominate cold-tail traffic and
    /// rarely benefit from a long-term reserve. Set to `0` to
    /// disable the admission filter.
    pub min_size_bytes: usize,
    /// When `true`, a hit on the reserve populates the primary with
    /// the entry so subsequent reads serve from the hot tier.
    pub promote_on_hit: bool,
}

impl Default for ReserveConfig {
    fn default() -> Self {
        Self {
            sample_rate: 1.0,
            min_size_bytes: 0,
            promote_on_hit: true,
        }
    }
}

/// Counters surfaced for observability / Prometheus scrape.
#[derive(Debug, Default)]
pub struct ReserveStats {
    /// Reserve `get` calls that returned a value (i.e. primary miss
    /// rescued by the reserve).
    pub hits: AtomicU64,
    /// Reserve `get` calls that returned `None` after the primary
    /// already missed.
    pub misses: AtomicU64,
    /// Writes the primary admitted into the reserve (passed
    /// admission filter and sampling).
    pub writes: AtomicU64,
    /// Writes the admission filter dropped (too small or
    /// sample-skipped).
    pub admissions_dropped: AtomicU64,
}

impl ReserveStats {
    fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.writes.load(Ordering::Relaxed),
            self.admissions_dropped.load(Ordering::Relaxed),
        )
    }
}

/// Hot/cold composer: primary first, reserve as the cold tier.
pub struct ReserveCacheStore {
    primary: Arc<dyn CacheStore>,
    reserve: Arc<dyn CacheStore>,
    config: ReserveConfig,
    stats: Arc<ReserveStats>,
    /// Mutex around a `rand::rngs::SmallRng`; the sampler runs once
    /// per put, so contention is bounded by put-rate.
    rng: Mutex<rand::rngs::SmallRng>,
}

impl std::fmt::Debug for ReserveCacheStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (hits, misses, writes, dropped) = self.stats.snapshot();
        f.debug_struct("ReserveCacheStore")
            .field("config", &self.config)
            .field("hits", &hits)
            .field("misses", &misses)
            .field("writes", &writes)
            .field("admissions_dropped", &dropped)
            .finish()
    }
}

impl ReserveCacheStore {
    /// Build a composer.
    pub fn new(
        primary: Arc<dyn CacheStore>,
        reserve: Arc<dyn CacheStore>,
        config: ReserveConfig,
    ) -> Self {
        use rand::SeedableRng;
        Self {
            primary,
            reserve,
            config,
            stats: Arc::new(ReserveStats::default()),
            rng: Mutex::new(rand::rngs::SmallRng::from_entropy()),
        }
    }

    /// Snapshot the four counters: `(hits, misses, writes, admissions_dropped)`.
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        self.stats.snapshot()
    }

    /// Borrow the underlying stats handle. Useful when an external
    /// metrics exporter wants a stable handle.
    pub fn stats_handle(&self) -> Arc<ReserveStats> {
        Arc::clone(&self.stats)
    }

    fn admit(&self, value: &CachedResponse) -> bool {
        if value.body.len() < self.config.min_size_bytes {
            return false;
        }
        if self.config.sample_rate >= 1.0 {
            return true;
        }
        if self.config.sample_rate <= 0.0 {
            return false;
        }
        let mut rng = self.rng.lock();
        rng.gen::<f64>() < self.config.sample_rate
    }
}

impl CacheStore for ReserveCacheStore {
    fn get(&self, key: &str) -> Result<Option<CachedResponse>> {
        // Primary first. On a hit, never touch the reserve.
        if let Some(entry) = self.primary.get(key)? {
            return Ok(Some(entry));
        }
        // Primary missed. Consult the reserve.
        match self.reserve.get(key)? {
            Some(entry) => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                if self.config.promote_on_hit {
                    // Best-effort: a failed promotion does not change
                    // the answer the caller sees.
                    let _ = self.primary.put(key, &entry);
                }
                Ok(Some(entry))
            }
            None => {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                Ok(None)
            }
        }
    }

    fn put(&self, key: &str, value: &CachedResponse) -> Result<()> {
        self.primary.put(key, value)?;
        if self.admit(value) {
            self.stats.writes.fetch_add(1, Ordering::Relaxed);
            // A failed reserve write must not fail the put: the
            // primary already accepted the entry. Log for diagnostics
            // and move on.
            if let Err(e) = self.reserve.put(key, value) {
                tracing::warn!(error = %e, "cache reserve put failed; primary unaffected");
            }
        } else {
            self.stats
                .admissions_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let p = self.primary.delete(key);
        let r = self.reserve.delete(key);
        // Surface the first error; the second is best-effort.
        p.or(r)
    }

    fn clear(&self) -> Result<()> {
        let p = self.primary.clear();
        let r = self.reserve.clear();
        p.or(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryCacheStore;

    fn entry(body: &[u8], ttl: u64) -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![],
            body: body.to_vec(),
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ttl_secs: ttl,
        }
    }

    #[test]
    fn primary_hit_does_not_touch_reserve() {
        let primary: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
        let reserve: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
        let store = ReserveCacheStore::new(primary, reserve, ReserveConfig::default());
        store.put("a", &entry(b"hello world", 60)).unwrap();
        let _ = store.get("a").unwrap().unwrap();
        let (hits, misses, _writes, _) = store.stats();
        assert_eq!(hits, 0, "primary served the read; reserve untouched");
        assert_eq!(misses, 0);
    }

    #[test]
    fn reserve_serves_after_primary_eviction_and_promotes() {
        let primary: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
        let reserve: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
        let store = ReserveCacheStore::new(
            primary.clone(),
            reserve,
            ReserveConfig {
                promote_on_hit: true,
                ..ReserveConfig::default()
            },
        );
        let val = entry(b"hello world", 60);
        store.put("k1", &val).unwrap();
        // Simulate primary eviction by deleting from the primary
        // directly, leaving the entry only in the reserve.
        primary.delete("k1").unwrap();
        // Reserve hit: served, and promoted back into primary.
        let got = store.get("k1").unwrap().expect("reserve served");
        assert_eq!(got.body, b"hello world".to_vec());
        let (hits, misses, _, _) = store.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 0);
        // Promotion: primary now has the entry again.
        assert!(primary.get("k1").unwrap().is_some());
    }

    #[test]
    fn admission_filter_drops_small_payloads() {
        let primary: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
        let reserve: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
        let store = ReserveCacheStore::new(
            primary.clone(),
            reserve.clone(),
            ReserveConfig {
                sample_rate: 1.0,
                min_size_bytes: 1024,
                promote_on_hit: false,
            },
        );
        store.put("small", &entry(b"tiny", 60)).unwrap();
        store.put("big", &entry(&vec![b'x'; 2048], 60)).unwrap();
        // Both entries land in the primary.
        assert!(primary.get("small").unwrap().is_some());
        assert!(primary.get("big").unwrap().is_some());
        // Only the big one mirrors to the reserve.
        assert!(reserve.get("small").unwrap().is_none());
        assert!(reserve.get("big").unwrap().is_some());
        let (_, _, writes, dropped) = store.stats();
        assert_eq!(writes, 1);
        assert_eq!(dropped, 1);
    }

    #[test]
    fn sample_rate_zero_skips_all_reserve_writes() {
        let primary: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
        let reserve: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
        let store = ReserveCacheStore::new(
            primary,
            reserve.clone(),
            ReserveConfig {
                sample_rate: 0.0,
                min_size_bytes: 0,
                promote_on_hit: false,
            },
        );
        for i in 0..50 {
            store
                .put(&format!("k{i}"), &entry(b"some body", 60))
                .unwrap();
        }
        // Reserve received nothing.
        for i in 0..50 {
            assert!(reserve.get(&format!("k{i}")).unwrap().is_none());
        }
        let (_, _, writes, dropped) = store.stats();
        assert_eq!(writes, 0);
        assert_eq!(dropped, 50);
    }

    #[test]
    fn delete_removes_from_both_tiers() {
        let primary: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
        let reserve: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
        let store =
            ReserveCacheStore::new(primary.clone(), reserve.clone(), ReserveConfig::default());
        store.put("k", &entry(b"hello", 60)).unwrap();
        assert!(primary.get("k").unwrap().is_some());
        assert!(reserve.get("k").unwrap().is_some());
        store.delete("k").unwrap();
        assert!(primary.get("k").unwrap().is_none());
        assert!(reserve.get("k").unwrap().is_none());
    }
}
