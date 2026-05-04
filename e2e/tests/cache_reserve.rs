//! End-to-end coverage for the Cache Reserve cold tier.
//!
//! These tests exercise the [`CacheReserveBackend`] trait directly
//! against the in-process [`MemoryReserve`] backend. The OSS request
//! pipeline calls into the trait through the same `put` / `get` /
//! `delete` surface, so tests at this level cover the user-visible
//! contract without requiring a live filesystem or Redis.
//!
//! The four cases below mirror the documented behaviour in
//! `docs/cache-reserve.md`:
//!   1. Hot miss + reserve miss yields the origin path (no reserve hit).
//!   2. Hot miss + reserve hit returns the reserved body, marks
//!      `X-Cache: HIT-RESERVE`, and promotes back into the hot tier.
//!   3. Hot eviction admits the entry into the reserve at sample_rate
//!      = 1.0; subsequent hot miss is rescued by the reserve.
//!   4. Oversize objects are skipped from the reserve regardless of
//!      sample rate.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use sbproxy_cache::{
    CacheReserveBackend, CacheStore, CachedResponse, MemoryCacheStore, MemoryReserve,
    ReserveMetadata,
};

// --- Test helpers ---

fn metadata_for(body_len: u64, ttl: Duration) -> ReserveMetadata {
    let now = SystemTime::now();
    ReserveMetadata {
        created_at: now,
        expires_at: now + ttl,
        content_type: Some("application/json".to_string()),
        vary_fingerprint: None,
        size: body_len,
        status: 200,
    }
}

/// Mirror the admission gates the request path applies before
/// writing into the reserve. Kept here as a test shim instead of
/// re-exporting `crate::pipeline::ReserveAdmission` so the e2e crate
/// only depends on the public cache surface.
struct TestAdmission {
    sample_rate: f64,
    min_ttl: u64,
    max_size_bytes: u64,
}

impl TestAdmission {
    fn admits(&self, ttl_secs: u64, body_len: usize) -> bool {
        if ttl_secs < self.min_ttl {
            return false;
        }
        if self.max_size_bytes > 0 && (body_len as u64) > self.max_size_bytes {
            return false;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }
        if self.sample_rate < 1.0 {
            return rand::random::<f64>() < self.sample_rate;
        }
        true
    }
}

// --- Test 1: cold start ---

#[tokio::test]
async fn hot_miss_and_reserve_miss_falls_through_to_origin() {
    let hot: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
    let reserve: Arc<dyn CacheReserveBackend> = Arc::new(MemoryReserve::new());

    // Hot miss.
    assert!(hot.get("/api").unwrap().is_none(), "hot must be empty");
    // Reserve miss.
    assert!(
        reserve.get("/api").await.unwrap().is_none(),
        "reserve must be empty"
    );
    // No fallback path here; the request handler would now go to
    // origin. The point of this test is the pre-condition: with
    // both tiers empty, no surprise data is produced.
}

// --- Test 2: reserve hit promotes into hot tier ---

#[tokio::test]
async fn reserve_hit_returns_body_and_promotes_to_hot() {
    let hot: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
    let reserve: Arc<dyn CacheReserveBackend> = Arc::new(MemoryReserve::new());

    // Pre-populate the reserve with an entry that the hot tier has
    // never seen (the canonical "primary evicted, only reserve has
    // it" state).
    let body = Bytes::from_static(b"reserved-body");
    let meta = metadata_for(body.len() as u64, Duration::from_secs(3600));
    reserve
        .put("/api/long-tail", body.clone(), meta.clone())
        .await
        .unwrap();

    // Hot miss.
    assert!(hot.get("/api/long-tail").unwrap().is_none());

    // Simulate the request path: hot miss => reserve get => promote
    // to hot => serve with x-sbproxy-cache: HIT-RESERVE.
    let (got_body, got_meta) = reserve
        .get("/api/long-tail")
        .await
        .unwrap()
        .expect("reserve hit");
    assert_eq!(got_body, body);
    assert_eq!(got_meta.status, 200);
    assert!(!got_meta.is_expired(SystemTime::now()));

    // Promotion: write into hot.
    let cached = CachedResponse {
        status: got_meta.status,
        headers: vec![],
        body: got_body.to_vec(),
        cached_at: SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ttl_secs: 3600,
    };
    hot.put("/api/long-tail", &cached).unwrap();

    // Subsequent read: hot hit, no reserve round-trip needed.
    let promoted = hot.get("/api/long-tail").unwrap().expect("promoted");
    assert_eq!(promoted.body, b"reserved-body".to_vec());
    assert_eq!(promoted.status, 200);
}

// --- Test 3: hot eviction admits to reserve, next miss is reserve-rescued ---

#[tokio::test]
async fn evicted_hot_entry_is_admitted_and_recovered_from_reserve() {
    let hot: Arc<dyn CacheStore> = Arc::new(MemoryCacheStore::new(16));
    let reserve: Arc<dyn CacheReserveBackend> = Arc::new(MemoryReserve::new());
    let admission = TestAdmission {
        sample_rate: 1.0,
        min_ttl: 60,
        max_size_bytes: 1_048_576,
    };

    // Hot put + admission to reserve.
    let body = Bytes::from_static(b"will-survive-eviction");
    let cached = CachedResponse {
        status: 200,
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body: body.to_vec(),
        cached_at: SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ttl_secs: 3600,
    };
    hot.put("/api/keep", &cached).unwrap();

    // Mirror to reserve (admitted: passes TTL floor and size cap).
    assert!(admission.admits(cached.ttl_secs, cached.body.len()));
    let meta = ReserveMetadata {
        created_at: SystemTime::now(),
        expires_at: SystemTime::now() + Duration::from_secs(cached.ttl_secs),
        content_type: Some("text/plain".to_string()),
        vary_fingerprint: None,
        size: cached.body.len() as u64,
        status: cached.status,
    };
    reserve.put("/api/keep", body.clone(), meta).await.unwrap();

    // Simulate hot eviction (LRU pressure or TTL-exhaustion path).
    hot.delete("/api/keep").unwrap();
    assert!(hot.get("/api/keep").unwrap().is_none());

    // Subsequent request: hot miss, reserve hit.
    let (rescued, rescued_meta) = reserve
        .get("/api/keep")
        .await
        .unwrap()
        .expect("reserve must have it");
    assert_eq!(rescued, body);
    assert_eq!(rescued_meta.content_type.as_deref(), Some("text/plain"));
}

// --- Test 4: oversize objects skip the reserve ---

#[tokio::test]
async fn oversize_object_is_skipped_from_reserve() {
    let reserve: Arc<dyn CacheReserveBackend> = Arc::new(MemoryReserve::new());
    let admission = TestAdmission {
        sample_rate: 1.0,
        min_ttl: 60,
        max_size_bytes: 1024,
    };

    // 2 KiB body: above the 1 KiB cap. The admission gate must
    // reject before any reserve I/O happens.
    let big_body = vec![b'X'; 2048];
    let small_body = vec![b'x'; 256];

    assert!(
        !admission.admits(3600, big_body.len()),
        "oversize must be rejected"
    );
    assert!(
        admission.admits(3600, small_body.len()),
        "small body must be admitted"
    );

    // Drive the trait: only small writes reach the reserve.
    reserve
        .put(
            "/api/small",
            Bytes::from(small_body.clone()),
            metadata_for(small_body.len() as u64, Duration::from_secs(3600)),
        )
        .await
        .unwrap();
    // (the oversize body would have been gated out by `admission`
    // before this call, so we don't even attempt the put).
    assert!(reserve.get("/api/small").await.unwrap().is_some());
    assert!(reserve.get("/api/big").await.unwrap().is_none());
}

// --- Test 5: short-TTL items are skipped by min_ttl gate ---

#[tokio::test]
async fn short_ttl_entry_is_skipped_from_reserve() {
    let admission = TestAdmission {
        sample_rate: 1.0,
        min_ttl: 3600,
        max_size_bytes: 1_048_576,
    };
    // Below the floor: 60 < 3600.
    assert!(!admission.admits(60, 1024));
    // Equal to the floor: admitted.
    assert!(admission.admits(3600, 1024));
}

// --- Test 6: sample_rate = 0 admits nothing ---

#[tokio::test]
async fn sample_rate_zero_skips_all_admission() {
    let admission = TestAdmission {
        sample_rate: 0.0,
        min_ttl: 60,
        max_size_bytes: 1_048_576,
    };
    for _ in 0..50 {
        assert!(
            !admission.admits(3600, 1024),
            "sample_rate=0 must reject every roll"
        );
    }
}

// --- Test 7: expired reserve metadata is treated as a miss ---

#[tokio::test]
async fn expired_reserve_metadata_reads_as_miss() {
    let reserve: Arc<dyn CacheReserveBackend> = Arc::new(MemoryReserve::new());
    let body = Bytes::from_static(b"old");
    let now = SystemTime::now();
    // Already expired.
    let meta = ReserveMetadata {
        created_at: now - Duration::from_secs(120),
        expires_at: now - Duration::from_secs(60),
        content_type: None,
        vary_fingerprint: None,
        size: body.len() as u64,
        status: 200,
    };
    reserve.put("/api/expired", body, meta).await.unwrap();

    // The trait `get` returns the entry; the request path itself
    // checks `is_expired()` and treats expired entries as misses.
    let (_, m) = reserve
        .get("/api/expired")
        .await
        .unwrap()
        .expect("trait still returns expired entries");
    assert!(
        m.is_expired(SystemTime::now()),
        "metadata must report expired"
    );
}

// --- Test 8: invalidate on mutation removes reserve entry ---

#[tokio::test]
async fn delete_clears_reserve_entry() {
    let reserve: Arc<dyn CacheReserveBackend> = Arc::new(MemoryReserve::new());
    reserve
        .put(
            "/api/users/42",
            Bytes::from_static(b"user-42"),
            metadata_for(7, Duration::from_secs(3600)),
        )
        .await
        .unwrap();
    assert!(reserve.get("/api/users/42").await.unwrap().is_some());

    // POST /api/users/42 path: the request handler calls
    // `reserve.delete(canonical_key)`.
    reserve.delete("/api/users/42").await.unwrap();
    assert!(reserve.get("/api/users/42").await.unwrap().is_none());
}

// --- Test 9: evict_expired sweeps stale entries ---

#[tokio::test]
async fn evict_expired_sweeps_stale_entries() {
    let reserve: Arc<dyn CacheReserveBackend> = Arc::new(MemoryReserve::new());
    let base = SystemTime::now();
    // expired
    reserve
        .put(
            "/old",
            Bytes::from_static(b"o"),
            ReserveMetadata {
                created_at: base - Duration::from_secs(120),
                expires_at: base - Duration::from_secs(60),
                content_type: None,
                vary_fingerprint: None,
                size: 1,
                status: 200,
            },
        )
        .await
        .unwrap();
    // fresh
    reserve
        .put(
            "/fresh",
            Bytes::from_static(b"f"),
            metadata_for(1, Duration::from_secs(60)),
        )
        .await
        .unwrap();

    let removed = reserve.evict_expired(base).await.unwrap();
    assert_eq!(removed, 1, "exactly one expired entry should be removed");
    assert!(reserve.get("/old").await.unwrap().is_none());
    assert!(reserve.get("/fresh").await.unwrap().is_some());
}
