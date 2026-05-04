//! In-memory [`CacheReserveBackend`].
//!
//! Backed by a [`DashMap`]. Intended for tests and ephemeral
//! single-replica workloads; production deployments should pick the
//! filesystem or Redis backend (or an enterprise object-store
//! backend) so the reserve survives restarts.

use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;

use super::{CacheReserveBackend, ReserveMetadata};

/// In-memory reserve backend.
///
/// Cheap to clone (`Arc`-friendly via `Clone`); every clone shares the
/// same backing map.
#[derive(Default, Debug)]
pub struct MemoryReserve {
    inner: DashMap<String, (Bytes, ReserveMetadata)>,
}

impl MemoryReserve {
    /// Build a fresh empty reserve.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries currently held. Useful in tests.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when the reserve has no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[async_trait]
impl CacheReserveBackend for MemoryReserve {
    async fn put(&self, key: &str, value: Bytes, metadata: ReserveMetadata) -> anyhow::Result<()> {
        self.inner.insert(key.to_string(), (value, metadata));
        Ok(())
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<(Bytes, ReserveMetadata)>> {
        Ok(self.inner.get(key).map(|e| e.value().clone()))
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.inner.remove(key);
        Ok(())
    }

    async fn evict_expired(&self, before: SystemTime) -> anyhow::Result<u64> {
        let mut removed = 0u64;
        // Collect first to avoid holding shard locks across the
        // remove(); DashMap allows concurrent reads, but the point of
        // a sweep is precisely to drop everything older than `before`
        // without blocking the request path.
        let stale: Vec<String> = self
            .inner
            .iter()
            .filter_map(|e| {
                if e.value().1.expires_at < before {
                    Some(e.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for k in stale {
            if self.inner.remove(&k).is_some() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn meta(now: SystemTime, ttl: Duration, size: u64) -> ReserveMetadata {
        ReserveMetadata {
            created_at: now,
            expires_at: now + ttl,
            content_type: Some("text/plain".to_string()),
            vary_fingerprint: None,
            size,
            status: 200,
        }
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let r = MemoryReserve::new();
        let body = Bytes::from_static(b"hello");
        r.put(
            "k",
            body.clone(),
            meta(SystemTime::now(), Duration::from_secs(60), 5),
        )
        .await
        .unwrap();
        let (got, m) = r.get("k").await.unwrap().expect("hit");
        assert_eq!(got, body);
        assert_eq!(m.size, 5);
        assert_eq!(m.status, 200);
    }

    #[tokio::test]
    async fn missing_key_returns_none() {
        let r = MemoryReserve::new();
        assert!(r.get("absent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_clears_entry() {
        let r = MemoryReserve::new();
        r.put(
            "k",
            Bytes::from_static(b"x"),
            meta(SystemTime::now(), Duration::from_secs(60), 1),
        )
        .await
        .unwrap();
        r.delete("k").await.unwrap();
        assert!(r.get("k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn evict_expired_drops_old_entries() {
        let r = MemoryReserve::new();
        let base = SystemTime::now();
        // entry expires immediately
        r.put(
            "old",
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
        r.put(
            "fresh",
            Bytes::from_static(b"f"),
            meta(base, Duration::from_secs(60), 1),
        )
        .await
        .unwrap();

        let removed = r.evict_expired(base).await.unwrap();
        assert_eq!(removed, 1);
        assert!(r.get("old").await.unwrap().is_none());
        assert!(r.get("fresh").await.unwrap().is_some());
    }
}
