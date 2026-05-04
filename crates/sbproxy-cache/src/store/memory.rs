//! In-memory CacheStore backed by DashMap for lock-free concurrent reads.
//!
//! The prior implementation used `Mutex<HashMap>` which serialised every
//! lookup, at ~15k rps this becomes the bottleneck for cache-hit scenarios
//! (P13/P14). DashMap shards internally so reads/writes on different keys
//! scale linearly with cores. See sbproxy-bench/docs/RUST_OPTIMIZATIONS.md A3.

use dashmap::DashMap;

use anyhow::Result;

use super::{CacheStore, CachedResponse};

/// Thread-safe in-memory cache store with entry count cap.
///
/// Expired entries are lazily removed on `get`. A `max_entries` of 0 means unlimited.
pub struct MemoryCacheStore {
    data: DashMap<String, CachedResponse>,
    max_entries: usize,
}

impl MemoryCacheStore {
    /// Create a new in-memory cache store. Pass 0 for unlimited entries.
    pub fn new(max_entries: usize) -> Self {
        Self {
            data: DashMap::new(),
            max_entries,
        }
    }
}

impl CacheStore for MemoryCacheStore {
    fn get(&self, key: &str) -> Result<Option<CachedResponse>> {
        // Clone the entry out so we drop the read guard before any write.
        let lookup = self.data.get(key).map(|e| (e.is_expired(), e.clone()));
        match lookup {
            Some((false, entry)) => Ok(Some(entry)),
            Some((true, _)) => {
                // Lazy expiry: stale entry is removed on access.
                self.data.remove(key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    fn get_including_expired(&self, key: &str) -> Result<Option<CachedResponse>> {
        // SWR path: read past TTL without evicting. The caller
        // checks the SWR window before serving the stale value.
        Ok(self.data.get(key).map(|e| e.clone()))
    }

    fn delete_prefix(&self, prefix: &str) -> Result<usize> {
        // Collect first to avoid holding shard guards during remove.
        let to_remove: Vec<String> = self
            .data
            .iter()
            .filter(|e| e.key().starts_with(prefix))
            .map(|e| e.key().clone())
            .collect();
        let n = to_remove.len();
        for k in to_remove {
            self.data.remove(&k);
        }
        Ok(n)
    }

    fn put(&self, key: &str, value: &CachedResponse) -> Result<()> {
        // Evict an arbitrary entry if at capacity and inserting a new key.
        // DashMap's len() iterates shards but is O(shards), not O(entries).
        if self.max_entries > 0
            && !self.data.contains_key(key)
            && self.data.len() >= self.max_entries
        {
            // The iterator holds a read lock on whichever shard it
            // landed on. We must drop the iterator (and its returned
            // RefMulti) BEFORE calling `remove`, otherwise a
            // same-shard remove deadlocks against our own read guard.
            // Collect into an owned String inside its own scope so
            // both temporaries are dropped before we proceed.
            let evict_key: Option<String> = {
                let mut iter = self.data.iter();
                iter.next().map(|e| e.key().clone())
            };
            if let Some(k) = evict_key {
                self.data.remove(&k);
            }
        }

        self.data.insert(key.to_string(), value.clone());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.data.remove(key);
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        self.data.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_entry(ttl_secs: u64) -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"hello".to_vec(),
            cached_at: now_secs(),
            ttl_secs,
        }
    }

    #[test]
    fn test_put_get_delete_clear() {
        let store = MemoryCacheStore::new(0);

        // Missing key returns None.
        assert!(store.get("k1").unwrap().is_none());

        // Put and get.
        let entry = make_entry(300);
        store.put("k1", &entry).unwrap();
        let got = store.get("k1").unwrap().unwrap();
        assert_eq!(got.status, 200);
        assert_eq!(got.body, b"hello");

        // Delete.
        store.delete("k1").unwrap();
        assert!(store.get("k1").unwrap().is_none());

        // Clear.
        store.put("a", &make_entry(300)).unwrap();
        store.put("b", &make_entry(300)).unwrap();
        store.clear().unwrap();
        assert!(store.get("a").unwrap().is_none());
        assert!(store.get("b").unwrap().is_none());
    }

    #[test]
    fn test_expired_entry_returns_none() {
        let store = MemoryCacheStore::new(0);

        // Entry that expired 10 seconds ago.
        let entry = CachedResponse {
            status: 200,
            headers: vec![],
            body: vec![],
            cached_at: now_secs().saturating_sub(100),
            ttl_secs: 1,
        };
        store.put("expired", &entry).unwrap();
        assert!(store.get("expired").unwrap().is_none());
    }

    #[test]
    fn test_max_entries() {
        let store = MemoryCacheStore::new(2);
        store.put("k1", &make_entry(300)).unwrap();
        store.put("k2", &make_entry(300)).unwrap();

        // Third insert should evict one entry.
        store.put("k3", &make_entry(300)).unwrap();

        assert_eq!(store.data.len(), 2);
        assert!(store.data.contains_key("k3"));
    }

    #[test]
    fn test_delete_prefix_removes_matching_entries() {
        let store = MemoryCacheStore::new(0);
        store
            .put("ws:host:GET:/users/42:a=1:fp1", &make_entry(300))
            .unwrap();
        store
            .put("ws:host:GET:/users/42::fp2", &make_entry(300))
            .unwrap();
        store
            .put("ws:host:GET:/users/99::fp1", &make_entry(300))
            .unwrap();
        store.put("other:key", &make_entry(300)).unwrap();

        let removed = store.delete_prefix("ws:host:GET:/users/42:").unwrap();
        assert_eq!(removed, 2);
        assert!(store
            .get("ws:host:GET:/users/42:a=1:fp1")
            .unwrap()
            .is_none());
        assert!(store.get("ws:host:GET:/users/42::fp2").unwrap().is_none());
        assert!(store.get("ws:host:GET:/users/99::fp1").unwrap().is_some());
        assert!(store.get("other:key").unwrap().is_some());
    }

    #[test]
    fn test_get_including_expired_returns_stale() {
        let store = MemoryCacheStore::new(0);
        let stale = CachedResponse {
            status: 200,
            headers: vec![],
            body: b"stale".to_vec(),
            cached_at: now_secs().saturating_sub(500),
            ttl_secs: 60,
        };
        store.put("k", &stale).unwrap();
        assert!(store.get("k").unwrap().is_none(), "live get evicts stale");
        // Need to put again because get evicted it.
        store.put("k", &stale).unwrap();
        let got = store.get_including_expired("k").unwrap();
        assert!(
            got.is_some(),
            "get_including_expired must return stale entry"
        );
        assert_eq!(got.unwrap().body, b"stale");
    }

    #[test]
    fn test_overwrite_no_eviction() {
        let store = MemoryCacheStore::new(2);
        store.put("k1", &make_entry(300)).unwrap();
        store.put("k2", &make_entry(300)).unwrap();

        // Overwriting existing key should not evict.
        let updated = CachedResponse {
            status: 404,
            headers: vec![],
            body: b"not found".to_vec(),
            cached_at: now_secs(),
            ttl_secs: 60,
        };
        store.put("k1", &updated).unwrap();

        assert_eq!(store.data.len(), 2);
        assert_eq!(store.data.get("k1").unwrap().status, 404);
    }
}
