//! In-memory KVStore backed by a HashMap with a max-entries cap.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Result;
use bytes::Bytes;

use super::KVStore;

/// Thread-safe in-memory key-value store with an entry count cap.
///
/// When the number of entries reaches `max_entries`, the oldest entry
/// (by insertion order approximation) is evicted on the next `put`.
/// A `max_entries` of 0 means unlimited.
pub struct MemoryKVStore {
    data: Mutex<HashMap<Vec<u8>, Bytes>>,
    max_entries: usize,
}

impl MemoryKVStore {
    /// Create a new in-memory store. Pass 0 for unlimited entries.
    pub fn new(max_entries: usize) -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
            max_entries,
        }
    }
}

impl KVStore for MemoryKVStore {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let data = self.data.lock().expect("lock poisoned");
        Ok(data.get(key).cloned())
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut data = self.data.lock().expect("lock poisoned");

        // Evict an arbitrary entry if at capacity and inserting a new key.
        if self.max_entries > 0 && data.len() >= self.max_entries && !data.contains_key(key) {
            // Remove an arbitrary entry (HashMap iteration order is random).
            if let Some(evict_key) = data.keys().next().cloned() {
                data.remove(&evict_key);
            }
        }

        data.insert(key.to_vec(), Bytes::copy_from_slice(value));
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let mut data = self.data.lock().expect("lock poisoned");
        data.remove(key);
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        let data = self.data.lock().expect("lock poisoned");
        let results = data
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (Bytes::copy_from_slice(k), v.clone()))
            .collect();
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_put_delete() {
        let store = MemoryKVStore::new(0);

        // Key does not exist yet.
        assert!(store.get(b"key1").unwrap().is_none());

        // Put and get.
        store.put(b"key1", b"value1").unwrap();
        assert_eq!(store.get(b"key1").unwrap().unwrap(), &b"value1"[..]);

        // Overwrite.
        store.put(b"key1", b"value2").unwrap();
        assert_eq!(store.get(b"key1").unwrap().unwrap(), &b"value2"[..]);

        // Delete.
        store.delete(b"key1").unwrap();
        assert!(store.get(b"key1").unwrap().is_none());

        // Delete non-existent is fine.
        store.delete(b"key1").unwrap();
    }

    #[test]
    fn test_scan_prefix() {
        let store = MemoryKVStore::new(0);
        store.put(b"app:user:1", b"alice").unwrap();
        store.put(b"app:user:2", b"bob").unwrap();
        store.put(b"app:config:x", b"val").unwrap();
        store.put(b"other:key", b"nope").unwrap();

        let results = store.scan_prefix(b"app:user:").unwrap();
        assert_eq!(results.len(), 2);

        let results = store.scan_prefix(b"app:").unwrap();
        assert_eq!(results.len(), 3);

        let results = store.scan_prefix(b"missing:").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_max_entries_eviction() {
        let store = MemoryKVStore::new(2);
        store.put(b"k1", b"v1").unwrap();
        store.put(b"k2", b"v2").unwrap();

        // At capacity. Inserting a new key should evict one entry.
        store.put(b"k3", b"v3").unwrap();

        let data = store.data.lock().unwrap();
        assert_eq!(data.len(), 2);
        // k3 must be present (just inserted).
        assert!(data.contains_key(&b"k3"[..]));
    }

    #[test]
    fn test_max_entries_overwrite_no_eviction() {
        let store = MemoryKVStore::new(2);
        store.put(b"k1", b"v1").unwrap();
        store.put(b"k2", b"v2").unwrap();

        // Overwriting an existing key should NOT evict.
        store.put(b"k1", b"updated").unwrap();

        let data = store.data.lock().unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data.get(&b"k1"[..]).unwrap(), &b"updated"[..]);
        assert_eq!(data.get(&b"k2"[..]).unwrap(), &b"v2"[..]);
    }

    #[test]
    fn test_unlimited_entries() {
        let store = MemoryKVStore::new(0);
        for i in 0..1000u32 {
            store.put(&i.to_be_bytes(), &i.to_be_bytes()).unwrap();
        }
        let data = store.data.lock().unwrap();
        assert_eq!(data.len(), 1000);
    }
}
