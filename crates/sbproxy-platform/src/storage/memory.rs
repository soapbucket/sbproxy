//! In-memory KVStore backed by a HashMap with a max-entries cap.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;

use super::KVStore;

/// One stored value and, when it was written with a TTL, the instant it
/// stops being readable.
#[derive(Clone)]
struct Entry {
    value: Bytes,
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_live(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|deadline| deadline > now)
    }
}

/// Thread-safe in-memory key-value store with an entry count cap.
///
/// When the number of entries reaches `max_entries`, the oldest entry
/// (by insertion order approximation) is evicted on the next `put`.
/// A `max_entries` of 0 means unlimited.
///
/// Uses `parking_lot::Mutex`, which is unpoisoned by design, so a panic
/// while a producer holds the lock cannot cascade into every subsequent
/// `get`/`put`/`delete` and turn one panic into a store-wide outage.
///
/// # TTLs
///
/// Every `*_with_ttl` write here honors its TTL, and a key past it
/// reads as absent and is takeable again. That used to be dropped on
/// the floor: `put_with_ttl` and `put_if_absent_with_ttl` both took
/// `_ttl_secs` and ignored it. The cost was not a leak but a blind
/// spot. This store is what every test of a TTL-shaped protocol runs
/// against, so no test anywhere in the workspace could observe a row
/// expiring, and the one whose expiry mattered most (an idempotency
/// claim, whose lease *is* the TTL on Redis) had its whole
/// lease-lapsed branch untested. Expiry is checked on read rather than
/// swept, so a key nobody reads again holds its memory until the
/// entry cap evicts it.
pub struct MemoryKVStore {
    data: Mutex<HashMap<Vec<u8>, Entry>>,
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

/// Absolute deadline for a TTL, or `None` when the caller passed zero.
fn deadline(ttl_secs: u64) -> Option<Instant> {
    if ttl_secs == 0 {
        return None;
    }
    Instant::now().checked_add(Duration::from_secs(ttl_secs))
}

impl KVStore for MemoryKVStore {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let now = Instant::now();
        let mut data = self.data.lock();
        match data.get(key) {
            Some(entry) if entry.is_live(now) => Ok(Some(entry.value.clone())),
            Some(_) => {
                // Read-side eviction: an expired row is gone, not
                // merely invisible, so the memory it holds is returned
                // on the first read past its deadline.
                data.remove(key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.insert(key, value, None)
    }

    fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl_secs: u64) -> Result<()> {
        self.insert(key, value, deadline(ttl_secs))
    }

    fn put_if_absent_with_ttl(&self, key: &[u8], value: &[u8], ttl_secs: u64) -> Result<bool> {
        // The whole check-and-insert happens under one lock, so two
        // threads racing the same absent key produce exactly one
        // creator. An expired key counts as absent: that is what makes
        // a lapsed lease takeable rather than permanent.
        let now = Instant::now();
        let mut data = self.data.lock();
        if data.get(key).is_some_and(|entry| entry.is_live(now)) {
            return Ok(false);
        }
        data.insert(
            key.to_vec(),
            Entry {
                value: Bytes::copy_from_slice(value),
                expires_at: deadline(ttl_secs),
            },
        );
        Ok(true)
    }

    fn compare_and_swap_with_ttl(
        &self,
        key: &[u8],
        expected: &[u8],
        value: &[u8],
        ttl_secs: u64,
    ) -> Result<bool> {
        let now = Instant::now();
        let mut data = self.data.lock();
        let matches = data
            .get(key)
            .is_some_and(|entry| entry.is_live(now) && entry.value.as_ref() == expected);
        if !matches {
            return Ok(false);
        }
        data.insert(
            key.to_vec(),
            Entry {
                value: Bytes::copy_from_slice(value),
                expires_at: deadline(ttl_secs),
            },
        );
        Ok(true)
    }

    fn supports_atomic_create(&self) -> bool {
        true
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let mut data = self.data.lock();
        data.remove(key);
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        let now = Instant::now();
        let data = self.data.lock();
        let results = data
            .iter()
            .filter(|(k, entry)| k.starts_with(prefix) && entry.is_live(now))
            .map(|(k, entry)| (Bytes::copy_from_slice(k), entry.value.clone()))
            .collect();
        Ok(results)
    }
}

impl MemoryKVStore {
    /// Insert under the entry cap, evicting one arbitrary key when the
    /// cap is reached and the incoming key is new.
    fn insert(&self, key: &[u8], value: &[u8], expires_at: Option<Instant>) -> Result<()> {
        let mut data = self.data.lock();

        // Evict an arbitrary entry if at capacity and inserting a new key.
        if self.max_entries > 0 && data.len() >= self.max_entries && !data.contains_key(key) {
            // Remove an arbitrary entry (HashMap iteration order is random).
            if let Some(evict_key) = data.keys().next().cloned() {
                data.remove(&evict_key);
            }
        }

        data.insert(
            key.to_vec(),
            Entry {
                value: Bytes::copy_from_slice(value),
                expires_at,
            },
        );
        Ok(())
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

        let data = store.data.lock();
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

        let data = store.data.lock();
        assert_eq!(data.len(), 2);
        assert_eq!(data.get(&b"k1"[..]).unwrap().value, &b"updated"[..]);
        assert_eq!(data.get(&b"k2"[..]).unwrap().value, &b"v2"[..]);
    }

    /// WOR-2609: `put_if_absent_with_ttl` is what single-flight rests
    /// on, and both halves of it were untested. The create half has to
    /// refuse the second caller; the TTL half has to let the key go, or
    /// a claim whose holder died wedges that key forever and every
    /// retry of it answers 409 for as long as the process lives.
    ///
    /// The TTL is a real second rather than a fake clock because this
    /// store has no clock to inject, and one second is the smallest
    /// value the seconds-valued trait method can express.
    #[test]
    fn put_if_absent_creates_once_and_lets_the_ttl_lapse() {
        let store = MemoryKVStore::new(0);

        assert!(
            store.put_if_absent_with_ttl(b"claim", b"first", 1).unwrap(),
            "the first caller must create the key"
        );
        assert!(
            !store
                .put_if_absent_with_ttl(b"claim", b"second", 1)
                .unwrap(),
            "a live key must refuse a second creator"
        );
        assert_eq!(store.get(b"claim").unwrap().unwrap(), &b"first"[..]);

        std::thread::sleep(Duration::from_millis(1_100));

        assert!(
            store.get(b"claim").unwrap().is_none(),
            "a key past its TTL must read as absent"
        );
        assert!(
            store.put_if_absent_with_ttl(b"claim", b"third", 1).unwrap(),
            "an expired key must be creatable again"
        );
        assert_eq!(store.get(b"claim").unwrap().unwrap(), &b"third"[..]);
    }

    /// A compare-and-swap against an expired row must fail rather than
    /// succeed on bytes that are no longer readable, and the swap it
    /// does perform carries the new TTL rather than inheriting the old
    /// one.
    #[test]
    fn compare_and_swap_refuses_an_expired_row() {
        let store = MemoryKVStore::new(0);
        store.put_with_ttl(b"k", b"old", 1).unwrap();
        assert!(store
            .compare_and_swap_with_ttl(b"k", b"old", b"new", 0)
            .unwrap());
        assert_eq!(store.get(b"k").unwrap().unwrap(), &b"new"[..]);

        store.put_with_ttl(b"gone", b"old", 1).unwrap();
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(
            !store
                .compare_and_swap_with_ttl(b"gone", b"old", b"new", 0)
                .unwrap(),
            "an expired row must not match its own bytes"
        );
    }

    /// The capability answer and the implementation have to agree, or a
    /// caller building single-flight on it picks the wrong mode before
    /// the first request.
    #[test]
    fn reports_that_it_supports_atomic_create() {
        assert!(MemoryKVStore::new(0).supports_atomic_create());
    }

    #[test]
    fn test_unlimited_entries() {
        let store = MemoryKVStore::new(0);
        for i in 0..1000u32 {
            store.put(&i.to_be_bytes(), &i.to_be_bytes()).unwrap();
        }
        let data = store.data.lock();
        assert_eq!(data.len(), 1000);
    }
}
