//! Redb KVStore backend.
//!
//! [redb](https://docs.rs/redb) is a pure-Rust, ACID-compliant embedded
//! key-value database with MVCC (multi-version concurrency control). It does
//! not require a mutex around individual operations because `redb::Database`
//! is internally `Send + Sync`.

use anyhow::{Context, Result};
use bytes::Bytes;
use redb::{Database, TableDefinition};

use super::KVStore;

/// Table name used in the redb database.
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kv");

/// Redb-backed key-value store.
///
/// The database file is created at the given path on construction. Use a path
/// inside a `tempfile::NamedTempFile` for tests.
pub struct RedbKVStore {
    db: Database,
}

impl RedbKVStore {
    /// Open (or create) a redb database at `path`.
    pub fn new(path: &str) -> Result<Self> {
        let db =
            Database::create(path).with_context(|| format!("open redb database at {:?}", path))?;

        // Ensure the table exists.
        let write_txn = db.begin_write().context("begin write transaction")?;
        write_txn.open_table(TABLE).context("open kv table")?;
        write_txn.commit().context("commit initial transaction")?;

        Ok(Self { db })
    }
}

impl KVStore for RedbKVStore {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let read_txn = self.db.begin_read().context("begin read transaction")?;
        let table = read_txn.open_table(TABLE).context("open kv table")?;
        match table.get(key).context("get key")? {
            Some(guard) => Ok(Some(Bytes::copy_from_slice(guard.value()))),
            None => Ok(None),
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let write_txn = self.db.begin_write().context("begin write transaction")?;
        {
            let mut table = write_txn.open_table(TABLE).context("open kv table")?;
            table.insert(key, value).context("insert key")?;
        }
        write_txn.commit().context("commit write transaction")
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let write_txn = self.db.begin_write().context("begin write transaction")?;
        {
            let mut table = write_txn.open_table(TABLE).context("open kv table")?;
            table.remove(key).context("delete key")?;
        }
        write_txn.commit().context("commit delete transaction")
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        let read_txn = self.db.begin_read().context("begin read transaction")?;
        let table = read_txn.open_table(TABLE).context("open kv table")?;

        let mut results = Vec::new();

        // redb supports range queries on byte-slice keys. Compute the
        // exclusive upper bound so we can use a bounded range instead of
        // scanning the entire table.
        if let Some(upper) = next_prefix(prefix) {
            let range = table
                .range(prefix..upper.as_slice())
                .context("range scan")?;

            for entry in range {
                let (k, v) = entry.context("read range entry")?;
                results.push((
                    Bytes::copy_from_slice(k.value()),
                    Bytes::copy_from_slice(v.value()),
                ));
            }
        } else {
            // Overflow case: start from prefix and iterate to end.
            let range = table.range(prefix..).context("range scan (unbounded)")?;
            for entry in range {
                let (k, v) = entry.context("read range entry")?;
                if !k.value().starts_with(prefix) {
                    break;
                }
                results.push((
                    Bytes::copy_from_slice(k.value()),
                    Bytes::copy_from_slice(v.value()),
                ));
            }
        }

        Ok(results)
    }
}

/// Compute the smallest byte string strictly greater than any string starting
/// with `prefix`. Returns `None` on overflow (all bytes are 0xFF).
fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    for byte in upper.iter_mut().rev() {
        if *byte < 0xFF {
            *byte += 1;
            return Some(upper);
        }
        *byte = 0x00;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_path() -> String {
        // Combine process id + monotonic counter + nanos so tests
        // running in parallel within the same process never collide,
        // and re-runs with the same nanos don't either.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            "/tmp/redb_test_{}_{}_{}.redb",
            std::process::id(),
            n,
            uuid_simple(),
        )
    }

    fn uuid_simple() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        format!("{:x}", nanos)
    }

    fn make_store() -> RedbKVStore {
        let path = unique_path();
        RedbKVStore::new(&path).unwrap()
    }

    #[test]
    fn test_get_put_delete_roundtrip() {
        let s = make_store();

        assert!(s.get(b"k1").unwrap().is_none());

        s.put(b"k1", b"hello").unwrap();
        assert_eq!(s.get(b"k1").unwrap().unwrap(), &b"hello"[..]);

        // Overwrite.
        s.put(b"k1", b"world").unwrap();
        assert_eq!(s.get(b"k1").unwrap().unwrap(), &b"world"[..]);

        s.delete(b"k1").unwrap();
        assert!(s.get(b"k1").unwrap().is_none());

        // Delete non-existent is fine.
        s.delete(b"k1").unwrap();
    }

    #[test]
    fn test_scan_prefix() {
        let s = make_store();

        s.put(b"app:user:1", b"alice").unwrap();
        s.put(b"app:user:2", b"bob").unwrap();
        s.put(b"app:config:x", b"cfg").unwrap();
        s.put(b"other:key", b"nope").unwrap();

        let results = s.scan_prefix(b"app:user:").unwrap();
        assert_eq!(results.len(), 2);

        let results = s.scan_prefix(b"app:").unwrap();
        assert_eq!(results.len(), 3);

        let results = s.scan_prefix(b"missing:").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_prefix_all_ff_edge() {
        let s = make_store();
        let key = vec![0xFFu8, 0xFF, 0x01];
        s.put(&key, b"v").unwrap();
        let results = s.scan_prefix(&[0xFF, 0xFF]).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_binary_keys_values() {
        let s = make_store();
        let key = &[0x00u8, 0xAB, 0xFF];
        let val = &[1u8, 2, 3, 4];
        s.put(key, val).unwrap();
        assert_eq!(s.get(key).unwrap().unwrap(), &val[..]);
    }
}
