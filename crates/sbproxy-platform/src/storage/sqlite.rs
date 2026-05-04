//! SQLite KVStore backend using `rusqlite`.
//!
//! A single table (`kv`) stores raw byte blobs for keys and values.
//! The SQLite connection is wrapped in a `Mutex` to satisfy the `Send + Sync`
//! requirements of `KVStore`.
//!
//! Use `":memory:"` as the path for a fully in-process, non-persistent store
//! (handy for tests).

use std::sync::Mutex;

use anyhow::{Context, Result};
use bytes::Bytes;
use rusqlite::{params, Connection, OpenFlags};

use super::KVStore;

/// SQLite-backed key-value store.
pub struct SqliteKVStore {
    conn: Mutex<Connection>,
}

impl SqliteKVStore {
    /// Open (or create) a SQLite database at `path`.
    ///
    /// Pass `":memory:"` for an ephemeral in-memory database.
    pub fn new(path: &str) -> Result<Self> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX; // We supply our own mutex.

        let conn = Connection::open_with_flags(path, flags)
            .with_context(|| format!("open SQLite database at {:?}", path))?;

        // Enable WAL mode for better concurrent read throughput.
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                key   BLOB NOT NULL PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )
        .context("create kv table")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl KVStore for SqliteKVStore {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let conn = self.conn.lock().expect("lock poisoned");
        let mut stmt = conn
            .prepare_cached("SELECT value FROM kv WHERE key = ?1")
            .context("prepare SELECT")?;

        let mut rows = stmt.query(params![key]).context("execute SELECT")?;
        if let Some(row) = rows.next().context("fetch row")? {
            let blob: Vec<u8> = row.get(0).context("read value column")?;
            Ok(Some(Bytes::from(blob)))
        } else {
            Ok(None)
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let conn = self.conn.lock().expect("lock poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .context("execute INSERT OR REPLACE")?;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let conn = self.conn.lock().expect("lock poisoned");
        conn.execute("DELETE FROM kv WHERE key = ?1", params![key])
            .context("execute DELETE")?;
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        let conn = self.conn.lock().expect("lock poisoned");

        // Compute the exclusive upper bound for the prefix range.
        // If every byte is 0xFF there is no upper bound - fall back to a full
        // scan filtered in Rust.
        let upper = next_prefix(prefix);

        let results = if let Some(upper) = upper {
            // Fast path: range query entirely inside SQLite.
            let mut stmt = conn
                .prepare_cached(
                    "SELECT key, value FROM kv
                     WHERE key >= ?1 AND key < ?2
                     ORDER BY key",
                )
                .context("prepare range SELECT")?;

            let rows = stmt
                .query_map(params![prefix, upper.as_slice()], |row| {
                    let k: Vec<u8> = row.get(0)?;
                    let v: Vec<u8> = row.get(1)?;
                    Ok((k, v))
                })
                .context("execute range SELECT")?;

            rows.map(|r| {
                r.map(|(k, v)| (Bytes::from(k), Bytes::from(v)))
                    .context("read row")
            })
            .collect::<Result<Vec<_>>>()?
        } else {
            // Slow fallback: read everything and filter.
            let mut stmt = conn
                .prepare_cached("SELECT key, value FROM kv ORDER BY key")
                .context("prepare full SELECT")?;

            let rows = stmt
                .query_map([], |row| {
                    let k: Vec<u8> = row.get(0)?;
                    let v: Vec<u8> = row.get(1)?;
                    Ok((k, v))
                })
                .context("execute full SELECT")?;

            rows.filter_map(|r| match r {
                Ok((k, v)) if k.starts_with(prefix) => Some(Ok((Bytes::from(k), Bytes::from(v)))),
                Ok(_) => None,
                Err(e) => Some(Err(anyhow::Error::from(e))),
            })
            .collect::<Result<Vec<_>>>()?
        };

        Ok(results)
    }
}

/// Compute the smallest byte string that is strictly greater than all strings
/// that start with `prefix`. Returns `None` if the prefix overflows (all 0xFF).
fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    // Increment from the rightmost byte, carrying left.
    for byte in upper.iter_mut().rev() {
        if *byte < 0xFF {
            *byte += 1;
            return Some(upper);
        }
        *byte = 0x00;
    }
    // All bytes were 0xFF - no upper bound exists.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_store() -> SqliteKVStore {
        SqliteKVStore::new(":memory:").unwrap()
    }

    #[test]
    fn test_get_put_delete_roundtrip() {
        let s = mem_store();

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
        let s = mem_store();

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
    fn test_binary_blobs() {
        let s = mem_store();
        let key = &[0x00u8, 0xFF, 0x7F];
        let value = &[0xDE, 0xAD, 0xBE, 0xEF];
        s.put(key, value).unwrap();
        assert_eq!(s.get(key).unwrap().unwrap(), &value[..]);
    }

    #[test]
    fn test_scan_prefix_all_ff() {
        // Edge case: prefix that ends with 0xFF triggers the fallback path.
        let s = mem_store();
        let key = &[0xFF, 0xFF, 0x01u8];
        s.put(key, b"v").unwrap();
        let results = s.scan_prefix(&[0xFF, 0xFF]).unwrap();
        assert_eq!(results.len(), 1);
    }
}
