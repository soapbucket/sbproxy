//! PostgreSQL KVStore backend.
//!
//! This module defines `PostgresKVStore` backed by the `postgres` crate
//! (synchronous PostgreSQL client). The implementation stores raw byte blobs
//! in a single table:
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS kv (
//!     key   BYTEA NOT NULL PRIMARY KEY,
//!     value BYTEA NOT NULL
//! );
//! ```
//!
//! # Dependency
//!
//! Enable the `postgres-store` feature in `sbproxy-platform` to compile this
//! backend:
//!
//! ```toml
//! sbproxy-platform = { path = "…", features = ["postgres-store"] }
//! ```
//!
//! That feature activates the `postgres` crate dependency.
//!
//! # Connection pooling
//!
//! A single synchronous `postgres::Client` is wrapped in a `Mutex`. For
//! production use behind a high-concurrency proxy, consider replacing this
//! with a connection pool such as `r2d2-postgres`.

use std::sync::Mutex;

use anyhow::{Context, Result};
use bytes::Bytes;
use postgres::{Client, NoTls};

use super::KVStore;

/// PostgreSQL-backed key-value store.
pub struct PostgresKVStore {
    client: Mutex<Client>,
}

impl PostgresKVStore {
    /// Connect to PostgreSQL and ensure the `kv` table exists.
    ///
    /// `connection_string` follows the `libpq` format, e.g.
    /// `"host=localhost user=postgres dbname=mydb"` or a `postgres://` URL.
    pub fn new(connection_string: &str) -> Result<Self> {
        let mut client = Client::connect(connection_string, NoTls)
            .with_context(|| format!("connect to PostgreSQL: {}", connection_string))?;

        client
            .execute(
                "CREATE TABLE IF NOT EXISTS kv (
                    key   BYTEA NOT NULL PRIMARY KEY,
                    value BYTEA NOT NULL
                )",
                &[],
            )
            .context("create kv table")?;

        Ok(Self {
            client: Mutex::new(client),
        })
    }
}

impl KVStore for PostgresKVStore {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let mut client = self.client.lock().expect("lock poisoned");
        let rows = client
            .query("SELECT value FROM kv WHERE key = $1", &[&key])
            .context("SELECT")?;

        if let Some(row) = rows.into_iter().next() {
            let value: Vec<u8> = row.try_get(0).context("read value column")?;
            Ok(Some(Bytes::from(value)))
        } else {
            Ok(None)
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut client = self.client.lock().expect("lock poisoned");
        client
            .execute(
                "INSERT INTO kv (key, value) VALUES ($1, $2)
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                &[&key, &value],
            )
            .context("UPSERT")?;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let mut client = self.client.lock().expect("lock poisoned");
        client
            .execute("DELETE FROM kv WHERE key = $1", &[&key])
            .context("DELETE")?;
        Ok(())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        let mut client = self.client.lock().expect("lock poisoned");

        // Use PostgreSQL's `LIKE` with byte-level prefix matching via CAST.
        // For binary data the safest approach is to fetch the range
        // [prefix, next_prefix) using >= / < on BYTEA.
        let results = if let Some(upper) = next_prefix(prefix) {
            client
                .query(
                    "SELECT key, value FROM kv
                     WHERE key >= $1 AND key < $2
                     ORDER BY key",
                    &[&prefix, &upper.as_slice()],
                )
                .context("range SELECT")?
        } else {
            // No upper bound - scan everything from prefix onwards.
            client
                .query(
                    "SELECT key, value FROM kv WHERE key >= $1 ORDER BY key",
                    &[&prefix],
                )
                .context("unbounded range SELECT")?
        };

        let pairs = results
            .into_iter()
            .filter_map(|row| {
                let k: Vec<u8> = row.try_get(0).ok()?;
                if !k.starts_with(prefix) {
                    return None;
                }
                let v: Vec<u8> = row.try_get(1).ok()?;
                Some((Bytes::from(k), Bytes::from(v)))
            })
            .collect();

        Ok(pairs)
    }
}

/// Smallest byte string strictly greater than any string starting with
/// `prefix`. Returns `None` on overflow (all 0xFF).
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

    const CONN: &str = "host=localhost user=postgres dbname=postgres";

    fn store() -> PostgresKVStore {
        PostgresKVStore::new(CONN).expect("connect to postgres")
    }

    #[test]
    #[ignore = "requires a running PostgreSQL instance"]
    fn test_get_put_delete_roundtrip() {
        let s = store();
        s.delete(b"pg:test:k1").unwrap();

        assert!(s.get(b"pg:test:k1").unwrap().is_none());

        s.put(b"pg:test:k1", b"hello").unwrap();
        assert_eq!(s.get(b"pg:test:k1").unwrap().unwrap(), &b"hello"[..]);

        s.put(b"pg:test:k1", b"world").unwrap();
        assert_eq!(s.get(b"pg:test:k1").unwrap().unwrap(), &b"world"[..]);

        s.delete(b"pg:test:k1").unwrap();
        assert!(s.get(b"pg:test:k1").unwrap().is_none());

        s.delete(b"pg:test:k1").unwrap(); // no-op
    }

    #[test]
    #[ignore = "requires a running PostgreSQL instance"]
    fn test_scan_prefix() {
        let s = store();
        let keys: &[&[u8]] = &[b"pg:scan:a", b"pg:scan:b", b"pg:other:c"];
        for k in keys {
            s.delete(k).unwrap();
        }

        s.put(b"pg:scan:a", b"1").unwrap();
        s.put(b"pg:scan:b", b"2").unwrap();
        s.put(b"pg:other:c", b"3").unwrap();

        let results = s.scan_prefix(b"pg:scan:").unwrap();
        assert_eq!(results.len(), 2);

        for k in keys {
            s.delete(k).unwrap();
        }
    }
}
