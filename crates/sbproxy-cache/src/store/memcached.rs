//! Memcached cache store using the ASCII protocol over TCP.
//!
//! Implements the [`CacheStore`] trait using raw TCP sockets and the memcached
//! ASCII text protocol.  Each call opens a fresh connection; connection pooling
//! can be layered on top if needed.
//!
//! Protocol overview:
//! - `get {key}\r\n` → `VALUE {key} {flags} {bytes}\r\n{data}\r\n END\r\n`
//! - `set {key} 0 {ttl} {bytes}\r\n{data}\r\n` → `STORED\r\n`
//! - `delete {key}\r\n` → `DELETED\r\n` | `NOT_FOUND\r\n`

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};

use super::{CacheStore, CachedResponse};

// --- Config ---

/// Configuration for the memcached cache store.
#[derive(Debug, Clone)]
pub struct MemcachedConfig {
    /// Memcached server hostname or IP.
    pub host: String,
    /// Memcached server port.
    pub port: u16,
}

impl Default for MemcachedConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 11211,
        }
    }
}

// --- Store ---

/// Memcached cache store.
///
/// Each operation opens a new TCP connection to the configured server.
/// Mark tests that require a live memcached instance with `#[ignore]`.
pub struct MemcachedStore {
    addr: String,
}

impl MemcachedStore {
    /// Create a new memcached store.
    pub fn new(config: MemcachedConfig) -> Self {
        Self {
            addr: format!("{}:{}", config.host, config.port),
        }
    }

    fn connect(&self) -> Result<TcpStream> {
        TcpStream::connect(&self.addr)
            .with_context(|| format!("MemcachedStore: cannot connect to {}", self.addr))
            .and_then(|s| {
                s.set_read_timeout(Some(Duration::from_secs(5)))
                    .context("MemcachedStore: set read timeout")?;
                s.set_write_timeout(Some(Duration::from_secs(5)))
                    .context("MemcachedStore: set write timeout")?;
                Ok(s)
            })
    }

    /// Compute remaining TTL in seconds.  Returns 0 for expired entries.
    fn remaining_ttl(entry: &CachedResponse) -> u64 {
        let expiry = entry.cached_at.saturating_add(entry.ttl_secs);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        expiry.saturating_sub(now)
    }

    /// Sanitize a cache key for memcached: replace whitespace with `_`.
    fn sanitize_key(key: &str) -> String {
        key.chars()
            .map(|c| if c.is_ascii_whitespace() { '_' } else { c })
            .collect()
    }
}

impl CacheStore for MemcachedStore {
    fn get(&self, key: &str) -> Result<Option<CachedResponse>> {
        let key = Self::sanitize_key(key);
        let stream = self.connect()?;
        let mut writer = stream.try_clone().context("MemcachedStore: clone stream")?;
        let mut reader = BufReader::new(stream);

        // --- Send get command ---
        write!(writer, "get {}\r\n", key).context("MemcachedStore: write get")?;
        writer.flush().context("MemcachedStore: flush get")?;

        // --- Read response header ---
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .context("MemcachedStore: read get header")?;
        let header = header.trim_end();

        if header == "END" {
            // Cache miss.
            return Ok(None);
        }

        if !header.starts_with("VALUE") {
            return Err(anyhow!(
                "MemcachedStore: unexpected get response: {}",
                header
            ));
        }

        // VALUE {key} {flags} {bytes}
        let parts: Vec<&str> = header.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(anyhow!(
                "MemcachedStore: malformed VALUE header: {}",
                header
            ));
        }
        let byte_count: usize = parts[3]
            .parse()
            .context("MemcachedStore: parse byte count")?;

        // --- Read value bytes ---
        let mut data = vec![0u8; byte_count];
        use std::io::Read;
        reader
            .read_exact(&mut data)
            .context("MemcachedStore: read value")?;

        // Consume trailing \r\n and END\r\n.
        let mut trailing = String::new();
        reader.read_line(&mut trailing).ok();
        let mut end_line = String::new();
        reader.read_line(&mut end_line).ok();

        // --- Deserialize ---
        let entry: CachedResponse =
            serde_json::from_slice(&data).context("MemcachedStore: deserialize value")?;

        if entry.is_expired() {
            return Ok(None);
        }

        Ok(Some(entry))
    }

    fn put(&self, key: &str, value: &CachedResponse) -> Result<()> {
        let key = Self::sanitize_key(key);
        let ttl = Self::remaining_ttl(value);
        if ttl == 0 {
            // Already expired; skip write.
            return Ok(());
        }

        let data = serde_json::to_vec(value).context("MemcachedStore: serialize value")?;

        let stream = self.connect()?;
        let mut writer = stream.try_clone().context("MemcachedStore: clone stream")?;
        let mut reader = BufReader::new(stream);

        // set {key} {flags} {ttl} {bytes}\r\n{data}\r\n
        write!(writer, "set {} 0 {} {}\r\n", key, ttl, data.len())
            .context("MemcachedStore: write set header")?;
        writer
            .write_all(&data)
            .context("MemcachedStore: write set data")?;
        writer
            .write_all(b"\r\n")
            .context("MemcachedStore: write set crlf")?;
        writer.flush().context("MemcachedStore: flush set")?;

        let mut response = String::new();
        reader
            .read_line(&mut response)
            .context("MemcachedStore: read set response")?;

        if response.trim() != "STORED" {
            return Err(anyhow!(
                "MemcachedStore: unexpected set response: {}",
                response.trim()
            ));
        }

        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let key = Self::sanitize_key(key);
        let stream = self.connect()?;
        let mut writer = stream.try_clone().context("MemcachedStore: clone stream")?;
        let mut reader = BufReader::new(stream);

        write!(writer, "delete {}\r\n", key).context("MemcachedStore: write delete")?;
        writer.flush().context("MemcachedStore: flush delete")?;

        let mut response = String::new();
        reader
            .read_line(&mut response)
            .context("MemcachedStore: read delete response")?;

        // Both DELETED and NOT_FOUND are acceptable.
        let r = response.trim();
        if r != "DELETED" && r != "NOT_FOUND" {
            return Err(anyhow!("MemcachedStore: unexpected delete response: {}", r));
        }

        Ok(())
    }

    fn clear(&self) -> Result<()> {
        let stream = self.connect()?;
        let mut writer = stream.try_clone().context("MemcachedStore: clone stream")?;
        let mut reader = BufReader::new(stream);

        write!(writer, "flush_all\r\n").context("MemcachedStore: write flush_all")?;
        writer.flush().context("MemcachedStore: flush flush_all")?;

        let mut response = String::new();
        reader
            .read_line(&mut response)
            .context("MemcachedStore: read flush_all response")?;

        if response.trim() != "OK" {
            return Err(anyhow!(
                "MemcachedStore: unexpected flush_all response: {}",
                response.trim()
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_entry(ttl_secs: u64) -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![("x-test".into(), "value".into())],
            body: b"memcached test".to_vec(),
            cached_at: now_secs(),
            ttl_secs,
        }
    }

    fn make_store() -> MemcachedStore {
        MemcachedStore::new(MemcachedConfig::default())
    }

    #[test]
    fn config_defaults() {
        let cfg = MemcachedConfig::default();
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 11211);
    }

    #[test]
    fn sanitize_key_replaces_whitespace() {
        assert_eq!(MemcachedStore::sanitize_key("hello world"), "hello_world");
        assert_eq!(MemcachedStore::sanitize_key("no-spaces"), "no-spaces");
    }

    #[test]
    fn remaining_ttl_future_entry() {
        let entry = make_entry(300);
        let ttl = MemcachedStore::remaining_ttl(&entry);
        // Should be close to 300 seconds.
        assert!(ttl > 280 && ttl <= 300, "expected ~300 got {}", ttl);
    }

    #[test]
    fn remaining_ttl_expired_entry() {
        let entry = CachedResponse {
            status: 200,
            headers: vec![],
            body: vec![],
            cached_at: now_secs().saturating_sub(400),
            ttl_secs: 1,
        };
        assert_eq!(MemcachedStore::remaining_ttl(&entry), 0);
    }

    // --- Integration tests (require live memcached) ---

    #[test]
    #[ignore]
    fn integration_put_get_delete() {
        let store = make_store();
        let entry = make_entry(60);

        store.put("mc_test_key", &entry).unwrap();
        let got = store.get("mc_test_key").unwrap().expect("should hit");
        assert_eq!(got.status, 200);
        assert_eq!(got.body, b"memcached test");

        store.delete("mc_test_key").unwrap();
        assert!(store.get("mc_test_key").unwrap().is_none());
    }

    #[test]
    #[ignore]
    fn integration_clear() {
        let store = make_store();
        store.put("mc_a", &make_entry(60)).unwrap();
        store.put("mc_b", &make_entry(60)).unwrap();
        store.clear().unwrap();
        assert!(store.get("mc_a").unwrap().is_none());
        assert!(store.get("mc_b").unwrap().is_none());
    }
}
