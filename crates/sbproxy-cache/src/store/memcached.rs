//! Memcached cache store using the ASCII protocol over TCP.
//!
//! Implements the [`CacheStore`] trait using raw TCP sockets and the memcached
//! ASCII text protocol.  Each call opens a fresh connection; connection pooling
//! can be layered on top if needed.
//!
//! Protocol overview:
//! - `get {key}` -> `VALUE {key} {flags} {bytes}` then the data then `END`
//! - `set {key} 0 {ttl} {bytes}` then the data -> `STORED`
//! - `delete {key}` -> `DELETED` or `NOT_FOUND`
//!
//! Known limits of this backend, all of them properties of memcached
//! rather than of this code:
//!
//! - **No stale-while-revalidate.** Memcached expires items server-side
//!   at the TTL it was given, and the store has no way to learn the SWR
//!   window, so `get_including_expired` can never return a past-TTL
//!   entry and `stale_while_revalidate` never fires.
//! - **No prefix purge.** Keys are hashed to fit the protocol's 250-byte
//!   limit, and memcached has no key scan, so `delete_prefix` returns
//!   `Ok(0)` and `invalidate_on_mutation` is a no-op. Entries fall out
//!   by TTL.
//! - **A default 1 MiB value cap.** Larger responses are refused by the
//!   server and the write returns an error, which the response phase
//!   logs and moves past.
//! - **One TCP connection per operation.** Cache reads run on the
//!   blocking pool, so this costs latency rather than reactor time.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use super::{CacheStore, CachedResponse};

/// Memcached reads any expiration above 30 days as an absolute Unix
/// timestamp rather than a relative offset (see the `set` command in
/// the ASCII protocol spec). Relative TTLs are clamped here so a long
/// configured TTL cannot be read as a 1970 timestamp, which would
/// expire the item the instant it is written.
const MAX_RELATIVE_TTL_SECS: u64 = 60 * 60 * 24 * 30;

/// Upper bound on a memcached key, in bytes.
const MAX_KEY_BYTES: usize = 250;

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
    ///
    /// Clamped to [`MAX_RELATIVE_TTL_SECS`]. An entry configured with a
    /// TTL past that ceiling expires early on this backend rather than
    /// never being cached at all, which is the honest degradation.
    fn remaining_ttl(entry: &CachedResponse) -> u64 {
        let expiry = entry.cached_at.saturating_add(entry.ttl_secs);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        expiry.saturating_sub(now).min(MAX_RELATIVE_TTL_SECS)
    }

    /// Encode a cache key into a memcached-safe key.
    ///
    /// Response-cache keys are `workspace:host:METHOD:/path:query:varyfp`
    /// and carry no length bound, while memcached caps keys at 250 bytes
    /// and rejects spaces and control characters. Hashing unconditionally
    /// makes every key fixed-length, printable, and deterministic, so the
    /// request path and an admin purge-by-key agree on the same key.
    ///
    /// One consequence: keys are one-way on this backend, so
    /// `delete_prefix` cannot be implemented (it already returns `Ok(0)`
    /// through the trait default) and `invalidate_on_mutation` is a
    /// no-op here. That is documented in `docs/configuration.md`.
    fn encode_key(key: &str) -> String {
        let digest = Sha256::digest(key.as_bytes());
        let encoded = format!("sbrc:{}", hex::encode(digest));
        debug_assert!(encoded.len() <= MAX_KEY_BYTES);
        encoded
    }
}

impl CacheStore for MemcachedStore {
    fn get(&self, key: &str) -> Result<Option<CachedResponse>> {
        let key = Self::encode_key(key);
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
        let key = Self::encode_key(key);
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
        let key = Self::encode_key(key);
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

    fn backend_name(&self) -> &'static str {
        "memcached"
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
    fn encode_key_is_short_and_protocol_safe_for_any_input() {
        // Real cache keys are `workspace:host:METHOD:/path:query:varyfp`
        // with no length bound. Memcached caps keys at 250 bytes and
        // rejects control characters and spaces, so a normal API path
        // used to draw `CLIENT_ERROR bad command line format` and the
        // cache silently never hit.
        let long_path = "/".to_string() + &"segment/".repeat(200);
        let raw = format!(":api.example.com:GET:{long_path}:a=1&b=2:fp");
        let encoded = MemcachedStore::encode_key(&raw);

        assert!(
            encoded.len() <= 250,
            "encoded key is {} bytes, over the memcached limit",
            encoded.len()
        );
        assert!(
            encoded.bytes().all(|b| b > 0x20 && b < 0x7f),
            "encoded key contains a byte memcached rejects: {encoded}"
        );
        assert!(encoded.starts_with("sbrc:"));
    }

    #[test]
    fn encode_key_is_deterministic_and_collision_free_for_distinct_keys() {
        // Admin purge-by-key and the request path must land on the same
        // memcached key for the same logical cache key.
        let a = MemcachedStore::encode_key("ws:host:GET:/users/42::fp");
        let b = MemcachedStore::encode_key("ws:host:GET:/users/42::fp");
        let c = MemcachedStore::encode_key("ws:host:GET:/users/43::fp");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn encode_key_handles_whitespace_and_control_bytes() {
        // The old sanitizer only swapped whitespace for underscores and
        // passed control bytes straight through.
        let encoded = MemcachedStore::encode_key("hello world\r\nset evil 0 0 1\r\n");
        assert!(encoded.starts_with("sbrc:"));
        assert!(!encoded.contains(' '));
        assert!(!encoded.contains('\r'));
        assert!(!encoded.contains('\n'));
    }

    #[test]
    fn remaining_ttl_is_clamped_to_the_relative_expiry_ceiling() {
        // Memcached reads any expiration above 30 days as an absolute
        // Unix timestamp. An unclamped 60-day TTL was therefore read as
        // a 1970 timestamp and the item expired the moment it was
        // written, so long-TTL entries never cached at all.
        let entry = CachedResponse {
            status: 200,
            headers: vec![],
            body: vec![],
            cached_at: now_secs(),
            ttl_secs: 60 * 60 * 24 * 60,
        };
        let ttl = MemcachedStore::remaining_ttl(&entry);
        assert_eq!(
            ttl, 2_592_000,
            "TTL above 30 days must clamp to the relative-expiry ceiling"
        );
    }

    #[test]
    fn remaining_ttl_below_the_ceiling_is_untouched() {
        let entry = make_entry(3600);
        let ttl = MemcachedStore::remaining_ttl(&entry);
        assert!(ttl > 3500 && ttl <= 3600, "expected ~3600 got {ttl}");
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
