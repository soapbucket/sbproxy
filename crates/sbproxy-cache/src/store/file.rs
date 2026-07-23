//! File-backed cache store.
//!
//! Each cache entry is stored as a separate file at:
//!   `{cache_dir}/{hex_key}.cache`
//!
//! File format:
//! - Bytes 0..8: expiry timestamp as a big-endian `u64` (Unix seconds).
//! - Bytes 8..: `serde_json`-encoded [`CachedResponse`].
//!
//! The store honours `max_size_mb` by refusing new writes when the directory
//! content would exceed the configured limit.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::{CacheStore, CachedResponse};

// --- Config ---

/// Configuration for the file-backed cache store.
#[derive(Debug, Clone)]
pub struct FileCacheConfig {
    /// Directory where cached files are stored.
    pub directory: String,
    /// Maximum total size of all cached files in megabytes.  0 means unlimited.
    pub max_size_mb: u64,
}

// --- Store ---

/// File-backed cache store.
///
/// Thread-safe: file system operations are atomic at the level of individual
/// file writes (write to temp file then rename).  Concurrent reads are always
/// safe; concurrent writes to the same key are last-write-wins.
pub struct FileCacheStore {
    dir: PathBuf,
    max_size_bytes: u64,
}

impl FileCacheStore {
    /// Create a new file cache store.  Pass `max_size_mb = 0` for unlimited.
    pub fn new(config: FileCacheConfig) -> Result<Self> {
        let dir = PathBuf::from(&config.directory);
        fs::create_dir_all(&dir).with_context(|| {
            format!(
                "FileCacheStore: cannot create directory '{}'",
                config.directory
            )
        })?;
        Ok(Self {
            dir,
            max_size_bytes: config.max_size_mb * 1024 * 1024,
        })
    }

    /// Derive the cache file path for a given `key`.
    fn path_for(&self, key: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hex = hex::encode(hasher.finalize());
        self.dir.join(format!("{}.cache", hex))
    }

    /// Total bytes currently used by all `.cache` files in the directory.
    fn current_size_bytes(&self) -> u64 {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return 0;
        };
        entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "cache").unwrap_or(false))
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    }

    /// Read the record at `path`.
    ///
    /// `allow_expired` is the stale-while-revalidate switch. The live
    /// `get` path passes `false`, so a past-TTL record is treated as a
    /// miss and removed. The `get_including_expired` path passes `true`
    /// and gets the record back untouched, which is what lets the
    /// caller evaluate the SWR window and serve it stale.
    fn read_entry(path: &Path, allow_expired: bool) -> Result<Option<CachedResponse>> {
        if !path.exists() {
            return Ok(None);
        }

        let data = fs::read(path).context("FileCacheStore: read failed")?;
        if data.len() < 8 {
            // Corrupt file.
            let _ = fs::remove_file(path);
            return Ok(None);
        }

        // --- Read expiry timestamp ---
        // `data.len() >= 8` is guaranteed by the corrupt-file check above, so
        // copy the header bytes into a fixed array rather than unwrapping a
        // fallible try_into on disk-controlled input.
        let mut header = [0u8; 8];
        header.copy_from_slice(&data[..8]);
        let expiry = u64::from_be_bytes(header);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > expiry && !allow_expired {
            // Entry is expired; remove lazily.
            let _ = fs::remove_file(path);
            return Ok(None);
        }

        // --- Deserialize payload ---
        let entry: CachedResponse =
            serde_json::from_slice(&data[8..]).context("FileCacheStore: JSON parse failed")?;

        Ok(Some(entry))
    }

    /// Stage the record in a writer-unique temp file, then rename it
    /// into place.
    ///
    /// The temp name carries a process-wide counter because the target
    /// path is derived from the cache key alone. Two threads writing the
    /// same key used to share one temp file and interleave their bytes
    /// into it, so the atomic rename could publish a torn record. Each
    /// call now owns its staging file; the rename is still the only
    /// operation observers can see.
    fn write_entry(path: &Path, entry: &CachedResponse) -> Result<()> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

        let expiry = Self::expiry_secs_static(entry);
        let payload = serde_json::to_vec(entry).context("FileCacheStore: JSON serialise failed")?;

        let seq = WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_path = path.with_extension(format!("{}.{}.tmp", std::process::id(), seq));

        // Any early return past this point must not leak the staging
        // file, so the body is wrapped and the temp file is removed on
        // failure.
        let staged = (|| -> Result<()> {
            let mut file =
                fs::File::create(&tmp_path).context("FileCacheStore: create temp file failed")?;
            file.write_all(&expiry.to_be_bytes())
                .context("FileCacheStore: write expiry failed")?;
            file.write_all(&payload)
                .context("FileCacheStore: write payload failed")?;
            drop(file);
            fs::rename(&tmp_path, path).context("FileCacheStore: rename failed")
        })();
        if staged.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        staged
    }

    fn expiry_secs_static(entry: &CachedResponse) -> u64 {
        entry.cached_at.saturating_add(entry.ttl_secs)
    }
}

impl CacheStore for FileCacheStore {
    fn get(&self, key: &str) -> Result<Option<CachedResponse>> {
        let path = self.path_for(key);
        Self::read_entry(&path, false)
    }

    /// Return the record even when it is past its TTL, without evicting
    /// it. The stale-while-revalidate path needs this: the live `get`
    /// removes an expired record, which would destroy the entry the SWR
    /// window intended to serve.
    fn get_including_expired(&self, key: &str) -> Result<Option<CachedResponse>> {
        let path = self.path_for(key);
        Self::read_entry(&path, true)
    }

    fn put(&self, key: &str, value: &CachedResponse) -> Result<()> {
        // Enforce size limit (skip check when unlimited).
        if self.max_size_bytes > 0 {
            let used = self.current_size_bytes();
            let payload_estimate = serde_json::to_vec(value)
                .map(|v| v.len() as u64)
                .unwrap_or(0);
            if used + payload_estimate > self.max_size_bytes {
                return Err(anyhow::anyhow!(
                    "FileCacheStore: cache directory exceeds {} MB limit",
                    self.max_size_bytes / (1024 * 1024)
                ));
            }
        }
        let path = self.path_for(key);
        Self::write_entry(&path, value)
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key);
        if path.exists() {
            fs::remove_file(&path).context("FileCacheStore: delete failed")?;
        }
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        for entry in fs::read_dir(&self.dir).context("FileCacheStore: read dir failed")? {
            let entry = entry.context("FileCacheStore: dir entry error")?;
            let path = entry.path();
            if path.extension().map(|x| x == "cache").unwrap_or(false) {
                fs::remove_file(&path).context("FileCacheStore: clear failed")?;
            }
        }
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_entry(ttl_secs: u64) -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"hello from file cache".to_vec(),
            cached_at: now_secs(),
            ttl_secs,
        }
    }

    fn make_store(dir: &TempDir) -> FileCacheStore {
        FileCacheStore::new(FileCacheConfig {
            directory: dir.path().to_str().unwrap().to_string(),
            max_size_mb: 0,
        })
        .unwrap()
    }

    #[test]
    fn put_and_get_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);

        let entry = make_entry(300);
        store.put("key1", &entry).unwrap();

        let got = store.get("key1").unwrap().expect("should hit");
        assert_eq!(got.status, 200);
        assert_eq!(got.body, b"hello from file cache");
    }

    #[test]
    fn get_missing_key_returns_none() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);
        assert!(store.get("nonexistent").unwrap().is_none());
    }

    #[test]
    fn expired_entry_returns_none() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);

        let expired = CachedResponse {
            status: 200,
            headers: vec![],
            body: b"stale".to_vec(),
            cached_at: now_secs().saturating_sub(200),
            ttl_secs: 1,
        };
        store.put("exp", &expired).unwrap();
        assert!(store.get("exp").unwrap().is_none());
    }

    #[test]
    fn corrupt_short_file_is_evicted() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);

        // A file shorter than the 8-byte expiry header is corrupt. Reading it
        // must not panic on the header parse; it returns None and evicts.
        let path = store.path_for("corrupt");
        std::fs::write(&path, b"abc").unwrap();
        assert!(path.exists());

        assert!(store.get("corrupt").unwrap().is_none());
        assert!(!path.exists(), "corrupt file should be evicted");
    }

    #[test]
    fn delete_removes_entry() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);

        store.put("k1", &make_entry(300)).unwrap();
        store.delete("k1").unwrap();
        assert!(store.get("k1").unwrap().is_none());
    }

    #[test]
    fn delete_nonexistent_is_ok() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);
        assert!(store.delete("nobody").is_ok());
    }

    #[test]
    fn clear_removes_all_entries() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);

        store.put("a", &make_entry(300)).unwrap();
        store.put("b", &make_entry(300)).unwrap();
        store.clear().unwrap();

        assert!(store.get("a").unwrap().is_none());
        assert!(store.get("b").unwrap().is_none());
    }

    #[test]
    fn different_keys_use_different_files() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);

        let e1 = CachedResponse {
            status: 200,
            headers: vec![],
            body: b"one".to_vec(),
            cached_at: now_secs(),
            ttl_secs: 300,
        };
        let e2 = CachedResponse {
            status: 404,
            headers: vec![],
            body: b"two".to_vec(),
            cached_at: now_secs(),
            ttl_secs: 300,
        };

        store.put("key1", &e1).unwrap();
        store.put("key2", &e2).unwrap();

        assert_eq!(store.get("key1").unwrap().unwrap().status, 200);
        assert_eq!(store.get("key2").unwrap().unwrap().status, 404);
    }

    #[test]
    fn size_limit_prevents_oversized_writes() {
        let dir = TempDir::new().unwrap();
        let store = FileCacheStore::new(FileCacheConfig {
            directory: dir.path().to_str().unwrap().to_string(),
            max_size_mb: 1, // 1 MB limit
        })
        .unwrap();

        // A small entry should succeed.
        store.put("small", &make_entry(300)).unwrap();

        // A 2 MB body should be rejected.
        let huge = CachedResponse {
            status: 200,
            headers: vec![],
            body: vec![0u8; 2 * 1024 * 1024],
            cached_at: now_secs(),
            ttl_secs: 300,
        };
        assert!(store.put("huge", &huge).is_err());
    }

    #[test]
    fn get_including_expired_returns_stale_without_deleting() {
        // The SWR path always reads through get_including_expired. The
        // trait default delegates to `get`, which evicts on expiry, so
        // without an override a past-TTL entry is destroyed by the very
        // lookup that wanted to serve it stale.
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);

        let stale = CachedResponse {
            status: 200,
            headers: vec![],
            body: b"stale".to_vec(),
            cached_at: now_secs().saturating_sub(500),
            ttl_secs: 60,
        };
        store.put("swr", &stale).unwrap();

        let got = store.get_including_expired("swr").unwrap();
        assert_eq!(
            got.expect("stale entry must be returned").body,
            b"stale",
            "get_including_expired must return the past-TTL entry"
        );
        assert!(
            store.path_for("swr").exists(),
            "get_including_expired must not evict the entry it returned"
        );
        // A second read still finds it, which is what the SWR
        // revalidation window depends on.
        assert!(store.get_including_expired("swr").unwrap().is_some());
    }

    #[test]
    fn get_including_expired_on_missing_key_is_none() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);
        assert!(store.get_including_expired("absent").unwrap().is_none());
    }

    #[test]
    fn live_get_still_evicts_an_expired_entry() {
        // The override must not change `get`. A past-TTL entry read
        // through the live path is still a miss and is still removed.
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir);

        let stale = CachedResponse {
            status: 200,
            headers: vec![],
            body: b"stale".to_vec(),
            cached_at: now_secs().saturating_sub(500),
            ttl_secs: 60,
        };
        store.put("gone", &stale).unwrap();
        assert!(store.get("gone").unwrap().is_none());
        assert!(!store.path_for("gone").exists());
    }

    #[test]
    fn concurrent_writes_of_one_key_do_not_leave_a_torn_file() {
        // Every writer used to stage through `<hash>.tmp`, a name derived
        // only from the key, so two writers interleaved into the same
        // temp file before the rename. Each write must stage through its
        // own path.
        use std::sync::Arc;

        let dir = TempDir::new().unwrap();
        let store = Arc::new(make_store(&dir));

        let mut handles = Vec::new();
        for i in 0..8u8 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let entry = CachedResponse {
                    status: 200,
                    headers: vec![("x-writer".into(), i.to_string())],
                    body: vec![i; 64 * 1024],
                    cached_at: now_secs(),
                    ttl_secs: 300,
                };
                for _ in 0..16 {
                    store.put("hot", &entry).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // Whichever writer won, the published record must be one
        // writer's bytes end to end, never a mix.
        let got = store.get("hot").unwrap().expect("entry should exist");
        assert_eq!(got.body.len(), 64 * 1024);
        let first = got.body[0];
        assert!(
            got.body.iter().all(|b| *b == first),
            "published entry is a mix of two writers' bodies"
        );

        // No temp files may survive a completed write.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "tmp").unwrap_or(false))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }
}
