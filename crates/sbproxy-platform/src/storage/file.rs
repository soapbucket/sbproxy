//! File-based KVStore backend.
//!
//! Each key-value pair is stored as a file on disk. The key is hex-encoded
//! as the filename; the file contents are the raw value bytes.
//!
//! A directory-level `Mutex` serialises all writes so that concurrent callers
//! cannot race on directory listing or file creation.

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use bytes::Bytes;

use super::KVStore;

/// File-backed key-value store. All operations are synchronous and
/// mutex-protected; it is not intended for high-concurrency workloads.
pub struct FileKVStore {
    directory: PathBuf,
    /// Protects all directory-level mutations (writes, deletes).
    _lock: Mutex<()>,
}

impl FileKVStore {
    /// Create (or open) a file store rooted at `directory`.
    ///
    /// The directory is created recursively if it does not already exist.
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        fs::create_dir_all(&directory)
            .with_context(|| format!("create KV directory {:?}", directory))?;
        Ok(Self {
            directory,
            _lock: Mutex::new(()),
        })
    }

    /// Convert a raw key slice to its hex-encoded filename.
    fn key_to_filename(key: &[u8]) -> String {
        hex::encode(key)
    }

    /// Decode a hex filename back to the original key bytes.
    fn filename_to_key(name: &str) -> Option<Vec<u8>> {
        hex::decode(name).ok()
    }

    fn path_for(&self, key: &[u8]) -> PathBuf {
        self.directory.join(Self::key_to_filename(key))
    }
}

impl KVStore for FileKVStore {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        let path = self.path_for(key);
        match fs::read(&path) {
            Ok(data) => Ok(Some(Bytes::from(data))),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {:?}", path)),
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let _guard = self._lock.lock().expect("lock poisoned");
        let path = self.path_for(key);
        fs::write(&path, value).with_context(|| format!("write {:?}", path))
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        let _guard = self._lock.lock().expect("lock poisoned");
        let path = self.path_for(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("delete {:?}", path)),
        }
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>> {
        let _guard = self._lock.lock().expect("lock poisoned");
        let encoded_prefix = Self::key_to_filename(prefix);

        let mut results = Vec::new();

        let read_dir = fs::read_dir(&self.directory)
            .with_context(|| format!("read_dir {:?}", self.directory))?;

        for entry in read_dir {
            let entry = entry.with_context(|| "read directory entry")?;
            let file_name = entry.file_name();
            let name = match file_name.to_str() {
                Some(n) => n,
                None => continue,
            };

            // A hex-encoded key has the prefix iff the original key bytes
            // start with `prefix`. Because hex encoding is prefix-safe (each
            // source byte becomes exactly two hex chars) we can compare the
            // encoded strings directly.
            if !name.starts_with(&encoded_prefix) {
                continue;
            }

            let key_bytes = match Self::filename_to_key(name) {
                Some(k) => k,
                None => continue,
            };

            let path = entry.path();
            let value = fs::read(&path).with_context(|| format!("read entry {:?}", path))?;

            results.push((Bytes::from(key_bytes), Bytes::from(value)));
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_store() -> (FileKVStore, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let store = FileKVStore::new(dir.path()).unwrap();
        (store, dir)
    }

    #[test]
    fn test_get_put_delete_roundtrip() {
        let (store, _dir) = make_store();

        // Missing key returns None.
        assert!(store.get(b"k1").unwrap().is_none());

        // Put and get.
        store.put(b"k1", b"hello").unwrap();
        assert_eq!(store.get(b"k1").unwrap().unwrap(), &b"hello"[..]);

        // Overwrite.
        store.put(b"k1", b"world").unwrap();
        assert_eq!(store.get(b"k1").unwrap().unwrap(), &b"world"[..]);

        // Delete.
        store.delete(b"k1").unwrap();
        assert!(store.get(b"k1").unwrap().is_none());

        // Delete non-existent is a no-op.
        store.delete(b"k1").unwrap();
    }

    #[test]
    fn test_scan_prefix() {
        let (store, _dir) = make_store();

        store.put(b"app:user:1", b"alice").unwrap();
        store.put(b"app:user:2", b"bob").unwrap();
        store.put(b"app:config:x", b"cfg").unwrap();
        store.put(b"other:key", b"nope").unwrap();

        let mut results = store.scan_prefix(b"app:user:").unwrap();
        results.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(results.len(), 2);

        let results = store.scan_prefix(b"app:").unwrap();
        assert_eq!(results.len(), 3);

        let results = store.scan_prefix(b"missing:").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_binary_keys_and_values() {
        let (store, _dir) = make_store();
        let key = &[0x00, 0xFF, 0xAB, 0x12];
        let value = &[0x01, 0x02, 0x03];
        store.put(key, value).unwrap();
        assert_eq!(store.get(key).unwrap().unwrap(), &value[..]);
    }
}
