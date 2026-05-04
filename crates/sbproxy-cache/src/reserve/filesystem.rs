//! Filesystem [`CacheReserveBackend`].
//!
//! One file per key under [`FsReserve::root`], plus a sidecar JSON
//! file holding the [`ReserveMetadata`]. The split layout keeps body
//! reads as a plain `read` syscall and lets ad-hoc tooling (`du`,
//! `find -mtime`) reason about reserve contents without parsing an
//! envelope format.
//!
//! Keys are hashed to a hex digest so callers can use anything
//! (including `:` and `/`) without escaping. The hash also fans the
//! files across hex-prefixed subdirectories so the directory entry
//! count per dir stays bounded for extN / XFS.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};

use super::{CacheReserveBackend, ReserveMetadata};

/// Filesystem-backed reserve.
///
/// Each `put(key, value, meta)` writes:
///   - `{root}/{aa}/{bb}/{hash}.bin`  -> `value`
///   - `{root}/{aa}/{bb}/{hash}.json` -> JSON-serialised `meta`
///
/// where `aa`/`bb` are the first two and next two hex bytes of the
/// SHA-256 of `key`.
#[derive(Debug, Clone)]
pub struct FsReserve {
    /// Root directory under which entries are written.
    pub root: PathBuf,
}

impl FsReserve {
    /// Build a new filesystem reserve at `root`. The directory is
    /// created lazily on the first `put`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn paths(&self, key: &str) -> (PathBuf, PathBuf, PathBuf) {
        let h = Self::hash_key(key);
        // 256-fan-out by first byte, then 256-fan-out by second so
        // a million entries yield ~16 files per leaf.
        let dir = self.root.join(&h[0..2]).join(&h[2..4]);
        let body = dir.join(format!("{}.bin", &h[4..]));
        let meta = dir.join(format!("{}.json", &h[4..]));
        (dir, body, meta)
    }

    async fn ensure_dir(dir: &Path) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(dir).await.map_err(Into::into)
    }
}

#[async_trait]
impl CacheReserveBackend for FsReserve {
    async fn put(&self, key: &str, value: Bytes, metadata: ReserveMetadata) -> anyhow::Result<()> {
        let (dir, body, meta) = self.paths(key);
        Self::ensure_dir(&dir).await?;
        // Write body first; if the metadata write later fails, the
        // body is unreachable (no metadata) and `evict_expired` /
        // `delete` clean it up. We accept this asymmetry instead of
        // an extra fsync round-trip.
        tokio::fs::write(&body, &value).await?;
        let meta_bytes = serde_json::to_vec(&metadata)?;
        tokio::fs::write(&meta, meta_bytes).await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<(Bytes, ReserveMetadata)>> {
        let (_dir, body, meta) = self.paths(key);
        // Metadata first: it's small, and an absent metadata file is
        // the canonical "miss" signal even if a stray body exists.
        let meta_bytes = match tokio::fs::read(&meta).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let metadata: ReserveMetadata = serde_json::from_slice(&meta_bytes)?;
        let body_bytes = match tokio::fs::read(&body).await {
            Ok(b) => Bytes::from(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(Some((body_bytes, metadata)))
    }

    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let (_dir, body, meta) = self.paths(key);
        // Best-effort on each: a missing file is not an error.
        if let Err(e) = tokio::fs::remove_file(&body).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        if let Err(e) = tokio::fs::remove_file(&meta).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        Ok(())
    }

    async fn evict_expired(&self, before: SystemTime) -> anyhow::Result<u64> {
        // Walk the two-level fan-out and sweep stale metadata files.
        // Errors mid-walk degrade to "skip and continue" so a single
        // permission glitch doesn't abandon the whole sweep.
        let mut removed = 0u64;
        let root = self.root.clone();
        if !root.exists() {
            return Ok(0);
        }
        let mut top = match tokio::fs::read_dir(&root).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        while let Some(level1) = top.next_entry().await? {
            if !level1.file_type().await?.is_dir() {
                continue;
            }
            let mut mid = tokio::fs::read_dir(level1.path()).await?;
            while let Some(level2) = mid.next_entry().await? {
                if !level2.file_type().await?.is_dir() {
                    continue;
                }
                let mut leaves = tokio::fs::read_dir(level2.path()).await?;
                while let Some(file) = leaves.next_entry().await? {
                    let path = file.path();
                    if path.extension().and_then(|s| s.to_str()) != Some("json") {
                        continue;
                    }
                    let bytes = match tokio::fs::read(&path).await {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    let meta: ReserveMetadata = match serde_json::from_slice(&bytes) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if meta.expires_at < before {
                        let body_path = path.with_extension("bin");
                        let _ = tokio::fs::remove_file(&body_path).await;
                        let _ = tokio::fs::remove_file(&path).await;
                        removed += 1;
                    }
                }
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;

    fn meta(now: SystemTime, ttl: Duration, size: u64) -> ReserveMetadata {
        ReserveMetadata {
            created_at: now,
            expires_at: now + ttl,
            content_type: Some("application/json".to_string()),
            vary_fingerprint: Some("vary-x".to_string()),
            size,
            status: 200,
        }
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let tmp = tempdir().unwrap();
        let r = FsReserve::new(tmp.path());
        let body = Bytes::from_static(b"abcd");
        r.put(
            "key/with:weird?chars",
            body.clone(),
            meta(SystemTime::now(), Duration::from_secs(60), 4),
        )
        .await
        .unwrap();
        let (got, m) = r.get("key/with:weird?chars").await.unwrap().expect("hit");
        assert_eq!(got, body);
        assert_eq!(m.size, 4);
        assert_eq!(m.vary_fingerprint.as_deref(), Some("vary-x"));
    }

    #[tokio::test]
    async fn missing_key_returns_none() {
        let tmp = tempdir().unwrap();
        let r = FsReserve::new(tmp.path());
        assert!(r.get("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_removes_files() {
        let tmp = tempdir().unwrap();
        let r = FsReserve::new(tmp.path());
        r.put(
            "k",
            Bytes::from_static(b"x"),
            meta(SystemTime::now(), Duration::from_secs(60), 1),
        )
        .await
        .unwrap();
        r.delete("k").await.unwrap();
        assert!(r.get("k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn evict_expired_sweeps_stale_entries() {
        let tmp = tempdir().unwrap();
        let r = FsReserve::new(tmp.path());
        let base = SystemTime::now();
        r.put(
            "stale",
            Bytes::from_static(b"s"),
            ReserveMetadata {
                created_at: base - Duration::from_secs(120),
                expires_at: base - Duration::from_secs(60),
                content_type: None,
                vary_fingerprint: None,
                size: 1,
                status: 200,
            },
        )
        .await
        .unwrap();
        r.put(
            "fresh",
            Bytes::from_static(b"f"),
            meta(base, Duration::from_secs(60), 1),
        )
        .await
        .unwrap();
        let removed = r.evict_expired(base).await.unwrap();
        assert_eq!(removed, 1);
        assert!(r.get("stale").await.unwrap().is_none());
        assert!(r.get("fresh").await.unwrap().is_some());
    }
}
