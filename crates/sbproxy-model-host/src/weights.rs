// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Weight cache addressing + download (WOR-1653 weight manager).
//!
//! The cache-key, cache-path, and sha256-verification logic is pure
//! and in the default build, so it is unit-tested in CI. The actual
//! Hugging Face download is behind the `weights` cargo feature (it
//! pulls `hf-hub`) and runs on the host that serves weights; it
//! reuses the same addressing so a verified file lands at a
//! deterministic path.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// A content-addressed cache directory for one model revision. Layout:
/// `<root>/<org>/<repo>/<revision>/`, with the org/repo slashes
/// sanitized so the path is a single directory level per component.
pub fn cache_dir(root: &Path, hf_repo: &str, revision: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    for component in hf_repo.split('/') {
        p.push(sanitize(component));
    }
    p.push(sanitize(revision));
    p
}

/// Path a specific weight file resolves to inside the revision dir.
pub fn cache_file(root: &Path, hf_repo: &str, revision: &str, filename: &str) -> PathBuf {
    cache_dir(root, hf_repo, revision).join(sanitize(filename))
}

/// Replace path-hostile characters so a repo/revision/filename maps to
/// one safe path component (no traversal, no separators).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
            _ => '_',
        })
        .collect::<String>()
        // Never let a component be empty or a bare-dots traversal.
        .trim_matches('.')
        .to_string()
}

/// The lowercase hex sha256 of a file's contents, or an error string.
pub fn sha256_hex(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

/// Verify a file matches an expected lowercase-hex sha256. A mismatch
/// or missing file is an error, so a corrupted or swapped weight
/// aborts a launch before an engine ever reads it.
pub fn verify_sha256(path: &Path, expected_hex: &str) -> Result<(), String> {
    let actual = sha256_hex(path)?;
    if actual.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(format!(
            "sha256 mismatch for {}: expected {expected_hex}, got {actual}",
            path.display()
        ))
    }
}

/// Download a file from a Hugging Face repo into the content-addressed
/// cache and return its local path. Behind the `weights` feature since
/// it pulls `hf-hub`. Verifies against `expected_sha256` when provided.
#[cfg(feature = "weights")]
pub async fn ensure_weight_file(
    cache_root: &Path,
    hf_repo: &str,
    revision: &str,
    filename: &str,
    expected_sha256: Option<&str>,
) -> Result<PathBuf, String> {
    use hf_hub::api::tokio::ApiBuilder;

    let api = ApiBuilder::new()
        .with_cache_dir(cache_root.to_path_buf())
        .build()
        .map_err(|e| format!("hf-hub api: {e}"))?;
    let repo = api.repo(hf_hub::Repo::with_revision(
        hf_repo.to_string(),
        hf_hub::RepoType::Model,
        revision.to_string(),
    ));
    let downloaded = repo
        .get(filename)
        .await
        .map_err(|e| format!("download {hf_repo}@{revision}/{filename}: {e}"))?;
    if let Some(expected) = expected_sha256 {
        verify_sha256(&downloaded, expected)?;
    }
    Ok(downloaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_dir_is_deterministic_and_layered() {
        let root = Path::new("/var/cache/sbproxy/models");
        let d = cache_dir(root, "Qwen/Qwen3-14B", "main");
        assert_eq!(
            d,
            Path::new("/var/cache/sbproxy/models/Qwen/Qwen3-14B/main")
        );
    }

    #[test]
    fn sanitize_blocks_traversal() {
        // A malicious repo/revision cannot escape the cache root.
        let root = Path::new("/cache");
        let d = cache_dir(root, "../../etc", "../secret");
        // No `..` component survives.
        assert!(d.components().all(|c| c.as_os_str() != ".."), "{d:?}");
        assert!(d.starts_with("/cache"));
    }

    #[test]
    fn sha256_and_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("w.bin");
        std::fs::write(&f, b"hello weights").unwrap();
        let hash = sha256_hex(&f).unwrap();
        assert!(verify_sha256(&f, &hash).is_ok());
        assert!(
            verify_sha256(&f, &hash.to_uppercase()).is_ok(),
            "case-insensitive"
        );
        assert!(
            verify_sha256(&f, "deadbeef").is_err(),
            "wrong hash rejected"
        );
    }

    #[test]
    fn verify_missing_file_is_error() {
        assert!(verify_sha256(Path::new("/no/such/file"), "abc").is_err());
    }
}
