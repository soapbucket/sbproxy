// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Serve-time reuse of weights other local tools already cached
//! (WOR-1863).
//!
//! [`crate::foreign_cache::discover`] finds the weight files Ollama,
//! LM Studio, and the Hugging Face hub keep on disk. When an ensure
//! call misses the verified cache, every discovered candidate whose
//! byte size matches a declared [`ArtifactFile`] is stream-hashed with
//! SHA-256; an exact digest match is hardlinked (copied when the link
//! fails, for example across devices) into the same partial staging
//! location a network download would use. The unchanged verify and
//! promote path then re-checks size and digest before the atomic
//! promote, so an import upholds every invariant a download does.
//!
//! The foreign cache stays owned by the foreign tool: candidates are
//! opened only for reading and are never renamed or deleted. The one
//! observable side effect is that a hardlinked blob becomes read-only
//! when the shared inode is promoted, which matches how the foreign
//! tools treat their own content-addressed blobs. A hardlinked blob
//! also shares its inode with the foreign file, so a foreign tool
//! rewriting it in place would change our blob too; the cache rehashes
//! every snapshot file on lookup, so such tampering is detected, and
//! the read-only bit set at promote blocks it in the common case.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::cache::{hash_file, ArtifactCache};
use super::{io_error, ArtifactError};
use crate::foreign_cache::ForeignModelFile;
use crate::{ArtifactFile, ResolvedArtifact};

/// The home directory foreign caches are discovered under: `$HOME`,
/// falling back to `%USERPROFILE%` on Windows, matching the doctor's
/// resolution. `None` skips the foreign-cache attempt entirely.
pub(crate) fn foreign_scan_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Stage every declared file of `artifact` that a foreign cache can
/// satisfy, returning the relative paths staged. Candidates are
/// filtered by exact size and confirmed by streaming SHA-256 before
/// any staging happens; a file with no confirmed candidate is simply
/// left for the caller's network path. `candidates` comes from one
/// [`crate::foreign_cache::discover`] scan per ensure call.
pub(crate) fn import_foreign_candidates(
    cache: &ArtifactCache,
    artifact: &ResolvedArtifact,
    candidates: &[ForeignModelFile],
) -> Result<BTreeSet<String>, ArtifactError> {
    let mut imported = BTreeSet::new();
    for file in &artifact.files {
        let sized = candidates
            .iter()
            .filter(|candidate| candidate.size_bytes == file.size_bytes);
        for candidate in sized {
            if stage_foreign_source(cache, &artifact.artifact_digest, file, &candidate.path)? {
                tracing::info!(
                    "reused {} from {} cache (digest verified)",
                    candidate.path.display(),
                    candidate.source.label()
                );
                imported.insert(file.path.clone());
                break;
            }
        }
    }
    Ok(imported)
}

/// Stage one foreign-cache `candidate_path` as the partial for
/// `artifact_file` under `artifact_digest`.
///
/// The candidate is stream-hashed with SHA-256 first: `Ok(false)` on a
/// size or digest mismatch, and also when the candidate cannot be
/// resolved or read, so the caller falls back to the network. On a
/// digest match the resolved file is hardlinked (copied when the link
/// fails) into the exact partial location a download would fill, and
/// the existing verify-and-promote path re-checks size and digest
/// before the atomic promote. The foreign file is opened only for
/// reading and is never renamed or deleted.
pub(crate) fn stage_foreign_source(
    cache: &ArtifactCache,
    artifact_digest: &str,
    artifact_file: &ArtifactFile,
    candidate_path: &Path,
) -> Result<bool, ArtifactError> {
    // Resolve through an HF-style snapshot symlink so both the hash
    // and the hardlink target the real blob; an unresolvable or
    // unreadable candidate falls back to the network instead of
    // failing the ensure call.
    let Ok(resolved) = fs::canonicalize(candidate_path) else {
        return Ok(false);
    };
    let Ok(metadata) = fs::symlink_metadata(&resolved) else {
        return Ok(false);
    };
    if !metadata.is_file() || metadata.len() != artifact_file.size_bytes {
        return Ok(false);
    }
    let Ok(actual) = hash_file(&resolved) else {
        return Ok(false);
    };
    if !actual.eq_ignore_ascii_case(&artifact_file.sha256) {
        return Ok(false);
    }
    let partial = cache.prepare_partial(artifact_digest, &artifact_file.path)?;
    // A stale partial from an interrupted download would collide with
    // the hardlink; the digest-confirmed candidate replaces it and any
    // resume metadata wholesale.
    cache.discard_partial_file(artifact_digest, &artifact_file.path)?;
    link_or_copy(&resolved, &partial)?;
    Ok(true)
}

/// Hardlink `source` at `destination`, falling back to a synced full
/// copy when the link fails (cross-device caches, filesystems without
/// hardlink support). The source is only read, never modified.
fn link_or_copy(source: &Path, destination: &Path) -> Result<(), ArtifactError> {
    if fs::hard_link(source, destination).is_ok() {
        return Ok(());
    }
    copy_synced(source, destination)
}

/// Copy `source` to `destination` and fsync the copy so the staged
/// bytes are durable before verification runs.
fn copy_synced(source: &Path, destination: &Path) -> Result<(), ArtifactError> {
    fs::copy(source, destination)
        .map_err(|error| io_error("copy foreign cache file", destination, error))?;
    fs::File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error("sync copied foreign cache file", destination, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    use crate::foreign_cache::ForeignCacheSource;
    use crate::{ArtifactFormat, EngineKind, SupportLevel};

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// Minimal valid resolved artifact whose declared files carry the
    /// real digests and sizes of `files`' bytes.
    fn artifact_for(digest_byte: char, files: Vec<(&str, &[u8])>) -> ResolvedArtifact {
        ResolvedArtifact {
            catalog_revision: "import-fixture".to_string(),
            logical_model: "fixture".to_string(),
            variant_id: "exact".to_string(),
            artifact_digest: digest_byte.to_string().repeat(64),
            format: ArtifactFormat::Gguf,
            quant: "fixture".to_string(),
            engine: EngineKind::LlamaCpp,
            source: "hf:Fixture/Import".to_string(),
            revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
            files: files
                .into_iter()
                .map(|(path, bytes)| ArtifactFile {
                    path: path.to_string(),
                    sha256: sha256_hex(bytes),
                    size_bytes: bytes.len() as u64,
                })
                .collect(),
            context_length: 4096,
            license: "apache-2.0".to_string(),
            stability: SupportLevel::Preview,
            pickle_allowed: false,
            modality: Default::default(),
        }
    }

    #[test]
    fn digest_match_imports_via_hardlink_and_survives_verify_and_promote() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ArtifactCache::open(dir.path().join("cache")).unwrap();
        let bytes = b"foreign gguf weights";
        let foreign = dir.path().join("foreign-blob");
        fs::write(&foreign, bytes).unwrap();
        let artifact = artifact_for('a', vec![("model.gguf", bytes.as_slice())]);
        let file = &artifact.files[0];

        assert!(stage_foreign_source(&cache, &artifact.artifact_digest, file, &foreign).unwrap());
        let partial = cache.partial_path(&artifact.artifact_digest, &file.path);
        assert!(partial.is_file(), "staged into the download's partial path");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                fs::metadata(&partial).unwrap().ino(),
                fs::metadata(&foreign).unwrap().ino(),
                "same-device staging is a hardlink, not a copy"
            );
        }

        // The unchanged verify+promote path accepts the staged file.
        cache.verify_and_promote(&artifact).unwrap();
        let blob = dir.path().join("cache/blobs/sha256").join(&file.sha256);
        assert_eq!(fs::read(&blob).unwrap(), bytes);
        // The foreign file is untouched: same path, identical bytes.
        assert_eq!(fs::read(&foreign).unwrap(), bytes);
    }

    #[test]
    fn digest_mismatch_returns_false_and_stages_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ArtifactCache::open(dir.path().join("cache")).unwrap();
        // Same length, different bytes: passes the size filter, fails
        // the streamed digest.
        let foreign = dir.path().join("imposter-blob");
        fs::write(&foreign, b"BBBBBBBB").unwrap();
        let artifact = artifact_for('b', vec![("model.gguf", b"AAAAAAAA".as_slice())]);
        let file = &artifact.files[0];

        assert!(!stage_foreign_source(&cache, &artifact.artifact_digest, file, &foreign).unwrap());
        assert!(
            !cache
                .partial_path(&artifact.artifact_digest, &file.path)
                .exists(),
            "a rejected candidate must stage nothing"
        );
        // The foreign file is byte-identical after the rejected attempt.
        assert_eq!(fs::read(&foreign).unwrap(), b"BBBBBBBB");
    }

    #[test]
    fn link_or_copy_falls_back_to_a_full_copy_when_the_link_fails() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        fs::write(&source, b"copy me").unwrap();
        // An existing destination makes the hardlink fail the same way
        // a cross-device target would, driving the copy branch.
        let destination = dir.path().join("destination");
        fs::write(&destination, b"stale").unwrap();

        link_or_copy(&source, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"copy me");
        assert_eq!(fs::read(&source).unwrap(), b"copy me");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                fs::metadata(&destination).unwrap().nlink(),
                1,
                "the fallback is a copy, not a link"
            );
        }
    }

    #[test]
    fn import_foreign_candidates_stages_only_confirmed_files() {
        let dir = tempfile::tempdir().unwrap();
        let cache = ArtifactCache::open(dir.path().join("cache")).unwrap();
        let matched = b"shard one bytes";
        let foreign = dir.path().join("ollama-blob");
        fs::write(&foreign, matched).unwrap();
        // The second declared file has a different size, so the single
        // candidate never even gets hashed for it.
        let artifact = artifact_for(
            'c',
            vec![
                ("model-00001.gguf", matched.as_slice()),
                ("model-00002.gguf", b"shard two is only remote".as_slice()),
            ],
        );
        let candidates = vec![ForeignModelFile {
            source: ForeignCacheSource::Ollama,
            path: foreign.clone(),
            repo_or_name: "fixture:latest".to_string(),
            size_bytes: matched.len() as u64,
            format_hint: Some(ArtifactFormat::Gguf),
        }];

        let imported = import_foreign_candidates(&cache, &artifact, &candidates).unwrap();
        assert_eq!(
            imported.into_iter().collect::<Vec<_>>(),
            vec!["model-00001.gguf".to_string()]
        );
        assert!(cache
            .partial_path(&artifact.artifact_digest, "model-00001.gguf")
            .is_file());
        assert!(!cache
            .partial_path(&artifact.artifact_digest, "model-00002.gguf")
            .exists());
    }
}
