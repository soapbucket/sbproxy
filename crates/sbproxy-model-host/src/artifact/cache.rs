// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Content-addressed artifact cache, verification, locks, and finalization.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ArtifactError;
use crate::{ArtifactFile, ArtifactFormat, OperationJob, ResolvedArtifact, SupportLevel};

const METADATA_SCHEMA_VERSION: u32 = 1;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Durable verified-artifact metadata. It intentionally contains no credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCacheMetadata {
    /// Metadata schema version.
    pub schema_version: u32,
    /// Canonical catalog artifact digest.
    pub artifact_digest: String,
    /// Catalog revision used for resolution.
    pub catalog_revision: String,
    /// Logical model ID.
    pub logical_model: String,
    /// Exact variant ID.
    pub variant_id: String,
    /// Artifact format.
    pub format: ArtifactFormat,
    /// Quantization name.
    pub quant: String,
    /// Exact source without credentials.
    pub source: String,
    /// Exact source revision.
    pub revision: String,
    /// Exact verified files.
    pub files: Vec<ArtifactFile>,
    /// Total verified bytes.
    pub total_size_bytes: u64,
    /// Maximum model context.
    pub context_length: u64,
    /// Model license.
    pub license: String,
    /// Catalog support level.
    pub stability: SupportLevel,
    /// Logical-model pickle opt-in captured at resolution.
    pub pickle_allowed: bool,
    /// Trust classification for managed v2 artifacts.
    pub trust: String,
    /// Initial finalization timestamp as Unix milliseconds.
    pub created_at_ms: u64,
    /// Most recent fully verified access as Unix milliseconds.
    pub last_accessed_ms: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct LegacyArtifactMetadata<'a> {
    pub(crate) schema_version: u32,
    pub(crate) identity_digest: &'a str,
    pub(crate) source: &'a str,
    pub(crate) revision: &'a str,
    pub(crate) file: &'a str,
    pub(crate) sha256: Option<&'a str>,
    pub(crate) size_bytes: u64,
    pub(crate) trust: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResumeMetadata {
    schema_version: u32,
    url: String,
    etag: Option<String>,
    expected_sha256: String,
    expected_size: u64,
    completed_bytes: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ResumeState {
    pub(crate) offset: u64,
    pub(crate) etag: Option<String>,
}

impl ArtifactCacheMetadata {
    fn from_artifact(
        artifact: &ResolvedArtifact,
        created_at_ms: u64,
    ) -> Result<Self, ArtifactError> {
        Ok(Self {
            schema_version: METADATA_SCHEMA_VERSION,
            artifact_digest: artifact.artifact_digest.clone(),
            catalog_revision: artifact.catalog_revision.clone(),
            logical_model: artifact.logical_model.clone(),
            variant_id: artifact.variant_id.clone(),
            format: artifact.format,
            quant: artifact.quant.clone(),
            source: artifact.source.clone(),
            revision: artifact.revision.clone(),
            files: artifact.files.clone(),
            total_size_bytes: total_size(&artifact.files)?,
            context_length: artifact.context_length,
            license: artifact.license.clone(),
            stability: artifact.stability,
            pickle_allowed: artifact.pickle_allowed,
            trust: "verified".to_string(),
            created_at_ms,
            last_accessed_ms: created_at_ms,
        })
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != METADATA_SCHEMA_VERSION {
            return Err(format!(
                "unsupported artifact metadata schema {}",
                self.schema_version
            ));
        }
        validate_digest(&self.artifact_digest).map_err(|error| error.to_string())?;
        if self.catalog_revision.trim().is_empty()
            || self.logical_model.trim().is_empty()
            || self.variant_id.trim().is_empty()
            || self.source.trim().is_empty()
            || self.revision.trim().is_empty()
            || self.trust != "verified"
        {
            return Err("artifact metadata has incomplete identity fields".to_string());
        }
        let expected_total = total_size(&self.files).map_err(|error| error.to_string())?;
        if expected_total != self.total_size_bytes {
            return Err(format!(
                "artifact metadata total is {}, declared files total {expected_total}",
                self.total_size_bytes
            ));
        }
        validate_files(&self.files).map_err(|error| error.to_string())?;
        if self.last_accessed_ms < self.created_at_ms {
            return Err("artifact last access precedes creation".to_string());
        }
        Ok(())
    }

    fn matches_artifact(&self, artifact: &ResolvedArtifact) -> bool {
        self.artifact_digest == artifact.artifact_digest
            && self.catalog_revision == artifact.catalog_revision
            && self.logical_model == artifact.logical_model
            && self.variant_id == artifact.variant_id
            && self.format == artifact.format
            && self.quant == artifact.quant
            && self.source == artifact.source
            && self.revision == artifact.revision
            && self.files == artifact.files
            && self.context_length == artifact.context_length
            && self.license == artifact.license
            && self.stability == artifact.stability
            && self.pickle_allowed == artifact.pickle_allowed
    }

    fn same_immutable_identity(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.artifact_digest == other.artifact_digest
            && self.catalog_revision == other.catalog_revision
            && self.logical_model == other.logical_model
            && self.variant_id == other.variant_id
            && self.format == other.format
            && self.quant == other.quant
            && self.source == other.source
            && self.revision == other.revision
            && self.files == other.files
            && self.total_size_bytes == other.total_size_bytes
            && self.context_length == other.context_length
            && self.license == other.license
            && self.stability == other.stability
            && self.pickle_allowed == other.pickle_allowed
            && self.trust == other.trust
            && self.created_at_ms == other.created_at_ms
    }
}

/// Public inspection result for one artifact digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactCacheState {
    /// No ready metadata, snapshot, or partial exists.
    Missing,
    /// Safe but not yet ready partial bytes exist.
    Partial {
        /// Bytes retained under the partial directory.
        completed_bytes: u64,
    },
    /// Every declared snapshot file was rehashed successfully.
    Ready {
        /// Verified snapshot directory.
        snapshot_path: PathBuf,
        /// Exact total bytes.
        total_size_bytes: u64,
        /// Most recent verified access timestamp.
        last_accessed_ms: u64,
    },
    /// Ready-looking cache state failed validation.
    Corrupt {
        /// Actionable validation failure without secrets.
        reason: String,
    },
}

/// Verified local artifact returned to a managed engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyArtifact {
    /// Canonical artifact digest.
    pub artifact_digest: String,
    /// Immutable local snapshot directory.
    pub snapshot_path: PathBuf,
    /// Declared relative paths mapped to verified local files.
    pub files: BTreeMap<String, PathBuf>,
    /// Durable cache metadata.
    pub metadata: ArtifactCacheMetadata,
    /// Durable operation job for this ensure call, including cache hits.
    pub job: OperationJob,
}

impl ReadyArtifact {
    /// Resolve one declared relative file in this verified snapshot.
    pub fn file(&self, relative_path: &str) -> Option<&Path> {
        self.files.get(relative_path).map(PathBuf::as_path)
    }

    pub(crate) fn new(root: &Path, metadata: ArtifactCacheMetadata, job: OperationJob) -> Self {
        let snapshot_path = root.join("snapshots").join(&metadata.artifact_digest);
        let files = metadata
            .files
            .iter()
            .map(|file| (file.path.clone(), snapshot_path.join(&file.path)))
            .collect();
        Self {
            artifact_digest: metadata.artifact_digest.clone(),
            snapshot_path,
            files,
            metadata,
            job,
        }
    }
}

#[derive(Debug)]
pub(crate) enum CacheLookup {
    Missing,
    Partial(u64),
    Ready(Box<ArtifactCacheMetadata>),
    Corrupt(String),
}

/// Keeps an artifact-specific exclusive file lock alive.
pub(crate) struct ArtifactLockGuard {
    _file: File,
}

#[derive(Debug, Clone)]
pub(crate) struct ArtifactCache {
    root: PathBuf,
}

impl ArtifactCache {
    pub(crate) fn open(root: impl Into<PathBuf>) -> Result<Self, ArtifactError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(ArtifactError::InvalidArtifact(
                "artifact cache root must not be empty".to_string(),
            ));
        }
        for directory in ["blobs/sha256", "snapshots", "metadata", "partials", "locks"] {
            let path = root.join(directory);
            fs::create_dir_all(&path)
                .map_err(|source| io_error("create artifact cache directory", &path, source))?;
        }
        Ok(Self { root })
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn lock_artifact(&self, digest: &str) -> Result<ArtifactLockGuard, ArtifactError> {
        validate_digest(digest)?;
        let path = self.root.join("locks").join(format!("{digest}.lock"));
        let file = open_lock(&path)?;
        FileExt::lock_exclusive(&file)
            .map_err(|source| io_error("lock artifact", &path, source))?;
        Ok(ArtifactLockGuard { _file: file })
    }

    pub(crate) fn inspect(&self, digest: &str) -> Result<ArtifactCacheState, ArtifactError> {
        Ok(match self.lookup(digest)? {
            CacheLookup::Missing => ArtifactCacheState::Missing,
            CacheLookup::Partial(completed_bytes) => {
                ArtifactCacheState::Partial { completed_bytes }
            }
            CacheLookup::Ready(metadata) => ArtifactCacheState::Ready {
                snapshot_path: self.root.join("snapshots").join(digest),
                total_size_bytes: metadata.total_size_bytes,
                last_accessed_ms: metadata.last_accessed_ms,
            },
            CacheLookup::Corrupt(reason) => ArtifactCacheState::Corrupt { reason },
        })
    }

    pub(crate) fn lookup_for(
        &self,
        artifact: &ResolvedArtifact,
    ) -> Result<CacheLookup, ArtifactError> {
        match self.lookup(&artifact.artifact_digest)? {
            CacheLookup::Ready(mut metadata) => {
                if !metadata.matches_artifact(artifact) {
                    return Ok(CacheLookup::Corrupt(
                        "ready metadata identity differs from the requested artifact".to_string(),
                    ));
                }
                metadata.last_accessed_ms = now_ms()?;
                self.write_metadata(&metadata)?;
                Ok(CacheLookup::Ready(metadata))
            }
            other => Ok(other),
        }
    }

    fn lookup(&self, digest: &str) -> Result<CacheLookup, ArtifactError> {
        validate_digest(digest)?;
        let metadata_path = self.metadata_path(digest);
        let snapshot_path = self.root.join("snapshots").join(digest);
        if !metadata_path.exists() {
            if snapshot_path.exists() {
                return Ok(CacheLookup::Corrupt(
                    "snapshot exists without ready metadata".to_string(),
                ));
            }
            let partial_bytes = directory_part_bytes(&self.partial_root(digest))?;
            return Ok(if partial_bytes == 0 {
                CacheLookup::Missing
            } else {
                CacheLookup::Partial(partial_bytes)
            });
        }

        let metadata = match read_json::<ArtifactCacheMetadata>(&metadata_path) {
            Ok(metadata) => metadata,
            Err(error) => return Ok(CacheLookup::Corrupt(error.to_string())),
        };
        if let Err(reason) = metadata.validate() {
            return Ok(CacheLookup::Corrupt(reason));
        }
        if metadata.artifact_digest != digest {
            return Ok(CacheLookup::Corrupt(
                "metadata digest differs from its filename".to_string(),
            ));
        }
        let snapshot_metadata = match fs::symlink_metadata(&snapshot_path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Ok(CacheLookup::Corrupt(format!(
                    "read snapshot directory metadata: {error}"
                )))
            }
        };
        if snapshot_metadata.file_type().is_symlink() || !snapshot_metadata.is_dir() {
            return Ok(CacheLookup::Corrupt(
                "ready metadata snapshot is missing, not a directory, or a symbolic link"
                    .to_string(),
            ));
        }
        let snapshot_manifest_path = snapshot_path.join("artifact.json");
        let snapshot_manifest = match read_json::<ArtifactCacheMetadata>(&snapshot_manifest_path) {
            Ok(manifest) => manifest,
            Err(error) => return Ok(CacheLookup::Corrupt(error.to_string())),
        };
        if !metadata.same_immutable_identity(&snapshot_manifest) {
            return Ok(CacheLookup::Corrupt(
                "snapshot artifact.json identity differs from ready metadata".to_string(),
            ));
        }
        for file in &metadata.files {
            if let Err(error) = verify_snapshot_file(&snapshot_path, file) {
                return Ok(CacheLookup::Corrupt(error.to_string()));
            }
        }
        Ok(CacheLookup::Ready(Box::new(metadata)))
    }

    pub(crate) fn partial_path(&self, digest: &str, relative: &str) -> PathBuf {
        let base = self.partial_root(digest).join(relative);
        append_suffix(&base, ".part")
    }

    pub(crate) fn resume_state(
        &self,
        digest: &str,
        file: &ArtifactFile,
        url: &str,
    ) -> Result<ResumeState, ArtifactError> {
        let partial = self.partial_path(digest, &file.path);
        let resume = self.resume_path(digest, &file.path);
        let partial_exists = partial.exists();
        let resume_exists = resume.exists();
        if !partial_exists && !resume_exists {
            return Ok(ResumeState {
                offset: 0,
                etag: None,
            });
        }
        if !partial_exists || !resume_exists {
            self.discard_partial_file(digest, &file.path)?;
            return Ok(ResumeState {
                offset: 0,
                etag: None,
            });
        }
        let metadata = match read_json::<ResumeMetadata>(&resume) {
            Ok(metadata) => metadata,
            Err(_) => {
                self.discard_partial_file(digest, &file.path)?;
                return Ok(ResumeState {
                    offset: 0,
                    etag: None,
                });
            }
        };
        let partial_metadata = fs::symlink_metadata(&partial)
            .map_err(|source| io_error("read artifact partial metadata", &partial, source))?;
        if partial_metadata.file_type().is_symlink() || !partial_metadata.is_file() {
            return Err(ArtifactError::CacheCorrupt {
                digest: digest.to_string(),
                reason: format!("artifact partial '{}' is not a regular file", file.path),
            });
        }
        let actual_size = partial_metadata.len();
        let valid = metadata.schema_version == 1
            && metadata.url == url
            && metadata.expected_sha256 == file.sha256
            && metadata.expected_size == file.size_bytes
            && metadata.completed_bytes == actual_size
            && metadata.completed_bytes <= file.size_bytes
            && metadata
                .etag
                .as_deref()
                .is_some_and(|etag| !etag.is_empty());
        if !valid {
            self.discard_partial_file(digest, &file.path)?;
            return Ok(ResumeState {
                offset: 0,
                etag: None,
            });
        }
        Ok(ResumeState {
            offset: metadata.completed_bytes,
            etag: metadata.etag,
        })
    }

    pub(crate) fn write_resume(
        &self,
        digest: &str,
        file: &ArtifactFile,
        url: &str,
        etag: Option<&str>,
        completed_bytes: u64,
    ) -> Result<(), ArtifactError> {
        let destination = self.resume_path(digest, &file.path);
        let parent = destination.parent().expect("resume metadata has parent");
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create artifact resume directory", parent, source))?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = append_suffix(
            &destination,
            &format!(".tmp.{}.{}", std::process::id(), sequence),
        );
        let metadata = ResumeMetadata {
            schema_version: 1,
            url: url.to_string(),
            etag: etag.map(str::to_string),
            expected_sha256: file.sha256.clone(),
            expected_size: file.size_bytes,
            completed_bytes,
        };
        let result = (|| {
            write_json_synced(&temporary, &metadata)?;
            fs::rename(&temporary, &destination).map_err(|source| {
                io_error("replace artifact resume metadata", &destination, source)
            })?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub(crate) fn discard_partial_file(
        &self,
        digest: &str,
        relative: &str,
    ) -> Result<(), ArtifactError> {
        for path in [
            self.partial_path(digest, relative),
            self.resume_path(digest, relative),
        ] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(io_error("discard artifact partial", &path, source));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_partial(
        &self,
        digest: &str,
        relative: &str,
    ) -> Result<PathBuf, ArtifactError> {
        validate_relative_path(relative)?;
        let path = self.partial_path(digest, relative);
        let parent = path.parent().expect("partial file always has a parent");
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create artifact partial directory", parent, source))?;
        if path.exists() {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("inspect artifact partial", &path, source))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ArtifactError::InvalidArtifact(format!(
                    "artifact partial '{}' is not a regular file",
                    path.display()
                )));
            }
        }
        Ok(path)
    }

    pub(crate) fn verify_and_promote(
        &self,
        artifact: &ResolvedArtifact,
    ) -> Result<(), ArtifactError> {
        for file in &artifact.files {
            let partial = self.partial_path(&artifact.artifact_digest, &file.path);
            verify_file(&partial, file)?;
            self.promote_blob(&partial, file)?;
            let resume = self.resume_path(&artifact.artifact_digest, &file.path);
            match fs::remove_file(&resume) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(io_error("remove artifact resume metadata", &resume, source));
                }
            }
        }
        Ok(())
    }

    fn promote_blob(&self, partial: &Path, file: &ArtifactFile) -> Result<(), ArtifactError> {
        let blob = self.root.join("blobs/sha256").join(&file.sha256);
        let lock_path = self
            .root
            .join("locks")
            .join(format!("blob-{}.lock", file.sha256));
        let lock = open_lock(&lock_path)?;
        FileExt::lock_exclusive(&lock)
            .map_err(|source| io_error("lock artifact blob", &lock_path, source))?;
        if blob.exists() {
            verify_file(&blob, file)?;
            fs::remove_file(partial)
                .map_err(|source| io_error("remove duplicate artifact partial", partial, source))?;
            return Ok(());
        }
        set_readonly(partial)?;
        fs::rename(partial, &blob)
            .map_err(|source| io_error("finalize artifact blob", &blob, source))?;
        sync_directory(blob.parent().expect("blob has parent"))?;
        Ok(())
    }

    pub(crate) fn finalize_snapshot(
        &self,
        artifact: &ResolvedArtifact,
    ) -> Result<ArtifactCacheMetadata, ArtifactError> {
        let digest = &artifact.artifact_digest;
        let snapshots = self.root.join("snapshots");
        let final_path = snapshots.join(digest);
        if final_path.exists() {
            return Err(ArtifactError::CacheCorrupt {
                digest: digest.clone(),
                reason: "snapshot path already exists without a valid cache hit".to_string(),
            });
        }
        let staging = snapshots.join(format!(".staging-{digest}-{}", std::process::id()));
        if staging.exists() {
            fs::remove_dir_all(&staging)
                .map_err(|source| io_error("remove stale artifact staging", &staging, source))?;
        }
        fs::create_dir(&staging)
            .map_err(|source| io_error("create artifact staging", &staging, source))?;

        let result = (|| {
            let mut directories = BTreeSet::from([staging.clone()]);
            for file in &artifact.files {
                let blob = self.root.join("blobs/sha256").join(&file.sha256);
                verify_file(&blob, file)?;
                let target = staging.join(&file.path);
                let parent = target.parent().expect("snapshot file has a parent");
                fs::create_dir_all(parent).map_err(|source| {
                    io_error("create artifact snapshot directory", parent, source)
                })?;
                directories.insert(parent.to_path_buf());
                match fs::hard_link(&blob, &target) {
                    Ok(()) => {}
                    Err(error) if hard_link_fallback_allowed(&error) => {
                        fs::copy(&blob, &target).map_err(|source| {
                            io_error("copy artifact blob into snapshot", &target, source)
                        })?;
                        set_readonly(&target)?;
                        File::open(&target)
                            .and_then(|file| file.sync_all())
                            .map_err(|source| {
                                io_error("sync copied artifact snapshot file", &target, source)
                            })?;
                    }
                    Err(source) => {
                        return Err(io_error(
                            "link artifact blob into snapshot",
                            &target,
                            source,
                        ))
                    }
                }
            }
            let metadata = ArtifactCacheMetadata::from_artifact(artifact, now_ms()?)?;
            write_json_synced(&staging.join("artifact.json"), &metadata)?;
            for directory in directories.iter().rev() {
                sync_directory(directory)?;
            }
            fs::rename(&staging, &final_path)
                .map_err(|source| io_error("finalize artifact snapshot", &final_path, source))?;
            sync_directory(&snapshots)?;
            self.write_metadata(&metadata)?;
            Ok(metadata)
        })();
        if result.is_err() && staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    pub(crate) fn cleanup_staging(&self, digest: &str) {
        let staging = self
            .root
            .join("snapshots")
            .join(format!(".staging-{digest}-{}", std::process::id()));
        let _ = fs::remove_dir_all(staging);
    }

    pub(crate) fn remove_partials(&self, digest: &str) -> Result<(), ArtifactError> {
        let root = self.partial_root(digest);
        match fs::remove_dir_all(&root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(io_error("remove invalid artifact partials", &root, source)),
        }
    }

    pub(crate) fn finalize_legacy_file(
        &self,
        partial: &Path,
        destination: &Path,
        identity_digest: &str,
        metadata: &LegacyArtifactMetadata<'_>,
    ) -> Result<(), ArtifactError> {
        let parent = destination.parent().ok_or_else(|| {
            ArtifactError::InvalidArtifact(
                "legacy artifact destination has no parent directory".to_string(),
            )
        })?;
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create legacy artifact directory", parent, source))?;
        fs::rename(partial, destination)
            .map_err(|source| io_error("finalize legacy artifact file", destination, source))?;
        sync_directory(parent)?;
        self.write_legacy_metadata(identity_digest, metadata)
    }

    pub(crate) fn write_legacy_metadata(
        &self,
        identity_digest: &str,
        metadata: &LegacyArtifactMetadata<'_>,
    ) -> Result<(), ArtifactError> {
        validate_digest(identity_digest)?;
        let metadata_dir = self.root.join("metadata");
        let destination = metadata_dir.join(format!("legacy-{identity_digest}.json"));
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = metadata_dir.join(format!(
            ".legacy-{identity_digest}.json.tmp.{}.{}",
            std::process::id(),
            sequence
        ));
        let result = (|| {
            write_json_synced(&temporary, metadata)?;
            fs::rename(&temporary, &destination).map_err(|source| {
                io_error("replace legacy artifact metadata", &destination, source)
            })?;
            sync_directory(&metadata_dir)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn partial_root(&self, digest: &str) -> PathBuf {
        self.root.join("partials").join(digest)
    }

    fn resume_path(&self, digest: &str, relative: &str) -> PathBuf {
        let base = self.partial_root(digest).join(relative);
        append_suffix(&base, ".resume.json")
    }

    fn metadata_path(&self, digest: &str) -> PathBuf {
        self.root.join("metadata").join(format!("{digest}.json"))
    }

    fn write_metadata(&self, metadata: &ArtifactCacheMetadata) -> Result<(), ArtifactError> {
        let destination = self.metadata_path(&metadata.artifact_digest);
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self.root.join("metadata").join(format!(
            ".{}.json.tmp.{}.{}",
            metadata.artifact_digest,
            std::process::id(),
            sequence
        ));
        let result = (|| {
            write_json_synced(&temporary, metadata)?;
            fs::rename(&temporary, &destination)
                .map_err(|source| io_error("replace artifact metadata", &destination, source))?;
            sync_directory(destination.parent().expect("metadata has parent"))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

pub(crate) fn validate_resolved_artifact(artifact: &ResolvedArtifact) -> Result<(), ArtifactError> {
    validate_digest(&artifact.artifact_digest)?;
    if artifact.catalog_revision.trim().is_empty()
        || artifact.logical_model.trim().is_empty()
        || artifact.variant_id.trim().is_empty()
        || artifact.source.trim().is_empty()
        || artifact.revision.trim().is_empty()
    {
        return Err(ArtifactError::InvalidArtifact(
            "resolved artifact has incomplete identity fields".to_string(),
        ));
    }
    validate_files(&artifact.files)?;
    total_size(&artifact.files)?;
    if artifact.format == ArtifactFormat::Pickle && !artifact.pickle_allowed {
        return Err(ArtifactError::PickleRefused {
            model: artifact.logical_model.clone(),
        });
    }
    Ok(())
}

fn validate_files(files: &[ArtifactFile]) -> Result<(), ArtifactError> {
    if files.is_empty() {
        return Err(ArtifactError::InvalidArtifact(
            "resolved artifact has no files".to_string(),
        ));
    }
    let mut paths = BTreeSet::new();
    for file in files {
        validate_relative_path(&file.path)?;
        if !paths.insert(file.path.as_str()) {
            return Err(ArtifactError::InvalidArtifact(format!(
                "resolved artifact repeats file path '{}'",
                file.path
            )));
        }
        validate_digest(&file.sha256)?;
        if file.size_bytes == 0 {
            return Err(ArtifactError::InvalidArtifact(format!(
                "resolved artifact file '{}' has zero size",
                file.path
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_relative_path(path: &str) -> Result<(), ArtifactError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('?')
        || path.contains('#')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(ArtifactError::InvalidArtifact(format!(
            "artifact file path '{path}' is not a safe relative path"
        )));
    }
    Ok(())
}

pub(crate) fn validate_digest(digest: &str) -> Result<(), ArtifactError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ArtifactError::InvalidArtifact(
            "artifact digest must be 64 hexadecimal characters".to_string(),
        ));
    }
    Ok(())
}

fn total_size(files: &[ArtifactFile]) -> Result<u64, ArtifactError> {
    files.iter().try_fold(0u64, |total, file| {
        total.checked_add(file.size_bytes).ok_or_else(|| {
            ArtifactError::InvalidArtifact("artifact total size overflows u64".to_string())
        })
    })
}

fn verify_file(path: &Path, expected: &ArtifactFile) -> Result<(), ArtifactError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("read artifact file metadata", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ArtifactError::InvalidArtifact(format!(
            "artifact file '{}' is not a regular file",
            path.display()
        )));
    }
    if metadata.len() != expected.size_bytes {
        return Err(ArtifactError::SizeMismatch {
            file: expected.path.clone(),
            expected: expected.size_bytes,
            actual: metadata.len(),
        });
    }
    let actual = hash_file(path)?;
    if !actual.eq_ignore_ascii_case(&expected.sha256) {
        return Err(ArtifactError::DigestMismatch {
            file: expected.path.clone(),
            expected: expected.sha256.clone(),
            actual,
        });
    }
    Ok(())
}

fn verify_snapshot_file(root: &Path, expected: &ArtifactFile) -> Result<(), ArtifactError> {
    let mut current = root.to_path_buf();
    let components: Vec<_> = Path::new(&expected.path).components().collect();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|source| io_error("inspect artifact snapshot path", &current, source))?;
        if metadata.file_type().is_symlink() {
            return Err(ArtifactError::InvalidArtifact(format!(
                "artifact snapshot path '{}' contains a symbolic link",
                current.display()
            )));
        }
        if index + 1 < components.len() && !metadata.is_dir() {
            return Err(ArtifactError::InvalidArtifact(format!(
                "artifact snapshot parent '{}' is not a directory",
                current.display()
            )));
        }
    }
    verify_file(&current, expected)
}

pub(crate) fn hash_file(path: &Path) -> Result<String, ArtifactError> {
    let mut file =
        File::open(path).map_err(|source| io_error("open artifact file", path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("hash artifact file", path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn open_lock(path: &Path) -> Result<File, ArtifactError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| io_error("open artifact lock", path, source))
}

fn set_readonly(path: &Path) -> Result<(), ArtifactError> {
    let mut permissions = fs::metadata(path)
        .map_err(|source| io_error("read artifact permissions", path, source))?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
        .map_err(|source| io_error("set artifact read-only", path, source))
}

fn hard_link_fallback_allowed(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Unsupported
        || matches!(error.raw_os_error(), Some(1 | 18 | 38 | 95))
}

fn write_json_synced<T: Serialize>(path: &Path, value: &T) -> Result<(), ArtifactError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| ArtifactError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create artifact JSON", path, source))?;
    file.write_all(&bytes)
        .map_err(|source| io_error("write artifact JSON", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync artifact JSON", path, source))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ArtifactError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect artifact JSON", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ArtifactError::CacheCorrupt {
            digest: path.display().to_string(),
            reason: "artifact JSON is not a regular file".to_string(),
        });
    }
    let bytes = fs::read(path).map_err(|source| io_error("read artifact JSON", path, source))?;
    serde_json::from_slice(&bytes).map_err(|error| ArtifactError::CacheCorrupt {
        digest: path.display().to_string(),
        reason: format!("parse artifact JSON: {error}"),
    })
}

fn directory_part_bytes(path: &Path) -> Result<u64, ArtifactError> {
    if !path.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|source| io_error("list artifact partials", &directory, source))?
        {
            let entry = entry
                .map_err(|source| io_error("read artifact partial entry", &directory, source))?;
            let path = entry.path();
            let metadata = entry
                .metadata()
                .map_err(|source| io_error("read artifact partial metadata", &path, source))?;
            if metadata.is_dir() {
                pending.push(path);
            } else if path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.ends_with(".part"))
            {
                total = total.checked_add(metadata.len()).ok_or_else(|| {
                    ArtifactError::InvalidArtifact("partial byte total overflows u64".to_string())
                })?;
            }
        }
    }
    Ok(total)
}

fn now_ms() -> Result<u64, ArtifactError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ArtifactError::Clock(error.to_string()))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| ArtifactError::Clock("Unix millisecond timestamp overflow".to_string()))
}

fn sync_directory(path: &Path) -> Result<(), ArtifactError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync artifact directory", path, source))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> ArtifactError {
    ArtifactError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
