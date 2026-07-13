// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cross-process atomic store for admin-managed deployment revisions.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fs2::FileExt;

use crate::{DeploymentError, DeploymentRevision, DeploymentRevisionDraft, DeploymentSourceMode};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Durable compare-and-swap store failure.
#[derive(Debug, thiserror::Error)]
pub enum DeploymentStoreError {
    /// File operation failed.
    #[error("{operation} '{}': {source}", path.display())]
    Io {
        /// Concise operation name.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// Stored JSON could not be decoded.
    #[error("parse deployment store '{}': {source}", path.display())]
    Parse {
        /// Store path.
        path: PathBuf,
        /// JSON failure.
        #[source]
        source: serde_json::Error,
    },
    /// Candidate or stored revision violates the canonical contract.
    #[error(transparent)]
    Deployment(#[from] DeploymentError),
    /// This store accepts only admin-managed authority.
    #[error("deployment store accepts only admin_managed revisions, got {0:?}")]
    WrongSourceMode(DeploymentSourceMode),
    /// Optimistic revision no longer matches durable state.
    #[error("deployment revision conflict: expected {expected:?}, actual {actual:?}")]
    Conflict {
        /// Caller-observed revision, or none for initial creation.
        expected: Option<u64>,
        /// Current durable revision, or none when empty.
        actual: Option<u64>,
    },
    /// Revision counter cannot advance beyond `u64::MAX`.
    #[error("deployment revision counter overflow")]
    RevisionOverflow,
}

/// File-backed admin desired-state store with cross-process CAS.
#[derive(Debug, Clone)]
pub struct FileDeploymentRevisionStore {
    path: PathBuf,
    lock_path: PathBuf,
}

impl FileDeploymentRevisionStore {
    /// Open a store path, creating its parent directory when needed.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DeploymentStoreError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(DeploymentError::Invalid(
                "deployment store path must not be empty".to_string(),
            )
            .into());
        }
        let parent = parent_directory(&path);
        fs::create_dir_all(parent)
            .map_err(|source| io_error("create deployment store directory", parent, source))?;
        let mut lock_name: OsString = path.as_os_str().to_owned();
        lock_name.push(".lock");
        Ok(Self {
            path,
            lock_path: PathBuf::from(lock_name),
        })
    }

    /// Read and fully validate the current revision, if present.
    pub fn load(&self) -> Result<Option<DeploymentRevision>, DeploymentStoreError> {
        let lock = self.open_lock()?;
        FileExt::lock_shared(&lock)
            .map_err(|source| io_error("lock deployment store", &self.lock_path, source))?;
        self.load_unlocked()
    }

    /// Load the current revision and adopt `expected_catalog_revision` only
    /// when durable desired state is already empty.
    ///
    /// The rebase is a monotonic revision written under the same exclusive
    /// cross-process lock as compare-and-swap. A nonempty revision remains
    /// fail-closed so configured deployments can never be reinterpreted by a
    /// different catalog.
    pub fn load_or_rebase_empty_catalog(
        &self,
        expected_catalog_revision: &str,
    ) -> Result<Option<DeploymentRevision>, DeploymentStoreError> {
        if expected_catalog_revision.trim().is_empty() {
            return Err(DeploymentError::Invalid(
                "expected catalog revision must not be empty".to_string(),
            )
            .into());
        }
        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)
            .map_err(|source| io_error("lock deployment store", &self.lock_path, source))?;
        let Some(current) = self.load_unlocked()? else {
            return Ok(None);
        };
        if current.source_mode != DeploymentSourceMode::AdminManaged {
            return Err(DeploymentStoreError::WrongSourceMode(current.source_mode));
        }
        if current.catalog_revision == expected_catalog_revision {
            return Ok(Some(current));
        }
        if !current.deployments.is_empty() {
            return Err(DeploymentError::Invalid(format!(
                "stored catalog revision {:?} differs from active {:?} while deployments remain configured",
                current.catalog_revision, expected_catalog_revision
            ))
            .into());
        }
        let next_revision = current
            .revision
            .checked_add(1)
            .ok_or(DeploymentStoreError::RevisionOverflow)?;
        if next_revision > crate::MAX_SAFE_JSON_INTEGER {
            return Err(DeploymentStoreError::RevisionOverflow);
        }
        let rebased = DeploymentRevisionDraft {
            source_mode: DeploymentSourceMode::AdminManaged,
            source_revision: current.source_revision,
            catalog_revision: expected_catalog_revision.to_string(),
            deployments: current.deployments,
        }
        .into_revision(next_revision)?;
        self.write_atomic(&rebased)?;
        Ok(Some(rebased))
    }

    /// Atomically replace desired state when `expected_revision` still
    /// matches the durable revision.
    pub fn compare_and_swap(
        &self,
        expected_revision: Option<u64>,
        candidate: DeploymentRevisionDraft,
    ) -> Result<DeploymentRevision, DeploymentStoreError> {
        candidate.validate()?;
        if candidate.source_mode != DeploymentSourceMode::AdminManaged {
            return Err(DeploymentStoreError::WrongSourceMode(candidate.source_mode));
        }

        let lock = self.open_lock()?;
        FileExt::lock_exclusive(&lock)
            .map_err(|source| io_error("lock deployment store", &self.lock_path, source))?;
        let current = self.load_unlocked()?;
        let actual = current.as_ref().map(|revision| revision.revision);
        if expected_revision != actual {
            return Err(DeploymentStoreError::Conflict {
                expected: expected_revision,
                actual,
            });
        }
        let next_revision = actual
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(DeploymentStoreError::RevisionOverflow)?;
        if next_revision > crate::MAX_SAFE_JSON_INTEGER {
            return Err(DeploymentStoreError::RevisionOverflow);
        }
        let revision = candidate.into_revision(next_revision)?;
        self.write_atomic(&revision)?;
        Ok(revision)
    }

    fn open_lock(&self) -> Result<File, DeploymentStoreError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)
            .map_err(|source| io_error("open deployment store lock", &self.lock_path, source))
    }

    fn load_unlocked(&self) -> Result<Option<DeploymentRevision>, DeploymentStoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(io_error("read deployment store", &self.path, source)),
        };
        let revision: DeploymentRevision =
            serde_json::from_slice(&bytes).map_err(|source| DeploymentStoreError::Parse {
                path: self.path.clone(),
                source,
            })?;
        revision.validate()?;
        Ok(Some(revision))
    }

    fn write_atomic(&self, revision: &DeploymentRevision) -> Result<(), DeploymentStoreError> {
        let mut bytes =
            serde_json::to_vec_pretty(revision).map_err(|source| DeploymentStoreError::Parse {
                path: self.path.clone(),
                source,
            })?;
        bytes.push(b'\n');

        let parent = parent_directory(&self.path);
        let temp_path = self.temp_path(parent);
        let result = (|| {
            let mut temp = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|source| {
                    io_error("create deployment store temporary file", &temp_path, source)
                })?;
            temp.write_all(&bytes).map_err(|source| {
                io_error("write deployment store temporary file", &temp_path, source)
            })?;
            temp.sync_all().map_err(|source| {
                io_error("sync deployment store temporary file", &temp_path, source)
            })?;
            fs::rename(&temp_path, &self.path)
                .map_err(|source| io_error("replace deployment store", &self.path, source))?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| io_error("sync deployment store directory", parent, source))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn temp_path(&self, parent: &Path) -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = self
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("deployments");
        parent.join(format!(".{name}.tmp.{}.{}", std::process::id(), sequence))
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn io_error(
    operation: &'static str,
    path: impl AsRef<Path>,
    source: io::Error,
) -> DeploymentStoreError {
    DeploymentStoreError::Io {
        operation,
        path: path.as_ref().to_path_buf(),
        source,
    }
}
