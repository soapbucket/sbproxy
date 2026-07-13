// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Durable per-deployment generation high-water marks.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::{ClusterPlacementState, DeploymentGenerationFence};

const STORE_SCHEMA_VERSION: u32 = 1;
const STORE_FILE: &str = "model-deployment-generations.json";
const LOCK_FILE: &str = ".model-deployment-generations.lock";
const MAX_STORE_BYTES: usize = 1024 * 1024;
const MAX_DEPLOYMENTS: usize = 4_096;

/// Durable deployment-generation state failure.
#[derive(Debug, thiserror::Error)]
pub enum DeploymentGenerationStoreError {
    /// Filesystem operation failed.
    #[error("deployment generation store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Stored JSON could not be decoded.
    #[error("deployment generation store decode failed: {0}")]
    Decode(#[from] serde_json::Error),
    /// Stored or proposed state violated the monotonic contract.
    #[error("deployment generation store is invalid: {0}")]
    Invalid(String),
    /// Desired-state identity could not be encoded.
    #[error("deployment generation desired-state identity failed: {0}")]
    DesiredIdentity(String),
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDeploymentGenerations {
    schema_version: u32,
    deployments: BTreeMap<String, DeploymentGenerationFence>,
}

/// Atomic file-backed deployment generation high-water store.
#[derive(Debug, Clone)]
pub struct FileDeploymentGenerationStore {
    directory: PathBuf,
}

impl FileDeploymentGenerationStore {
    /// Open a store rooted in the canonical cluster `state_dir`.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, DeploymentGenerationStoreError> {
        let directory = directory.as_ref().to_path_buf();
        std::fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    /// Load the last committed high-water marks.
    pub fn load(
        &self,
    ) -> Result<BTreeMap<String, DeploymentGenerationFence>, DeploymentGenerationStoreError> {
        let lock = self.lock()?;
        let result = self.load_unlocked();
        FileExt::unlock(&lock)?;
        result
    }

    /// Persist all target generations before publishing a placement commit.
    pub fn persist(
        &self,
        placement: &ClusterPlacementState,
    ) -> Result<(), DeploymentGenerationStoreError> {
        let digest = placement
            .global()
            .revision_digest()
            .map_err(|error| DeploymentGenerationStoreError::DesiredIdentity(error.to_string()))?;
        let lock = self.lock()?;
        let result = (|| {
            let mut stored = self.load_unlocked()?;
            for (deployment_id, deployment) in placement.deployments() {
                let candidate = DeploymentGenerationFence {
                    deployment_generation: deployment.target.deployment_generation,
                    desired_revision_digest: Some(digest.clone()),
                };
                if let Some(current) = stored.get(deployment_id) {
                    if candidate.deployment_generation < current.deployment_generation {
                        return Err(DeploymentGenerationStoreError::Invalid(format!(
                            "deployment {deployment_id:?} regressed from {} to {}",
                            current.deployment_generation, candidate.deployment_generation
                        )));
                    }
                    if candidate.deployment_generation == current.deployment_generation
                        && candidate.desired_revision_digest != current.desired_revision_digest
                    {
                        return Err(DeploymentGenerationStoreError::Invalid(format!(
                            "deployment {deployment_id:?} reused generation {} for different desired state",
                            candidate.deployment_generation
                        )));
                    }
                }
                stored.insert(deployment_id.clone(), candidate);
            }
            if stored.len() > MAX_DEPLOYMENTS {
                return Err(DeploymentGenerationStoreError::Invalid(format!(
                    "deployment count exceeds {MAX_DEPLOYMENTS}"
                )));
            }
            let bytes = serde_json::to_vec(&StoredDeploymentGenerations {
                schema_version: STORE_SCHEMA_VERSION,
                deployments: stored,
            })?;
            if bytes.len() > MAX_STORE_BYTES {
                return Err(DeploymentGenerationStoreError::Invalid(format!(
                    "encoded store exceeds {MAX_STORE_BYTES} bytes"
                )));
            }
            atomic_write(&self.directory.join(STORE_FILE), &bytes)?;
            Ok(())
        })();
        FileExt::unlock(&lock)?;
        result
    }

    fn lock(&self) -> Result<File, DeploymentGenerationStoreError> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.directory.join(LOCK_FILE))?;
        set_owner_only(&lock)?;
        FileExt::lock_exclusive(&lock)?;
        Ok(lock)
    }

    fn load_unlocked(
        &self,
    ) -> Result<BTreeMap<String, DeploymentGenerationFence>, DeploymentGenerationStoreError> {
        let bytes = match std::fs::read(self.directory.join(STORE_FILE)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => return Err(error.into()),
        };
        if bytes.len() > MAX_STORE_BYTES {
            return Err(DeploymentGenerationStoreError::Invalid(format!(
                "encoded store exceeds {MAX_STORE_BYTES} bytes"
            )));
        }
        let stored: StoredDeploymentGenerations = serde_json::from_slice(&bytes)?;
        if stored.schema_version != STORE_SCHEMA_VERSION
            || stored.deployments.len() > MAX_DEPLOYMENTS
            || stored.deployments.iter().any(|(deployment_id, fence)| {
                deployment_id.is_empty()
                    || deployment_id.len() > 128
                    || fence.deployment_generation == 0
                    || fence.desired_revision_digest.as_ref().is_none_or(|digest| {
                        digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
            })
        {
            return Err(DeploymentGenerationStoreError::Invalid(
                "schema, bounds, generation, or digest is invalid".to_string(),
            ));
        }
        Ok(stored.deployments)
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    for attempt in 0..16u8 {
        let temporary = parent.join(format!(
            ".{STORE_FILE}.{}.{}.tmp",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(mut file) => {
                set_owner_only(&file)?;
                let result = (|| {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    std::fs::rename(&temporary, path)?;
                    sync_directory(parent)
                })();
                if result.is_err() {
                    let _ = std::fs::remove_file(&temporary);
                }
                return result;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate deployment generation temporary file",
    ))
}

#[cfg(unix)]
fn set_owner_only(file: &File) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_file: &File) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}
