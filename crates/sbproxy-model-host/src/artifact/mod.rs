// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Atomic verified artifact acquisition and cache inspection.

mod cache;
mod http;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::StreamExt;
use sha2::Digest as _;
use tokio::io::AsyncWriteExt;

pub use cache::{ArtifactCacheMetadata, ArtifactCacheState, ReadyArtifact};
#[cfg(feature = "weights")]
pub use http::HttpArtifactTransport;
pub use http::{
    ArtifactTransport, ResponseDisposition, SourceCredential, TransportRequest, TransportResponse,
};

use crate::{
    FileJobStore, JobError, OperationJob, OperationKind, OperationProgress, OperationState,
    PullPolicy, ResolvedArtifact,
};
use cache::{
    hash_file, validate_digest, validate_relative_path, validate_resolved_artifact, ArtifactCache,
    CacheLookup, LegacyArtifactMetadata,
};

/// Why an artifact could not become verified ready state.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// Resolved artifact metadata is unsafe or incomplete.
    #[error("invalid resolved artifact: {0}")]
    InvalidArtifact(String),
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
    /// Transport failed without exposing credentials or headers.
    #[error("artifact transport: {0}")]
    Transport(String),
    /// HTTP source returned an unusable status.
    #[error("artifact request {url} returned HTTP {status}")]
    HttpStatus {
        /// Credential-free source URL.
        url: String,
        /// HTTP status code.
        status: u16,
    },
    /// Transport response cannot safely update the partial.
    #[error("artifact response for '{file}' is unusable: {reason}")]
    UnexpectedResponse {
        /// Relative artifact file.
        file: String,
        /// Response contract failure.
        reason: String,
    },
    /// Exact file length differs from the catalog.
    #[error("artifact size mismatch for '{file}': expected {expected}, got {actual}")]
    SizeMismatch {
        /// Relative artifact file.
        file: String,
        /// Catalog byte length.
        expected: u64,
        /// Observed byte length.
        actual: u64,
    },
    /// Exact file SHA-256 differs from the catalog.
    #[error("artifact digest mismatch for '{file}': expected {expected}, got {actual}")]
    DigestMismatch {
        /// Relative artifact file.
        file: String,
        /// Catalog SHA-256.
        expected: String,
        /// Observed SHA-256.
        actual: String,
    },
    /// Ready-looking cache state failed complete verification.
    #[error("artifact cache '{digest}' is corrupt: {reason}")]
    CacheCorrupt {
        /// Artifact digest.
        digest: String,
        /// Safe verification failure.
        reason: String,
    },
    /// Durable operation job failed.
    #[error(transparent)]
    Job(#[from] JobError),
    /// JSON encoding failed.
    #[error("serialize artifact metadata: {0}")]
    Serialization(String),
    /// Wall-clock time was unavailable.
    #[error("read artifact clock: {0}")]
    Clock(String),
    /// Blocking cache task panicked or was cancelled.
    #[error("artifact cache task failed: {0}")]
    Join(String),
}

impl ArtifactError {
    fn invalid_bytes(&self) -> bool {
        matches!(
            self,
            Self::SizeMismatch { .. } | Self::DigestMismatch { .. }
        )
    }
}

/// Why a cache miss is being acquired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullIntent {
    /// Startup warming before the deployment is reported warm.
    Startup,
    /// First-request acquisition.
    Runtime,
    /// Explicit operator pull.
    Explicit,
}

/// Whether this operation may contact a network source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Network transport may be used.
    Allowed,
    /// Network transport must not be invoked.
    Denied,
}

/// Acquisition policy and transport-only credential for one ensure call.
#[derive(Debug, Clone)]
pub struct AcquisitionContext {
    /// Startup, runtime, or explicit operator intent.
    pub intent: PullIntent,
    /// Whether network access is allowed.
    pub network: NetworkPolicy,
    /// Catalog pull policy.
    pub pull_policy: PullPolicy,
    /// Resolved bearer credential, never serialized.
    pub credential: Option<SourceCredential>,
}

/// Receives durable job snapshots for progress rendering or admin events.
pub trait ArtifactObserver: Send + Sync {
    /// Publish one durable job state or progress update.
    fn on_job(&self, job: &OperationJob);
}

#[derive(Debug)]
struct NoopArtifactObserver;

impl ArtifactObserver for NoopArtifactObserver {
    fn on_job(&self, _job: &OperationJob) {}
}

/// Shared verified-artifact service.
pub struct ArtifactManager {
    cache: ArtifactCache,
    transport: Arc<dyn ArtifactTransport>,
    jobs: FileJobStore,
    observer: Arc<dyn ArtifactObserver>,
}

impl ArtifactManager {
    /// Open a cache root and its durable job store.
    pub fn new(
        root: impl Into<PathBuf>,
        transport: Arc<dyn ArtifactTransport>,
    ) -> Result<Self, ArtifactError> {
        let root = root.into();
        let cache = ArtifactCache::open(root.clone())?;
        let jobs = FileJobStore::open(root, 256)?;
        Ok(Self {
            cache,
            transport,
            jobs,
            observer: Arc::new(NoopArtifactObserver),
        })
    }

    /// Attach a progress observer. Durable jobs remain the source of truth.
    pub fn with_observer(mut self, observer: Arc<dyn ArtifactObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Access the shared durable job store.
    pub fn jobs(&self) -> &FileJobStore {
        &self.jobs
    }

    /// Inspect and fully verify one cache digest.
    pub fn inspect(&self, artifact_digest: &str) -> Result<ArtifactCacheState, ArtifactError> {
        self.cache.inspect(artifact_digest)
    }

    /// Return verified local bytes, downloading and finalizing atomically on a miss.
    pub async fn ensure(
        &self,
        artifact: &ResolvedArtifact,
        context: AcquisitionContext,
    ) -> Result<ReadyArtifact, ArtifactError> {
        validate_resolved_artifact(artifact)?;
        let mut job = self.jobs.create(
            OperationKind::Pull,
            format!("artifact:sha256:{}", artifact.artifact_digest),
        )?;
        self.observer.on_job(&job);

        let cache = self.cache.clone();
        let digest = artifact.artifact_digest.clone();
        let guard = tokio::task::spawn_blocking(move || cache.lock_artifact(&digest))
            .await
            .map_err(|error| ArtifactError::Join(error.to_string()))??;

        let result = self.ensure_locked(artifact, context, &mut job).await;
        drop(guard);
        match result {
            Ok(ready) => Ok(ready),
            Err(error) => {
                self.cache.cleanup_staging(&artifact.artifact_digest);
                if error.invalid_bytes() {
                    self.cache.remove_partials(&artifact.artifact_digest)?;
                }
                let failed = self.jobs.transition(
                    &job.id,
                    OperationState::Failed,
                    job.progress.clone(),
                    Some(&error.to_string()),
                )?;
                self.observer.on_job(&failed);
                Err(error)
            }
        }
    }

    /// Safely acquire one legacy Hugging Face file for the documented
    /// preview compatibility path. Managed v2 launches never consume
    /// this path because it lacks a catalog-declared exact byte size.
    pub async fn ensure_legacy_file(
        &self,
        hf_repo: &str,
        revision: &str,
        filename: &str,
        expected_sha256: Option<&str>,
        credential: Option<SourceCredential>,
    ) -> Result<PathBuf, ArtifactError> {
        if hf_repo.trim().is_empty() || !hf_repo.contains('/') || revision.trim().is_empty() {
            return Err(ArtifactError::InvalidArtifact(
                "legacy Hugging Face source requires repo and revision".to_string(),
            ));
        }
        validate_relative_path(filename)?;
        if let Some(expected) = expected_sha256 {
            validate_digest(expected)?;
        }
        let identity =
            serde_json_canonicalizer::to_vec(&(hf_repo, revision, filename, expected_sha256))
                .map_err(|error| ArtifactError::Serialization(error.to_string()))?;
        let identity_digest = hex::encode(sha2::Sha256::digest(identity));
        let mut job = self.jobs.create(
            OperationKind::Pull,
            format!("legacy-artifact:sha256:{identity_digest}"),
        )?;
        self.observer.on_job(&job);

        let cache = self.cache.clone();
        let lock_digest = identity_digest.clone();
        let guard = tokio::task::spawn_blocking(move || cache.lock_artifact(&lock_digest))
            .await
            .map_err(|error| ArtifactError::Join(error.to_string()))??;
        let result = self
            .ensure_legacy_locked(
                hf_repo,
                revision,
                filename,
                expected_sha256,
                credential,
                &identity_digest,
                &mut job,
            )
            .await;
        drop(guard);
        match result {
            Ok(path) => Ok(path),
            Err(error) => {
                if error.invalid_bytes() {
                    self.cache.remove_partials(&identity_digest)?;
                }
                let failed = self.jobs.transition(
                    &job.id,
                    OperationState::Failed,
                    job.progress.clone(),
                    Some(&error.to_string()),
                )?;
                self.observer.on_job(&failed);
                Err(error)
            }
        }
    }

    async fn ensure_locked(
        &self,
        artifact: &ResolvedArtifact,
        context: AcquisitionContext,
        job: &mut OperationJob,
    ) -> Result<ReadyArtifact, ArtifactError> {
        let cache = self.cache.clone();
        let requested = artifact.clone();
        let lookup = tokio::task::spawn_blocking(move || cache.lookup_for(&requested))
            .await
            .map_err(|error| ArtifactError::Join(error.to_string()))??;
        let total_bytes = artifact
            .files
            .iter()
            .try_fold(0u64, |total, file| total.checked_add(file.size_bytes))
            .ok_or_else(|| {
                ArtifactError::InvalidArtifact("artifact total size overflows u64".to_string())
            })?;

        match lookup {
            CacheLookup::Ready(metadata) => {
                *job = self.transition_job(
                    job,
                    OperationState::Ready,
                    OperationProgress {
                        completed_bytes: total_bytes,
                        total_bytes,
                        current_file: None,
                    },
                )?;
                return Ok(ReadyArtifact::new(
                    self.cache.root(),
                    *metadata,
                    job.clone(),
                ));
            }
            CacheLookup::Corrupt(reason) => {
                return Err(ArtifactError::CacheCorrupt {
                    digest: artifact.artifact_digest.clone(),
                    reason,
                })
            }
            CacheLookup::Missing | CacheLookup::Partial(_) => {}
        }

        let first_file = artifact.files.first().map(|file| file.path.clone());
        *job = self.transition_job(
            job,
            OperationState::Downloading,
            OperationProgress {
                completed_bytes: 0,
                total_bytes,
                current_file: first_file,
            },
        )?;

        let mut completed_bytes = 0u64;
        for file in &artifact.files {
            if job.progress.current_file.as_deref() != Some(file.path.as_str()) {
                *job = self.transition_job(
                    job,
                    OperationState::Downloading,
                    OperationProgress {
                        completed_bytes,
                        total_bytes,
                        current_file: Some(file.path.clone()),
                    },
                )?;
            }
            let url = source_url(artifact, &file.path)?;
            let response = self
                .transport
                .get(TransportRequest {
                    url,
                    offset: 0,
                    if_range: None,
                    credential: context.credential.clone(),
                })
                .await?;
            if response.disposition != ResponseDisposition::Replacement {
                return Err(ArtifactError::UnexpectedResponse {
                    file: file.path.clone(),
                    reason: format!("byte-zero request returned {:?}", response.disposition),
                });
            }
            if let Some(actual) = response.total_size {
                if actual != file.size_bytes {
                    return Err(ArtifactError::SizeMismatch {
                        file: file.path.clone(),
                        expected: file.size_bytes,
                        actual,
                    });
                }
            }

            let partial = self
                .cache
                .prepare_partial(&artifact.artifact_digest, &file.path)?;
            let mut destination = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&partial)
                .await
                .map_err(|source| io_error("open artifact partial", &partial, source))?;
            let mut body = response.body;
            let mut file_bytes = 0u64;
            while let Some(chunk) = body.next().await {
                let chunk = chunk?;
                let chunk_len = u64::try_from(chunk.len()).map_err(|_| {
                    ArtifactError::InvalidArtifact(
                        "transport chunk length overflows u64".to_string(),
                    )
                })?;
                file_bytes = file_bytes.checked_add(chunk_len).ok_or_else(|| {
                    ArtifactError::InvalidArtifact("artifact file length overflows u64".to_string())
                })?;
                if file_bytes > file.size_bytes {
                    return Err(ArtifactError::SizeMismatch {
                        file: file.path.clone(),
                        expected: file.size_bytes,
                        actual: file_bytes,
                    });
                }
                destination
                    .write_all(&chunk)
                    .await
                    .map_err(|source| io_error("write artifact partial", &partial, source))?;
                let progress_bytes = completed_bytes.checked_add(file_bytes).ok_or_else(|| {
                    ArtifactError::InvalidArtifact("artifact progress overflows u64".to_string())
                })?;
                *job = self.transition_job(
                    job,
                    OperationState::Downloading,
                    OperationProgress {
                        completed_bytes: progress_bytes,
                        total_bytes,
                        current_file: Some(file.path.clone()),
                    },
                )?;
            }
            destination
                .sync_all()
                .await
                .map_err(|source| io_error("sync artifact partial", &partial, source))?;
            if file_bytes != file.size_bytes {
                return Err(ArtifactError::SizeMismatch {
                    file: file.path.clone(),
                    expected: file.size_bytes,
                    actual: file_bytes,
                });
            }
            completed_bytes = completed_bytes.checked_add(file_bytes).ok_or_else(|| {
                ArtifactError::InvalidArtifact("artifact progress overflows u64".to_string())
            })?;
        }

        *job = self.transition_job(
            job,
            OperationState::Verifying,
            OperationProgress {
                completed_bytes: total_bytes,
                total_bytes,
                current_file: None,
            },
        )?;
        let cache = self.cache.clone();
        let requested = artifact.clone();
        tokio::task::spawn_blocking(move || cache.verify_and_promote(&requested))
            .await
            .map_err(|error| ArtifactError::Join(error.to_string()))??;
        let cache = self.cache.clone();
        let requested = artifact.clone();
        let metadata = tokio::task::spawn_blocking(move || cache.finalize_snapshot(&requested))
            .await
            .map_err(|error| ArtifactError::Join(error.to_string()))??;
        *job = self.transition_job(
            job,
            OperationState::Ready,
            OperationProgress {
                completed_bytes: total_bytes,
                total_bytes,
                current_file: None,
            },
        )?;
        Ok(ReadyArtifact::new(self.cache.root(), metadata, job.clone()))
    }

    #[allow(clippy::too_many_arguments)]
    async fn ensure_legacy_locked(
        &self,
        hf_repo: &str,
        revision: &str,
        filename: &str,
        expected_sha256: Option<&str>,
        credential: Option<SourceCredential>,
        identity_digest: &str,
        job: &mut OperationJob,
    ) -> Result<PathBuf, ArtifactError> {
        let destination =
            crate::weights::cache_file(self.cache.root(), hf_repo, revision, filename);
        if destination.is_file() {
            let size_bytes = std::fs::metadata(&destination)
                .map_err(|source| io_error("read legacy artifact metadata", &destination, source))?
                .len();
            if let Some(expected) = expected_sha256 {
                let actual = hash_file(&destination)?;
                if !actual.eq_ignore_ascii_case(expected) {
                    return Err(ArtifactError::DigestMismatch {
                        file: filename.to_string(),
                        expected: expected.to_string(),
                        actual,
                    });
                }
            }
            self.record_legacy_metadata(
                identity_digest,
                hf_repo,
                revision,
                filename,
                expected_sha256,
                size_bytes,
            )?;
            *job = self.transition_job(
                job,
                OperationState::Ready,
                OperationProgress {
                    completed_bytes: size_bytes,
                    total_bytes: size_bytes,
                    current_file: None,
                },
            )?;
            return Ok(destination);
        }

        let source = format!("hf:{hf_repo}");
        let response = self
            .transport
            .get(TransportRequest {
                url: hf_url(hf_repo, revision, filename),
                offset: 0,
                if_range: None,
                credential,
            })
            .await?;
        if response.disposition != ResponseDisposition::Replacement {
            return Err(ArtifactError::UnexpectedResponse {
                file: filename.to_string(),
                reason: "legacy byte-zero request was not a replacement response".to_string(),
            });
        }
        let reported_total = response.total_size.unwrap_or(0);
        *job = self.transition_job(
            job,
            OperationState::Downloading,
            OperationProgress {
                completed_bytes: 0,
                total_bytes: reported_total,
                current_file: Some(filename.to_string()),
            },
        )?;
        let partial = self.cache.prepare_partial(identity_digest, filename)?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&partial)
            .await
            .map_err(|source| io_error("open legacy artifact partial", &partial, source))?;
        let mut body = response.body;
        let mut actual_size = 0u64;
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            let chunk_len = u64::try_from(chunk.len()).map_err(|_| {
                ArtifactError::InvalidArtifact(
                    "legacy transport chunk length overflows u64".to_string(),
                )
            })?;
            actual_size = actual_size.checked_add(chunk_len).ok_or_else(|| {
                ArtifactError::InvalidArtifact("legacy artifact length overflows u64".to_string())
            })?;
            file.write_all(&chunk)
                .await
                .map_err(|source| io_error("write legacy artifact partial", &partial, source))?;
            if reported_total > 0 {
                if actual_size > reported_total {
                    return Err(ArtifactError::SizeMismatch {
                        file: filename.to_string(),
                        expected: reported_total,
                        actual: actual_size,
                    });
                }
                *job = self.transition_job(
                    job,
                    OperationState::Downloading,
                    OperationProgress {
                        completed_bytes: actual_size,
                        total_bytes: reported_total,
                        current_file: Some(filename.to_string()),
                    },
                )?;
            }
        }
        file.sync_all()
            .await
            .map_err(|source| io_error("sync legacy artifact partial", &partial, source))?;
        if reported_total > 0 && actual_size != reported_total {
            return Err(ArtifactError::SizeMismatch {
                file: filename.to_string(),
                expected: reported_total,
                actual: actual_size,
            });
        }
        if reported_total == 0 {
            *job = self.transition_job(
                job,
                OperationState::Downloading,
                OperationProgress {
                    completed_bytes: actual_size,
                    total_bytes: actual_size,
                    current_file: Some(filename.to_string()),
                },
            )?;
        }
        *job = self.transition_job(
            job,
            OperationState::Verifying,
            OperationProgress {
                completed_bytes: actual_size,
                total_bytes: actual_size,
                current_file: None,
            },
        )?;
        if let Some(expected) = expected_sha256 {
            let actual = hash_file(&partial)?;
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(ArtifactError::DigestMismatch {
                    file: filename.to_string(),
                    expected: expected.to_string(),
                    actual,
                });
            }
        }
        let metadata = LegacyArtifactMetadata {
            schema_version: 1,
            identity_digest,
            source: &source,
            revision,
            file: filename,
            sha256: expected_sha256,
            size_bytes: actual_size,
            trust: if expected_sha256.is_some() {
                "verified_legacy"
            } else {
                "preview_unpinned"
            },
        };
        self.cache
            .finalize_legacy_file(&partial, &destination, identity_digest, &metadata)?;
        *job = self.transition_job(
            job,
            OperationState::Ready,
            OperationProgress {
                completed_bytes: actual_size,
                total_bytes: actual_size,
                current_file: None,
            },
        )?;
        Ok(destination)
    }

    fn record_legacy_metadata(
        &self,
        identity_digest: &str,
        hf_repo: &str,
        revision: &str,
        filename: &str,
        expected_sha256: Option<&str>,
        size_bytes: u64,
    ) -> Result<(), ArtifactError> {
        let source = format!("hf:{hf_repo}");
        self.cache.write_legacy_metadata(
            identity_digest,
            &LegacyArtifactMetadata {
                schema_version: 1,
                identity_digest,
                source: &source,
                revision,
                file: filename,
                sha256: expected_sha256,
                size_bytes,
                trust: if expected_sha256.is_some() {
                    "verified_legacy"
                } else {
                    "preview_unpinned"
                },
            },
        )
    }

    fn transition_job(
        &self,
        job: &OperationJob,
        state: OperationState,
        progress: OperationProgress,
    ) -> Result<OperationJob, ArtifactError> {
        let next = self.jobs.transition(&job.id, state, progress, None)?;
        self.observer.on_job(&next);
        Ok(next)
    }
}

fn source_url(artifact: &ResolvedArtifact, relative_path: &str) -> Result<String, ArtifactError> {
    let repo = artifact.source.strip_prefix("hf:").ok_or_else(|| {
        ArtifactError::InvalidArtifact(format!(
            "managed HTTP acquisition requires an hf: source, got '{}'",
            artifact.source
        ))
    })?;
    Ok(hf_url(repo, &artifact.revision, relative_path))
}

fn hf_url(repo: &str, revision: &str, relative_path: &str) -> String {
    let endpoint =
        std::env::var("HF_ENDPOINT").unwrap_or_else(|_| "https://huggingface.co".to_string());
    format!(
        "{}/{repo}/resolve/{revision}/{relative_path}",
        endpoint.trim_end_matches('/')
    )
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> ArtifactError {
    ArtifactError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
