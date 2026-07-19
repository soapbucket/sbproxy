// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Atomic verified artifact acquisition and cache inspection.

mod cache;
mod gc;
mod http;
mod import;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use sha2::Digest as _;
use tokio::io::AsyncWriteExt;

pub use cache::{ArtifactCacheMetadata, ArtifactCacheState, ReadyArtifact};
pub(crate) use gc::explicit_protection_reason;
pub use gc::{CacheProtection, GcReport, PruneReport, RemoveArtifactReport};
#[cfg(feature = "weights")]
pub use http::HttpArtifactTransport;
pub use http::{
    ArtifactTransport, ResponseDisposition, SourceCredential, TransportRequest, TransportResponse,
    UnavailableArtifactTransport,
};

use crate::{
    ArtifactFile, ArtifactFormat, FileJobStore, JobError, OperationJob, OperationKind,
    OperationProgress, OperationState, PullPolicy, ResolvedArtifact, WeightFormat,
};
use cache::{
    hash_file, validate_digest, validate_relative_path, validate_resolved_artifact, ArtifactCache,
    ArtifactLeaseGuard, CacheLookup, LegacyArtifactMetadata,
};

/// Cross-process shared lease held while a digest is configured or resident.
pub struct ArtifactLease {
    _guard: ArtifactLeaseGuard,
}

impl std::fmt::Debug for ArtifactLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArtifactLease")
            .finish_non_exhaustive()
    }
}

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
    /// Runtime acquisition was blocked by manual pull policy.
    #[error("manual artifact '{digest}' is not in the verified cache; run sbproxy models pull")]
    ManualArtifactMissing {
        /// Artifact digest.
        digest: String,
    },
    /// Network-denied acquisition encountered an HTTP cache miss.
    #[error("offline artifact '{digest}' is not in the verified cache{detail}")]
    OfflineArtifactMissing {
        /// Artifact digest.
        digest: String,
        /// Bounded message suffix naming the files no foreign cache
        /// could satisfy after a partial import (WOR-1863); empty when
        /// nothing was importable locally.
        detail: String,
    },
    /// Startup warming was requested for a non-on-boot artifact.
    #[error("startup warming skipped artifact '{digest}' with pull policy {pull_policy:?}")]
    StartupArtifactNotSelected {
        /// Artifact digest.
        digest: String,
        /// Declared pull policy.
        pull_policy: PullPolicy,
    },
    /// Pickle artifact did not carry explicit logical-model opt-in.
    #[error("pickle artifact '{model}' is refused without allow_pickle: true")]
    PickleRefused {
        /// Logical model ID.
        model: String,
    },
    /// Opted-in pickle bytes failed opcode scanning.
    #[error("pickle artifact file '{file}' is unsafe: {reason}")]
    PickleUnsafe {
        /// Relative pickle file.
        file: String,
        /// Scanner failure.
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
    /// Exact removal was blocked by a configured, resident, pinned, busy, or
    /// nonterminal reference.
    #[error("artifact '{digest}' cannot be removed: {reason}")]
    RemovalBlocked {
        /// Canonical artifact digest.
        digest: String,
        /// Stable bounded protection reason.
        reason: String,
    },
}

impl ArtifactError {
    fn invalid_bytes(&self) -> bool {
        matches!(
            self,
            Self::SizeMismatch { .. } | Self::DigestMismatch { .. } | Self::PickleUnsafe { .. }
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

    /// List durable ready metadata in deterministic digest order. This
    /// is a lightweight inventory for CLI and admin surfaces; callers
    /// that need byte-for-byte validation should call [`Self::inspect`]
    /// for the selected digest.
    pub fn cached_artifacts(&self) -> Result<Vec<ArtifactCacheMetadata>, ArtifactError> {
        self.cache.metadata_entries()
    }

    /// Hold one digest against collection or exact removal across processes.
    pub fn lease(&self, artifact_digest: &str) -> Result<ArtifactLease, ArtifactError> {
        self.cache
            .lock_shared_lease(artifact_digest)
            .map(|guard| ArtifactLease { _guard: guard })
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

    /// Prepare an unpinned raw `hf:Org/Repo` reference for a
    /// self-downloading container launch. There are no pinned bytes to
    /// stage or verify, so this skips the content-addressed download. It
    /// prefetches `config.json` (the fit planner needs the model shape
    /// before the engine starts) and returns a repo-mode [`ReadyArtifact`]
    /// whose `snapshot_path` is a writable, shared Hugging Face cache the
    /// container mounts and downloads the weights into.
    pub async fn ensure_unpinned(
        &self,
        artifact: &ResolvedArtifact,
    ) -> Result<ReadyArtifact, ArtifactError> {
        let repo = artifact
            .source
            .strip_prefix("hf:")
            .unwrap_or(artifact.source.as_str())
            .to_string();
        if repo.trim().is_empty() || !repo.contains('/') {
            return Err(ArtifactError::InvalidArtifact(format!(
                "unpinned artifact source {:?} is not an hf:Org/Repo reference",
                artifact.source
            )));
        }
        let mut job = self.jobs.create(
            OperationKind::Pull,
            format!("unpinned:sha256:{}", artifact.artifact_digest),
        )?;
        self.observer.on_job(&job);

        // A safetensors model carries its shape in config.json; prefetch it
        // so the fit planner can size KV and pick devices before launch. A
        // GGUF ref carries its shape in the file header (read at launch),
        // so nothing is prefetched here for it.
        let mut files = std::collections::BTreeMap::new();
        if artifact.format != ArtifactFormat::Gguf {
            match self
                .ensure_legacy_file(&repo, &artifact.revision, "config.json", None, None)
                .await
            {
                Ok(path) => {
                    files.insert("config.json".to_string(), path);
                }
                Err(error) => {
                    let failed = self.jobs.transition(
                        &job.id,
                        OperationState::Failed,
                        job.progress.clone(),
                        Some(&error.to_string()),
                    )?;
                    self.observer.on_job(&failed);
                    return Err(error);
                }
            }

            // Best-effort prefetch of the tokenizer and its config so the
            // gateway can count prompt tokens against the model's own
            // tokenizer, and (for a future raw-prompt engine) render its
            // chat template. Some models ship neither; a miss just leaves
            // the request path on its length heuristic, so a failure here
            // is not fatal to the pull.
            for optional in ["tokenizer.json", "tokenizer_config.json"] {
                if let Ok(path) = self
                    .ensure_legacy_file(&repo, &artifact.revision, optional, None, None)
                    .await
                {
                    files.insert(optional.to_string(), path);
                }
            }
        }

        let hf_home = self.cache.root().join("hf-home");
        std::fs::create_dir_all(&hf_home).map_err(|error| {
            ArtifactError::InvalidArtifact(format!(
                "create hugging face cache {}: {error}",
                hf_home.display()
            ))
        })?;

        job = self.transition_job(
            &job,
            OperationState::Ready,
            OperationProgress {
                completed_bytes: 0,
                total_bytes: 0,
                current_file: None,
            },
        )?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0);
        ReadyArtifact::unpinned(artifact, repo, hf_home, files, job, now_ms)
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

        let local_source = artifact.source.strip_prefix("file:");
        if let Some(local_source) = local_source {
            enforce_cache_miss_policy(
                &artifact.artifact_digest,
                context.intent,
                context.network,
                context.pull_policy,
                true,
            )?;
            self.stage_local_files(artifact, local_source, total_bytes, job)
                .await?;
        } else {
            // Intent and pull-policy gates cover every acquisition,
            // including a foreign-cache import, so they run before any
            // bytes move. The network gate is deferred until after the
            // import attempt: a file another local tool already holds
            // never needs the network, so in denied mode a full import
            // turns the refusal into a success (WOR-1863).
            enforce_cache_miss_policy(
                &artifact.artifact_digest,
                context.intent,
                NetworkPolicy::Allowed,
                context.pull_policy,
                false,
            )?;
            let imported = self.import_foreign_sources(artifact).await?;
            let missing: Vec<ArtifactFile> = artifact
                .files
                .iter()
                .filter(|file| !imported.contains(file.path.as_str()))
                .cloned()
                .collect();
            if !missing.is_empty() {
                if context.network == NetworkPolicy::Denied {
                    return Err(ArtifactError::OfflineArtifactMissing {
                        digest: artifact.artifact_digest.clone(),
                        detail: offline_missing_detail(&imported, &missing),
                    });
                }
                let imported_bytes = artifact
                    .files
                    .iter()
                    .filter(|file| imported.contains(file.path.as_str()))
                    .try_fold(0u64, |total, file| total.checked_add(file.size_bytes))
                    .ok_or_else(|| {
                        ArtifactError::InvalidArtifact(
                            "artifact progress overflows u64".to_string(),
                        )
                    })?;
                *job = self.transition_job(
                    job,
                    OperationState::Downloading,
                    OperationProgress {
                        completed_bytes: imported_bytes,
                        total_bytes,
                        current_file: missing.first().map(|file| file.path.clone()),
                    },
                )?;
                let mut completed_bytes = imported_bytes;
                for file in &missing {
                    let file_bytes = self
                        .download_http_file(
                            artifact,
                            file,
                            completed_bytes,
                            total_bytes,
                            context.credential.clone(),
                            job,
                        )
                        .await?;
                    completed_bytes = completed_bytes.checked_add(file_bytes).ok_or_else(|| {
                        ArtifactError::InvalidArtifact(
                            "artifact progress overflows u64".to_string(),
                        )
                    })?;
                }
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
        }

        let cache = self.cache.clone();
        let mutation_guard = tokio::task::spawn_blocking(move || cache.lock_shared_mutation())
            .await
            .map_err(|error| ArtifactError::Join(error.to_string()))??;
        let cache = self.cache.clone();
        let requested = artifact.clone();
        tokio::task::spawn_blocking(move || scan_pickle_partials(&cache, &requested))
            .await
            .map_err(|error| ArtifactError::Join(error.to_string()))??;
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
        drop(mutation_guard);
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

    async fn stage_local_files(
        &self,
        artifact: &ResolvedArtifact,
        local_source: &str,
        total_bytes: u64,
        job: &mut OperationJob,
    ) -> Result<(), ArtifactError> {
        if local_source.trim().is_empty() {
            return Err(ArtifactError::InvalidArtifact(
                "file: source path must not be empty".to_string(),
            ));
        }
        let source_root = PathBuf::from(local_source);
        let source_metadata = std::fs::symlink_metadata(&source_root)
            .map_err(|source| io_error("read local artifact source", &source_root, source))?;
        if source_metadata.file_type().is_symlink() {
            return Err(ArtifactError::InvalidArtifact(
                "file: source must not be a symbolic link".to_string(),
            ));
        }
        if source_metadata.is_file() && artifact.files.len() != 1 {
            return Err(ArtifactError::InvalidArtifact(
                "a file: source file can satisfy only one declared artifact file".to_string(),
            ));
        }
        if !source_metadata.is_file() && !source_metadata.is_dir() {
            return Err(ArtifactError::InvalidArtifact(
                "file: source must be a regular file or directory".to_string(),
            ));
        }

        *job = self.transition_job(
            job,
            OperationState::Verifying,
            OperationProgress {
                completed_bytes: 0,
                total_bytes,
                current_file: artifact.files.first().map(|file| file.path.clone()),
            },
        )?;
        let mut completed_bytes = 0u64;
        for file in &artifact.files {
            let source = if source_metadata.is_file() {
                source_root.clone()
            } else {
                source_root.join(&file.path)
            };
            reject_symlink_path(&source_root, &source)?;
            let metadata = std::fs::metadata(&source)
                .map_err(|error| io_error("read local artifact file", &source, error))?;
            if !metadata.is_file() {
                return Err(ArtifactError::InvalidArtifact(format!(
                    "local artifact '{}' is not a regular file",
                    source.display()
                )));
            }
            if metadata.len() != file.size_bytes {
                return Err(ArtifactError::SizeMismatch {
                    file: file.path.clone(),
                    expected: file.size_bytes,
                    actual: metadata.len(),
                });
            }
            let partial = self
                .cache
                .prepare_partial(&artifact.artifact_digest, &file.path)?;
            let mut reader = tokio::fs::File::open(&source)
                .await
                .map_err(|error| io_error("open local artifact file", &source, error))?;
            let mut writer = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&partial)
                .await
                .map_err(|error| io_error("open local artifact partial", &partial, error))?;
            let copied = tokio::io::copy(&mut reader, &mut writer)
                .await
                .map_err(|error| io_error("stage local artifact file", &partial, error))?;
            writer
                .sync_all()
                .await
                .map_err(|error| io_error("sync local artifact partial", &partial, error))?;
            if copied != file.size_bytes {
                return Err(ArtifactError::SizeMismatch {
                    file: file.path.clone(),
                    expected: file.size_bytes,
                    actual: copied,
                });
            }
            completed_bytes = completed_bytes.checked_add(copied).ok_or_else(|| {
                ArtifactError::InvalidArtifact("artifact progress overflows u64".to_string())
            })?;
            *job = self.transition_job(
                job,
                OperationState::Verifying,
                OperationProgress {
                    completed_bytes,
                    total_bytes,
                    current_file: Some(file.path.clone()),
                },
            )?;
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
        Ok(())
    }

    /// Try to satisfy this ensure call's declared files from weights
    /// other local tools already cached (WOR-1863). Runs one read-only
    /// [`crate::foreign_cache::discover`] scan per call, confirms each
    /// size-matched candidate by streaming SHA-256, and stages matches
    /// into the normal partial location so the unchanged verify and
    /// promote path re-checks every invariant. Returns the relative
    /// paths staged; the remainder is left for the network.
    async fn import_foreign_sources(
        &self,
        artifact: &ResolvedArtifact,
    ) -> Result<std::collections::BTreeSet<String>, ArtifactError> {
        let Some(home) = import::foreign_scan_home() else {
            return Ok(std::collections::BTreeSet::new());
        };
        let cache = self.cache.clone();
        let requested = artifact.clone();
        tokio::task::spawn_blocking(move || {
            let candidates = crate::foreign_cache::discover(&home);
            import::import_foreign_candidates(&cache, &requested, &candidates)
        })
        .await
        .map_err(|error| ArtifactError::Join(error.to_string()))?
    }

    #[allow(clippy::too_many_arguments)]
    async fn download_http_file(
        &self,
        artifact: &ResolvedArtifact,
        file: &ArtifactFile,
        completed_before: u64,
        total_bytes: u64,
        credential: Option<SourceCredential>,
        job: &mut OperationJob,
    ) -> Result<u64, ArtifactError> {
        let url = source_url(artifact, &file.path)?;
        let mut resume = self
            .cache
            .resume_state(&artifact.artifact_digest, file, &url)?;
        *job = self.transition_job(
            job,
            OperationState::Downloading,
            OperationProgress {
                completed_bytes: completed_before.checked_add(resume.offset).ok_or_else(|| {
                    ArtifactError::InvalidArtifact("artifact progress overflows u64".to_string())
                })?,
                total_bytes,
                current_file: Some(file.path.clone()),
            },
        )?;

        let mut restarted = false;
        let mut checkpointed_bytes = resume.offset;
        let mut last_checkpoint = Instant::now();
        let mut body_checkpointed = false;
        loop {
            let response = self
                .transport
                .get(TransportRequest {
                    url: url.clone(),
                    offset: resume.offset,
                    if_range: resume.etag.clone(),
                    credential: credential.clone(),
                })
                .await?;

            let append = match response.disposition {
                ResponseDisposition::Replacement => {
                    if let Some(actual) = response.total_size {
                        if actual != file.size_bytes {
                            return Err(ArtifactError::SizeMismatch {
                                file: file.path.clone(),
                                expected: file.size_bytes,
                                actual,
                            });
                        }
                    }
                    if resume.offset > 0 {
                        self.cache
                            .discard_partial_file(&artifact.artifact_digest, &file.path)?;
                    }
                    resume.offset = 0;
                    resume.etag = response.etag.clone();
                    checkpointed_bytes = 0;
                    last_checkpoint = Instant::now();
                    body_checkpointed = false;
                    false
                }
                ResponseDisposition::Append
                    if resume.offset > 0
                        && response.etag == resume.etag
                        && response.total_size == Some(file.size_bytes) =>
                {
                    true
                }
                ResponseDisposition::RangeComplete
                    if resume.offset == file.size_bytes
                        && response.total_size == Some(file.size_bytes)
                        && response
                            .etag
                            .as_ref()
                            .is_none_or(|etag| Some(etag) == resume.etag.as_ref()) =>
                {
                    *job = self.transition_job(
                        job,
                        OperationState::Downloading,
                        OperationProgress {
                            completed_bytes: completed_before
                                .checked_add(resume.offset)
                                .ok_or_else(|| {
                                    ArtifactError::InvalidArtifact(
                                        "artifact progress overflows u64".to_string(),
                                    )
                                })?,
                            total_bytes,
                            current_file: Some(file.path.clone()),
                        },
                    )?;
                    return Ok(resume.offset);
                }
                ResponseDisposition::Append | ResponseDisposition::RangeComplete
                    if resume.offset > 0 && !restarted =>
                {
                    self.cache
                        .discard_partial_file(&artifact.artifact_digest, &file.path)?;
                    resume.offset = 0;
                    resume.etag = None;
                    checkpointed_bytes = 0;
                    last_checkpoint = Instant::now();
                    body_checkpointed = false;
                    restarted = true;
                    continue;
                }
                disposition => {
                    return Err(ArtifactError::UnexpectedResponse {
                        file: file.path.clone(),
                        reason: format!(
                            "response {disposition:?} is incompatible with offset {}",
                            resume.offset
                        ),
                    })
                }
            };

            let partial = self
                .cache
                .prepare_partial(&artifact.artifact_digest, &file.path)?;
            self.cache.write_resume(
                &artifact.artifact_digest,
                file,
                &url,
                response.etag.as_deref(),
                resume.offset,
            )?;
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create(true);
            if append {
                options.append(true);
            } else {
                options.truncate(true);
            }
            let mut destination = options
                .open(&partial)
                .await
                .map_err(|source| io_error("open artifact partial", &partial, source))?;
            let response_etag = response.etag;
            let mut body = response.body;
            let mut file_bytes = resume.offset;
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
                let checkpoint_due = !body_checkpointed
                    || file_bytes == file.size_bytes
                    || file_bytes.saturating_sub(checkpointed_bytes) >= 8 * 1024 * 1024
                    || last_checkpoint.elapsed() >= Duration::from_secs(2);
                if checkpoint_due {
                    destination.sync_data().await.map_err(|source| {
                        io_error("checkpoint artifact partial", &partial, source)
                    })?;
                    self.cache.write_resume(
                        &artifact.artifact_digest,
                        file,
                        &url,
                        response_etag.as_deref(),
                        file_bytes,
                    )?;
                    let completed_bytes = completed_before
                        .checked_add(file_bytes)
                        .ok_or_else(|| {
                            ArtifactError::InvalidArtifact(
                                "artifact progress overflows u64".to_string(),
                            )
                        })?
                        .max(job.progress.completed_bytes);
                    *job = self.transition_job(
                        job,
                        OperationState::Downloading,
                        OperationProgress {
                            completed_bytes,
                            total_bytes,
                            current_file: Some(file.path.clone()),
                        },
                    )?;
                    checkpointed_bytes = file_bytes;
                    last_checkpoint = Instant::now();
                    body_checkpointed = true;
                }
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
            return Ok(file_bytes);
        }
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

pub(crate) fn enforce_cache_miss_policy(
    digest: &str,
    intent: PullIntent,
    network: NetworkPolicy,
    pull_policy: PullPolicy,
    local_source: bool,
) -> Result<(), ArtifactError> {
    if intent == PullIntent::Runtime && pull_policy == PullPolicy::Manual {
        return Err(ArtifactError::ManualArtifactMissing {
            digest: digest.to_string(),
        });
    }
    if intent == PullIntent::Startup && pull_policy != PullPolicy::OnBoot {
        return Err(ArtifactError::StartupArtifactNotSelected {
            digest: digest.to_string(),
            pull_policy,
        });
    }
    if network == NetworkPolicy::Denied && !local_source {
        return Err(ArtifactError::OfflineArtifactMissing {
            digest: digest.to_string(),
            detail: String::new(),
        });
    }
    Ok(())
}

/// Message suffix for a network-denied miss: names the files no
/// foreign cache satisfied when an import staged part of the artifact
/// (WOR-1863), and stays empty on a plain miss so the established
/// message is unchanged.
fn offline_missing_detail(
    imported: &std::collections::BTreeSet<String>,
    missing: &[ArtifactFile],
) -> String {
    if imported.is_empty() {
        return String::new();
    }
    let names: Vec<&str> = missing.iter().map(|file| file.path.as_str()).collect();
    format!(
        "; foreign caches satisfied only part of it, still missing: {}",
        names.join(", ")
    )
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

fn scan_pickle_partials(
    cache: &ArtifactCache,
    artifact: &ResolvedArtifact,
) -> Result<(), ArtifactError> {
    if artifact.format != ArtifactFormat::Pickle {
        return Ok(());
    }
    let mut scanned = false;
    for file in &artifact.files {
        if WeightFormat::from_filename(&file.path) != WeightFormat::Pickle {
            continue;
        }
        scanned = true;
        let path = cache.partial_path(&artifact.artifact_digest, &file.path);
        let bytes = std::fs::read(&path)
            .map_err(|source| io_error("read pickle artifact for scanning", &path, source))?;
        crate::scan_pickle(&file.path, &bytes).map_err(|error| ArtifactError::PickleUnsafe {
            file: file.path.clone(),
            reason: error.to_string(),
        })?;
    }
    if !scanned {
        return Err(ArtifactError::InvalidArtifact(
            "pickle artifact has no declared pickle file".to_string(),
        ));
    }
    Ok(())
}

fn reject_symlink_path(root: &Path, target: &Path) -> Result<(), ArtifactError> {
    if root == target {
        return Ok(());
    }
    let relative = target.strip_prefix(root).map_err(|_| {
        ArtifactError::InvalidArtifact(format!(
            "local artifact path '{}' escapes source root '{}'",
            target.display(),
            root.display()
        ))
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|source| io_error("inspect local artifact path", &current, source))?;
        if metadata.file_type().is_symlink() {
            return Err(ArtifactError::InvalidArtifact(format!(
                "local artifact path '{}' contains a symbolic link",
                current.display()
            )));
        }
    }
    Ok(())
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
