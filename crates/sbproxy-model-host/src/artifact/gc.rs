// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Protected deterministic LRU collection for verified artifacts.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{ArtifactError, ArtifactManager};
use crate::{OperationKind, OperationProgress, OperationState};

/// Artifact digests that collection must never remove.
#[derive(Debug, Clone, Default)]
pub struct CacheProtection {
    /// Artifacts referenced by the active desired configuration.
    pub configured: BTreeSet<String>,
    /// Artifacts currently attached to resident model processes.
    pub resident: BTreeSet<String>,
    /// Operator-pinned artifacts.
    pub pinned: BTreeSet<String>,
}

/// Deterministic cache-budget collection result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GcReport {
    /// Physical content-addressed blob bytes before collection.
    pub before_bytes: u64,
    /// Physical content-addressed blob bytes after collection.
    pub after_bytes: u64,
    /// Blob bytes removed by this collection.
    pub reclaimed_bytes: u64,
    /// Artifact digests deleted in LRU order.
    pub deleted_artifacts: Vec<String>,
    /// Protected or busy artifacts and their stable reason.
    pub skipped_artifacts: BTreeMap<String, String>,
    /// Bytes still above budget because remaining artifacts were protected.
    pub budget_unsatisfied_bytes: u64,
}

/// Result of reclaiming unreferenced content-addressed blobs (WOR-1862).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PruneReport {
    /// Physical content-addressed blob bytes before pruning.
    pub before_bytes: u64,
    /// Number of unreferenced blobs found (deleted unless `dry_run`).
    pub orphan_blobs: u64,
    /// Bytes reclaimed, or that would be reclaimed under `dry_run`.
    pub reclaimed_bytes: u64,
    /// Whether this was a report-only run that deleted nothing.
    pub dry_run: bool,
}

/// Result of one exact, protected artifact removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoveArtifactReport {
    /// Canonical artifact digest requested by the operator.
    pub artifact_digest: String,
    /// Whether a ready artifact existed and was removed.
    pub removed: bool,
    /// Physical blob bytes reclaimed after shared-blob reference checks.
    pub reclaimed_bytes: u64,
    /// Durable deletion operation ID, absent for an idempotent miss.
    pub job_id: Option<String>,
}

impl ArtifactManager {
    /// Reclaim content-addressed blobs referenced by no cached artifact
    /// (WOR-1862): orphans left by an interrupted pull or a removed
    /// artifact whose shared blobs another model no longer keeps alive.
    /// This is the standalone counterpart to the post-collection sweep
    /// `enforce_budget` already runs. Under the collection lock so it never
    /// races a concurrent pull's promote. `dry_run` reports what it would
    /// reclaim and deletes nothing; a cold cache with no orphans reclaims
    /// zero either way.
    pub fn prune(&self, dry_run: bool) -> Result<PruneReport, ArtifactError> {
        let _mutation = self.cache.lock_exclusive_mutation()?;
        let before_bytes = self.cache.blob_bytes()?;
        let (orphan_blobs, reclaimed_bytes) = if dry_run {
            let (bytes, count) = self.cache.unreferenced_blob_bytes()?;
            (count, bytes)
        } else {
            let (_, count) = self.cache.unreferenced_blob_bytes()?;
            let reclaimed = self.cache.remove_unreferenced_blobs()?;
            (count, reclaimed)
        };
        Ok(PruneReport {
            before_bytes,
            orphan_blobs,
            reclaimed_bytes,
            dry_run,
        })
    }

    /// Enforce a physical blob budget without deleting protected or busy artifacts.
    pub fn enforce_budget(
        &self,
        budget_bytes: u64,
        protection: &CacheProtection,
    ) -> Result<GcReport, ArtifactError> {
        let _mutation = self.cache.lock_exclusive_mutation()?;
        let before_bytes = self.cache.blob_bytes()?;
        let mut candidates = self.cache.metadata_entries()?;
        candidates.sort_by(|left, right| {
            (left.last_accessed_ms, left.artifact_digest.as_str())
                .cmp(&(right.last_accessed_ms, right.artifact_digest.as_str()))
        });
        let mut skipped_artifacts = BTreeMap::new();
        let mut deleted_artifacts = Vec::new();

        self.cache.remove_unreferenced_blobs()?;
        let mut after_bytes = self.cache.blob_bytes()?;

        for candidate in candidates {
            if after_bytes <= budget_bytes {
                break;
            }
            let digest = candidate.artifact_digest;
            if let Some(reason) = explicit_protection_reason(protection, &digest) {
                skipped_artifacts.insert(digest, reason.to_string());
                continue;
            }
            let Some(_lease_lock) = self.cache.try_lock_exclusive_lease(&digest)? else {
                skipped_artifacts.insert(digest, "leased".to_string());
                continue;
            };
            let Some(_artifact_lock) = self.cache.try_lock_artifact(&digest)? else {
                skipped_artifacts.insert(digest, "locked".to_string());
                continue;
            };
            let Some(_metadata) = self.cache.verified_metadata(&digest)? else {
                continue;
            };
            if let Some(state) = active_state(&self.jobs, &digest)? {
                skipped_artifacts.insert(digest, state_name(state).to_string());
                continue;
            }

            let job = self
                .jobs
                .create(OperationKind::Delete, format!("artifact:sha256:{digest}"))?;
            let deleting = self.jobs.transition(
                &job.id,
                OperationState::Deleting,
                OperationProgress::default(),
                None,
            )?;
            if let Err(error) = self.cache.delete_ready_artifact(&digest) {
                let _ = self.jobs.transition(
                    &deleting.id,
                    OperationState::Failed,
                    OperationProgress::default(),
                    Some(&error.to_string()),
                );
                return Err(error);
            }
            self.cache.remove_unreferenced_blobs()?;
            self.jobs.transition(
                &deleting.id,
                OperationState::Deleted,
                OperationProgress::default(),
                None,
            )?;
            deleted_artifacts.push(digest);
            after_bytes = self.cache.blob_bytes()?;
        }

        Ok(GcReport {
            before_bytes,
            after_bytes,
            reclaimed_bytes: before_bytes.saturating_sub(after_bytes),
            deleted_artifacts,
            skipped_artifacts,
            budget_unsatisfied_bytes: after_bytes.saturating_sub(budget_bytes),
        })
    }

    /// Remove one exact verified artifact after revalidating every protection.
    ///
    /// A missing artifact is an idempotent success. Configured, resident,
    /// pinned, locked, or nonterminal artifacts fail closed with a stable
    /// [`ArtifactError::RemovalBlocked`] reason.
    pub async fn remove(
        &self,
        artifact_digest: &str,
        protection: &CacheProtection,
    ) -> Result<RemoveArtifactReport, ArtifactError> {
        if let Some(reason) = explicit_protection_reason(protection, artifact_digest) {
            return Err(removal_blocked(artifact_digest, reason));
        }
        let digest = artifact_digest.to_string();
        let cache = self.cache.clone();
        let jobs = self.jobs.clone();
        let observer = self.observer.clone();
        let protection = protection.clone();
        tokio::task::spawn_blocking(move || {
            let _mutation = cache.lock_exclusive_mutation()?;
            let Some(_lease_lock) = cache.try_lock_exclusive_lease(&digest)? else {
                return Err(removal_blocked(&digest, "leased"));
            };
            let Some(_artifact_lock) = cache.try_lock_artifact(&digest)? else {
                return Err(removal_blocked(&digest, "locked"));
            };
            if let Some(reason) = explicit_protection_reason(&protection, &digest) {
                return Err(removal_blocked(&digest, reason));
            }
            if let Some(state) = active_state(&jobs, &digest)? {
                return Err(removal_blocked(&digest, state_name(state)));
            }
            let Some(_metadata) = cache.verified_metadata(&digest)? else {
                return Ok(RemoveArtifactReport {
                    artifact_digest: digest,
                    removed: false,
                    reclaimed_bytes: 0,
                    job_id: None,
                });
            };

            cache.remove_unreferenced_blobs()?;
            let before_bytes = cache.blob_bytes()?;
            let job = jobs.create(OperationKind::Delete, format!("artifact:sha256:{digest}"))?;
            observer.on_job(&job);
            let deleting = jobs.transition(
                &job.id,
                OperationState::Deleting,
                OperationProgress::default(),
                None,
            )?;
            observer.on_job(&deleting);
            if let Err(error) = cache.delete_ready_artifact(&digest) {
                if let Ok(failed) = jobs.transition(
                    &deleting.id,
                    OperationState::Failed,
                    OperationProgress::default(),
                    Some(&error.to_string()),
                ) {
                    observer.on_job(&failed);
                }
                return Err(error);
            }
            cache.remove_unreferenced_blobs()?;
            let deleted = jobs.transition(
                &deleting.id,
                OperationState::Deleted,
                OperationProgress::default(),
                None,
            )?;
            observer.on_job(&deleted);
            let after_bytes = cache.blob_bytes()?;
            Ok(RemoveArtifactReport {
                artifact_digest: digest,
                removed: true,
                reclaimed_bytes: before_bytes.saturating_sub(after_bytes),
                job_id: Some(deleted.id),
            })
        })
        .await
        .map_err(|error| ArtifactError::Join(error.to_string()))?
    }
}

pub(crate) fn explicit_protection_reason(
    protection: &CacheProtection,
    digest: &str,
) -> Option<&'static str> {
    if protection.resident.contains(digest) {
        Some("resident")
    } else if protection.configured.contains(digest) {
        Some("configured")
    } else if protection.pinned.contains(digest) {
        Some("pinned")
    } else {
        None
    }
}

fn active_state(
    jobs: &crate::FileJobStore,
    digest: &str,
) -> Result<Option<OperationState>, ArtifactError> {
    let subject = format!("artifact:sha256:{digest}");
    Ok(jobs
        .list()?
        .into_iter()
        .filter(|job| job.subject == subject)
        .map(|job| job.state)
        .find(|state| {
            matches!(
                state,
                OperationState::Queued
                    | OperationState::Downloading
                    | OperationState::Verifying
                    | OperationState::Deleting
            )
        }))
}

fn removal_blocked(digest: &str, reason: &str) -> ArtifactError {
    ArtifactError::RemovalBlocked {
        digest: digest.to_string(),
        reason: reason.to_string(),
    }
}

const fn state_name(state: OperationState) -> &'static str {
    match state {
        OperationState::Downloading => "downloading",
        OperationState::Verifying => "verifying",
        OperationState::Deleting => "deleting",
        OperationState::Queued => "queued",
        OperationState::Ready => "ready",
        OperationState::Failed => "failed",
        OperationState::Deleted => "deleted",
    }
}
