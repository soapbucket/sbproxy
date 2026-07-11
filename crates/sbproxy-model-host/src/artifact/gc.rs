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

impl ArtifactManager {
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
            let Some(_artifact_lock) = self.cache.try_lock_artifact(&digest)? else {
                skipped_artifacts.insert(digest, "locked".to_string());
                continue;
            };
            let Some(_metadata) = self.cache.verified_metadata(&digest)? else {
                continue;
            };
            if let Some(state) = active_state(self, &digest)? {
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
}

pub(crate) fn explicit_protection_reason(
    protection: &CacheProtection,
    digest: &str,
) -> Option<&'static str> {
    if protection.resident.contains(digest) {
        Some("resident")
    } else if protection.pinned.contains(digest) {
        Some("pinned")
    } else {
        None
    }
}

fn active_state(
    manager: &ArtifactManager,
    digest: &str,
) -> Result<Option<OperationState>, ArtifactError> {
    let subject = format!("artifact:sha256:{digest}");
    Ok(manager
        .jobs
        .list()?
        .into_iter()
        .filter(|job| job.subject == subject)
        .map(|job| job.state)
        .find(|state| {
            matches!(
                state,
                OperationState::Downloading | OperationState::Verifying | OperationState::Deleting
            )
        }))
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
