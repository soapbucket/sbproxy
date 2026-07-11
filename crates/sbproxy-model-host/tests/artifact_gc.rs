// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::sync::Arc;

use async_trait::async_trait;
use fs2::FileExt;
use sbproxy_model_host::{
    AcquisitionContext, ArtifactCacheMetadata, ArtifactError, ArtifactFile, ArtifactFormat,
    ArtifactManager, ArtifactTransport, CacheProtection, EngineKind, NetworkPolicy, OperationKind,
    OperationProgress, OperationState, PullIntent, PullPolicy, ResolvedArtifact, SupportLevel,
    TransportRequest, TransportResponse,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

#[derive(Debug)]
struct NoNetwork;

#[async_trait]
impl ArtifactTransport for NoNetwork {
    async fn get(&self, _request: TransportRequest) -> Result<TransportResponse, ArtifactError> {
        Err(ArtifactError::Transport(
            "GC fixtures must use file sources".to_string(),
        ))
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn artifact(digest_byte: char, source: String, bytes: &[u8]) -> ResolvedArtifact {
    ResolvedArtifact {
        catalog_revision: "gc-fixture-v2".to_string(),
        logical_model: format!("model-{digest_byte}"),
        variant_id: "exact".to_string(),
        artifact_digest: digest_byte.to_string().repeat(64),
        format: ArtifactFormat::Gguf,
        quant: "Q4".to_string(),
        engine: EngineKind::LlamaCpp,
        source,
        revision: "local-fixture".to_string(),
        files: vec![ArtifactFile {
            path: "weights.gguf".to_string(),
            sha256: sha256(bytes),
            size_bytes: bytes.len() as u64,
        }],
        context_length: 4096,
        license: "apache-2.0".to_string(),
        stability: SupportLevel::Preview,
        pickle_allowed: false,
    }
}

fn context() -> AcquisitionContext {
    AcquisitionContext {
        intent: PullIntent::Explicit,
        network: NetworkPolicy::Denied,
        pull_policy: PullPolicy::Manual,
        credential: None,
    }
}

async fn prepare_artifact(
    root: &std::path::Path,
    manager: &ArtifactManager,
    digest_byte: char,
    bytes: &[u8],
    last_accessed_ms: u64,
) -> ResolvedArtifact {
    let source = root.join(format!("source-{digest_byte}"));
    fs::create_dir(&source).unwrap();
    fs::write(source.join("weights.gguf"), bytes).unwrap();
    let artifact = artifact(digest_byte, format!("file:{}", source.display()), bytes);
    manager.ensure(&artifact, context()).await.unwrap();
    set_last_access(root, &artifact.artifact_digest, last_accessed_ms);
    artifact
}

fn set_last_access(root: &std::path::Path, digest: &str, last_accessed_ms: u64) {
    let path = root.join("metadata").join(format!("{digest}.json"));
    let mut metadata: ArtifactCacheMetadata =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    metadata.last_accessed_ms = metadata.created_at_ms.saturating_add(last_accessed_ms);
    fs::write(path, serde_json::to_vec_pretty(&metadata).unwrap()).unwrap();
}

#[tokio::test]
async fn lru_collection_reclaims_to_budget_and_records_deletion_jobs() {
    let directory = tempdir().unwrap();
    let manager = ArtifactManager::new(directory.path(), Arc::new(NoNetwork)).unwrap();
    let oldest = prepare_artifact(directory.path(), &manager, '1', b"1111111111", 1).await;
    let middle = prepare_artifact(directory.path(), &manager, '2', b"2222222222", 2).await;
    let newest = prepare_artifact(directory.path(), &manager, '3', b"3333333333", 3).await;

    let report = manager
        .enforce_budget(20, &CacheProtection::default())
        .expect("collect to two blobs");

    assert_eq!(report.before_bytes, 30);
    assert_eq!(report.after_bytes, 20);
    assert_eq!(report.reclaimed_bytes, 10);
    assert_eq!(
        report.deleted_artifacts,
        vec![oldest.artifact_digest.clone()]
    );
    assert_eq!(report.budget_unsatisfied_bytes, 0);
    assert!(!directory
        .path()
        .join("metadata")
        .join(format!("{}.json", oldest.artifact_digest))
        .exists());
    assert!(directory
        .path()
        .join("metadata")
        .join(format!("{}.json", middle.artifact_digest))
        .exists());
    assert!(directory
        .path()
        .join("metadata")
        .join(format!("{}.json", newest.artifact_digest))
        .exists());
    assert!(manager.jobs().list().unwrap().iter().any(|job| {
        job.kind == OperationKind::Delete
            && job.subject.ends_with(&oldest.artifact_digest)
            && job.state == OperationState::Deleted
    }));
}

#[tokio::test]
async fn shared_blob_survives_deleting_one_reference() {
    let directory = tempdir().unwrap();
    let manager = ArtifactManager::new(directory.path(), Arc::new(NoNetwork)).unwrap();
    let shared_bytes = b"sharedblob";
    let first = prepare_artifact(directory.path(), &manager, '4', shared_bytes, 1).await;
    let unique = prepare_artifact(directory.path(), &manager, '5', b"uniqueblob", 2).await;
    let second = prepare_artifact(directory.path(), &manager, '6', shared_bytes, 3).await;
    let shared_blob = directory
        .path()
        .join("blobs/sha256")
        .join(sha256(shared_bytes));

    let report = manager
        .enforce_budget(shared_bytes.len() as u64, &CacheProtection::default())
        .unwrap();

    assert_eq!(report.before_bytes, 20);
    assert_eq!(report.after_bytes, 10);
    assert_eq!(
        report.deleted_artifacts,
        vec![first.artifact_digest, unique.artifact_digest]
    );
    assert!(
        shared_blob.exists(),
        "remaining snapshot still references blob"
    );
    assert!(directory
        .path()
        .join("metadata")
        .join(format!("{}.json", second.artifact_digest))
        .exists());
}

#[tokio::test]
async fn resident_and_pinned_artifacts_are_nonfatal_budget_constraints() {
    let directory = tempdir().unwrap();
    let manager = ArtifactManager::new(directory.path(), Arc::new(NoNetwork)).unwrap();
    let resident = prepare_artifact(directory.path(), &manager, '7', b"resident10", 1).await;
    let pinned = prepare_artifact(directory.path(), &manager, '8', b"pinned-010", 2).await;
    let disposable = prepare_artifact(directory.path(), &manager, '9', b"dispose010", 3).await;
    let protection = CacheProtection {
        resident: BTreeSet::from([resident.artifact_digest.clone()]),
        pinned: BTreeSet::from([pinned.artifact_digest.clone()]),
    };

    let report = manager.enforce_budget(0, &protection).unwrap();

    assert_eq!(report.deleted_artifacts, vec![disposable.artifact_digest]);
    assert_eq!(report.after_bytes, 20);
    assert_eq!(report.budget_unsatisfied_bytes, 20);
    assert_eq!(
        report.skipped_artifacts.get(&resident.artifact_digest),
        Some(&"resident".to_string())
    );
    assert_eq!(
        report.skipped_artifacts.get(&pinned.artifact_digest),
        Some(&"pinned".to_string())
    );
}

#[tokio::test]
async fn locked_and_active_artifacts_are_never_collected() {
    let directory = tempdir().unwrap();
    let manager = ArtifactManager::new(directory.path(), Arc::new(NoNetwork)).unwrap();
    let locked = prepare_artifact(directory.path(), &manager, 'a', b"locked-010", 1).await;
    let downloading = prepare_artifact(directory.path(), &manager, 'b', b"download10", 2).await;
    let verifying = prepare_artifact(directory.path(), &manager, 'c', b"verify--10", 3).await;
    let deleting = prepare_artifact(directory.path(), &manager, 'd', b"deleting10", 4).await;

    let lock_path = directory
        .path()
        .join("locks")
        .join(format!("{}.lock", locked.artifact_digest));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .unwrap();
    FileExt::lock_exclusive(&lock).unwrap();

    let download_job = manager
        .jobs()
        .create(
            OperationKind::Pull,
            format!("artifact:sha256:{}", downloading.artifact_digest),
        )
        .unwrap();
    manager
        .jobs()
        .transition(
            &download_job.id,
            OperationState::Downloading,
            OperationProgress::default(),
            None,
        )
        .unwrap();
    let verify_job = manager
        .jobs()
        .create(
            OperationKind::Pull,
            format!("artifact:sha256:{}", verifying.artifact_digest),
        )
        .unwrap();
    manager
        .jobs()
        .transition(
            &verify_job.id,
            OperationState::Verifying,
            OperationProgress::default(),
            None,
        )
        .unwrap();
    let delete_job = manager
        .jobs()
        .create(
            OperationKind::Delete,
            format!("artifact:sha256:{}", deleting.artifact_digest),
        )
        .unwrap();
    manager
        .jobs()
        .transition(
            &delete_job.id,
            OperationState::Deleting,
            OperationProgress::default(),
            None,
        )
        .unwrap();

    let report = manager
        .enforce_budget(0, &CacheProtection::default())
        .unwrap();

    assert!(report.deleted_artifacts.is_empty());
    assert_eq!(report.before_bytes, 40);
    assert_eq!(report.after_bytes, 40);
    assert_eq!(report.budget_unsatisfied_bytes, 40);
    assert_eq!(
        report.skipped_artifacts.get(&locked.artifact_digest),
        Some(&"locked".to_string())
    );
    assert_eq!(
        report.skipped_artifacts.get(&downloading.artifact_digest),
        Some(&"downloading".to_string())
    );
    assert_eq!(
        report.skipped_artifacts.get(&verifying.artifact_digest),
        Some(&"verifying".to_string())
    );
    assert_eq!(
        report.skipped_artifacts.get(&deleting.artifact_digest),
        Some(&"deleting".to_string())
    );
}
