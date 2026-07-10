// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use sbproxy_model_host::{
    AcquisitionContext, ArtifactCacheState, ArtifactError, ArtifactFile, ArtifactFormat,
    ArtifactManager, ArtifactObserver, ArtifactTransport, EngineKind, NetworkPolicy, OperationJob,
    OperationState, PullIntent, PullPolicy, ReadyArtifact, ResolvedArtifact, ResponseDisposition,
    SupportLevel, TransportRequest, TransportResponse,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone)]
struct FakeTransport {
    files: Arc<BTreeMap<String, Vec<u8>>>,
    requests: Arc<AtomicUsize>,
}

impl FakeTransport {
    fn new(files: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            files: Arc::new(files),
            requests: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ArtifactTransport for FakeTransport {
    async fn get(&self, request: TransportRequest) -> Result<TransportResponse, ArtifactError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let (path, bytes) = self
            .files
            .iter()
            .find(|(path, _)| request.url.ends_with(path.as_str()))
            .ok_or_else(|| ArtifactError::Transport(format!("unexpected URL {}", request.url)))?;
        assert_eq!(request.offset, 0, "basic manager starts from byte zero");
        assert!(request.if_range.is_none());
        let split = bytes.len().div_ceil(2);
        let chunks = bytes
            .chunks(split.max(1))
            .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
            .collect::<Vec<_>>();
        Ok(TransportResponse {
            disposition: ResponseDisposition::Replacement,
            etag: Some(format!("fixture-{path}")),
            total_size: Some(bytes.len() as u64),
            body: Box::pin(stream::iter(chunks)),
        })
    }
}

fn artifact(digest_byte: char, files: &BTreeMap<String, Vec<u8>>) -> ResolvedArtifact {
    ResolvedArtifact {
        catalog_revision: "fixture-catalog-v2".to_string(),
        logical_model: "fixture-model".to_string(),
        variant_id: "safetensors".to_string(),
        artifact_digest: digest_byte.to_string().repeat(64),
        format: ArtifactFormat::Safetensors,
        quant: "bf16".to_string(),
        engine: EngineKind::Vllm,
        source: "hf:Fixture/Model".to_string(),
        revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
        files: files
            .iter()
            .map(|(path, bytes)| ArtifactFile {
                path: path.clone(),
                sha256: sha256(bytes),
                size_bytes: bytes.len() as u64,
            })
            .collect(),
        context_length: 8192,
        license: "apache-2.0".to_string(),
        stability: SupportLevel::Preview,
        pickle_allowed: false,
    }
}

fn context() -> AcquisitionContext {
    AcquisitionContext {
        intent: PullIntent::Explicit,
        network: NetworkPolicy::Allowed,
        pull_policy: PullPolicy::OnDemand,
        credential: None,
    }
}

fn fixture_files() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            "config/config.json".to_string(),
            br#"{"model_type":"fixture"}"#.to_vec(),
        ),
        (
            "model-00001-of-00001.safetensors".to_string(),
            b"safe tensor fixture bytes".to_vec(),
        ),
    ])
}

#[derive(Default)]
struct PhaseObserver {
    snapshot: Mutex<Option<PathBuf>>,
    saw_verifying: AtomicBool,
    states: Mutex<Vec<OperationState>>,
}

impl ArtifactObserver for PhaseObserver {
    fn on_job(&self, job: &OperationJob) {
        self.states.lock().unwrap().push(job.state);
        if job.state == OperationState::Verifying {
            let snapshot = self.snapshot.lock().unwrap().clone().unwrap();
            assert!(
                !snapshot.exists(),
                "final snapshot must remain invisible until verification completes"
            );
            self.saw_verifying.store(true, Ordering::SeqCst);
        }
    }
}

#[tokio::test]
async fn successful_multi_file_pull_is_atomic_and_preserves_snapshot_layout() {
    let directory = tempdir().expect("temp dir");
    let files = fixture_files();
    let artifact = artifact('a', &files);
    let transport = Arc::new(FakeTransport::new(files.clone()));
    let observer = Arc::new(PhaseObserver::default());
    *observer.snapshot.lock().unwrap() = Some(
        directory
            .path()
            .join("snapshots")
            .join(&artifact.artifact_digest),
    );
    let manager = ArtifactManager::new(directory.path(), transport.clone())
        .expect("artifact manager")
        .with_observer(observer.clone());

    let ready = manager
        .ensure(&artifact, context())
        .await
        .expect("verified artifact");

    assert_ready_matches(&ready, &files);
    assert_eq!(ready.job.state, OperationState::Ready);
    assert_eq!(
        ready.job.progress.completed_bytes,
        files.values().map(Vec::len).sum::<usize>() as u64
    );
    assert!(ready.job.progress.current_file.is_none());
    assert_eq!(transport.request_count(), files.len());
    assert!(ready.snapshot_path.join("artifact.json").is_file());
    assert!(observer.saw_verifying.load(Ordering::SeqCst));
    let states: BTreeSet<_> = observer.states.lock().unwrap().iter().copied().collect();
    assert!(states.contains(&OperationState::Queued));
    assert!(states.contains(&OperationState::Downloading));
    assert!(states.contains(&OperationState::Verifying));
    assert!(states.contains(&OperationState::Ready));

    assert!(matches!(
        manager.inspect(&artifact.artifact_digest).unwrap(),
        ArtifactCacheState::Ready { .. }
    ));
}

#[tokio::test]
async fn a_verified_cache_hit_performs_zero_transport_requests() {
    let directory = tempdir().expect("temp dir");
    let files = fixture_files();
    let artifact = artifact('b', &files);
    let transport = Arc::new(FakeTransport::new(files));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();

    let first = manager.ensure(&artifact, context()).await.unwrap();
    let after_first = transport.request_count();
    let second = manager.ensure(&artifact, context()).await.unwrap();

    assert_eq!(transport.request_count(), after_first);
    assert_eq!(first.snapshot_path, second.snapshot_path);
    assert_ne!(first.job.id, second.job.id);
    assert_eq!(second.job.state, OperationState::Ready);
}

#[tokio::test]
async fn tampered_ready_snapshot_fails_closed_without_network_repair() {
    let directory = tempdir().expect("temp dir");
    let files = fixture_files();
    let artifact = artifact('c', &files);
    let transport = Arc::new(FakeTransport::new(files));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let ready = manager.ensure(&artifact, context()).await.unwrap();
    let requests = transport.request_count();

    let target = ready.snapshot_path.join("config/config.json");
    fs::remove_file(&target).expect("unlink snapshot hard link");
    fs::write(&target, b"tampered").expect("replace snapshot bytes");

    let error = manager
        .ensure(&artifact, context())
        .await
        .expect_err("tampered ready bytes cannot be trusted or repaired implicitly");
    assert!(matches!(error, ArtifactError::CacheCorrupt { .. }));
    assert_eq!(transport.request_count(), requests);
    assert!(matches!(
        manager.inspect(&artifact.artifact_digest).unwrap(),
        ArtifactCacheState::Corrupt { .. }
    ));
}

#[tokio::test]
async fn digest_mismatch_leaves_no_ready_snapshot_or_partial_bytes() {
    let directory = tempdir().expect("temp dir");
    let served = BTreeMap::from([("weights.safetensors".to_string(), b"wrong bytes".to_vec())]);
    let expected = BTreeMap::from([("weights.safetensors".to_string(), b"right bytes".to_vec())]);
    let artifact = artifact('d', &expected);
    let transport = Arc::new(FakeTransport::new(served));
    let manager = ArtifactManager::new(directory.path(), transport).unwrap();

    let error = manager
        .ensure(&artifact, context())
        .await
        .expect_err("digest mismatch fails acquisition");
    assert!(matches!(error, ArtifactError::DigestMismatch { .. }));
    assert!(!directory
        .path()
        .join("snapshots")
        .join(&artifact.artifact_digest)
        .exists());
    assert!(!directory
        .path()
        .join("metadata")
        .join(format!("{}.json", artifact.artifact_digest))
        .exists());
    let partial_root = directory
        .path()
        .join("partials")
        .join(&artifact.artifact_digest);
    assert!(
        !partial_root.exists() || fs::read_dir(partial_root).unwrap().next().is_none(),
        "unverified bytes must be removed"
    );
    assert!(manager
        .jobs()
        .list()
        .unwrap()
        .iter()
        .any(|job| job.state == OperationState::Failed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_managers_share_one_cross_process_artifact_lock() {
    let directory = tempdir().expect("temp dir");
    let files = fixture_files();
    let artifact = artifact('e', &files);
    let transport = Arc::new(FakeTransport::new(files.clone()));
    let first = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let second = ArtifactManager::new(directory.path(), transport.clone()).unwrap();

    let (left, right) = tokio::join!(
        first.ensure(&artifact, context()),
        second.ensure(&artifact, context())
    );
    let left = left.expect("first caller");
    let right = right.expect("second caller");

    assert_eq!(left.snapshot_path, right.snapshot_path);
    assert_eq!(transport.request_count(), files.len());
    assert_eq!(first.jobs().list().unwrap().len(), 2);
    assert!(first
        .jobs()
        .list()
        .unwrap()
        .iter()
        .all(|job| job.state == OperationState::Ready));
}

#[tokio::test]
async fn legacy_adapter_is_atomic_and_records_explicit_trust() {
    let directory = tempdir().expect("temp dir");
    let bytes = b"legacy compatibility weights".to_vec();
    let transport = Arc::new(FakeTransport::new(BTreeMap::from([(
        "legacy.bin".to_string(),
        bytes.clone(),
    )])));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let digest = sha256(&bytes);

    let first = manager
        .ensure_legacy_file(
            "Fixture/Legacy",
            "0123456789abcdef0123456789abcdef01234567",
            "legacy.bin",
            Some(&digest),
            None,
        )
        .await
        .expect("verified legacy file");
    let second = manager
        .ensure_legacy_file(
            "Fixture/Legacy",
            "0123456789abcdef0123456789abcdef01234567",
            "legacy.bin",
            Some(&digest),
            None,
        )
        .await
        .expect("verified legacy cache hit");

    assert_eq!(first, second);
    assert_eq!(fs::read(first).unwrap(), bytes);
    assert_eq!(transport.request_count(), 1);
    let metadata = fs::read_dir(directory.path().join("metadata"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("legacy-"))
        .expect("legacy trust metadata");
    let metadata = fs::read_to_string(metadata.path()).unwrap();
    assert!(metadata.contains("verified_legacy"));
    assert!(!metadata.contains("preview_unpinned"));
}

#[tokio::test]
async fn unpinned_legacy_adapter_is_explicitly_preview_only() {
    let directory = tempdir().expect("temp dir");
    let bytes = b"unpinned legacy bytes".to_vec();
    let transport = Arc::new(FakeTransport::new(BTreeMap::from([(
        "unpinned.bin".to_string(),
        bytes,
    )])));
    let manager = ArtifactManager::new(directory.path(), transport).unwrap();

    manager
        .ensure_legacy_file("Fixture/Legacy", "main", "unpinned.bin", None, None)
        .await
        .expect("preview legacy file");

    let metadata = fs::read_dir(directory.path().join("metadata"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("legacy-"))
        .expect("legacy trust metadata");
    let metadata = fs::read_to_string(metadata.path()).unwrap();
    assert!(metadata.contains("preview_unpinned"));
    assert!(!metadata.contains("verified_legacy"));
}

fn assert_ready_matches(ready: &ReadyArtifact, expected: &BTreeMap<String, Vec<u8>>) {
    for (path, bytes) in expected {
        assert_eq!(
            fs::read(ready.file(path).expect("declared ready file")).unwrap(),
            *bytes,
            "snapshot path {path}"
        );
    }
}
