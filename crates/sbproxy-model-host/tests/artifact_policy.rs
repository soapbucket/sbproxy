// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::collections::VecDeque;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use sbproxy_model_host::{
    select_weight_file, AcquisitionContext, ArtifactError, ArtifactFile, ArtifactFormat,
    ArtifactManager, ArtifactObserver, ArtifactTransport, EngineKind, NetworkPolicy, OperationJob,
    OperationState, PullIntent, PullPolicy, ResolvedArtifact, ResponseDisposition,
    SourceCredential, SupportLevel, TransportRequest, TransportResponse,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug)]
enum BodyStep {
    Bytes(Vec<u8>),
    Error(&'static str),
}

#[derive(Debug)]
struct ResponseStep {
    disposition: ResponseDisposition,
    etag: Option<&'static str>,
    total_size: Option<u64>,
    body: Vec<BodyStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestRecord {
    url: String,
    offset: u64,
    if_range: Option<String>,
    credential_debug: Option<String>,
}

#[derive(Clone, Default)]
struct ScriptedTransport {
    steps: Arc<Mutex<VecDeque<ResponseStep>>>,
    requests: Arc<Mutex<Vec<RequestRecord>>>,
}

impl ScriptedTransport {
    fn new(steps: impl IntoIterator<Item = ResponseStep>) -> Self {
        Self {
            steps: Arc::new(Mutex::new(steps.into_iter().collect())),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn requests(&self) -> Vec<RequestRecord> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl ArtifactTransport for ScriptedTransport {
    async fn get(&self, request: TransportRequest) -> Result<TransportResponse, ArtifactError> {
        self.requests.lock().unwrap().push(RequestRecord {
            url: request.url,
            offset: request.offset,
            if_range: request.if_range,
            credential_debug: request
                .credential
                .as_ref()
                .map(|credential| format!("{credential:?}")),
        });
        let step = self
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted transport exhausted");
        let body = step.body.into_iter().map(|step| match step {
            BodyStep::Bytes(bytes) => Ok(Bytes::from(bytes)),
            BodyStep::Error(message) => Err(ArtifactError::Transport(message.to_string())),
        });
        Ok(TransportResponse {
            disposition: step.disposition,
            etag: step.etag.map(str::to_string),
            total_size: step.total_size,
            body: Box::pin(stream::iter(body)),
        })
    }
}

#[derive(Clone, Default)]
struct CountingTransport {
    calls: Arc<AtomicUsize>,
}

impl CountingTransport {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ArtifactTransport for CountingTransport {
    async fn get(&self, _request: TransportRequest) -> Result<TransportResponse, ArtifactError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ArtifactError::Transport(
            "counting transport must not be called".to_string(),
        ))
    }
}

fn response(
    disposition: ResponseDisposition,
    etag: Option<&'static str>,
    total_size: u64,
    body: Vec<BodyStep>,
) -> ResponseStep {
    ResponseStep {
        disposition,
        etag,
        total_size: Some(total_size),
        body,
    }
}

fn artifact(
    digest_byte: char,
    source: String,
    path: &str,
    bytes: &[u8],
    format: ArtifactFormat,
    pickle_allowed: bool,
) -> ResolvedArtifact {
    ResolvedArtifact {
        catalog_revision: "policy-fixture-v2".to_string(),
        logical_model: format!("fixture-{digest_byte}"),
        variant_id: "exact".to_string(),
        artifact_digest: digest_byte.to_string().repeat(64),
        format,
        quant: "fixture".to_string(),
        engine: if format == ArtifactFormat::Gguf {
            EngineKind::LlamaCpp
        } else {
            EngineKind::Vllm
        },
        source,
        revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
        files: vec![ArtifactFile {
            path: path.to_string(),
            sha256: sha256(bytes),
            size_bytes: bytes.len() as u64,
        }],
        context_length: 4096,
        license: "apache-2.0".to_string(),
        stability: SupportLevel::Preview,
        pickle_allowed,
    }
}

fn context(
    intent: PullIntent,
    network: NetworkPolicy,
    pull_policy: PullPolicy,
) -> AcquisitionContext {
    AcquisitionContext {
        intent,
        network,
        pull_policy,
        credential: None,
    }
}

#[tokio::test]
async fn interrupted_download_resumes_only_with_matching_url_etag_digest_and_size() {
    let directory = tempdir().unwrap();
    let bytes = b"0123456789";
    let transport = Arc::new(ScriptedTransport::new([
        response(
            ResponseDisposition::Replacement,
            Some("etag-one"),
            bytes.len() as u64,
            vec![
                BodyStep::Bytes(bytes[..4].to_vec()),
                BodyStep::Error("interrupted"),
            ],
        ),
        response(
            ResponseDisposition::Append,
            Some("etag-one"),
            bytes.len() as u64,
            vec![BodyStep::Bytes(bytes[4..].to_vec())],
        ),
    ]));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let artifact = artifact(
        '1',
        "hf:Fixture/Resume".to_string(),
        "weights.safetensors",
        bytes,
        ArtifactFormat::Safetensors,
        false,
    );

    manager
        .ensure(
            &artifact,
            context(
                PullIntent::Explicit,
                NetworkPolicy::Allowed,
                PullPolicy::OnDemand,
            ),
        )
        .await
        .expect_err("first body is interrupted");
    let ready = manager
        .ensure(
            &artifact,
            context(
                PullIntent::Explicit,
                NetworkPolicy::Allowed,
                PullPolicy::OnDemand,
            ),
        )
        .await
        .expect("matching partial resumes");

    assert_eq!(
        fs::read(ready.file("weights.safetensors").unwrap()).unwrap(),
        bytes
    );
    let requests = transport.requests();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.offset)
            .collect::<Vec<_>>(),
        vec![0, 4]
    );
    assert_eq!(requests[1].if_range.as_deref(), Some("etag-one"));
    assert!(!directory
        .path()
        .join("partials")
        .join(&artifact.artifact_digest)
        .join("weights.safetensors.resume.json")
        .exists());
}

#[tokio::test]
async fn changed_etag_discards_append_body_and_restarts_from_zero() {
    let directory = tempdir().unwrap();
    let bytes = b"abcdefghij";
    let transport = Arc::new(ScriptedTransport::new([
        response(
            ResponseDisposition::Replacement,
            Some("old"),
            bytes.len() as u64,
            vec![
                BodyStep::Bytes(bytes[..3].to_vec()),
                BodyStep::Error("interrupted"),
            ],
        ),
        response(
            ResponseDisposition::Append,
            Some("new"),
            bytes.len() as u64,
            vec![BodyStep::Bytes(b"must-not-be-used".to_vec())],
        ),
        response(
            ResponseDisposition::Replacement,
            Some("new"),
            bytes.len() as u64,
            vec![BodyStep::Bytes(bytes.to_vec())],
        ),
    ]));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let artifact = artifact(
        '2',
        "hf:Fixture/Changed".to_string(),
        "weights.safetensors",
        bytes,
        ArtifactFormat::Safetensors,
        false,
    );
    let pull = || {
        context(
            PullIntent::Explicit,
            NetworkPolicy::Allowed,
            PullPolicy::OnDemand,
        )
    };

    manager.ensure(&artifact, pull()).await.unwrap_err();
    let ready = manager.ensure(&artifact, pull()).await.unwrap();

    assert_eq!(
        fs::read(ready.file("weights.safetensors").unwrap()).unwrap(),
        bytes
    );
    assert_eq!(
        transport
            .requests()
            .iter()
            .map(|request| request.offset)
            .collect::<Vec<_>>(),
        vec![0, 3, 0]
    );
}

#[tokio::test]
async fn changed_source_url_invalidates_resume_metadata_before_transport() {
    let directory = tempdir().unwrap();
    let bytes = b"source-bound";
    let transport = Arc::new(ScriptedTransport::new([
        response(
            ResponseDisposition::Replacement,
            Some("one"),
            bytes.len() as u64,
            vec![
                BodyStep::Bytes(bytes[..5].to_vec()),
                BodyStep::Error("interrupted"),
            ],
        ),
        response(
            ResponseDisposition::Replacement,
            Some("two"),
            bytes.len() as u64,
            vec![BodyStep::Bytes(bytes.to_vec())],
        ),
    ]));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let first = artifact(
        '3',
        "hf:Fixture/SourceOne".to_string(),
        "weights.safetensors",
        bytes,
        ArtifactFormat::Safetensors,
        false,
    );
    let mut second = first.clone();
    second.source = "hf:Fixture/SourceTwo".to_string();
    let pull = || {
        context(
            PullIntent::Explicit,
            NetworkPolicy::Allowed,
            PullPolicy::OnDemand,
        )
    };

    manager.ensure(&first, pull()).await.unwrap_err();
    manager.ensure(&second, pull()).await.unwrap();

    let requests = transport.requests();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.offset)
            .collect::<Vec<_>>(),
        vec![0, 0]
    );
    assert!(requests[1].url.contains("SourceTwo"));
}

#[tokio::test]
async fn changed_expected_digest_or_size_invalidates_resume_metadata() {
    let directory = tempdir().unwrap();
    let first_bytes = b"first-generation";
    let second_bytes = b"second-generation-longer";
    let transport = Arc::new(ScriptedTransport::new([
        response(
            ResponseDisposition::Replacement,
            Some("one"),
            first_bytes.len() as u64,
            vec![
                BodyStep::Bytes(first_bytes[..5].to_vec()),
                BodyStep::Error("interrupted"),
            ],
        ),
        response(
            ResponseDisposition::Replacement,
            Some("two"),
            second_bytes.len() as u64,
            vec![BodyStep::Bytes(second_bytes.to_vec())],
        ),
    ]));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let first = artifact(
        'e',
        "hf:Fixture/Generation".to_string(),
        "weights.safetensors",
        first_bytes,
        ArtifactFormat::Safetensors,
        false,
    );
    let second = artifact(
        'e',
        "hf:Fixture/Generation".to_string(),
        "weights.safetensors",
        second_bytes,
        ArtifactFormat::Safetensors,
        false,
    );
    let pull = || {
        context(
            PullIntent::Explicit,
            NetworkPolicy::Allowed,
            PullPolicy::OnDemand,
        )
    };

    manager.ensure(&first, pull()).await.unwrap_err();
    let ready = manager.ensure(&second, pull()).await.unwrap();

    assert_eq!(
        fs::read(ready.file("weights.safetensors").unwrap()).unwrap(),
        second_bytes
    );
    assert_eq!(
        transport
            .requests()
            .iter()
            .map(|request| request.offset)
            .collect::<Vec<_>>(),
        vec![0, 0]
    );
}

#[tokio::test]
async fn exact_size_range_not_satisfiable_completes_existing_partial() {
    let directory = tempdir().unwrap();
    let bytes = b"already-complete";
    let transport = Arc::new(ScriptedTransport::new([
        response(
            ResponseDisposition::Replacement,
            Some("etag"),
            bytes.len() as u64,
            vec![
                BodyStep::Bytes(bytes.to_vec()),
                BodyStep::Error("connection ended after complete body"),
            ],
        ),
        response(
            ResponseDisposition::RangeComplete,
            Some("etag"),
            bytes.len() as u64,
            vec![],
        ),
    ]));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let artifact = artifact(
        '4',
        "hf:Fixture/Complete".to_string(),
        "weights.safetensors",
        bytes,
        ArtifactFormat::Safetensors,
        false,
    );
    let pull = || {
        context(
            PullIntent::Explicit,
            NetworkPolicy::Allowed,
            PullPolicy::OnDemand,
        )
    };

    manager.ensure(&artifact, pull()).await.unwrap_err();
    let ready = manager.ensure(&artifact, pull()).await.unwrap();

    assert_eq!(
        fs::read(ready.file("weights.safetensors").unwrap()).unwrap(),
        bytes
    );
    assert_eq!(transport.requests()[1].offset, bytes.len() as u64);
}

#[tokio::test]
async fn manual_offline_startup_and_file_policies_short_circuit_transport() {
    let directory = tempdir().unwrap();
    let counting = Arc::new(CountingTransport::default());
    let manager = ArtifactManager::new(directory.path(), counting.clone()).unwrap();
    let bytes = b"policy bytes";
    let manual = artifact(
        '5',
        "hf:Fixture/Manual".to_string(),
        "weights.safetensors",
        bytes,
        ArtifactFormat::Safetensors,
        false,
    );

    let error = manager
        .ensure(
            &manual,
            context(
                PullIntent::Runtime,
                NetworkPolicy::Allowed,
                PullPolicy::Manual,
            ),
        )
        .await
        .expect_err("runtime cannot override manual policy");
    assert!(matches!(error, ArtifactError::ManualArtifactMissing { .. }));
    let error = manager
        .ensure(
            &manual,
            context(
                PullIntent::Explicit,
                NetworkPolicy::Denied,
                PullPolicy::Manual,
            ),
        )
        .await
        .expect_err("offline HTTP miss fails before transport");
    assert!(matches!(
        error,
        ArtifactError::OfflineArtifactMissing { .. }
    ));
    let error = manager
        .ensure(
            &manual,
            context(
                PullIntent::Startup,
                NetworkPolicy::Allowed,
                PullPolicy::OnDemand,
            ),
        )
        .await
        .expect_err("startup warming selects only on_boot");
    assert!(matches!(
        error,
        ArtifactError::StartupArtifactNotSelected { .. }
    ));
    assert_eq!(counting.calls(), 0);

    let local = directory.path().join("local");
    fs::create_dir(&local).unwrap();
    fs::write(local.join("weights.gguf"), bytes).unwrap();
    let local_artifact = artifact(
        '6',
        format!("file:{}", local.display()),
        "weights.gguf",
        bytes,
        ArtifactFormat::Gguf,
        false,
    );
    let ready = manager
        .ensure(
            &local_artifact,
            context(
                PullIntent::Explicit,
                NetworkPolicy::Denied,
                PullPolicy::Manual,
            ),
        )
        .await
        .expect("file source needs no network");
    assert_eq!(
        fs::read(ready.file("weights.gguf").unwrap()).unwrap(),
        bytes
    );
    assert_eq!(counting.calls(), 0);
}

#[tokio::test]
async fn explicit_pull_overrides_manual_and_runtime_uses_verified_manual_cache_hit() {
    let directory = tempdir().unwrap();
    let bytes = b"manual explicit";
    let transport = Arc::new(ScriptedTransport::new([response(
        ResponseDisposition::Replacement,
        Some("manual"),
        bytes.len() as u64,
        vec![BodyStep::Bytes(bytes.to_vec())],
    )]));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let artifact = artifact(
        '7',
        "hf:Fixture/Manual".to_string(),
        "weights.safetensors",
        bytes,
        ArtifactFormat::Safetensors,
        false,
    );

    manager
        .ensure(
            &artifact,
            context(
                PullIntent::Explicit,
                NetworkPolicy::Allowed,
                PullPolicy::Manual,
            ),
        )
        .await
        .expect("operator explicitly pulls manual artifact");
    manager
        .ensure(
            &artifact,
            context(
                PullIntent::Runtime,
                NetworkPolicy::Denied,
                PullPolicy::Manual,
            ),
        )
        .await
        .expect("manual runtime may use a verified cache hit");
    assert_eq!(transport.requests().len(), 1);
}

#[tokio::test]
async fn startup_on_boot_and_runtime_on_demand_both_acquire_on_a_miss() {
    let directory = tempdir().unwrap();
    let boot_bytes = b"boot bytes";
    let demand_bytes = b"demand bytes";
    let transport = Arc::new(ScriptedTransport::new([
        response(
            ResponseDisposition::Replacement,
            Some("boot"),
            boot_bytes.len() as u64,
            vec![BodyStep::Bytes(boot_bytes.to_vec())],
        ),
        response(
            ResponseDisposition::Replacement,
            Some("demand"),
            demand_bytes.len() as u64,
            vec![BodyStep::Bytes(demand_bytes.to_vec())],
        ),
    ]));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let boot = artifact(
        'c',
        "hf:Fixture/Boot".to_string(),
        "weights.safetensors",
        boot_bytes,
        ArtifactFormat::Safetensors,
        false,
    );
    let demand = artifact(
        'd',
        "hf:Fixture/Demand".to_string(),
        "weights.safetensors",
        demand_bytes,
        ArtifactFormat::Safetensors,
        false,
    );

    manager
        .ensure(
            &boot,
            context(
                PullIntent::Startup,
                NetworkPolicy::Allowed,
                PullPolicy::OnBoot,
            ),
        )
        .await
        .expect("on-boot artifact warms at startup");
    manager
        .ensure(
            &demand,
            context(
                PullIntent::Runtime,
                NetworkPolicy::Allowed,
                PullPolicy::OnDemand,
            ),
        )
        .await
        .expect("on-demand artifact acquires at runtime");
    assert_eq!(transport.requests().len(), 2);
}

#[derive(Default)]
struct ProgressObserver {
    downloading_updates: AtomicUsize,
}

impl ArtifactObserver for ProgressObserver {
    fn on_job(&self, job: &OperationJob) {
        if job.state == OperationState::Downloading && job.progress.completed_bytes > 0 {
            self.downloading_updates.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[tokio::test]
async fn credential_is_transport_only_and_advancing_progress_is_published() {
    let directory = tempdir().unwrap();
    let bytes = b"three progress chunks";
    let secret = "hf_top_secret_value";
    let transport = Arc::new(ScriptedTransport::new([response(
        ResponseDisposition::Replacement,
        Some("gated"),
        bytes.len() as u64,
        vec![
            BodyStep::Bytes(bytes[..5].to_vec()),
            BodyStep::Bytes(bytes[5..12].to_vec()),
            BodyStep::Bytes(bytes[12..].to_vec()),
        ],
    )]));
    let observer = Arc::new(ProgressObserver::default());
    let manager = ArtifactManager::new(directory.path(), transport.clone())
        .unwrap()
        .with_observer(observer.clone());
    let artifact = artifact(
        '8',
        "hf:Fixture/Gated".to_string(),
        "weights.safetensors",
        bytes,
        ArtifactFormat::Safetensors,
        false,
    );
    let credential = SourceCredential::new(secret).unwrap();
    assert!(!format!("{credential:?}").contains(secret));
    assert!(!credential.to_string().contains(secret));
    let mut acquisition = context(
        PullIntent::Explicit,
        NetworkPolicy::Allowed,
        PullPolicy::OnDemand,
    );
    acquisition.credential = Some(credential);

    manager.ensure(&artifact, acquisition).await.unwrap();

    assert_eq!(
        transport.requests()[0].credential_debug.as_deref(),
        Some("SourceCredential([REDACTED])")
    );
    assert!(observer.downloading_updates.load(Ordering::SeqCst) >= 2);
    assert_cache_tree_excludes(directory.path(), secret);
}

#[tokio::test]
async fn pickle_requires_resolution_opt_in_and_is_scanned_before_finalization() {
    let directory = tempdir().unwrap();
    let malicious = b"cos\nsystem\n.";
    let benign = b"ctorch._utils\n_rebuild_tensor_v2\n.";
    let transport = Arc::new(ScriptedTransport::new([
        response(
            ResponseDisposition::Replacement,
            Some("bad"),
            malicious.len() as u64,
            vec![BodyStep::Bytes(malicious.to_vec())],
        ),
        response(
            ResponseDisposition::Replacement,
            Some("good"),
            benign.len() as u64,
            vec![BodyStep::Bytes(benign.to_vec())],
        ),
    ]));
    let manager = ArtifactManager::new(directory.path(), transport.clone()).unwrap();
    let refused = artifact(
        '9',
        "hf:Fixture/Pickle".to_string(),
        "model.bin",
        benign,
        ArtifactFormat::Pickle,
        false,
    );
    let pull = || {
        context(
            PullIntent::Explicit,
            NetworkPolicy::Allowed,
            PullPolicy::OnDemand,
        )
    };
    assert!(matches!(
        manager.ensure(&refused, pull()).await,
        Err(ArtifactError::PickleRefused { .. })
    ));
    assert!(transport.requests().is_empty());

    let unsafe_artifact = artifact(
        'a',
        "hf:Fixture/Pickle".to_string(),
        "model.bin",
        malicious,
        ArtifactFormat::Pickle,
        true,
    );
    assert!(matches!(
        manager.ensure(&unsafe_artifact, pull()).await,
        Err(ArtifactError::PickleUnsafe { .. })
    ));
    assert!(!directory
        .path()
        .join("snapshots")
        .join(&unsafe_artifact.artifact_digest)
        .exists());

    let safe_artifact = artifact(
        'b',
        "hf:Fixture/Pickle".to_string(),
        "model.bin",
        benign,
        ArtifactFormat::Pickle,
        true,
    );
    manager
        .ensure(&safe_artifact, pull())
        .await
        .expect("opted-in benign pickle passes scan");
    assert_eq!(transport.requests().len(), 2);

    assert_eq!(
        select_weight_file(
            &["model.bin".to_string(), "model.safetensors".to_string()],
            true
        )
        .unwrap(),
        "model.safetensors"
    );
}

fn assert_cache_tree_excludes(root: &std::path::Path, needle: &str) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap().filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let bytes = fs::read(&path).unwrap();
                assert!(
                    !String::from_utf8_lossy(&bytes).contains(needle),
                    "secret leaked to {}",
                    path.display()
                );
            }
        }
    }
}
