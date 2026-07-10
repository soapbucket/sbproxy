// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use sbproxy_model_host::{
    ArtifactError, ArtifactManager, ArtifactTransport, Catalog, EngineKind, EngineLauncher,
    GpuDescriptor, ModelHostConfig, ModelHostRuntime, ModelMetadata, ModelMetadataProvider,
    ModelRef, NetworkPolicy, ResponseDisposition, RuntimeError, StaticGpuProbe, TransportRequest,
    TransportResponse,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone)]
struct MapTransport {
    files: Arc<BTreeMap<String, Vec<u8>>>,
    calls: Arc<AtomicUsize>,
}

impl MapTransport {
    fn new(files: BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            files: Arc::new(files),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ArtifactTransport for MapTransport {
    async fn get(&self, request: TransportRequest) -> Result<TransportResponse, ArtifactError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let bytes = self
            .files
            .iter()
            .find(|(key, _)| request.url.contains(key.as_str()))
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| ArtifactError::Transport(format!("unexpected URL {}", request.url)))?;
        Ok(TransportResponse {
            disposition: ResponseDisposition::Replacement,
            etag: Some("runtime-fixture".to_string()),
            total_size: Some(bytes.len() as u64),
            body: Box::pin(stream::iter([Ok(Bytes::from(bytes))])),
        })
    }
}

#[derive(Clone, Default)]
struct RecordingLauncher {
    specs: Arc<Mutex<Vec<sbproxy_model_host::LaunchSpec>>>,
}

impl RecordingLauncher {
    fn specs(&self) -> Vec<sbproxy_model_host::LaunchSpec> {
        self.specs.lock().unwrap().clone()
    }
}

impl EngineLauncher for RecordingLauncher {
    async fn launch(&self, spec: &sbproxy_model_host::LaunchSpec) -> Result<u16, String> {
        self.specs.lock().unwrap().push(spec.clone());
        let index = spec
            .args
            .iter()
            .position(|arg| arg == "--port")
            .ok_or_else(|| "missing --port".to_string())?;
        spec.args
            .get(index + 1)
            .and_then(|port| port.parse().ok())
            .ok_or_else(|| "invalid --port".to_string())
    }

    async fn kill(&self) {}
}

struct FixtureMetadata;

impl ModelMetadataProvider for FixtureMetadata {
    fn metadata(&self, _model: &ModelRef) -> Option<ModelMetadata> {
        Some(ModelMetadata {
            params: 1_000_000,
            layers: 8,
            kv_heads: 4,
            head_dim: 64,
            max_context: 4096,
        })
    }
}

fn variant_yaml(
    model: &str,
    repo: &str,
    variant: &str,
    format: &str,
    engine: &str,
    file: &str,
    bytes: &[u8],
    pull: &str,
) -> String {
    format!(
        "  {model}:\n    params: 0.001B\n    license: apache-2.0\n    family: fixture\n    context_length: 4096\n    pull: {pull}\n    variants:\n      - id: {variant}\n        format: {format}\n        quant: Q4\n        engines: [{engine}]\n        source: hf:{repo}\n        revision: 0123456789abcdef0123456789abcdef01234567\n        files:\n          - path: {file}\n            sha256: {}\n            size_bytes: {}\n        requirements:\n          accelerators: [cuda]\n          min_compute_capability: {{ major: 7, minor: 5 }}\n          min_memory_bytes: 1\n        stability: preview\n        certification: runtime-fixture\n",
        sha256(bytes),
        bytes.len()
    )
}

fn catalog(models: &str) -> Catalog {
    Catalog::from_yaml(&format!(
        "schema_version: 2\ncatalog_revision: runtime-fixture-v2\nmodels:\n{models}"
    ))
    .unwrap()
}

fn config(yaml: &str) -> ModelHostConfig {
    serde_yaml::from_str(yaml).unwrap()
}

fn runtime(
    config: ModelHostConfig,
    catalog: Catalog,
    manager: Option<Arc<ArtifactManager>>,
    network: NetworkPolicy,
    launcher: RecordingLauncher,
) -> ModelHostRuntime<RecordingLauncher> {
    let launcher_factory = launcher.clone();
    let runtime = ModelHostRuntime::new(
        config,
        catalog,
        Arc::new(StaticGpuProbe::new(vec![GpuDescriptor::l4()])),
        Arc::new(FixtureMetadata),
        Box::new(move || launcher_factory.clone()),
        false,
    )
    .with_artifact_network_policy(network);
    match manager {
        Some(manager) => runtime.with_artifact_manager(manager),
        None => runtime,
    }
}

#[tokio::test]
async fn on_demand_gguf_is_verified_before_launcher_gets_only_a_local_model() {
    let directory = tempdir().unwrap();
    let bytes = b"fixture gguf bytes";
    let transport = Arc::new(MapTransport::new(BTreeMap::from([(
        "Fixture/Gguf".to_string(),
        bytes.to_vec(),
    )])));
    let manager = Arc::new(ArtifactManager::new(directory.path(), transport.clone()).unwrap());
    let launcher = RecordingLauncher::default();
    let catalog = catalog(&variant_yaml(
        "coder",
        "Fixture/Gguf",
        "q4",
        "gguf",
        "llama_cpp",
        "weights.gguf",
        bytes,
        "on_demand",
    ));
    let runtime = runtime(
        config("models:\n  - model: coder\n    variant: q4\n"),
        catalog,
        Some(manager),
        NetworkPolicy::Allowed,
        launcher.clone(),
    );

    runtime.ensure_ready("coder").await.unwrap();

    assert_eq!(transport.calls(), 1);
    let specs = launcher.specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].engine, EngineKind::LlamaCpp);
    let model_index = specs[0]
        .args
        .iter()
        .position(|arg| arg == "--model")
        .expect("llama.cpp receives local model");
    assert!(specs[0].args[model_index + 1].contains("/snapshots/"));
    assert!(!specs[0].args.iter().any(|arg| arg == "--hf-repo"));
    assert!(!specs[0].args.iter().any(|arg| arg == "--hf-file"));
}

#[tokio::test]
async fn vllm_receives_verified_snapshot_instead_of_repository() {
    let directory = tempdir().unwrap();
    let bytes = b"fixture safetensors bytes";
    let transport = Arc::new(MapTransport::new(BTreeMap::from([(
        "Fixture/Safe".to_string(),
        bytes.to_vec(),
    )])));
    let manager = Arc::new(ArtifactManager::new(directory.path(), transport).unwrap());
    let launcher = RecordingLauncher::default();
    let catalog = catalog(&variant_yaml(
        "assistant",
        "Fixture/Safe",
        "safe",
        "safetensors",
        "vllm",
        "model.safetensors",
        bytes,
        "on_demand",
    ));
    let runtime = runtime(
        config("models:\n  - model: assistant\n    variant: safe\n"),
        catalog,
        Some(manager),
        NetworkPolicy::Allowed,
        launcher.clone(),
    );

    runtime.ensure_ready("assistant").await.unwrap();

    let specs = launcher.specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].engine, EngineKind::Vllm);
    assert_eq!(specs[0].args.first().map(String::as_str), Some("serve"));
    assert!(specs[0].args[1].contains("/snapshots/"));
    assert_ne!(specs[0].args[1], "Fixture/Safe");
}

#[tokio::test]
async fn on_boot_warming_downloads_without_allocating_or_launching_an_engine() {
    let directory = tempdir().unwrap();
    let boot = b"boot artifact";
    let demand = b"demand artifact";
    let transport = Arc::new(MapTransport::new(BTreeMap::from([
        ("Fixture/Boot".to_string(), boot.to_vec()),
        ("Fixture/Demand".to_string(), demand.to_vec()),
    ])));
    let manager = Arc::new(ArtifactManager::new(directory.path(), transport.clone()).unwrap());
    let launcher = RecordingLauncher::default();
    let models = format!(
        "{}{}",
        variant_yaml(
            "boot",
            "Fixture/Boot",
            "q4",
            "gguf",
            "llama_cpp",
            "boot.gguf",
            boot,
            "on_boot"
        ),
        variant_yaml(
            "demand",
            "Fixture/Demand",
            "q4",
            "gguf",
            "llama_cpp",
            "demand.gguf",
            demand,
            "on_demand"
        )
    );
    let runtime = runtime(
        config("models:\n  - model: boot\n  - model: demand\n"),
        catalog(&models),
        Some(manager),
        NetworkPolicy::Allowed,
        launcher.clone(),
    );

    let warmed = runtime.warm_on_boot().await.unwrap();

    assert_eq!(warmed.len(), 1);
    assert_eq!(transport.calls(), 1);
    assert!(launcher.specs().is_empty());
    assert!(runtime.resident_models().await.is_empty());
}

#[tokio::test]
async fn manual_offline_and_digest_failures_call_neither_transport_fallback_nor_launcher() {
    let bytes = b"expected bytes";
    let models = variant_yaml(
        "manual",
        "Fixture/Manual",
        "q4",
        "gguf",
        "llama_cpp",
        "weights.gguf",
        bytes,
        "manual",
    );

    let directory = tempdir().unwrap();
    let transport = Arc::new(MapTransport::new(BTreeMap::new()));
    let manager = Arc::new(ArtifactManager::new(directory.path(), transport.clone()).unwrap());
    let launcher = RecordingLauncher::default();
    let manual_runtime = runtime(
        config("models:\n  - model: manual\n"),
        catalog(&models),
        Some(manager),
        NetworkPolicy::Allowed,
        launcher.clone(),
    );
    let error = manual_runtime.ensure_ready("manual").await.unwrap_err();
    assert!(matches!(error, RuntimeError::Artifact(_)));
    assert!(error.to_string().contains("manual"));
    assert_eq!(transport.calls(), 0);
    assert!(launcher.specs().is_empty());

    let directory = tempdir().unwrap();
    let transport = Arc::new(MapTransport::new(BTreeMap::new()));
    let manager = Arc::new(ArtifactManager::new(directory.path(), transport.clone()).unwrap());
    let launcher = RecordingLauncher::default();
    let offline_runtime = runtime(
        config("models:\n  - model: demand\n"),
        catalog(&variant_yaml(
            "demand",
            "Fixture/Demand",
            "q4",
            "gguf",
            "llama_cpp",
            "weights.gguf",
            bytes,
            "on_demand",
        )),
        Some(manager),
        NetworkPolicy::Denied,
        launcher.clone(),
    );
    let error = offline_runtime.ensure_ready("demand").await.unwrap_err();
    assert!(matches!(error, RuntimeError::Artifact(_)));
    assert!(error.to_string().contains("offline"));
    assert_eq!(transport.calls(), 0);
    assert!(launcher.specs().is_empty());

    let directory = tempdir().unwrap();
    let transport = Arc::new(MapTransport::new(BTreeMap::from([(
        "Fixture/Bad".to_string(),
        b"corrupt-bytes!".to_vec(),
    )])));
    let manager = Arc::new(ArtifactManager::new(directory.path(), transport.clone()).unwrap());
    let launcher = RecordingLauncher::default();
    let bad_runtime = runtime(
        config("models:\n  - model: bad\n"),
        catalog(&variant_yaml(
            "bad",
            "Fixture/Bad",
            "q4",
            "gguf",
            "llama_cpp",
            "weights.gguf",
            bytes,
            "on_demand",
        )),
        Some(manager),
        NetworkPolicy::Allowed,
        launcher.clone(),
    );
    let error = bad_runtime.ensure_ready("bad").await.unwrap_err();
    assert!(matches!(error, RuntimeError::Artifact(_)));
    assert!(error.to_string().contains("digest mismatch"));
    assert_eq!(transport.calls(), 1);
    assert!(launcher.specs().is_empty());
}

#[tokio::test]
async fn v2_runtime_without_artifact_service_fails_before_launcher() {
    let bytes = b"managed bytes";
    let launcher = RecordingLauncher::default();
    let runtime = runtime(
        config("models:\n  - model: managed\n"),
        catalog(&variant_yaml(
            "managed",
            "Fixture/Managed",
            "q4",
            "gguf",
            "llama_cpp",
            "weights.gguf",
            bytes,
            "on_demand",
        )),
        None,
        NetworkPolicy::Allowed,
        launcher.clone(),
    );

    let error = runtime.ensure_ready("managed").await.unwrap_err();

    assert!(matches!(error, RuntimeError::Artifact(_)));
    assert!(error
        .to_string()
        .contains("managed artifact service is not configured"));
    assert!(launcher.specs().is_empty());
}
