use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sbproxy_model_host::{
    validate_engine_args, ArtifactCacheMetadata, ArtifactFile, ArtifactFormat, CommandExecutor,
    EngineAccel, EngineAvailability, EngineCapabilities, EngineCommand, EngineDetection,
    EngineDriver, EngineDriverError, EngineFailureReason, EngineHealth, EngineKind, EngineProcess,
    EngineProcessRunner, EngineProvisioning, EngineReadinessProbe, FitPlan, KvCacheQuant,
    LaunchRequest, LlamaBinarySource, LlamaCppDriver, OperationJob, OperationKind,
    OperationProgress, OperationState, ProvisionRequest, ProvisionedEngine, Quant, ReadyArtifact,
    ResolvedArtifact, RunningEngine, SupportLevel, WorkerProfile,
};

#[derive(Debug)]
struct FixtureProcess {
    stopped: AtomicBool,
}

#[async_trait]
impl EngineProcess for FixtureProcess {
    fn id(&self) -> Option<u32> {
        Some(42)
    }

    async fn has_exited(&self) -> Result<bool, EngineDriverError> {
        Ok(self.stopped.load(Ordering::SeqCst))
    }

    async fn shutdown(&self, _grace: Duration) -> Result<(), EngineDriverError> {
        self.stopped.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn stderr_tail(&self) -> String {
        String::new()
    }
}

struct FixtureDriver {
    kind: EngineKind,
}

#[async_trait]
impl EngineDriver for FixtureDriver {
    fn kind(&self) -> EngineKind {
        self.kind
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            artifact_formats: match self.kind {
                EngineKind::LlamaCpp => vec![ArtifactFormat::Gguf],
                EngineKind::Vllm => vec![ArtifactFormat::Safetensors],
                EngineKind::Embedded => Vec::new(),
            },
            accelerators: vec![sbproxy_model_host::AcceleratorKind::Cpu],
            supports_container: self.kind == EngineKind::Vllm,
            supports_uv: self.kind == EngineKind::Vllm,
        }
    }

    fn detect(
        &self,
        _worker: &WorkerProfile,
        _provisioning: &EngineProvisioning,
    ) -> EngineDetection {
        EngineDetection {
            kind: self.kind,
            availability: EngineAvailability::Available,
            version: Some("fixture-1".to_string()),
            reason: "fixture engine is available".to_string(),
            remediation: None,
        }
    }

    async fn provision(
        &self,
        request: &ProvisionRequest,
    ) -> Result<ProvisionedEngine, EngineDriverError> {
        Ok(ProvisionedEngine {
            kind: self.kind,
            executable: PathBuf::from(self.kind.binary_name()),
            version: Some("fixture-1".to_string()),
            fingerprint: format!("fixture:{:?}", self.kind),
            provisioning: request.provisioning.clone(),
        })
    }

    async fn launch(
        &self,
        provisioned: &ProvisionedEngine,
        request: &LaunchRequest,
    ) -> Result<RunningEngine, EngineDriverError> {
        Ok(RunningEngine {
            deployment: request.deployment.clone(),
            generation: request.generation,
            kind: provisioned.kind,
            port: request.port,
            selected_devices: request.selected_devices.clone(),
            started_at_ms: 1,
            artifact_digest: request.artifact.artifact_digest.clone(),
            process: Arc::new(FixtureProcess {
                stopped: AtomicBool::new(false),
            }),
        })
    }

    async fn health(&self, running: &RunningEngine) -> Result<EngineHealth, EngineDriverError> {
        Ok(if running.process.has_exited().await? {
            EngineHealth::Stopped
        } else {
            EngineHealth::Ready
        })
    }

    async fn shutdown(
        &self,
        running: RunningEngine,
        grace: Duration,
    ) -> Result<(), EngineDriverError> {
        running.process.shutdown(grace).await
    }
}

fn worker() -> WorkerProfile {
    WorkerProfile {
        accelerator: sbproxy_model_host::AcceleratorKind::Cpu,
        compute_capability: None,
        memory_bytes: 8 * 1024 * 1024 * 1024,
        engines: BTreeSet::from([EngineKind::Vllm, EngineKind::LlamaCpp]),
    }
}

fn resolved(kind: EngineKind, format: ArtifactFormat) -> ResolvedArtifact {
    ResolvedArtifact {
        catalog_revision: "fixture-catalog".to_string(),
        logical_model: "fixture-model".to_string(),
        variant_id: "fixture-variant".to_string(),
        artifact_digest: "a".repeat(64),
        format,
        quant: "fixture".to_string(),
        engine: kind,
        source: "hf:Fixture/Model".to_string(),
        revision: "b".repeat(40),
        files: vec![ArtifactFile {
            path: "model.bin".to_string(),
            sha256: "c".repeat(64),
            size_bytes: 16,
        }],
        context_length: 4096,
        license: "apache-2.0".to_string(),
        stability: SupportLevel::Preview,
        pickle_allowed: false,
    }
}

fn ready(kind: EngineKind, format: ArtifactFormat) -> ReadyArtifact {
    let resolved = resolved(kind, format);
    let snapshot = PathBuf::from("/verified/fixture");
    let filename = match format {
        ArtifactFormat::Gguf => "model.gguf",
        ArtifactFormat::Safetensors | ArtifactFormat::Pickle => "model.bin",
    };
    let mut metadata_files = resolved.files;
    metadata_files[0].path = filename.to_string();
    ReadyArtifact {
        artifact_digest: resolved.artifact_digest.clone(),
        snapshot_path: snapshot.clone(),
        files: BTreeMap::from([(filename.to_string(), snapshot.join(filename))]),
        metadata: ArtifactCacheMetadata {
            schema_version: 1,
            artifact_digest: resolved.artifact_digest,
            catalog_revision: resolved.catalog_revision,
            logical_model: resolved.logical_model,
            variant_id: resolved.variant_id,
            format: resolved.format,
            quant: resolved.quant,
            source: resolved.source,
            revision: resolved.revision,
            files: metadata_files,
            total_size_bytes: 16,
            context_length: 4096,
            license: resolved.license,
            stability: resolved.stability,
            pickle_allowed: false,
            trust: "verified".to_string(),
            created_at_ms: 1,
            last_accessed_ms: 1,
        },
        job: OperationJob {
            id: "01J00000000000000000000000".to_string(),
            kind: OperationKind::Pull,
            subject: "artifact:sha256:fixture".to_string(),
            state: OperationState::Ready,
            progress: OperationProgress {
                completed_bytes: 16,
                total_bytes: 16,
                current_file: None,
            },
            created_at_ms: 1,
            updated_at_ms: 1,
            terminal_at_ms: Some(1),
            error: None,
        },
    }
}

fn fit() -> FitPlan {
    FitPlan {
        quant_name: "fixture".to_string(),
        quant: Quant::classify("fixture"),
        estimated_vram_bytes: 1024,
        gpu_index: 0,
        seq_len: 4096,
    }
}

#[tokio::test]
async fn driver_contract_is_complete_and_object_safe() {
    for (kind, format) in [
        (EngineKind::LlamaCpp, ArtifactFormat::Gguf),
        (EngineKind::Vllm, ArtifactFormat::Safetensors),
    ] {
        let driver: Arc<dyn EngineDriver> = Arc::new(FixtureDriver { kind });
        let provisioning = EngineProvisioning::default();
        assert_eq!(
            driver.detect(&worker(), &provisioning).availability,
            EngineAvailability::Available
        );
        let provisioned = driver
            .provision(&ProvisionRequest {
                artifact: resolved(kind, format),
                worker: worker(),
                provisioning,
                engine_cache_dir: PathBuf::from("/engines"),
                job_store: None,
            })
            .await
            .expect("fixture provision");
        let running = driver
            .launch(
                &provisioned,
                &LaunchRequest {
                    deployment: "coder".to_string(),
                    generation: 7,
                    artifact: ready(kind, format),
                    fit: fit(),
                    port: 18080,
                    selected_devices: vec![0],
                    kv_quant: KvCacheQuant::Auto,
                    extra_args: Vec::new(),
                    ready_timeout: Duration::from_secs(1),
                },
            )
            .await
            .expect("fixture launch");
        assert_eq!(driver.health(&running).await.unwrap(), EngineHealth::Ready);
        assert_eq!(running.generation, 7);
        driver
            .shutdown(running, Duration::from_secs(1))
            .await
            .expect("fixture shutdown");
    }
}

#[test]
fn driver_errors_always_carry_stable_reason_and_remediation() {
    let error = EngineDriverError::blocked(
        "container runtime is disabled",
        "enable a supported runtime or choose binary launch",
    );

    assert_eq!(error.reason().as_str(), "engine_blocked");
    assert!(!error.remediation().is_empty());
    assert!(error.to_string().contains("container runtime is disabled"));
    assert!(!format!("{error:?}").contains("secret-token"));
}

#[test]
fn unsafe_arguments_cannot_override_runtime_owned_launch_fields() {
    for (kind, arguments) in [
        (EngineKind::Vllm, vec!["--host", "0.0.0.0"]),
        (EngineKind::Vllm, vec!["--port=9000"]),
        (EngineKind::Vllm, vec!["--api-key", "secret"]),
        (EngineKind::Vllm, vec!["--model", "/tmp/other"]),
        (EngineKind::Vllm, vec!["--tensor-parallel-size", "8"]),
        (EngineKind::Vllm, vec!["--device", "7"]),
        (EngineKind::LlamaCpp, vec!["--hf-repo", "Other/Model"]),
        (EngineKind::LlamaCpp, vec!["--model=/tmp/other.gguf"]),
        (EngineKind::LlamaCpp, vec!["--port", "9000"]),
        (EngineKind::LlamaCpp, vec!["--host", "0.0.0.0"]),
        (EngineKind::LlamaCpp, vec!["--api-key", "secret"]),
        (EngineKind::LlamaCpp, vec!["--device", "CUDA7"]),
        (EngineKind::LlamaCpp, vec!["--mount", "/:/host"]),
    ] {
        let arguments = arguments
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let error = validate_engine_args(kind, &arguments).expect_err("runtime-owned flag");
        assert_eq!(error.reason(), EngineFailureReason::UnsafeArgument);
        assert!(!error.remediation().is_empty());
    }

    assert_eq!(
        validate_engine_args(
            EngineKind::Vllm,
            &[
                "--enable-prefix-caching".to_string(),
                "--seed=7".to_string()
            ]
        )
        .expect("allowlisted vllm arguments"),
        vec!["--enable-prefix-caching", "--seed=7"]
    );
    assert_eq!(
        validate_engine_args(
            EngineKind::LlamaCpp,
            &["--flash-attn".to_string(), "--threads=8".to_string()]
        )
        .expect("allowlisted llama.cpp arguments"),
        vec!["--flash-attn", "--threads=8"]
    );
}

#[test]
fn launch_request_accepts_only_verified_paths_inside_the_snapshot() {
    let mut request = LaunchRequest {
        deployment: "coder".to_string(),
        generation: 1,
        artifact: ready(EngineKind::LlamaCpp, ArtifactFormat::Gguf),
        fit: fit(),
        port: 18080,
        selected_devices: vec![0],
        kv_quant: KvCacheQuant::Auto,
        extra_args: vec!["--flash-attn".to_string()],
        ready_timeout: Duration::from_secs(1),
    };
    request
        .validate(EngineKind::LlamaCpp)
        .expect("verified snapshot request");

    let relative = request.artifact.metadata.files[0].path.clone();
    request
        .artifact
        .files
        .insert(relative, PathBuf::from("/unverified/model.gguf"));
    let error = request
        .validate(EngineKind::LlamaCpp)
        .expect_err("path escaped snapshot");
    assert_eq!(error.reason(), EngineFailureReason::ArtifactNotReady);

    let mut request = LaunchRequest {
        deployment: "coder".to_string(),
        generation: 1,
        artifact: ready(EngineKind::LlamaCpp, ArtifactFormat::Gguf),
        fit: fit(),
        port: 18080,
        selected_devices: vec![0],
        kv_quant: KvCacheQuant::Auto,
        extra_args: Vec::new(),
        ready_timeout: Duration::from_secs(1),
    };
    request.artifact.metadata.trust = "legacy-unverified".to_string();
    let error = request
        .validate(EngineKind::LlamaCpp)
        .expect_err("unverified metadata");
    assert_eq!(error.reason(), EngineFailureReason::ArtifactNotReady);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedCommand {
    executable: PathBuf,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    stderr_tail_lines: usize,
}

#[derive(Clone)]
struct RecordingExecutor {
    commands: Arc<Mutex<Vec<CapturedCommand>>>,
    process: Arc<FixtureProcess>,
}

#[async_trait]
impl CommandExecutor for RecordingExecutor {
    async fn spawn(
        &self,
        executable: &std::path::Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        self.commands.lock().unwrap().push(CapturedCommand {
            executable: executable.to_path_buf(),
            arguments: arguments.to_vec(),
            environment: environment.clone(),
            stderr_tail_lines,
        });
        Ok(self.process.clone())
    }
}

struct FixtureProbe {
    ready: bool,
}

#[async_trait]
impl EngineReadinessProbe for FixtureProbe {
    async fn ready(&self, _port: u16, _path: &str) -> Result<bool, EngineDriverError> {
        Ok(self.ready)
    }
}

#[tokio::test]
async fn process_runner_passes_tokenized_arguments_without_a_shell() {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let process = Arc::new(FixtureProcess {
        stopped: AtomicBool::new(false),
    });
    let runner = EngineProcessRunner::new(
        Arc::new(RecordingExecutor {
            commands: commands.clone(),
            process,
        }),
        Arc::new(FixtureProbe { ready: true }),
    )
    .with_poll_interval(Duration::from_millis(1));
    let command = EngineCommand {
        executable: PathBuf::from("/engines/vllm"),
        arguments: vec![
            "serve".to_string(),
            "/verified/model with spaces".to_string(),
            "--port".to_string(),
            "18080".to_string(),
        ],
        environment: BTreeMap::from([("CUDA_VISIBLE_DEVICES".to_string(), "0".to_string())]),
        port: 18080,
        health_path: "/health".to_string(),
        ready_timeout: Duration::from_secs(1),
        stderr_tail_lines: 15,
    };

    let running = runner.launch(&command).await.expect("fixture readiness");
    assert_eq!(running.id(), Some(42));
    let captured = commands.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].executable, PathBuf::from("/engines/vllm"));
    assert_eq!(captured[0].arguments, command.arguments);
    assert_eq!(captured[0].arguments[1], "/verified/model with spaces");
}

#[tokio::test]
async fn process_runner_reports_early_exit_with_a_stable_reason() {
    let process = Arc::new(FixtureProcess {
        stopped: AtomicBool::new(true),
    });
    let runner = EngineProcessRunner::new(
        Arc::new(RecordingExecutor {
            commands: Arc::new(Mutex::new(Vec::new())),
            process,
        }),
        Arc::new(FixtureProbe { ready: false }),
    )
    .with_poll_interval(Duration::from_millis(1));
    let command = EngineCommand {
        executable: PathBuf::from("/engines/vllm"),
        arguments: vec!["serve".to_string()],
        environment: BTreeMap::new(),
        port: 18080,
        health_path: "/health".to_string(),
        ready_timeout: Duration::from_secs(1),
        stderr_tail_lines: 15,
    };

    let error = runner.launch(&command).await.expect_err("early exit");
    assert_eq!(error.reason(), EngineFailureReason::EngineEarlyExit);
    assert!(!error.remediation().is_empty());
}

type LlamaFetchRecord = (String, EngineAccel, Option<String>);

#[derive(Clone)]
struct FixtureLlamaSource {
    on_path: Option<PathBuf>,
    executable: bool,
    fetched: Result<PathBuf, String>,
    fetches: Arc<Mutex<Vec<LlamaFetchRecord>>>,
}

#[async_trait]
impl LlamaBinarySource for FixtureLlamaSource {
    fn resolve_on_path(&self) -> Option<PathBuf> {
        self.on_path.clone()
    }

    fn is_executable(&self, _path: &std::path::Path) -> bool {
        self.executable
    }

    async fn fetch_release(
        &self,
        _cache_dir: &std::path::Path,
        version: &str,
        acceleration: EngineAccel,
        sha256: Option<&str>,
    ) -> Result<PathBuf, String> {
        self.fetches.lock().unwrap().push((
            version.to_string(),
            acceleration,
            sha256.map(str::to_string),
        ));
        self.fetched.clone()
    }
}

fn llama_source(on_path: Option<&str>, executable: bool) -> Arc<FixtureLlamaSource> {
    Arc::new(FixtureLlamaSource {
        on_path: on_path.map(PathBuf::from),
        executable,
        fetched: Ok(PathBuf::from("/engines/llama-server")),
        fetches: Arc::new(Mutex::new(Vec::new())),
    })
}

fn llama_worker() -> WorkerProfile {
    WorkerProfile {
        accelerator: sbproxy_model_host::AcceleratorKind::Cpu,
        compute_capability: None,
        memory_bytes: 8 * 1024 * 1024 * 1024,
        engines: BTreeSet::from([EngineKind::LlamaCpp]),
    }
}

fn fixture_runner(commands: Arc<Mutex<Vec<CapturedCommand>>>) -> EngineProcessRunner {
    EngineProcessRunner::new(
        Arc::new(RecordingExecutor {
            commands,
            process: Arc::new(FixtureProcess {
                stopped: AtomicBool::new(false),
            }),
        }),
        Arc::new(FixtureProbe { ready: true }),
    )
}

#[test]
fn llama_detection_distinguishes_available_acquirable_incompatible_and_blocked() {
    let runner = fixture_runner(Arc::new(Mutex::new(Vec::new())));
    let available = LlamaCppDriver::new(
        runner.clone(),
        llama_source(Some("/usr/bin/llama-server"), true),
    );
    assert_eq!(
        available
            .detect(&llama_worker(), &EngineProvisioning::default())
            .availability,
        EngineAvailability::Available
    );

    let acquirable = LlamaCppDriver::new(runner.clone(), llama_source(None, true));
    let detection = acquirable.detect(&llama_worker(), &EngineProvisioning::default());
    assert_eq!(detection.availability, EngineAvailability::Acquirable);
    assert!(detection.reason.contains("sha256"));
    assert!(detection.remediation.is_some());

    let mut incompatible_worker = llama_worker();
    incompatible_worker.engines.clear();
    assert_eq!(
        acquirable
            .detect(&incompatible_worker, &EngineProvisioning::default())
            .availability,
        EngineAvailability::Incompatible
    );

    let explicit: EngineProvisioning = serde_yaml::from_str(
        r#"
acquire:
  source: path
  path: /opt/llama/llama-server
"#,
    )
    .unwrap();
    let blocked = LlamaCppDriver::new(runner.clone(), llama_source(None, false));
    assert_eq!(
        blocked.detect(&llama_worker(), &explicit).availability,
        EngineAvailability::Blocked
    );

    let cuda: EngineProvisioning = serde_yaml::from_str(
        r#"
acquire:
  source: release
  accel: cuda
  sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#,
    )
    .unwrap();
    assert_eq!(
        acquirable.detect(&llama_worker(), &cuda).availability,
        EngineAvailability::Incompatible
    );
}

#[tokio::test]
async fn llama_provision_prefers_compatible_path_and_release_failures_do_not_fallback() {
    let runner = fixture_runner(Arc::new(Mutex::new(Vec::new())));
    let path_source = llama_source(Some("/usr/bin/llama-server"), true);
    let driver = LlamaCppDriver::new(runner.clone(), path_source.clone());
    let provisioned = driver
        .provision(&ProvisionRequest {
            artifact: resolved(EngineKind::LlamaCpp, ArtifactFormat::Gguf),
            worker: llama_worker(),
            provisioning: EngineProvisioning::default(),
            engine_cache_dir: PathBuf::from("/engines"),
            job_store: None,
        })
        .await
        .expect("PATH engine");
    assert_eq!(
        provisioned.executable,
        PathBuf::from("/usr/bin/llama-server")
    );
    assert!(path_source.fetches.lock().unwrap().is_empty());

    let failing_source = Arc::new(FixtureLlamaSource {
        on_path: None,
        executable: true,
        fetched: Err("fixture release failure".to_string()),
        fetches: Arc::new(Mutex::new(Vec::new())),
    });
    let driver = LlamaCppDriver::new(runner, failing_source);
    let error = driver
        .provision(&ProvisionRequest {
            artifact: resolved(EngineKind::LlamaCpp, ArtifactFormat::Gguf),
            worker: llama_worker(),
            provisioning: EngineProvisioning::default(),
            engine_cache_dir: PathBuf::from("/engines"),
            job_store: None,
        })
        .await
        .expect_err("release failure must surface");
    assert_eq!(error.reason(), EngineFailureReason::EngineProvisionFailed);
}

#[tokio::test]
async fn llama_launch_uses_one_verified_gguf_and_runtime_owned_network_and_devices() {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let driver = LlamaCppDriver::new(
        fixture_runner(commands.clone()),
        llama_source(Some("/usr/bin/llama-server"), true),
    );
    let provisioned = ProvisionedEngine {
        kind: EngineKind::LlamaCpp,
        executable: PathBuf::from("/usr/bin/llama-server"),
        version: Some("fixture".to_string()),
        fingerprint: "fixture".to_string(),
        provisioning: EngineProvisioning::default(),
    };
    let request = LaunchRequest {
        deployment: "coder".to_string(),
        generation: 3,
        artifact: ready(EngineKind::LlamaCpp, ArtifactFormat::Gguf),
        fit: fit(),
        port: 18080,
        selected_devices: vec![2],
        kv_quant: KvCacheQuant::Int4,
        extra_args: vec!["--flash-attn".to_string()],
        ready_timeout: Duration::from_secs(1),
    };

    let running = driver
        .launch(&provisioned, &request)
        .await
        .expect("llama launch");
    assert_eq!(running.port, 18080);
    assert_eq!(driver.health(&running).await.unwrap(), EngineHealth::Ready);

    let captured = commands.lock().unwrap();
    let arguments = &captured[0].arguments;
    let model_indices = arguments
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (value == "--model").then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(model_indices.len(), 1);
    assert_eq!(
        arguments[model_indices[0] + 1],
        "/verified/fixture/model.gguf"
    );
    assert!(!arguments.iter().any(|value| value == "--hf-repo"));
    assert!(!arguments.iter().any(|value| value == "--hf-file"));
    assert_eq!(flag_value(arguments, "--host"), "127.0.0.1");
    assert_eq!(flag_value(arguments, "--port"), "18080");
    assert_eq!(flag_value(arguments, "--ctx-size"), "4096");
    assert_eq!(flag_value(arguments, "--n-gpu-layers"), "999");
    assert_eq!(flag_value(arguments, "--cache-type-k"), "q4_0");
    assert_eq!(flag_value(arguments, "--cache-type-v"), "q4_0");
    assert_eq!(captured[0].environment["CUDA_VISIBLE_DEVICES"], "2");
}

fn flag_value<'a>(arguments: &'a [String], flag: &str) -> &'a str {
    let index = arguments
        .iter()
        .position(|argument| argument == flag)
        .unwrap_or_else(|| panic!("missing {flag}"));
    arguments[index + 1].as_str()
}
