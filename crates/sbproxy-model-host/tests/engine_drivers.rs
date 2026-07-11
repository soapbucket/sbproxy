use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sbproxy_model_host::{
    build_vllm_container_plan, validate_engine_args, ArtifactCacheMetadata, ArtifactFile,
    ArtifactFormat, BackoffPolicy, CommandExecutor, CommandOutput, ContainerRuntime,
    CudaBuildPrerequisites, EngineAccel, EngineAvailability, EngineCapabilities, EngineCommand,
    EngineDetection, EngineDriver, EngineDriverError, EngineFailureReason, EngineHealth,
    EngineKind, EngineProcess, EngineProcessRunner, EngineProvisioning, EngineReadinessProbe,
    EngineSupervisor, FileJobStore, FitPlan, KvCacheQuant, LaunchRequest, LlamaBinarySource,
    LlamaCppDriver, OperationJob, OperationKind, OperationProgress, OperationState,
    ProvisionRequest, ProvisionedEngine, Quant, ReadyArtifact, ResolvedArtifact, RunningEngine,
    SupervisorClock, SupportLevel, VllmDriver, VllmHost, VllmLaunchMode, WorkerProfile,
};
use tempfile::tempdir;

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
            accelerator: request.accelerator,
            selected_devices: request.selected_devices.clone(),
            started_at_ms: 1,
            artifact_digest: request.artifact.artifact_digest.clone(),
            memory: request.fit.memory.clone(),
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
        memory: sbproxy_model_host::MemoryEstimate::from_total(0, 1024),
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
                    accelerator: sbproxy_model_host::AcceleratorKind::Cpu,
                    selected_devices: Vec::new(),
                    kv_quant: KvCacheQuant::Auto,
                    extra_args: Vec::new(),
                    max_concurrency: 1,
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

struct CrashDriver {
    launches: Arc<AtomicU32>,
    allow_success: Arc<AtomicBool>,
}

#[async_trait]
impl EngineDriver for CrashDriver {
    fn kind(&self) -> EngineKind {
        EngineKind::LlamaCpp
    }

    fn capabilities(&self) -> EngineCapabilities {
        FixtureDriver {
            kind: EngineKind::LlamaCpp,
        }
        .capabilities()
    }

    fn detect(&self, worker: &WorkerProfile, provisioning: &EngineProvisioning) -> EngineDetection {
        FixtureDriver {
            kind: EngineKind::LlamaCpp,
        }
        .detect(worker, provisioning)
    }

    async fn provision(
        &self,
        request: &ProvisionRequest,
    ) -> Result<ProvisionedEngine, EngineDriverError> {
        FixtureDriver {
            kind: EngineKind::LlamaCpp,
        }
        .provision(request)
        .await
    }

    async fn launch(
        &self,
        provisioned: &ProvisionedEngine,
        request: &LaunchRequest,
    ) -> Result<RunningEngine, EngineDriverError> {
        let attempt = self.launches.fetch_add(1, Ordering::SeqCst) + 1;
        if self.allow_success.load(Ordering::SeqCst) {
            return FixtureDriver {
                kind: EngineKind::LlamaCpp,
            }
            .launch(provisioned, request)
            .await;
        }
        Err(EngineDriverError::new(
            EngineFailureReason::EngineEarlyExit,
            format!("fixture launch attempt {attempt} exited"),
            "repair the fixture engine and reset the crash loop",
            true,
        )
        .with_diagnostic_tail(format!(
            "stderr attempt {attempt}: Authorization: Bearer secret-token\n{}",
            "x".repeat(10_000)
        )))
    }

    async fn health(&self, running: &RunningEngine) -> Result<EngineHealth, EngineDriverError> {
        FixtureDriver {
            kind: EngineKind::LlamaCpp,
        }
        .health(running)
        .await
    }

    async fn shutdown(
        &self,
        running: RunningEngine,
        grace: Duration,
    ) -> Result<(), EngineDriverError> {
        FixtureDriver {
            kind: EngineKind::LlamaCpp,
        }
        .shutdown(running, grace)
        .await
    }
}

struct PausedClock {
    now_ms: AtomicU64,
}

#[async_trait]
impl SupervisorClock for PausedClock {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
        self.now_ms.fetch_add(
            u64::try_from(duration.as_millis()).unwrap(),
            Ordering::SeqCst,
        );
    }

    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

#[tokio::test(start_paused = true)]
async fn crash_loop_observes_backoff_retains_failure_and_requires_durable_reset() {
    let directory = tempdir().unwrap();
    let store = FileJobStore::open(directory.path(), 50).unwrap();
    let launches = Arc::new(AtomicU32::new(0));
    let allow_success = Arc::new(AtomicBool::new(false));
    let driver: Arc<dyn EngineDriver> = Arc::new(CrashDriver {
        launches: launches.clone(),
        allow_success: allow_success.clone(),
    });
    let clock = Arc::new(PausedClock {
        now_ms: AtomicU64::new(1_000),
    });
    let mut supervisor = EngineSupervisor::new(
        "coder",
        driver,
        BackoffPolicy {
            base: Duration::from_millis(10),
            max: Duration::from_millis(25),
            max_attempts: Some(4),
        },
        Some(store.clone()),
    )
    .with_clock(clock);
    let provisioned = supervisor
        .provision(&ProvisionRequest {
            artifact: resolved(EngineKind::LlamaCpp, ArtifactFormat::Gguf),
            worker: worker(),
            provisioning: EngineProvisioning::default(),
            engine_cache_dir: PathBuf::from("/engines"),
            job_store: None,
        })
        .await
        .unwrap();
    let request = LaunchRequest {
        deployment: "coder".to_string(),
        generation: 1,
        artifact: ready(EngineKind::LlamaCpp, ArtifactFormat::Gguf),
        fit: fit(),
        port: 18080,
        accelerator: sbproxy_model_host::AcceleratorKind::Cpu,
        selected_devices: Vec::new(),
        kv_quant: KvCacheQuant::Auto,
        extra_args: Vec::new(),
        max_concurrency: 1,
        ready_timeout: Duration::from_secs(1),
    };
    let task_request = request.clone();
    let task_provisioned = provisioned.clone();
    let task = tokio::spawn(async move {
        let result = supervisor
            .ensure_ready(&task_provisioned, &task_request)
            .await;
        (supervisor, result)
    });

    tokio::task::yield_now().await;
    assert_eq!(launches.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(9)).await;
    assert_eq!(launches.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(launches.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_millis(19)).await;
    assert_eq!(launches.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(launches.load(Ordering::SeqCst), 3);
    tokio::time::advance(Duration::from_millis(24)).await;
    assert_eq!(launches.load(Ordering::SeqCst), 3);
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;

    let (mut supervisor, result) = task.await.unwrap();
    assert_eq!(
        result.unwrap_err().reason(),
        EngineFailureReason::EngineEarlyExit
    );
    assert_eq!(launches.load(Ordering::SeqCst), 4);
    let crash = supervisor.crash_loop().expect("retained crash loop");
    assert_eq!(crash.attempts, 4);
    assert_eq!(crash.reason, EngineFailureReason::EngineEarlyExit);
    assert!(crash.last_error.contains("attempt 4"));
    assert_eq!(crash.first_failure_at_ms, 1_000);
    assert_eq!(crash.last_failure_at_ms, 1_055);
    assert!(crash.stderr_tail.as_deref().unwrap().len() <= 8_192);
    assert!(!crash
        .stderr_tail
        .as_deref()
        .unwrap()
        .contains("secret-token"));
    assert!(!crash.next_remediation.is_empty());

    let blocked = supervisor
        .ensure_ready(&provisioned, &request)
        .await
        .expect_err("crash loop requires reset");
    assert_eq!(blocked.reason(), EngineFailureReason::CrashLoop);
    assert_eq!(launches.load(Ordering::SeqCst), 4);

    let reset = supervisor
        .reset()
        .expect("durable reset")
        .expect("reset job");
    assert_eq!(reset.kind, OperationKind::Reset);
    assert_eq!(reset.state, OperationState::Ready);
    allow_success.store(true, Ordering::SeqCst);
    let running = supervisor
        .ensure_ready(&provisioned, &request)
        .await
        .expect("launch after explicit reset");
    let drain = supervisor.begin_drain_job().expect("begin durable drain");
    let drain = supervisor
        .finish_drain_job(drain.as_ref(), None)
        .expect("finish durable drain")
        .expect("drain job");
    assert_eq!(drain.kind, OperationKind::Drain);
    assert_eq!(drain.state, OperationState::Ready);
    supervisor
        .shutdown(Duration::from_secs(1))
        .await
        .expect("durable stop");
    assert!(running.process.has_exited().await.unwrap());

    let jobs = FileJobStore::open(directory.path(), 50)
        .unwrap()
        .list()
        .unwrap();
    for kind in [
        OperationKind::Provision,
        OperationKind::Launch,
        OperationKind::Load,
        OperationKind::Drain,
        OperationKind::Stop,
        OperationKind::Reset,
    ] {
        assert!(jobs.iter().any(|job| job.kind == kind), "{kind:?}");
    }
    assert!(jobs
        .iter()
        .filter(|job| matches!(job.kind, OperationKind::Launch | OperationKind::Load))
        .any(|job| job.state == OperationState::Failed));
    let stored = jobs
        .iter()
        .map(|job| serde_json::to_string(job).unwrap())
        .collect::<String>();
    assert!(!stored.contains("secret-token"));
    assert!(!stored.contains("stderr attempt"));
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
        accelerator: sbproxy_model_host::AcceleratorKind::Cpu,
        selected_devices: Vec::new(),
        kv_quant: KvCacheQuant::Auto,
        extra_args: vec!["--flash-attn".to_string()],
        max_concurrency: 1,
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
        accelerator: sbproxy_model_host::AcceleratorKind::Cpu,
        selected_devices: Vec::new(),
        kv_quant: KvCacheQuant::Auto,
        extra_args: Vec::new(),
        max_concurrency: 1,
        ready_timeout: Duration::from_secs(1),
    };
    request.artifact.metadata.trust = "legacy-unverified".to_string();
    let error = request
        .validate(EngineKind::LlamaCpp)
        .expect_err("unverified metadata");
    assert_eq!(error.reason(), EngineFailureReason::ArtifactNotReady);
}

#[test]
fn launch_request_requires_devices_that_match_the_accelerator() {
    let mut request = LaunchRequest {
        deployment: "coder".to_string(),
        generation: 1,
        artifact: ready(EngineKind::LlamaCpp, ArtifactFormat::Gguf),
        fit: fit(),
        port: 18080,
        accelerator: sbproxy_model_host::AcceleratorKind::Cuda,
        selected_devices: Vec::new(),
        kv_quant: KvCacheQuant::Auto,
        extra_args: Vec::new(),
        max_concurrency: 1,
        ready_timeout: Duration::from_secs(1),
    };
    assert_eq!(
        request.validate(EngineKind::LlamaCpp).unwrap_err().reason(),
        EngineFailureReason::EngineInternal
    );

    request.accelerator = sbproxy_model_host::AcceleratorKind::Metal;
    assert_eq!(
        request.validate(EngineKind::LlamaCpp).unwrap_err().reason(),
        EngineFailureReason::EngineInternal
    );

    request.selected_devices = vec![0];
    request
        .validate(EngineKind::LlamaCpp)
        .expect("one Metal device");
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

type CudaBuildRecord = (PathBuf, String, String);

#[derive(Clone)]
struct FixtureCudaLlamaSource {
    prerequisites: CudaBuildPrerequisites,
    built: Result<PathBuf, String>,
    builds: Arc<Mutex<Vec<CudaBuildRecord>>>,
}

#[async_trait]
impl LlamaBinarySource for FixtureCudaLlamaSource {
    fn resolve_on_path(&self) -> Option<PathBuf> {
        None
    }

    fn is_executable(&self, _path: &std::path::Path) -> bool {
        true
    }

    async fn fetch_release(
        &self,
        _cache_dir: &std::path::Path,
        _version: &str,
        _acceleration: EngineAccel,
        _sha256: Option<&str>,
    ) -> Result<PathBuf, String> {
        Err("release acquisition must not handle CUDA".to_string())
    }

    fn cuda_prerequisites(&self) -> CudaBuildPrerequisites {
        self.prerequisites.clone()
    }

    async fn build_cuda(
        &self,
        cache_dir: &std::path::Path,
        tag: &str,
        source_sha256: &str,
    ) -> Result<PathBuf, String> {
        self.builds.lock().unwrap().push((
            cache_dir.to_path_buf(),
            tag.to_string(),
            source_sha256.to_string(),
        ));
        self.built.clone()
    }
}

fn cuda_prerequisites() -> CudaBuildPrerequisites {
    CudaBuildPrerequisites {
        linux_x86_64: true,
        nvidia_gpu: true,
        nvcc: Some(PathBuf::from("/usr/local/cuda/bin/nvcc")),
        cmake: Some(PathBuf::from("/usr/bin/cmake")),
        compiler: Some(PathBuf::from("/usr/bin/cc")),
        tar: Some(PathBuf::from("/usr/bin/tar")),
    }
}

fn llama_cuda_worker() -> WorkerProfile {
    WorkerProfile {
        accelerator: sbproxy_model_host::AcceleratorKind::Cuda,
        compute_capability: Some(sbproxy_model_host::ComputeCapability { major: 8, minor: 9 }),
        memory_bytes: 24 * 1024 * 1024 * 1024,
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
    assert!(detection.reason.contains("digest-pinned"));
    assert!(detection.remediation.is_none());

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
async fn llama_cuda_source_build_is_detected_and_provisioned_with_the_exact_pin() {
    let provisioning: EngineProvisioning = serde_yaml::from_str(
        r#"
acquire:
  source: source_build
  version: b9905
  accel: cuda
  sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"#,
    )
    .unwrap();
    let builds = Arc::new(Mutex::new(Vec::new()));
    let source = Arc::new(FixtureCudaLlamaSource {
        prerequisites: cuda_prerequisites(),
        built: Ok(PathBuf::from("/engines/cuda/llama-server")),
        builds: builds.clone(),
    });
    let driver = LlamaCppDriver::new(fixture_runner(Arc::new(Mutex::new(Vec::new()))), source);

    let detection = driver.detect(&llama_cuda_worker(), &provisioning);
    assert_eq!(detection.availability, EngineAvailability::Acquirable);
    assert!(detection.reason.contains("digest-pinned CUDA"));
    let provisioned = driver
        .provision(&ProvisionRequest {
            artifact: resolved(EngineKind::LlamaCpp, ArtifactFormat::Gguf),
            worker: llama_cuda_worker(),
            provisioning: provisioning.clone(),
            engine_cache_dir: PathBuf::from("/engines"),
            job_store: None,
        })
        .await
        .expect("CUDA source build");
    assert_eq!(
        provisioned.executable,
        PathBuf::from("/engines/cuda/llama-server")
    );
    assert_eq!(provisioned.version.as_deref(), Some("b9905"));
    assert_eq!(
        provisioned.fingerprint,
        "source-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        builds.lock().unwrap().as_slice(),
        &[(
            PathBuf::from("/engines"),
            "b9905".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )]
    );

    let mut missing_nvcc = cuda_prerequisites();
    missing_nvcc.nvcc = None;
    let blocked = LlamaCppDriver::new(
        fixture_runner(Arc::new(Mutex::new(Vec::new()))),
        Arc::new(FixtureCudaLlamaSource {
            prerequisites: missing_nvcc,
            built: Ok(PathBuf::from("/engines/cuda/llama-server")),
            builds: Arc::new(Mutex::new(Vec::new())),
        }),
    )
    .detect(&llama_cuda_worker(), &provisioning);
    assert_eq!(blocked.availability, EngineAvailability::Blocked);
    assert!(blocked.reason.contains("nvcc"));
    assert!(blocked.remediation.is_some());
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
        accelerator: sbproxy_model_host::AcceleratorKind::Cuda,
        selected_devices: vec![2],
        kv_quant: KvCacheQuant::Int4,
        extra_args: vec!["--flash-attn".to_string()],
        max_concurrency: 1,
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

#[tokio::test]
async fn llama_metal_launch_offloads_without_exporting_a_cuda_device() {
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
    driver
        .launch(
            &provisioned,
            &LaunchRequest {
                deployment: "mac-coder".to_string(),
                generation: 1,
                artifact: ready(EngineKind::LlamaCpp, ArtifactFormat::Gguf),
                fit: fit(),
                port: 18081,
                accelerator: sbproxy_model_host::AcceleratorKind::Metal,
                selected_devices: vec![0],
                kv_quant: KvCacheQuant::Auto,
                extra_args: Vec::new(),
                max_concurrency: 1,
                ready_timeout: Duration::from_secs(1),
            },
        )
        .await
        .unwrap();

    let captured = commands.lock().unwrap();
    assert_eq!(flag_value(&captured[0].arguments, "--n-gpu-layers"), "999");
    assert!(!captured[0].environment.contains_key("CUDA_VISIBLE_DEVICES"));
}

fn flag_value<'a>(arguments: &'a [String], flag: &str) -> &'a str {
    let index = arguments
        .iter()
        .position(|argument| argument == flag)
        .unwrap_or_else(|| panic!("missing {flag}"));
    arguments[index + 1].as_str()
}

#[derive(Clone)]
struct FixtureVllmHost {
    paths: Arc<BTreeMap<String, PathBuf>>,
    executable: bool,
    uv_result: Result<PathBuf, String>,
    shared_memory_bytes: u64,
}

#[async_trait]
impl VllmHost for FixtureVllmHost {
    fn resolve_on_path(&self, name: &str) -> Option<PathBuf> {
        self.paths.get(name).cloned()
    }

    fn is_executable(&self, _path: &std::path::Path) -> bool {
        self.executable
    }

    async fn ensure_uv(
        &self,
        _cache_dir: &std::path::Path,
        _version: &str,
    ) -> Result<PathBuf, String> {
        self.uv_result.clone()
    }

    fn available_shared_memory_bytes(&self) -> u64 {
        self.shared_memory_bytes
    }
}

#[derive(Clone)]
struct ProbeCommandExecutor {
    process: Arc<FixtureProcess>,
    outputs: Arc<Mutex<Vec<CommandOutput>>>,
    commands: Arc<Mutex<Vec<CapturedCommand>>>,
}

#[async_trait]
impl CommandExecutor for ProbeCommandExecutor {
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

    async fn output(
        &self,
        _executable: &std::path::Path,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _timeout: Duration,
        _max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        if self.outputs.lock().unwrap().is_empty() {
            return Err(EngineDriverError::blocked(
                "fixture output is unavailable",
                "provide a fixture command result",
            ));
        }
        Ok(self.outputs.lock().unwrap().remove(0))
    }
}

fn vllm_host(paths: &[(&str, &str)]) -> Arc<FixtureVllmHost> {
    Arc::new(FixtureVllmHost {
        paths: Arc::new(
            paths
                .iter()
                .map(|(name, path)| ((*name).to_string(), PathBuf::from(path)))
                .collect(),
        ),
        executable: true,
        uv_result: Ok(PathBuf::from("/engines/uv")),
        shared_memory_bytes: 16 * 1024 * 1024 * 1024,
    })
}

fn vllm_runner(outputs: Vec<CommandOutput>) -> EngineProcessRunner {
    vllm_runner_with_commands(outputs).0
}

fn vllm_runner_with_commands(
    outputs: Vec<CommandOutput>,
) -> (EngineProcessRunner, Arc<Mutex<Vec<CapturedCommand>>>) {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let runner = EngineProcessRunner::new(
        Arc::new(ProbeCommandExecutor {
            process: Arc::new(FixtureProcess {
                stopped: AtomicBool::new(false),
            }),
            outputs: Arc::new(Mutex::new(outputs)),
            commands: commands.clone(),
        }),
        Arc::new(FixtureProbe { ready: true }),
    );
    (runner, commands)
}

fn cuda_worker() -> WorkerProfile {
    WorkerProfile {
        accelerator: sbproxy_model_host::AcceleratorKind::Cuda,
        compute_capability: Some(sbproxy_model_host::ComputeCapability { major: 8, minor: 9 }),
        memory_bytes: 24 * 1024 * 1024 * 1024,
        engines: BTreeSet::from([EngineKind::Vllm]),
    }
}

fn compatibility_output(compatible: bool) -> CommandOutput {
    CommandOutput {
        success: true,
        stdout: format!(
            r#"{{"python":"3.12.4","torch":"2.7.1","cuda":"12.8","vllm":"0.10.0","compatible":{compatible},"reason":{}}}"#,
            if compatible {
                "null"
            } else {
                "\"torch CUDA build cannot use the selected driver\""
            }
        ),
        stderr: String::new(),
    }
}

#[test]
fn vllm_detection_covers_binary_uv_container_and_worker_blockers() {
    let binary = VllmDriver::new(
        vllm_runner(Vec::new()),
        vllm_host(&[("vllm", "/usr/bin/vllm"), ("python3", "/usr/bin/python3")]),
    );
    assert_eq!(
        binary
            .detect(&cuda_worker(), &EngineProvisioning::default())
            .availability,
        EngineAvailability::Available
    );
    let missing_python = VllmDriver::new(
        vllm_runner(Vec::new()),
        vllm_host(&[("vllm", "/usr/bin/vllm")]),
    );
    let detection = missing_python.detect(&cuda_worker(), &EngineProvisioning::default());
    assert_eq!(detection.availability, EngineAvailability::Incompatible);
    assert!(detection.reason.contains("python3"));

    let uv: EngineProvisioning = serde_yaml::from_str(
        r#"
launch: venv
acquire:
  source: uvx
  version: 0.10.0
"#,
    )
    .unwrap();
    let uv_driver = VllmDriver::new(vllm_runner(Vec::new()), vllm_host(&[]));
    assert_eq!(
        uv_driver.detect(&cuda_worker(), &uv).availability,
        EngineAvailability::Acquirable
    );
    let uv_alias: EngineProvisioning = serde_yaml::from_str(
        r#"
launch: uv
acquire:
  source: uvx
  version: 0.10.0
"#,
    )
    .expect("uv is the canonical spelling for the managed environment");
    assert_eq!(
        uv_driver.detect(&cuda_worker(), &uv_alias).availability,
        EngineAvailability::Acquirable
    );

    let container: EngineProvisioning = serde_yaml::from_str(&format!(
        "launch: container\nimage: ghcr.io/vllm-project/vllm-openai@sha256:{}\nshm_size_gib: 4\n",
        "a".repeat(64)
    ))
    .unwrap();
    let docker = VllmDriver::new(
        vllm_runner(Vec::new()),
        vllm_host(&[("docker", "/usr/bin/docker")]),
    );
    assert_eq!(
        docker.detect(&cuda_worker(), &container).availability,
        EngineAvailability::Acquirable
    );
    let podman = VllmDriver::new(
        vllm_runner(Vec::new()),
        vllm_host(&[("podman", "/usr/bin/podman")]),
    );
    assert_eq!(
        podman.detect(&cuda_worker(), &container).availability,
        EngineAvailability::Acquirable
    );
    let absent = VllmDriver::new(vllm_runner(Vec::new()), vllm_host(&[]));
    assert_eq!(
        absent.detect(&cuda_worker(), &container).availability,
        EngineAvailability::Blocked
    );

    let mut old_gpu = cuda_worker();
    old_gpu.compute_capability = Some(sbproxy_model_host::ComputeCapability { major: 6, minor: 1 });
    assert_eq!(
        binary
            .detect(&old_gpu, &EngineProvisioning::default())
            .availability,
        EngineAvailability::Incompatible
    );
}

#[tokio::test]
async fn vllm_compatibility_reports_versions_or_bounded_unavailable_reasons() {
    let driver = VllmDriver::new(
        vllm_runner(vec![compatibility_output(true)]),
        vllm_host(&[("python3", "/usr/bin/python3")]),
    );
    let report = driver
        .compatibility_report(
            &VllmLaunchMode::Binary {
                executable: PathBuf::from("/usr/bin/vllm"),
                python: PathBuf::from("/usr/bin/python3"),
            },
            &cuda_worker(),
        )
        .await;
    assert!(report.compatible);
    assert_eq!(report.python.version.as_deref(), Some("3.12.4"));
    assert_eq!(report.torch.version.as_deref(), Some("2.7.1"));
    assert_eq!(report.cuda.version.as_deref(), Some("12.8"));
    assert_eq!(report.vllm.version.as_deref(), Some("0.10.0"));

    let unavailable = VllmDriver::new(vllm_runner(Vec::new()), vllm_host(&[]));
    let report = unavailable
        .compatibility_report(
            &VllmLaunchMode::Binary {
                executable: PathBuf::from("/usr/bin/vllm"),
                python: PathBuf::from("/usr/bin/python3"),
            },
            &cuda_worker(),
        )
        .await;
    assert!(!report.compatible);
    for component in [&report.python, &report.torch, &report.cuda, &report.vllm] {
        assert!(component.version.is_none());
        assert!(component
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.len() <= 256));
    }
}

#[tokio::test]
async fn vllm_provision_rejects_torch_cuda_mismatch_and_binary_launch_is_exact() {
    let incompatible = VllmDriver::new(
        vllm_runner(vec![compatibility_output(false)]),
        vllm_host(&[("vllm", "/usr/bin/vllm"), ("python3", "/usr/bin/python3")]),
    );
    let request = ProvisionRequest {
        artifact: resolved(EngineKind::Vllm, ArtifactFormat::Safetensors),
        worker: cuda_worker(),
        provisioning: EngineProvisioning::default(),
        engine_cache_dir: PathBuf::from("/engines"),
        job_store: None,
    };
    let error = incompatible
        .provision(&request)
        .await
        .expect_err("torch and CUDA mismatch");
    assert_eq!(error.reason(), EngineFailureReason::EngineIncompatible);

    let (runner, commands) = vllm_runner_with_commands(vec![compatibility_output(true)]);
    let driver = VllmDriver::new(
        runner,
        vllm_host(&[("vllm", "/usr/bin/vllm"), ("python3", "/usr/bin/python3")]),
    );
    let provisioned = driver.provision(&request).await.expect("binary vLLM");
    let mut launch = LaunchRequest {
        deployment: "coder".to_string(),
        generation: 5,
        artifact: ready(EngineKind::Vllm, ArtifactFormat::Safetensors),
        fit: fit(),
        port: 18124,
        accelerator: sbproxy_model_host::AcceleratorKind::Cuda,
        selected_devices: vec![3],
        kv_quant: KvCacheQuant::Fp8,
        extra_args: vec!["--enable-prefix-caching".to_string()],
        max_concurrency: 1,
        ready_timeout: Duration::from_secs(1),
    };
    launch.fit.memory = sbproxy_model_host::MemoryEstimate {
        device_index: 0,
        weight_bytes: 512,
        kv_bytes: 256,
        runtime_overhead_bytes: 128,
        safety_margin_bytes: 128,
        total_bytes: 1024,
    };
    let running = driver
        .launch(&provisioned, &launch)
        .await
        .expect("vLLM launch");
    assert_eq!(running.port, 18124);
    let captured = commands.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].executable, PathBuf::from("/usr/bin/vllm"));
    assert_eq!(captured[0].arguments[0], "serve");
    assert_eq!(captured[0].arguments[1], "/verified/fixture");
    assert_eq!(flag_value(&captured[0].arguments, "--host"), "127.0.0.1");
    assert_eq!(flag_value(&captured[0].arguments, "--port"), "18124");
    assert_eq!(
        flag_value(&captured[0].arguments, "--served-model-name"),
        "coder"
    );
    assert_eq!(
        flag_value(&captured[0].arguments, "--kv-cache-dtype"),
        "fp8"
    );
    assert_eq!(flag_value(&captured[0].arguments, "--max-num-seqs"), "1");
    assert_eq!(
        flag_value(&captured[0].arguments, "--kv-cache-memory-bytes"),
        "256"
    );
    assert_eq!(captured[0].environment["CUDA_VISIBLE_DEVICES"], "3");
}

#[tokio::test]
async fn vllm_uv_provision_and_launch_keep_the_package_pin() {
    let provisioning: EngineProvisioning = serde_yaml::from_str(
        r#"
launch: venv
acquire:
  source: uvx
  version: 0.10.0
"#,
    )
    .unwrap();
    let (runner, commands) = vllm_runner_with_commands(vec![compatibility_output(true)]);
    let driver = VllmDriver::new(runner, vllm_host(&[]));
    let provisioned = driver
        .provision(&ProvisionRequest {
            artifact: resolved(EngineKind::Vllm, ArtifactFormat::Safetensors),
            worker: cuda_worker(),
            provisioning,
            engine_cache_dir: PathBuf::from("/engines"),
            job_store: None,
        })
        .await
        .expect("managed uv environment");
    assert_eq!(provisioned.executable, PathBuf::from("/engines/uv"));
    assert_eq!(provisioned.version.as_deref(), Some("0.10.0"));
    driver
        .launch(
            &provisioned,
            &LaunchRequest {
                deployment: "coder".to_string(),
                generation: 6,
                artifact: ready(EngineKind::Vllm, ArtifactFormat::Safetensors),
                fit: fit(),
                port: 18125,
                accelerator: sbproxy_model_host::AcceleratorKind::Cuda,
                selected_devices: vec![0],
                kv_quant: KvCacheQuant::Auto,
                extra_args: Vec::new(),
                max_concurrency: 1,
                ready_timeout: Duration::from_secs(1),
            },
        )
        .await
        .expect("uv vLLM launch");

    let captured = commands.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        &captured[0].arguments[..6],
        &["tool", "run", "--from", "vllm==0.10.0", "vllm", "serve"]
    );
}

#[test]
fn vllm_container_launch_is_private_read_only_and_device_scoped() {
    let request = LaunchRequest {
        deployment: "coder".to_string(),
        generation: 4,
        artifact: ready(EngineKind::Vllm, ArtifactFormat::Safetensors),
        fit: fit(),
        port: 18123,
        accelerator: sbproxy_model_host::AcceleratorKind::Cuda,
        selected_devices: vec![1],
        kv_quant: KvCacheQuant::Auto,
        extra_args: vec!["--enable-prefix-caching".to_string()],
        max_concurrency: 1,
        ready_timeout: Duration::from_secs(1),
    };
    let image = format!("ghcr.io/vllm-project/vllm-openai@sha256:{}", "a".repeat(64));
    let plan = build_vllm_container_plan(
        ContainerRuntime::Docker,
        PathBuf::from("/usr/bin/docker"),
        &image,
        4,
        &request,
    )
    .expect("isolated container plan");

    assert!(plan
        .arguments
        .windows(2)
        .any(|window| window == ["--gpus", "device=1"]));
    assert!(plan
        .arguments
        .iter()
        .any(|value| value == "127.0.0.1:18123:8000"));
    assert!(plan
        .arguments
        .iter()
        .any(|value| { value.contains("dst=/models/model") && value.contains("readonly") }));
    assert!(plan
        .arguments
        .windows(2)
        .any(|window| window == ["--network", "sbproxy-model-host"]));
    assert!(!plan.arguments.iter().any(|value| {
        value == "--privileged"
            || value == "host"
            || value == "all"
            || value.contains("readonly=false")
    }));

    let podman = build_vllm_container_plan(
        ContainerRuntime::Podman,
        PathBuf::from("/usr/bin/podman"),
        &image,
        4,
        &request,
    )
    .expect("Podman CDI plan");
    assert!(podman
        .arguments
        .windows(2)
        .any(|window| window == ["--device", "nvidia.com/gpu=1"]));
    assert!(!podman.arguments.iter().any(|value| value == "--gpus"));

    for invalid in [
        "ghcr.io/vllm-project/vllm-openai:latest",
        "ghcr.io/vllm-project/vllm-openai:v0.10.0",
    ] {
        assert!(build_vllm_container_plan(
            ContainerRuntime::Docker,
            PathBuf::from("/usr/bin/docker"),
            invalid,
            4,
            &request,
        )
        .is_err());
    }
}
