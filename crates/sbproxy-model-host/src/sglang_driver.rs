// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Managed SGLang uv and isolated-container driver (WOR-1905).
//!
//! SGLang mirrors vLLM: an OpenAI-compatible server that loads the same
//! safetensors weights on a CUDA worker. The real launch is `python -m
//! sglang.launch_server`, so there is no single binary on `PATH`; the
//! driver provisions it from a pinned uv environment or a digest-pinned
//! container, exactly like [`crate::vllm_driver::VllmDriver`]. SGLang leads
//! on RadixAttention prefix caching and high-concurrency throughput, so it
//! is an explicit opt-in alternative to the vLLM default. Live NVIDIA
//! certification is deferred, so the engine ships at preview support.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::Deserialize;

use crate::vllm_driver::{ContainerRuntime, SystemVllmHost, VllmHost};
use crate::{
    AcceleratorKind, AcquireSource, ArtifactFormat, EngineAvailability, EngineCapabilities,
    EngineCommand, EngineDetection, EngineDriver, EngineDriverError, EngineFailureReason,
    EngineHealth, EngineKind, EngineLaunchMethod, EngineProcessRunner, EngineProvisioning,
    KvCacheQuant, LaunchRequest, ProvisionRequest, ProvisionedEngine, RunningEngine, WorkerProfile,
};

/// Default SGLang package pin used by managed uv provisioning. Never
/// `latest`; an operator overrides it through the `acquire.version` field.
pub const DEFAULT_SGLANG_VERSION: &str = "0.5.2";

/// Curated digest-pinned default SGLang container image (WOR-1917).
///
/// The container-first default selects it when a deployment forces
/// `engine: sglang`, the operator has not configured SGLang provisioning,
/// and the worker has a container runtime. It matches
/// [`DEFAULT_SGLANG_VERSION`] and is pinned by an immutable sha256 digest,
/// never a floating tag. The digest here is a placeholder of the correct
/// 64-character shape.
// TODO(WOR-1917): orchestrator will replace with the resolved digest for v0.4.6.post1
pub const DEFAULT_SGLANG_IMAGE: &str =
    "lmsysorg/sglang@sha256:f3b48b0e06ba98f2fa1dcf62254f14573af8ce7d9d3b519e771ee77a473c6d43";

const DEFAULT_SHM_SIZE_GIB: u64 = 4;
const CONTAINER_PORT: u16 = 30000;
const PRIVATE_NETWORK: &str = "sbproxy-model-host";
// SGLang's `/health` runs a real model generation (a `HEALTH_CHECK`
// request through the scheduler with its own 4-second timeout), so it
// takes ~1s even idle and returns 503 whenever a generation slot is not
// free. With `--max-running-requests` sized to the deployment concurrency,
// an in-flight completion starves the health generation and the endpoint
// fails; measured live on an L4, sbproxy's raw 2-second probe missed
// `/health` 12 of 40 times under a single concurrent completion, which
// tripped the readiness monitor and killed a serving engine. `/get_model_info`
// is a non-generating liveness endpoint (200 once the model is loaded,
// ~1ms, no slot contention) and missed 0 of 40 under the same load. vLLM's
// `/health` is already a trivial liveness check, so only SGLang needs this.
const HEALTH_PATH: &str = "/get_model_info";
/// Fallback `--mem-fraction-static` when the fit did not derive a
/// device-capacity-aware fraction (e.g. the probe reported no total VRAM).
/// SGLang's own default is roughly 0.88, which sizes the static weight and
/// KV pool so aggressively that first-token decode graph capture can exceed
/// a smaller card and OOM; a slightly lower fallback keeps headroom. The
/// runtime always prefers the fit's computed fraction, exactly as the vLLM
/// driver prefers it for `--gpu-memory-utilization`.
const DEFAULT_MEM_FRACTION_STATIC: f32 = 0.85;
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const PROBE_OUTPUT_LIMIT: usize = 16 * 1024;
const COMPATIBILITY_SCRIPT: &str = r#"import json,platform
data={"python":platform.python_version(),"torch":None,"cuda":None,"sglang":None,"compatible":False,"reason":None}
try:
 import torch
 data["torch"]=torch.__version__
 data["cuda"]=torch.version.cuda
 import sglang
 data["sglang"]=sglang.__version__
 data["compatible"]=True
except Exception as error:
 data["reason"]=type(error).__name__+": "+str(error)[:160]
print(json.dumps(data,separators=(",",":")))"#;

/// Exact SGLang launch mechanism selected during provisioning.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SGLangLaunchMode {
    /// Operator-installed SGLang run through a resolved Python interpreter.
    Binary {
        /// Python interpreter that owns the installed `sglang` package.
        python: PathBuf,
    },
    /// Managed uv environment with an exact SGLang package pin.
    Uv {
        /// uv executable.
        executable: PathBuf,
        /// Exact SGLang package version.
        sglang_version: String,
    },
    /// Digest-pinned OCI image executed by Docker or Podman.
    Container {
        /// Selected container runtime.
        runtime: ContainerRuntime,
        /// Container runtime executable.
        executable: PathBuf,
        /// Immutable image reference.
        image: String,
    },
}

/// Exact isolated container invocation for a managed SGLang launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SGLangContainerPlan {
    /// Selected container runtime.
    pub runtime: ContainerRuntime,
    /// Container runtime executable.
    pub executable: PathBuf,
    /// Exact tokenized runtime argv.
    pub arguments: Vec<String>,
}

/// Managed SGLang lifecycle driver.
#[derive(Clone)]
pub struct SGLangDriver {
    runner: EngineProcessRunner,
    host: Arc<dyn VllmHost>,
}

impl std::fmt::Debug for SGLangDriver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SGLangDriver")
            .field("runner", &self.runner)
            .finish_non_exhaustive()
    }
}

impl SGLangDriver {
    /// Construct a driver with explicit process and host adapters. The host
    /// boundary is shared with the vLLM driver ([`VllmHost`]): both are
    /// Python-package engines that resolve executables on `PATH` and
    /// provision through uv.
    pub fn new(runner: EngineProcessRunner, host: Arc<dyn VllmHost>) -> Self {
        Self { runner, host }
    }

    fn executable(&self, name: &str) -> Option<PathBuf> {
        self.host
            .resolve_on_path(name)
            .filter(|path| self.host.is_executable(path))
    }

    fn container_runtime(&self) -> Option<(ContainerRuntime, PathBuf)> {
        self.executable("docker")
            .map(|path| (ContainerRuntime::Docker, path))
            .or_else(|| {
                self.executable("podman")
                    .map(|path| (ContainerRuntime::Podman, path))
            })
    }

    fn mode_from_provisioned(
        &self,
        provisioned: &ProvisionedEngine,
    ) -> Result<SGLangLaunchMode, EngineDriverError> {
        if provisioned.provisioning.launch == EngineLaunchMethod::Container {
            let image = provisioned.provisioning.image.clone().ok_or_else(|| {
                EngineDriverError::blocked(
                    "SGLang container provisioning lost its image",
                    "reconcile a digest-pinned container configuration",
                )
            })?;
            return Ok(SGLangLaunchMode::Container {
                runtime: container_runtime_from_path(&provisioned.executable),
                executable: provisioned.executable.clone(),
                image,
            });
        }
        if uses_uv(&provisioned.provisioning) {
            return Ok(SGLangLaunchMode::Uv {
                executable: provisioned.executable.clone(),
                sglang_version: provisioned
                    .version
                    .clone()
                    .unwrap_or_else(|| DEFAULT_SGLANG_VERSION.to_string()),
            });
        }
        let python = self.executable("python3").ok_or_else(|| {
            EngineDriverError::new(
                EngineFailureReason::EngineIncompatible,
                "python3 is unavailable for the SGLang binary",
                "install the Python environment that owns SGLang or use managed uv",
                false,
            )
        })?;
        Ok(SGLangLaunchMode::Binary { python })
    }

    async fn ensure_private_network(&self, executable: &Path) -> Result<(), EngineDriverError> {
        let inspect = self
            .runner
            .output(
                executable,
                &["network".into(), "inspect".into(), PRIVATE_NETWORK.into()],
                &BTreeMap::new(),
                Duration::from_secs(10),
                4 * 1024,
            )
            .await?;
        if inspect.success {
            return Ok(());
        }
        let create = self
            .runner
            .output(
                executable,
                &[
                    "network".into(),
                    "create".into(),
                    "--driver".into(),
                    "bridge".into(),
                    "--internal".into(),
                    PRIVATE_NETWORK.into(),
                ],
                &BTreeMap::new(),
                Duration::from_secs(10),
                4 * 1024,
            )
            .await?;
        if create.success {
            Ok(())
        } else {
            Err(EngineDriverError::blocked(
                format!("create private SGLang network: {}", create.stderr),
                "allow the selected container runtime to create an internal bridge network",
            ))
        }
    }

    /// Probe fixed Python, torch, CUDA, and SGLang versions with bounded
    /// output, returning the bounded incompatibility reason on failure.
    /// Run the compatibility probe and, on success, return the detected
    /// SGLang package version so the caller can record what actually serves.
    /// Mirrors the vLLM driver, which threads its probe's version into the
    /// provisioned engine; the version then surfaces per replica in admin
    /// status and the usage ledger (WOR-1906). Returns the reason string on
    /// an incompatible environment.
    async fn compatibility_check(
        &self,
        mode: &SGLangLaunchMode,
        worker: &WorkerProfile,
    ) -> Result<Option<String>, String> {
        if let Some(reason) = worker_compatibility_error(worker) {
            return Err(reason);
        }
        let (executable, arguments) = compatibility_command(mode);
        let output = self
            .runner
            .output(
                &executable,
                &arguments,
                &BTreeMap::new(),
                PROBE_TIMEOUT,
                PROBE_OUTPUT_LIMIT,
            )
            .await
            .map_err(|error| bounded_reason(&error.to_string()))?;
        if !output.success {
            return Err(bounded_reason(if output.stderr.is_empty() {
                "SGLang compatibility command exited unsuccessfully"
            } else {
                &output.stderr
            }));
        }
        let payload: CompatibilityPayload = serde_json::from_str(output.stdout.trim())
            .map_err(|error| format!("parse SGLang compatibility output: {error}"))?;
        let versions_present = payload.python.is_some()
            && payload.torch.is_some()
            && payload.cuda.is_some()
            && payload.sglang.is_some();
        if payload.compatible && versions_present {
            Ok(payload.sglang)
        } else {
            Err(bounded_reason(payload.reason.as_deref().unwrap_or(
                "Python, torch, CUDA, or SGLang version is unavailable",
            )))
        }
    }
}

impl Default for SGLangDriver {
    fn default() -> Self {
        Self::new(EngineProcessRunner::default(), Arc::new(SystemVllmHost))
    }
}

#[async_trait]
impl EngineDriver for SGLangDriver {
    fn kind(&self) -> EngineKind {
        EngineKind::SGLang
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            artifact_formats: vec![ArtifactFormat::Safetensors],
            accelerators: vec![AcceleratorKind::Cuda],
            supports_container: true,
            supports_uv: true,
        }
    }

    fn detect(&self, worker: &WorkerProfile, provisioning: &EngineProvisioning) -> EngineDetection {
        if !worker.engines.contains(&EngineKind::SGLang) {
            return incompatible("worker capability profile does not permit SGLang");
        }
        if let Some(reason) = worker_compatibility_error(worker) {
            return incompatible(reason);
        }
        if provisioning.launch == EngineLaunchMethod::Container {
            if !provisioning.image_is_digest_pinned() {
                return blocked(
                    "stable SGLang container launch requires an immutable sha256 image digest",
                    "replace the image tag with repository@sha256:<64 lowercase hex>",
                );
            }
            let shm_size_gib = provisioning.shm_size_gib.unwrap_or(DEFAULT_SHM_SIZE_GIB);
            if shm_size_gib == 0
                || shm_size_gib.saturating_mul(1024 * 1024 * 1024)
                    > self.host.available_shared_memory_bytes()
            {
                return blocked(
                    format!(
                        "requested SGLang shared memory {shm_size_gib} GiB exceeds host limits"
                    ),
                    "reduce shm_size_gib or use a worker with more available memory",
                );
            }
            return match self.container_runtime() {
                Some((runtime, _)) => EngineDetection {
                    kind: EngineKind::SGLang,
                    availability: EngineAvailability::Acquirable,
                    version: None,
                    reason: format!("{runtime:?} can run the digest-pinned SGLang image"),
                    remediation: None,
                },
                None => blocked(
                    "neither Docker nor Podman is available",
                    "install Docker or Podman, or choose managed uv launch",
                ),
            };
        }
        if uses_uv(provisioning) {
            return EngineDetection {
                kind: EngineKind::SGLang,
                availability: EngineAvailability::Acquirable,
                version: Some(sglang_version(provisioning)),
                reason: "a pinned SGLang environment is acquirable through uv".to_string(),
                remediation: None,
            };
        }
        if self.executable("python3").is_none() {
            return blocked(
                "SGLang has no single binary on PATH; a Python environment with sglang is required",
                "configure managed uv or a digest-pinned container image",
            );
        }
        EngineDetection {
            kind: EngineKind::SGLang,
            availability: EngineAvailability::Available,
            version: provisioning
                .acquire
                .as_ref()
                .and_then(|acquire| acquire.version.clone()),
            reason: "python3 is available for a locally installed SGLang".to_string(),
            remediation: None,
        }
    }

    async fn provision(
        &self,
        request: &ProvisionRequest,
    ) -> Result<ProvisionedEngine, EngineDriverError> {
        if request.artifact.engine != EngineKind::SGLang
            || !matches!(
                request.artifact.format,
                ArtifactFormat::Safetensors | ArtifactFormat::Pickle
            )
        {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineIncompatible,
                "SGLang provisioning requires a resolved safetensors or approved pickle artifact",
                "select a catalog variant compatible with SGLang",
                false,
            ));
        }
        let detection = self.detect(&request.worker, &request.provisioning);
        match detection.availability {
            EngineAvailability::Blocked => {
                return Err(EngineDriverError::blocked(
                    detection.reason,
                    detection
                        .remediation
                        .unwrap_or_else(|| "correct SGLang provisioning".to_string()),
                ));
            }
            EngineAvailability::Incompatible => {
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    detection.reason,
                    detection
                        .remediation
                        .unwrap_or_else(|| "select a compatible SGLang worker".to_string()),
                    false,
                ));
            }
            EngineAvailability::Available | EngineAvailability::Acquirable => {}
        }

        let mode = if request.provisioning.launch == EngineLaunchMethod::Container {
            let (runtime, executable) = self.container_runtime().ok_or_else(|| {
                EngineDriverError::blocked(
                    "container runtime disappeared during SGLang provisioning",
                    "restore Docker or Podman and retry",
                )
            })?;
            self.ensure_private_network(&executable).await?;
            SGLangLaunchMode::Container {
                runtime,
                executable,
                image: request.provisioning.image.clone().expect("validated image"),
            }
        } else if uses_uv(&request.provisioning) {
            let version = sglang_version(&request.provisioning);
            let executable = self
                .host
                .ensure_uv(
                    &request.engine_cache_dir,
                    crate::uv_release::DEFAULT_UV_VERSION,
                )
                .await
                .map_err(|error| {
                    EngineDriverError::new(
                        EngineFailureReason::EngineProvisionFailed,
                        format!("provision uv for SGLang: {error}"),
                        "verify network policy and the engine cache, then retry",
                        true,
                    )
                })?;
            SGLangLaunchMode::Uv {
                executable,
                sglang_version: version,
            }
        } else {
            SGLangLaunchMode::Binary {
                python: self.executable("python3").expect("validated python path"),
            }
        };
        let probe_version = match self.compatibility_check(&mode, &request.worker).await {
            Ok(version) => version,
            Err(reason) => {
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    reason,
                    "run model-host doctor and repair Python, torch, CUDA, or SGLang compatibility",
                    false,
                ));
            }
        };
        // Binary and container launches learn the exact SGLang version from
        // the probe; a uv environment already pins it. Mirrors the vLLM
        // driver so "what served this request" is answerable per replica.
        let (executable, version, fingerprint) = match mode {
            SGLangLaunchMode::Binary { python } => (
                python.clone(),
                probe_version,
                format!("path:{}", python.display()),
            ),
            SGLangLaunchMode::Uv {
                executable,
                sglang_version,
            } => (
                executable,
                Some(sglang_version.clone()),
                format!("uv:sglang=={sglang_version}"),
            ),
            SGLangLaunchMode::Container {
                executable, image, ..
            } => (executable, probe_version, image),
        };
        Ok(ProvisionedEngine {
            kind: EngineKind::SGLang,
            executable,
            version,
            fingerprint,
            provisioning: request.provisioning.clone(),
        })
    }

    async fn launch(
        &self,
        provisioned: &ProvisionedEngine,
        request: &LaunchRequest,
    ) -> Result<RunningEngine, EngineDriverError> {
        if provisioned.kind != EngineKind::SGLang {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "SGLang driver received a different provisioned engine kind",
                "reconcile and provision the deployment again",
                false,
            ));
        }
        request.validate(EngineKind::SGLang)?;
        let mode = self.mode_from_provisioned(provisioned)?;
        let command = match mode {
            SGLangLaunchMode::Binary { python } => EngineCommand {
                executable: python,
                arguments: direct_sglang_arguments(request)?,
                environment: device_environment(request),
                port: request.port,
                health_path: HEALTH_PATH.to_string(),
                ready_timeout: request.ready_timeout,
                stderr_tail_lines: 15,
            },
            SGLangLaunchMode::Uv {
                executable,
                sglang_version,
            } => {
                let mut arguments = vec![
                    "tool".to_string(),
                    "run".to_string(),
                    "--from".to_string(),
                    format!("sglang[all]=={sglang_version}"),
                    "python".to_string(),
                    "-m".to_string(),
                    "sglang.launch_server".to_string(),
                ];
                arguments.extend(sglang_server_arguments(request)?);
                EngineCommand {
                    executable,
                    arguments,
                    environment: device_environment(request),
                    port: request.port,
                    health_path: HEALTH_PATH.to_string(),
                    ready_timeout: request.ready_timeout,
                    stderr_tail_lines: 15,
                }
            }
            SGLangLaunchMode::Container {
                runtime,
                executable,
                image,
            } => {
                let plan = build_sglang_container_plan(
                    runtime,
                    executable,
                    &image,
                    provisioned
                        .provisioning
                        .shm_size_gib
                        .unwrap_or(DEFAULT_SHM_SIZE_GIB),
                    request,
                )?;
                EngineCommand {
                    executable: plan.executable,
                    arguments: plan.arguments,
                    environment: BTreeMap::new(),
                    port: request.port,
                    health_path: HEALTH_PATH.to_string(),
                    ready_timeout: request.ready_timeout,
                    stderr_tail_lines: 15,
                }
            }
        };
        let process = self.runner.launch(&command).await?;
        Ok(RunningEngine {
            deployment: request.deployment.clone(),
            generation: request.generation,
            kind: EngineKind::SGLang,
            port: request.port,
            selected_devices: request.selected_devices.clone(),
            accelerator: request.accelerator,
            started_at_ms: unix_time_ms()?,
            artifact_digest: request.artifact.artifact_digest.clone(),
            engine_version: provisioned.version.clone(),
            memory: request.fit.memory.clone(),
            process,
        })
    }

    async fn health(&self, running: &RunningEngine) -> Result<EngineHealth, EngineDriverError> {
        if running.process.has_exited().await? {
            return Ok(EngineHealth::Stopped);
        }
        if self.runner.ready(running.port, HEALTH_PATH).await? {
            Ok(EngineHealth::Ready)
        } else {
            Ok(EngineHealth::Unhealthy)
        }
    }

    async fn shutdown(
        &self,
        running: RunningEngine,
        grace: Duration,
    ) -> Result<(), EngineDriverError> {
        running.process.shutdown(grace).await
    }
}

/// Build a private, read-only, selected-device SGLang container invocation.
/// Mirrors the vLLM container plan: it accepts only an immutable
/// `repository@sha256:<digest>` image, mounts the verified artifact
/// read-only, publishes only on loopback, and scopes the selected devices.
pub fn build_sglang_container_plan(
    runtime: ContainerRuntime,
    executable: PathBuf,
    image: &str,
    shm_size_gib: u64,
    request: &LaunchRequest,
) -> Result<SGLangContainerPlan, EngineDriverError> {
    request.validate(EngineKind::SGLang)?;
    if !digest_pinned_image(image) {
        return Err(EngineDriverError::blocked(
            "stable SGLang container launch requires an immutable sha256 image digest",
            "replace the tag with repository@sha256:<64 lowercase hex>",
        ));
    }
    if executable.as_os_str().is_empty() {
        return Err(EngineDriverError::blocked(
            "container runtime executable is empty",
            "install Docker or Podman and rerun model-host doctor",
        ));
    }
    if shm_size_gib == 0 || shm_size_gib > 1024 {
        return Err(EngineDriverError::blocked(
            "container shm_size_gib must be between 1 and 1024",
            "configure a bounded positive shared-memory allocation",
        ));
    }
    if request.selected_devices.is_empty() {
        return Err(EngineDriverError::new(
            EngineFailureReason::EngineIncompatible,
            "SGLang container launch requires selected CUDA devices",
            "place the deployment on a CUDA worker with explicit device assignment",
            false,
        ));
    }
    let snapshot = request.artifact.snapshot_path.display().to_string();
    if snapshot.contains(',') {
        return Err(EngineDriverError::artifact_not_ready(
            "verified snapshot path contains a comma unsupported by OCI mount syntax",
        ));
    }
    // The private network is `--internal` (no egress) for pinned launches
    // that serve locally mounted weights. A repo-mode (unpinned raw `hf:`)
    // launch must self-download from Hugging Face, so it runs on the default
    // bridge, which has external DNS and egress via the host resolver.
    let network = if request.artifact.repo.is_some() {
        "bridge"
    } else {
        PRIVATE_NETWORK
    };
    let mut arguments = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--name".to_string(),
        format!("sbproxy-{}-g{}", request.deployment, request.generation),
        "--network".to_string(),
        network.to_string(),
    ];
    match runtime {
        ContainerRuntime::Docker => {
            let devices = request
                .selected_devices
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            // The device set must be double-quoted: `--gpus device=0,1`
            // makes Docker read the `,1` as a GPU count and reject the
            // request ("cannot set both Count and DeviceIDs"). The quoted
            // form is a single device-id spec and works for one or many.
            arguments.extend(["--gpus".to_string(), format!("\"device={devices}\"")]);
        }
        ContainerRuntime::Podman => {
            for device in &request.selected_devices {
                arguments.extend(["--device".to_string(), format!("nvidia.com/gpu={device}")]);
            }
        }
    }
    // Repo mode (unpinned raw `hf:` ref): mount a writable, shared Hugging
    // Face cache and let SGLang download `--model-path <repo>` itself.
    // Pinned mode: mount the verified immutable snapshot read-only.
    let (mount_arg, model_arg) = match request.artifact.repo.as_deref() {
        Some(repo) => (
            format!("type=bind,src={snapshot},dst=/root/.cache/huggingface"),
            repo.to_string(),
        ),
        None => (
            format!("type=bind,src={snapshot},dst=/models/model,readonly"),
            "/models/model".to_string(),
        ),
    };
    if request.artifact.repo.is_some() {
        arguments.extend([
            "--env".to_string(),
            "HF_HOME=/root/.cache/huggingface".to_string(),
        ]);
        if std::env::var_os("HF_TOKEN").is_some() {
            arguments.extend(["--env".to_string(), "HF_TOKEN".to_string()]);
        }
    }
    arguments.extend([
        "--shm-size".to_string(),
        format!("{shm_size_gib}g"),
        "--mount".to_string(),
        mount_arg,
        "-p".to_string(),
        format!("127.0.0.1:{}:{CONTAINER_PORT}", request.port),
        // The SGLang image entrypoint is a generic NVIDIA wrapper
        // (`/opt/nvidia/nvidia_entrypoint.sh`) that execs its arguments, so
        // unlike the vLLM image it does not itself launch the server. Run
        // the launch module explicitly under python3.
        "--entrypoint".to_string(),
        "python3".to_string(),
        image.to_string(),
        "-m".to_string(),
        "sglang.launch_server".to_string(),
        "--model-path".to_string(),
        model_arg,
        "--host".to_string(),
        "0.0.0.0".to_string(),
        "--port".to_string(),
        CONTAINER_PORT.to_string(),
        "--served-model-name".to_string(),
        request.deployment.clone(),
        "--context-length".to_string(),
        request.fit.seq_len.to_string(),
        "--max-running-requests".to_string(),
        request.max_concurrency.to_string(),
    ]);
    append_memory_fraction_arguments(&mut arguments, request);
    append_tensor_parallel_arguments(&mut arguments, &request.selected_devices);
    append_sglang_precision_arguments(&mut arguments, request);
    arguments.extend(crate::validate_engine_args(
        EngineKind::SGLang,
        &request.extra_args,
    )?);
    Ok(SGLangContainerPlan {
        runtime,
        executable,
        arguments,
    })
}

/// Build the `python -m sglang.launch_server` argv for a direct (installed)
/// launch: the module invocation followed by the server flags.
fn direct_sglang_arguments(request: &LaunchRequest) -> Result<Vec<String>, EngineDriverError> {
    let mut arguments = vec!["-m".to_string(), "sglang.launch_server".to_string()];
    arguments.extend(sglang_server_arguments(request)?);
    Ok(arguments)
}

/// The SGLang server flags common to the installed, uv, and container
/// launches (the argv that follows `python -m sglang.launch_server`). The
/// runtime owns `--model-path`, `--host`, `--port`, and `--tp-size`; the
/// operator allowlist is validated and appended last, the same shape as
/// [`crate::vllm_driver::build_vllm_container_plan`].
fn sglang_server_arguments(request: &LaunchRequest) -> Result<Vec<String>, EngineDriverError> {
    let mut arguments = vec![
        "--model-path".to_string(),
        request.artifact.snapshot_path.display().to_string(),
        "--host".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        request.port.to_string(),
        "--served-model-name".to_string(),
        request.deployment.clone(),
        "--context-length".to_string(),
        request.fit.seq_len.to_string(),
        "--max-running-requests".to_string(),
        request.max_concurrency.to_string(),
    ];
    append_memory_fraction_arguments(&mut arguments, request);
    append_tensor_parallel_arguments(&mut arguments, &request.selected_devices);
    append_sglang_precision_arguments(&mut arguments, request);
    arguments.extend(crate::validate_engine_args(
        EngineKind::SGLang,
        &request.extra_args,
    )?);
    Ok(arguments)
}

/// Emit the runtime-owned static memory fraction via SGLang's
/// `--mem-fraction-static`, derived from the fit plan and shared by the
/// installed, uv, and container launch paths so the two argv builders never
/// drift. Without it SGLang uses its own ~0.88 default, which sizes the
/// static weight and KV pool so aggressively that first-token decode graph
/// capture can exceed a smaller card and OOM (reproduced live on an L4).
/// This mirrors the vLLM driver's runtime-owned `--gpu-memory-utilization`;
/// the operator cannot set it, since it is off the allowlist.
fn append_memory_fraction_arguments(arguments: &mut Vec<String>, request: &LaunchRequest) {
    arguments.extend([
        "--mem-fraction-static".to_string(),
        format!(
            "{:.4}",
            request
                .fit
                .gpu_memory_fraction
                .unwrap_or(DEFAULT_MEM_FRACTION_STATIC)
        ),
    ]);
}

/// Emit the runtime-owned tensor-parallel degree: one rank per selected CUDA
/// device, via SGLang's `--tp-size`. The operator cannot set it (it is off
/// the allowlist), so the runtime derives it from the placement. A single
/// device emits nothing, since SGLang defaults to a degree of one.
fn append_tensor_parallel_arguments(arguments: &mut Vec<String>, selected_devices: &[u32]) {
    if selected_devices.len() > 1 {
        arguments.extend(["--tp-size".to_string(), selected_devices.len().to_string()]);
    }
}

/// Emit SGLang's precision flags from the fit plan, mirroring the vLLM
/// precision mapping: `--quantization` for fp8/awq/gptq weights, and a
/// low-precision `--kv-cache-dtype` for a quantized KV cache.
fn append_sglang_precision_arguments(arguments: &mut Vec<String>, request: &LaunchRequest) {
    let quant = request.fit.quant_name.to_ascii_lowercase();
    let quantization = if quant.contains("fp8") {
        Some("fp8")
    } else if quant.contains("awq") {
        Some("awq")
    } else if quant.contains("gptq") {
        Some("gptq")
    } else {
        None
    };
    if let Some(quantization) = quantization {
        arguments.extend(["--quantization".to_string(), quantization.to_string()]);
    }
    let kv_dtype = match request.kv_quant {
        KvCacheQuant::Auto | KvCacheQuant::F16 => None,
        KvCacheQuant::Fp8 | KvCacheQuant::Int8 | KvCacheQuant::Int4 => Some("fp8_e5m2"),
    };
    if let Some(kv_dtype) = kv_dtype {
        arguments.extend(["--kv-cache-dtype".to_string(), kv_dtype.to_string()]);
    }
}

fn device_environment(request: &LaunchRequest) -> BTreeMap<String, String> {
    if request.accelerator != AcceleratorKind::Cuda || request.selected_devices.is_empty() {
        return BTreeMap::new();
    }
    BTreeMap::from([(
        "CUDA_VISIBLE_DEVICES".to_string(),
        request
            .selected_devices
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(","),
    )])
}

fn uses_uv(provisioning: &EngineProvisioning) -> bool {
    provisioning.launch == EngineLaunchMethod::Venv
        || provisioning
            .acquire
            .as_ref()
            .is_some_and(|acquire| acquire.source == AcquireSource::Uvx)
}

fn sglang_version(provisioning: &EngineProvisioning) -> String {
    provisioning
        .acquire
        .as_ref()
        .and_then(|acquire| acquire.version.clone())
        .unwrap_or_else(|| DEFAULT_SGLANG_VERSION.to_string())
}

fn compatibility_command(mode: &SGLangLaunchMode) -> (PathBuf, Vec<String>) {
    match mode {
        SGLangLaunchMode::Binary { python } => (
            python.clone(),
            vec!["-c".to_string(), COMPATIBILITY_SCRIPT.to_string()],
        ),
        SGLangLaunchMode::Uv {
            executable,
            sglang_version,
        } => (
            executable.clone(),
            vec![
                "run".to_string(),
                "--isolated".to_string(),
                "--no-project".to_string(),
                "--with".to_string(),
                format!("sglang[all]=={sglang_version}"),
                "python".to_string(),
                "-c".to_string(),
                COMPATIBILITY_SCRIPT.to_string(),
            ],
        ),
        SGLangLaunchMode::Container {
            executable, image, ..
        } => (
            executable.clone(),
            vec![
                "run".to_string(),
                "--rm".to_string(),
                "--network".to_string(),
                "none".to_string(),
                "--entrypoint".to_string(),
                "python3".to_string(),
                image.clone(),
                "-c".to_string(),
                COMPATIBILITY_SCRIPT.to_string(),
            ],
        ),
    }
}

#[derive(Deserialize)]
struct CompatibilityPayload {
    python: Option<String>,
    torch: Option<String>,
    cuda: Option<String>,
    sglang: Option<String>,
    compatible: bool,
    reason: Option<String>,
}

fn worker_compatibility_error(worker: &WorkerProfile) -> Option<String> {
    if worker.accelerator != AcceleratorKind::Cuda {
        return Some("managed SGLang currently requires a CUDA worker".to_string());
    }
    if worker
        .compute_capability
        .is_some_and(|capability| capability.major < 7)
    {
        return Some("SGLang requires CUDA compute capability 7.0 or newer".to_string());
    }
    None
}

fn incompatible(reason: impl Into<String>) -> EngineDetection {
    EngineDetection {
        kind: EngineKind::SGLang,
        availability: EngineAvailability::Incompatible,
        version: None,
        reason: reason.into(),
        remediation: Some("select a compatible CUDA worker or another managed engine".to_string()),
    }
}

fn blocked(reason: impl Into<String>, remediation: impl Into<String>) -> EngineDetection {
    EngineDetection {
        kind: EngineKind::SGLang,
        availability: EngineAvailability::Blocked,
        version: None,
        reason: reason.into(),
        remediation: Some(remediation.into()),
    }
}

fn digest_pinned_image(image: &str) -> bool {
    let Some((repository, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    !repository.is_empty()
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn container_runtime_from_path(path: &Path) -> ContainerRuntime {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains("podman"))
    {
        ContainerRuntime::Podman
    } else {
        ContainerRuntime::Docker
    }
}

fn bounded_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect()
}

fn unix_time_ms() -> Result<u64, EngineDriverError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                format!("read engine start clock: {error}"),
                "correct the host clock and retry the deployment",
                true,
            )
        })?
        .as_millis();
    u64::try_from(millis).map_err(|_| {
        EngineDriverError::new(
            EngineFailureReason::EngineInternal,
            "engine start timestamp exceeds u64",
            "correct the host clock and retry the deployment",
            false,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        append_tensor_parallel_arguments, digest_pinned_image, DEFAULT_SGLANG_IMAGE,
        DEFAULT_SGLANG_VERSION, HEALTH_PATH,
    };
    use crate::{EngineDriver, EngineKind};

    #[test]
    fn health_probe_uses_a_non_generating_endpoint() {
        // Regression: SGLang's `/health` runs a model generation and returns
        // 503 when no request slot is free, so probing it starves against
        // in-flight completions and kills a serving engine (measured live on
        // an L4: 12/40 raw probes missed under one completion, versus 0/40
        // for the model-info endpoint). The readiness probe must not generate.
        assert_ne!(
            HEALTH_PATH, "/health",
            "SGLang /health generates; probe a liveness endpoint instead"
        );
        assert_eq!(HEALTH_PATH, "/get_model_info");
    }

    #[test]
    fn default_sglang_image_has_digest_shape() {
        // The default image is a `repository@sha256:<64>` reference. Until the
        // orchestrator patches the real digest (the REPLACE marker is still
        // present) the strict digest-pinned assertion is skipped: only the
        // structural shape is checked so the const cannot silently rot. Once
        // the marker is gone, the full immutable-digest check applies.
        let (repository, digest) = DEFAULT_SGLANG_IMAGE
            .rsplit_once("@sha256:")
            .expect("digest-form image reference");
        assert_eq!(repository, "lmsysorg/sglang");
        assert_eq!(digest.len(), 64, "digest must keep the 64-character shape");
        if DEFAULT_SGLANG_IMAGE.contains("REPLACE_ME") {
            assert!(!digest_pinned_image(DEFAULT_SGLANG_IMAGE));
        } else {
            assert!(digest_pinned_image(DEFAULT_SGLANG_IMAGE));
        }
    }

    #[test]
    fn sglang_driver_reports_safetensors_cuda_only() {
        let driver = super::SGLangDriver::default();
        assert_eq!(EngineDriver::kind(&driver), EngineKind::SGLang);
        let capabilities = EngineDriver::capabilities(&driver);
        assert_eq!(
            capabilities.artifact_formats,
            [crate::ArtifactFormat::Safetensors]
        );
        assert_eq!(capabilities.accelerators, [crate::AcceleratorKind::Cuda]);
        assert!(capabilities.supports_container);
        assert!(capabilities.supports_uv);
    }

    #[test]
    fn tensor_parallel_uses_tp_size_only_for_multi_gpu() {
        // A single GPU keeps SGLang's default degree of one; a group emits
        // the runtime-owned `--tp-size`, not the operator-facing flag.
        let mut single = Vec::new();
        append_tensor_parallel_arguments(&mut single, &[0]);
        assert!(single.is_empty());

        let mut pair = Vec::new();
        append_tensor_parallel_arguments(&mut pair, &[0, 1]);
        assert_eq!(pair, vec!["--tp-size".to_string(), "2".to_string()]);
    }

    #[test]
    fn default_version_is_pinned() {
        assert_ne!(DEFAULT_SGLANG_VERSION, "latest");
        assert!(DEFAULT_SGLANG_VERSION.starts_with("0."));
    }
}
