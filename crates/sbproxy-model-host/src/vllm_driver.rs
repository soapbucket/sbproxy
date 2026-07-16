// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Managed vLLM binary, uv, and isolated-container driver.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::Deserialize;

use crate::{
    AcceleratorKind, AcquireSource, ArtifactFormat, CommandOutput, EngineAvailability,
    EngineCapabilities, EngineCommand, EngineDetection, EngineDriver, EngineDriverError,
    EngineFailureReason, EngineHealth, EngineKind, EngineLaunchMethod, EngineProcessRunner,
    EngineProvisioning, KvCacheQuant, LaunchRequest, ProvisionRequest, ProvisionedEngine,
    RunningEngine, WorkerProfile,
};

/// Default vLLM package pin used by managed uv provisioning.
pub const DEFAULT_VLLM_VERSION: &str = "0.10.0";

const DEFAULT_SHM_SIZE_GIB: u64 = 4;
const CONTAINER_PORT: u16 = 8000;
const PRIVATE_NETWORK: &str = "sbproxy-model-host";
const HEALTH_PATH: &str = "/health";
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const PROBE_OUTPUT_LIMIT: usize = 16 * 1024;
const COMPATIBILITY_SCRIPT: &str = r#"import json,platform
data={"python":platform.python_version(),"torch":None,"cuda":None,"vllm":None,"compatible":False,"reason":None}
try:
 import torch
 data["torch"]=torch.__version__
 data["cuda"]=torch.version.cuda
 import vllm
 data["vllm"]=vllm.__version__
 data["compatible"]=True
except Exception as error:
 data["reason"]=type(error).__name__+": "+str(error)[:160]
print(json.dumps(data,separators=(",",":")))"#;

/// Supported OCI command-line runtimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerRuntime {
    /// Docker Engine CLI.
    Docker,
    /// Podman CLI.
    Podman,
}

/// Exact vLLM launch mechanism selected during provisioning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VllmLaunchMode {
    /// Operator-installed vLLM and its Python interpreter.
    Binary {
        /// vLLM executable.
        executable: PathBuf,
        /// Python interpreter used for compatibility probes.
        python: PathBuf,
    },
    /// Managed uv environment with an exact vLLM package pin.
    Uv {
        /// uv executable.
        executable: PathBuf,
        /// Exact vLLM package version.
        vllm_version: String,
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

/// One compatibility component's version or bounded unavailable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VllmComponentStatus {
    /// Detected version.
    pub version: Option<String>,
    /// Bounded reason the version could not be detected.
    pub unavailable_reason: Option<String>,
}

impl VllmComponentStatus {
    fn version(version: Option<String>, component: &str) -> Self {
        match version.filter(|value| !value.trim().is_empty()) {
            Some(version) => Self {
                version: Some(version),
                unavailable_reason: None,
            },
            None => Self::unavailable(format!("{component} version was not reported")),
        }
    }

    fn unavailable(reason: impl AsRef<str>) -> Self {
        Self {
            version: None,
            unavailable_reason: Some(bounded_reason(reason.as_ref())),
        }
    }
}

/// Bounded vLLM environment compatibility report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VllmCompatibilityReport {
    /// Python runtime status.
    pub python: VllmComponentStatus,
    /// PyTorch runtime status.
    pub torch: VllmComponentStatus,
    /// CUDA toolkit exposed through PyTorch.
    pub cuda: VllmComponentStatus,
    /// vLLM package status.
    pub vllm: VllmComponentStatus,
    /// Whether all required components and the selected worker are compatible.
    pub compatible: bool,
    /// Bounded incompatibility reason.
    pub reason: Option<String>,
}

impl VllmCompatibilityReport {
    fn unavailable(reason: impl AsRef<str>) -> Self {
        let reason = bounded_reason(reason.as_ref());
        Self {
            python: VllmComponentStatus::unavailable(&reason),
            torch: VllmComponentStatus::unavailable(&reason),
            cuda: VllmComponentStatus::unavailable(&reason),
            vllm: VllmComponentStatus::unavailable(&reason),
            compatible: false,
            reason: Some(reason),
        }
    }
}

/// Host lookup and uv acquisition boundary for the vLLM driver.
#[async_trait]
pub trait VllmHost: Send + Sync {
    /// Resolve an executable by allowlisted name from `PATH`.
    fn resolve_on_path(&self, name: &str) -> Option<PathBuf>;

    /// Whether a path is an executable regular file.
    fn is_executable(&self, path: &Path) -> bool;

    /// Ensure the pinned uv binary is available.
    async fn ensure_uv(&self, cache_dir: &Path, version: &str) -> Result<PathBuf, String>;

    /// Host memory available for container shared-memory allocation.
    fn available_shared_memory_bytes(&self) -> u64;
}

/// Production vLLM host adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemVllmHost;

#[async_trait]
impl VllmHost for SystemVllmHost {
    fn resolve_on_path(&self, name: &str) -> Option<PathBuf> {
        crate::llama_release::resolve_on_path(name)
    }

    fn is_executable(&self, path: &Path) -> bool {
        crate::llama_release::is_executable_file(path)
    }

    async fn ensure_uv(&self, cache_dir: &Path, version: &str) -> Result<PathBuf, String> {
        #[cfg(feature = "weights")]
        {
            crate::uv_release::ensure_uv(cache_dir, version).await
        }
        #[cfg(not(feature = "weights"))]
        {
            let _ = (cache_dir, version);
            Err("managed uv provisioning requires the model-host weights feature".to_string())
        }
    }

    fn available_shared_memory_bytes(&self) -> u64 {
        crate::detect_total_memory_bytes().unwrap_or(0)
    }
}

/// Exact isolated container invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VllmContainerPlan {
    /// Selected container runtime.
    pub runtime: ContainerRuntime,
    /// Container runtime executable.
    pub executable: PathBuf,
    /// Exact tokenized runtime argv.
    pub arguments: Vec<String>,
}

/// Managed vLLM lifecycle driver.
#[derive(Clone)]
pub struct VllmDriver {
    runner: EngineProcessRunner,
    host: Arc<dyn VllmHost>,
}

impl std::fmt::Debug for VllmDriver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VllmDriver")
            .field("runner", &self.runner)
            .finish_non_exhaustive()
    }
}

impl VllmDriver {
    /// Construct a driver with explicit process and host adapters.
    pub fn new(runner: EngineProcessRunner, host: Arc<dyn VllmHost>) -> Self {
        Self { runner, host }
    }

    /// Probe fixed Python, torch, CUDA, and vLLM versions with bounded output.
    pub async fn compatibility_report(
        &self,
        mode: &VllmLaunchMode,
        worker: &WorkerProfile,
    ) -> VllmCompatibilityReport {
        if let Some(reason) = worker_compatibility_error(worker) {
            return VllmCompatibilityReport::unavailable(reason);
        }
        let (executable, arguments) = compatibility_command(mode);
        let output = match self
            .runner
            .output(
                &executable,
                &arguments,
                &BTreeMap::new(),
                PROBE_TIMEOUT,
                PROBE_OUTPUT_LIMIT,
            )
            .await
        {
            Ok(output) => output,
            Err(error) => return VllmCompatibilityReport::unavailable(error.to_string()),
        };
        parse_compatibility_output(output, worker)
    }

    fn mode_from_provisioned(
        &self,
        provisioned: &ProvisionedEngine,
    ) -> Result<VllmLaunchMode, EngineDriverError> {
        if provisioned.provisioning.launch == EngineLaunchMethod::Container {
            let image = provisioned.provisioning.image.clone().ok_or_else(|| {
                EngineDriverError::blocked(
                    "vLLM container provisioning lost its image",
                    "reconcile a digest-pinned container configuration",
                )
            })?;
            return Ok(VllmLaunchMode::Container {
                runtime: container_runtime_from_path(&provisioned.executable),
                executable: provisioned.executable.clone(),
                image,
            });
        }
        if uses_uv(&provisioned.provisioning) {
            return Ok(VllmLaunchMode::Uv {
                executable: provisioned.executable.clone(),
                vllm_version: provisioned
                    .version
                    .clone()
                    .unwrap_or_else(|| DEFAULT_VLLM_VERSION.to_string()),
            });
        }
        let python = self.executable("python3").ok_or_else(|| {
            EngineDriverError::new(
                EngineFailureReason::EngineIncompatible,
                "python3 is unavailable for the vLLM binary",
                "install the Python environment that owns vLLM or use managed uv",
                false,
            )
        })?;
        Ok(VllmLaunchMode::Binary {
            executable: provisioned.executable.clone(),
            python,
        })
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
                format!("create private vLLM network: {}", create.stderr),
                "allow the selected container runtime to create an internal bridge network",
            ))
        }
    }
}

impl Default for VllmDriver {
    fn default() -> Self {
        Self::new(EngineProcessRunner::default(), Arc::new(SystemVllmHost))
    }
}

#[async_trait]
impl EngineDriver for VllmDriver {
    fn kind(&self) -> EngineKind {
        EngineKind::Vllm
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            artifact_formats: vec![ArtifactFormat::Safetensors, ArtifactFormat::Pickle],
            accelerators: vec![AcceleratorKind::Cuda],
            supports_container: true,
            supports_uv: true,
        }
    }

    fn detect(&self, worker: &WorkerProfile, provisioning: &EngineProvisioning) -> EngineDetection {
        if !worker.engines.contains(&EngineKind::Vllm) {
            return incompatible("worker capability profile does not permit vLLM");
        }
        if let Some(reason) = worker_compatibility_error(worker) {
            return incompatible(reason);
        }
        if provisioning.launch == EngineLaunchMethod::Container {
            if !provisioning.image_is_digest_pinned() {
                return blocked(
                    "stable vLLM container launch requires an immutable sha256 image digest",
                    "replace the image tag with repository@sha256:<64 lowercase hex>",
                );
            }
            let shm_size_gib = provisioning.shm_size_gib.unwrap_or(DEFAULT_SHM_SIZE_GIB);
            if shm_size_gib == 0
                || shm_size_gib.saturating_mul(1024 * 1024 * 1024)
                    > self.host.available_shared_memory_bytes()
            {
                return blocked(
                    format!("requested vLLM shared memory {shm_size_gib} GiB exceeds host limits"),
                    "reduce shm_size_gib or use a worker with more available memory",
                );
            }
            return match self.container_runtime() {
                Some((runtime, _)) => EngineDetection {
                    kind: EngineKind::Vllm,
                    availability: EngineAvailability::Acquirable,
                    version: None,
                    reason: format!("{runtime:?} can run the digest-pinned vLLM image"),
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
                kind: EngineKind::Vllm,
                availability: EngineAvailability::Acquirable,
                version: Some(vllm_version(provisioning)),
                reason: "a pinned vLLM environment is acquirable through uv".to_string(),
                remediation: None,
            };
        }
        let Some(vllm) = self.executable("vllm") else {
            return blocked(
                "vLLM is not installed on PATH",
                "configure managed uv or a digest-pinned container image",
            );
        };
        if self.executable("python3").is_none() {
            return incompatible(
                "python3 for the installed vLLM environment is unavailable; use managed uv",
            );
        }
        EngineDetection {
            kind: EngineKind::Vllm,
            availability: EngineAvailability::Available,
            version: provisioning
                .acquire
                .as_ref()
                .and_then(|acquire| acquire.version.clone()),
            reason: format!("executable vLLM found at {}", vllm.display()),
            remediation: None,
        }
    }

    async fn provision(
        &self,
        request: &ProvisionRequest,
    ) -> Result<ProvisionedEngine, EngineDriverError> {
        if request.artifact.engine != EngineKind::Vllm
            || !matches!(
                request.artifact.format,
                ArtifactFormat::Safetensors | ArtifactFormat::Pickle
            )
        {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineIncompatible,
                "vLLM provisioning requires a resolved safetensors or approved pickle artifact",
                "select a catalog variant compatible with vLLM",
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
                        .unwrap_or_else(|| "correct vLLM provisioning".to_string()),
                ));
            }
            EngineAvailability::Incompatible => {
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    detection.reason,
                    detection
                        .remediation
                        .unwrap_or_else(|| "select a compatible vLLM worker".to_string()),
                    false,
                ));
            }
            EngineAvailability::Available | EngineAvailability::Acquirable => {}
        }

        let mode = if request.provisioning.launch == EngineLaunchMethod::Container {
            let (runtime, executable) = self.container_runtime().ok_or_else(|| {
                EngineDriverError::blocked(
                    "container runtime disappeared during vLLM provisioning",
                    "restore Docker or Podman and retry",
                )
            })?;
            self.ensure_private_network(&executable).await?;
            VllmLaunchMode::Container {
                runtime,
                executable,
                image: request.provisioning.image.clone().expect("validated image"),
            }
        } else if uses_uv(&request.provisioning) {
            let version = vllm_version(&request.provisioning);
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
                        format!("provision uv for vLLM: {error}"),
                        "verify network policy and the engine cache, then retry",
                        true,
                    )
                })?;
            VllmLaunchMode::Uv {
                executable,
                vllm_version: version,
            }
        } else {
            VllmLaunchMode::Binary {
                executable: self.executable("vllm").expect("validated vllm path"),
                python: self.executable("python3").expect("validated python path"),
            }
        };
        let report = self.compatibility_report(&mode, &request.worker).await;
        if !report.compatible {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineIncompatible,
                report
                    .reason
                    .unwrap_or_else(|| "vLLM compatibility probe failed".to_string()),
                "run model-host doctor and repair Python, torch, CUDA, or vLLM compatibility",
                false,
            ));
        }
        let (executable, version, fingerprint) = match mode {
            VllmLaunchMode::Binary { executable, .. } => (
                executable.clone(),
                report.vllm.version.clone(),
                format!("path:{}", executable.display()),
            ),
            VllmLaunchMode::Uv {
                executable,
                vllm_version,
            } => (
                executable,
                Some(vllm_version.clone()),
                format!("uv:vllm=={vllm_version}"),
            ),
            VllmLaunchMode::Container {
                executable, image, ..
            } => (executable, report.vllm.version.clone(), image),
        };
        Ok(ProvisionedEngine {
            kind: EngineKind::Vllm,
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
        if provisioned.kind != EngineKind::Vllm {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "vLLM driver received a different provisioned engine kind",
                "reconcile and provision the deployment again",
                false,
            ));
        }
        request.validate(EngineKind::Vllm)?;
        let mode = self.mode_from_provisioned(provisioned)?;
        let command = match mode {
            VllmLaunchMode::Binary { executable, .. } => EngineCommand {
                executable,
                arguments: direct_vllm_arguments(request)?,
                environment: device_environment(request),
                port: request.port,
                health_path: HEALTH_PATH.to_string(),
                ready_timeout: request.ready_timeout,
                stderr_tail_lines: 15,
            },
            VllmLaunchMode::Uv {
                executable,
                vllm_version,
            } => {
                let mut arguments = vec![
                    "tool".to_string(),
                    "run".to_string(),
                    "--from".to_string(),
                    format!("vllm=={vllm_version}"),
                    "vllm".to_string(),
                ];
                arguments.extend(direct_vllm_arguments(request)?);
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
            VllmLaunchMode::Container {
                runtime,
                executable,
                image,
            } => {
                let plan = build_vllm_container_plan(
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
            kind: EngineKind::Vllm,
            port: request.port,
            selected_devices: request.selected_devices.clone(),
            accelerator: request.accelerator,
            started_at_ms: unix_time_ms()?,
            artifact_digest: request.artifact.artifact_digest.clone(),
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

/// Build a private, read-only, selected-device container invocation.
pub fn build_vllm_container_plan(
    runtime: ContainerRuntime,
    executable: PathBuf,
    image: &str,
    shm_size_gib: u64,
    request: &LaunchRequest,
) -> Result<VllmContainerPlan, EngineDriverError> {
    request.validate(EngineKind::Vllm)?;
    if !digest_pinned_image(image) {
        return Err(EngineDriverError::blocked(
            "stable vLLM container launch requires an immutable sha256 image digest",
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
            "vLLM container launch requires selected CUDA devices",
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
    let mut arguments = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--name".to_string(),
        format!("sbproxy-{}-g{}", request.deployment, request.generation),
        "--network".to_string(),
        PRIVATE_NETWORK.to_string(),
    ];
    match runtime {
        ContainerRuntime::Docker => {
            let devices = request
                .selected_devices
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            arguments.extend(["--gpus".to_string(), format!("device={devices}")]);
        }
        ContainerRuntime::Podman => {
            for device in &request.selected_devices {
                arguments.extend(["--device".to_string(), format!("nvidia.com/gpu={device}")]);
            }
        }
    }
    arguments.extend([
        "--shm-size".to_string(),
        format!("{shm_size_gib}g"),
        "--mount".to_string(),
        format!("type=bind,src={snapshot},dst=/models/model,readonly"),
        "-p".to_string(),
        format!("127.0.0.1:{}:{CONTAINER_PORT}", request.port),
        image.to_string(),
        "--model".to_string(),
        "/models/model".to_string(),
        "--host".to_string(),
        "0.0.0.0".to_string(),
        "--port".to_string(),
        CONTAINER_PORT.to_string(),
        "--served-model-name".to_string(),
        request.deployment.clone(),
        "--max-model-len".to_string(),
        request.fit.seq_len.to_string(),
        "--max-num-seqs".to_string(),
        request.max_concurrency.to_string(),
        "--kv-cache-memory-bytes".to_string(),
        request.fit.memory.kv_bytes.to_string(),
    ]);
    append_tensor_parallel_arguments(&mut arguments, &request.selected_devices);
    append_vllm_precision_arguments(&mut arguments, request);
    append_vllm_passthrough_arguments(&mut arguments, &request.engine_tuning);
    arguments.extend(crate::validate_engine_args(
        EngineKind::Vllm,
        &request.extra_args,
    )?);
    Ok(VllmContainerPlan {
        runtime,
        executable,
        arguments,
    })
}

fn direct_vllm_arguments(request: &LaunchRequest) -> Result<Vec<String>, EngineDriverError> {
    let mut arguments = vec![
        "serve".to_string(),
        request.artifact.snapshot_path.display().to_string(),
        "--host".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        request.port.to_string(),
        "--served-model-name".to_string(),
        request.deployment.clone(),
        "--max-model-len".to_string(),
        request.fit.seq_len.to_string(),
        "--max-num-seqs".to_string(),
        request.max_concurrency.to_string(),
        "--kv-cache-memory-bytes".to_string(),
        request.fit.memory.kv_bytes.to_string(),
    ];
    append_tensor_parallel_arguments(&mut arguments, &request.selected_devices);
    append_vllm_precision_arguments(&mut arguments, request);
    append_vllm_passthrough_arguments(&mut arguments, &request.engine_tuning);
    arguments.extend(crate::validate_engine_args(
        EngineKind::Vllm,
        &request.extra_args,
    )?);
    Ok(arguments)
}

/// Emit the runtime-owned tensor-parallel degree: one rank per selected CUDA
/// device. The operator cannot set `--tensor-parallel-size` (it is on the
/// rejected-argument denylist), so the runtime derives it from the placement
/// and config can never contradict the device assignment. Single-device
/// deployments emit nothing, since vLLM defaults to a degree of one.
fn append_tensor_parallel_arguments(arguments: &mut Vec<String>, selected_devices: &[u32]) {
    if selected_devices.len() > 1 {
        arguments.extend([
            "--tensor-parallel-size".to_string(),
            selected_devices.len().to_string(),
        ]);
    }
}

/// Emit the runtime-owned vLLM tuning passthroughs from the served-model
/// config: chunked prefill, tool-call parsing, and CPU KV/weight offload.
/// These flags are not on the operator `extra_args` allowlist, so the
/// runtime owns them here (the same pattern as tensor parallelism); the
/// desired-state validator rejects a non-vLLM model that sets them, so
/// only vLLM launches ever reach this path with them populated.
fn append_vllm_passthrough_arguments(arguments: &mut Vec<String>, tuning: &crate::EngineTuning) {
    // Tool calling: vLLM rejects `tool_choice: auto` unless launched with a
    // model-specific parser, so the operator declares it and we enable it.
    if let Some(parser) = &tuning.tool_call_parser {
        arguments.push("--enable-auto-tool-choice".to_string());
        arguments.push("--tool-call-parser".to_string());
        arguments.push(parser.clone());
    }
    // CPU KV tier: `--swap-space` sizes the CPU pool vLLM spills GPU KV
    // blocks into; `--cpu-offload-gb` keeps that many GiB of weights in RAM.
    if let Some(gib) = tuning.swap_space_gib {
        arguments.push("--swap-space".to_string());
        arguments.push(gib.to_string());
    }
    if let Some(gib) = tuning.cpu_offload_gib {
        arguments.push("--cpu-offload-gb".to_string());
        arguments.push(gib.to_string());
    }
    // Chunked prefill: enable it and, when the config pins a chunk size,
    // pass it through. Auto-tuning the chunk size to a TTFT target waits on
    // the throughput predictor and is not derived here.
    if let Some(chunked_prefill) = &tuning.chunked_prefill {
        arguments.push("--enable-chunked-prefill".to_string());
        if let Some(max_batched_tokens) = chunked_prefill.max_batched_tokens {
            arguments.push("--max-num-batched-tokens".to_string());
            arguments.push(max_batched_tokens.to_string());
        }
    }
}

fn append_vllm_precision_arguments(arguments: &mut Vec<String>, request: &LaunchRequest) {
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
        KvCacheQuant::Fp8 | KvCacheQuant::Int8 | KvCacheQuant::Int4 => Some("fp8"),
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

fn vllm_version(provisioning: &EngineProvisioning) -> String {
    provisioning
        .acquire
        .as_ref()
        .and_then(|acquire| acquire.version.clone())
        .unwrap_or_else(|| DEFAULT_VLLM_VERSION.to_string())
}

fn compatibility_command(mode: &VllmLaunchMode) -> (PathBuf, Vec<String>) {
    match mode {
        VllmLaunchMode::Binary { python, .. } => (
            python.clone(),
            vec!["-c".to_string(), COMPATIBILITY_SCRIPT.to_string()],
        ),
        VllmLaunchMode::Uv {
            executable,
            vllm_version,
        } => (
            executable.clone(),
            vec![
                "run".to_string(),
                "--isolated".to_string(),
                "--no-project".to_string(),
                "--with".to_string(),
                format!("vllm=={vllm_version}"),
                "python".to_string(),
                "-c".to_string(),
                COMPATIBILITY_SCRIPT.to_string(),
            ],
        ),
        VllmLaunchMode::Container {
            executable, image, ..
        } => (
            executable.clone(),
            vec![
                "run".to_string(),
                "--rm".to_string(),
                "--network".to_string(),
                "none".to_string(),
                "--entrypoint".to_string(),
                "python".to_string(),
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
    vllm: Option<String>,
    compatible: bool,
    reason: Option<String>,
}

fn parse_compatibility_output(
    output: CommandOutput,
    worker: &WorkerProfile,
) -> VllmCompatibilityReport {
    if !output.success {
        return VllmCompatibilityReport::unavailable(if output.stderr.is_empty() {
            "vLLM compatibility command exited unsuccessfully"
        } else {
            &output.stderr
        });
    }
    let payload: CompatibilityPayload = match serde_json::from_str(output.stdout.trim()) {
        Ok(payload) => payload,
        Err(error) => {
            return VllmCompatibilityReport::unavailable(format!(
                "parse vLLM compatibility output: {error}"
            ));
        }
    };
    let python = VllmComponentStatus::version(payload.python, "python");
    let torch = VllmComponentStatus::version(payload.torch, "torch");
    let cuda = VllmComponentStatus::version(payload.cuda, "CUDA");
    let vllm = VllmComponentStatus::version(payload.vllm, "vLLM");
    let versions_present = [&python, &torch, &cuda, &vllm]
        .iter()
        .all(|component| component.version.is_some());
    let worker_compatible = worker_compatibility_error(worker).is_none();
    let compatible = payload.compatible && versions_present && worker_compatible;
    VllmCompatibilityReport {
        python,
        torch,
        cuda,
        vllm,
        compatible,
        reason: (!compatible).then(|| {
            bounded_reason(
                payload
                    .reason
                    .as_deref()
                    .unwrap_or("Python, torch, CUDA, or vLLM version is unavailable"),
            )
        }),
    }
}

fn worker_compatibility_error(worker: &WorkerProfile) -> Option<String> {
    if worker.accelerator != AcceleratorKind::Cuda {
        return Some("managed vLLM currently requires a CUDA worker".to_string());
    }
    if worker
        .compute_capability
        .is_some_and(|capability| capability.major < 7)
    {
        return Some("vLLM requires CUDA compute capability 7.0 or newer".to_string());
    }
    None
}

fn incompatible(reason: impl Into<String>) -> EngineDetection {
    EngineDetection {
        kind: EngineKind::Vllm,
        availability: EngineAvailability::Incompatible,
        version: None,
        reason: reason.into(),
        remediation: Some("select a compatible CUDA worker or another managed engine".to_string()),
    }
}

fn blocked(reason: impl Into<String>, remediation: impl Into<String>) -> EngineDetection {
    EngineDetection {
        kind: EngineKind::Vllm,
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
    use super::{append_tensor_parallel_arguments, append_vllm_passthrough_arguments};
    use crate::{ChunkedPrefill, EngineTuning};

    fn value_after(arguments: &[String], flag: &str) -> String {
        let index = arguments
            .iter()
            .position(|argument| argument == flag)
            .unwrap_or_else(|| panic!("{flag} not emitted"));
        arguments[index + 1].clone()
    }

    #[test]
    fn tensor_parallel_size_is_emitted_only_for_a_multi_gpu_group() {
        let mut single = Vec::new();
        append_tensor_parallel_arguments(&mut single, &[0]);
        assert!(
            single.is_empty(),
            "a single GPU keeps vLLM's default of one"
        );

        let mut pair = Vec::new();
        append_tensor_parallel_arguments(&mut pair, &[0, 1]);
        assert_eq!(
            pair,
            vec!["--tensor-parallel-size".to_string(), "2".to_string()]
        );
    }

    #[test]
    fn empty_tuning_emits_no_passthrough_flags() {
        let mut arguments = Vec::new();
        append_vllm_passthrough_arguments(&mut arguments, &EngineTuning::default());
        assert!(arguments.is_empty());
    }

    #[test]
    fn every_tuning_knob_maps_to_its_vllm_flag() {
        let tuning = EngineTuning {
            chunked_prefill: Some(ChunkedPrefill {
                max_batched_tokens: Some(2048),
                target_ttft_ms: None,
            }),
            tool_call_parser: Some("hermes".to_string()),
            swap_space_gib: Some(16),
            cpu_offload_gib: Some(8),
        };
        let mut arguments = Vec::new();
        append_vllm_passthrough_arguments(&mut arguments, &tuning);

        assert!(arguments.iter().any(|a| a == "--enable-auto-tool-choice"));
        assert_eq!(value_after(&arguments, "--tool-call-parser"), "hermes");
        assert_eq!(value_after(&arguments, "--swap-space"), "16");
        assert_eq!(value_after(&arguments, "--cpu-offload-gb"), "8");
        assert!(arguments.iter().any(|a| a == "--enable-chunked-prefill"));
        assert_eq!(value_after(&arguments, "--max-num-batched-tokens"), "2048");
    }

    #[test]
    fn chunked_prefill_without_a_chunk_size_only_enables_it() {
        let tuning = EngineTuning {
            chunked_prefill: Some(ChunkedPrefill {
                max_batched_tokens: None,
                target_ttft_ms: Some(250),
            }),
            ..EngineTuning::default()
        };
        let mut arguments = Vec::new();
        append_vllm_passthrough_arguments(&mut arguments, &tuning);

        assert!(arguments.iter().any(|a| a == "--enable-chunked-prefill"));
        assert!(
            !arguments.iter().any(|a| a == "--max-num-batched-tokens"),
            "the target_ttft_ms auto-tune is not derived here yet"
        );
    }
}
