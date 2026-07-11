// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Managed llama.cpp driver over verified GGUF artifacts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::{
    AcceleratorKind, ArtifactFormat, BinaryAcquirePlan, EngineAccel, EngineAvailability,
    EngineCapabilities, EngineCommand, EngineDetection, EngineDriver, EngineDriverError,
    EngineFailureReason, EngineHealth, EngineKind, EngineLaunchMethod, EngineProcessRunner,
    EngineProvisioning, KvCacheQuant, LaunchRequest, ProvisionRequest, ProvisionedEngine,
    RunningEngine, WorkerProfile,
};

const HEALTH_PATH: &str = "/health";

/// llama.cpp-specific detection result.
pub type LlamaDetection = EngineDetection;

/// llama.cpp-specific provisioned engine.
pub type LlamaProvisioned = ProvisionedEngine;

/// Binary lookup and release acquisition boundary used by the llama.cpp driver.
#[async_trait]
pub trait LlamaBinarySource: Send + Sync {
    /// Resolve an operator-installed `llama-server` from `PATH`.
    fn resolve_on_path(&self) -> Option<PathBuf>;

    /// Whether a resolved path names an executable regular file.
    fn is_executable(&self, path: &Path) -> bool;

    /// Acquire one pinned llama.cpp release into `cache_dir`.
    async fn fetch_release(
        &self,
        cache_dir: &Path,
        version: &str,
        acceleration: EngineAccel,
        sha256: Option<&str>,
    ) -> Result<PathBuf, String>;

    /// Detect fixed CUDA source-build prerequisites.
    fn cuda_prerequisites(&self) -> crate::CudaBuildPrerequisites {
        crate::CudaBuildPrerequisites::detect_system()
    }

    /// Build or return a cached CUDA llama-server from pinned source.
    async fn build_cuda(
        &self,
        cache_dir: &Path,
        tag: &str,
        source_sha256: &str,
    ) -> Result<PathBuf, String> {
        let _ = (cache_dir, tag, source_sha256);
        Err("CUDA source building is unavailable from this binary source".to_string())
    }
}

/// Production llama.cpp binary source.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemLlamaBinarySource;

#[async_trait]
impl LlamaBinarySource for SystemLlamaBinarySource {
    fn resolve_on_path(&self) -> Option<PathBuf> {
        crate::llama_release::resolve_on_path("llama-server")
    }

    fn is_executable(&self, path: &Path) -> bool {
        crate::llama_release::is_executable_file(path)
    }

    async fn fetch_release(
        &self,
        cache_dir: &Path,
        version: &str,
        acceleration: EngineAccel,
        sha256: Option<&str>,
    ) -> Result<PathBuf, String> {
        #[cfg(feature = "weights")]
        {
            crate::llama_release::ensure_llama_server(cache_dir, version, acceleration, sha256)
                .await
        }
        #[cfg(not(feature = "weights"))]
        {
            let _ = (cache_dir, version, acceleration, sha256);
            Err(
                "automatic llama.cpp release acquisition requires the model-host weights feature"
                    .to_string(),
            )
        }
    }

    async fn build_cuda(
        &self,
        cache_dir: &Path,
        tag: &str,
        source_sha256: &str,
    ) -> Result<PathBuf, String> {
        let plan = crate::CudaBuildPlan::official(cache_dir, tag, source_sha256)
            .map_err(|error| error.to_string())?;
        crate::CudaLlamaBuilder::default()
            .build(&plan, &crate::CudaBuildPrerequisites::detect_system())
            .await
            .map_err(|error| error.to_string())
    }
}

/// Managed llama.cpp lifecycle driver.
#[derive(Clone)]
pub struct LlamaCppDriver {
    runner: EngineProcessRunner,
    binaries: Arc<dyn LlamaBinarySource>,
}

impl std::fmt::Debug for LlamaCppDriver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LlamaCppDriver")
            .field("runner", &self.runner)
            .finish_non_exhaustive()
    }
}

impl LlamaCppDriver {
    /// Construct a driver with explicit process and binary boundaries.
    pub fn new(runner: EngineProcessRunner, binaries: Arc<dyn LlamaBinarySource>) -> Self {
        Self { runner, binaries }
    }

    fn acquisition_plan(
        &self,
        provisioning: &EngineProvisioning,
        worker: &WorkerProfile,
    ) -> BinaryAcquirePlan {
        let on_path = self
            .binaries
            .resolve_on_path()
            .filter(|path| self.binaries.is_executable(path));
        let mut cuda = self.binaries.cuda_prerequisites();
        cuda.nvidia_gpu &= worker.accelerator == AcceleratorKind::Cuda;
        crate::plan_binary_acquire_with_cuda(
            EngineKind::LlamaCpp,
            Some(provisioning),
            on_path,
            Some(&cuda),
        )
    }

    fn incompatible_detection(reason: impl Into<String>) -> EngineDetection {
        EngineDetection {
            kind: EngineKind::LlamaCpp,
            availability: EngineAvailability::Incompatible,
            version: None,
            reason: reason.into(),
            remediation: Some(
                "select a GGUF variant and llama.cpp build compatible with the worker".to_string(),
            ),
        }
    }
}

impl Default for LlamaCppDriver {
    fn default() -> Self {
        Self::new(
            EngineProcessRunner::default(),
            Arc::new(SystemLlamaBinarySource),
        )
    }
}

#[async_trait]
impl EngineDriver for LlamaCppDriver {
    fn kind(&self) -> EngineKind {
        EngineKind::LlamaCpp
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            artifact_formats: vec![ArtifactFormat::Gguf],
            accelerators: vec![
                AcceleratorKind::Cpu,
                AcceleratorKind::Metal,
                AcceleratorKind::Cuda,
            ],
            supports_container: false,
            supports_uv: false,
        }
    }

    fn detect(&self, worker: &WorkerProfile, provisioning: &EngineProvisioning) -> LlamaDetection {
        if !worker.engines.contains(&EngineKind::LlamaCpp) {
            return Self::incompatible_detection(
                "worker capability profile does not permit llama.cpp",
            );
        }
        if provisioning.launch != EngineLaunchMethod::Binary {
            return EngineDetection {
                kind: EngineKind::LlamaCpp,
                availability: EngineAvailability::Blocked,
                version: None,
                reason: format!(
                    "llama.cpp driver does not implement {:?} launch",
                    provisioning.launch
                ),
                remediation: Some("choose binary launch for llama.cpp".to_string()),
            };
        }
        let acceleration = provisioning
            .acquire
            .as_ref()
            .map(|acquire| acquire.accel)
            .unwrap_or_default();
        if !acceleration_matches_worker(acceleration, worker.accelerator) {
            return Self::incompatible_detection(format!(
                "requested {acceleration:?} llama.cpp build is incompatible with {:?} worker",
                worker.accelerator
            ));
        }

        match self.acquisition_plan(provisioning, worker) {
            BinaryAcquirePlan::OnPath(path) | BinaryAcquirePlan::Explicit(path) => {
                if self.binaries.is_executable(&path) {
                    EngineDetection {
                        kind: EngineKind::LlamaCpp,
                        availability: EngineAvailability::Available,
                        version: provisioning
                            .acquire
                            .as_ref()
                            .and_then(|acquire| acquire.version.clone()),
                        reason: format!("executable llama-server found at {}", path.display()),
                        remediation: None,
                    }
                } else {
                    EngineDetection {
                        kind: EngineKind::LlamaCpp,
                        availability: EngineAvailability::Blocked,
                        version: None,
                        reason: format!(
                            "configured llama-server path {} is not executable",
                            path.display()
                        ),
                        remediation: Some(
                            "install an executable llama-server or correct acquire.path"
                                .to_string(),
                        ),
                    }
                }
            }
            BinaryAcquirePlan::FetchRelease { tag, sha256, .. } => {
                let missing_digest = sha256.is_none();
                EngineDetection {
                    kind: EngineKind::LlamaCpp,
                    availability: EngineAvailability::Acquirable,
                    version: Some(tag),
                    reason: if missing_digest {
                        "pinned llama.cpp release is acquirable, but sha256 is not pinned"
                            .to_string()
                    } else {
                        "digest-pinned llama.cpp release is acquirable".to_string()
                    },
                    remediation: missing_digest.then(|| {
                        "pin engines.llama_cpp.acquire.sha256 before stable deployment".to_string()
                    }),
                }
            }
            BinaryAcquirePlan::BuildCuda { tag, source_sha256 } => EngineDetection {
                kind: EngineKind::LlamaCpp,
                availability: EngineAvailability::Acquirable,
                version: Some(tag),
                reason: format!(
                    "digest-pinned CUDA llama.cpp source build is acquirable ({})",
                    &source_sha256[..8]
                ),
                remediation: None,
            },
            BinaryAcquirePlan::Blocked(reason) => EngineDetection {
                kind: EngineKind::LlamaCpp,
                availability: if reason.contains("no prebuilt") {
                    EngineAvailability::Incompatible
                } else {
                    EngineAvailability::Blocked
                },
                version: None,
                reason,
                remediation: Some(
                    "install a compatible llama-server or configure a pinned release".to_string(),
                ),
            },
            BinaryAcquirePlan::ProvisionUvx { .. } => {
                Self::incompatible_detection("uv provisioning cannot produce a llama.cpp binary")
            }
        }
    }

    async fn provision(
        &self,
        request: &ProvisionRequest,
    ) -> Result<LlamaProvisioned, EngineDriverError> {
        if request.artifact.engine != EngineKind::LlamaCpp
            || request.artifact.format != ArtifactFormat::Gguf
        {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineIncompatible,
                "llama.cpp provisioning requires a resolved GGUF artifact",
                "select a GGUF catalog variant compatible with llama.cpp",
                false,
            ));
        }
        let detection = self.detect(&request.worker, &request.provisioning);
        match detection.availability {
            EngineAvailability::Incompatible => {
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    detection.reason,
                    detection.remediation.unwrap_or_else(|| {
                        "select a compatible worker and engine build".to_string()
                    }),
                    false,
                ));
            }
            EngineAvailability::Blocked => {
                return Err(EngineDriverError::blocked(
                    detection.reason,
                    detection
                        .remediation
                        .unwrap_or_else(|| "correct the llama.cpp provisioning policy".to_string()),
                ));
            }
            EngineAvailability::Available | EngineAvailability::Acquirable => {}
        }

        let (executable, version, fingerprint) = match self
            .acquisition_plan(&request.provisioning, &request.worker)
        {
            BinaryAcquirePlan::OnPath(path) => {
                ensure_executable(self.binaries.as_ref(), &path)?;
                (path.clone(), None, format!("path:{}", path.display()))
            }
            BinaryAcquirePlan::Explicit(path) => {
                ensure_executable(self.binaries.as_ref(), &path)?;
                (path.clone(), None, format!("explicit:{}", path.display()))
            }
            BinaryAcquirePlan::FetchRelease { tag, accel, sha256 } => {
                let path = self
                    .binaries
                    .fetch_release(
                        &request.engine_cache_dir,
                        &tag,
                        accel,
                        sha256.as_deref(),
                    )
                    .await
                    .map_err(|error| {
                        EngineDriverError::new(
                            EngineFailureReason::EngineProvisionFailed,
                            format!("provision llama.cpp release {tag}: {error}"),
                            "verify network policy, release pin, digest, and engine cache permissions",
                            true,
                        )
                    })?;
                ensure_executable(self.binaries.as_ref(), &path)?;
                let fingerprint = sha256
                    .map(|digest| format!("sha256:{digest}"))
                    .unwrap_or_else(|| format!("release:{tag}:digest-unpinned"));
                (path, Some(tag), fingerprint)
            }
            BinaryAcquirePlan::BuildCuda { tag, source_sha256 } => {
                let path = self
                    .binaries
                    .build_cuda(&request.engine_cache_dir, &tag, &source_sha256)
                    .await
                    .map_err(|error| {
                        EngineDriverError::new(
                            EngineFailureReason::EngineProvisionFailed,
                            format!("build CUDA llama.cpp {tag}: {error}"),
                            "install nvcc, CMake, a compiler, and tar, then retry the pinned build",
                            true,
                        )
                    })?;
                ensure_executable(self.binaries.as_ref(), &path)?;
                (path, Some(tag), format!("source-sha256:{source_sha256}"))
            }
            BinaryAcquirePlan::Blocked(reason) => {
                return Err(EngineDriverError::blocked(
                    reason,
                    "install a compatible llama-server or configure a pinned release",
                ));
            }
            BinaryAcquirePlan::ProvisionUvx { .. } => {
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    "uv provisioning cannot produce llama.cpp",
                    "choose binary release acquisition for llama.cpp",
                    false,
                ));
            }
        };
        Ok(ProvisionedEngine {
            kind: EngineKind::LlamaCpp,
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
        if provisioned.kind != EngineKind::LlamaCpp {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "llama.cpp driver received a different provisioned engine kind",
                "reconcile and provision the deployment again",
                false,
            ));
        }
        request.validate(EngineKind::LlamaCpp)?;
        let model_path = verified_gguf_path(request)?;
        let mut arguments = vec![
            "--model".to_string(),
            model_path.display().to_string(),
            "--host".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            request.port.to_string(),
            "--ctx-size".to_string(),
            request.fit.seq_len.to_string(),
            "--n-gpu-layers".to_string(),
            if request.accelerator == AcceleratorKind::Cpu {
                "0".to_string()
            } else {
                "999".to_string()
            },
        ];
        if let Some(cache_type) = llama_cache_type(request.kv_quant) {
            arguments.extend([
                "--cache-type-k".to_string(),
                cache_type.to_string(),
                "--cache-type-v".to_string(),
                cache_type.to_string(),
            ]);
        }
        arguments.extend(crate::validate_engine_args(
            EngineKind::LlamaCpp,
            &request.extra_args,
        )?);
        let mut environment = BTreeMap::new();
        if request.accelerator == AcceleratorKind::Cuda && !request.selected_devices.is_empty() {
            environment.insert(
                "CUDA_VISIBLE_DEVICES".to_string(),
                request
                    .selected_devices
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        let process = self
            .runner
            .launch(&EngineCommand {
                executable: provisioned.executable.clone(),
                arguments,
                environment,
                port: request.port,
                health_path: HEALTH_PATH.to_string(),
                ready_timeout: request.ready_timeout,
                stderr_tail_lines: 15,
            })
            .await?;
        Ok(RunningEngine {
            deployment: request.deployment.clone(),
            generation: request.generation,
            kind: EngineKind::LlamaCpp,
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

fn acceleration_matches_worker(acceleration: EngineAccel, worker: AcceleratorKind) -> bool {
    match acceleration {
        EngineAccel::Auto => true,
        EngineAccel::Cpu => worker == AcceleratorKind::Cpu,
        EngineAccel::Metal => worker == AcceleratorKind::Metal,
        EngineAccel::Cuda | EngineAccel::Vulkan => worker == AcceleratorKind::Cuda,
    }
}

fn ensure_executable(source: &dyn LlamaBinarySource, path: &Path) -> Result<(), EngineDriverError> {
    if source.is_executable(path) {
        Ok(())
    } else {
        Err(EngineDriverError::new(
            EngineFailureReason::EngineProvisionFailed,
            format!(
                "provisioned llama-server {} is not executable",
                path.display()
            ),
            "correct file ownership and executable permissions or reprovision the engine",
            false,
        ))
    }
}

fn verified_gguf_path(request: &LaunchRequest) -> Result<&Path, EngineDriverError> {
    let paths = request
        .artifact
        .metadata
        .files
        .iter()
        .filter(|file| file.path.to_ascii_lowercase().ends_with(".gguf"))
        .filter_map(|file| request.artifact.file(&file.path))
        .collect::<Vec<_>>();
    match paths.as_slice() {
        [path] => Ok(path),
        [] => Err(EngineDriverError::artifact_not_ready(
            "verified artifact contains no GGUF file",
        )),
        _ => Err(EngineDriverError::artifact_not_ready(
            "verified artifact must select exactly one GGUF file",
        )),
    }
}

fn llama_cache_type(quant: KvCacheQuant) -> Option<&'static str> {
    match quant {
        KvCacheQuant::Auto | KvCacheQuant::F16 => None,
        KvCacheQuant::Fp8 | KvCacheQuant::Int8 => Some("q8_0"),
        KvCacheQuant::Int4 => Some("q4_0"),
    }
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
