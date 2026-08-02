// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Managed mistral.rs driver over verified safetensors artifacts
//! (WOR-1861).
//!
//! mistral.rs is the second single-binary subprocess engine after
//! llama.cpp: the upstream v0.9 release ships a pinned `mistralrs` CLI
//! per platform, acquired PATH-first with a sha256-verified prebuilt
//! fallback ([`crate::mistralrs_release`]), and driven over its
//! OpenAI-compatible HTTP surface (`mistralrs serve`). Tool calls are
//! native to that surface, so no parser flag is needed.
//!
//! The lane starts safetensors-only: GGUF stays llama.cpp's certified
//! lane (a second argv shape buys nothing until it is certified), and
//! `Auto` never resolves to mistral.rs. Its `/health` endpoint is a
//! plain liveness probe (unlike SGLang's generating `/health`, see
//! `sglang_driver.rs`), so the default probe path is correct here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::{
    AcceleratorKind, ArtifactFormat, BinaryAcquirePlan, EngineAccel, EngineAvailability,
    EngineCapabilities, EngineCommand, EngineDetection, EngineDriver, EngineDriverError,
    EngineFailureReason, EngineHealth, EngineKind, EngineLaunchMethod, EngineProcessRunner,
    EngineProvisioning, LaunchRequest, ProvisionRequest, ProvisionedEngine, RunningEngine,
    WorkerProfile,
};

/// mistral.rs `/health` returns a static 200 without touching the model
/// (verified against the v0.9.0 `mistralrs-server-core` handlers), so
/// the plain probe path is safe under load, unlike SGLang's.
const HEALTH_PATH: &str = "/health";

/// Binary lookup and release acquisition boundary used by the
/// mistral.rs driver. The seam mirrors
/// [`crate::llama_driver::LlamaBinarySource`] so tests can substitute a
/// fixture without network or filesystem access.
#[async_trait]
pub trait MistralRsBinarySource: Send + Sync {
    /// Resolve an operator-installed `mistralrs` from `PATH`.
    fn resolve_on_path(&self) -> Option<PathBuf>;

    /// Whether a resolved path names an executable regular file.
    fn is_executable(&self, path: &Path) -> bool;

    /// Acquire one pinned mistral.rs release asset into `cache_dir`.
    async fn fetch_release(
        &self,
        cache_dir: &Path,
        tag: &str,
        asset: &str,
        sha256: Option<&str>,
    ) -> Result<PathBuf, String>;
}

/// Production mistral.rs binary source.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemMistralRsBinarySource;

#[async_trait]
impl MistralRsBinarySource for SystemMistralRsBinarySource {
    fn resolve_on_path(&self) -> Option<PathBuf> {
        crate::llama_release::resolve_on_path("mistralrs")
    }

    fn is_executable(&self, path: &Path) -> bool {
        crate::llama_release::is_executable_file(path)
    }

    async fn fetch_release(
        &self,
        cache_dir: &Path,
        tag: &str,
        asset: &str,
        sha256: Option<&str>,
    ) -> Result<PathBuf, String> {
        #[cfg(feature = "weights")]
        {
            crate::mistralrs_release::ensure_mistralrs_binary(cache_dir, tag, asset, sha256).await
        }
        #[cfg(not(feature = "weights"))]
        {
            let _ = (cache_dir, tag, asset, sha256);
            Err(
                "automatic mistral.rs release acquisition requires the model-host weights feature"
                    .to_string(),
            )
        }
    }
}

/// Managed mistral.rs lifecycle driver.
#[derive(Clone)]
pub struct MistralRsDriver {
    runner: EngineProcessRunner,
    binaries: Arc<dyn MistralRsBinarySource>,
}

impl std::fmt::Debug for MistralRsDriver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MistralRsDriver")
            .field("runner", &self.runner)
            .finish_non_exhaustive()
    }
}

impl MistralRsDriver {
    /// Construct a driver with explicit process and binary boundaries.
    pub fn new(runner: EngineProcessRunner, binaries: Arc<dyn MistralRsBinarySource>) -> Self {
        Self { runner, binaries }
    }

    fn acquisition_plan(&self, provisioning: &EngineProvisioning) -> BinaryAcquirePlan {
        let on_path = self
            .binaries
            .resolve_on_path()
            .filter(|path| self.binaries.is_executable(path));
        // mistral.rs never source-builds here, so CUDA prerequisites are
        // irrelevant to the plan.
        crate::plan_binary_acquire_with_cuda(
            EngineKind::MistralRs,
            Some(provisioning),
            on_path,
            None,
        )
    }

    /// Resolve the concrete release asset for this worker: the accel
    /// flavour comes from the acquire block and the CUDA compute
    /// capability from the probed worker profile.
    fn release_asset(
        provisioning: &EngineProvisioning,
        worker: &WorkerProfile,
    ) -> Result<String, String> {
        let platform = crate::llama_release::Platform::detect().ok_or_else(|| {
            format!(
                "no prebuilt mistral.rs release for {}/{}; install mistralrs on PATH",
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        })?;
        let accel = provisioning
            .acquire
            .as_ref()
            .map(|acquire| acquire.accel)
            .unwrap_or_default();
        let capability = match worker.accelerator {
            AcceleratorKind::Cuda => worker
                .compute_capability
                .map(|capability| (capability.major, capability.minor)),
            _ => None,
        };
        crate::mistralrs_release::release_asset(platform, accel, capability)
    }

    fn incompatible_detection(reason: impl Into<String>) -> EngineDetection {
        EngineDetection {
            kind: EngineKind::MistralRs,
            availability: EngineAvailability::Incompatible,
            version: None,
            reason: reason.into(),
            remediation: Some(
                "select a safetensors variant and mistral.rs build compatible with the worker"
                    .to_string(),
            ),
        }
    }
}

impl Default for MistralRsDriver {
    fn default() -> Self {
        Self::new(
            EngineProcessRunner::default(),
            Arc::new(SystemMistralRsBinarySource),
        )
    }
}

#[async_trait]
impl EngineDriver for MistralRsDriver {
    fn kind(&self) -> EngineKind {
        EngineKind::MistralRs
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            artifact_formats: vec![ArtifactFormat::Safetensors],
            accelerators: vec![
                AcceleratorKind::Cpu,
                AcceleratorKind::Metal,
                AcceleratorKind::Cuda,
            ],
            supports_container: false,
            supports_uv: false,
        }
    }

    fn detect(&self, worker: &WorkerProfile, provisioning: &EngineProvisioning) -> EngineDetection {
        if !worker.engines.contains(&EngineKind::MistralRs) {
            return Self::incompatible_detection(
                "worker capability profile does not permit mistral.rs",
            );
        }
        if provisioning.launch != EngineLaunchMethod::Binary {
            return EngineDetection {
                kind: EngineKind::MistralRs,
                availability: EngineAvailability::Blocked,
                version: None,
                reason: format!(
                    "mistral.rs driver does not implement {:?} launch",
                    provisioning.launch
                ),
                remediation: Some("choose binary launch for mistralrs".to_string()),
            };
        }
        let acceleration = provisioning
            .acquire
            .as_ref()
            .map(|acquire| acquire.accel)
            .unwrap_or_default();
        if !acceleration_matches_worker(acceleration, worker.accelerator) {
            return Self::incompatible_detection(format!(
                "requested {acceleration:?} mistral.rs build is incompatible with {:?} worker",
                worker.accelerator
            ));
        }

        match self.acquisition_plan(provisioning) {
            BinaryAcquirePlan::OnPath(path) | BinaryAcquirePlan::Explicit(path) => {
                if self.binaries.is_executable(&path) {
                    EngineDetection {
                        kind: EngineKind::MistralRs,
                        availability: EngineAvailability::Available,
                        version: provisioning
                            .acquire
                            .as_ref()
                            .and_then(|acquire| acquire.version.clone()),
                        reason: format!("executable mistralrs found at {}", path.display()),
                        remediation: None,
                    }
                } else {
                    EngineDetection {
                        kind: EngineKind::MistralRs,
                        availability: EngineAvailability::Blocked,
                        version: None,
                        reason: format!(
                            "configured mistralrs path {} is not executable",
                            path.display()
                        ),
                        remediation: Some(
                            "install an executable mistralrs or correct acquire.path".to_string(),
                        ),
                    }
                }
            }
            BinaryAcquirePlan::FetchRelease { tag, sha256, .. } => {
                // The asset (and its built-in digest) depends on the
                // worker, so resolve it here rather than at plan time.
                match Self::release_asset(provisioning, worker) {
                    Ok(asset) => {
                        let digest = sha256.or_else(|| {
                            crate::mistralrs_release::default_release_sha256(&tag, &asset)
                                .map(str::to_string)
                        });
                        let missing_digest = digest.is_none();
                        EngineDetection {
                            kind: EngineKind::MistralRs,
                            availability: EngineAvailability::Acquirable,
                            version: Some(tag),
                            reason: if missing_digest {
                                format!(
                                    "pinned mistral.rs release asset {asset} is acquirable, but \
                                     sha256 is not pinned"
                                )
                            } else {
                                format!(
                                    "digest-pinned mistral.rs release asset {asset} is acquirable"
                                )
                            },
                            remediation: missing_digest.then(|| {
                                "pin engines.mistralrs.acquire.sha256 before stable deployment"
                                    .to_string()
                            }),
                        }
                    }
                    Err(reason) => EngineDetection {
                        kind: EngineKind::MistralRs,
                        availability: EngineAvailability::Incompatible,
                        version: None,
                        reason,
                        remediation: Some(
                            "install a compatible mistralrs on PATH or configure acquire.path"
                                .to_string(),
                        ),
                    },
                }
            }
            BinaryAcquirePlan::Blocked(reason) => EngineDetection {
                kind: EngineKind::MistralRs,
                availability: if reason.contains("no prebuilt") {
                    EngineAvailability::Incompatible
                } else {
                    EngineAvailability::Blocked
                },
                version: None,
                reason,
                remediation: Some(
                    "install a compatible mistralrs or configure a pinned release".to_string(),
                ),
            },
            BinaryAcquirePlan::BuildCuda { .. } => Self::incompatible_detection(
                "mistral.rs has no source-build path; use the prebuilt release",
            ),
            BinaryAcquirePlan::ProvisionUvx { .. } => {
                Self::incompatible_detection("uv provisioning cannot produce a mistralrs binary")
            }
        }
    }

    async fn provision(
        &self,
        request: &ProvisionRequest,
    ) -> Result<ProvisionedEngine, EngineDriverError> {
        if request.artifact.engine != EngineKind::MistralRs
            || request.artifact.format != ArtifactFormat::Safetensors
        {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineIncompatible,
                "mistral.rs provisioning requires a resolved safetensors artifact",
                "select a safetensors catalog variant compatible with mistral.rs",
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
                        .unwrap_or_else(|| "correct the mistralrs provisioning policy".to_string()),
                ));
            }
            EngineAvailability::Available | EngineAvailability::Acquirable => {}
        }

        let (executable, version, fingerprint) =
            match self.acquisition_plan(&request.provisioning) {
                BinaryAcquirePlan::OnPath(path) => {
                    ensure_executable(self.binaries.as_ref(), &path)?;
                    (path.clone(), None, format!("path:{}", path.display()))
                }
                BinaryAcquirePlan::Explicit(path) => {
                    ensure_executable(self.binaries.as_ref(), &path)?;
                    (path.clone(), None, format!("explicit:{}", path.display()))
                }
                BinaryAcquirePlan::FetchRelease { tag, sha256, .. } => {
                    let asset = Self::release_asset(&request.provisioning, &request.worker)
                        .map_err(|reason| {
                            EngineDriverError::new(
                                EngineFailureReason::EngineIncompatible,
                                reason,
                                "install a compatible mistralrs on PATH or configure acquire.path",
                                false,
                            )
                        })?;
                    let sha256 = sha256.or_else(|| {
                        crate::mistralrs_release::default_release_sha256(&tag, &asset)
                            .map(str::to_string)
                    });
                    let path = self
                        .binaries
                        .fetch_release(&request.engine_cache_dir, &tag, &asset, sha256.as_deref())
                        .await
                        .map_err(|error| {
                            EngineDriverError::new(
                                EngineFailureReason::EngineProvisionFailed,
                                format!("provision mistral.rs release {tag} ({asset}): {error}"),
                                "verify network policy, release pin, digest, and engine cache \
                                 permissions",
                                true,
                            )
                        })?;
                    ensure_executable(self.binaries.as_ref(), &path)?;
                    let fingerprint = sha256
                        .map(|digest| format!("sha256:{digest}"))
                        .unwrap_or_else(|| format!("release:{tag}:digest-unpinned"));
                    (path, Some(tag), fingerprint)
                }
                BinaryAcquirePlan::Blocked(reason) => {
                    return Err(EngineDriverError::blocked(
                        reason,
                        "install a compatible mistralrs or configure a pinned release",
                    ));
                }
                BinaryAcquirePlan::BuildCuda { .. } | BinaryAcquirePlan::ProvisionUvx { .. } => {
                    return Err(EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    "mistral.rs acquires only PATH, explicit-path, or prebuilt-release binaries",
                    "choose binary release acquisition for mistralrs",
                    false,
                ));
                }
            };
        Ok(ProvisionedEngine {
            kind: EngineKind::MistralRs,
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
        if provisioned.kind != EngineKind::MistralRs {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "mistral.rs driver received a different provisioned engine kind",
                "reconcile and provision the deployment again",
                false,
            ));
        }
        request.validate(EngineKind::MistralRs)?;
        // The runtime owns the serving identity and capacity: model
        // path, loopback bind, port, sequence length, and concurrency.
        // `--no-ui` keeps the subprocess an API server (no web UI on the
        // loopback port). The operator allowlist is appended last.
        let mut arguments = vec![
            "serve".to_string(),
            "-m".to_string(),
            request.artifact.snapshot_path.display().to_string(),
            "--host".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            request.port.to_string(),
            "--no-ui".to_string(),
            "--max-seq-len".to_string(),
            request.fit.seq_len.to_string(),
            "--max-seqs".to_string(),
            request.max_concurrency.to_string(),
        ];
        if request.accelerator == AcceleratorKind::Cpu {
            arguments.push("--cpu".to_string());
        }
        arguments.extend(crate::validate_engine_args(
            EngineKind::MistralRs,
            &request.extra_args,
        )?);
        let mut environment = BTreeMap::new();
        if request.accelerator == AcceleratorKind::Cuda {
            if !request.selected_devices.is_empty() {
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
            // v0.9 defaults the FlashInfer decode kernel on for CUDA, and
            // it fails live on GQA shapes (measured on an L4 with
            // Qwen2.5-0.5B, qo_heads=14 kv_heads=2: "flashinfer_decode
            // failed with status 999" on the first decode step). Pin the
            // certified fallback decode path; revisit when upstream
            // stabilises FlashInfer.
            environment.insert("MISTRALRS_FLASHINFER_DECODE".to_string(), "0".to_string());
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
            kind: EngineKind::MistralRs,
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

fn acceleration_matches_worker(acceleration: EngineAccel, worker: AcceleratorKind) -> bool {
    match acceleration {
        EngineAccel::Auto => true,
        EngineAccel::Cpu => worker == AcceleratorKind::Cpu,
        EngineAccel::Metal => worker == AcceleratorKind::Metal,
        EngineAccel::Cuda => worker == AcceleratorKind::Cuda,
        // Upstream publishes no Vulkan asset; llama.cpp owns that lane.
        EngineAccel::Vulkan => false,
    }
}

fn ensure_executable(
    source: &dyn MistralRsBinarySource,
    path: &Path,
) -> Result<(), EngineDriverError> {
    if source.is_executable(path) {
        Ok(())
    } else {
        Err(EngineDriverError::new(
            EngineFailureReason::EngineProvisionFailed,
            format!("provisioned mistralrs {} is not executable", path.display()),
            "correct file ownership and executable permissions or reprovision the engine",
            false,
        ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_path_is_the_plain_liveness_probe() {
        // mistral.rs `/health` is static liveness (no generation), so
        // the default probe path is correct; this pin is deliberate,
        // contrast sglang_driver's `/get_model_info`.
        assert_eq!(HEALTH_PATH, "/health");
    }

    #[test]
    fn vulkan_never_matches_a_worker() {
        assert!(!acceleration_matches_worker(
            EngineAccel::Vulkan,
            AcceleratorKind::Cuda
        ));
        assert!(acceleration_matches_worker(
            EngineAccel::Auto,
            AcceleratorKind::Cpu
        ));
        assert!(acceleration_matches_worker(
            EngineAccel::Cuda,
            AcceleratorKind::Cuda
        ));
    }
}
