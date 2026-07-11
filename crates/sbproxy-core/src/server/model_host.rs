// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Process-global managed local model runtime (WOR-1680, WOR-1841).
//!
//! When any `ai_proxy` provider carries a `serve:` block, the gateway
//! itself hosts those models: it spawns and supervises an inference
//! engine and routes requests to its loopback port. The
//! [`ProductionModelRuntime`] owns the permanent process-wide handle.
//! Complete desired revisions prepare before publication, so an invalid
//! reload preserves both the prior pipeline and the prior resident engines.
//!
//! [`managed_upstream`] is the request-path entry point for canonical
//! `managed_model` providers and compatibility `serve:` blocks.
//!
//! The GPU probe is feature-selected: with `gpu-nvidia` it is the real
//! NVML probe; without it a zero-GPU probe, so on a CPU-only build a
//! `serve:` provider fails admission with a clear residency error
//! rather than pretending to serve.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use sbproxy_ai::local_host::pick_local_model_name;
use sbproxy_ai::AiHandlerConfig;
use sbproxy_model_host::{
    ArtifactManager, ArtifactTransport, Catalog, ConfigDirMetadataProvider, GpuProbe,
    ModelHostConfig,
};

/// Permanent process-wide managed-model runtime adapter.
///
/// The outer handle never changes, including when the process starts with an
/// empty config. Its active worker-local manager may be replaced only when an
/// immutable runtime foundation, such as the catalog revision or cache root,
/// changes. Ordinary desired-state reloads reconcile in place and preserve
/// unaffected engine generations.
pub struct ProductionModelRuntime {
    active: ArcSwap<sbproxy_model_host::ModelRuntimeManager>,
    foundation: RwLock<Option<RuntimeFoundation>>,
    epoch: AtomicU64,
    commit_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for ProductionModelRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionModelRuntime")
            .field("epoch", &self.epoch.load(Ordering::SeqCst))
            .field(
                "foundation",
                &self
                    .foundation
                    .read()
                    .expect("model runtime foundation lock")
                    .clone(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeFoundation {
    catalog_revision: String,
    cache_root: PathBuf,
}

/// A complete model-runtime candidate prepared without changing live routes.
pub struct PreparedModelRuntime {
    owner: Arc<ProductionModelRuntime>,
    manager: Arc<sbproxy_model_host::ModelRuntimeManager>,
    prepared: sbproxy_model_host::PreparedRevision,
    base_epoch: u64,
    foundation: Option<RuntimeFoundation>,
    replace_manager: bool,
}

impl std::fmt::Debug for PreparedModelRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedModelRuntime")
            .field("prepared", &self.prepared)
            .field("base_epoch", &self.base_epoch)
            .field("foundation", &self.foundation)
            .field("replace_manager", &self.replace_manager)
            .finish_non_exhaustive()
    }
}

/// Admission permit bound to the exact manager revision that resolved a route.
///
/// Keeping this value in the request context holds deployment capacity through
/// the complete response stream. Dropping it releases capacity.
pub struct ManagedModelPermit {
    manager: Arc<sbproxy_model_host::ModelRuntimeManager>,
    deployment: String,
    admission: sbproxy_model_host::DeploymentAdmissionPermit,
}

impl std::fmt::Debug for ManagedModelPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedModelPermit")
            .field("deployment", &self.deployment)
            .finish_non_exhaustive()
    }
}

impl ManagedModelPermit {
    /// Canonical deployment held by this request.
    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    async fn ensure_ready(
        &self,
        priority: sbproxy_model_host::PriorityClass,
    ) -> Result<sbproxy_model_host::RunningEngine, sbproxy_model_host::RuntimeManagerError> {
        self.manager
            .ensure_ready_for_generation(
                &self.deployment,
                self.admission.generation(),
                self.admission.start_epoch(),
                priority,
            )
            .await
    }
}

struct EmptyDeploymentPreparer;

#[async_trait]
impl sbproxy_model_host::DeploymentPreparer for EmptyDeploymentPreparer {
    async fn prepare(
        &self,
        _request: sbproxy_model_host::DeploymentPrepareRequest,
    ) -> Result<
        Arc<dyn sbproxy_model_host::PreparedDeploymentRuntime>,
        sbproxy_model_host::RuntimeManagerError,
    > {
        Err(sbproxy_model_host::RuntimeManagerError::Prepare(
            "empty model runtime cannot prepare a deployment".to_string(),
        ))
    }
}

static MODEL_RUNTIME: OnceLock<Arc<ProductionModelRuntime>> = OnceLock::new();

fn load_catalog_from_dir(
    config: &ModelHostConfig,
    config_dir: &Path,
) -> Result<Arc<Catalog>, String> {
    let Some(configured) = config.catalog_file.as_deref() else {
        return Ok(Arc::new(Catalog::builtin()));
    };
    let configured = PathBuf::from(configured);
    let path = if configured.is_absolute() {
        configured
    } else {
        config_dir.join(configured)
    };
    let yaml = std::fs::read_to_string(&path)
        .map_err(|error| format!("read model catalog '{}': {error}", path.display()))?;
    let loaded = Catalog::from_yaml_with_diagnostics(&yaml)
        .map_err(|error| format!("load model catalog '{}': {error}", path.display()))?;
    for diagnostic in loaded.diagnostics {
        tracing::warn!(catalog = %path.display(), %diagnostic, "model catalog migration finding");
    }
    Ok(Arc::new(loaded.catalog))
}

fn artifact_transport() -> Result<Arc<dyn ArtifactTransport>, String> {
    #[cfg(feature = "model-weights")]
    {
        sbproxy_model_host::HttpArtifactTransport::new()
            .map(|transport| Arc::new(transport) as Arc<dyn ArtifactTransport>)
            .map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "model-weights"))]
    {
        Ok(Arc::new(sbproxy_model_host::UnavailableArtifactTransport))
    }
}

/// Records the model-host lifecycle into the `sbproxy_model_host_*`
/// metrics (WOR-1659). The model-host crate stays observe-free and
/// calls this seam; here we forward to the observe recording fns that
/// the Grafana dashboard (WOR-1664) and value report (WOR-1665) consume.
struct MetricsObserver;

impl sbproxy_model_host::ModelHostObserver for MetricsObserver {
    fn on_engine_ready(&self, engine: &str, model: &str, secs: f64) {
        sbproxy_observe::metrics::record_model_host_time_to_ready(engine, model, "ready", secs);
    }
    fn on_engine_failed(&self, engine: &str, model: &str, secs: f64) {
        sbproxy_observe::metrics::record_model_host_time_to_ready(engine, model, "failed", secs);
    }
    fn on_eviction(&self, reason: &'static str) {
        sbproxy_observe::metrics::record_model_host_eviction(reason);
    }
    fn set_resident_models(&self, count: i64) {
        sbproxy_observe::metrics::set_model_host_resident_models(count);
    }
    fn set_gpu_stats(
        &self,
        device: &str,
        total_bytes: u64,
        free_bytes: u64,
        compute_utilization: Option<f64>,
        memory_occupancy: Option<f64>,
    ) {
        sbproxy_observe::metrics::set_model_host_gpu_stats(
            device,
            i64::try_from(total_bytes).unwrap_or(i64::MAX),
            i64::try_from(free_bytes).unwrap_or(i64::MAX),
            compute_utilization,
            memory_occupancy,
        );
    }
    fn on_adapter_loaded(&self, _base: &str, _adapter: &str) {
        sbproxy_observe::metrics::record_model_host_lora_load();
    }
    fn on_adapter_evicted(&self, _base: &str, _adapter: &str) {
        sbproxy_observe::metrics::record_model_host_lora_eviction();
    }
    fn set_resident_adapters(&self, count: i64) {
        sbproxy_observe::metrics::set_model_host_resident_adapters(count);
    }
    fn on_ensure_failed(&self, _model: &str, reason: &'static str) {
        sbproxy_observe::metrics::record_model_host_ensure_failure(reason);
    }
    fn on_weight_download(&self, _model: &str, bytes: u64, secs: f64, ok: bool) {
        sbproxy_observe::metrics::record_model_host_weight_download(bytes, secs, ok);
    }
    fn set_deployment_requests(&self, deployment: &str, active: usize, queued: usize) {
        sbproxy_observe::metrics::set_model_host_deployment_requests(
            deployment,
            i64::try_from(active).unwrap_or(i64::MAX),
            i64::try_from(queued).unwrap_or(i64::MAX),
        );
    }
    fn set_deployment_state(
        &self,
        deployment: &str,
        engine: Option<sbproxy_model_host::EngineKind>,
        state: sbproxy_model_host::DeploymentRuntimeState,
    ) {
        let engine = match engine {
            Some(sbproxy_model_host::EngineKind::Vllm) => "vllm",
            Some(sbproxy_model_host::EngineKind::LlamaCpp) => "llama_cpp",
            Some(sbproxy_model_host::EngineKind::Embedded) => "embedded",
            None => "unknown",
        };
        sbproxy_observe::metrics::set_model_host_deployment_state(
            deployment,
            engine,
            state.as_str(),
        );
    }
    fn on_admission_rejected(
        &self,
        deployment: &str,
        priority: sbproxy_model_host::PriorityClass,
        reason: sbproxy_model_host::AdmissionReason,
    ) {
        sbproxy_observe::metrics::record_model_host_admission_rejection(
            deployment,
            priority.as_str(),
            reason.as_str(),
        );
    }
}

/// The GPU probe for the runtime. Also used by [`crate::doctor`] so the
/// diagnostics report the same devices the admission path will see.
///
/// The probe is layered so one binary adapts to any host (WOR-1800):
/// NVIDIA discrete GPUs first (when the `gpu-nvidia` feature is
/// compiled and NVML sees cards), then Apple Silicon unified memory
/// (`gpu-apple` on macOS), then a CPU / system-RAM budget as the
/// universal fallback. The CPU budget means a `serve:` provider admits
/// small models on a Mac or a GPU-less server instead of rejecting
/// everything; set `SBPROXY_CPU_MEMORY_FRACTION=0` to opt back into
/// hard rejection.
pub(crate) fn make_probe() -> Arc<dyn GpuProbe> {
    #[cfg(feature = "gpu-nvidia")]
    {
        let nvml = sbproxy_model_host::NvmlGpuProbe::new();
        if !nvml.probe().is_empty() {
            return Arc::new(nvml);
        }
    }
    #[cfg(all(target_os = "macos", feature = "gpu-apple"))]
    {
        let metal = sbproxy_model_host::MetalGpuProbe::new();
        if !metal.probe().is_empty() {
            return Arc::new(metal);
        }
    }
    // Universal fallback: a fraction of system RAM as the serving
    // budget. Reports no device (so admission still rejects) when RAM
    // cannot be read or the operator set the fraction to 0.
    Arc::new(sbproxy_model_host::CpuProbe::from_system())
}

fn build_model_maintenance_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

impl ProductionModelRuntime {
    fn empty() -> Result<Self, sbproxy_model_host::RuntimeManagerError> {
        let catalog = Catalog::builtin();
        let manager = sbproxy_model_host::ModelRuntimeManager::new(
            catalog.catalog_revision,
            Arc::new(EmptyDeploymentPreparer),
        )?
        .with_observer(Arc::new(MetricsObserver));
        Ok(Self {
            active: ArcSwap::from_pointee(manager),
            foundation: RwLock::new(None),
            epoch: AtomicU64::new(0),
            commit_lock: tokio::sync::Mutex::new(()),
        })
    }

    fn active_manager(&self) -> Arc<sbproxy_model_host::ModelRuntimeManager> {
        self.active.load_full()
    }

    fn start_maintenance(runtime: &Arc<Self>) {
        let weak = Arc::downgrade(runtime);
        if let Err(error) = std::thread::Builder::new()
            .name("sbproxy-model-maintenance".to_string())
            .spawn(move || {
                let executor = match build_model_maintenance_runtime() {
                    Ok(executor) => executor,
                    Err(error) => {
                        tracing::error!(%error, "failed to build model maintenance runtime");
                        return;
                    }
                };
                executor.block_on(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                    loop {
                        interval.tick().await;
                        let Some(runtime) = weak.upgrade() else {
                            break;
                        };
                        let stopped = runtime
                            .active_manager()
                            .maintenance_tick(tokio::time::Instant::now())
                            .await;
                        for deployment in stopped {
                            tracing::info!(%deployment, "managed model keep-alive elapsed");
                        }
                    }
                });
            })
        {
            tracing::error!(%error, "failed to spawn model maintenance thread");
        }
    }

    /// Current process-local desired-state revision.
    pub fn current_revision(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Current atomic managed-model desired state.
    pub fn current_desired(&self) -> Arc<sbproxy_model_host::RuntimeDesiredState> {
        self.active_manager().current_desired()
    }

    /// Snapshot every configured deployment in deterministic ID order.
    pub async fn statuses(&self) -> Vec<sbproxy_model_host::DeploymentRuntimeStatus> {
        self.active_manager().statuses().await
    }

    /// Snapshot one configured deployment.
    pub async fn status(
        &self,
        deployment: &str,
    ) -> Option<sbproxy_model_host::DeploymentRuntimeStatus> {
        self.active_manager().status(deployment).await
    }

    /// Bring one configured deployment to ready.
    pub async fn ensure_ready(
        &self,
        deployment: &str,
    ) -> Result<sbproxy_model_host::RunningEngine, sbproxy_model_host::RuntimeManagerError> {
        self.active_manager().ensure_ready(deployment).await
    }

    /// Acquire request capacity from the current deployment generation.
    pub async fn admit_request(
        &self,
        deployment: &str,
        priority: sbproxy_model_host::PriorityClass,
    ) -> Result<ManagedModelPermit, sbproxy_model_host::AdmissionRejection> {
        let manager = self.active_manager();
        let admission = manager.admit(deployment, priority).await?;
        Ok(ManagedModelPermit {
            manager,
            deployment: deployment.to_string(),
            admission,
        })
    }

    /// Drain and stop one configured deployment within its configured deadline.
    pub async fn drain(
        &self,
        deployment: &str,
    ) -> Result<sbproxy_model_host::DrainReport, sbproxy_model_host::RuntimeManagerError> {
        self.active_manager().drain(deployment).await
    }

    /// Clear retained crash-loop state for one configured deployment.
    pub async fn reset(
        &self,
        deployment: &str,
    ) -> Result<Option<sbproxy_model_host::OperationJob>, sbproxy_model_host::RuntimeManagerError>
    {
        self.active_manager().reset(deployment).await
    }

    /// Drain and stop every configured deployment before process exit.
    pub async fn shutdown(&self) -> BTreeMap<String, String> {
        let manager = self.active_manager();
        let deployments = manager
            .statuses()
            .await
            .into_iter()
            .map(|status| status.deployment)
            .collect::<Vec<_>>();
        let mut failures = BTreeMap::new();
        for deployment in deployments {
            match manager.drain(&deployment).await {
                Ok(report) if report.timed_out => {
                    failures.insert(
                        deployment,
                        format!(
                            "drain deadline elapsed with {} active requests",
                            report.remaining_active
                        ),
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    failures.insert(deployment, error.to_string());
                }
            }
        }
        failures
    }

    async fn prepare(
        self: &Arc<Self>,
        pipeline: &crate::pipeline::CompiledPipeline,
        config_dir: &Path,
    ) -> anyhow::Result<PreparedModelRuntime> {
        let candidate = compile_runtime_candidate(pipeline, config_dir)?;
        self.prepare_candidate(candidate).await
    }

    async fn prepare_candidate(
        self: &Arc<Self>,
        candidate: RuntimeCandidate,
    ) -> anyhow::Result<PreparedModelRuntime> {
        let base_epoch = self.epoch.load(Ordering::SeqCst);
        let current_foundation = self
            .foundation
            .read()
            .expect("model runtime foundation lock")
            .clone();
        let active_manager = self.active_manager();

        let needs_production_manager = !candidate.desired.deployments.is_empty()
            || candidate.desired.control.authority
                == sbproxy_config::ModelHostAuthority::AdminManaged;
        let (manager, foundation) = if !needs_production_manager {
            (active_manager.clone(), current_foundation)
        } else {
            let foundation = RuntimeFoundation {
                catalog_revision: candidate.catalog.catalog_revision.clone(),
                cache_root: candidate.cache_root.clone(),
            };
            if current_foundation.as_ref() == Some(&foundation) {
                (active_manager.clone(), Some(foundation))
            } else {
                if !active_manager.current_desired().deployments.is_empty() {
                    anyhow::bail!(
                        "model runtime catalog or cache foundation changed while deployments are configured; reload an empty model_host revision first so the prior engines drain before replacing the foundation"
                    );
                }
                (
                    build_production_manager(
                        candidate.catalog.clone(),
                        candidate.cache_root.clone(),
                    )?,
                    Some(foundation),
                )
            }
        };
        let replace_manager = !Arc::ptr_eq(&manager, &active_manager);
        let prepared = manager.prepare_revision(candidate.desired).await?;
        Ok(PreparedModelRuntime {
            owner: Arc::clone(self),
            manager,
            prepared,
            base_epoch,
            foundation,
            replace_manager,
        })
    }

    async fn commit(
        &self,
        candidate: PreparedModelRuntime,
    ) -> Result<sbproxy_model_host::ReconcileReport, sbproxy_model_host::RuntimeManagerError> {
        let _guard = self.commit_lock.lock().await;
        let current_epoch = self.epoch.load(Ordering::SeqCst);
        if candidate.base_epoch != current_epoch {
            candidate.manager.abort_prepared(candidate.prepared).await;
            return Err(sbproxy_model_host::RuntimeManagerError::StalePrepared {
                based_on: candidate.base_epoch,
                current: current_epoch,
            });
        }
        let next_epoch = current_epoch
            .checked_add(1)
            .ok_or(sbproxy_model_host::RuntimeManagerError::CounterOverflow)?;
        let report = candidate
            .manager
            .commit_revision(candidate.prepared)
            .await?;
        if candidate.replace_manager {
            self.active.store(candidate.manager);
        }
        *self
            .foundation
            .write()
            .expect("model runtime foundation lock") = candidate.foundation;
        self.epoch.store(next_epoch, Ordering::SeqCst);
        Ok(report)
    }
}

struct RuntimeCandidate {
    desired: sbproxy_model_host::RuntimeDesiredState,
    catalog: Arc<Catalog>,
    cache_root: PathBuf,
}

fn compile_runtime_candidate(
    pipeline: &crate::pipeline::CompiledPipeline,
    config_dir: &Path,
) -> anyhow::Result<RuntimeCandidate> {
    let mut managed_providers = Vec::new();
    let mut legacy_providers = Vec::new();
    for (origin, action) in pipeline.config.origins.iter().zip(&pipeline.actions) {
        let sbproxy_modules::Action::AiProxy(ai) = action else {
            continue;
        };
        for provider in &ai.config.providers {
            if provider.is_managed_model() {
                managed_providers.push(sbproxy_model_host::ManagedProviderInput {
                    origin: origin.origin_id.to_string(),
                    provider: provider.name.as_str().to_string(),
                    deployment: provider
                        .deployment
                        .clone()
                        .expect("managed provider shape validated during action compilation"),
                    models: provider
                        .models
                        .iter()
                        .map(|model| model.as_str().to_string())
                        .collect(),
                });
            }
            if let Some(config) = &provider.serve {
                legacy_providers.push(sbproxy_model_host::LegacyServeInput {
                    origin: origin.origin_id.to_string(),
                    provider: provider.name.as_str().to_string(),
                    config: config.clone(),
                });
            }
        }
    }

    let catalog = match legacy_providers.first() {
        Some(legacy) => {
            load_catalog_from_dir(&legacy.config, config_dir).map_err(anyhow::Error::msg)?
        }
        None => Arc::new(Catalog::builtin()),
    };
    let desired = sbproxy_model_host::compile_desired_state(
        sbproxy_model_host::RuntimeDesiredInput {
            source_revision: pipeline.config_revision.clone(),
            canonical: pipeline.config.server.model_host.clone(),
            managed_providers,
            legacy_providers,
        },
        &catalog,
    )?;
    let configured_cache = desired.control.cache.directory.as_deref().or_else(|| {
        desired
            .legacy_host_policy
            .as_ref()
            .and_then(|policy| policy.cache_dir.as_deref())
    });
    let cache_root = sbproxy_model_host::resolve_cache_dir_default(configured_cache);
    Ok(RuntimeCandidate {
        desired,
        catalog,
        cache_root,
    })
}

/// Run the side-effect-free managed-model checks shared by validate and boot.
pub fn validate_model_runtime(
    pipeline: &crate::pipeline::CompiledPipeline,
    config_dir: &Path,
) -> anyhow::Result<()> {
    compile_runtime_candidate(pipeline, config_dir).map(|_| ())
}

fn build_production_manager(
    catalog: Arc<Catalog>,
    cache_root: PathBuf,
) -> anyhow::Result<Arc<sbproxy_model_host::ModelRuntimeManager>> {
    let transport = artifact_transport().map_err(anyhow::Error::msg)?;
    let artifacts = Arc::new(
        ArtifactManager::new(cache_root.clone(), transport)
            .map_err(|error| anyhow::anyhow!("open model artifact cache: {error}"))?,
    );
    let metadata = Arc::new(ConfigDirMetadataProvider {
        cache_root,
        revision: "main".to_string(),
        catalog: Arc::clone(&catalog),
    });
    let probe = make_probe();
    let descriptors = probe.probe();
    let capacities = if descriptors.is_empty() {
        BTreeMap::from([(0, 0)])
    } else {
        descriptors
            .iter()
            .map(|device| (device.index, device.free_vram_bytes))
            .collect()
    };
    let preparer = Arc::new(sbproxy_model_host::ProductionDeploymentPreparer::new(
        Arc::clone(&catalog),
        artifacts,
        probe,
        metadata,
        sbproxy_model_host::NetworkPolicy::Allowed,
    ));
    let manager = sbproxy_model_host::ModelRuntimeManager::new_with_device_capacities(
        catalog.catalog_revision.clone(),
        preparer,
        capacities,
    )?
    .with_observer(Arc::new(MetricsObserver));
    Ok(Arc::new(manager))
}

/// Return the permanent process-wide managed-model runtime handle.
pub fn model_runtime_manager() -> Arc<ProductionModelRuntime> {
    MODEL_RUNTIME
        .get_or_init(|| {
            let runtime = Arc::new(
                ProductionModelRuntime::empty()
                    .expect("built-in empty model runtime must be valid"),
            );
            ProductionModelRuntime::start_maintenance(&runtime);
            runtime
        })
        .clone()
}

/// Prepare a complete pipeline model revision without changing live state.
pub async fn prepare_model_runtime(
    pipeline: &crate::pipeline::CompiledPipeline,
    config_dir: &Path,
) -> anyhow::Result<PreparedModelRuntime> {
    model_runtime_manager().prepare(pipeline, config_dir).await
}

/// Atomically publish a prepared model revision.
pub async fn commit_model_runtime(
    prepared: PreparedModelRuntime,
) -> Result<sbproxy_model_host::ReconcileReport, sbproxy_model_host::RuntimeManagerError> {
    let owner = Arc::clone(&prepared.owner);
    owner.commit(prepared).await
}

/// Prepare and commit a complete model-runtime revision on an isolated Tokio
/// executor. This is safe from synchronous startup, file-watch threads, and
/// callbacks already running inside another executor.
pub(crate) fn reconcile_model_runtime_blocking(
    pipeline: &crate::pipeline::CompiledPipeline,
    config_dir: &Path,
) -> anyhow::Result<sbproxy_model_host::ReconcileReport> {
    let runtime = model_runtime_manager();
    let candidate = compile_runtime_candidate(pipeline, config_dir)?;
    let config_dir = config_dir.to_path_buf();
    let pipeline_revision = pipeline.config_revision.clone();
    std::thread::Builder::new()
        .name("sbproxy-model-reconcile".to_string())
        .spawn(move || {
            let executor = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| anyhow::anyhow!("build model reconcile runtime: {error}"))?;
            executor.block_on(async move {
                let prepared = runtime.prepare_candidate(candidate).await?;
                runtime.commit(prepared).await
                    .map_err(anyhow::Error::from)
            })
        })
        .map_err(|error| anyhow::anyhow!("spawn model reconcile thread: {error}"))?
        .join()
        .map_err(|_| {
            anyhow::anyhow!(
                "model runtime reconcile thread panicked for config revision {pipeline_revision:?} in {}",
                config_dir.display()
            )
        })?
}

/// Stop every managed engine from synchronous process-shutdown paths.
pub(crate) fn shutdown_model_runtime_blocking() -> anyhow::Result<BTreeMap<String, String>> {
    let Some(runtime) = MODEL_RUNTIME.get().cloned() else {
        return Ok(BTreeMap::new());
    };
    std::thread::Builder::new()
        .name("sbproxy-model-shutdown".to_string())
        .spawn(move || {
            let executor = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| anyhow::anyhow!("build model shutdown runtime: {error}"))?;
            Ok::<_, anyhow::Error>(executor.block_on(runtime.shutdown()))
        })
        .map_err(|error| anyhow::anyhow!("spawn model shutdown thread: {error}"))?
        .join()
        .map_err(|_| anyhow::anyhow!("model shutdown thread panicked"))?
}

/// Warn, at pipeline load time (startup and every hot reload), about
/// every `serve:` prerequisite this host is missing: no visible GPU,
/// or a serve entry whose resolved engine has no binary (and no
/// container runtime) to run it with. The request path degrades
/// gracefully either way (admission rejects / the attempt fails over
/// to the next provider), but silently degrading at 3am is not
/// bulletproof; the operator finds out when the config lands, with a
/// pointer at `sbproxy doctor`.
///
/// Best-effort and read-only: probes never panic, and a pipeline with
/// no `serve:` block logs nothing.
pub(crate) fn preflight_serve_warnings(actions: &[sbproxy_modules::Action]) {
    for action in actions {
        if let sbproxy_modules::Action::AiProxy(ai) = action {
            warn_missing_serve_prereqs(&ai.config);
        }
    }
}

/// The per-config half of [`preflight_serve_warnings`].
fn warn_missing_serve_prereqs(config: &AiHandlerConfig) {
    let Some(merged) = merged_serve_config(config) else {
        return;
    };
    let gpus = make_probe().probe();
    let env = sbproxy_model_host::EngineEnv::probe_host(!gpus.is_empty());
    if gpus.is_empty() {
        tracing::warn!(
            "serve: is configured but no GPU is visible to this process; \
             local model serving will reject admission and requests will \
             fail over to the next provider (or 502 with no fallback). \
             Run `sbproxy doctor` for the full host report"
        );
    }
    for entry in &merged.models {
        // GGUF-ness steers the `auto` engine choice toward llama.cpp;
        // at this preflight the weights are not resolved yet, so the
        // reference string is the best available signal.
        let is_gguf =
            entry.model.to_ascii_lowercase().contains("gguf") || entry.gguf_file.is_some();
        let doctor = sbproxy_model_host::EngineDoctor::for_entry(entry, is_gguf, &env);
        if !doctor.runnable {
            // WOR-1827: the doctor's `runnable` only reflects a PATH
            // binary, but the runtime acquires engines on demand
            // (WOR-1801). When the acquire plan can supply the engine
            // (a pinned prebuilt fetch, an explicit path, uvx), the
            // honest message is "fetched on first use", not "cannot
            // start"; the hard warning stays for a genuinely blocked
            // engine.
            let prov = merged.engines.get(&doctor.resolved);
            let plan = sbproxy_model_host::plan_binary_acquire(doctor.resolved, prov, None);
            match plan {
                sbproxy_model_host::BinaryAcquirePlan::Blocked(reason) => {
                    tracing::warn!(
                        model = %doctor.model,
                        engine = ?doctor.resolved,
                        "serve: model cannot start on this host: {reason}. Run \
                         `sbproxy doctor` to see the prerequisites and how to install them",
                    );
                }
                _ => {
                    tracing::info!(
                        model = %doctor.model,
                        engine = ?doctor.resolved,
                        "serve: engine not on PATH; sbproxy acquires it on the first \
                         request (a PATH install is preferred when present)",
                    );
                }
            }
        }
    }
}

/// Merge every provider's `serve:` block into one host config. A single
/// node has one GPU and one residency budget, so all served models
/// share one runtime; a provider's models are concatenated and the
/// engine-provisioning maps unioned. The first serve block's host
/// policy (eviction, cache dir/budget) wins.
fn merged_serve_config(config: &AiHandlerConfig) -> Option<ModelHostConfig> {
    let mut merged: Option<ModelHostConfig> = None;
    for provider in &config.providers {
        let Some(serve) = &provider.serve else {
            continue;
        };
        match &mut merged {
            None => merged = Some(serve.clone()),
            Some(m) => {
                m.models.extend(serve.models.iter().cloned());
                for (k, v) in &serve.engines {
                    m.engines.entry(*k).or_insert_with(|| v.clone());
                }
            }
        }
    }
    merged
}

/// Loopback target and request-lifetime permit for one managed local attempt.
pub struct ManagedLocalUpstream {
    /// OpenAI-compatible loopback engine URL.
    pub base_url: String,
    /// Stable public model name selected by the route table.
    pub public_model: String,
    /// Exact model identifier accepted by the managed engine.
    pub engine_model: String,
    /// Deployment admission held until the complete request context drops.
    pub permit: ManagedModelPermit,
}

/// Resolve, admit, and ready a canonical or legacy managed provider.
///
/// `Ok(None)` identifies an ordinary proxied provider. Every local provider
/// uses the current atomic desired-state route map, then binds admission and
/// readiness to the same manager snapshot so a concurrent reload cannot mix
/// generations within one request attempt.
pub async fn managed_upstream(
    origin: &str,
    provider: &sbproxy_ai::provider::ProviderConfig,
    requested_model: Option<&str>,
    priority: sbproxy_model_host::PriorityClass,
) -> Result<Option<ManagedLocalUpstream>, String> {
    if provider.serve.is_none() && !provider.is_managed_model() {
        return Ok(None);
    }
    let runtime = model_runtime_manager();
    let manager = runtime.active_manager();
    let desired = manager.current_desired();
    let names = desired
        .routes
        .iter()
        .filter(|route| route.origin == origin && route.provider == provider.name.as_str())
        .map(|route| route.model.clone())
        .collect::<Vec<_>>();
    let public_model = pick_local_model_name(&names, requested_model, provider).ok_or_else(|| {
        format!(
            "engine_unhealthy: provider {:?} has local routes {names:?}, but request model {requested_model:?} has no unambiguous match",
            provider.name.as_str()
        )
    })?;
    let route = desired
        .route_for(origin, provider.name.as_str(), &public_model)
        .ok_or_else(|| {
            format!(
                "engine_unhealthy: provider {:?} model {public_model:?} has no committed deployment route",
                provider.name.as_str()
            )
        })?;
    let deployment = route.deployment.clone();
    let engine_model = deployment.clone();
    let admission = manager
        .admit(&deployment, priority)
        .await
        .map_err(|error| format!("{}: {}", error.reason.as_str(), error.detail))?;
    let permit = ManagedModelPermit {
        manager,
        deployment,
        admission,
    };
    let running = permit
        .ensure_ready(priority)
        .await
        .map_err(|error| format!("{}: {error}", error.reason_code()))?;
    Ok(Some(ManagedLocalUpstream {
        base_url: format!("http://127.0.0.1:{}/v1", running.port),
        public_model,
        engine_model,
        permit,
    }))
}

use sbproxy_model_host::PriorityClass;

/// Map a virtual key's lane onto the scheduler's class. No key or no
/// declared lane both mean standard.
pub(crate) fn lane_class_for(priority: Option<sbproxy_ai::identity::KeyPriority>) -> PriorityClass {
    match priority {
        Some(sbproxy_ai::identity::KeyPriority::Interactive) => PriorityClass::Interactive,
        Some(sbproxy_ai::identity::KeyPriority::Batch) => PriorityClass::Batch,
        Some(sbproxy_ai::identity::KeyPriority::Standard) | None => PriorityClass::Standard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_serve(serve_yaml: Option<&str>) -> AiHandlerConfig {
        let providers = match serve_yaml {
            Some(y) => serde_json::json!([{
                "name": "local",
                "serve": serde_yaml::from_str::<serde_json::Value>(y).unwrap()
            }]),
            None => serde_json::json!([{"name": "openai", "api_key": "sk-x"}]),
        };
        AiHandlerConfig::from_config(serde_json::json!({ "providers": providers })).unwrap()
    }

    #[test]
    fn merged_serve_config_none_without_serve() {
        let cfg = config_with_serve(None);
        assert!(merged_serve_config(&cfg).is_none());
    }

    #[test]
    fn merged_serve_config_collects_models() {
        let cfg = config_with_serve(Some("models:\n  - model: qwen3-14b\n"));
        let merged = merged_serve_config(&cfg).expect("one serve block");
        assert_eq!(merged.models.len(), 1);
        assert!(merged.validate().is_ok());
    }

    #[test]
    fn custom_catalog_resolves_relative_to_sb_yml_directory() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("models.yaml"),
            "models:\n  exact:\n    hf_repo: Org/Exact\n    quants: [Q4_K_M]\n    params: 1B\n    license: apache-2.0\n    family: fixture\n    min_vram_hint_gib: 1.0\n",
        )
        .unwrap();
        let config: ModelHostConfig =
            serde_yaml::from_str("catalog_file: models.yaml\nmodels:\n  - model: exact\n").unwrap();

        let catalog = load_catalog_from_dir(&config, directory.path()).unwrap();

        assert!(catalog.get("exact").is_some());
    }

    #[test]
    fn lane_class_defaults_to_standard() {
        assert_eq!(lane_class_for(None), PriorityClass::Standard);
        assert_eq!(
            lane_class_for(Some(sbproxy_ai::identity::KeyPriority::Batch)),
            PriorityClass::Batch
        );
    }

    #[test]
    fn model_maintenance_runtime_supports_engine_health_io() {
        let executor = build_model_maintenance_runtime().unwrap();
        executor.block_on(async {
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let client = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
            let _server = listener.accept().await.unwrap();
            client.await.unwrap().unwrap();
        });
    }
}
