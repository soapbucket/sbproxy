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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use anyhow::Context;
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
    active_catalog: ArcSwap<Catalog>,
    foundation: RwLock<Option<RuntimeFoundation>>,
    snapshot_preparer: RwLock<Option<Arc<sbproxy_model_host::ProductionDeploymentPreparer>>>,
    cluster_state: RwLock<Option<ClusterRuntimeState>>,
    model_plane_health: AtomicU8,
    epoch: AtomicU64,
    commit_lock: tokio::sync::Mutex<()>,
}

const MODEL_PLANE_UNAVAILABLE: u8 = 0;
const MODEL_PLANE_DEGRADED: u8 = 1;
const MODEL_PLANE_READY: u8 = 2;

/// Successful durable admin deployment revision and its runtime effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminDeploymentRevisionResult {
    /// Monotonic durable store revision.
    pub revision: u64,
    /// Canonical digest of the exact durable revision.
    pub content_digest: String,
    /// Runtime reconciliation caused by the revision.
    pub plan: sbproxy_model_host::ReconcilePlan,
}

/// Failure to apply one complete admin-managed deployment revision.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdminDeploymentRevisionError {
    /// The configured authority does not accept local admin mutations.
    #[error("model host authority {authority:?} does not allow local admin mutations")]
    AuthorityReadOnly {
        /// Active persistent desired-state authority.
        authority: sbproxy_config::ModelHostAuthority,
    },
    /// The caller's optimistic revision no longer matches durable state.
    #[error("deployment revision conflict: expected {expected:?}, actual {actual:?}")]
    RevisionConflict {
        /// Caller-observed revision, or none for initial creation.
        expected: Option<u64>,
        /// Current durable revision, or none when the store is empty.
        actual: Option<u64>,
    },
    /// The durable revision store could not be read or updated.
    #[error("admin deployment store: {0}")]
    Store(String),
    /// Candidate preparation or runtime commit failed.
    #[error(transparent)]
    Runtime(#[from] sbproxy_model_host::RuntimeManagerError),
    /// Durable desired state advanced, but its prepared runtime could not publish.
    #[error("durable state advanced to revision {revision}, but runtime commit failed: {source}")]
    DurableStateAdvanced {
        /// Durable revision callers must use for their next optimistic update.
        revision: u64,
        /// Canonical digest of the durable revision that won the compare-and-swap.
        content_digest: String,
        /// Detailed process-local failure, retained for logs rather than API display.
        #[source]
        source: sbproxy_model_host::RuntimeManagerError,
    },
}

/// Authority and durable desired state exposed to authenticated management APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelManagementSnapshot {
    /// Active persistent desired-state authority.
    pub authority: sbproxy_config::ModelHostAuthority,
    /// Whether local admin mutation is disabled for this authority.
    pub read_only: bool,
    /// Durable admin store revision, when admin-managed state is active.
    pub revision: Option<u64>,
    /// Durable admin store content digest, when a revision exists.
    pub content_digest: Option<String>,
    /// Complete desired deployment map visible to this process.
    pub deployments: BTreeMap<String, sbproxy_model_host::ModelDeployment>,
}

impl std::fmt::Debug for ProductionModelRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionModelRuntime")
            .field("epoch", &self.epoch.load(Ordering::SeqCst))
            .field("model_plane_health", &self.model_plane_health())
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

#[derive(Debug, Clone)]
struct ClusterRuntimeState {
    placement: sbproxy_model_host::ClusterPlacementState,
    catalog: Arc<Catalog>,
}

/// A complete model-runtime candidate prepared without changing live routes.
pub struct PreparedModelRuntime {
    owner: Arc<ProductionModelRuntime>,
    manager: Arc<sbproxy_model_host::ModelRuntimeManager>,
    catalog: Arc<Catalog>,
    snapshot_preparer: Option<Arc<sbproxy_model_host::ProductionDeploymentPreparer>>,
    prepared: sbproxy_model_host::PreparedRevision,
    base_epoch: u64,
    foundation: Option<RuntimeFoundation>,
    replace_manager: bool,
    cluster_state: Option<ClusterRuntimeState>,
    authority_bundle: Option<sbproxy_model_host::VerifiedDeploymentBundle>,
}

impl std::fmt::Debug for PreparedModelRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedModelRuntime")
            .field("prepared", &self.prepared)
            .field("base_epoch", &self.base_epoch)
            .field("foundation", &self.foundation)
            .field("replace_manager", &self.replace_manager)
            .field("cluster_model_control", &self.cluster_state.is_some())
            .field("authority_bundle", &self.authority_bundle.is_some())
            .field("has_snapshot_preparer", &self.snapshot_preparer.is_some())
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
    pub(crate) fn from_admission(
        manager: Arc<sbproxy_model_host::ModelRuntimeManager>,
        deployment: String,
        admission: sbproxy_model_host::DeploymentAdmissionPermit,
    ) -> Self {
        Self {
            manager,
            deployment,
            admission,
        }
    }

    /// Canonical deployment held by this request.
    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    pub(crate) async fn ensure_ready(
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

fn empty_runtime_manager(
    catalog_revision: String,
) -> Result<Arc<sbproxy_model_host::ModelRuntimeManager>, sbproxy_model_host::RuntimeManagerError> {
    Ok(Arc::new(
        sbproxy_model_host::ModelRuntimeManager::new(
            catalog_revision,
            Arc::new(EmptyDeploymentPreparer),
        )?
        .with_observer(Arc::new(MetricsObserver)),
    ))
}

fn load_catalog_from_dir(
    config: &ModelHostConfig,
    config_dir: &Path,
) -> Result<Arc<Catalog>, String> {
    load_catalog_path(config.catalog_file.as_deref(), config_dir)
}

fn load_catalog_path(configured: Option<&str>, config_dir: &Path) -> Result<Arc<Catalog>, String> {
    let Some(configured) = configured else {
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
        let catalog = Arc::new(Catalog::builtin());
        let manager = empty_runtime_manager(catalog.catalog_revision.clone())?;
        Ok(Self {
            active: ArcSwap::from(manager),
            active_catalog: ArcSwap::from(catalog),
            foundation: RwLock::new(None),
            snapshot_preparer: RwLock::new(None),
            cluster_state: RwLock::new(None),
            model_plane_health: AtomicU8::new(MODEL_PLANE_UNAVAILABLE),
            epoch: AtomicU64::new(0),
            commit_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub(crate) fn active_manager(&self) -> Arc<sbproxy_model_host::ModelRuntimeManager> {
        self.active.load_full()
    }

    pub(crate) fn cluster_assignment_generation(
        &self,
        local_node_id: &str,
        deployment: &str,
    ) -> Option<u64> {
        self.cluster_state
            .read()
            .expect("cluster model state lock")
            .as_ref()
            .and_then(|state| {
                state
                    .placement
                    .local_assignments(local_node_id)
                    .get(deployment)
                    .map(|assignment| assignment.deployment_generation)
            })
    }

    /// Publish the current private model-plane listener health into worker snapshots.
    pub(crate) fn set_model_plane_health(
        &self,
        health: sbproxy_model_host::node_snapshot::ModelPlaneHealth,
    ) {
        let value = match health {
            sbproxy_model_host::node_snapshot::ModelPlaneHealth::Unavailable => {
                MODEL_PLANE_UNAVAILABLE
            }
            sbproxy_model_host::node_snapshot::ModelPlaneHealth::Degraded => MODEL_PLANE_DEGRADED,
            sbproxy_model_host::node_snapshot::ModelPlaneHealth::Ready => MODEL_PLANE_READY,
        };
        self.model_plane_health.store(value, Ordering::SeqCst);
    }

    /// Load the health value included in the next immutable worker snapshot.
    pub(crate) fn model_plane_health(&self) -> sbproxy_model_host::node_snapshot::ModelPlaneHealth {
        match self.model_plane_health.load(Ordering::SeqCst) {
            MODEL_PLANE_READY => sbproxy_model_host::node_snapshot::ModelPlaneHealth::Ready,
            MODEL_PLANE_DEGRADED => sbproxy_model_host::node_snapshot::ModelPlaneHealth::Degraded,
            _ => sbproxy_model_host::node_snapshot::ModelPlaneHealth::Unavailable,
        }
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
                    // Let initial cluster and model-runtime reconciliation commit before
                    // publishing the first worker snapshot.
                    interval.tick().await;
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
                        if let Err(error) = publish_cluster_node_snapshot(&runtime).await {
                            tracing::warn!(%error, "publish cluster node model snapshot");
                        }
                        match crate::cluster::collect_process_model_directory(false).await {
                            Ok(Some(view)) => {
                                if let Err(error) = runtime.reconcile_cluster_directory(view).await
                                {
                                    tracing::warn!(%error, "reconcile cluster model placement");
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                tracing::warn!(%error, "collect live cluster model directory");
                            }
                        }
                        if let Err(error) = refresh_cluster_deployment_bundle(&runtime).await {
                            tracing::warn!(%error, "refresh signed cluster deployment bundle");
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

    /// Catalog committed with the current runtime revision.
    pub fn active_catalog(&self) -> Arc<Catalog> {
        self.active_catalog.load_full()
    }

    /// Authority-aware desired-state snapshot for authenticated management APIs.
    pub fn management_snapshot(
        &self,
    ) -> Result<ModelManagementSnapshot, AdminDeploymentRevisionError> {
        let desired = self.current_desired();
        let authority = desired.control.authority;
        if authority == sbproxy_config::ModelHostAuthority::AdminManaged {
            let store_path = desired.control.store_path.clone().ok_or_else(|| {
                AdminDeploymentRevisionError::Runtime(
                    sbproxy_model_host::RuntimeManagerError::InvalidDesired(
                        "admin-managed model host requires a deployment store path".to_string(),
                    ),
                )
            })?;
            let store = sbproxy_model_host::FileDeploymentRevisionStore::open(store_path)
                .map_err(map_admin_store_error)?;
            let durable = store.load().map_err(map_admin_store_error)?;
            return Ok(match durable {
                Some(revision) => ModelManagementSnapshot {
                    authority,
                    read_only: false,
                    revision: Some(revision.revision),
                    content_digest: Some(revision.content_digest),
                    deployments: revision.deployments,
                },
                None => ModelManagementSnapshot {
                    authority,
                    read_only: false,
                    revision: None,
                    content_digest: None,
                    deployments: desired.revision.deployments.clone(),
                },
            });
        }

        Ok(ModelManagementSnapshot {
            authority,
            read_only: true,
            revision: None,
            content_digest: None,
            deployments: desired.revision.deployments.clone(),
        })
    }

    /// Prepare, durably compare-and-swap, and commit one complete admin revision.
    pub async fn apply_admin_deployment_revision(
        &self,
        expected_revision: Option<u64>,
        deployments: BTreeMap<String, sbproxy_model_host::ModelDeployment>,
    ) -> Result<AdminDeploymentRevisionResult, AdminDeploymentRevisionError> {
        let _guard = self.commit_lock.lock().await;
        let manager = self.active_manager();
        let template = manager.current_desired();
        let authority = template.control.authority;
        if authority != sbproxy_config::ModelHostAuthority::AdminManaged {
            return Err(AdminDeploymentRevisionError::AuthorityReadOnly { authority });
        }
        let store_path = template.control.store_path.clone().ok_or_else(|| {
            sbproxy_model_host::RuntimeManagerError::InvalidDesired(
                "admin-managed model host requires a deployment store path".to_string(),
            )
        })?;
        let store = sbproxy_model_host::FileDeploymentRevisionStore::open(store_path)
            .map_err(map_admin_store_error)?;
        let current = store.load().map_err(map_admin_store_error)?;
        let actual_revision = current.as_ref().map(|revision| revision.revision);
        if expected_revision != actual_revision {
            return Err(AdminDeploymentRevisionError::RevisionConflict {
                expected: expected_revision,
                actual: actual_revision,
            });
        }
        let current_epoch = self.epoch.load(Ordering::SeqCst);
        let next_epoch = current_epoch
            .checked_add(1)
            .ok_or(sbproxy_model_host::RuntimeManagerError::CounterOverflow)?;
        let next_revision = actual_revision.unwrap_or(0).checked_add(1).ok_or_else(|| {
            AdminDeploymentRevisionError::Store("deployment revision counter overflow".to_string())
        })?;
        let draft = sbproxy_model_host::DeploymentRevisionDraft {
            source_mode: sbproxy_model_host::DeploymentSourceMode::AdminManaged,
            source_revision: "admin-api".to_string(),
            catalog_revision: template.revision.catalog_revision.clone(),
            deployments,
        };
        let candidate = draft
            .clone()
            .into_revision(next_revision)
            .map_err(|error| {
                sbproxy_model_host::RuntimeManagerError::InvalidDesired(error.to_string())
            })?;
        let prepared = manager
            .prepare_admin_revision((*template).clone(), candidate.clone())
            .await?;
        let durable = match store.compare_and_swap(expected_revision, draft) {
            Ok(durable) => durable,
            Err(error) => {
                manager.abort_prepared(prepared).await;
                return Err(map_admin_store_error(error));
            }
        };
        if durable != candidate {
            manager.abort_prepared(prepared).await;
            return Err(AdminDeploymentRevisionError::Store(
                "compare-and-swap returned a different revision than the prepared candidate"
                    .to_string(),
            ));
        }
        self.epoch.store(next_epoch, Ordering::SeqCst);
        let report = manager.commit_revision(prepared).await.map_err(|source| {
            AdminDeploymentRevisionError::DurableStateAdvanced {
                revision: durable.revision,
                content_digest: durable.content_digest.clone(),
                source,
            }
        })?;
        Ok(AdminDeploymentRevisionResult {
            revision: durable.revision,
            content_digest: durable.content_digest,
            plan: report.plan,
        })
    }

    /// Current committed fleet placement status, when canonical cluster control is active.
    pub fn cluster_placement_state(&self) -> Option<sbproxy_model_host::ClusterPlacementState> {
        self.cluster_state
            .read()
            .expect("cluster model state lock")
            .as_ref()
            .map(|state| state.placement.clone())
    }

    /// Recompute and atomically reconcile assignments from one directory publication.
    pub async fn reconcile_cluster_directory(
        &self,
        view: Arc<sbproxy_ai::model_directory::ModelDirectoryView>,
    ) -> anyhow::Result<bool> {
        let Some(context) = crate::cluster_models::current_cluster_model_context() else {
            return Ok(false);
        };
        let input = crate::cluster_models::placement_input_from_directory(&view)?;
        self.reconcile_cluster_input(context, input, current_unix_time_ms()?)
            .await
    }

    async fn reconcile_cluster_input(
        &self,
        context: crate::cluster_models::ClusterModelContext,
        input: crate::cluster_models::DirectoryPlacementInput,
        now_unix_ms: u64,
    ) -> anyhow::Result<bool> {
        let _guard = self.commit_lock.lock().await;
        let Some(current_cluster) = self
            .cluster_state
            .read()
            .expect("cluster model state lock")
            .clone()
        else {
            return Ok(false);
        };
        let next_placement = sbproxy_model_host::reconcile_cluster_placement(
            &current_cluster.catalog,
            Some(&current_cluster.placement),
            current_cluster.placement.global().clone(),
            input.nodes,
            &input.observations,
            &input.generation_fences,
            now_unix_ms,
        )?;
        crate::cluster_models::persist_deployment_generations(&next_placement)
            .context("persist cluster deployment generations before placement commit")?;
        let local_desired = next_placement.local_desired(&context.node_id)?;
        let manager = self.active_manager();
        if local_desired == *manager.current_desired() {
            *self
                .cluster_state
                .write()
                .expect("cluster model state lock") = Some(ClusterRuntimeState {
                placement: next_placement,
                catalog: current_cluster.catalog,
            });
            return Ok(false);
        }

        let current_epoch = self.epoch.load(Ordering::SeqCst);
        let next_epoch = current_epoch
            .checked_add(1)
            .ok_or(sbproxy_model_host::RuntimeManagerError::CounterOverflow)?;
        let prepared = manager.prepare_revision(local_desired).await?;
        manager.commit_revision(prepared).await?;
        *self
            .cluster_state
            .write()
            .expect("cluster model state lock") = Some(ClusterRuntimeState {
            placement: next_placement,
            catalog: current_cluster.catalog,
        });
        self.epoch.store(next_epoch, Ordering::SeqCst);
        Ok(true)
    }

    /// Verify and atomically apply one newer signed authority bundle.
    pub async fn apply_cluster_authority_bundle(
        &self,
        verified: &sbproxy_model_host::VerifiedDeploymentBundle,
    ) -> anyhow::Result<bool> {
        let Some(context) = crate::cluster_models::current_cluster_model_context() else {
            anyhow::bail!("signed cluster deployment bundle requires canonical cluster mode");
        };
        let _guard = self.commit_lock.lock().await;
        let Some(current_cluster) = self
            .cluster_state
            .read()
            .expect("cluster model state lock")
            .clone()
        else {
            anyhow::bail!("cluster model controller is not initialized");
        };
        if current_cluster.placement.global().control.authority
            != sbproxy_config::ModelHostAuthority::ClusterAuthority
        {
            anyhow::bail!("model host is not configured for cluster_authority");
        }
        if verified.bundle().catalog_revision != current_cluster.catalog.catalog_revision {
            anyhow::bail!(
                "signed deployment catalog revision {:?} differs from active {:?}",
                verified.bundle().catalog_revision,
                current_cluster.catalog.catalog_revision
            );
        }
        let global = desired_from_verified_bundle(current_cluster.placement.global(), verified)?;
        let view = crate::cluster::current_model_directory()
            .map(|directory| directory.load())
            .unwrap_or_else(
                || Arc::new(sbproxy_ai::model_directory::ModelDirectoryView::default()),
            );
        let input = crate::cluster_models::placement_input_from_directory(&view)?;
        let next_placement = sbproxy_model_host::reconcile_cluster_placement(
            &current_cluster.catalog,
            Some(&current_cluster.placement),
            global,
            input.nodes,
            &input.observations,
            &input.generation_fences,
            current_unix_time_ms()?,
        )?;
        crate::cluster_models::persist_deployment_generations(&next_placement)
            .context("persist cluster deployment generations before authority commit")?;
        let local_desired = next_placement.local_desired(&context.node_id)?;
        let current_epoch = self.epoch.load(Ordering::SeqCst);
        let next_epoch = current_epoch
            .checked_add(1)
            .ok_or(sbproxy_model_host::RuntimeManagerError::CounterOverflow)?;
        let manager = self.active_manager();
        let runtime_changed = local_desired != *manager.current_desired();
        let authority = crate::cluster::current_deployment_authority()
            .ok_or_else(|| anyhow::anyhow!("cluster deployment authority is not installed"))?;
        authority
            .persist(verified)
            .context("persist cluster deployment authority cursor before runtime commit")?;
        if runtime_changed {
            let prepared = manager.prepare_revision(local_desired).await?;
            manager.commit_revision(prepared).await?;
        }
        *self
            .cluster_state
            .write()
            .expect("cluster model state lock") = Some(ClusterRuntimeState {
            placement: next_placement,
            catalog: current_cluster.catalog,
        });
        authority.activate(verified.clone());
        self.epoch.store(next_epoch, Ordering::SeqCst);
        Ok(runtime_changed)
    }

    /// Snapshot every configured deployment in deterministic ID order.
    pub async fn statuses(&self) -> Vec<sbproxy_model_host::DeploymentRuntimeStatus> {
        self.active_manager().statuses().await
    }

    /// Build one bounded, path-free cluster snapshot from current runtime truth.
    pub async fn node_model_snapshot(
        &self,
        identity: &sbproxy_mesh::ClusterIdentity,
        generation: u64,
        published_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<
        sbproxy_model_host::node_snapshot::NodeModelSnapshot,
        sbproxy_model_host::node_snapshot::NodeSnapshotError,
    > {
        use sbproxy_model_host::node_snapshot::{
            NodeArtifactSnapshot, NodeArtifactState, NodeHealthSnapshot, NodeHealthState,
            NodeIdentitySnapshot, NodeModelSnapshot, NodeReplicaSnapshot, NodeSnapshotError,
            NodeSnapshotInventory, RuntimeReplicaIdentity, NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
        };
        use sbproxy_model_host::{DeploymentRuntimeState, EngineAvailability};
        use sha2::{Digest as _, Sha256};

        let is_worker = identity
            .roles
            .contains(&sbproxy_mesh::ClusterNodeRole::Worker);
        let snapshot_preparer = self
            .snapshot_preparer
            .read()
            .expect("model runtime snapshot-preparer lock")
            .clone();
        let (mut inventory, inventory_available) = if is_worker {
            match snapshot_preparer {
                Some(preparer) => match preparer.node_snapshot_inventory() {
                    Ok(inventory) => (inventory, true),
                    Err(error) => {
                        tracing::warn!(%error, "build cluster model inventory");
                        (NodeSnapshotInventory::default(), false)
                    }
                },
                None => (NodeSnapshotInventory::default(), false),
            }
        } else {
            (NodeSnapshotInventory::default(), true)
        };
        let desired = self.current_desired();
        let cluster_state = self
            .cluster_state
            .read()
            .expect("cluster model state lock")
            .clone();
        let cluster_assignments = cluster_state
            .as_ref()
            .map(|state| state.placement.local_assignments(&identity.node_id))
            .unwrap_or_default();
        let statuses = self.statuses().await;
        let mut health_reasons = BTreeSet::new();
        let mut unhealthy = false;
        if is_worker && !inventory_available {
            health_reasons.insert("model_inventory_unavailable".to_string());
            unhealthy = true;
        }

        if is_worker {
            if !inventory
                .devices
                .iter()
                .any(|device| device.accelerator.is_some())
            {
                health_reasons.insert("no_compatible_model_device".to_string());
                unhealthy = true;
            }
            if !inventory.engines.iter().any(|engine| {
                matches!(
                    engine.availability,
                    EngineAvailability::Available | EngineAvailability::Acquirable
                )
            }) {
                health_reasons.insert("no_usable_model_engine".to_string());
                unhealthy = true;
            }
            if identity.model_endpoint.is_none() {
                health_reasons.insert("model_endpoint_missing".to_string());
                unhealthy = true;
            }
        }

        let failed_count = statuses
            .iter()
            .filter(|status| status.state == DeploymentRuntimeState::Failed)
            .count();
        for status in statuses
            .iter()
            .filter(|status| status.state == DeploymentRuntimeState::Failed)
        {
            health_reasons.insert(
                status
                    .reason_code
                    .clone()
                    .unwrap_or_else(|| "deployment_failed".to_string()),
            );
        }
        if !statuses.is_empty() && failed_count == statuses.len() {
            unhealthy = true;
        }

        let mut replicas = Vec::with_capacity(statuses.len());
        for status in &statuses {
            let Some(compiled) = desired.deployments.get(&status.deployment) else {
                tracing::warn!(
                    deployment = %status.deployment,
                    "runtime status has no current desired deployment"
                );
                health_reasons.insert("runtime_desired_mismatch".to_string());
                unhealthy = true;
                continue;
            };
            let matching_artifact = status.artifact_digest.as_deref().and_then(|digest| {
                inventory
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.artifact_digest == digest)
            });
            let artifact_was_in_inventory = matching_artifact.is_some();
            let variant = matching_artifact
                .map(|artifact| artifact.variant.clone())
                .or_else(|| compiled.desired.variant.clone());
            if let Some(digest) = status.artifact_digest.as_deref() {
                if !artifact_was_in_inventory {
                    inventory.artifacts.push(NodeArtifactSnapshot {
                        artifact_digest: digest.to_string(),
                        model: compiled.desired.model.clone(),
                        variant: variant.clone().unwrap_or_else(|| "unresolved".to_string()),
                        state: NodeArtifactState::Missing,
                        completed_bytes: 0,
                        total_bytes: None,
                        last_accessed_unix_ms: None,
                        reason_code: None,
                    });
                    health_reasons.insert("artifact_inventory_missing".to_string());
                }
            }
            let mut adapters = compiled
                .legacy_entry
                .as_ref()
                .map(|entry| {
                    entry
                        .lora_adapters
                        .iter()
                        .map(|adapter| adapter.name.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            adapters.sort();
            let deployment_generation = cluster_assignments
                .get(&status.deployment)
                .map_or(status.generation, |assignment| {
                    assignment.deployment_generation
                });
            replicas.push(NodeReplicaSnapshot::from_runtime_at_generation(
                status,
                deployment_generation,
                RuntimeReplicaIdentity {
                    model: &compiled.desired.model,
                    variant: variant.as_deref(),
                    endpoint: identity.model_endpoint.as_deref(),
                    adapters: &adapters,
                },
            )?);
        }
        inventory
            .artifacts
            .sort_by(|left, right| left.artifact_digest.cmp(&right.artifact_digest));
        replicas.sort_by(|left, right| left.deployment.cmp(&right.deployment));

        let health_state = if unhealthy {
            NodeHealthState::Unhealthy
        } else if !health_reasons.is_empty() {
            NodeHealthState::Degraded
        } else {
            NodeHealthState::Ready
        };
        let placement_weight = if is_worker && health_state != NodeHealthState::Unhealthy {
            let available_mib = inventory.devices.iter().fold(0u64, |total, device| {
                total.saturating_add(device.available_memory_bytes / (1024 * 1024))
            });
            u32::try_from(available_mib.clamp(1, u64::from(u32::MAX)))
                .unwrap_or(u32::MAX)
                .min(1_000_000)
        } else {
            0
        };
        let active_revision = cluster_state.as_ref().map_or(&desired.revision, |state| {
            &state.placement.global().revision
        });
        let digest_material = serde_json::to_vec(active_revision).map_err(|error| {
            NodeSnapshotError::Invalid(format!("encode active deployment digest: {error}"))
        })?;
        let active_deployment_digest = hex::encode(Sha256::digest(digest_material));
        let snapshot = NodeModelSnapshot {
            schema_version: NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
            node: NodeIdentitySnapshot {
                node_id: identity.node_id.clone(),
                roles: identity.roles.iter().copied().map(snapshot_role).collect(),
                labels: identity.labels.clone(),
                model_endpoint: identity.model_endpoint.clone(),
            },
            health: NodeHealthSnapshot {
                state: health_state,
                reason_codes: health_reasons.into_iter().collect(),
                model_plane: self.model_plane_health(),
            },
            engines: inventory.engines,
            devices: inventory.devices,
            artifacts: inventory.artifacts,
            replicas,
            placement_weight,
            active_deployment_digest: Some(active_deployment_digest),
            generation,
            published_at_unix_ms,
            expires_at_unix_ms,
        };
        snapshot.validate()?;
        Ok(snapshot)
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
        mut candidate: RuntimeCandidate,
    ) -> anyhow::Result<PreparedModelRuntime> {
        let base_epoch = self.epoch.load(Ordering::SeqCst);
        let cluster_context = crate::cluster_models::current_cluster_model_context();
        validate_model_authority_context(
            candidate.desired.control.authority,
            cluster_context.is_some(),
        )?;
        let mut proposed_cluster_state = None;
        let mut cluster_worker = false;
        if let Some(context) = cluster_context {
            let view = crate::cluster::current_model_directory()
                .map(|directory| directory.load())
                .unwrap_or_else(|| {
                    Arc::new(sbproxy_ai::model_directory::ModelDirectoryView::default())
                });
            let input = crate::cluster_models::placement_input_from_directory(&view)?;
            let previous = self
                .cluster_state
                .read()
                .expect("cluster model state lock")
                .clone();
            let now_unix_ms = current_unix_time_ms()?;
            let placement = sbproxy_model_host::reconcile_cluster_placement(
                &candidate.catalog,
                previous.as_ref().map(|state| &state.placement),
                candidate.desired.clone(),
                input.nodes,
                &input.observations,
                &input.generation_fences,
                now_unix_ms,
            )?;
            candidate.desired = placement.local_desired(&context.node_id)?;
            cluster_worker = context.is_worker;
            proposed_cluster_state = Some(ClusterRuntimeState {
                placement,
                catalog: Arc::clone(&candidate.catalog),
            });
        }
        let current_foundation = self
            .foundation
            .read()
            .expect("model runtime foundation lock")
            .clone();
        let current_snapshot_preparer = self
            .snapshot_preparer
            .read()
            .expect("model runtime snapshot-preparer lock")
            .clone();
        let active_manager = self.active_manager();

        let needs_production_manager = !candidate.desired.deployments.is_empty()
            || (cluster_worker
                && proposed_cluster_state
                    .as_ref()
                    .is_some_and(|state| !state.placement.global().deployments.is_empty()))
            || candidate.desired.control.authority
                != sbproxy_config::ModelHostAuthority::FileManaged;
        let active_catalog_matches = active_manager.current_desired().revision.catalog_revision
            == candidate.desired.revision.catalog_revision;
        let (manager, foundation, snapshot_preparer) = if !needs_production_manager
            && !active_catalog_matches
        {
            (
                empty_runtime_manager(candidate.desired.revision.catalog_revision.clone())?,
                None,
                None,
            )
        } else if !needs_production_manager {
            (
                active_manager.clone(),
                current_foundation,
                current_snapshot_preparer,
            )
        } else {
            let foundation = RuntimeFoundation {
                catalog_revision: candidate.catalog.catalog_revision.clone(),
                cache_root: candidate.cache_root.clone(),
            };
            if current_foundation.as_ref() == Some(&foundation) {
                (
                    active_manager.clone(),
                    Some(foundation),
                    current_snapshot_preparer,
                )
            } else {
                if !active_manager.current_desired().deployments.is_empty() {
                    anyhow::bail!(
                        "model runtime catalog or cache foundation changed while deployments are configured; reload an empty model_host revision first so the prior engines drain before replacing the foundation"
                    );
                }
                let built = build_production_manager(
                    candidate.catalog.clone(),
                    candidate.cache_root.clone(),
                )?;
                (
                    built.manager,
                    Some(foundation),
                    Some(built.snapshot_preparer),
                )
            }
        };
        let replace_manager = !Arc::ptr_eq(&manager, &active_manager);
        let prepared = manager.prepare_revision(candidate.desired).await?;
        Ok(PreparedModelRuntime {
            owner: Arc::clone(self),
            manager,
            catalog: candidate.catalog,
            snapshot_preparer,
            prepared,
            base_epoch,
            foundation,
            replace_manager,
            cluster_state: proposed_cluster_state,
            authority_bundle: candidate.authority_bundle,
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
        if let Some(cluster) = candidate.cluster_state.as_ref() {
            crate::cluster_models::persist_deployment_generations(&cluster.placement).map_err(
                |error| {
                    sbproxy_model_host::RuntimeManagerError::Prepare(format!(
                        "persist cluster deployment generations before runtime commit: {error}"
                    ))
                },
            )?;
        }
        let authority_activation = if let Some(verified) = candidate.authority_bundle.as_ref() {
            let authority = crate::cluster::current_deployment_authority().ok_or_else(|| {
                sbproxy_model_host::RuntimeManagerError::Prepare(
                    "cluster deployment authority is not installed".to_string(),
                )
            })?;
            authority.persist(verified).map_err(|error| {
                sbproxy_model_host::RuntimeManagerError::Prepare(format!(
                    "persist cluster deployment authority cursor before runtime commit: {error}"
                ))
            })?;
            Some((authority, verified.clone()))
        } else {
            None
        };
        let report = candidate
            .manager
            .commit_revision(candidate.prepared)
            .await?;
        if candidate.replace_manager {
            self.active.store(candidate.manager);
        }
        self.active_catalog.store(candidate.catalog);
        *self
            .snapshot_preparer
            .write()
            .expect("model runtime snapshot-preparer lock") = candidate.snapshot_preparer;
        *self
            .foundation
            .write()
            .expect("model runtime foundation lock") = candidate.foundation;
        *self
            .cluster_state
            .write()
            .expect("cluster model state lock") = candidate.cluster_state;
        if let Some((authority, verified)) = authority_activation {
            authority.activate(verified);
        }
        self.epoch.store(next_epoch, Ordering::SeqCst);
        Ok(report)
    }
}

fn map_admin_store_error(
    error: sbproxy_model_host::DeploymentStoreError,
) -> AdminDeploymentRevisionError {
    match error {
        sbproxy_model_host::DeploymentStoreError::Conflict { expected, actual } => {
            AdminDeploymentRevisionError::RevisionConflict { expected, actual }
        }
        error => AdminDeploymentRevisionError::Store(error.to_string()),
    }
}

fn current_unix_time_ms() -> anyhow::Result<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| anyhow::anyhow!("system time before Unix epoch: {error}"))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| anyhow::anyhow!("Unix time milliseconds overflowed"))
}

fn desired_from_verified_bundle(
    current: &sbproxy_model_host::RuntimeDesiredState,
    verified: &sbproxy_model_host::VerifiedDeploymentBundle,
) -> anyhow::Result<sbproxy_model_host::RuntimeDesiredState> {
    if current.legacy_host_policy.is_some() {
        anyhow::bail!("cluster_authority cannot replace legacy serve desired state");
    }
    let revision = verified.revision_draft();
    let deployments = revision
        .deployments
        .iter()
        .map(|(id, deployment)| {
            (
                id.clone(),
                sbproxy_model_host::CompiledDeployment {
                    desired: deployment.clone(),
                    origin: sbproxy_model_host::DesiredDeploymentOrigin::Canonical,
                    legacy_entry: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for route in &current.routes {
        if !deployments.contains_key(&route.deployment) {
            anyhow::bail!(
                "signed deployment bundle omits routed deployment {:?}",
                route.deployment
            );
        }
    }
    let mut control = current.control.clone();
    control.deployments = revision
        .deployments
        .iter()
        .map(|(id, deployment)| {
            managed_deployment_from_model(deployment.clone())
                .map(|deployment| (id.clone(), deployment))
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(sbproxy_model_host::RuntimeDesiredState {
        revision,
        deployments,
        routes: current.routes.clone(),
        control,
        legacy_host_policy: None,
    })
}

async fn refresh_cluster_deployment_bundle(runtime: &ProductionModelRuntime) -> anyhow::Result<()> {
    let Some(state) = runtime.cluster_placement_state() else {
        return Ok(());
    };
    if state.global().control.authority != sbproxy_config::ModelHostAuthority::ClusterAuthority {
        return Ok(());
    }
    let authority = crate::cluster::current_deployment_authority()
        .ok_or_else(|| anyhow::anyhow!("cluster deployment authority is not installed"))?;
    if let Some(verified) = authority.read_candidate().await? {
        runtime.apply_cluster_authority_bundle(&verified).await?;
    }
    authority
        .republish_active_if_due(std::time::Duration::from_secs(24 * 60 * 60))
        .await?;
    Ok(())
}

async fn publish_cluster_node_snapshot(runtime: &ProductionModelRuntime) -> anyhow::Result<()> {
    let Some(publication) = crate::cluster::begin_process_node_snapshot_publication(false).await?
    else {
        return Ok(());
    };
    let snapshot = runtime
        .node_model_snapshot(
            publication.identity(),
            publication.generation(),
            publication.published_at_unix_ms(),
            publication.expires_at_unix_ms(),
        )
        .await?;
    publication.publish(snapshot).await
}

struct RuntimeCandidate {
    desired: sbproxy_model_host::RuntimeDesiredState,
    catalog: Arc<Catalog>,
    cache_root: PathBuf,
    authority_bundle: Option<sbproxy_model_host::VerifiedDeploymentBundle>,
}

const fn snapshot_role(
    role: sbproxy_mesh::ClusterNodeRole,
) -> sbproxy_model_host::node_snapshot::NodeRole {
    match role {
        sbproxy_mesh::ClusterNodeRole::Gateway => {
            sbproxy_model_host::node_snapshot::NodeRole::Gateway
        }
        sbproxy_mesh::ClusterNodeRole::Worker => {
            sbproxy_model_host::node_snapshot::NodeRole::Worker
        }
        sbproxy_mesh::ClusterNodeRole::Authority => {
            sbproxy_model_host::node_snapshot::NodeRole::Authority
        }
    }
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

    let catalog = match pipeline
        .config
        .server
        .model_host
        .as_ref()
        .and_then(|control| control.catalog_file.as_deref())
    {
        Some(catalog_file) => {
            load_catalog_path(Some(catalog_file), config_dir).map_err(anyhow::Error::msg)?
        }
        None if !legacy_providers.is_empty() => {
            let legacy = &legacy_providers[0];
            load_catalog_from_dir(&legacy.config, config_dir).map_err(anyhow::Error::msg)?
        }
        None => Arc::new(Catalog::builtin()),
    };
    let mut canonical = pipeline.config.server.model_host.clone();
    let mut authority_bundle = None;
    if canonical.as_ref().is_some_and(|control| {
        control.authority == sbproxy_config::ModelHostAuthority::ClusterAuthority
    }) {
        let authority = crate::cluster::current_deployment_authority().ok_or_else(|| {
            anyhow::anyhow!(
                "cluster_authority model host requires proxy.cluster.deployment_authority"
            )
        })?;
        let verified = authority
            .read_candidate_blocking()
            .map_err(anyhow::Error::from)?
            .or_else(|| authority.active());
        let control = canonical
            .as_mut()
            .expect("cluster authority control exists");
        control.deployments.clear();
        if let Some(verified) = verified {
            if verified.bundle().catalog_revision != catalog.catalog_revision {
                anyhow::bail!(
                    "signed deployment catalog revision {:?} differs from active {:?}",
                    verified.bundle().catalog_revision,
                    catalog.catalog_revision
                );
            }
            control.deployments = verified
                .bundle()
                .deployments()
                .into_iter()
                .map(|(id, deployment)| {
                    managed_deployment_from_model(deployment).map(|deployment| (id, deployment))
                })
                .collect::<anyhow::Result<_>>()?;
            authority_bundle = Some(verified);
        } else if !managed_providers.is_empty() {
            anyhow::bail!(
                "cluster_authority model providers require an active signed deployment bundle"
            );
        }
    }
    let desired_source_revision = authority_bundle.as_ref().map_or_else(
        || pipeline.config_revision.clone(),
        |verified| verified.revision_draft().source_revision,
    );
    let desired = sbproxy_model_host::compile_desired_state(
        sbproxy_model_host::RuntimeDesiredInput {
            source_revision: desired_source_revision,
            canonical,
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
        authority_bundle,
    })
}

fn managed_deployment_from_model(
    deployment: sbproxy_model_host::ModelDeployment,
) -> anyhow::Result<sbproxy_config::ManagedDeploymentConfig> {
    let engine = match deployment.engine {
        sbproxy_model_host::EngineChoice::Auto => sbproxy_config::ManagedEngineChoice::Auto,
        sbproxy_model_host::EngineChoice::Vllm => sbproxy_config::ManagedEngineChoice::Vllm,
        sbproxy_model_host::EngineChoice::LlamaCpp => sbproxy_config::ManagedEngineChoice::LlamaCpp,
        sbproxy_model_host::EngineChoice::Embedded => {
            anyhow::bail!("signed cluster deployments do not support the embedded engine")
        }
    };
    Ok(sbproxy_config::ManagedDeploymentConfig {
        model: deployment.model,
        variant: deployment.variant,
        heterogeneous_variants: deployment.heterogeneous_variants,
        replicas: deployment.replicas,
        required_labels: deployment.required_labels,
        spread_by: deployment.spread_by,
        pull: match deployment.pull {
            sbproxy_model_host::PullPolicy::OnBoot => sbproxy_config::ManagedPullPolicy::OnBoot,
            sbproxy_model_host::PullPolicy::OnDemand => sbproxy_config::ManagedPullPolicy::OnDemand,
            sbproxy_model_host::PullPolicy::Manual => sbproxy_config::ManagedPullPolicy::Manual,
        },
        warm: deployment.warm,
        keep_alive_secs: deployment.keep_alive_secs,
        max_concurrency: deployment.max_concurrency,
        max_queue_depth: deployment.max_queue_depth,
        queue_timeout_ms: deployment.queue_timeout_ms,
        engine,
        rollout: match deployment.rollout {
            sbproxy_model_host::RolloutPolicy::Rolling => {
                sbproxy_config::ManagedRolloutPolicy::Rolling
            }
            sbproxy_model_host::RolloutPolicy::Recreate => {
                sbproxy_config::ManagedRolloutPolicy::Recreate
            }
        },
    })
}

/// Run the side-effect-free managed-model checks shared by validate and boot.
pub fn validate_model_runtime(
    pipeline: &crate::pipeline::CompiledPipeline,
    config_dir: &Path,
) -> anyhow::Result<()> {
    let candidate = compile_runtime_candidate(pipeline, config_dir)?;
    validate_model_authority_context(
        candidate.desired.control.authority,
        pipeline.config.server.cluster.is_some(),
    )?;
    if pipeline.config.server.cluster.is_none() {
        if let Some((deployment, _)) = candidate
            .desired
            .deployments
            .iter()
            .find(|(_, deployment)| deployment.desired.replicas != 1)
        {
            anyhow::bail!(
                "single-node runtime requires deployment {deployment:?} to use replicas: 1"
            );
        }
    }
    Ok(())
}

fn validate_model_authority_context(
    authority: sbproxy_config::ModelHostAuthority,
    cluster_model_control: bool,
) -> anyhow::Result<()> {
    if cluster_model_control && authority == sbproxy_config::ModelHostAuthority::AdminManaged {
        anyhow::bail!(
            "model_host authority admin_managed cannot be combined with cluster model control; use cluster_authority for admin-published multi-node desired state"
        );
    }
    Ok(())
}

struct BuiltProductionManager {
    manager: Arc<sbproxy_model_host::ModelRuntimeManager>,
    snapshot_preparer: Arc<sbproxy_model_host::ProductionDeploymentPreparer>,
}

fn build_production_manager(
    catalog: Arc<Catalog>,
    cache_root: PathBuf,
) -> anyhow::Result<BuiltProductionManager> {
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
        preparer.clone(),
        capacities,
    )?
    .with_observer(Arc::new(MetricsObserver));
    Ok(BuiltProductionManager {
        manager: Arc::new(manager),
        snapshot_preparer: preparer,
    })
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
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    #[derive(Debug, Default)]
    struct ClusterFixtureProcess;

    #[async_trait::async_trait]
    impl sbproxy_model_host::EngineProcess for ClusterFixtureProcess {
        fn id(&self) -> Option<u32> {
            Some(17)
        }

        async fn has_exited(&self) -> Result<bool, sbproxy_model_host::EngineDriverError> {
            Ok(false)
        }

        async fn shutdown(
            &self,
            _grace: std::time::Duration,
        ) -> Result<(), sbproxy_model_host::EngineDriverError> {
            Ok(())
        }

        fn stderr_tail(&self) -> String {
            String::new()
        }
    }

    struct ClusterFixtureRuntime {
        deployment: String,
        generation: u64,
        stops: Arc<AtomicUsize>,
        fail_start: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl sbproxy_model_host::PreparedDeploymentRuntime for ClusterFixtureRuntime {
        async fn memory_estimate(
            &self,
            _intent: sbproxy_model_host::PullIntent,
        ) -> Result<sbproxy_model_host::MemoryEstimate, sbproxy_model_host::RuntimeManagerError>
        {
            Ok(sbproxy_model_host::MemoryEstimate::from_total(0, 1))
        }

        async fn start(
            &self,
            _intent: sbproxy_model_host::PullIntent,
        ) -> Result<sbproxy_model_host::RunningEngine, sbproxy_model_host::RuntimeManagerError>
        {
            if self.fail_start.load(Ordering::SeqCst) {
                return Err(sbproxy_model_host::RuntimeManagerError::Prepare(
                    "injected cluster start failure".to_string(),
                ));
            }
            Ok(sbproxy_model_host::RunningEngine {
                deployment: self.deployment.clone(),
                generation: self.generation,
                kind: sbproxy_model_host::EngineKind::LlamaCpp,
                port: 20_017,
                selected_devices: vec![0],
                accelerator: sbproxy_model_host::AcceleratorKind::Cpu,
                started_at_ms: 1,
                artifact_digest: "a".repeat(64),
                memory: sbproxy_model_host::MemoryEstimate::from_total(0, 1),
                process: Arc::new(ClusterFixtureProcess),
            })
        }

        async fn stop(
            &self,
            _grace: std::time::Duration,
        ) -> Result<(), sbproxy_model_host::RuntimeManagerError> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn reset(
            &self,
        ) -> Result<Option<sbproxy_model_host::OperationJob>, sbproxy_model_host::RuntimeManagerError>
        {
            Ok(None)
        }
    }

    #[derive(Default)]
    struct ClusterFixturePreparer {
        fail: AtomicBool,
        fail_start: Arc<AtomicBool>,
        stops: Arc<AtomicUsize>,
        block_prepare: AtomicBool,
        prepare_entered: tokio::sync::Notify,
        prepare_release: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl sbproxy_model_host::DeploymentPreparer for ClusterFixturePreparer {
        async fn prepare(
            &self,
            request: sbproxy_model_host::DeploymentPrepareRequest,
        ) -> Result<
            Arc<dyn sbproxy_model_host::PreparedDeploymentRuntime>,
            sbproxy_model_host::RuntimeManagerError,
        > {
            if self.block_prepare.load(Ordering::SeqCst) {
                self.prepare_entered.notify_one();
                self.prepare_release.notified().await;
            }
            if self.fail.load(Ordering::SeqCst) {
                return Err(sbproxy_model_host::RuntimeManagerError::Prepare(
                    "injected cluster prepare failure".to_string(),
                ));
            }
            Ok(Arc::new(ClusterFixtureRuntime {
                deployment: request.deployment_id,
                generation: request.generation,
                stops: self.stops.clone(),
                fail_start: self.fail_start.clone(),
            }))
        }
    }

    fn cluster_fixture_node() -> sbproxy_model_host::PlacementNode {
        use sbproxy_model_host::node_snapshot::{
            NodeDeviceSnapshot, NodeEngineSnapshot, NodeHealthState, NodeRole,
        };

        sbproxy_model_host::PlacementNode {
            node_id: "worker-a".to_string(),
            roles: BTreeSet::from([NodeRole::Worker]),
            health: NodeHealthState::Ready,
            labels: BTreeMap::from([("zone".to_string(), "a".to_string())]),
            model_endpoint: Some("https://worker-a.internal:9443".to_string()),
            placement_weight: 64_000,
            engines: vec![NodeEngineSnapshot {
                engine: sbproxy_model_host::EngineKind::LlamaCpp,
                availability: sbproxy_model_host::EngineAvailability::Available,
                version: Some("fixture".to_string()),
                artifact_formats: vec![sbproxy_model_host::ArtifactFormat::Gguf],
                accelerators: BTreeSet::from([sbproxy_model_host::AcceleratorKind::Cpu]),
                supports_container: false,
                supports_uv: false,
                reason_code: None,
            }],
            devices: vec![NodeDeviceSnapshot {
                index: 0,
                vendor: sbproxy_model_host::GpuVendor::Cpu,
                accelerator: Some(sbproxy_model_host::AcceleratorKind::Cpu),
                name: "host RAM".to_string(),
                total_memory_bytes: 64_000_000_000,
                available_memory_bytes: 64_000_000_000,
                compute_capability: None,
                supports_fp8: false,
                compute_utilization_millis: None,
                memory_occupancy_millis: None,
            }],
            artifacts: Vec::new(),
        }
    }

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

    fn admin_fixture_deployment() -> sbproxy_model_host::ModelDeployment {
        serde_yaml::from_str("model: qwen2.5-0.5b-instruct\nvariant: q4_k_m\npull: on_demand\n")
            .expect("fixture deployment")
    }

    fn admin_fixture_template(store_path: &Path) -> sbproxy_model_host::RuntimeDesiredState {
        sbproxy_model_host::compile_desired_state(
            sbproxy_model_host::RuntimeDesiredInput {
                source_revision: "admin-fixture-template".to_string(),
                canonical: Some(sbproxy_config::ModelHostControlConfig {
                    authority: sbproxy_config::ModelHostAuthority::AdminManaged,
                    store_path: Some(store_path.display().to_string()),
                    ..sbproxy_config::ModelHostControlConfig::default()
                }),
                managed_providers: Vec::new(),
                legacy_providers: Vec::new(),
            },
            &Catalog::builtin(),
        )
        .expect("admin fixture template")
    }

    async fn admin_fixture_runtime(
        store_path: &Path,
        preparer: Arc<ClusterFixturePreparer>,
    ) -> ProductionModelRuntime {
        let catalog = Arc::new(Catalog::builtin());
        let manager = Arc::new(
            sbproxy_model_host::ModelRuntimeManager::new(
                catalog.catalog_revision.clone(),
                preparer,
            )
            .expect("fixture manager"),
        );
        let prepared = manager
            .prepare_revision(admin_fixture_template(store_path))
            .await
            .expect("fixture admin revision prepares");
        manager
            .commit_revision(prepared)
            .await
            .expect("fixture admin revision commits");
        ProductionModelRuntime {
            active: ArcSwap::from(manager),
            active_catalog: ArcSwap::from(catalog),
            foundation: RwLock::new(None),
            snapshot_preparer: RwLock::new(None),
            cluster_state: RwLock::new(None),
            model_plane_health: AtomicU8::new(MODEL_PLANE_UNAVAILABLE),
            epoch: AtomicU64::new(0),
            commit_lock: tokio::sync::Mutex::new(()),
        }
    }

    #[tokio::test]
    async fn prepared_catalog_becomes_active_only_after_candidate_commit() {
        let runtime = Arc::new(ProductionModelRuntime::empty().expect("empty runtime"));
        let initial_revision = runtime.active_catalog().catalog_revision.clone();
        let mut catalog = Catalog::builtin();
        catalog.catalog_revision = "prepared-catalog-v2".to_string();
        let catalog = Arc::new(catalog);
        let desired = sbproxy_model_host::compile_desired_state(
            sbproxy_model_host::RuntimeDesiredInput {
                source_revision: "prepared-catalog-config".to_string(),
                canonical: None,
                managed_providers: Vec::new(),
                legacy_providers: Vec::new(),
            },
            &catalog,
        )
        .expect("catalog candidate desired state");
        let directory = tempfile::tempdir().expect("catalog candidate cache");

        let prepared = runtime
            .prepare_candidate(RuntimeCandidate {
                desired,
                catalog: Arc::clone(&catalog),
                cache_root: directory.path().to_path_buf(),
                authority_bundle: None,
            })
            .await
            .expect("catalog candidate prepares");

        assert_eq!(runtime.active_catalog().catalog_revision, initial_revision);
        runtime
            .commit(prepared)
            .await
            .expect("catalog candidate commits");
        assert_eq!(
            runtime.active_catalog().catalog_revision,
            "prepared-catalog-v2"
        );
    }

    #[tokio::test]
    async fn admin_revision_mutation_rejects_non_admin_authority() {
        let runtime = ProductionModelRuntime::empty().expect("empty runtime");

        let error = runtime
            .apply_admin_deployment_revision(None, BTreeMap::new())
            .await
            .expect_err("file-managed runtime is read-only to admin mutation");

        assert_eq!(
            error,
            AdminDeploymentRevisionError::AuthorityReadOnly {
                authority: sbproxy_config::ModelHostAuthority::FileManaged,
            }
        );
    }

    #[tokio::test]
    async fn admin_revision_mutation_maps_known_conflict_before_preparing() {
        let directory = tempfile::tempdir().unwrap();
        let store_path = directory.path().join("deployments.json");
        let store = sbproxy_model_host::FileDeploymentRevisionStore::open(&store_path).unwrap();
        let catalog_revision = Catalog::builtin().catalog_revision;
        store
            .compare_and_swap(
                None,
                sbproxy_model_host::DeploymentRevisionDraft {
                    source_mode: sbproxy_model_host::DeploymentSourceMode::AdminManaged,
                    source_revision: "existing-admin-revision".to_string(),
                    catalog_revision,
                    deployments: BTreeMap::from([(
                        "existing".to_string(),
                        admin_fixture_deployment(),
                    )]),
                },
            )
            .unwrap();
        let preparer = Arc::new(ClusterFixturePreparer::default());
        let runtime = admin_fixture_runtime(&store_path, preparer.clone()).await;

        let error = runtime
            .apply_admin_deployment_revision(
                None,
                BTreeMap::from([("replacement".to_string(), admin_fixture_deployment())]),
            )
            .await
            .expect_err("stale expected revision conflicts");

        assert_eq!(
            error,
            AdminDeploymentRevisionError::RevisionConflict {
                expected: None,
                actual: Some(1),
            }
        );
        let durable = store.load().unwrap().expect("existing durable revision");
        assert_eq!(durable.revision, 1);
        assert!(durable.deployments.contains_key("existing"));
        assert!(runtime
            .current_desired()
            .deployments
            .contains_key("existing"));
        assert_eq!(preparer.stops.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn admin_revision_max_stale_cursor_returns_conflict_before_increment() {
        let directory = tempfile::tempdir().unwrap();
        let store_path = directory.path().join("deployments.json");
        let store = sbproxy_model_host::FileDeploymentRevisionStore::open(&store_path).unwrap();
        store
            .compare_and_swap(
                None,
                sbproxy_model_host::DeploymentRevisionDraft {
                    source_mode: sbproxy_model_host::DeploymentSourceMode::AdminManaged,
                    source_revision: "existing-admin-revision".to_string(),
                    catalog_revision: Catalog::builtin().catalog_revision,
                    deployments: BTreeMap::new(),
                },
            )
            .unwrap();
        let preparer = Arc::new(ClusterFixturePreparer::default());
        let runtime = admin_fixture_runtime(&store_path, preparer.clone()).await;

        let error = runtime
            .apply_admin_deployment_revision(u64::MAX.into(), BTreeMap::new())
            .await
            .expect_err("stale maximum cursor conflicts with durable revision");

        assert_eq!(
            error,
            AdminDeploymentRevisionError::RevisionConflict {
                expected: Some(u64::MAX),
                actual: Some(1),
            }
        );
        assert_eq!(preparer.stops.load(Ordering::SeqCst), 0);
        assert_eq!(store.load().unwrap().expect("durable revision").revision, 1);
    }

    #[tokio::test]
    async fn admin_revision_keeps_durable_cas_safety_when_store_advances_during_prepare() {
        let directory = tempfile::tempdir().unwrap();
        let store_path = directory.path().join("deployments.json");
        let store = sbproxy_model_host::FileDeploymentRevisionStore::open(&store_path).unwrap();
        let catalog_revision = Catalog::builtin().catalog_revision;
        store
            .compare_and_swap(
                None,
                sbproxy_model_host::DeploymentRevisionDraft {
                    source_mode: sbproxy_model_host::DeploymentSourceMode::AdminManaged,
                    source_revision: "existing-admin-revision".to_string(),
                    catalog_revision: catalog_revision.clone(),
                    deployments: BTreeMap::from([(
                        "existing".to_string(),
                        admin_fixture_deployment(),
                    )]),
                },
            )
            .unwrap();
        let preparer = Arc::new(ClusterFixturePreparer::default());
        let runtime = Arc::new(admin_fixture_runtime(&store_path, preparer.clone()).await);
        preparer.block_prepare.store(true, Ordering::SeqCst);
        let apply = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                runtime
                    .apply_admin_deployment_revision(
                        Some(1),
                        BTreeMap::from([("replacement".to_string(), admin_fixture_deployment())]),
                    )
                    .await
            }
        });
        preparer.prepare_entered.notified().await;
        store
            .compare_and_swap(
                Some(1),
                sbproxy_model_host::DeploymentRevisionDraft {
                    source_mode: sbproxy_model_host::DeploymentSourceMode::AdminManaged,
                    source_revision: "concurrent-admin-revision".to_string(),
                    catalog_revision,
                    deployments: BTreeMap::from([(
                        "concurrent".to_string(),
                        admin_fixture_deployment(),
                    )]),
                },
            )
            .expect("concurrent writer advances the store past the expected cursor");
        preparer.block_prepare.store(false, Ordering::SeqCst);
        preparer.prepare_release.notify_one();

        let error = apply
            .await
            .expect("apply task")
            .expect_err("durable compare-and-swap rejects the prepared stale cursor");

        assert_eq!(
            error,
            AdminDeploymentRevisionError::RevisionConflict {
                expected: Some(1),
                actual: Some(2),
            }
        );
        let durable = store.load().unwrap().expect("concurrent durable revision");
        assert_eq!(durable.revision, 2);
        assert!(durable.deployments.contains_key("concurrent"));
        assert!(runtime
            .current_desired()
            .deployments
            .contains_key("existing"));
        assert_eq!(preparer.stops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn admin_revision_preparation_failure_leaves_store_and_runtime_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let store_path = directory.path().join("deployments.json");
        let store = sbproxy_model_host::FileDeploymentRevisionStore::open(&store_path).unwrap();
        let preparer = Arc::new(ClusterFixturePreparer::default());
        let runtime = admin_fixture_runtime(&store_path, preparer.clone()).await;
        preparer.fail.store(true, Ordering::SeqCst);

        let error = runtime
            .apply_admin_deployment_revision(
                None,
                BTreeMap::from([("broken".to_string(), admin_fixture_deployment())]),
            )
            .await
            .expect_err("injected preparation failure rejects candidate");

        assert!(matches!(
            error,
            AdminDeploymentRevisionError::Runtime(
                sbproxy_model_host::RuntimeManagerError::Prepare(ref message)
            ) if message.contains("injected cluster prepare failure")
        ));
        assert!(store.load().unwrap().is_none());
        assert!(runtime.current_desired().deployments.is_empty());
    }

    #[tokio::test]
    async fn admin_revision_reports_when_durable_state_advances_before_commit_failure() {
        let directory = tempfile::tempdir().unwrap();
        let store_path = directory.path().join("deployments.json");
        let store = sbproxy_model_host::FileDeploymentRevisionStore::open(&store_path).unwrap();
        let preparer = Arc::new(ClusterFixturePreparer::default());
        preparer.fail_start.store(true, Ordering::SeqCst);
        let runtime = admin_fixture_runtime(&store_path, preparer).await;
        let mut deployment = admin_fixture_deployment();
        deployment.warm = true;

        let error = runtime
            .apply_admin_deployment_revision(
                None,
                BTreeMap::from([("warm-failure".to_string(), deployment)]),
            )
            .await
            .expect_err("runtime commit fails after durable compare-and-swap");

        assert!(error.to_string().contains("durable state advanced"));
        let durable = store.load().unwrap().expect("durable revision committed");
        assert_eq!(durable.revision, 1);
        assert!(durable.deployments.contains_key("warm-failure"));
        assert!(runtime.current_desired().deployments.is_empty());
        assert_eq!(runtime.epoch.load(Ordering::SeqCst), 1);
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
    fn admin_managed_authority_is_rejected_when_cluster_model_control_is_active() {
        let error = validate_model_authority_context(
            sbproxy_config::ModelHostAuthority::AdminManaged,
            true,
        )
        .expect_err("cluster model control requires signed authority state");

        assert!(error
            .to_string()
            .contains("admin_managed cannot be combined with cluster model control"));
        assert!(validate_model_authority_context(
            sbproxy_config::ModelHostAuthority::ClusterAuthority,
            true
        )
        .is_ok());
        assert!(validate_model_authority_context(
            sbproxy_config::ModelHostAuthority::AdminManaged,
            false
        )
        .is_ok());
    }

    #[tokio::test]
    async fn control_only_empty_manager_accepts_the_global_custom_catalog() {
        let mut catalog = Catalog::builtin();
        catalog.catalog_revision = "control-only-catalog-v2".to_string();
        let desired = sbproxy_model_host::compile_desired_state(
            sbproxy_model_host::RuntimeDesiredInput {
                source_revision: "control-only-config".to_string(),
                canonical: None,
                managed_providers: Vec::new(),
                legacy_providers: Vec::new(),
            },
            &catalog,
        )
        .expect("empty control-only projection");
        let manager = empty_runtime_manager(catalog.catalog_revision.clone())
            .expect("catalog-aligned empty manager");

        let prepared = manager
            .prepare_revision(desired)
            .await
            .expect("custom catalog projection prepares");
        manager
            .commit_revision(prepared)
            .await
            .expect("custom catalog projection commits");

        assert_eq!(
            manager.current_desired().revision.catalog_revision,
            "control-only-catalog-v2"
        );
        assert!(manager.current_desired().deployments.is_empty());
    }

    #[tokio::test]
    async fn cluster_snapshot_reports_inventory_failure_as_stable_unhealthy_state() {
        let runtime = ProductionModelRuntime::empty().expect("empty runtime");
        let identity = sbproxy_mesh::ClusterIdentity {
            cluster_id: "cluster-a".to_string(),
            node_id: "worker-a".to_string(),
            roles: BTreeSet::from([sbproxy_mesh::ClusterNodeRole::Worker]),
            labels: BTreeMap::from([("zone".to_string(), "a".to_string())]),
            peer_address: Some("127.0.0.1:7946".to_string()),
            model_endpoint: Some("https://127.0.0.1:9443".to_string()),
        };

        let snapshot = runtime
            .node_model_snapshot(&identity, 3, 1_000, 31_000)
            .await
            .expect("bounded unhealthy snapshot");

        assert_eq!(
            snapshot.health.state,
            sbproxy_model_host::node_snapshot::NodeHealthState::Unhealthy
        );
        assert!(snapshot
            .health
            .reason_codes
            .contains(&"model_inventory_unavailable".to_string()));
        assert_eq!(snapshot.placement_weight, 0);
        assert!(snapshot.replicas.is_empty());
        snapshot.validate().expect("snapshot remains publishable");

        let gateway = sbproxy_mesh::ClusterIdentity {
            cluster_id: "cluster-a".to_string(),
            node_id: "gateway-a".to_string(),
            roles: BTreeSet::from([sbproxy_mesh::ClusterNodeRole::Gateway]),
            labels: BTreeMap::new(),
            peer_address: Some("127.0.0.1:7947".to_string()),
            model_endpoint: None,
        };
        let snapshot = runtime
            .node_model_snapshot(&gateway, 4, 2_000, 32_000)
            .await
            .expect("gateway snapshot");
        assert_eq!(
            snapshot.health.state,
            sbproxy_model_host::node_snapshot::NodeHealthState::Ready
        );
        assert!(snapshot.health.reason_codes.is_empty());
        assert_eq!(snapshot.placement_weight, 0);
    }

    #[tokio::test]
    async fn cluster_assignment_prepare_failure_preserves_prior_plan_and_runtime() {
        let catalog = Arc::new(Catalog::builtin());
        let global = sbproxy_model_host::compile_desired_state(
            sbproxy_model_host::RuntimeDesiredInput {
                source_revision: "cluster-fixture-1".to_string(),
                canonical: Some(
                    serde_yaml::from_str(
                        r#"
deployments:
  coder:
    model: qwen2.5-0.5b-instruct
    variant: q4_k_m
"#,
                    )
                    .expect("model host config"),
                ),
                managed_providers: Vec::new(),
                legacy_providers: Vec::new(),
            },
            &catalog,
        )
        .expect("global desired");
        let placement = sbproxy_model_host::reconcile_cluster_placement(
            &catalog,
            None,
            global,
            Vec::new(),
            &BTreeMap::new(),
            &sbproxy_model_host::DeploymentGenerationFences::default(),
            1_000,
        )
        .expect("initial unplaced state");
        let preparer = Arc::new(ClusterFixturePreparer::default());
        preparer.fail.store(true, Ordering::SeqCst);
        let manager = Arc::new(
            sbproxy_model_host::ModelRuntimeManager::new(
                catalog.catalog_revision.clone(),
                preparer.clone(),
            )
            .expect("fixture manager"),
        );
        let runtime = ProductionModelRuntime {
            active: ArcSwap::from(manager),
            active_catalog: ArcSwap::from(Arc::clone(&catalog)),
            foundation: RwLock::new(None),
            snapshot_preparer: RwLock::new(None),
            cluster_state: RwLock::new(Some(ClusterRuntimeState { placement, catalog })),
            model_plane_health: AtomicU8::new(MODEL_PLANE_UNAVAILABLE),
            epoch: AtomicU64::new(0),
            commit_lock: tokio::sync::Mutex::new(()),
        };
        let context = crate::cluster_models::ClusterModelContext {
            node_id: "worker-a".to_string(),
            is_worker: true,
        };
        let input = crate::cluster_models::DirectoryPlacementInput {
            nodes: vec![cluster_fixture_node()],
            observations: BTreeMap::new(),
            generation_fences: sbproxy_model_host::DeploymentGenerationFences::default(),
        };

        let error = runtime
            .reconcile_cluster_input(context.clone(), input.clone(), 1_100)
            .await
            .expect_err("injected prepare must abort the placement commit");
        assert!(error
            .to_string()
            .contains("injected cluster prepare failure"));
        assert!(runtime.current_desired().deployments.is_empty());
        assert!(runtime
            .cluster_placement_state()
            .expect("prior placement")
            .deployments()["coder"]
            .target
            .assignments
            .is_empty());

        preparer.fail.store(false, Ordering::SeqCst);
        assert!(runtime
            .reconcile_cluster_input(context, input, 1_200)
            .await
            .expect("retry succeeds"));
        assert!(runtime.current_desired().deployments.contains_key("coder"));
        assert_eq!(
            runtime.status("coder").await.expect("status").state,
            sbproxy_model_host::DeploymentRuntimeState::Ready
        );
        assert_eq!(
            runtime
                .cluster_placement_state()
                .expect("placement")
                .deployments()["coder"]
                .target
                .assignments[0]
                .node_id,
            "worker-a"
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
