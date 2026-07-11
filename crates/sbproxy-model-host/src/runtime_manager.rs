// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Process-wide managed model runtime and atomic desired-state reconciliation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use futures::future::{BoxFuture, FutureExt, Shared};
use futures::{stream, StreamExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore};

use crate::{
    AcceleratorKind, AcquireSource, AcquisitionContext, ArtifactFormat, ArtifactManager,
    BackoffPolicy, Catalog, CompiledDeployment, DeploymentRevisionDraft, DeploymentRoute,
    DeploymentSourceMode, EngineAccel, EngineAvailability, EngineDriver, EngineDriverError,
    EngineFailureReason, EngineKind, EngineLaunchMethod, EngineProvisioning,
    FileDeploymentRevisionStore, GpuProbe, KvCacheQuant, LaunchRequest, LegacyHostPolicy,
    LlamaCppDriver, ModelMetadata, ModelMetadataProvider, NetworkPolicy, OperationJob,
    ProvisionRequest, PullIntent, ResolveArtifactRequest, RunningEngine, RuntimeDesiredState,
    VllmDriver, WorkerProfile,
};

/// Reconciliation, preparation, or lifecycle failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeManagerError {
    /// Complete desired state failed validation.
    #[error("invalid runtime desired state: {0}")]
    InvalidDesired(String),
    /// Static deployment preparation failed.
    #[error("prepare deployment: {0}")]
    Prepare(String),
    /// Managed engine lifecycle failed.
    #[error(transparent)]
    Engine(#[from] EngineDriverError),
    /// Admin-managed desired-state store failed validation or loading.
    #[error("deployment store: {0}")]
    Store(String),
    /// Requested deployment is absent from the current revision.
    #[error("managed deployment {0:?} is not configured")]
    UnknownDeployment(String),
    /// Deployment is no longer accepting lifecycle work.
    #[error("managed deployment {0:?} is draining")]
    Draining(String),
    /// Prepared work was based on a revision that is no longer current.
    #[error("prepared revision is stale: based on {based_on}, current is {current}")]
    StalePrepared {
        /// Manager revision observed before preparation.
        based_on: u64,
        /// Manager revision at commit time.
        current: u64,
    },
    /// Manager revision or generation counter overflowed.
    #[error("model runtime counter overflow")]
    CounterOverflow,
}

/// Immutable input used to create one deployment runtime generation.
#[derive(Debug, Clone)]
pub struct DeploymentPrepareRequest {
    /// Canonical deployment ID.
    pub deployment_id: String,
    /// Monotonic process-local generation.
    pub generation: u64,
    /// Compiled deployment desired state.
    pub desired: CompiledDeployment,
    /// Canonical host-wide control policy.
    pub control: sbproxy_config::ModelHostControlConfig,
    /// Compatibility host policy for a legacy deployment.
    pub legacy_host_policy: Option<LegacyHostPolicy>,
}

/// Static deployment validation and runtime construction boundary.
#[async_trait]
pub trait DeploymentPreparer: Send + Sync {
    /// Resolve capabilities and construct one cold runtime generation.
    async fn prepare(
        &self,
        request: DeploymentPrepareRequest,
    ) -> Result<Arc<dyn PreparedDeploymentRuntime>, RuntimeManagerError>;
}

/// One statically validated deployment generation that can be started and stopped.
#[async_trait]
pub trait PreparedDeploymentRuntime: Send + Sync {
    /// Acquire verified artifacts, provision the engine, and reach readiness.
    async fn start(&self, intent: PullIntent) -> Result<RunningEngine, RuntimeManagerError>;
    /// Stop this generation, if it is running.
    async fn stop(&self, grace: Duration) -> Result<(), RuntimeManagerError>;
    /// Clear retained failure state before another explicit start.
    async fn reset(&self) -> Result<Option<OperationJob>, RuntimeManagerError>;
}

/// Planned relationship between current and candidate deployment slots.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReconcilePlan {
    /// New deployment IDs.
    pub added: Vec<String>,
    /// Deployment IDs whose complete desired state changed.
    pub changed: Vec<String>,
    /// Deployment IDs absent from the candidate.
    pub removed: Vec<String>,
    /// Deployment IDs whose exact runtime generation is reused.
    pub preserved: Vec<String>,
}

/// Result of one committed desired-state revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReconcileReport {
    /// New process-local manager revision.
    pub revision: u64,
    /// Deterministic add, change, remove, and preserve plan.
    pub plan: ReconcilePlan,
    /// Retired generations that failed bounded shutdown after the swap.
    pub retire_failures: BTreeMap<String, String>,
}

/// Public lifecycle state for one configured deployment generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentRuntimeState {
    /// Statically validated but not loaded.
    Configured,
    /// Artifact, engine, or model readiness is in progress.
    Preparing,
    /// Engine is ready on its loopback port.
    Ready,
    /// New lifecycle work is blocked while the generation stops.
    Draining,
    /// Generation has stopped and may be explicitly started again.
    Stopped,
    /// Preparation or launch failed and requires reset or reconciliation.
    Failed,
}

/// Point-in-time lifecycle status for one current deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentRuntimeStatus {
    /// Canonical deployment ID.
    pub deployment: String,
    /// Process-local generation.
    pub generation: u64,
    /// Current lifecycle state.
    pub state: DeploymentRuntimeState,
    /// Ready loopback port.
    pub port: Option<u16>,
    /// Bounded last failure, when state is failed.
    pub last_error: Option<String>,
}

type Activation = Shared<BoxFuture<'static, Result<RunningEngine, RuntimeManagerError>>>;

struct SlotLifecycle {
    state: DeploymentRuntimeState,
    running: Option<RunningEngine>,
    last_error: Option<RuntimeManagerError>,
    activation: Option<Activation>,
}

struct DeploymentSlot {
    id: String,
    generation: u64,
    desired: CompiledDeployment,
    preparation_identity: PreparationIdentity,
    runtime: Arc<dyn PreparedDeploymentRuntime>,
    lifecycle: Mutex<SlotLifecycle>,
}

impl std::fmt::Debug for DeploymentSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeploymentSlot")
            .field("id", &self.id)
            .field("generation", &self.generation)
            .field("desired", &self.desired)
            .finish_non_exhaustive()
    }
}

impl DeploymentSlot {
    fn new(
        id: String,
        generation: u64,
        desired: CompiledDeployment,
        preparation_identity: PreparationIdentity,
        runtime: Arc<dyn PreparedDeploymentRuntime>,
    ) -> Self {
        Self {
            id,
            generation,
            desired,
            preparation_identity,
            runtime,
            lifecycle: Mutex::new(SlotLifecycle {
                state: DeploymentRuntimeState::Configured,
                running: None,
                last_error: None,
                activation: None,
            }),
        }
    }

    async fn ensure_ready(
        &self,
        intent: PullIntent,
        limiter: Arc<Semaphore>,
    ) -> Result<RunningEngine, RuntimeManagerError> {
        let activation = {
            let mut lifecycle = self.lifecycle.lock().await;
            match lifecycle.state {
                DeploymentRuntimeState::Ready => {
                    return lifecycle.running.clone().ok_or_else(|| {
                        RuntimeManagerError::Prepare(format!(
                            "deployment {:?} is ready without a running engine",
                            self.id
                        ))
                    });
                }
                DeploymentRuntimeState::Preparing => {
                    lifecycle.activation.clone().ok_or_else(|| {
                        RuntimeManagerError::Prepare(format!(
                            "deployment {:?} is preparing without shared work",
                            self.id
                        ))
                    })?
                }
                DeploymentRuntimeState::Draining => {
                    return Err(RuntimeManagerError::Draining(self.id.clone()));
                }
                DeploymentRuntimeState::Failed => {
                    return Err(lifecycle.last_error.clone().unwrap_or_else(|| {
                        RuntimeManagerError::Prepare(format!(
                            "deployment {:?} failed without a retained reason",
                            self.id
                        ))
                    }));
                }
                DeploymentRuntimeState::Configured | DeploymentRuntimeState::Stopped => {
                    let runtime = self.runtime.clone();
                    let future = async move {
                        let _permit = limiter.acquire_owned().await.map_err(|_| {
                            RuntimeManagerError::Prepare(
                                "model preparation limiter is closed".to_string(),
                            )
                        })?;
                        runtime.start(intent).await
                    }
                    .boxed()
                    .shared();
                    lifecycle.state = DeploymentRuntimeState::Preparing;
                    lifecycle.last_error = None;
                    lifecycle.activation = Some(future.clone());
                    future
                }
            }
        };

        let result = activation.await.and_then(|running| {
            if running.deployment != self.id || running.generation != self.generation {
                return Err(RuntimeManagerError::Prepare(format!(
                    "deployment runtime returned identity {:?}/{} for {:?}/{}",
                    running.deployment, running.generation, self.id, self.generation
                )));
            }
            Ok(running)
        });
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.activation.is_none() {
            return result;
        }
        lifecycle.activation = None;
        match &result {
            Ok(running) => {
                lifecycle.running = Some(running.clone());
                lifecycle.last_error = None;
                if lifecycle.state != DeploymentRuntimeState::Draining {
                    lifecycle.state = DeploymentRuntimeState::Ready;
                }
            }
            Err(error) => {
                lifecycle.running = None;
                lifecycle.last_error = Some(error.clone());
                if lifecycle.state != DeploymentRuntimeState::Draining {
                    lifecycle.state = DeploymentRuntimeState::Failed;
                }
            }
        }
        result
    }

    async fn stop(&self, grace: Duration) -> Result<(), RuntimeManagerError> {
        let activation = {
            let mut lifecycle = self.lifecycle.lock().await;
            if lifecycle.state == DeploymentRuntimeState::Stopped {
                return Ok(());
            }
            lifecycle.state = DeploymentRuntimeState::Draining;
            lifecycle.activation.clone()
        };
        if let Some(activation) = activation {
            let _ = activation.await;
        }
        let result = self.runtime.stop(grace).await;
        let mut lifecycle = self.lifecycle.lock().await;
        lifecycle.activation = None;
        lifecycle.running = None;
        match &result {
            Ok(()) => {
                lifecycle.state = DeploymentRuntimeState::Stopped;
                lifecycle.last_error = None;
            }
            Err(error) => {
                lifecycle.state = DeploymentRuntimeState::Failed;
                lifecycle.last_error = Some(error.clone());
            }
        }
        result
    }

    async fn reset(&self) -> Result<Option<OperationJob>, RuntimeManagerError> {
        {
            let lifecycle = self.lifecycle.lock().await;
            if lifecycle.state == DeploymentRuntimeState::Preparing
                || lifecycle.state == DeploymentRuntimeState::Draining
            {
                return Err(RuntimeManagerError::Draining(self.id.clone()));
            }
        }
        let job = self.runtime.reset().await?;
        let mut lifecycle = self.lifecycle.lock().await;
        lifecycle.state = DeploymentRuntimeState::Configured;
        lifecycle.running = None;
        lifecycle.last_error = None;
        lifecycle.activation = None;
        Ok(job)
    }

    async fn status(&self) -> DeploymentRuntimeStatus {
        let lifecycle = self.lifecycle.lock().await;
        DeploymentRuntimeStatus {
            deployment: self.id.clone(),
            generation: self.generation,
            state: lifecycle.state,
            port: lifecycle.running.as_ref().map(|running| running.port),
            last_error: lifecycle.last_error.as_ref().map(ToString::to_string),
        }
    }
}

struct RuntimeSnapshot {
    revision: u64,
    desired: Arc<RuntimeDesiredState>,
    slots: BTreeMap<String, Arc<DeploymentSlot>>,
    limiter: Arc<Semaphore>,
}

impl std::fmt::Debug for RuntimeSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeSnapshot")
            .field("revision", &self.revision)
            .field("desired", &self.desired)
            .field("slots", &self.slots.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Complete, staged revision that has not yet changed live routing.
pub struct PreparedRevision {
    base_revision: u64,
    desired: Arc<RuntimeDesiredState>,
    /// Deterministic reconciliation plan.
    pub plan: ReconcilePlan,
    staged_slots: BTreeMap<String, Arc<DeploymentSlot>>,
    limiter: Arc<Semaphore>,
}

impl std::fmt::Debug for PreparedRevision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedRevision")
            .field("base_revision", &self.base_revision)
            .field("source_revision", &self.desired.revision.source_revision)
            .field("plan", &self.plan)
            .field(
                "staged_slots",
                &self.staged_slots.keys().collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// One process-wide runtime handle that survives empty startup and every reload.
pub struct ModelRuntimeManager {
    expected_catalog_revision: String,
    preparer: Arc<dyn DeploymentPreparer>,
    snapshot: ArcSwap<RuntimeSnapshot>,
    generation: AtomicU64,
    reconcile_lock: Mutex<()>,
}

/// Production deployment preparer over the catalog, artifact cache, probes, and typed drivers.
pub struct ProductionDeploymentPreparer {
    catalog: Arc<Catalog>,
    artifacts: Arc<ArtifactManager>,
    probe: Arc<dyn GpuProbe>,
    metadata: Arc<dyn ModelMetadataProvider>,
    drivers: BTreeMap<EngineKind, Arc<dyn EngineDriver>>,
    network_policy: NetworkPolicy,
    backoff: BackoffPolicy,
}

impl std::fmt::Debug for ProductionDeploymentPreparer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionDeploymentPreparer")
            .field("catalog_revision", &self.catalog.catalog_revision)
            .field("drivers", &self.drivers.keys().collect::<Vec<_>>())
            .field("network_policy", &self.network_policy)
            .field("backoff", &self.backoff)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ModelRuntimeManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ModelRuntimeManager")
            .field("expected_catalog_revision", &self.expected_catalog_revision)
            .field("snapshot", &self.snapshot.load())
            .finish_non_exhaustive()
    }
}

impl ModelRuntimeManager {
    /// Create the permanent process-wide handle with an empty desired revision.
    pub fn new(
        catalog_revision: impl Into<String>,
        preparer: Arc<dyn DeploymentPreparer>,
    ) -> Result<Self, RuntimeManagerError> {
        let catalog_revision = catalog_revision.into();
        if catalog_revision.trim().is_empty() {
            return Err(RuntimeManagerError::InvalidDesired(
                "catalog revision must not be empty".to_string(),
            ));
        }
        let desired = Arc::new(empty_desired_state(&catalog_revision)?);
        let snapshot = RuntimeSnapshot {
            revision: 0,
            desired,
            slots: BTreeMap::new(),
            limiter: Arc::new(Semaphore::new(2)),
        };
        Ok(Self {
            expected_catalog_revision: catalog_revision,
            preparer,
            snapshot: ArcSwap::from_pointee(snapshot),
            generation: AtomicU64::new(1),
            reconcile_lock: Mutex::new(()),
        })
    }

    /// Current process-local committed revision number.
    pub fn current_revision(&self) -> u64 {
        self.snapshot.load().revision
    }

    /// Current atomic desired-state snapshot.
    pub fn current_desired(&self) -> Arc<RuntimeDesiredState> {
        self.snapshot.load_full().desired.clone()
    }

    /// Resolve one current route without observing a partially committed revision.
    pub fn route_for(&self, origin: &str, provider: &str, model: &str) -> Option<DeploymentRoute> {
        self.snapshot
            .load()
            .desired
            .route_for(origin, provider, model)
            .cloned()
    }

    /// Prepare a complete candidate without changing current routes or slots.
    pub async fn prepare_revision(
        &self,
        desired: RuntimeDesiredState,
    ) -> Result<PreparedRevision, RuntimeManagerError> {
        let desired = self.normalize_candidate(desired)?;
        validate_desired_state(&desired, &self.expected_catalog_revision)?;
        let current = self.snapshot.load_full();
        let plan = plan_reconciliation(&current, &desired);
        let limiter = Arc::new(Semaphore::new(desired.control.max_parallel_prepares));

        let mut requests = Vec::new();
        for id in plan.added.iter().chain(plan.changed.iter()) {
            let generation = self
                .generation
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| RuntimeManagerError::CounterOverflow)?;
            let compiled = desired.deployments.get(id).ok_or_else(|| {
                RuntimeManagerError::InvalidDesired(format!(
                    "reconcile plan references absent deployment {id:?}"
                ))
            })?;
            requests.push(DeploymentPrepareRequest {
                deployment_id: id.clone(),
                generation,
                desired: compiled.clone(),
                control: desired.control.clone(),
                legacy_host_policy: desired.legacy_host_policy.clone(),
            });
        }

        let parallelism = desired.control.max_parallel_prepares;
        let preparer = self.preparer.clone();
        let warm_ids = desired
            .deployments
            .iter()
            .filter_map(|(id, deployment)| deployment.desired.warm.then_some(id.clone()))
            .collect::<BTreeSet<_>>();
        let shutdown_grace = Duration::from_millis(desired.control.shutdown_deadline_ms);
        let mut preparations = stream::iter(requests)
            .map(|request| {
                let preparer = preparer.clone();
                let limiter = limiter.clone();
                let warm = warm_ids.contains(&request.deployment_id);
                async move {
                    let id = request.deployment_id.clone();
                    let generation = request.generation;
                    let desired = request.desired.clone();
                    let preparation_identity = PreparationIdentity::from_request(&request);
                    let permit = limiter.clone().acquire_owned().await.map_err(|_| {
                        RuntimeManagerError::Prepare(
                            "model preparation limiter is closed".to_string(),
                        )
                    })?;
                    let runtime = preparer.prepare(request).await?;
                    drop(permit);
                    let slot = Arc::new(DeploymentSlot::new(
                        id.clone(),
                        generation,
                        desired,
                        preparation_identity,
                        runtime,
                    ));
                    if warm {
                        if let Err(error) = slot.ensure_ready(PullIntent::Startup, limiter).await {
                            let _ = slot.stop(shutdown_grace).await;
                            return Err(error);
                        }
                    }
                    Ok::<_, RuntimeManagerError>((id, slot))
                }
            })
            .buffer_unordered(parallelism);

        let mut staged_slots = BTreeMap::new();
        let mut first_error = None;
        while let Some(result) = preparations.next().await {
            match result {
                Ok((id, slot)) => {
                    staged_slots.insert(id, slot);
                }
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        drop(preparations);
        if let Some(error) = first_error {
            teardown_slots(
                staged_slots.values().cloned().collect(),
                Duration::from_millis(desired.control.shutdown_deadline_ms),
            )
            .await;
            return Err(error);
        }

        Ok(PreparedRevision {
            base_revision: current.revision,
            desired: Arc::new(desired),
            plan,
            staged_slots,
            limiter,
        })
    }

    /// Atomically publish one prepared revision and retire superseded slots.
    pub async fn commit_revision(
        &self,
        prepared: PreparedRevision,
    ) -> Result<ReconcileReport, RuntimeManagerError> {
        let _guard = self.reconcile_lock.lock().await;
        self.commit_prepared(prepared).await
    }

    /// Prepare and commit one complete revision under a single transaction lock.
    pub async fn reconcile(
        &self,
        desired: RuntimeDesiredState,
    ) -> Result<ReconcileReport, RuntimeManagerError> {
        let _guard = self.reconcile_lock.lock().await;
        let prepared = self.prepare_revision(desired).await?;
        self.commit_prepared(prepared).await
    }

    /// Tear down a prepared revision without publishing it.
    pub async fn abort_prepared(&self, prepared: PreparedRevision) {
        teardown_slots(
            prepared.staged_slots.into_values().collect(),
            Duration::from_millis(prepared.desired.control.shutdown_deadline_ms),
        )
        .await;
    }

    /// Bring one current deployment generation to ready.
    pub async fn ensure_ready(
        &self,
        deployment: &str,
    ) -> Result<RunningEngine, RuntimeManagerError> {
        let snapshot = self.snapshot.load_full();
        let slot = snapshot
            .slots
            .get(deployment)
            .cloned()
            .ok_or_else(|| RuntimeManagerError::UnknownDeployment(deployment.to_string()))?;
        slot.ensure_ready(PullIntent::Runtime, snapshot.limiter.clone())
            .await
    }

    /// Stop one current deployment generation.
    pub async fn stop(&self, deployment: &str) -> Result<(), RuntimeManagerError> {
        let snapshot = self.snapshot.load_full();
        let slot = snapshot
            .slots
            .get(deployment)
            .cloned()
            .ok_or_else(|| RuntimeManagerError::UnknownDeployment(deployment.to_string()))?;
        slot.stop(Duration::from_millis(
            snapshot.desired.control.shutdown_deadline_ms,
        ))
        .await
    }

    /// Clear one current deployment's retained failure state.
    pub async fn reset(
        &self,
        deployment: &str,
    ) -> Result<Option<OperationJob>, RuntimeManagerError> {
        let snapshot = self.snapshot.load_full();
        let slot = snapshot
            .slots
            .get(deployment)
            .cloned()
            .ok_or_else(|| RuntimeManagerError::UnknownDeployment(deployment.to_string()))?;
        slot.reset().await
    }

    /// Snapshot every current deployment status in deterministic ID order.
    pub async fn statuses(&self) -> Vec<DeploymentRuntimeStatus> {
        let slots = self
            .snapshot
            .load_full()
            .slots
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut statuses = Vec::with_capacity(slots.len());
        for slot in slots {
            statuses.push(slot.status().await);
        }
        statuses
    }

    /// Snapshot one current deployment status.
    pub async fn status(&self, deployment: &str) -> Option<DeploymentRuntimeStatus> {
        let slot = self.snapshot.load_full().slots.get(deployment).cloned()?;
        Some(slot.status().await)
    }

    async fn commit_prepared(
        &self,
        mut prepared: PreparedRevision,
    ) -> Result<ReconcileReport, RuntimeManagerError> {
        let current = self.snapshot.load_full();
        if current.revision != prepared.base_revision {
            let error = RuntimeManagerError::StalePrepared {
                based_on: prepared.base_revision,
                current: current.revision,
            };
            teardown_slots(
                prepared.staged_slots.into_values().collect(),
                Duration::from_millis(prepared.desired.control.shutdown_deadline_ms),
            )
            .await;
            return Err(error);
        }
        let next_revision = current
            .revision
            .checked_add(1)
            .ok_or(RuntimeManagerError::CounterOverflow)?;
        let preserved = prepared
            .plan
            .preserved
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let mut slots = BTreeMap::new();
        for id in prepared.desired.deployments.keys() {
            let slot = if preserved.contains(id.as_str()) {
                current.slots.get(id).cloned()
            } else {
                prepared.staged_slots.remove(id)
            }
            .ok_or_else(|| {
                RuntimeManagerError::Prepare(format!(
                    "prepared revision has no runtime slot for {id:?}"
                ))
            })?;
            slots.insert(id.clone(), slot);
        }

        let retired = current
            .slots
            .iter()
            .filter_map(|(id, old)| {
                slots
                    .get(id)
                    .is_none_or(|new| !Arc::ptr_eq(old, new))
                    .then_some((id.clone(), old.clone()))
            })
            .collect::<Vec<_>>();
        self.snapshot.store(Arc::new(RuntimeSnapshot {
            revision: next_revision,
            desired: prepared.desired.clone(),
            slots,
            limiter: prepared.limiter,
        }));

        let grace = Duration::from_millis(prepared.desired.control.shutdown_deadline_ms);
        let mut retire_failures = BTreeMap::new();
        for (id, slot) in retired {
            if let Err(error) = slot.stop(grace).await {
                retire_failures.insert(id, error.to_string());
            }
        }
        Ok(ReconcileReport {
            revision: next_revision,
            plan: prepared.plan,
            retire_failures,
        })
    }

    fn normalize_candidate(
        &self,
        desired: RuntimeDesiredState,
    ) -> Result<RuntimeDesiredState, RuntimeManagerError> {
        if desired.revision.source_mode != DeploymentSourceMode::AdminManaged {
            return Ok(desired);
        }
        load_admin_candidate(desired, &self.expected_catalog_revision)
    }
}

impl ProductionDeploymentPreparer {
    /// Construct the production preparer with the managed llama.cpp and vLLM drivers.
    pub fn new(
        catalog: Arc<Catalog>,
        artifacts: Arc<ArtifactManager>,
        probe: Arc<dyn GpuProbe>,
        metadata: Arc<dyn ModelMetadataProvider>,
        network_policy: NetworkPolicy,
    ) -> Self {
        let drivers: BTreeMap<EngineKind, Arc<dyn EngineDriver>> = BTreeMap::from([
            (
                EngineKind::LlamaCpp,
                Arc::new(LlamaCppDriver::default()) as Arc<dyn EngineDriver>,
            ),
            (
                EngineKind::Vllm,
                Arc::new(VllmDriver::default()) as Arc<dyn EngineDriver>,
            ),
        ]);
        Self {
            catalog,
            artifacts,
            probe,
            metadata,
            drivers,
            network_policy,
            backoff: BackoffPolicy::default(),
        }
    }

    /// Replace the driver registry for deterministic integration tests.
    pub fn with_drivers(mut self, drivers: BTreeMap<EngineKind, Arc<dyn EngineDriver>>) -> Self {
        self.drivers = drivers;
        self
    }

    /// Override the bounded launch retry policy.
    pub fn with_backoff(mut self, backoff: BackoffPolicy) -> Self {
        self.backoff = backoff;
        self
    }
}

#[async_trait]
impl DeploymentPreparer for ProductionDeploymentPreparer {
    async fn prepare(
        &self,
        request: DeploymentPrepareRequest,
    ) -> Result<Arc<dyn PreparedDeploymentRuntime>, RuntimeManagerError> {
        if request.desired.desired.replicas != 1 {
            return Err(RuntimeManagerError::Prepare(format!(
                "single-node runtime requires deployment {:?} to use replicas: 1",
                request.deployment_id
            )));
        }
        let worker = WorkerProfile::from_descriptors(&self.probe.probe())
            .map_err(RuntimeManagerError::Prepare)?;
        let resolved = self
            .catalog
            .resolve_artifact(
                &ResolveArtifactRequest {
                    model: request.desired.desired.model.clone(),
                    variant: request.desired.desired.variant.clone(),
                    engine: request.desired.desired.engine,
                    replicas: request.desired.desired.replicas,
                    heterogeneous_variants: request.desired.desired.heterogeneous_variants,
                },
                &worker,
            )
            .map_err(|error| RuntimeManagerError::Prepare(error.to_string()))?;
        let driver = self.drivers.get(&resolved.engine).cloned().ok_or_else(|| {
            RuntimeManagerError::Prepare(format!(
                "no managed {:?} driver is registered for deployment {:?}",
                resolved.engine, request.deployment_id
            ))
        })?;
        let provisioning = provisioning_for(&request, resolved.engine);
        let detection = driver.detect(&worker, &provisioning);
        match detection.availability {
            EngineAvailability::Available | EngineAvailability::Acquirable => {}
            EngineAvailability::Incompatible => {
                return Err(RuntimeManagerError::Engine(EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    detection.reason,
                    detection.remediation.unwrap_or_else(|| {
                        "select a compatible artifact, engine, and worker".to_string()
                    }),
                    false,
                )));
            }
            EngineAvailability::Blocked => {
                return Err(RuntimeManagerError::Engine(EngineDriverError::blocked(
                    detection.reason,
                    detection.remediation.unwrap_or_else(|| {
                        "repair the managed engine provisioning policy".to_string()
                    }),
                )));
            }
        }
        let params_fallback = self
            .catalog
            .get(&resolved.logical_model)
            .map(|entry| crate::parse_params(&entry.params))
            .unwrap_or(0);
        let engine_cache_dir =
            crate::resolve_cache_dir_default(request.control.cache.directory.as_deref())
                .join("engines");
        let supervisor = crate::EngineSupervisor::new(
            request.deployment_id.clone(),
            driver,
            self.backoff,
            Some(self.artifacts.jobs().clone()),
        );
        Ok(Arc::new(ProductionPreparedDeployment {
            id: request.deployment_id,
            generation: request.generation,
            desired: request.desired,
            resolved,
            worker,
            provisioning,
            engine_cache_dir,
            artifacts: self.artifacts.clone(),
            probe: self.probe.clone(),
            metadata: self.metadata.clone(),
            network_policy: self.network_policy,
            params_fallback,
            supervisor: Mutex::new(supervisor),
        }))
    }
}

struct ProductionPreparedDeployment {
    id: String,
    generation: u64,
    desired: CompiledDeployment,
    resolved: crate::ResolvedArtifact,
    worker: WorkerProfile,
    provisioning: EngineProvisioning,
    engine_cache_dir: std::path::PathBuf,
    artifacts: Arc<ArtifactManager>,
    probe: Arc<dyn GpuProbe>,
    metadata: Arc<dyn ModelMetadataProvider>,
    network_policy: NetworkPolicy,
    params_fallback: u64,
    supervisor: Mutex<crate::EngineSupervisor>,
}

impl std::fmt::Debug for ProductionPreparedDeployment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionPreparedDeployment")
            .field("id", &self.id)
            .field("generation", &self.generation)
            .field("desired", &self.desired)
            .field("resolved", &self.resolved)
            .field("worker", &self.worker)
            .field("provisioning", &self.provisioning)
            .field("engine_cache_dir", &self.engine_cache_dir)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PreparedDeploymentRuntime for ProductionPreparedDeployment {
    async fn start(&self, intent: PullIntent) -> Result<RunningEngine, RuntimeManagerError> {
        let pull_policy = self.desired.desired.pull;
        let artifact_intent =
            if intent == PullIntent::Startup && pull_policy != crate::PullPolicy::OnBoot {
                PullIntent::Runtime
            } else {
                intent
            };
        let ready = self
            .artifacts
            .ensure(
                &self.resolved,
                AcquisitionContext {
                    intent: artifact_intent,
                    network: self.network_policy,
                    pull_policy,
                    credential: None,
                },
            )
            .await
            .map_err(|error| RuntimeManagerError::Prepare(error.to_string()))?;
        let metadata = ready_metadata(
            self.metadata.as_ref(),
            &self.resolved,
            &ready,
            self.params_fallback,
        )
        .await
        .ok_or_else(|| {
            RuntimeManagerError::Prepare(format!(
                "verified artifact {} has no usable model shape metadata",
                self.resolved.artifact_digest
            ))
        })?;
        let seq_len = self
            .desired
            .legacy_entry
            .as_ref()
            .and_then(|entry| entry.max_context)
            .unwrap_or(self.resolved.context_length.max(1));
        let kv_quant = self
            .desired
            .legacy_entry
            .as_ref()
            .map(|entry| entry.kv_quant)
            .unwrap_or(KvCacheQuant::Auto);
        let fit = crate::fit::plan_fit_auto_kv(
            self.probe.as_ref(),
            &metadata,
            std::slice::from_ref(&self.resolved.quant),
            seq_len,
            crate::fit::DEFAULT_OVERHEAD,
            kv_quant.bytes_per_element(),
        )
        .map_err(|error| RuntimeManagerError::Prepare(error.to_string()))?;
        let selected_devices = if self.worker.accelerator == AcceleratorKind::Cpu {
            Vec::new()
        } else {
            vec![fit.gpu_index]
        };
        let extra_args = self
            .desired
            .legacy_entry
            .as_ref()
            .map(|entry| entry.extra_args.clone())
            .unwrap_or_default();
        let mut supervisor = self.supervisor.lock().await;
        let provisioned = supervisor
            .provision(&ProvisionRequest {
                artifact: self.resolved.clone(),
                worker: self.worker.clone(),
                provisioning: self.provisioning.clone(),
                engine_cache_dir: self.engine_cache_dir.clone(),
                job_store: Some(self.artifacts.jobs().clone()),
            })
            .await?;
        let port = allocate_loopback_port()?;
        supervisor
            .ensure_ready(
                &provisioned,
                &LaunchRequest {
                    deployment: self.id.clone(),
                    generation: self.generation,
                    artifact: ready,
                    fit,
                    port,
                    selected_devices,
                    kv_quant,
                    extra_args,
                    ready_timeout: Duration::from_secs(300),
                },
            )
            .await
            .map_err(RuntimeManagerError::Engine)
    }

    async fn stop(&self, grace: Duration) -> Result<(), RuntimeManagerError> {
        self.supervisor
            .lock()
            .await
            .shutdown(grace)
            .await
            .map(|_| ())
            .map_err(RuntimeManagerError::Engine)
    }

    async fn reset(&self) -> Result<Option<OperationJob>, RuntimeManagerError> {
        self.supervisor
            .lock()
            .await
            .reset()
            .map_err(RuntimeManagerError::Engine)
    }
}

fn provisioning_for(request: &DeploymentPrepareRequest, kind: EngineKind) -> EngineProvisioning {
    if request.desired.origin == crate::DesiredDeploymentOrigin::LegacyServe {
        return request
            .legacy_host_policy
            .as_ref()
            .and_then(|policy| policy.engines.get(&kind))
            .cloned()
            .unwrap_or_default();
    }
    let managed_kind = match kind {
        EngineKind::Vllm => sbproxy_config::ManagedEngineKind::Vllm,
        EngineKind::LlamaCpp => sbproxy_config::ManagedEngineKind::LlamaCpp,
        EngineKind::Embedded => return EngineProvisioning::default(),
    };
    let Some(config) = request.control.engines.get(&managed_kind) else {
        return EngineProvisioning::default();
    };
    let launch = match config.launch {
        sbproxy_config::ManagedEngineLaunch::Binary => EngineLaunchMethod::Binary,
        sbproxy_config::ManagedEngineLaunch::Container => EngineLaunchMethod::Container,
        sbproxy_config::ManagedEngineLaunch::Uv => EngineLaunchMethod::Venv,
    };
    let accel = match config.acceleration {
        sbproxy_config::ManagedEngineAcceleration::Auto => EngineAccel::Auto,
        sbproxy_config::ManagedEngineAcceleration::Cuda => EngineAccel::Cuda,
        sbproxy_config::ManagedEngineAcceleration::Metal => EngineAccel::Metal,
        sbproxy_config::ManagedEngineAcceleration::Vulkan => EngineAccel::Vulkan,
        sbproxy_config::ManagedEngineAcceleration::Cpu => EngineAccel::Cpu,
    };
    let acquire = match config.launch {
        sbproxy_config::ManagedEngineLaunch::Uv => Some(crate::EngineAcquire {
            source: AcquireSource::Uvx,
            version: config.version.clone(),
            accel,
            path: None,
            sha256: config.sha256.clone(),
        }),
        sbproxy_config::ManagedEngineLaunch::Binary
            if config.path.is_some()
                || config.version.is_some()
                || config.sha256.is_some()
                || config.acceleration != sbproxy_config::ManagedEngineAcceleration::Auto =>
        {
            Some(crate::EngineAcquire {
                source: if config.path.is_some() {
                    AcquireSource::Path
                } else {
                    AcquireSource::Release
                },
                version: config.version.clone(),
                accel,
                path: config.path.clone(),
                sha256: config.sha256.clone(),
            })
        }
        _ => None,
    };
    EngineProvisioning {
        launch,
        image: config.image.clone(),
        acquire,
        shm_size_gib: config.shm_size_gib,
    }
}

async fn ready_metadata(
    provider: &dyn ModelMetadataProvider,
    artifact: &crate::ResolvedArtifact,
    ready: &crate::ReadyArtifact,
    params_fallback: u64,
) -> Option<ModelMetadata> {
    if artifact.format == ArtifactFormat::Gguf {
        let path = artifact
            .files
            .iter()
            .find(|file| file.path.to_ascii_lowercase().ends_with(".gguf"))
            .and_then(|file| ready.file(&file.path));
        if let Some(path) = path {
            if let Some(metadata) = read_gguf_metadata(path, params_fallback).await {
                return Some(metadata);
            }
        }
    }
    provider.metadata_for_artifact(artifact, ready)
}

async fn read_gguf_metadata(path: &std::path::Path, params_fallback: u64) -> Option<ModelMetadata> {
    use tokio::io::AsyncReadExt;

    const HEADER_CAP: usize = 64 * 1024 * 1024;
    const CHUNK: usize = 1024 * 1024;
    let mut file = tokio::fs::File::open(path).await.ok()?;
    let mut bytes = Vec::with_capacity(CHUNK);
    let mut chunk = vec![0u8; CHUNK];
    while bytes.len() < HEADER_CAP {
        let count = file.read(&mut chunk).await.ok()?;
        if count == 0 {
            break;
        }
        let remaining = HEADER_CAP - bytes.len();
        bytes.extend_from_slice(&chunk[..count.min(remaining)]);
    }
    ModelMetadata::from_gguf(&bytes, params_fallback)
}

fn allocate_loopback_port() -> Result<u16, RuntimeManagerError> {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|error| RuntimeManagerError::Prepare(format!("allocate loopback port: {error}")))
}

fn empty_desired_state(catalog_revision: &str) -> Result<RuntimeDesiredState, RuntimeManagerError> {
    let revision = DeploymentRevisionDraft {
        source_mode: DeploymentSourceMode::FileManaged,
        source_revision: "runtime-empty".to_string(),
        catalog_revision: catalog_revision.to_string(),
        deployments: BTreeMap::new(),
    };
    revision
        .validate()
        .map_err(|error| RuntimeManagerError::InvalidDesired(error.to_string()))?;
    Ok(RuntimeDesiredState {
        revision,
        deployments: BTreeMap::new(),
        routes: Vec::new(),
        control: sbproxy_config::ModelHostControlConfig::default(),
        legacy_host_policy: None,
    })
}

fn validate_desired_state(
    desired: &RuntimeDesiredState,
    expected_catalog_revision: &str,
) -> Result<(), RuntimeManagerError> {
    desired
        .control
        .validate()
        .map_err(|error| RuntimeManagerError::InvalidDesired(error.to_string()))?;
    desired
        .revision
        .validate()
        .map_err(|error| RuntimeManagerError::InvalidDesired(error.to_string()))?;
    if desired.revision.catalog_revision != expected_catalog_revision {
        return Err(RuntimeManagerError::InvalidDesired(format!(
            "candidate catalog revision {:?} differs from active {:?}",
            desired.revision.catalog_revision, expected_catalog_revision
        )));
    }
    let compiled = desired
        .deployments
        .iter()
        .map(|(id, deployment)| (id.clone(), deployment.desired.clone()))
        .collect::<BTreeMap<_, _>>();
    if compiled != desired.revision.deployments {
        return Err(RuntimeManagerError::InvalidDesired(
            "compiled deployments differ from the canonical revision".to_string(),
        ));
    }
    for route in &desired.routes {
        if !desired.deployments.contains_key(&route.deployment) {
            return Err(RuntimeManagerError::InvalidDesired(format!(
                "route {}/{}/{} references missing deployment {:?}",
                route.origin, route.provider, route.model, route.deployment
            )));
        }
    }
    Ok(())
}

fn plan_reconciliation(current: &RuntimeSnapshot, desired: &RuntimeDesiredState) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    for (id, candidate) in &desired.deployments {
        match current.slots.get(id) {
            None => plan.added.push(id.clone()),
            Some(slot)
                if slot.preparation_identity
                    == PreparationIdentity::from_desired(candidate, desired) =>
            {
                plan.preserved.push(id.clone());
            }
            Some(_) => plan.changed.push(id.clone()),
        }
    }
    for id in current.slots.keys() {
        if !desired.deployments.contains_key(id) {
            plan.removed.push(id.clone());
        }
    }
    plan
}

#[derive(Debug, Clone, PartialEq)]
struct PreparationIdentity {
    desired: CompiledDeployment,
    engines: BTreeMap<sbproxy_config::ManagedEngineKind, sbproxy_config::ManagedEngineConfig>,
    cache_directory: Option<String>,
    safety_margin: f64,
    legacy_host_policy: Option<LegacyHostPolicy>,
}

impl PreparationIdentity {
    fn from_request(request: &DeploymentPrepareRequest) -> Self {
        Self {
            desired: request.desired.clone(),
            engines: request.control.engines.clone(),
            cache_directory: request.control.cache.directory.clone(),
            safety_margin: request.control.safety_margin,
            legacy_host_policy: request.legacy_host_policy.clone(),
        }
    }

    fn from_desired(deployment: &CompiledDeployment, desired: &RuntimeDesiredState) -> Self {
        Self {
            desired: deployment.clone(),
            engines: desired.control.engines.clone(),
            cache_directory: desired.control.cache.directory.clone(),
            safety_margin: desired.control.safety_margin,
            legacy_host_policy: desired.legacy_host_policy.clone(),
        }
    }
}

fn load_admin_candidate(
    mut desired: RuntimeDesiredState,
    expected_catalog_revision: &str,
) -> Result<RuntimeDesiredState, RuntimeManagerError> {
    let path = desired.control.store_path.clone().ok_or_else(|| {
        RuntimeManagerError::InvalidDesired(
            "admin-managed model host requires a deployment store path".to_string(),
        )
    })?;
    let store = FileDeploymentRevisionStore::open(path)
        .map_err(|error| RuntimeManagerError::Store(error.to_string()))?;
    let stored = store
        .load()
        .map_err(|error| RuntimeManagerError::Store(error.to_string()))?;
    let (source_revision, deployments) = match stored {
        Some(revision) => {
            if revision.catalog_revision != expected_catalog_revision {
                return Err(RuntimeManagerError::Store(format!(
                    "stored catalog revision {:?} differs from active {:?}",
                    revision.catalog_revision, expected_catalog_revision
                )));
            }
            (
                format!("{}#{}", revision.source_revision, revision.revision),
                revision.deployments,
            )
        }
        None => ("admin-store-empty".to_string(), BTreeMap::new()),
    };
    desired.revision = DeploymentRevisionDraft {
        source_mode: DeploymentSourceMode::AdminManaged,
        source_revision,
        catalog_revision: expected_catalog_revision.to_string(),
        deployments: deployments.clone(),
    };
    desired.deployments = deployments
        .into_iter()
        .map(|(id, deployment)| {
            (
                id,
                CompiledDeployment {
                    desired: deployment,
                    origin: crate::DesiredDeploymentOrigin::Canonical,
                    legacy_entry: None,
                },
            )
        })
        .collect();
    desired.control.deployments.clear();
    desired.legacy_host_policy = None;
    Ok(desired)
}

async fn teardown_slots(slots: Vec<Arc<DeploymentSlot>>, grace: Duration) {
    for slot in slots {
        let _ = slot.stop(grace).await;
    }
}
