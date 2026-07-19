// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Process-wide managed model runtime and atomic desired-state reconciliation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
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
    BackoffPolicy, Catalog, CompiledDeployment, DeploymentRevision, DeploymentRevisionDraft,
    DeploymentRoute, DeploymentSourceMode, EngineAccel, EngineAvailability, EngineDriver,
    EngineDriverError, EngineFailureReason, EngineHealth, EngineKind, EngineLaunchMethod,
    EngineProvisioning, FileDeploymentRevisionStore, GpuProbe, KvCacheQuant, LaunchRequest,
    LegacyHostPolicy, LlamaCppDriver, ModelMetadata, ModelMetadataProvider, NetworkPolicy,
    OperationJob, ProvisionRequest, PullIntent, ResolveArtifactRequest, RunningEngine,
    RuntimeDesiredState, SGLangDriver, VllmDriver, WorkerProfile,
};

/// Extra readiness re-probes before a ready engine is declared unhealthy.
///
/// The health probe is a 2-second raw-socket check, and it runs from two
/// places: the periodic maintenance tick and the request path
/// (`ensure_ready`). Those can probe concurrently, and an engine whose
/// `/health` is momentarily slow under two simultaneous probes (observed
/// with SGLang during scheduler activity) can miss one. A single dropped
/// probe must not kill a working engine, so a non-ready result is re-probed
/// a few times before the deployment is failed. A process that has actually
/// exited (`EngineHealth::Stopped`) is terminal and skips the retries.
const HEALTH_RECHECK_ATTEMPTS: u32 = 3;

/// Delay between readiness re-probes. Bounds the added latency before a
/// genuinely dead engine is failed to `HEALTH_RECHECK_ATTEMPTS` times this.
const HEALTH_RECHECK_DELAY: Duration = Duration::from_millis(250);

/// Reconciliation, preparation, or lifecycle failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeManagerError {
    /// Complete desired state failed validation.
    #[error("invalid runtime desired state: {0}")]
    InvalidDesired(String),
    /// Static deployment preparation failed.
    #[error("prepare deployment: {0}")]
    Prepare(String),
    /// Host infrastructure failed while preparing a deployment.
    #[error("prepare deployment infrastructure: {0}")]
    PrepareInfrastructure(String),
    /// Managed engine lifecycle failed.
    #[error(transparent)]
    Engine(#[from] EngineDriverError),
    /// Per-device or request admission failed.
    #[error(transparent)]
    Admission(#[from] crate::AdmissionRejection),
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

impl RuntimeManagerError {
    /// Stable bounded reason code for request failover and admin responses.
    pub fn reason_code(&self) -> &'static str {
        runtime_error_reason_code(self)
    }
}

impl From<crate::ArtifactError> for RuntimeManagerError {
    fn from(error: crate::ArtifactError) -> Self {
        match error {
            candidate @ (crate::ArtifactError::InvalidArtifact(_)
            | crate::ArtifactError::SizeMismatch { .. }
            | crate::ArtifactError::DigestMismatch { .. }
            | crate::ArtifactError::ManualArtifactMissing { .. }
            | crate::ArtifactError::OfflineArtifactMissing { .. }
            | crate::ArtifactError::StartupArtifactNotSelected { .. }
            | crate::ArtifactError::PickleRefused { .. }
            | crate::ArtifactError::PickleUnsafe { .. }
            | crate::ArtifactError::RemovalBlocked { .. }) => Self::Prepare(candidate.to_string()),
            infrastructure @ (crate::ArtifactError::Io { .. }
            | crate::ArtifactError::Transport(_)
            | crate::ArtifactError::HttpStatus { .. }
            | crate::ArtifactError::UnexpectedResponse { .. }
            | crate::ArtifactError::CacheCorrupt { .. }
            | crate::ArtifactError::Job(_)
            | crate::ArtifactError::Serialization(_)
            | crate::ArtifactError::Clock(_)
            | crate::ArtifactError::Join(_)) => {
                Self::PrepareInfrastructure(infrastructure.to_string())
            }
        }
    }
}

/// Immutable input used to create one deployment runtime generation.
#[derive(Debug, Clone)]
pub struct DeploymentPrepareRequest {
    /// Canonical deployment ID.
    pub deployment_id: String,
    /// Zero-based replica index within the deployment.
    pub replica_idx: u32,
    /// Monotonic process-local generation.
    pub generation: u64,
    /// Compiled deployment desired state.
    pub desired: CompiledDeployment,
    /// Node-level device set assigned to this replica, when a deployment runs
    /// more than one replica. `None` leaves fit planning to choose devices
    /// lazily, the single-replica default.
    pub pinned_fit: Option<crate::FitPlan>,
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

    /// Pack a multi-replica deployment onto disjoint device sets, one
    /// [`crate::FitPlan`] per replica in replica-index order.
    ///
    /// Called once per deployment before per-replica preparation when the
    /// desired replica count exceeds one. Over-subscription (more replicas,
    /// or replicas times tensor-parallel degree, than the node has devices)
    /// must fail here with a legible reason rather than silently dropping
    /// replicas. The default rejects multi-replica deployments so preparers
    /// that only ever serve one replica need not implement it.
    async fn plan_replica_devices(
        &self,
        request: &DeploymentPrepareRequest,
    ) -> Result<Vec<crate::FitPlan>, RuntimeManagerError> {
        Err(RuntimeManagerError::Prepare(format!(
            "deployment {:?} requests {} replicas, but this runtime serves a single replica per deployment",
            request.deployment_id, request.desired.desired.replicas
        )))
    }
}

/// One statically validated deployment generation that can be started and stopped.
#[async_trait]
pub trait PreparedDeploymentRuntime: Send + Sync {
    /// Resolve verified metadata and return the selected-device memory need before launch.
    async fn memory_estimate(
        &self,
        intent: PullIntent,
    ) -> Result<crate::MemoryEstimate, RuntimeManagerError>;
    /// Acquire verified artifacts, provision the engine, and reach readiness.
    async fn start(&self, intent: PullIntent) -> Result<RunningEngine, RuntimeManagerError>;
    /// Check a generation that previously reached readiness.
    async fn health(
        &self,
        running: &RunningEngine,
    ) -> Result<crate::EngineHealth, RuntimeManagerError> {
        if running.process.has_exited().await? {
            Ok(crate::EngineHealth::Stopped)
        } else {
            Ok(crate::EngineHealth::Ready)
        }
    }
    /// Stop this generation, if it is running.
    async fn stop(&self, grace: Duration) -> Result<(), RuntimeManagerError>;
    /// Clear retained failure state before another explicit start.
    async fn reset(&self) -> Result<Option<OperationJob>, RuntimeManagerError>;
    /// Snapshot static assignment, artifact, and durable-job details for status.
    async fn telemetry(&self) -> PreparedRuntimeTelemetry {
        PreparedRuntimeTelemetry::default()
    }
}

/// Cold-runtime progress that exists below the public lifecycle state machine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PreparedRuntimePhase {
    /// Desired state exists but has no reported worker assignment yet.
    #[default]
    Configured,
    /// A compatible worker, artifact, and engine have been selected.
    Assigned,
    /// Verified artifact bytes are present in the local cache.
    Cached,
}

/// Driver, artifact, placement, and durable-job details for a prepared runtime.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PreparedRuntimeTelemetry {
    /// Cold-runtime progress before engine preparation begins.
    pub phase: PreparedRuntimePhase,
    /// Resolved engine kind.
    pub engine: Option<EngineKind>,
    /// Driver availability observed during preparation.
    pub driver_availability: Option<EngineAvailability>,
    /// Canonical verified-artifact identity selected from the catalog.
    pub artifact_digest: Option<String>,
    /// Worker-local devices selected by fit planning.
    pub selected_devices: Vec<u32>,
    /// Complete selected-device memory estimate, when fit has run.
    pub memory: Option<crate::MemoryEstimate>,
    /// Most recently retained durable lifecycle job.
    pub job_id: Option<String>,
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
    /// Worker, artifact, and engine assignment is complete.
    Assigned,
    /// Verified artifact bytes are cached but the engine is not running.
    Cached,
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

impl DeploymentRuntimeState {
    /// Stable snake-case lifecycle label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Assigned => "assigned",
            Self::Cached => "cached",
            Self::Preparing => "preparing",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

/// Point-in-time lifecycle status for one current deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentRuntimeStatus {
    /// Canonical deployment ID.
    pub deployment: String,
    /// Zero-based replica index within the deployment.
    pub replica: u32,
    /// Process-local generation.
    pub generation: u64,
    /// Current lifecycle state.
    pub state: DeploymentRuntimeState,
    /// Exact requests holding an active permit.
    pub active_requests: usize,
    /// Exact requests waiting in the priority queue.
    pub queued_requests: usize,
    /// Resolved managed engine.
    pub engine: Option<EngineKind>,
    /// Resolved engine version serving this generation, when a running engine
    /// reported one.
    pub engine_version: Option<String>,
    /// Driver availability retained from worker preparation.
    pub driver_availability: Option<EngineAvailability>,
    /// Canonical artifact digest, without a source or local path.
    pub artifact_digest: Option<String>,
    /// Worker-local devices assigned to this generation.
    pub selected_devices: Vec<u32>,
    /// Complete memory reservation for the selected device.
    pub memory: Option<crate::MemoryEstimate>,
    /// Ready loopback port.
    pub port: Option<u16>,
    /// Stable bounded failure reason code.
    pub reason_code: Option<String>,
    /// Most recently retained durable lifecycle job ID.
    pub job_id: Option<String>,
    /// Bounded last failure, when state is failed.
    pub last_error: Option<String>,
}

type Activation = Shared<BoxFuture<'static, Result<RunningEngine, RuntimeManagerError>>>;

/// Request admission bound to one exact committed deployment generation.
pub struct DeploymentAdmissionPermit {
    deployment: String,
    generation: u64,
    start_epoch: u64,
    _permit: crate::AdmissionPermit,
}

impl std::fmt::Debug for DeploymentAdmissionPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeploymentAdmissionPermit")
            .field("deployment", &self.deployment)
            .field("generation", &self.generation)
            .field("start_epoch", &self.start_epoch)
            .finish_non_exhaustive()
    }
}

impl DeploymentAdmissionPermit {
    /// Canonical deployment held by this request.
    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    /// Exact process-local generation admitted for this request.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Drain epoch in which this request was admitted.
    pub fn start_epoch(&self) -> u64 {
        self.start_epoch
    }
}

struct SlotLifecycle {
    start_epoch: u64,
    state: DeploymentRuntimeState,
    running: Option<RunningEngine>,
    last_error: Option<RuntimeManagerError>,
    activation: Option<Activation>,
}

struct RecreateBegin {
    owner_epoch: u64,
    prior_state: DeploymentRuntimeState,
    prior_error: Option<RuntimeManagerError>,
    activation: Option<Activation>,
}

struct RecreateCheckpoint {
    owner_epoch: u64,
    restore_state: DeploymentRuntimeState,
    last_error: Option<RuntimeManagerError>,
    was_running: bool,
}

#[derive(Clone)]
struct RetiredSlot {
    slot: Arc<DeploymentSlot>,
    drain_owner: Option<u64>,
}

struct DeploymentSlot {
    id: String,
    replica_idx: u32,
    generation: u64,
    desired: CompiledDeployment,
    preparation_identity: PreparationIdentity,
    runtime: Arc<dyn PreparedDeploymentRuntime>,
    admission: crate::AdmissionGate,
    observer: Arc<dyn crate::ModelHostObserver>,
    engine: Option<EngineKind>,
    observed: AtomicBool,
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
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: String,
        replica_idx: u32,
        generation: u64,
        desired: CompiledDeployment,
        preparation_identity: PreparationIdentity,
        runtime: Arc<dyn PreparedDeploymentRuntime>,
        observer: Arc<dyn crate::ModelHostObserver>,
        engine: Option<EngineKind>,
    ) -> Result<Self, RuntimeManagerError> {
        let max_active = desired.desired.max_concurrency.unwrap_or(1) as usize;
        let admission = crate::AdmissionGate::new(
            max_active,
            desired.desired.max_queue_depth,
            Duration::from_millis(desired.desired.queue_timeout_ms),
        )
        .map_err(RuntimeManagerError::InvalidDesired)?;
        Ok(Self {
            id,
            replica_idx,
            generation,
            desired,
            preparation_identity,
            runtime,
            admission,
            observer,
            engine,
            observed: AtomicBool::new(false),
            lifecycle: Mutex::new(SlotLifecycle {
                start_epoch: 0,
                state: DeploymentRuntimeState::Configured,
                running: None,
                last_error: None,
                activation: None,
            }),
        })
    }

    async fn current_start_epoch(&self) -> u64 {
        self.lifecycle.lock().await.start_epoch
    }

    async fn accepts_start_epoch(&self, expected: u64) -> bool {
        let lifecycle = self.lifecycle.lock().await;
        lifecycle.start_epoch == expected
            && !matches!(
                lifecycle.state,
                DeploymentRuntimeState::Draining | DeploymentRuntimeState::Failed
            )
    }

    async fn accepts_drain_owner(&self, owner_epoch: u64) -> bool {
        let lifecycle = self.lifecycle.lock().await;
        lifecycle.start_epoch == owner_epoch && lifecycle.state == DeploymentRuntimeState::Draining
    }

    async fn begin_draining(&self) -> Result<u64, RuntimeManagerError> {
        let owner_epoch = {
            let mut lifecycle = self.lifecycle.lock().await;
            lifecycle.start_epoch = lifecycle
                .start_epoch
                .checked_add(1)
                .ok_or(RuntimeManagerError::CounterOverflow)?;
            lifecycle.state = DeploymentRuntimeState::Draining;
            lifecycle.start_epoch
        };
        self.publish_lifecycle_state().await;
        Ok(owner_epoch)
    }

    async fn memory_estimate(
        &self,
        intent: PullIntent,
        limiter: Arc<Semaphore>,
        remain_preparing: bool,
        expected_start_epoch: u64,
    ) -> Result<crate::MemoryEstimate, RuntimeManagerError> {
        let was_stopped = {
            let mut lifecycle = self.lifecycle.lock().await;
            if lifecycle.start_epoch != expected_start_epoch {
                return Err(RuntimeManagerError::Draining(self.id.clone()));
            }
            match lifecycle.state {
                DeploymentRuntimeState::Ready => {
                    return lifecycle
                        .running
                        .as_ref()
                        .map(|running| running.memory.clone())
                        .ok_or_else(|| {
                            RuntimeManagerError::Prepare(format!(
                                "deployment {:?} is ready without a running engine",
                                self.id
                            ))
                        });
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
                _ => {
                    let was_stopped = lifecycle.state == DeploymentRuntimeState::Stopped;
                    lifecycle.state = DeploymentRuntimeState::Preparing;
                    lifecycle.last_error = None;
                    was_stopped
                }
            }
        };
        if was_stopped && remain_preparing {
            self.admission.resume();
        }
        self.publish_lifecycle_state().await;
        let result = match limiter.acquire_owned().await {
            Ok(_permit) => self.runtime.memory_estimate(intent).await,
            Err(_) => Err(RuntimeManagerError::Prepare(
                "model preparation limiter is closed".to_string(),
            )),
        };
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.start_epoch != expected_start_epoch {
            return Err(RuntimeManagerError::Draining(self.id.clone()));
        }
        let owns_preparation = lifecycle.state == DeploymentRuntimeState::Preparing
            && lifecycle.running.is_none()
            && lifecycle.activation.is_none();
        match &result {
            Ok(_) if !remain_preparing && owns_preparation => {
                lifecycle.state = if was_stopped {
                    DeploymentRuntimeState::Stopped
                } else {
                    DeploymentRuntimeState::Configured
                };
            }
            Ok(_) => {}
            Err(error) if owns_preparation => {
                lifecycle.state = DeploymentRuntimeState::Failed;
                lifecycle.last_error = Some(error.clone());
            }
            Err(_) => {}
        }
        let state = lifecycle.state;
        drop(lifecycle);
        if matches!(
            state,
            DeploymentRuntimeState::Configured | DeploymentRuntimeState::Stopped
        ) {
            self.publish_current_state().await;
        } else {
            self.publish_lifecycle_state().await;
        }
        result
    }

    fn start_activation(
        self: &Arc<Self>,
        intent: PullIntent,
        limiter: Arc<Semaphore>,
    ) -> Activation {
        let runtime = self.runtime.clone();
        let slot = Arc::clone(self);
        let activation = async move {
            let _permit = limiter.acquire_owned().await.map_err(|_| {
                RuntimeManagerError::Prepare("model preparation limiter is closed".to_string())
            })?;
            let result = runtime.start(intent).await.and_then(|running| {
                if running.deployment != slot.id || running.generation != slot.generation {
                    return Err(RuntimeManagerError::Prepare(format!(
                        "deployment runtime returned identity {:?}/{} for {:?}/{}",
                        running.deployment, running.generation, slot.id, slot.generation
                    )));
                }
                Ok(running)
            });
            slot.finish_activation(&result).await;
            result
        }
        .boxed()
        .shared();
        let background = activation.clone();
        tokio::spawn(async move {
            let _ = background.await;
        });
        activation
    }

    async fn finish_activation(&self, result: &Result<RunningEngine, RuntimeManagerError>) {
        let mut lifecycle = self.lifecycle.lock().await;
        lifecycle.activation = None;
        match result {
            Ok(running) => {
                lifecycle.running = Some(running.clone());
                lifecycle.last_error = None;
                if lifecycle.state != DeploymentRuntimeState::Draining {
                    lifecycle.state = DeploymentRuntimeState::Ready;
                    self.admission.mark_ready_idle();
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
        drop(lifecycle);
        self.publish_lifecycle_state().await;
    }

    async fn refresh_ready_health(&self) -> Result<Option<RunningEngine>, RuntimeManagerError> {
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.state != DeploymentRuntimeState::Ready {
            return Ok(None);
        }
        let running = lifecycle.running.clone().ok_or_else(|| {
            RuntimeManagerError::Prepare(format!(
                "deployment {:?} is ready without a running engine",
                self.id
            ))
        })?;
        // Re-probe a non-ready result before failing the deployment: a
        // single dropped or timed-out /health probe (probe races between the
        // maintenance tick and the request path, brief scheduler stalls) must
        // not kill a working engine. A process that has exited is terminal
        // and does not benefit from retries.
        let mut health_error = None;
        for attempt in 0..=HEALTH_RECHECK_ATTEMPTS {
            match self.runtime.health(&running).await {
                Ok(EngineHealth::Ready) => return Ok(Some(running)),
                Ok(EngineHealth::Stopped) => {
                    health_error = Some(RuntimeManagerError::Engine(EngineDriverError::new(
                        EngineFailureReason::EngineHealthFailed,
                        format!("managed deployment {:?} engine process has exited", self.id),
                        "inspect the retained engine diagnostics, then reset the deployment",
                        true,
                    )));
                    break;
                }
                Ok(observed) => {
                    health_error = Some(RuntimeManagerError::Engine(EngineDriverError::new(
                        EngineFailureReason::EngineHealthFailed,
                        format!(
                            "managed deployment {:?} health changed from ready to {observed:?}",
                            self.id
                        ),
                        "inspect the retained engine diagnostics, then reset the deployment",
                        true,
                    )));
                }
                Err(error) => health_error = Some(error),
            }
            if attempt < HEALTH_RECHECK_ATTEMPTS {
                tokio::time::sleep(HEALTH_RECHECK_DELAY).await;
            }
        }
        let health_error =
            health_error.expect("a non-ready health result records an error before failing");
        let cleanup = self.runtime.stop(Duration::from_secs(1)).await;
        lifecycle.start_epoch = lifecycle
            .start_epoch
            .checked_add(1)
            .ok_or(RuntimeManagerError::CounterOverflow)?;
        lifecycle.activation = None;
        lifecycle.state = DeploymentRuntimeState::Failed;
        let surfaced = match cleanup {
            Ok(()) => {
                lifecycle.running = None;
                health_error
            }
            Err(cleanup_error) => {
                // The runtime still owns the process handle when shutdown fails.
                // Keep that handle and its residency until a later stop succeeds.
                cleanup_error
            }
        };
        lifecycle.last_error = Some(surfaced.clone());
        drop(lifecycle);
        self.publish_lifecycle_state().await;
        Err(surfaced)
    }

    async fn ensure_ready(
        self: &Arc<Self>,
        intent: PullIntent,
        limiter: Arc<Semaphore>,
        expected_start_epoch: u64,
    ) -> Result<RunningEngine, RuntimeManagerError> {
        if !self.accepts_start_epoch(expected_start_epoch).await {
            return Err(RuntimeManagerError::Draining(self.id.clone()));
        }
        if let Some(running) = self.refresh_ready_health().await? {
            return Ok(running);
        }
        let activation = {
            let mut lifecycle = self.lifecycle.lock().await;
            if lifecycle.start_epoch != expected_start_epoch {
                return Err(RuntimeManagerError::Draining(self.id.clone()));
            }
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
                    if let Some(activation) = lifecycle.activation.clone() {
                        activation
                    } else {
                        let future = self.start_activation(intent, limiter.clone());
                        lifecycle.activation = Some(future.clone());
                        future
                    }
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
                DeploymentRuntimeState::Configured
                | DeploymentRuntimeState::Assigned
                | DeploymentRuntimeState::Cached
                | DeploymentRuntimeState::Stopped => {
                    if lifecycle.state == DeploymentRuntimeState::Stopped {
                        self.admission.resume();
                    }
                    let future = self.start_activation(intent, limiter.clone());
                    lifecycle.state = DeploymentRuntimeState::Preparing;
                    lifecycle.last_error = None;
                    lifecycle.activation = Some(future.clone());
                    future
                }
            }
        };
        self.publish_lifecycle_state().await;

        let result = activation.await;
        let lifecycle = self.lifecycle.lock().await;
        match lifecycle.state {
            DeploymentRuntimeState::Ready => result,
            DeploymentRuntimeState::Draining | DeploymentRuntimeState::Stopped => {
                Err(RuntimeManagerError::Draining(self.id.clone()))
            }
            DeploymentRuntimeState::Failed => {
                Err(lifecycle.last_error.clone().unwrap_or_else(|| {
                    RuntimeManagerError::Prepare(result.err().map_or_else(
                        || format!("deployment {:?} failed without a retained reason", self.id),
                        |error| error.to_string(),
                    ))
                }))
            }
            _ => result,
        }
    }

    async fn stop_owned(
        &self,
        grace: Duration,
        owner_epoch: u64,
    ) -> Result<(), RuntimeManagerError> {
        let activation = {
            let lifecycle = self.lifecycle.lock().await;
            if lifecycle.start_epoch != owner_epoch {
                return Err(RuntimeManagerError::Draining(self.id.clone()));
            }
            lifecycle.activation.clone()
        };
        if let Some(activation) = activation {
            let _ = activation.await;
        }
        if !self.accepts_drain_owner(owner_epoch).await {
            return Err(RuntimeManagerError::Draining(self.id.clone()));
        }
        let result = self.runtime.stop(grace).await;
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.start_epoch != owner_epoch {
            return Err(RuntimeManagerError::Draining(self.id.clone()));
        }
        lifecycle.activation = None;
        match &result {
            Ok(()) => {
                lifecycle.running = None;
                lifecycle.state = DeploymentRuntimeState::Draining;
                lifecycle.last_error = None;
            }
            Err(error) => {
                lifecycle.state = DeploymentRuntimeState::Failed;
                lifecycle.last_error = Some(error.clone());
            }
        }
        drop(lifecycle);
        self.publish_lifecycle_state().await;
        result
    }

    async fn finalize_stop_owned(&self, owner_epoch: u64) -> Result<(), RuntimeManagerError> {
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.start_epoch != owner_epoch
            || lifecycle.state != DeploymentRuntimeState::Draining
        {
            return Err(RuntimeManagerError::Draining(self.id.clone()));
        }
        lifecycle.state = DeploymentRuntimeState::Stopped;
        drop(lifecycle);
        self.publish_lifecycle_state().await;
        Ok(())
    }

    async fn stop(&self, grace: Duration) -> Result<(), RuntimeManagerError> {
        let owner_epoch = self.begin_draining().await?;
        self.stop_owned(grace, owner_epoch).await?;
        self.finalize_stop_owned(owner_epoch).await
    }

    async fn drain_runtime_owned(
        &self,
        grace: Duration,
        owner_epoch: u64,
    ) -> Result<crate::DrainReport, RuntimeManagerError> {
        if !self.accepts_drain_owner(owner_epoch).await {
            return Err(RuntimeManagerError::Draining(self.id.clone()));
        }
        let report = self.admission.drain(grace).await;
        self.stop_owned(grace, owner_epoch).await?;
        Ok(report)
    }

    async fn drain_owned(
        &self,
        grace: Duration,
        owner_epoch: u64,
    ) -> Result<crate::DrainReport, RuntimeManagerError> {
        let report = self.drain_runtime_owned(grace, owner_epoch).await?;
        self.finalize_stop_owned(owner_epoch).await?;
        Ok(report)
    }

    async fn drain(&self, grace: Duration) -> Result<crate::DrainReport, RuntimeManagerError> {
        let owner_epoch = self.begin_draining().await?;
        self.drain_owned(grace, owner_epoch).await
    }

    async fn begin_recreate(&self) -> Result<RecreateBegin, RuntimeManagerError> {
        let begin = {
            let mut lifecycle = self.lifecycle.lock().await;
            if lifecycle.state == DeploymentRuntimeState::Draining {
                return Err(RuntimeManagerError::Draining(self.id.clone()));
            }
            let prior_state = if lifecycle.state == DeploymentRuntimeState::Preparing
                && lifecycle.activation.is_none()
            {
                DeploymentRuntimeState::Configured
            } else {
                lifecycle.state
            };
            lifecycle.start_epoch = lifecycle
                .start_epoch
                .checked_add(1)
                .ok_or(RuntimeManagerError::CounterOverflow)?;
            let begin = RecreateBegin {
                owner_epoch: lifecycle.start_epoch,
                prior_state,
                prior_error: lifecycle.last_error.clone(),
                activation: lifecycle.activation.clone(),
            };
            lifecycle.state = DeploymentRuntimeState::Draining;
            begin
        };
        self.publish_lifecycle_state().await;
        Ok(begin)
    }

    async fn abort_recreate_begin(&self, begin: RecreateBegin) {
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.start_epoch != begin.owner_epoch {
            return;
        }
        lifecycle.state = begin.prior_state;
        lifecycle.last_error = begin.prior_error;
        lifecycle.activation = begin.activation;
        self.admission.resume();
        drop(lifecycle);
        self.publish_lifecycle_state().await;
    }

    async fn finish_recreate(
        &self,
        begin: RecreateBegin,
        grace: Duration,
    ) -> Result<RecreateCheckpoint, RuntimeManagerError> {
        let report = self.admission.drain(grace).await;
        if !self.accepts_drain_owner(begin.owner_epoch).await {
            return Err(RuntimeManagerError::Draining(self.id.clone()));
        }
        if report.timed_out {
            self.abort_recreate_begin(begin).await;
            return Err(RuntimeManagerError::Prepare(format!(
                "recreate rollout for deployment {:?} exceeded the drain deadline with {} active requests",
                self.id, report.remaining_active
            )));
        }
        if let Some(activation) = begin.activation.clone() {
            let _ = activation.await;
        }
        if !self.accepts_drain_owner(begin.owner_epoch).await {
            return Err(RuntimeManagerError::Draining(self.id.clone()));
        }
        let (running, last_error) = {
            let lifecycle = self.lifecycle.lock().await;
            (lifecycle.running.clone(), lifecycle.last_error.clone())
        };
        let restore_state = if running.is_some() {
            DeploymentRuntimeState::Ready
        } else if last_error.is_some() {
            DeploymentRuntimeState::Failed
        } else {
            begin.prior_state
        };
        if let Err(error) = self.runtime.stop(grace).await {
            let mut lifecycle = self.lifecycle.lock().await;
            if lifecycle.start_epoch != begin.owner_epoch {
                return Err(RuntimeManagerError::Draining(self.id.clone()));
            }
            lifecycle.state = restore_state;
            lifecycle.running = running;
            lifecycle.last_error = last_error.or(begin.prior_error);
            lifecycle.activation = None;
            self.admission.resume();
            drop(lifecycle);
            self.publish_lifecycle_state().await;
            return Err(error);
        }
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.start_epoch != begin.owner_epoch {
            return Err(RuntimeManagerError::Draining(self.id.clone()));
        }
        lifecycle.state = DeploymentRuntimeState::Draining;
        lifecycle.running = None;
        lifecycle.last_error = None;
        lifecycle.activation = None;
        drop(lifecycle);
        self.publish_lifecycle_state().await;
        Ok(RecreateCheckpoint {
            owner_epoch: begin.owner_epoch,
            restore_state,
            last_error: last_error.or(begin.prior_error),
            was_running: running.is_some(),
        })
    }

    async fn restore_after_recreate_abort(
        self: &Arc<Self>,
        checkpoint: RecreateCheckpoint,
        limiter: Arc<Semaphore>,
    ) -> Result<(), RuntimeManagerError> {
        if checkpoint.was_running {
            {
                let mut lifecycle = self.lifecycle.lock().await;
                if lifecycle.start_epoch != checkpoint.owner_epoch {
                    return Ok(());
                }
                lifecycle.state = DeploymentRuntimeState::Stopped;
                lifecycle.running = None;
                lifecycle.last_error = checkpoint.last_error;
                lifecycle.activation = None;
                self.admission.resume();
            }
            return match self
                .ensure_ready(PullIntent::Startup, limiter, checkpoint.owner_epoch)
                .await
            {
                Ok(_) | Err(RuntimeManagerError::Draining(_)) => Ok(()),
                Err(error) => Err(error),
            };
        }
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.start_epoch != checkpoint.owner_epoch {
            return Ok(());
        }
        lifecycle.state = checkpoint.restore_state;
        lifecycle.running = None;
        lifecycle.last_error = checkpoint.last_error;
        lifecycle.activation = None;
        self.admission.resume();
        drop(lifecycle);
        self.publish_current_state().await;
        Ok(())
    }

    async fn reset(&self) -> Result<Option<OperationJob>, RuntimeManagerError> {
        let owner_epoch = {
            let mut lifecycle = self.lifecycle.lock().await;
            match lifecycle.state {
                DeploymentRuntimeState::Failed if lifecycle.running.is_none() => {}
                DeploymentRuntimeState::Failed => {
                    return Err(RuntimeManagerError::Prepare(format!(
                        "managed deployment {:?} cannot reset while a process whose shutdown failed remains owned; stop it first",
                        self.id
                    )));
                }
                DeploymentRuntimeState::Preparing | DeploymentRuntimeState::Draining => {
                    return Err(RuntimeManagerError::Draining(self.id.clone()));
                }
                state => {
                    return Err(RuntimeManagerError::Prepare(format!(
                        "managed deployment {:?} cannot reset from {}; reset requires a retained failure",
                        self.id,
                        state.as_str()
                    )));
                }
            }
            lifecycle.start_epoch = lifecycle
                .start_epoch
                .checked_add(1)
                .ok_or(RuntimeManagerError::CounterOverflow)?;
            lifecycle.state = DeploymentRuntimeState::Draining;
            lifecycle.start_epoch
        };
        self.publish_lifecycle_state().await;
        let result = self.runtime.reset().await;
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.start_epoch != owner_epoch
            || lifecycle.state != DeploymentRuntimeState::Draining
        {
            return Err(RuntimeManagerError::Draining(self.id.clone()));
        }
        match &result {
            Ok(_) => {
                lifecycle.state = DeploymentRuntimeState::Configured;
                lifecycle.running = None;
                lifecycle.last_error = None;
                lifecycle.activation = None;
                self.admission.resume();
            }
            Err(error) => {
                lifecycle.state = DeploymentRuntimeState::Failed;
                lifecycle.last_error = Some(error.clone());
            }
        }
        let state = lifecycle.state;
        drop(lifecycle);
        if state == DeploymentRuntimeState::Configured {
            self.publish_current_state().await;
        } else {
            self.publish_lifecycle_state().await;
        }
        result
    }

    async fn status(&self) -> DeploymentRuntimeStatus {
        let telemetry = self.runtime.telemetry().await;
        let lifecycle = self.lifecycle.lock().await;
        let counts = self.admission.counts();
        let running = lifecycle.running.as_ref();
        let state = if lifecycle.state == DeploymentRuntimeState::Configured {
            match telemetry.phase {
                PreparedRuntimePhase::Configured => DeploymentRuntimeState::Configured,
                PreparedRuntimePhase::Assigned => DeploymentRuntimeState::Assigned,
                PreparedRuntimePhase::Cached => DeploymentRuntimeState::Cached,
            }
        } else {
            lifecycle.state
        };
        DeploymentRuntimeStatus {
            deployment: self.id.clone(),
            replica: self.replica_idx,
            generation: self.generation,
            state,
            active_requests: counts.active,
            queued_requests: counts.queued,
            engine: running.map(|running| running.kind).or(telemetry.engine),
            engine_version: running.and_then(|running| running.engine_version.clone()),
            driver_availability: telemetry.driver_availability,
            artifact_digest: running
                .map(|running| running.artifact_digest.clone())
                .or(telemetry.artifact_digest),
            selected_devices: running
                .map(|running| running.selected_devices.clone())
                .unwrap_or(telemetry.selected_devices),
            memory: running
                .map(|running| running.memory.clone())
                .or(telemetry.memory),
            port: running.map(|running| running.port),
            reason_code: lifecycle
                .last_error
                .as_ref()
                .map(runtime_error_reason_code)
                .map(str::to_string),
            job_id: telemetry.job_id,
            last_error: lifecycle
                .last_error
                .as_ref()
                .map(ToString::to_string)
                .map(|error| bounded_status_text(&error)),
        }
    }

    async fn admit(
        &self,
        priority: crate::PriorityClass,
    ) -> Result<(crate::AdmissionPermit, u64), crate::AdmissionRejection> {
        let start_epoch = {
            let lifecycle = self.lifecycle.lock().await;
            match lifecycle.state {
                DeploymentRuntimeState::Draining => {
                    return Err(crate::AdmissionRejection::new(
                        crate::AdmissionReason::Draining,
                        "deployment is draining or stopped",
                        true,
                        None,
                    ));
                }
                DeploymentRuntimeState::Failed => {
                    let crash_loop = lifecycle.last_error.as_ref().is_some_and(|error| {
                        matches!(
                            error,
                            RuntimeManagerError::Engine(driver)
                                if driver.reason() == EngineFailureReason::CrashLoop
                        )
                    });
                    return Err(crate::AdmissionRejection::new(
                        if crash_loop {
                            crate::AdmissionReason::CrashLoop
                        } else {
                            crate::AdmissionReason::EngineUnhealthy
                        },
                        "deployment runtime is failed",
                        true,
                        None,
                    ));
                }
                DeploymentRuntimeState::Configured
                | DeploymentRuntimeState::Assigned
                | DeploymentRuntimeState::Cached
                | DeploymentRuntimeState::Preparing
                | DeploymentRuntimeState::Ready => {}
                DeploymentRuntimeState::Stopped => self.admission.resume(),
            }
            lifecycle.start_epoch
        };
        let permit = self.admission.admit(priority).await?;
        if !self.accepts_start_epoch(start_epoch).await {
            drop(permit);
            return Err(crate::AdmissionRejection::new(
                crate::AdmissionReason::Draining,
                "deployment drain began while admission waited",
                true,
                None,
            ));
        }
        Ok((permit, start_epoch))
    }

    async fn reservation_facts(&self) -> Option<(u32, String, u64, crate::ResidencyProtection)> {
        let lifecycle = self.lifecycle.lock().await;
        let running = lifecycle.running.as_ref()?;
        Some((
            running.memory.primary_device(),
            self.id.clone(),
            self.generation,
            self.protection(
                lifecycle.state == DeploymentRuntimeState::Preparing,
                lifecycle.state == DeploymentRuntimeState::Draining,
            ),
        ))
    }

    async fn owns_reservation(&self) -> bool {
        let lifecycle = self.lifecycle.lock().await;
        lifecycle.running.is_some()
            || (lifecycle.state == DeploymentRuntimeState::Preparing
                && lifecycle.activation.is_some())
    }

    async fn begin_idle_eviction(&self) -> Result<Option<u64>, RuntimeManagerError> {
        let mut lifecycle = self.lifecycle.lock().await;
        let owner_epoch = lifecycle
            .start_epoch
            .checked_add(1)
            .ok_or(RuntimeManagerError::CounterOverflow)?;
        if self
            .desired
            .legacy_entry
            .as_ref()
            .is_some_and(|entry| entry.pinned)
            || lifecycle.state != DeploymentRuntimeState::Ready
            || lifecycle.running.is_none()
            || !self.admission.begin_idle_drain()
        {
            return Ok(None);
        }
        lifecycle.start_epoch = owner_epoch;
        lifecycle.state = DeploymentRuntimeState::Draining;
        drop(lifecycle);
        self.publish_lifecycle_state().await;
        Ok(Some(owner_epoch))
    }

    async fn abort_idle_eviction(&self, owner_epoch: u64) {
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.start_epoch != owner_epoch
            || lifecycle.state != DeploymentRuntimeState::Draining
            || lifecycle.running.is_none()
        {
            return;
        }
        lifecycle.state = DeploymentRuntimeState::Ready;
        self.admission.resume();
        drop(lifecycle);
        self.publish_lifecycle_state().await;
    }

    fn emit_state(&self, state: DeploymentRuntimeState, engine: Option<EngineKind>) {
        if self.observed.load(Ordering::SeqCst) {
            self.observer.set_deployment_state(&self.id, engine, state);
        }
    }

    async fn publish_lifecycle_state(&self) {
        if !self.observed.load(Ordering::SeqCst) {
            return;
        }
        let lifecycle = self.lifecycle.lock().await;
        let state = lifecycle.state;
        let engine = lifecycle
            .running
            .as_ref()
            .map(|running| running.kind)
            .or(self.engine);
        drop(lifecycle);
        self.emit_state(state, engine);
    }

    async fn publish_current_state(&self) {
        let status = self.status().await;
        self.emit_state(status.state, status.engine);
    }

    async fn activate_observation(&self) {
        if !self.observed.swap(true, Ordering::SeqCst) {
            self.admission
                .set_observer(self.id.clone(), self.observer.clone());
        }
        self.publish_current_state().await;
    }

    async fn cancel_preparation(&self) {
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.state == DeploymentRuntimeState::Preparing && lifecycle.activation.is_none() {
            lifecycle.state = DeploymentRuntimeState::Configured;
            lifecycle.last_error = None;
        }
        drop(lifecycle);
        self.publish_current_state().await;
    }

    fn protection(&self, preparing: bool, draining: bool) -> crate::ResidencyProtection {
        let counts = self.admission.counts();
        crate::ResidencyProtection {
            pinned: self
                .desired
                .legacy_entry
                .as_ref()
                .is_some_and(|entry| entry.pinned),
            active: counts.active > 0,
            queued: counts.queued > 0,
            preparing,
            draining: draining || counts.draining,
        }
    }
}

/// One or more running replica slots for a single logical deployment.
///
/// Replicas share a logical deployment ID and configuration but each holds its
/// own engine process, generation, and device set, so per-replica keep-alive,
/// eviction, and admission stay independent. Ordered by replica index; the
/// primary is index 0 and is the single member in the common one-replica case.
/// Never empty.
#[derive(Debug, Clone)]
struct DeploymentReplicas {
    replicas: Vec<Arc<DeploymentSlot>>,
}

impl DeploymentReplicas {
    fn from_slots(replicas: Vec<Arc<DeploymentSlot>>) -> Self {
        debug_assert!(
            !replicas.is_empty(),
            "a deployment has at least one replica"
        );
        Self { replicas }
    }

    /// The first replica; the sole member in the one-replica case.
    fn primary(&self) -> &Arc<DeploymentSlot> {
        &self.replicas[0]
    }

    fn iter(&self) -> impl Iterator<Item = &Arc<DeploymentSlot>> {
        self.replicas.iter()
    }

    /// Find the replica running a specific process-local generation.
    fn by_generation(&self, generation: u64) -> Option<&Arc<DeploymentSlot>> {
        self.replicas
            .iter()
            .find(|slot| slot.generation == generation)
    }

    /// Preparation identity, shared by every replica of one deployment.
    fn preparation_identity(&self) -> &PreparationIdentity {
        &self.primary().preparation_identity
    }

    fn into_slots(self) -> Vec<Arc<DeploymentSlot>> {
        self.replicas
    }
}

struct RuntimeSnapshot {
    revision: u64,
    desired: Arc<RuntimeDesiredState>,
    slots: BTreeMap<String, DeploymentReplicas>,
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
    staged_slots: BTreeMap<String, DeploymentReplicas>,
    /// Warm memory estimates keyed by replica generation.
    staged_memory: BTreeMap<u64, crate::MemoryEstimate>,
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
            .field(
                "staged_memory",
                &self.staged_memory.keys().collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// One process-wide runtime handle that survives empty startup and every reload.
pub struct ModelRuntimeManager {
    expected_catalog_revision: String,
    preparer: Arc<dyn DeploymentPreparer>,
    snapshot: ArcSwap<RuntimeSnapshot>,
    serving_device_count: usize,
    residency: Mutex<crate::DeviceResidencySet>,
    retired_slots: Mutex<BTreeMap<(String, u64), RetiredSlot>>,
    retirement_lock: Mutex<()>,
    placement_lock: Mutex<()>,
    observer: Arc<dyn crate::ModelHostObserver>,
    generation: AtomicU64,
    residency_tick: AtomicU64,
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
        Self::new_with_device_capacities(
            catalog_revision,
            preparer,
            BTreeMap::from([(0, u64::MAX)]),
        )
    }

    /// Create the permanent handle with explicit per-device serving capacities.
    pub fn new_with_device_capacities(
        catalog_revision: impl Into<String>,
        preparer: Arc<dyn DeploymentPreparer>,
        device_capacities: BTreeMap<u32, u64>,
    ) -> Result<Self, RuntimeManagerError> {
        let catalog_revision = catalog_revision.into();
        if catalog_revision.trim().is_empty() {
            return Err(RuntimeManagerError::InvalidDesired(
                "catalog revision must not be empty".to_string(),
            ));
        }
        if device_capacities.is_empty() {
            return Err(RuntimeManagerError::InvalidDesired(
                "at least one model-serving device capacity is required".to_string(),
            ));
        }
        let desired = Arc::new(empty_desired_state(&catalog_revision)?);
        let snapshot = RuntimeSnapshot {
            revision: 0,
            desired,
            slots: BTreeMap::new(),
            limiter: Arc::new(Semaphore::new(2)),
        };
        let serving_device_count = device_capacities.len();
        Ok(Self {
            expected_catalog_revision: catalog_revision,
            preparer,
            snapshot: ArcSwap::from_pointee(snapshot),
            serving_device_count,
            residency: Mutex::new(crate::DeviceResidencySet::new(device_capacities)),
            retired_slots: Mutex::new(BTreeMap::new()),
            retirement_lock: Mutex::new(()),
            placement_lock: Mutex::new(()),
            observer: Arc::new(crate::NoopObserver),
            generation: AtomicU64::new(1),
            residency_tick: AtomicU64::new(1),
            reconcile_lock: Mutex::new(()),
        })
    }

    /// Attach lifecycle metrics before reconciling the first deployment.
    pub fn with_observer(mut self, observer: Arc<dyn crate::ModelHostObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Current process-local committed revision number.
    pub fn current_revision(&self) -> u64 {
        self.snapshot.load().revision
    }

    /// Number of model-serving devices this node has, the ceiling on
    /// `replicas * tensor_parallel` for any one deployment.
    pub fn serving_device_count(&self) -> usize {
        self.serving_device_count
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
        self.prepare_normalized_revision(desired).await
    }

    /// Prepare one caller-supplied durable admin revision without rereading its store.
    pub async fn prepare_admin_revision(
        &self,
        template: RuntimeDesiredState,
        revision: DeploymentRevision,
    ) -> Result<PreparedRevision, RuntimeManagerError> {
        let desired =
            normalize_admin_revision(template, revision, self.expected_catalog_revision.as_str())?;
        self.prepare_normalized_revision(desired).await
    }

    async fn prepare_normalized_revision(
        &self,
        desired: RuntimeDesiredState,
    ) -> Result<PreparedRevision, RuntimeManagerError> {
        validate_desired_state(&desired, &self.expected_catalog_revision)?;
        let current = self.snapshot.load_full();
        let plan = plan_reconciliation(&current, &desired);
        let limiter = Arc::new(Semaphore::new(desired.control.max_parallel_prepares));

        let mut requests = Vec::new();
        for id in plan.added.iter().chain(plan.changed.iter()) {
            let compiled = desired.deployments.get(id).ok_or_else(|| {
                RuntimeManagerError::InvalidDesired(format!(
                    "reconcile plan references absent deployment {id:?}"
                ))
            })?;
            let replicas = compiled.desired.replicas.max(1);
            // A deployment with more than one replica has its devices packed at
            // the node level, so replicas claim disjoint device sets instead of
            // all landing on device 0. A single replica keeps the lazy path,
            // choosing its device when it first reaches readiness.
            let pinned_fits = if replicas > 1 {
                let probe = DeploymentPrepareRequest {
                    deployment_id: id.clone(),
                    replica_idx: 0,
                    generation: 0,
                    desired: compiled.clone(),
                    pinned_fit: None,
                    control: desired.control.clone(),
                    legacy_host_policy: desired.legacy_host_policy.clone(),
                };
                let fits = self.preparer.plan_replica_devices(&probe).await?;
                if fits.len() != replicas as usize {
                    return Err(RuntimeManagerError::Prepare(format!(
                        "replica device planning for deployment {id:?} returned {} device sets for {replicas} replicas",
                        fits.len()
                    )));
                }
                Some(fits)
            } else {
                None
            };
            for replica_idx in 0..replicas {
                let generation = self
                    .generation
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                        current.checked_add(1)
                    })
                    .map_err(|_| RuntimeManagerError::CounterOverflow)?;
                requests.push(DeploymentPrepareRequest {
                    deployment_id: id.clone(),
                    replica_idx,
                    generation,
                    desired: compiled.clone(),
                    pinned_fit: pinned_fits
                        .as_ref()
                        .map(|fits| fits[replica_idx as usize].clone()),
                    control: desired.control.clone(),
                    legacy_host_policy: desired.legacy_host_policy.clone(),
                });
            }
        }

        let parallelism = desired.control.max_parallel_prepares;
        let preparer = self.preparer.clone();
        let observer = self.observer.clone();
        let warm_ids = desired
            .deployments
            .iter()
            .filter_map(|(id, deployment)| deployment.desired.warm.then_some(id.clone()))
            .collect::<BTreeSet<_>>();
        let on_boot_ids = desired
            .deployments
            .iter()
            .filter_map(|(id, deployment)| {
                (deployment.desired.pull == crate::PullPolicy::OnBoot).then_some(id.clone())
            })
            .collect::<BTreeSet<_>>();
        let mut preparations = stream::iter(requests)
            .map(|request| {
                let preparer = preparer.clone();
                let observer = observer.clone();
                let limiter = limiter.clone();
                let warm = warm_ids.contains(&request.deployment_id);
                let on_boot = on_boot_ids.contains(&request.deployment_id);
                async move {
                    let id = request.deployment_id.clone();
                    let replica_idx = request.replica_idx;
                    let generation = request.generation;
                    let desired = request.desired.clone();
                    let preparation_identity = PreparationIdentity::from_request(&request);
                    let permit = limiter.clone().acquire_owned().await.map_err(|_| {
                        RuntimeManagerError::PrepareInfrastructure(
                            "model preparation limiter is closed".to_string(),
                        )
                    })?;
                    let runtime = preparer.prepare(request).await?;
                    drop(permit);
                    let engine = runtime.telemetry().await.engine;
                    let slot = Arc::new(DeploymentSlot::new(
                        id.clone(),
                        replica_idx,
                        generation,
                        desired,
                        preparation_identity,
                        runtime,
                        observer,
                        engine,
                    )?);
                    let memory = if warm {
                        let start_epoch = slot.current_start_epoch().await;
                        Some(
                            slot.memory_estimate(PullIntent::Startup, limiter, true, start_epoch)
                                .await?,
                        )
                    } else if on_boot {
                        let start_epoch = slot.current_start_epoch().await;
                        Some(
                            slot.memory_estimate(PullIntent::Startup, limiter, false, start_epoch)
                                .await?,
                        )
                    } else {
                        None
                    };
                    Ok::<_, RuntimeManagerError>((id, replica_idx, generation, slot, memory))
                }
            })
            .buffer_unordered(parallelism);

        // Group prepared replicas under their deployment ID, ordered by replica
        // index. Warm memory estimates are keyed by generation, unique per
        // replica, so a multi-replica warm launch reserves each replica's need.
        let mut staged_replicas: BTreeMap<String, Vec<(u32, Arc<DeploymentSlot>)>> =
            BTreeMap::new();
        let mut staged_memory = BTreeMap::new();
        let mut first_error = None;
        while let Some(result) = preparations.next().await {
            match result {
                Ok((id, replica_idx, generation, slot, memory)) => {
                    if let Some(memory) = memory {
                        staged_memory.insert(generation, memory);
                    }
                    staged_replicas
                        .entry(id)
                        .or_default()
                        .push((replica_idx, slot));
                }
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        drop(preparations);
        let mut staged_slots = BTreeMap::new();
        for (id, mut replicas) in staged_replicas {
            replicas.sort_by_key(|(replica_idx, _)| *replica_idx);
            let slots = replicas.into_iter().map(|(_, slot)| slot).collect();
            staged_slots.insert(id, DeploymentReplicas::from_slots(slots));
        }
        if let Some(error) = first_error {
            teardown_slots(
                staged_slots
                    .values()
                    .flat_map(|replicas| replicas.iter().cloned())
                    .collect(),
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
            staged_memory,
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
            prepared
                .staged_slots
                .into_values()
                .flat_map(DeploymentReplicas::into_slots)
                .collect(),
            Duration::from_millis(prepared.desired.control.shutdown_deadline_ms),
        )
        .await;
    }

    /// Bring one current deployment generation to ready.
    pub async fn ensure_ready(
        &self,
        deployment: &str,
    ) -> Result<RunningEngine, RuntimeManagerError> {
        self.ensure_ready_for(deployment, crate::PriorityClass::Standard)
            .await
    }

    /// Bring one generation to ready and attribute capacity rejection to request priority.
    pub async fn ensure_ready_for(
        &self,
        deployment: &str,
        priority: crate::PriorityClass,
    ) -> Result<RunningEngine, RuntimeManagerError> {
        let result = self.ensure_ready_inner(deployment, None, None).await;
        if let Err(RuntimeManagerError::Admission(rejection)) = &result {
            self.observer
                .on_admission_rejected(deployment, priority, rejection.reason);
        }
        result
    }

    /// Bring only the generation named by an existing admission permit to ready.
    pub async fn ensure_ready_for_generation(
        &self,
        deployment: &str,
        generation: u64,
        start_epoch: u64,
        priority: crate::PriorityClass,
    ) -> Result<RunningEngine, RuntimeManagerError> {
        let result = self
            .ensure_ready_inner(deployment, Some(generation), Some(start_epoch))
            .await;
        if let Err(RuntimeManagerError::Admission(rejection)) = &result {
            self.observer
                .on_admission_rejected(deployment, priority, rejection.reason);
        }
        result
    }

    async fn ensure_ready_inner(
        &self,
        deployment: &str,
        expected_generation: Option<u64>,
        expected_start_epoch: Option<u64>,
    ) -> Result<RunningEngine, RuntimeManagerError> {
        let snapshot = self.snapshot.load_full();
        let replicas = snapshot
            .slots
            .get(deployment)
            .ok_or_else(|| RuntimeManagerError::UnknownDeployment(deployment.to_string()))?;
        // A generation names an exact replica; without one, target the primary.
        let slot = match expected_generation {
            Some(generation) => replicas
                .by_generation(generation)
                .cloned()
                .ok_or_else(|| RuntimeManagerError::Draining(deployment.to_string()))?,
            None => replicas.primary().clone(),
        };
        let start_epoch = match expected_start_epoch {
            Some(start_epoch) => start_epoch,
            None => slot.current_start_epoch().await,
        };
        if !slot.accepts_start_epoch(start_epoch).await {
            return Err(RuntimeManagerError::Draining(deployment.to_string()));
        }
        let memory = slot
            .memory_estimate(
                PullIntent::Runtime,
                snapshot.limiter.clone(),
                true,
                start_epoch,
            )
            .await?;
        let placement = self.placement_lock.lock().await;
        let current = self.snapshot.load_full();
        if current.slots.get(deployment).is_none_or(|replicas| {
            !replicas
                .iter()
                .any(|current_slot| Arc::ptr_eq(current_slot, &slot))
        }) {
            slot.cancel_preparation().await;
            return Err(RuntimeManagerError::Draining(deployment.to_string()));
        }
        if !slot.accepts_start_epoch(start_epoch).await {
            slot.cancel_preparation().await;
            return Err(RuntimeManagerError::Draining(deployment.to_string()));
        }
        self.refresh_residency_protections(&current).await;
        let tick = self.residency_tick.fetch_add(1, Ordering::SeqCst);
        let residency_policy = residency_policy(&current.desired);
        let (previous_residency, reservation) = {
            let mut residency = self.residency.lock().await;
            let previous = residency.clone();
            let reservation = residency.reserve_with_policy(
                deployment,
                slot.generation,
                memory.clone(),
                slot.protection(true, false),
                tick,
                residency_policy,
            );
            (previous, reservation)
        };
        let reservation = match reservation {
            Ok(reservation) => reservation,
            Err(rejection) => {
                slot.cancel_preparation().await;
                return Err(RuntimeManagerError::Admission(rejection));
            }
        };
        let mut stopped_victims = Vec::new();
        for (victim, victim_generation) in reservation.evicted {
            if let Some(victim_slot) = current
                .slots
                .get(&victim)
                .and_then(|replicas| replicas.by_generation(victim_generation))
            {
                let Some(owner_epoch) = victim_slot.begin_idle_eviction().await? else {
                    self.restore_residency_after_failed_eviction(
                        previous_residency,
                        &stopped_victims,
                        &current,
                    )
                    .await;
                    slot.cancel_preparation().await;
                    return Err(RuntimeManagerError::Admission(
                        crate::AdmissionRejection::new(
                            crate::AdmissionReason::InsufficientCapacity,
                            format!("deployment {victim:?} became protected before eviction"),
                            true,
                            None,
                        ),
                    ));
                };
                let facts = victim_slot.reservation_facts().await;
                if let Err(error) = victim_slot
                    .drain_owned(
                        Duration::from_millis(current.desired.control.shutdown_deadline_ms),
                        owner_epoch,
                    )
                    .await
                {
                    self.restore_residency_after_failed_eviction(
                        previous_residency,
                        &stopped_victims,
                        &current,
                    )
                    .await;
                    slot.cancel_preparation().await;
                    return Err(error);
                }
                if let Some(facts) = facts {
                    stopped_victims.push(facts);
                }
            }
        }
        drop(placement);
        match slot
            .ensure_ready(PullIntent::Runtime, current.limiter.clone(), start_epoch)
            .await
        {
            Ok(running) => {
                self.residency.lock().await.update_protection(
                    memory.primary_device(),
                    deployment,
                    slot.generation,
                    slot.protection(false, false),
                );
                Ok(running)
            }
            Err(error) => {
                if !slot.owns_reservation().await {
                    self.residency.lock().await.release(
                        memory.primary_device(),
                        deployment,
                        slot.generation,
                    );
                }
                Err(error)
            }
        }
    }

    /// Acquire and verify one deployment artifact without launching its engine.
    pub async fn cache(
        &self,
        deployment: &str,
    ) -> Result<crate::MemoryEstimate, RuntimeManagerError> {
        let snapshot = self.snapshot.load_full();
        // Every replica shares one artifact, so caching the primary caches it
        // for the whole deployment.
        let slot = snapshot
            .slots
            .get(deployment)
            .map(|replicas| replicas.primary().clone())
            .ok_or_else(|| RuntimeManagerError::UnknownDeployment(deployment.to_string()))?;
        let start_epoch = slot.current_start_epoch().await;
        let memory = slot
            .memory_estimate(
                PullIntent::Explicit,
                snapshot.limiter.clone(),
                false,
                start_epoch,
            )
            .await?;
        slot.publish_current_state().await;
        Ok(memory)
    }

    /// Acquire one request permit against a deployment's least-loaded ready
    /// replica, or the primary when none is ready yet.
    pub async fn admit(
        &self,
        deployment: &str,
        priority: crate::PriorityClass,
    ) -> Result<DeploymentAdmissionPermit, crate::AdmissionRejection> {
        let snapshot = self.snapshot.load_full();
        let replicas = snapshot.slots.get(deployment).ok_or_else(|| {
            crate::AdmissionRejection::new(
                crate::AdmissionReason::EngineUnhealthy,
                format!("managed deployment {deployment:?} is not configured"),
                false,
                None,
            )
        })?;
        let slot = select_admission_replica(replicas);
        let (permit, start_epoch) = slot.admit(priority).await?;
        let current = self.snapshot.load_full();
        if current.slots.get(deployment).is_none_or(|replicas| {
            !replicas
                .iter()
                .any(|current_slot| Arc::ptr_eq(current_slot, &slot))
        }) {
            drop(permit);
            return Err(crate::AdmissionRejection::new(
                crate::AdmissionReason::Draining,
                format!(
                    "managed deployment {deployment:?} changed generation while admission waited"
                ),
                true,
                None,
            ));
        }
        self.refresh_residency_protections(&snapshot).await;
        Ok(DeploymentAdmissionPermit {
            deployment: deployment.to_string(),
            generation: slot.generation,
            start_epoch,
            _permit: permit,
        })
    }

    /// Stop one current deployment generation.
    pub async fn stop(&self, deployment: &str) -> Result<(), RuntimeManagerError> {
        self.drain(deployment).await.map(|_| ())
    }

    /// Reject new work, cancel queued work, wait boundedly, and stop every
    /// replica of one deployment, aggregating their drain reports.
    pub async fn drain(&self, deployment: &str) -> Result<crate::DrainReport, RuntimeManagerError> {
        let (replicas, grace) = {
            let snapshot = self.snapshot.load_full();
            let replicas =
                snapshot.slots.get(deployment).cloned().ok_or_else(|| {
                    RuntimeManagerError::UnknownDeployment(deployment.to_string())
                })?;
            let grace = Duration::from_millis(snapshot.desired.control.shutdown_deadline_ms);
            (replicas, grace)
        };
        let mut aggregate: Option<crate::DrainReport> = None;
        for slot in replicas.iter() {
            let owner_epoch = {
                let _placement = self.placement_lock.lock().await;
                slot.begin_draining().await?
            };
            let report = slot.drain_runtime_owned(grace, owner_epoch).await?;
            let _placement = self.placement_lock.lock().await;
            if !slot.accepts_drain_owner(owner_epoch).await {
                return Err(RuntimeManagerError::Draining(deployment.to_string()));
            }
            let mut residency = self.residency.lock().await;
            for reservation in residency.reservations().into_iter().filter(|reservation| {
                reservation.deployment == deployment && reservation.generation == slot.generation
            }) {
                residency.release(
                    reservation.memory.primary_device(),
                    deployment,
                    slot.generation,
                );
            }
            drop(residency);
            slot.finalize_stop_owned(owner_epoch).await?;
            let _cleanup = self.retirement_lock.lock().await;
            let key = (deployment.to_string(), slot.generation);
            let mut retired = self.retired_slots.lock().await;
            if retired
                .get(&key)
                .is_some_and(|registered| Arc::ptr_eq(&registered.slot, slot))
            {
                retired.remove(&key);
            }
            aggregate = Some(merge_drain_reports(aggregate, report));
        }
        Ok(aggregate.unwrap_or_default())
    }

    /// Clear the retained failure state of every replica of one deployment.
    pub async fn reset(
        &self,
        deployment: &str,
    ) -> Result<Option<OperationJob>, RuntimeManagerError> {
        let snapshot = self.snapshot.load_full();
        let replicas = snapshot
            .slots
            .get(deployment)
            .cloned()
            .ok_or_else(|| RuntimeManagerError::UnknownDeployment(deployment.to_string()))?;
        let mut job = None;
        for slot in replicas.iter() {
            let reset = slot.reset().await?;
            job = job.or(reset);
        }
        Ok(job)
    }

    /// Snapshot every current replica status in deterministic deployment and
    /// replica-index order.
    pub async fn statuses(&self) -> Vec<DeploymentRuntimeStatus> {
        let slots = self
            .snapshot
            .load_full()
            .slots
            .values()
            .flat_map(|replicas| replicas.iter().cloned())
            .collect::<Vec<_>>();
        let mut statuses = Vec::with_capacity(slots.len());
        for slot in slots {
            statuses.push(slot.status().await);
        }
        statuses
    }

    /// Snapshot current per-device reservations for diagnostics and tests.
    pub async fn residency_reservations(&self) -> Vec<crate::DeviceReservation> {
        self.residency.lock().await.reservations()
    }

    /// Snapshot one current deployment's primary-replica status.
    pub async fn status(&self, deployment: &str) -> Option<DeploymentRuntimeStatus> {
        let slot = self
            .snapshot
            .load_full()
            .slots
            .get(deployment)
            .map(|replicas| replicas.primary().clone())?;
        Some(slot.status().await)
    }

    async fn register_retired_slots(&self, retired: &[(String, Arc<DeploymentSlot>, Option<u64>)]) {
        {
            let mut retained = self.retired_slots.lock().await;
            for (deployment, slot, drain_owner) in retired {
                retained.insert(
                    (deployment.clone(), slot.generation),
                    RetiredSlot {
                        slot: Arc::clone(slot),
                        drain_owner: *drain_owner,
                    },
                );
            }
        }
        let mut residency = self.residency.lock().await;
        for (deployment, slot, _) in retired {
            for reservation in residency.reservations().into_iter().filter(|reservation| {
                reservation.deployment == *deployment && reservation.generation == slot.generation
            }) {
                let mut protection = reservation.protection;
                protection.draining = true;
                residency.update_protection(
                    reservation.memory.primary_device(),
                    deployment,
                    slot.generation,
                    protection,
                );
            }
        }
    }

    async fn cleanup_retired_slot(
        &self,
        deployment: &str,
        slot: &Arc<DeploymentSlot>,
        grace: Duration,
    ) -> Result<Option<crate::DrainReport>, RuntimeManagerError> {
        let _cleanup = self.retirement_lock.lock().await;
        let key = (deployment.to_string(), slot.generation);
        let retained = self.retired_slots.lock().await.get(&key).cloned();
        let Some(retained) = retained.filter(|retained| Arc::ptr_eq(&retained.slot, slot)) else {
            return Ok(None);
        };
        let result = match retained.drain_owner {
            Some(owner_epoch) => slot.drain_owned(grace, owner_epoch).await,
            None => slot.drain(grace).await,
        };
        let report = match result {
            Ok(report) => report,
            Err(error) => {
                if retained.drain_owner.is_some() {
                    let mut registry = self.retired_slots.lock().await;
                    if let Some(registered) = registry.get_mut(&key).filter(|registered| {
                        Arc::ptr_eq(&registered.slot, slot)
                            && registered.drain_owner == retained.drain_owner
                    }) {
                        registered.drain_owner = None;
                    }
                }
                return Err(error);
            }
        };
        let mut residency = self.residency.lock().await;
        for reservation in residency.reservations().into_iter().filter(|reservation| {
            reservation.deployment == deployment && reservation.generation == slot.generation
        }) {
            residency.release(
                reservation.memory.primary_device(),
                deployment,
                slot.generation,
            );
        }
        drop(residency);
        let mut retained = self.retired_slots.lock().await;
        if retained
            .get(&key)
            .is_some_and(|registered| Arc::ptr_eq(&registered.slot, slot))
        {
            retained.remove(&key);
        }
        Ok(Some(report))
    }

    /// Stop ready generations whose keep-alive elapsed and which have no protection.
    pub async fn maintenance_tick(&self, now: tokio::time::Instant) -> Vec<String> {
        let _placement = self.placement_lock.lock().await;
        let snapshot = self.snapshot.load_full();
        let mut stopped = Vec::new();
        for (id, replicas) in &snapshot.slots {
            for slot in replicas.iter() {
                if let Err(error) = slot.refresh_ready_health().await {
                    tracing::warn!(deployment = %id, replica = slot.replica_idx, reason = error.reason_code(), %error, "managed engine health check failed");
                }
            }
        }
        let grace = Duration::from_millis(snapshot.desired.control.shutdown_deadline_ms);
        let retired = self
            .retired_slots
            .lock()
            .await
            .iter()
            .map(|((deployment, _), retired)| (deployment.clone(), Arc::clone(&retired.slot)))
            .collect::<Vec<_>>();
        for (deployment, slot) in retired {
            if let Err(error) = self.cleanup_retired_slot(&deployment, &slot, grace).await {
                tracing::warn!(
                    %deployment,
                    generation = slot.generation,
                    reason = error.reason_code(),
                    %error,
                    "retired managed engine shutdown retry failed"
                );
            }
        }
        let retained = self
            .retired_slots
            .lock()
            .await
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let reservations = self.residency.lock().await.reservations();
        for reservation in reservations {
            let keep = match snapshot
                .slots
                .get(&reservation.deployment)
                .and_then(|replicas| replicas.by_generation(reservation.generation))
            {
                Some(slot) => slot.owns_reservation().await,
                None => false,
            } || retained
                .contains(&(reservation.deployment.clone(), reservation.generation));
            if !keep {
                self.residency.lock().await.release(
                    reservation.memory.primary_device(),
                    &reservation.deployment,
                    reservation.generation,
                );
            }
        }
        for (id, replicas) in &snapshot.slots {
            for slot in replicas.iter() {
                let Some(keep_alive_secs) = slot.desired.desired.keep_alive_secs else {
                    continue;
                };
                let Some((device, _, generation, _)) = slot.reservation_facts().await else {
                    continue;
                };
                if slot
                    .desired
                    .legacy_entry
                    .as_ref()
                    .is_some_and(|entry| entry.pinned)
                    || !slot
                        .admission
                        .begin_idle_drain_if_expired_at(now, Duration::from_secs(keep_alive_secs))
                {
                    continue;
                }
                if slot
                    .drain(Duration::from_millis(
                        snapshot.desired.control.shutdown_deadline_ms,
                    ))
                    .await
                    .is_ok()
                {
                    self.residency.lock().await.release(device, id, generation);
                    stopped.push(id.clone());
                }
            }
        }
        stopped
    }

    async fn commit_prepared(
        &self,
        mut prepared: PreparedRevision,
    ) -> Result<ReconcileReport, RuntimeManagerError> {
        let placement = self.placement_lock.lock().await;
        let current = self.snapshot.load_full();
        if current.revision != prepared.base_revision {
            let error = RuntimeManagerError::StalePrepared {
                based_on: prepared.base_revision,
                current: current.revision,
            };
            teardown_slots(
                prepared
                    .staged_slots
                    .into_values()
                    .flat_map(DeploymentReplicas::into_slots)
                    .collect(),
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
            let replicas = if preserved.contains(id.as_str()) {
                current.slots.get(id).cloned()
            } else {
                prepared.staged_slots.remove(id)
            }
            .ok_or_else(|| {
                RuntimeManagerError::Prepare(format!(
                    "prepared revision has no runtime slot for {id:?}"
                ))
            })?;
            slots.insert(id.clone(), replicas);
        }

        let candidate_ids = prepared
            .plan
            .added
            .iter()
            .chain(prepared.plan.changed.iter())
            .cloned()
            .collect::<Vec<_>>();
        let warm_candidate_ids = candidate_ids
            .iter()
            .filter(|id| {
                prepared
                    .desired
                    .deployments
                    .get(*id)
                    .is_some_and(|deployment| deployment.desired.warm)
            })
            .cloned()
            .collect::<Vec<_>>();
        let recreate_ids = prepared
            .plan
            .changed
            .iter()
            .filter(|id| {
                prepared
                    .desired
                    .deployments
                    .get(*id)
                    .is_some_and(|deployment| {
                        deployment.desired.rollout == crate::RolloutPolicy::Recreate
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        let grace = Duration::from_millis(prepared.desired.control.shutdown_deadline_ms);

        let mut recreate_begins = Vec::new();
        for id in &recreate_ids {
            let Some(old) = current.slots.get(id) else {
                continue;
            };
            for replica in old.iter() {
                match replica.begin_recreate().await {
                    Ok(begin) => recreate_begins.push((replica.clone(), begin)),
                    Err(error) => {
                        for (begun, begin) in recreate_begins {
                            begun.abort_recreate_begin(begin).await;
                        }
                        teardown_slots(candidate_replica_slots(&candidate_ids, &slots), grace)
                            .await;
                        return Err(error);
                    }
                }
            }
        }
        drop(placement);

        let mut recreate_checkpoints = Vec::new();
        let mut pending_recreates = recreate_begins.into_iter();
        while let Some((old, begin)) = pending_recreates.next() {
            match old.finish_recreate(begin, grace).await {
                Ok(checkpoint) => recreate_checkpoints.push((old, checkpoint)),
                Err(error) => {
                    for (pending, begin) in pending_recreates {
                        pending.abort_recreate_begin(begin).await;
                    }
                    teardown_slots(candidate_replica_slots(&candidate_ids, &slots), grace).await;
                    if let Some(rollback) =
                        rollback_recreate_slots(recreate_checkpoints, current.limiter.clone()).await
                    {
                        return Err(RuntimeManagerError::Prepare(format!(
                            "{error}; recreate rollback failed: {rollback}"
                        )));
                    }
                    return Err(error);
                }
            }
        }

        let placement = self.placement_lock.lock().await;
        let latest = self.snapshot.load_full();
        if latest.revision != prepared.base_revision {
            let error = RuntimeManagerError::StalePrepared {
                based_on: prepared.base_revision,
                current: latest.revision,
            };
            teardown_slots(candidate_replica_slots(&candidate_ids, &slots), grace).await;
            if let Some(rollback) =
                rollback_recreate_slots(recreate_checkpoints, current.limiter.clone()).await
            {
                return Err(RuntimeManagerError::Prepare(format!(
                    "{error}; recreate rollback failed: {rollback}"
                )));
            }
            return Err(error);
        }
        self.refresh_residency_protections(&current).await;
        let (mut planned, current_reservations) = {
            let residency = self.residency.lock().await;
            (residency.clone(), residency.reservations())
        };
        for id in &recreate_ids {
            let Some(old) = current.slots.get(id) else {
                continue;
            };
            for replica in old.iter() {
                for reservation in planned.reservations().into_iter().filter(|reservation| {
                    reservation.deployment == *id && reservation.generation == replica.generation
                }) {
                    planned.release(reservation.memory.primary_device(), id, replica.generation);
                }
            }
        }

        let residency_policy = residency_policy(&prepared.desired);
        let mut capacity_probe = planned.clone();
        capacity_probe.protect_all_for_rollout();
        let mut warm_specs = Vec::new();
        let mut capacity_error = None;
        'warm: for id in &warm_candidate_ids {
            let Some(replicas) = slots.get(id).cloned() else {
                capacity_error = Some(RuntimeManagerError::Prepare(format!(
                    "prepared warm revision has no runtime slot for {id:?}"
                )));
                break;
            };
            for slot in replicas.iter() {
                let Some(memory) = prepared.staged_memory.get(&slot.generation).cloned() else {
                    capacity_error = Some(RuntimeManagerError::Prepare(format!(
                        "prepared warm revision has no memory estimate for {id:?}"
                    )));
                    break 'warm;
                };
                let tick = self.residency_tick.fetch_add(1, Ordering::SeqCst);
                match capacity_probe.reserve_with_policy(
                    id,
                    slot.generation,
                    memory.clone(),
                    slot.protection(true, false),
                    tick,
                    residency_policy,
                ) {
                    Ok(reservation) if reservation.evicted.is_empty() => {
                        warm_specs.push((id.clone(), slot.clone(), memory, tick));
                    }
                    Ok(_) => {
                        capacity_error = Some(RuntimeManagerError::Prepare(format!(
                            "warm rollout capacity probe unexpectedly evicted a protected generation for {id:?}"
                        )));
                        break 'warm;
                    }
                    Err(error) => {
                        capacity_error = Some(RuntimeManagerError::Admission(error));
                        break 'warm;
                    }
                }
            }
        }

        let mut capacity_evictions = BTreeSet::new();
        if capacity_error.is_none() {
            for (id, slot, memory, tick) in &warm_specs {
                match planned.reserve_with_policy(
                    id,
                    slot.generation,
                    memory.clone(),
                    slot.protection(true, false),
                    *tick,
                    residency_policy,
                ) {
                    Ok(reservation) if reservation.evicted.is_empty() => {}
                    Ok(_) => {
                        capacity_error = Some(RuntimeManagerError::Prepare(format!(
                            "warm rollout capacity changed after the protected probe for {id:?}"
                        )));
                        break;
                    }
                    Err(error) => {
                        capacity_error = Some(RuntimeManagerError::Admission(error));
                        break;
                    }
                }
            }
        }
        if capacity_error.is_none() {
            match planned.enforce_policy(residency_policy) {
                Ok(reservation) => capacity_evictions.extend(reservation.evicted),
                Err(error) => capacity_error = Some(RuntimeManagerError::Admission(error)),
            }
        }
        if capacity_error.is_none() {
            for mut reservation in current_reservations.into_iter().filter(|reservation| {
                capacity_evictions
                    .contains(&(reservation.deployment.clone(), reservation.generation))
                    && current
                        .slots
                        .get(&reservation.deployment)
                        .is_some_and(|replicas| {
                            replicas.by_generation(reservation.generation).is_some()
                        })
            }) {
                reservation.protection.draining = true;
                if let Err(error) = planned.retain_existing(reservation) {
                    capacity_error = Some(RuntimeManagerError::Admission(error));
                    break;
                }
            }
        }
        if let Some(error) = capacity_error {
            teardown_slots(candidate_replica_slots(&candidate_ids, &slots), grace).await;
            if let Some(rollback) =
                rollback_recreate_slots(recreate_checkpoints, current.limiter.clone()).await
            {
                return Err(RuntimeManagerError::Prepare(format!(
                    "{error}; recreate rollback failed: {rollback}"
                )));
            }
            return Err(error);
        }

        let mut launch_error = None;
        for (id, slot, memory, _) in &warm_specs {
            let start_epoch = slot.current_start_epoch().await;
            match slot
                .ensure_ready(PullIntent::Startup, prepared.limiter.clone(), start_epoch)
                .await
            {
                Ok(running) if &running.memory == memory => {
                    planned.update_protection(
                        memory.primary_device(),
                        id,
                        slot.generation,
                        slot.protection(false, false),
                    );
                }
                Ok(running) => {
                    launch_error = Some(RuntimeManagerError::Prepare(format!(
                        "warm deployment {id:?} launched with memory estimate {:?}, expected {:?}",
                        running.memory, memory
                    )));
                    break;
                }
                Err(error) => {
                    launch_error = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = launch_error {
            teardown_slots(candidate_replica_slots(&candidate_ids, &slots), grace).await;
            if let Some(rollback) =
                rollback_recreate_slots(recreate_checkpoints, current.limiter.clone()).await
            {
                return Err(RuntimeManagerError::Prepare(format!(
                    "{error}; recreate rollback failed: {rollback}"
                )));
            }
            return Err(error);
        }
        let mut eviction_claims = BTreeMap::new();
        let mut claim_error = None;
        for (id, generation) in &capacity_evictions {
            let Some(slot) = current
                .slots
                .get(id)
                .and_then(|replicas| replicas.by_generation(*generation))
                .cloned()
            else {
                claim_error = Some(RuntimeManagerError::Prepare(format!(
                    "policy eviction selected unknown deployment {id:?}"
                )));
                break;
            };
            match slot.begin_idle_eviction().await {
                Ok(Some(owner_epoch)) => {
                    eviction_claims.insert((id.clone(), *generation), owner_epoch);
                }
                Ok(None) => {
                    claim_error = Some(RuntimeManagerError::Admission(
                        crate::AdmissionRejection::new(
                            crate::AdmissionReason::InsufficientCapacity,
                            format!("deployment {id:?} became protected before policy eviction"),
                            true,
                            None,
                        ),
                    ));
                    break;
                }
                Err(error) => {
                    claim_error = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = claim_error {
            for ((id, generation), owner_epoch) in &eviction_claims {
                if let Some(slot) = current
                    .slots
                    .get(id)
                    .and_then(|replicas| replicas.by_generation(*generation))
                {
                    slot.abort_idle_eviction(*owner_epoch).await;
                }
            }
            teardown_slots(candidate_replica_slots(&candidate_ids, &slots), grace).await;
            if let Some(rollback) =
                rollback_recreate_slots(recreate_checkpoints, current.limiter.clone()).await
            {
                return Err(RuntimeManagerError::Prepare(format!(
                    "{error}; recreate rollback failed: {rollback}"
                )));
            }
            return Err(error);
        }
        *self.residency.lock().await = planned;

        // Retire every old replica slot the swap displaced: one evicted by
        // policy, or one absent from the new snapshot (its deployment changed
        // or was removed). Preserved deployments reuse the same slot Arcs, so
        // none of their replicas retire.
        let mut retired = Vec::new();
        for (id, old) in &current.slots {
            let new = slots.get(id);
            for replica in old.iter() {
                let evicted = capacity_evictions.contains(&(id.clone(), replica.generation));
                let superseded =
                    new.is_none_or(|new| !new.iter().any(|slot| Arc::ptr_eq(slot, replica)));
                if evicted || superseded {
                    retired.push((
                        id.clone(),
                        replica.clone(),
                        eviction_claims
                            .get(&(id.clone(), replica.generation))
                            .copied(),
                    ));
                }
            }
        }
        self.register_retired_slots(&retired).await;
        self.snapshot.store(Arc::new(RuntimeSnapshot {
            revision: next_revision,
            desired: prepared.desired.clone(),
            slots,
            limiter: prepared.limiter,
        }));
        drop(placement);
        let published = self.snapshot.load_full();
        for replicas in published.slots.values() {
            for slot in replicas.iter() {
                slot.activate_observation().await;
            }
        }

        let grace = Duration::from_millis(prepared.desired.control.shutdown_deadline_ms);
        let mut retire_failures = BTreeMap::new();
        for (id, slot, _) in retired {
            match self.cleanup_retired_slot(&id, &slot, grace).await {
                Ok(Some(report)) if report.timed_out => {
                    retire_failures.insert(
                        id.clone(),
                        format!(
                            "drain deadline elapsed with {} active requests",
                            report.remaining_active
                        ),
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    retire_failures.insert(id.clone(), error.to_string());
                }
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

    async fn refresh_residency_protections(&self, snapshot: &RuntimeSnapshot) {
        let mut facts = Vec::new();
        for replicas in snapshot.slots.values() {
            for slot in replicas.iter() {
                if let Some(fact) = slot.reservation_facts().await {
                    facts.push(fact);
                }
            }
        }
        let mut residency = self.residency.lock().await;
        for (device, deployment, generation, protection) in facts {
            residency.update_protection(device, &deployment, generation, protection);
        }
    }

    async fn restore_residency_after_failed_eviction(
        &self,
        mut previous: crate::DeviceResidencySet,
        stopped: &[(u32, String, u64, crate::ResidencyProtection)],
        snapshot: &RuntimeSnapshot,
    ) {
        for (device, deployment, generation, _) in stopped {
            previous.release(*device, deployment, *generation);
        }
        *self.residency.lock().await = previous;
        self.refresh_residency_protections(snapshot).await;
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
            (
                EngineKind::SGLang,
                Arc::new(SGLangDriver::default()) as Arc<dyn EngineDriver>,
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

    /// List durable ready artifact metadata from the verified cache in
    /// deterministic digest order. Read-only inventory passthrough to
    /// [`ArtifactManager::cached_artifacts`] for admin surfaces; it never
    /// touches artifact bytes.
    pub fn cached_artifacts(
        &self,
    ) -> Result<Vec<crate::ArtifactCacheMetadata>, crate::ArtifactError> {
        self.artifacts.cached_artifacts()
    }

    /// Snapshot path-free worker hardware, engine, and verified-cache truth.
    pub fn node_snapshot_inventory(
        &self,
    ) -> Result<crate::node_snapshot::NodeSnapshotInventory, crate::node_snapshot::NodeSnapshotError>
    {
        use crate::node_snapshot::{
            NodeArtifactSnapshot, NodeEngineSnapshot, NodeSnapshotError, NodeSnapshotInventory,
        };

        let descriptors = self.probe.probe();
        let mut devices = descriptors
            .iter()
            .map(crate::node_snapshot::NodeDeviceSnapshot::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        devices.sort_by_key(|device| device.index);

        let worker = crate::WorkerProfile::from_descriptors(&descriptors).ok();
        let mut engines = Vec::with_capacity(self.drivers.len());
        for driver in self.drivers.values() {
            let capabilities = driver.capabilities();
            let (detection, reason_code) = match worker.as_ref() {
                Some(worker) => {
                    let detection = driver.detect(worker, &crate::EngineProvisioning::default());
                    let reason_code = match detection.availability {
                        crate::EngineAvailability::Available => None,
                        crate::EngineAvailability::Acquirable => {
                            Some("engine_acquirable".to_string())
                        }
                        crate::EngineAvailability::Incompatible => {
                            Some("engine_incompatible".to_string())
                        }
                        crate::EngineAvailability::Blocked => Some("engine_blocked".to_string()),
                    };
                    (detection, reason_code)
                }
                None => (
                    crate::EngineDetection {
                        kind: driver.kind(),
                        availability: crate::EngineAvailability::Incompatible,
                        version: None,
                        reason: String::new(),
                        remediation: None,
                    },
                    Some("no_compatible_device".to_string()),
                ),
            };
            engines.push(NodeEngineSnapshot::from_runtime(
                &detection,
                &capabilities,
                reason_code,
            )?);
        }
        engines.sort_by_key(|engine| engine.engine);

        let metadata = self.artifacts.cached_artifacts().map_err(|error| {
            tracing::warn!(%error, "inspect node artifact inventory");
            NodeSnapshotError::Invalid("artifact inventory is unavailable".to_string())
        })?;
        let mut artifacts = Vec::with_capacity(metadata.len());
        for artifact in metadata {
            let cache = self
                .artifacts
                .inspect(&artifact.artifact_digest)
                .map_err(|error| {
                    tracing::warn!(
                        artifact_digest = %artifact.artifact_digest,
                        %error,
                        "inspect node artifact for cluster snapshot"
                    );
                    NodeSnapshotError::Invalid(format!(
                        "artifact {} inventory is unavailable",
                        artifact.artifact_digest
                    ))
                })?;
            artifacts.push(NodeArtifactSnapshot::from_cache(
                &artifact.artifact_digest,
                &artifact.logical_model,
                &artifact.variant_id,
                &cache,
            )?);
        }
        artifacts.sort_by(|left, right| left.artifact_digest.cmp(&right.artifact_digest));

        Ok(NodeSnapshotInventory {
            engines,
            devices,
            artifacts,
        })
    }
}

/// Resolve a deployment's model to a [`crate::ResolvedArtifact`], handling
/// raw `hf:Org/Repo[:QUANT]` references that have no catalog-v2 variant.
///
/// A catalog id resolves through the pinned catalog path. A raw `hf:` ref
/// synthesizes an unpinned artifact ([`crate::ResolvedArtifact::unpinned`]):
/// there are no bytes to stage, so the container engine self-downloads the
/// weights from the repo at launch. Modality has no serve-entry field, so a
/// raw ref defaults to chat; `gguf_file` selects the GGUF format (llama.cpp),
/// otherwise safetensors (vLLM/SGLang).
fn resolve_artifact_or_unpinned(
    catalog: &crate::Catalog,
    desired: &crate::ModelDeployment,
    legacy_entry: Option<&crate::config::ServeEntry>,
    worker: &WorkerProfile,
) -> Result<crate::ResolvedArtifact, RuntimeManagerError> {
    if desired.model.starts_with("hf:") {
        let model_ref = catalog
            .resolve(&desired.model)
            .map_err(|error| RuntimeManagerError::Prepare(error.to_string()))?;
        let gguf = legacy_entry
            .and_then(|entry| entry.gguf_file.as_ref())
            .is_some();
        let format = if gguf {
            ArtifactFormat::Gguf
        } else {
            ArtifactFormat::Safetensors
        };
        let engine = crate::artifact_spec::forced_engine(desired.engine).unwrap_or(if gguf {
            crate::EngineKind::LlamaCpp
        } else {
            crate::EngineKind::Vllm
        });
        let context_length = legacy_entry
            .and_then(|entry| entry.max_context)
            .unwrap_or(0);
        let modality = legacy_entry
            .and_then(|entry| entry.modality)
            .unwrap_or_default();
        return Ok(crate::ResolvedArtifact::unpinned(
            &desired.model,
            &model_ref.hf_repo,
            &model_ref.quant,
            format,
            engine,
            context_length,
            modality,
        ));
    }
    catalog
        .resolve_artifact(
            &ResolveArtifactRequest {
                model: desired.model.clone(),
                variant: desired.variant.clone(),
                engine: desired.engine,
                replicas: desired.replicas,
                heterogeneous_variants: desired.heterogeneous_variants,
            },
            worker,
        )
        .map_err(|error| RuntimeManagerError::Prepare(error.to_string()))
}

#[async_trait]
impl DeploymentPreparer for ProductionDeploymentPreparer {
    async fn prepare(
        &self,
        request: DeploymentPrepareRequest,
    ) -> Result<Arc<dyn PreparedDeploymentRuntime>, RuntimeManagerError> {
        let worker = WorkerProfile::from_descriptors(&self.probe.probe())
            .map_err(RuntimeManagerError::Prepare)?;
        let resolved = resolve_artifact_or_unpinned(
            &self.catalog,
            &request.desired.desired,
            request.desired.legacy_entry.as_ref(),
            &worker,
        )?;
        let driver = self.drivers.get(&resolved.engine).cloned().ok_or_else(|| {
            RuntimeManagerError::PrepareInfrastructure(format!(
                "no managed {:?} driver is registered for deployment {:?}",
                resolved.engine, request.deployment_id
            ))
        })?;
        if let Some(entry) = request.desired.legacy_entry.as_ref() {
            validate_legacy_managed_entry(entry, resolved.engine)?;
        }
        // WOR-1917: a container runtime makes container the default engine
        // launch, so probe docker/podman once here and thread it into the
        // default-provisioning decision (the same signal `EngineEnv` uses).
        let container_runtime = crate::llama_release::resolve_on_path("docker").is_some()
            || crate::llama_release::resolve_on_path("podman").is_some();
        let provisioning = provisioning_for(&request, resolved.engine, container_runtime);
        let detection = driver.detect(&worker, &provisioning);
        let driver_availability = detection.availability;
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
        let configured_cache = request.control.cache.directory.as_deref().or_else(|| {
            request
                .legacy_host_policy
                .as_ref()
                .and_then(|policy| policy.cache_dir.as_deref())
        });
        let engine_cache_dir = crate::resolve_cache_dir_default(configured_cache).join("engines");
        let supervisor = crate::EngineSupervisor::new(
            request.deployment_id.clone(),
            driver,
            self.backoff,
            Some(self.artifacts.jobs().clone()),
        );
        let artifact_cached = self.artifacts.cached_artifacts().is_ok_and(|artifacts| {
            artifacts
                .iter()
                .any(|artifact| artifact.artifact_digest == resolved.artifact_digest)
        });
        let artifact_lease = self
            .artifacts
            .lease(&resolved.artifact_digest)
            .map_err(|error| RuntimeManagerError::PrepareInfrastructure(error.to_string()))?;
        Ok(Arc::new(ProductionPreparedDeployment {
            id: request.deployment_id,
            generation: request.generation,
            desired: request.desired,
            pinned_fit: request.pinned_fit,
            resolved,
            worker,
            provisioning,
            engine_cache_dir,
            artifacts: self.artifacts.clone(),
            probe: self.probe.clone(),
            metadata: self.metadata.clone(),
            network_policy: self.network_policy,
            params_fallback,
            safety_margin: request.control.safety_margin,
            driver_availability: AtomicU8::new(engine_availability_code(driver_availability)),
            artifact_cached: AtomicBool::new(artifact_cached),
            last_job_id: Mutex::new(None),
            activation: Mutex::new(None),
            supervisor: Mutex::new(supervisor),
            _artifact_lease: artifact_lease,
        }))
    }

    async fn plan_replica_devices(
        &self,
        request: &DeploymentPrepareRequest,
    ) -> Result<Vec<crate::FitPlan>, RuntimeManagerError> {
        let replicas = request.desired.desired.replicas.max(1);
        let tensor_parallel = request
            .desired
            .desired
            .tensor_parallel
            .map(|degree| degree as usize);
        // Packing needs the model's shape and quant, which come from the
        // resolved artifact. Fetch it once here; each replica's own preparation
        // then reads it back from the cache.
        let worker = WorkerProfile::from_descriptors(&self.probe.probe())
            .map_err(RuntimeManagerError::Prepare)?;
        let resolved = resolve_artifact_or_unpinned(
            &self.catalog,
            &request.desired.desired,
            request.desired.legacy_entry.as_ref(),
            &worker,
        )?;
        let params_fallback = self
            .catalog
            .get(&resolved.logical_model)
            .map(|entry| crate::parse_params(&entry.params))
            .unwrap_or(0);
        let pull_policy = request.desired.desired.pull;
        let ready = if resolved.is_unpinned() {
            self.artifacts
                .ensure_unpinned(&resolved)
                .await
                .map_err(RuntimeManagerError::from)?
        } else {
            self.artifacts
                .ensure(
                    &resolved,
                    AcquisitionContext {
                        intent: PullIntent::Startup,
                        network: self.network_policy,
                        pull_policy,
                        credential: None,
                    },
                )
                .await
                .map_err(RuntimeManagerError::from)?
        };
        let metadata = ready_metadata(self.metadata.as_ref(), &resolved, &ready, params_fallback)
            .await
            .ok_or_else(|| {
                RuntimeManagerError::Prepare(format!(
                    "verified artifact {} has no usable model shape metadata",
                    resolved.artifact_digest
                ))
            })?;
        // A raw `hf:` ref carries no declared context, so fall back to the
        // shape the weights declare (config.json) rather than capping the
        // served model to a 1-token context.
        let seq_len = request
            .desired
            .legacy_entry
            .as_ref()
            .and_then(|entry| entry.max_context)
            .filter(|value| *value > 0)
            .or_else(|| Some(resolved.context_length).filter(|value| *value > 0))
            .or_else(|| Some(metadata.max_context).filter(|value| *value > 0))
            .unwrap_or(1);
        let kv_quant = request
            .desired
            .legacy_entry
            .as_ref()
            .map(|entry| entry.kv_quant)
            .unwrap_or(KvCacheQuant::Auto);
        let concurrency = request.desired.desired.max_concurrency.unwrap_or(1);
        crate::fit::plan_replica_fits(
            &self.probe.probe(),
            &metadata,
            std::slice::from_ref(&resolved.quant),
            seq_len,
            crate::fit::DEFAULT_OVERHEAD,
            request.control.safety_margin,
            kv_quant.bytes_per_element(),
            concurrency,
            replicas,
            tensor_parallel,
        )
        .map_err(|error| RuntimeManagerError::Prepare(error.to_string()))
    }
}

fn validate_legacy_managed_entry(
    entry: &crate::ServeEntry,
    engine: EngineKind,
) -> Result<(), RuntimeManagerError> {
    crate::desired::validate_legacy_managed_compatibility(entry, Some(engine))
        .map_err(RuntimeManagerError::Prepare)
}

struct ProductionPreparedDeployment {
    id: String,
    generation: u64,
    desired: CompiledDeployment,
    /// Node-level device set pinned for this replica; when present,
    /// activation uses it instead of choosing devices itself.
    pinned_fit: Option<crate::FitPlan>,
    resolved: crate::ResolvedArtifact,
    worker: WorkerProfile,
    provisioning: EngineProvisioning,
    engine_cache_dir: std::path::PathBuf,
    artifacts: Arc<ArtifactManager>,
    probe: Arc<dyn GpuProbe>,
    metadata: Arc<dyn ModelMetadataProvider>,
    network_policy: NetworkPolicy,
    params_fallback: u64,
    safety_margin: f64,
    driver_availability: AtomicU8,
    artifact_cached: AtomicBool,
    last_job_id: Mutex<Option<String>>,
    activation: Mutex<Option<PreparedActivation>>,
    supervisor: Mutex<crate::EngineSupervisor>,
    _artifact_lease: crate::ArtifactLease,
}

#[derive(Debug, Clone)]
struct PreparedActivation {
    fit: crate::FitPlan,
    selected_devices: Vec<u32>,
    kv_quant: KvCacheQuant,
    extra_args: Vec<String>,
    engine_tuning: crate::EngineTuning,
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

impl ProductionPreparedDeployment {
    async fn ensure_artifact(
        &self,
        intent: PullIntent,
    ) -> Result<crate::ReadyArtifact, RuntimeManagerError> {
        let pull_policy = self.desired.desired.pull;
        let artifact_intent =
            if intent == PullIntent::Startup && pull_policy != crate::PullPolicy::OnBoot {
                PullIntent::Runtime
            } else {
                intent
            };
        let ready = if self.resolved.is_unpinned() {
            self.artifacts
                .ensure_unpinned(&self.resolved)
                .await
                .map_err(RuntimeManagerError::from)?
        } else {
            self.artifacts
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
                .map_err(RuntimeManagerError::from)?
        };
        self.artifact_cached.store(true, Ordering::SeqCst);
        *self.last_job_id.lock().await = Some(ready.job.id.clone());
        Ok(ready)
    }

    async fn activation_plan(
        &self,
        intent: PullIntent,
    ) -> Result<PreparedActivation, RuntimeManagerError> {
        let mut activation = self.activation.lock().await;
        if let Some(prepared) = activation.as_ref() {
            return Ok(prepared.clone());
        }
        let ready = self.ensure_artifact(intent).await?;
        let kv_quant = self
            .desired
            .legacy_entry
            .as_ref()
            .map(|entry| entry.kv_quant)
            .unwrap_or(KvCacheQuant::Auto);
        // A replica with a node-level device set uses it directly; the rest
        // choose a device by planning a fit here.
        let fit = match self.pinned_fit.clone() {
            Some(pinned) => pinned,
            None => {
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
                    .filter(|value| *value > 0)
                    .or_else(|| Some(self.resolved.context_length).filter(|value| *value > 0))
                    .or_else(|| Some(metadata.max_context).filter(|value| *value > 0))
                    .unwrap_or(1);
                let concurrency = self.desired.desired.max_concurrency.unwrap_or(1);
                crate::fit::plan_fit_auto_kv_with_margin_and_concurrency(
                    self.probe.as_ref(),
                    &metadata,
                    std::slice::from_ref(&self.resolved.quant),
                    seq_len,
                    crate::fit::DEFAULT_OVERHEAD,
                    self.safety_margin,
                    // WOR-1908: a non-decode modality holds no KV cache, so
                    // its KV term is zeroed regardless of the KV-quant lever.
                    self.resolved
                        .modality
                        .kv_bytes_per_element_override(kv_quant.bytes_per_element()),
                    concurrency,
                    self.desired
                        .desired
                        .tensor_parallel
                        .map(|degree| degree as usize),
                )
                .map_err(|error| RuntimeManagerError::Prepare(error.to_string()))?
            }
        };
        let selected_devices = if self.worker.accelerator == AcceleratorKind::Cpu {
            Vec::new()
        } else {
            fit.gpu_indexes.clone()
        };
        tracing::info!(
            deployment = %self.id,
            model = %self.resolved.logical_model,
            engine = ?self.resolved.engine,
            modality = ?self.resolved.modality,
            quant = %fit.quant_name,
            devices = ?selected_devices,
            seq_len = fit.seq_len,
            estimated_vram_bytes = fit.estimated_vram_bytes,
            gpu_memory_fraction = ?fit.gpu_memory_fraction,
            estimated_decode_tokens_per_sec =
                ?fit.throughput.as_ref().map(|t| t.decode_tokens_per_sec),
            moe_cpu_layers = ?fit.moe.as_ref().map(|placement| placement.cpu_moe_layers),
            "model-host fit plan selected",
        );
        // Serving tuning comes from the legacy `serve:` entry when present, and
        // otherwise from the canonical deployment's own fields.
        let extra_args = self
            .desired
            .legacy_entry
            .as_ref()
            .map(|entry| entry.extra_args.clone())
            .unwrap_or_else(|| self.desired.desired.extra_args.clone());
        let engine_tuning = self
            .desired
            .legacy_entry
            .as_ref()
            .map(|entry| crate::EngineTuning {
                chunked_prefill: entry.chunked_prefill,
                tool_call_parser: entry.tool_call_parser.clone(),
                swap_space_gib: entry.swap_space_gib,
                cpu_offload_gib: entry.cpu_offload_gib,
            })
            .unwrap_or_else(|| crate::EngineTuning {
                chunked_prefill: self.desired.desired.chunked_prefill,
                tool_call_parser: self.desired.desired.tool_call_parser.clone(),
                swap_space_gib: self.desired.desired.swap_space_gib,
                cpu_offload_gib: self.desired.desired.cpu_offload_gib,
            });
        let prepared = PreparedActivation {
            fit,
            selected_devices,
            kv_quant,
            extra_args,
            engine_tuning,
        };
        *activation = Some(prepared.clone());
        Ok(prepared)
    }
}

#[async_trait]
impl PreparedDeploymentRuntime for ProductionPreparedDeployment {
    async fn memory_estimate(
        &self,
        intent: PullIntent,
    ) -> Result<crate::MemoryEstimate, RuntimeManagerError> {
        self.activation_plan(intent)
            .await
            .map(|prepared| prepared.fit.memory)
    }

    async fn start(&self, intent: PullIntent) -> Result<RunningEngine, RuntimeManagerError> {
        let prepared = self.activation_plan(intent).await?;
        let ready = self.ensure_artifact(intent).await?;
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
        self.driver_availability.store(
            engine_availability_code(EngineAvailability::Available),
            Ordering::SeqCst,
        );
        let port = allocate_loopback_port()?;
        supervisor
            .ensure_ready(
                &provisioned,
                &LaunchRequest {
                    deployment: self.id.clone(),
                    generation: self.generation,
                    artifact: ready,
                    fit: prepared.fit,
                    port,
                    accelerator: self.worker.accelerator,
                    selected_devices: prepared.selected_devices,
                    kv_quant: prepared.kv_quant,
                    extra_args: prepared.extra_args,
                    engine_tuning: prepared.engine_tuning,
                    max_concurrency: self.desired.desired.max_concurrency.unwrap_or(1),
                    modality: self.resolved.modality,
                    ready_timeout: Duration::from_secs(300),
                },
            )
            .await
            .map_err(RuntimeManagerError::Engine)
    }

    async fn health(&self, running: &RunningEngine) -> Result<EngineHealth, RuntimeManagerError> {
        self.supervisor
            .lock()
            .await
            .health(running)
            .await
            .map_err(RuntimeManagerError::Engine)
    }

    async fn stop(&self, grace: Duration) -> Result<(), RuntimeManagerError> {
        let job = self
            .supervisor
            .lock()
            .await
            .shutdown(grace)
            .await
            .map_err(RuntimeManagerError::Engine)?;
        if let Some(job) = job {
            *self.last_job_id.lock().await = Some(job.id);
        }
        Ok(())
    }

    async fn reset(&self) -> Result<Option<OperationJob>, RuntimeManagerError> {
        let job = self
            .supervisor
            .lock()
            .await
            .reset()
            .map_err(RuntimeManagerError::Engine)?;
        if let Some(job) = &job {
            *self.last_job_id.lock().await = Some(job.id.clone());
        }
        Ok(job)
    }

    async fn telemetry(&self) -> PreparedRuntimeTelemetry {
        let activation = self
            .activation
            .try_lock()
            .ok()
            .and_then(|activation| activation.clone());
        let supervisor_job = self
            .supervisor
            .try_lock()
            .ok()
            .and_then(|supervisor| supervisor.last_job_id());
        let retained_job = self.last_job_id.try_lock().ok().and_then(|job| job.clone());
        let job_id = supervisor_job.or(retained_job);
        PreparedRuntimeTelemetry {
            phase: if self.artifact_cached.load(Ordering::SeqCst) {
                PreparedRuntimePhase::Cached
            } else {
                PreparedRuntimePhase::Assigned
            },
            engine: Some(self.resolved.engine),
            driver_availability: Some(engine_availability_from_code(
                self.driver_availability.load(Ordering::SeqCst),
            )),
            artifact_digest: Some(self.resolved.artifact_digest.clone()),
            selected_devices: activation
                .as_ref()
                .map(|prepared| prepared.selected_devices.clone())
                .unwrap_or_default(),
            memory: activation.map(|prepared| prepared.fit.memory),
            job_id,
        }
    }
}

/// The curated digest-pinned default container image for a
/// container-capable Python engine (WOR-1917), or `None` for an engine that
/// has no container-first default here (llama.cpp, the embedded engine).
fn default_container_image(kind: EngineKind) -> Option<&'static str> {
    match kind {
        EngineKind::Vllm => Some(crate::vllm_driver::DEFAULT_VLLM_IMAGE),
        EngineKind::SGLang => Some(crate::sglang_driver::DEFAULT_SGLANG_IMAGE),
        EngineKind::LlamaCpp | EngineKind::Embedded => None,
    }
}

/// The container-first default provisioning (WOR-1917) for an engine the
/// operator did not configure under `engines:`.
///
/// Returns `Some` container provisioning when the worker has a container
/// runtime and the engine is a container-capable Python engine (vLLM or
/// SGLang); it packages the whole CUDA and Python toolchain, so it serves
/// cleanly with no host build cascade, unlike the fragile host uv path.
/// Returns `None` when the caller should keep the prior binary/uv default:
/// no container runtime, or a non-container engine (llama.cpp, embedded). A
/// per-deployment `engine_image` pin overrides the curated default image.
fn container_first_default(
    kind: EngineKind,
    container_runtime: bool,
    pinned_image: Option<&str>,
) -> Option<EngineProvisioning> {
    if !container_runtime {
        return None;
    }
    let default_image = default_container_image(kind)?;
    Some(EngineProvisioning {
        launch: EngineLaunchMethod::Container,
        image: Some(pinned_image.unwrap_or(default_image).to_string()),
        acquire: None,
        shm_size_gib: None,
    })
}

fn provisioning_for(
    request: &DeploymentPrepareRequest,
    kind: EngineKind,
    container_runtime: bool,
) -> EngineProvisioning {
    if request.desired.origin == crate::DesiredDeploymentOrigin::LegacyServe {
        if let Some(configured) = request
            .legacy_host_policy
            .as_ref()
            .and_then(|policy| policy.engines.get(&kind))
        {
            return configured.clone();
        }
        // WOR-1917: an unconfigured legacy `serve:` entry gets the same
        // container-first default as a managed deployment, so easy
        // self-hosting works without an explicit `engines:` block wherever
        // a container runtime is present. An explicit engine policy above
        // still wins.
        if let Some(provisioning) = container_first_default(
            kind,
            container_runtime,
            request.desired.desired.engine_image.as_deref(),
        ) {
            return provisioning;
        }
        return EngineProvisioning::default();
    }
    let managed_kind = match kind {
        EngineKind::Vllm => sbproxy_config::ManagedEngineKind::Vllm,
        EngineKind::SGLang => sbproxy_config::ManagedEngineKind::SGLang,
        EngineKind::LlamaCpp => sbproxy_config::ManagedEngineKind::LlamaCpp,
        EngineKind::Embedded => return EngineProvisioning::default(),
    };
    // WOR-1917: when the operator has not configured this engine under
    // `engines:`, a container-capable Python engine defaults to a
    // digest-pinned container launch wherever a container runtime is
    // present. An explicit `engines:` block still wins (this branch is
    // skipped when one is present), so only the default changes.
    if !request.control.engines.contains_key(&managed_kind) {
        if let Some(provisioning) = container_first_default(
            kind,
            container_runtime,
            request.desired.desired.engine_image.as_deref(),
        ) {
            return provisioning;
        }
    }
    let config = request
        .control
        .engines
        .get(&managed_kind)
        .cloned()
        .unwrap_or_default();
    // A per-deployment engine pin overrides the node-wide policy field by
    // field, so one model can run a different backend version than another.
    // The launch method and acceleration stay from the node policy; the pin
    // only replaces the version, image, and expected digest.
    let deployment = &request.desired.desired;
    let version = deployment
        .engine_version
        .clone()
        .or_else(|| config.version.clone());
    let image = deployment
        .engine_image
        .clone()
        .or_else(|| config.image.clone());
    let sha256 = deployment
        .engine_sha256
        .clone()
        .or_else(|| config.sha256.clone());
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
            version: version.clone(),
            accel,
            path: None,
            sha256: sha256.clone(),
        }),
        sbproxy_config::ManagedEngineLaunch::Binary
            if config.path.is_some()
                || version.is_some()
                || sha256.is_some()
                || config.acceleration != sbproxy_config::ManagedEngineAcceleration::Auto =>
        {
            Some(crate::EngineAcquire {
                source: if config.path.is_some() {
                    AcquireSource::Path
                } else {
                    AcquireSource::Release
                },
                version: version.clone(),
                accel,
                path: config.path.clone(),
                sha256: sha256.clone(),
            })
        }
        _ => None,
    };
    EngineProvisioning {
        launch,
        image,
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
        .map_err(|error| {
            RuntimeManagerError::PrepareInfrastructure(format!("allocate loopback port: {error}"))
        })
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

fn residency_policy(desired: &RuntimeDesiredState) -> crate::DeviceResidencyPolicy {
    let eviction = desired
        .legacy_host_policy
        .as_ref()
        .map_or(crate::EvictionPolicy::Lru, |policy| policy.eviction);
    crate::DeviceResidencyPolicy::new(desired.control.cache.max_resident_models, eviction)
}

fn plan_reconciliation(current: &RuntimeSnapshot, desired: &RuntimeDesiredState) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    for (id, candidate) in &desired.deployments {
        match current.slots.get(id) {
            None => plan.added.push(id.clone()),
            Some(replicas)
                if *replicas.preparation_identity()
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
        .load_or_rebase_empty_catalog(expected_catalog_revision)
        .map_err(|error| RuntimeManagerError::Store(error.to_string()))?;
    let (source_revision, deployments) = match stored {
        Some(revision) => {
            debug_assert_eq!(revision.catalog_revision, expected_catalog_revision);
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
    desired.deployments = compile_canonical_deployments(deployments);
    desired.control.deployments.clear();
    desired.legacy_host_policy = None;
    Ok(desired)
}

fn normalize_admin_revision(
    mut template: RuntimeDesiredState,
    revision: DeploymentRevision,
    expected_catalog_revision: &str,
) -> Result<RuntimeDesiredState, RuntimeManagerError> {
    if template.control.authority != sbproxy_config::ModelHostAuthority::AdminManaged
        || template.revision.source_mode != DeploymentSourceMode::AdminManaged
    {
        return Err(RuntimeManagerError::InvalidDesired(
            "admin revision preparation requires admin_managed authority".to_string(),
        ));
    }
    let configured_store = template.control.store_path.as_deref().ok_or_else(|| {
        RuntimeManagerError::InvalidDesired(
            "admin-managed model host requires a deployment store path".to_string(),
        )
    })?;
    if configured_store.trim().is_empty() {
        return Err(RuntimeManagerError::InvalidDesired(
            "admin-managed model host requires a non-empty deployment store path".to_string(),
        ));
    }
    revision
        .validate()
        .map_err(|error| RuntimeManagerError::InvalidDesired(error.to_string()))?;
    if revision.source_mode != DeploymentSourceMode::AdminManaged {
        return Err(RuntimeManagerError::InvalidDesired(format!(
            "admin revision preparation requires admin_managed source mode, got {:?}",
            revision.source_mode
        )));
    }
    if template.revision.catalog_revision != expected_catalog_revision {
        return Err(RuntimeManagerError::InvalidDesired(format!(
            "template catalog revision {:?} differs from active {:?}",
            template.revision.catalog_revision, expected_catalog_revision
        )));
    }
    if revision.catalog_revision != expected_catalog_revision {
        return Err(RuntimeManagerError::InvalidDesired(format!(
            "candidate catalog revision {:?} differs from active {:?}",
            revision.catalog_revision, expected_catalog_revision
        )));
    }

    template.revision = DeploymentRevisionDraft {
        source_mode: DeploymentSourceMode::AdminManaged,
        source_revision: format!("{}#{}", revision.source_revision, revision.revision),
        catalog_revision: revision.catalog_revision,
        deployments: revision.deployments.clone(),
    };
    template.deployments = compile_canonical_deployments(revision.deployments);
    template.control.deployments.clear();
    template.legacy_host_policy = None;
    validate_desired_state(&template, expected_catalog_revision)?;
    Ok(template)
}

fn compile_canonical_deployments(
    deployments: BTreeMap<String, crate::ModelDeployment>,
) -> BTreeMap<String, CompiledDeployment> {
    deployments
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
        .collect()
}

fn runtime_error_reason_code(error: &RuntimeManagerError) -> &'static str {
    match error {
        RuntimeManagerError::InvalidDesired(_) => "invalid_desired",
        RuntimeManagerError::Prepare(_) => "prepare_failed",
        RuntimeManagerError::PrepareInfrastructure(_) => "prepare_infrastructure_failed",
        RuntimeManagerError::Engine(error) => error.reason().as_str(),
        RuntimeManagerError::Admission(rejection) => rejection.reason.as_str(),
        RuntimeManagerError::Store(_) => "store_failed",
        RuntimeManagerError::UnknownDeployment(_) => "unknown_deployment",
        RuntimeManagerError::Draining(_) => "draining",
        RuntimeManagerError::StalePrepared { .. } => "stale_revision",
        RuntimeManagerError::CounterOverflow => "counter_overflow",
    }
}

const fn engine_availability_code(availability: EngineAvailability) -> u8 {
    match availability {
        EngineAvailability::Available => 0,
        EngineAvailability::Acquirable => 1,
        EngineAvailability::Incompatible => 2,
        EngineAvailability::Blocked => 3,
    }
}

const fn engine_availability_from_code(code: u8) -> EngineAvailability {
    match code {
        0 => EngineAvailability::Available,
        1 => EngineAvailability::Acquirable,
        2 => EngineAvailability::Incompatible,
        _ => EngineAvailability::Blocked,
    }
}

fn bounded_status_text(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(512)
        .collect()
}

async fn teardown_slots(slots: Vec<Arc<DeploymentSlot>>, grace: Duration) {
    for slot in slots {
        let _ = slot.stop(grace).await;
    }
}

/// Sum the counts of two drain reports and take the worse timeout, so a
/// deployment-wide drain reports across all its replicas as one result.
fn merge_drain_reports(
    accumulated: Option<crate::DrainReport>,
    report: crate::DrainReport,
) -> crate::DrainReport {
    match accumulated {
        None => report,
        Some(base) => crate::DrainReport {
            active_at_start: base.active_at_start.saturating_add(report.active_at_start),
            cancelled_queued: base
                .cancelled_queued
                .saturating_add(report.cancelled_queued),
            remaining_active: base
                .remaining_active
                .saturating_add(report.remaining_active),
            timed_out: base.timed_out || report.timed_out,
        },
    }
}

/// Pick the replica with the fewest in-flight requests (ties by replica
/// index), so local admission spreads across a deployment's replicas. This is
/// the deployment-local default balance; the request router applies the named
/// strategies across the wider replica set.
fn select_admission_replica(replicas: &DeploymentReplicas) -> Arc<DeploymentSlot> {
    let mut best: Option<(usize, u32)> = None;
    let mut chosen = replicas.primary();
    for slot in replicas.iter() {
        let counts = slot.admission.counts();
        let load = counts.active.saturating_add(counts.queued);
        let key = (load, slot.replica_idx);
        if best.is_none_or(|current| key < current) {
            best = Some(key);
            chosen = slot;
        }
    }
    chosen.clone()
}

/// Every replica slot backing the named deployment IDs, for teardown.
fn candidate_replica_slots(
    ids: &[String],
    slots: &BTreeMap<String, DeploymentReplicas>,
) -> Vec<Arc<DeploymentSlot>> {
    ids.iter()
        .filter_map(|id| slots.get(id))
        .flat_map(|replicas| replicas.iter().cloned())
        .collect()
}

async fn rollback_recreate_slots(
    checkpoints: Vec<(Arc<DeploymentSlot>, RecreateCheckpoint)>,
    limiter: Arc<Semaphore>,
) -> Option<String> {
    let mut failures = Vec::new();
    for (slot, checkpoint) in checkpoints.into_iter().rev() {
        if let Err(error) = slot
            .restore_after_recreate_abort(checkpoint, limiter.clone())
            .await
        {
            failures.push(format!("deployment {:?}: {error}", slot.id));
        }
    }
    (!failures.is_empty()).then(|| failures.join("; "))
}

#[cfg(test)]
mod provisioning_tests {
    use super::*;

    fn request(deployment_yaml: &str, control_yaml: &str) -> DeploymentPrepareRequest {
        let desired: CompiledDeployment = CompiledDeployment {
            desired: serde_yaml::from_str(deployment_yaml).expect("deployment parses"),
            origin: crate::DesiredDeploymentOrigin::Canonical,
            legacy_entry: None,
        };
        DeploymentPrepareRequest {
            deployment_id: "m".to_string(),
            replica_idx: 0,
            generation: 1,
            desired,
            pinned_fit: None,
            control: serde_yaml::from_str(control_yaml).expect("control parses"),
            legacy_host_policy: None,
        }
    }

    #[test]
    fn a_deployment_engine_version_overrides_the_node_policy() {
        let control = "engines:\n  vllm:\n    launch: uv\n    version: 0.10.0\n";
        // With no per-deployment pin, the node policy's version resolves.
        let node = request("model: qwen3-8b\nengine: vllm\n", control);
        // The operator configured `engines.vllm`, so the container-first
        // default is skipped regardless of the container-runtime signal.
        let resolved = provisioning_for(&node, EngineKind::Vllm, false);
        assert_eq!(
            resolved.acquire.as_ref().and_then(|a| a.version.as_deref()),
            Some("0.10.0")
        );
        // A per-deployment pin overrides it, so two models on one node can run
        // different backend versions.
        let pinned = request(
            "model: qwen3-8b\nengine: vllm\nengine_version: 0.11.0\n",
            control,
        );
        let resolved = provisioning_for(&pinned, EngineKind::Vllm, false);
        assert_eq!(
            resolved.acquire.as_ref().and_then(|a| a.version.as_deref()),
            Some("0.11.0")
        );
    }

    #[test]
    fn a_deployment_engine_image_overrides_the_node_policy() {
        let control =
            "engines:\n  vllm:\n    launch: container\n    image: vllm/vllm-openai:v0.10.0\n";
        let pinned = request(
            "model: qwen3-8b\nengine: vllm\nengine_image: vllm/vllm-openai:v0.11.0\n",
            control,
        );
        let resolved = provisioning_for(&pinned, EngineKind::Vllm, false);
        assert_eq!(resolved.image.as_deref(), Some("vllm/vllm-openai:v0.11.0"));
    }

    // --- WOR-1917: container-first default provisioning ---

    #[test]
    fn container_first_default_prefers_container_for_python_engines() {
        // A container runtime present and a container-capable engine: the
        // default is a container launch with the curated digest-pinned image.
        let vllm = container_first_default(EngineKind::Vllm, true, None).expect("vllm default");
        assert_eq!(vllm.launch, EngineLaunchMethod::Container);
        assert_eq!(
            vllm.image.as_deref(),
            Some(crate::vllm_driver::DEFAULT_VLLM_IMAGE)
        );
        assert!(vllm.acquire.is_none());

        let sglang =
            container_first_default(EngineKind::SGLang, true, None).expect("sglang default");
        assert_eq!(sglang.launch, EngineLaunchMethod::Container);
        assert_eq!(
            sglang.image.as_deref(),
            Some(crate::sglang_driver::DEFAULT_SGLANG_IMAGE)
        );
    }

    #[test]
    fn container_first_default_keeps_binary_without_a_runtime() {
        // No container runtime: fall through to the prior binary/uv default.
        assert!(container_first_default(EngineKind::Vllm, false, None).is_none());
        assert!(container_first_default(EngineKind::SGLang, false, None).is_none());
    }

    #[test]
    fn container_first_default_skips_non_container_engines() {
        // llama.cpp and the embedded engine have no container-first default
        // even when a container runtime is present.
        assert!(container_first_default(EngineKind::LlamaCpp, true, None).is_none());
        assert!(container_first_default(EngineKind::Embedded, true, None).is_none());
    }

    #[test]
    fn container_first_default_honours_a_per_deployment_image_pin() {
        // A per-deployment `engine_image` pin overrides the curated default.
        let pinned = "vllm/vllm-openai@sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let resolved =
            container_first_default(EngineKind::Vllm, true, Some(pinned)).expect("vllm default");
        assert_eq!(resolved.image.as_deref(), Some(pinned));
    }

    #[test]
    fn unconfigured_vllm_defaults_to_container_when_a_runtime_is_present() {
        // No `engines:` block at all: with a container runtime the default
        // vLLM provisioning is the curated digest-pinned container image.
        let node = request(
            "model: qwen3-8b\nengine: vllm\n",
            "authority: file_managed\n",
        );
        let resolved = provisioning_for(&node, EngineKind::Vllm, true);
        assert_eq!(resolved.launch, EngineLaunchMethod::Container);
        assert_eq!(
            resolved.image.as_deref(),
            Some(crate::vllm_driver::DEFAULT_VLLM_IMAGE)
        );

        // Without a container runtime the default keeps the prior binary path.
        let resolved = provisioning_for(&node, EngineKind::Vllm, false);
        assert_eq!(resolved.launch, EngineLaunchMethod::Binary);
        assert!(resolved.image.is_none());
    }

    #[test]
    fn an_operator_uv_engine_block_still_wins_over_container_default() {
        // An explicit `engines.vllm.launch: uv` wins even where a container
        // runtime is present: only the DEFAULT changes.
        let control = "engines:\n  vllm:\n    launch: uv\n    version: 0.10.0\n";
        let node = request("model: qwen3-8b\nengine: vllm\n", control);
        let resolved = provisioning_for(&node, EngineKind::Vllm, true);
        assert_eq!(resolved.launch, EngineLaunchMethod::Venv);
        assert!(resolved.image.is_none());
    }
}
