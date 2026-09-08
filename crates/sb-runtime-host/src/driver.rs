// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Typed managed-engine driver boundary.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sb_runtime_core::{
    EngineCapabilities, EngineDetection, EngineDriverError, EngineExecutionIdentity,
    EngineFailureReason, EngineHealth, EngineKind,
};

/// Consumer-typed provisioning inputs, without a dependency on a catalog or job store.
#[derive(Clone)]
pub struct ProvisionRequest<Artifact, Worker, Provisioning> {
    /// Artifact selected and authorized by the consumer.
    pub artifact: Artifact,
    /// Worker compatibility facts interpreted by the driver.
    pub worker: Worker,
    /// Consumer-owned provisioning policy and progress context.
    pub provisioning: Provisioning,
    /// Explicit root for managed engine binaries and environments.
    pub engine_cache_dir: PathBuf,
}

impl<Artifact, Worker, Provisioning> fmt::Debug
    for ProvisionRequest<Artifact, Worker, Provisioning>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Generic consumer payloads may contain credentials or private catalog data.
        formatter
            .debug_struct("ProvisionRequest")
            .field("engine_cache_dir", &self.engine_cache_dir)
            .finish_non_exhaustive()
    }
}

/// Installation identity and consumer-owned state returned by provisioning.
#[derive(Clone, PartialEq, Eq)]
pub struct ProvisionedEngine<State> {
    /// Engine implemented by the selected installation.
    pub kind: EngineKind,
    /// Explicit executable or container-runtime binary to launch.
    pub executable: PathBuf,
    /// Resolved engine version, when known.
    pub version: Option<String>,
    /// Stable identity of the installation or image.
    pub fingerprint: String,
    /// Typed installation state retained by the driver, never interpreted by the host.
    pub state: State,
}

impl<State> fmt::Debug for ProvisionedEngine<State> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedEngine")
            .field("kind", &self.kind)
            .field("executable", &self.executable)
            .field("version", &self.version)
            .field("fingerprint", &self.fingerprint)
            // Provisioning state can carry consumer secrets; do not format it.
            .finish_non_exhaustive()
    }
}

/// Launch identity and consumer-typed inputs for one managed process.
///
/// Constructing this envelope does not establish artifact trust. The consumer
/// must enforce its own artifact, placement and argument policies before launch.
#[derive(Clone)]
pub struct LaunchRequest<Artifact, Fit, Accelerator, Tuning> {
    /// Runtime-owned deployment, generation, kind and serving port.
    pub identity: EngineExecutionIdentity,
    /// Artifact already authorized by the consumer's trust boundary.
    pub artifact: Artifact,
    /// Device and memory fit selected for this replica.
    pub fit: Fit,
    /// Accelerator selected by consumer compatibility and placement rules.
    pub accelerator: Accelerator,
    /// Worker-local device indices assigned to this replica.
    pub selected_devices: Vec<u32>,
    /// Consumer-owned tuning, interpreted only by its driver.
    pub tuning: Tuning,
    /// Maximum concurrent sequences reserved for this replica.
    pub max_concurrency: u32,
    /// Maximum wait for readiness after spawning the engine.
    pub ready_timeout: Duration,
}

impl<Artifact, Fit, Accelerator, Tuning> LaunchRequest<Artifact, Fit, Accelerator, Tuning> {
    /// Validate host-owned fields before the consumer checks artifact or tuning policy.
    ///
    /// Refusal order is deployment, generation, port, readiness timeout, then
    /// concurrency, matching the existing managed-driver launch boundary.
    pub fn validate(&self) -> Result<(), EngineDriverError> {
        self.identity.validate()?;
        if self.ready_timeout.is_zero() {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "readiness timeout must be positive",
                "configure a positive engine readiness deadline",
                false,
            ));
        }
        if self.max_concurrency == 0 {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "launch max_concurrency must be positive",
                "compile a positive managed deployment concurrency limit",
                false,
            ));
        }
        Ok(())
    }
}

impl<Artifact, Fit, Accelerator, Tuning> fmt::Debug
    for LaunchRequest<Artifact, Fit, Accelerator, Tuning>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Trust, fit and tuning remain opaque at this consumer-neutral boundary.
        formatter
            .debug_struct("LaunchRequest")
            .field("identity", &self.identity)
            .field("selected_devices", &self.selected_devices)
            .field("max_concurrency", &self.max_concurrency)
            .field("ready_timeout", &self.ready_timeout)
            .finish_non_exhaustive()
    }
}

/// One live engine's execution identity, resource accounting and owned process handle.
///
/// `Process` is explicit so a consumer can retain either its concrete handle or
/// a process trait object without type erasure or a dependency on a specific driver.
pub struct RunningEngine<Accelerator, Memory, Process: ?Sized> {
    /// Runtime-owned identity of the active generation.
    pub identity: EngineExecutionIdentity,
    /// Worker-local device indices assigned to this process.
    pub selected_devices: Vec<u32>,
    /// Accelerator actually used by the process.
    pub accelerator: Accelerator,
    /// Process start time as Unix milliseconds.
    pub started_at_ms: u64,
    /// Identity of the artifact authorized by the consumer.
    pub artifact_digest: String,
    /// Engine version selected by provisioning, when known.
    pub engine_version: Option<String>,
    /// Consumer-typed memory reservation for this generation.
    pub memory: Memory,
    /// Shared ownership of a concrete process handle or an explicit process trait object.
    pub process: Arc<Process>,
}

impl<Accelerator: Clone, Memory: Clone, Process: ?Sized> Clone
    for RunningEngine<Accelerator, Memory, Process>
{
    fn clone(&self) -> Self {
        // Cloning ownership must not require the process itself to be cloneable.
        Self {
            identity: self.identity.clone(),
            selected_devices: self.selected_devices.clone(),
            accelerator: self.accelerator.clone(),
            started_at_ms: self.started_at_ms,
            artifact_digest: self.artifact_digest.clone(),
            engine_version: self.engine_version.clone(),
            memory: self.memory.clone(),
            process: Arc::clone(&self.process),
        }
    }
}

impl<Accelerator, Memory, Process: ?Sized> fmt::Debug
    for RunningEngine<Accelerator, Memory, Process>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never invoke arbitrary process/payload Debug implementations during diagnostics.
        formatter
            .debug_struct("RunningEngine")
            .field("identity", &self.identity)
            .field("selected_devices", &self.selected_devices)
            .field("started_at_ms", &self.started_at_ms)
            .field("artifact_digest", &self.artifact_digest)
            .field("engine_version", &self.engine_version)
            .finish_non_exhaustive()
    }
}

/// Typed engine lifecycle implemented by a consumer's managed-runtime driver.
///
/// Associated types preserve each consumer's artifact, provisioning, placement
/// and process boundaries. The neutral host neither downcasts them nor grants
/// authority to launch a process merely because a value implements this trait.
#[async_trait]
pub trait EngineDriver: Send + Sync {
    /// Artifact-format vocabulary advertised by this driver.
    type ArtifactFormat: Send + Sync;
    /// Accelerator vocabulary advertised by this driver.
    type Accelerator: Send + Sync;
    /// Worker compatibility facts accepted by detection.
    type Worker: Send + Sync;
    /// Provisioning policy inspected by detection.
    type Provisioning: Send + Sync;
    /// Typed provisioning request accepted by this driver.
    type ProvisionRequest: Send + Sync;
    /// Installation selected by provisioning.
    type ProvisionedEngine: Send + Sync;
    /// Consumer-validated launch request.
    type LaunchRequest: Send + Sync;
    /// Live generation and process ownership returned by launch.
    type RunningEngine: Clone + Send + Sync;

    /// Engine kind implemented by this driver.
    fn kind(&self) -> EngineKind;

    /// Static compatibility facts for the driver's artifact and accelerator vocabularies.
    fn capabilities(&self) -> EngineCapabilities<Self::ArtifactFormat, Self::Accelerator>;

    /// Detect installed or provisionable engine paths using the consumer's policy.
    fn detect(&self, worker: &Self::Worker, provisioning: &Self::Provisioning) -> EngineDetection;

    /// Extract the runtime-owned identity from a typed launch request.
    fn launch_identity(&self, request: &Self::LaunchRequest) -> EngineExecutionIdentity;

    /// Extract the identity of a live generation without changing it.
    fn running_identity(&self, running: &Self::RunningEngine) -> EngineExecutionIdentity;

    /// Provision or select the exact engine installation authorized by the request.
    async fn provision(
        &self,
        request: &Self::ProvisionRequest,
    ) -> Result<Self::ProvisionedEngine, EngineDriverError>;

    /// Launch authorized artifact bytes and wait for the consumer's readiness probe.
    async fn launch(
        &self,
        provisioned: &Self::ProvisionedEngine,
        request: &Self::LaunchRequest,
    ) -> Result<Self::RunningEngine, EngineDriverError>;

    /// Observe the running generation without changing desired state.
    async fn health(
        &self,
        running: &Self::RunningEngine,
    ) -> Result<EngineHealth, EngineDriverError>;

    /// Stop the owned generation, forcing termination after the supplied grace period.
    async fn shutdown(
        &self,
        running: Self::RunningEngine,
        grace: Duration,
    ) -> Result<(), EngineDriverError>;
}
