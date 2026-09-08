// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Reusable deterministic fixtures for managed-runtime consumers.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sb_runtime_core::{
    EngineAvailability, EngineCapabilities, EngineDetection, EngineDriverError,
    EngineExecutionIdentity, EngineFailureReason, EngineHealth, EngineKind,
};

use crate::{
    CommandExecutor, CommandOutput, EngineDriver, EngineProcess, EngineReadinessProbe,
    LaunchRequest, ProvisionRequest, ProvisionedEngine, RunningEngine, SupervisorClock,
};

/// Provisioning request used by [`ScriptedDriver`].
pub type ScriptedProvisionRequest = ProvisionRequest<String, String, String>;
/// Provisioned installation used by [`ScriptedDriver`].
pub type ScriptedProvisionedEngine = ProvisionedEngine<String>;
/// Launch request used by [`ScriptedDriver`].
pub type ScriptedLaunchRequest = LaunchRequest<String, u64, String, ()>;
/// Running generation used by [`ScriptedDriver`].
pub type ScriptedRunningEngine = RunningEngine<String, u64, dyn EngineProcess>;

/// Controllable process handle for consumer lifecycle tests.
pub struct FakeProcess {
    id: Option<u32>,
    exited: AtomicBool,
    shutdowns: AtomicU32,
    fail_shutdown: AtomicBool,
    stderr_tail: Mutex<String>,
}

impl fmt::Debug for FakeProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeProcess")
            .field("id", &self.id)
            .field("exited", &self.exited.load(Ordering::SeqCst))
            .field("shutdown_count", &self.shutdown_count())
            .finish_non_exhaustive()
    }
}

impl FakeProcess {
    /// Construct a live fake process with an optional operating-system ID.
    #[must_use]
    pub fn new(id: Option<u32>) -> Self {
        Self {
            id,
            exited: AtomicBool::new(false),
            shutdowns: AtomicU32::new(0),
            fail_shutdown: AtomicBool::new(false),
            stderr_tail: Mutex::new(String::new()),
        }
    }

    /// Mark the process as exited or live.
    pub fn set_exited(&self, exited: bool) {
        self.exited.store(exited, Ordering::SeqCst);
    }

    /// Inject or clear a shutdown failure.
    pub fn set_shutdown_failure(&self, fail: bool) {
        self.fail_shutdown.store(fail, Ordering::SeqCst);
    }

    /// Replace the bounded diagnostic tail returned by the process.
    pub fn set_stderr_tail(&self, tail: impl Into<String>) {
        *self
            .stderr_tail
            .lock()
            .expect("fake process mutex poisoned") = tail.into();
    }

    /// Number of shutdown calls observed by this process.
    #[must_use]
    pub fn shutdown_count(&self) -> u32 {
        self.shutdowns.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl EngineProcess for FakeProcess {
    fn id(&self) -> Option<u32> {
        self.id
    }

    async fn has_exited(&self) -> Result<bool, EngineDriverError> {
        Ok(self.exited.load(Ordering::SeqCst))
    }

    async fn shutdown(&self, _grace: Duration) -> Result<(), EngineDriverError> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        if self.fail_shutdown.load(Ordering::SeqCst) {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineShutdownFailed,
                "injected fake process shutdown failure",
                "clear the injected shutdown failure and retry",
                true,
            ));
        }
        self.exited.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn stderr_tail(&self) -> String {
        self.stderr_tail
            .lock()
            .expect("fake process mutex poisoned")
            .clone()
    }
}

/// Command executor that always returns one caller-supplied process.
pub struct FakeCommandExecutor {
    process: Arc<dyn EngineProcess>,
    spawns: AtomicU32,
    outputs: Mutex<VecDeque<Result<CommandOutput, EngineDriverError>>>,
}

impl fmt::Debug for FakeCommandExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeCommandExecutor")
            .field("spawn_count", &self.spawn_count())
            .field(
                "queued_output_count",
                &self.outputs.lock().map_or(0, |outputs| outputs.len()),
            )
            .finish_non_exhaustive()
    }
}

impl FakeCommandExecutor {
    /// Construct an executor around a reusable fake process handle.
    #[must_use]
    pub fn new(process: Arc<dyn EngineProcess>) -> Self {
        Self {
            process,
            spawns: AtomicU32::new(0),
            outputs: Mutex::new(VecDeque::new()),
        }
    }

    /// Queue one bounded-output result.
    pub fn push_output(&self, output: Result<CommandOutput, EngineDriverError>) {
        self.outputs
            .lock()
            .expect("fake executor mutex poisoned")
            .push_back(output);
    }

    /// Number of spawn requests observed by this executor.
    #[must_use]
    pub fn spawn_count(&self) -> u32 {
        self.spawns.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl CommandExecutor for FakeCommandExecutor {
    async fn spawn(
        &self,
        _executable: &Path,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::clone(&self.process))
    }

    async fn output(
        &self,
        _executable: &Path,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _timeout: Duration,
        _max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        self.outputs
            .lock()
            .expect("fake executor mutex poisoned")
            .pop_front()
            .unwrap_or_else(|| {
                Ok(CommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
    }
}

/// Readiness probe driven by queued results and a stable fallback.
pub struct FakeReadinessProbe {
    fallback: AtomicBool,
    probes: AtomicU32,
    results: Mutex<VecDeque<Result<bool, EngineDriverError>>>,
}

impl fmt::Debug for FakeReadinessProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeReadinessProbe")
            .field("probe_count", &self.probe_count())
            .field(
                "queued_result_count",
                &self.results.lock().map_or(0, |results| results.len()),
            )
            .finish_non_exhaustive()
    }
}

impl FakeReadinessProbe {
    /// Construct a probe with the result used after its script is exhausted.
    #[must_use]
    pub fn new(fallback: bool) -> Self {
        Self {
            fallback: AtomicBool::new(fallback),
            probes: AtomicU32::new(0),
            results: Mutex::new(VecDeque::new()),
        }
    }

    /// Queue one probe result.
    pub fn push(&self, result: Result<bool, EngineDriverError>) {
        self.results
            .lock()
            .expect("fake readiness mutex poisoned")
            .push_back(result);
    }

    /// Change the fallback result.
    pub fn set_fallback(&self, ready: bool) {
        self.fallback.store(ready, Ordering::SeqCst);
    }

    /// Number of readiness probes observed.
    #[must_use]
    pub fn probe_count(&self) -> u32 {
        self.probes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl EngineReadinessProbe for FakeReadinessProbe {
    async fn ready(&self, _port: u16, _path: &str) -> Result<bool, EngineDriverError> {
        self.probes.fetch_add(1, Ordering::SeqCst);
        self.results
            .lock()
            .expect("fake readiness mutex poisoned")
            .pop_front()
            .unwrap_or_else(|| Ok(self.fallback.load(Ordering::SeqCst)))
    }
}

/// Deterministic clock that records retry sleeps without waiting.
#[derive(Debug, Default)]
pub struct ManualClock {
    now_ms: AtomicU64,
    sleeps: Mutex<Vec<Duration>>,
}

impl ManualClock {
    /// Construct a clock at the supplied Unix millisecond timestamp.
    #[must_use]
    pub fn at(now_ms: u64) -> Self {
        Self {
            now_ms: AtomicU64::new(now_ms),
            sleeps: Mutex::new(Vec::new()),
        }
    }

    /// Retry delays observed by the clock.
    #[must_use]
    pub fn sleeps(&self) -> Vec<Duration> {
        self.sleeps
            .lock()
            .expect("manual clock mutex poisoned")
            .clone()
    }
}

#[async_trait]
impl SupervisorClock for ManualClock {
    async fn sleep(&self, duration: Duration) {
        self.sleeps
            .lock()
            .expect("manual clock mutex poisoned")
            .push(duration);
        let elapsed_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let _ = self
            .now_ms
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
                Some(now.saturating_add(elapsed_ms))
            });
    }

    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

/// Typed driver with queued launch failures and one explicit process handle.
pub struct ScriptedDriver {
    kind: EngineKind,
    process: Arc<dyn EngineProcess>,
    launches: AtomicU32,
    launch_errors: Mutex<VecDeque<EngineDriverError>>,
    health: Mutex<EngineHealth>,
}

impl fmt::Debug for ScriptedDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptedDriver")
            .field("kind", &self.kind)
            .field("launch_count", &self.launch_count())
            .field(
                "queued_launch_error_count",
                &self.launch_errors.lock().map_or(0, |errors| errors.len()),
            )
            .finish_non_exhaustive()
    }
}

impl ScriptedDriver {
    /// Construct an available driver for one engine kind.
    #[must_use]
    pub fn new(kind: EngineKind, process: Arc<dyn EngineProcess>) -> Self {
        Self {
            kind,
            process,
            launches: AtomicU32::new(0),
            launch_errors: Mutex::new(VecDeque::new()),
            health: Mutex::new(EngineHealth::Ready),
        }
    }

    /// Queue one launch failure before the next successful launch.
    pub fn push_launch_error(&self, error: EngineDriverError) {
        self.launch_errors
            .lock()
            .expect("scripted driver mutex poisoned")
            .push_back(error);
    }

    /// Replace the health result returned for a running generation.
    pub fn set_health(&self, health: EngineHealth) {
        *self.health.lock().expect("scripted driver mutex poisoned") = health;
    }

    /// Number of launch attempts observed.
    #[must_use]
    pub fn launch_count(&self) -> u32 {
        self.launches.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl EngineDriver for ScriptedDriver {
    type ArtifactFormat = String;
    type Accelerator = String;
    type Worker = String;
    type Provisioning = String;
    type ProvisionRequest = ScriptedProvisionRequest;
    type ProvisionedEngine = ScriptedProvisionedEngine;
    type LaunchRequest = ScriptedLaunchRequest;
    type RunningEngine = ScriptedRunningEngine;

    fn kind(&self) -> EngineKind {
        self.kind
    }

    fn capabilities(&self) -> EngineCapabilities<Self::ArtifactFormat, Self::Accelerator> {
        EngineCapabilities {
            artifact_formats: vec!["fixture".to_string()],
            accelerators: vec!["fixture".to_string()],
            supports_container: false,
            supports_uv: false,
        }
    }

    fn detect(
        &self,
        _worker: &Self::Worker,
        _provisioning: &Self::Provisioning,
    ) -> EngineDetection {
        EngineDetection {
            kind: self.kind,
            availability: EngineAvailability::Available,
            version: Some("fixture-v1".to_string()),
            reason: "scripted fixture is available".to_string(),
            remediation: None,
        }
    }

    fn launch_identity(&self, request: &Self::LaunchRequest) -> EngineExecutionIdentity {
        request.identity.clone()
    }

    fn running_identity(&self, running: &Self::RunningEngine) -> EngineExecutionIdentity {
        running.identity.clone()
    }

    async fn provision(
        &self,
        request: &Self::ProvisionRequest,
    ) -> Result<Self::ProvisionedEngine, EngineDriverError> {
        Ok(ProvisionedEngine {
            kind: self.kind,
            executable: request.engine_cache_dir.join("fixture-engine"),
            version: Some("fixture-v1".to_string()),
            fingerprint: request.artifact.clone(),
            state: request.provisioning.clone(),
        })
    }

    async fn launch(
        &self,
        provisioned: &Self::ProvisionedEngine,
        request: &Self::LaunchRequest,
    ) -> Result<Self::RunningEngine, EngineDriverError> {
        self.launches.fetch_add(1, Ordering::SeqCst);
        request.validate()?;
        if let Some(error) = self
            .launch_errors
            .lock()
            .expect("scripted driver mutex poisoned")
            .pop_front()
        {
            return Err(error);
        }
        Ok(RunningEngine {
            identity: request.identity.clone(),
            selected_devices: request.selected_devices.clone(),
            accelerator: request.accelerator.clone(),
            started_at_ms: 1,
            artifact_digest: request.artifact.clone(),
            engine_version: provisioned.version.clone(),
            memory: request.fit,
            process: Arc::clone(&self.process),
        })
    }

    async fn health(
        &self,
        _running: &Self::RunningEngine,
    ) -> Result<EngineHealth, EngineDriverError> {
        Ok(*self.health.lock().expect("scripted driver mutex poisoned"))
    }

    async fn shutdown(
        &self,
        running: Self::RunningEngine,
        grace: Duration,
    ) -> Result<(), EngineDriverError> {
        running.process.shutdown(grace).await
    }
}
