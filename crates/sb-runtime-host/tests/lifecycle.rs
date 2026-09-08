// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sb_runtime_core::{
    EngineAvailability, EngineCapabilities, EngineDetection, EngineDriverError,
    EngineExecutionIdentity, EngineFailureReason, EngineHealth, EngineKind,
};
use sb_runtime_host::{
    BackoffPolicy, EngineDriver, EngineSupervisor, LaunchRequest, ProvisionRequest,
    ProvisionedEngine, RunningEngine, SupervisorClock,
};

#[derive(Debug)]
struct FixtureProcess;

#[derive(Debug)]
struct ScriptedDriver {
    launch_calls: AtomicU32,
    failures_before_success: u32,
    retryable: bool,
    shutdown_calls: AtomicU32,
    shutdown_fails: AtomicBool,
}

#[async_trait]
impl EngineDriver for ScriptedDriver {
    type ArtifactFormat = &'static str;
    type Accelerator = &'static str;
    type Worker = ();
    type Provisioning = ();
    type ProvisionRequest = ProvisionRequest<&'static str, (), ()>;
    type ProvisionedEngine = ProvisionedEngine<()>;
    type LaunchRequest = LaunchRequest<&'static str, u64, &'static str, ()>;
    type RunningEngine = RunningEngine<&'static str, u64, FixtureProcess>;

    fn kind(&self) -> EngineKind {
        EngineKind::LlamaCpp
    }

    fn capabilities(&self) -> EngineCapabilities<Self::ArtifactFormat, Self::Accelerator> {
        EngineCapabilities {
            artifact_formats: vec!["gguf"],
            accelerators: vec!["cpu"],
            supports_container: false,
            supports_uv: false,
        }
    }

    fn detect(&self, _worker: &(), _provisioning: &()) -> EngineDetection {
        EngineDetection {
            kind: self.kind(),
            availability: EngineAvailability::Available,
            version: None,
            reason: "fixture".to_string(),
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
        _request: &Self::ProvisionRequest,
    ) -> Result<Self::ProvisionedEngine, EngineDriverError> {
        Ok(ProvisionedEngine {
            kind: self.kind(),
            executable: PathBuf::from("/fixture/engine"),
            version: None,
            fingerprint: "sha256:fixture".to_string(),
            state: (),
        })
    }

    async fn launch(
        &self,
        _provisioned: &Self::ProvisionedEngine,
        request: &Self::LaunchRequest,
    ) -> Result<Self::RunningEngine, EngineDriverError> {
        let call = self.launch_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call <= self.failures_before_success {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineEarlyExit,
                "fixture launch failed",
                "reset the fixture",
                self.retryable,
            )
            .with_diagnostic_tail("Bearer SYNTHETIC_CANARY"));
        }
        Ok(RunningEngine {
            identity: request.identity.clone(),
            selected_devices: Vec::new(),
            accelerator: "cpu",
            started_at_ms: 1,
            artifact_digest: "sha256:model".to_string(),
            engine_version: None,
            memory: 1_024,
            process: Arc::new(FixtureProcess),
        })
    }

    async fn health(
        &self,
        _running: &Self::RunningEngine,
    ) -> Result<EngineHealth, EngineDriverError> {
        Ok(EngineHealth::Ready)
    }

    async fn shutdown(
        &self,
        _running: Self::RunningEngine,
        _grace: Duration,
    ) -> Result<(), EngineDriverError> {
        self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        if self.shutdown_fails.load(Ordering::SeqCst) {
            Err(EngineDriverError::new(
                EngineFailureReason::EngineShutdownFailed,
                "fixture shutdown failed",
                "retry stop",
                true,
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
struct ManualClock {
    now_ms: AtomicU64,
    slept_ms: AtomicU64,
}

#[async_trait]
impl SupervisorClock for ManualClock {
    async fn sleep(&self, duration: Duration) {
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        self.slept_ms.fetch_add(millis, Ordering::SeqCst);
        self.now_ms.fetch_add(millis, Ordering::SeqCst);
    }

    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

fn provisioned() -> ProvisionedEngine<()> {
    ProvisionedEngine {
        kind: EngineKind::LlamaCpp,
        executable: PathBuf::from("/fixture/engine"),
        version: None,
        fingerprint: "sha256:fixture".to_string(),
        state: (),
    }
}

fn launch() -> LaunchRequest<&'static str, u64, &'static str, ()> {
    LaunchRequest {
        identity: EngineExecutionIdentity {
            deployment: "fixture".to_string(),
            generation: 1,
            kind: EngineKind::LlamaCpp,
            port: 18_080,
        },
        artifact: "sha256:model",
        fit: 1_024,
        accelerator: "cpu",
        selected_devices: Vec::new(),
        tuning: (),
        max_concurrency: 1,
        ready_timeout: Duration::from_secs(1),
    }
}

#[tokio::test]
async fn supervisor_retries_with_capped_delays_then_publishes_ready() {
    let driver = Arc::new(ScriptedDriver {
        launch_calls: AtomicU32::new(0),
        failures_before_success: 2,
        retryable: true,
        shutdown_calls: AtomicU32::new(0),
        shutdown_fails: AtomicBool::new(false),
    });
    let clock = Arc::new(ManualClock::default());
    let mut supervisor = EngineSupervisor::new(
        "fixture",
        driver.clone(),
        BackoffPolicy {
            base: Duration::from_millis(10),
            max: Duration::from_millis(15),
            max_attempts: Some(3),
        },
    )
    .with_clock(clock.clone());

    let running = supervisor
        .ensure_ready(&provisioned(), &launch())
        .await
        .expect("third attempt is ready");
    assert_eq!(running.identity.port, 18_080);
    assert_eq!(driver.launch_calls.load(Ordering::SeqCst), 3);
    assert_eq!(clock.slept_ms.load(Ordering::SeqCst), 25);
    assert!(supervisor.crash_loop().is_none());
}

#[tokio::test]
async fn terminal_crash_loop_blocks_relaunch_until_explicit_reset() {
    let driver = Arc::new(ScriptedDriver {
        launch_calls: AtomicU32::new(0),
        failures_before_success: 1,
        retryable: false,
        shutdown_calls: AtomicU32::new(0),
        shutdown_fails: AtomicBool::new(false),
    });
    let mut supervisor = EngineSupervisor::new("fixture", driver.clone(), BackoffPolicy::default());

    let first = supervisor
        .ensure_ready(&provisioned(), &launch())
        .await
        .expect_err("nonretryable failure is terminal");
    assert_eq!(first.reason(), EngineFailureReason::EngineEarlyExit);
    let retained = supervisor.crash_loop().expect("crash loop retained");
    assert_eq!(retained.attempts, 1);
    assert_eq!(retained.stderr_tail.as_deref(), Some("Bearer [REDACTED]"));

    let blocked = supervisor
        .ensure_ready(&provisioned(), &launch())
        .await
        .expect_err("crash loop blocks relaunch");
    assert_eq!(blocked.reason(), EngineFailureReason::CrashLoop);
    assert_eq!(driver.launch_calls.load(Ordering::SeqCst), 1);

    assert!(supervisor.reset());
    supervisor
        .ensure_ready(&provisioned(), &launch())
        .await
        .expect("reset permits a new launch");
    assert_eq!(driver.launch_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn retry_budget_exhaustion_retains_failure_times_and_blocks_relaunch() {
    let driver = Arc::new(ScriptedDriver {
        launch_calls: AtomicU32::new(0),
        failures_before_success: u32::MAX,
        retryable: true,
        shutdown_calls: AtomicU32::new(0),
        shutdown_fails: AtomicBool::new(false),
    });
    let clock = Arc::new(ManualClock::default());
    let mut supervisor = EngineSupervisor::new(
        "fixture",
        driver.clone(),
        BackoffPolicy {
            base: Duration::from_millis(10),
            max: Duration::from_millis(15),
            max_attempts: Some(3),
        },
    )
    .with_clock(clock.clone());

    let error = supervisor
        .ensure_ready(&provisioned(), &launch())
        .await
        .expect_err("third retryable failure exhausts the budget");

    assert_eq!(error.reason(), EngineFailureReason::EngineEarlyExit);
    assert_eq!(driver.launch_calls.load(Ordering::SeqCst), 3);
    assert_eq!(clock.slept_ms.load(Ordering::SeqCst), 25);
    let retained = supervisor.crash_loop().expect("terminal state retained");
    assert_eq!(retained.attempts, 3);
    assert_eq!(retained.first_failure_at_ms, 0);
    assert_eq!(retained.last_failure_at_ms, 25);
    assert_eq!(retained.stderr_tail.as_deref(), Some("Bearer [REDACTED]"));

    let blocked = supervisor
        .ensure_ready(&provisioned(), &launch())
        .await
        .expect_err("retained crash loop blocks another launch");
    assert_eq!(blocked.reason(), EngineFailureReason::CrashLoop);
    assert_eq!(driver.launch_calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn failed_shutdown_retains_running_generation_for_retry() {
    let driver = Arc::new(ScriptedDriver {
        launch_calls: AtomicU32::new(0),
        failures_before_success: 0,
        retryable: true,
        shutdown_calls: AtomicU32::new(0),
        shutdown_fails: AtomicBool::new(true),
    });
    let mut supervisor = EngineSupervisor::new("fixture", driver.clone(), BackoffPolicy::default());
    supervisor
        .ensure_ready(&provisioned(), &launch())
        .await
        .expect("ready");

    let failure = supervisor
        .shutdown(Duration::from_millis(1))
        .await
        .expect_err("first shutdown fails");
    assert_eq!(failure.reason(), EngineFailureReason::EngineShutdownFailed);
    assert!(supervisor.running().is_some());

    driver.shutdown_fails.store(false, Ordering::SeqCst);
    assert!(supervisor.shutdown(Duration::from_millis(1)).await.is_ok());
    assert!(supervisor.running().is_none());
    assert_eq!(driver.shutdown_calls.load(Ordering::SeqCst), 2);
    assert!(supervisor.shutdown(Duration::from_millis(1)).await.is_ok());
    assert_eq!(driver.shutdown_calls.load(Ordering::SeqCst), 2);
}
