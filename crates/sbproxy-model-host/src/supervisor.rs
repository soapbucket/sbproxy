// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Engine lifecycle supervision (WOR-1653 core).
//!
//! This is the state machine half of the engine supervisor,
//! generalized from the classifier-sidecar precedent: an engine goes
//! Idle -> Loading -> Ready, can Fail (with bounded exponential-backoff
//! restart), and can be Evicted to free VRAM. Requests that arrive
//! while an engine is Loading queue rather than error.
//!
//! The actual process spawn, readiness HTTP probe, and kill live
//! behind the [`EngineLauncher`] trait, so this state machine is
//! driven and unit-tested with a fake launcher, no real vLLM /
//! llama.cpp and no GPU. The production launcher (spawn the engine
//! binary from the templated args, poll `/health`, kill the whole
//! process tree) implements the same trait in a later phase.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    EngineDriver, EngineDriverError, EngineFailureReason, FileJobStore, LaunchRequest,
    OperationJob, OperationKind, OperationProgress, OperationState, ProvisionRequest,
    ProvisionedEngine, RunningEngine,
};

/// The lifecycle state of one supervised engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum EngineState {
    /// Not started (or unloaded), holding no VRAM.
    Idle,
    /// Spawned, weights loading / warming up. Requests queue here.
    Loading,
    /// Serving on `port`, healthy.
    Ready {
        /// The port the engine bound and answers on.
        port: u16,
    },
    /// The last launch attempt failed; `attempts` restarts have been
    /// made, next retry after the backoff delay.
    Failed {
        /// How many launch attempts have failed in a row.
        attempts: u32,
        /// Human-readable last error.
        reason: String,
    },
    /// Deliberately evicted to free VRAM (distinct from Failed: no
    /// restart, this was policy).
    Evicted,
}

impl EngineState {
    /// True when the engine can serve requests right now.
    pub fn is_ready(&self) -> bool {
        matches!(self, EngineState::Ready { .. })
    }

    /// The serving port when Ready.
    pub fn port(&self) -> Option<u16> {
        match self {
            EngineState::Ready { port } => Some(*port),
            _ => None,
        }
    }
}

/// What to launch: the resolved binary, its templated argv, and the
/// working-directory-free environment the engine needs. Built by the
/// runtime from the engine kind + fit plan + resolved weights; this
/// crate treats it as opaque data the launcher consumes.
#[derive(Debug, Clone, PartialEq)]
pub struct LaunchSpec {
    /// The engine this spec launches. The launcher dispatches on it:
    /// an in-process engine ([`crate::config::EngineKind::Embedded`])
    /// starts a server inside the process instead of spawning
    /// `program` (WOR-1658).
    pub engine: crate::config::EngineKind,
    /// Executable resolved from PATH (or a pinned release). Unused for
    /// an in-process engine.
    pub program: String,
    /// Full argument vector (already templated; no shell parsing).
    pub args: Vec<String>,
    /// Environment overrides as (key, value) pairs.
    pub env: Vec<(String, String)>,
    /// Estimated VRAM the launched engine will hold, from the fit
    /// planner. Used by the residency budget, not the launcher.
    pub vram_bytes: u64,
}

/// The side-effecting operations the state machine drives. The
/// production impl spawns/probes/kills a real process; tests use a
/// fake. `async` so the real impl can await the readiness probe.
#[allow(async_fn_in_trait)]
pub trait EngineLauncher: Send + Sync {
    /// Spawn the engine and wait until its readiness probe passes,
    /// returning the bound port. An error means the launch failed
    /// (the state machine will back off and retry).
    async fn launch(&self, spec: &LaunchSpec) -> Result<u16, String>;
    /// Kill the engine process tree and free its VRAM. Best-effort;
    /// errors are logged, not surfaced (eviction must make progress).
    async fn kill(&self);
}

/// Bounded exponential-backoff policy for restarts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BackoffPolicy {
    /// Delay before the first retry.
    pub base: Duration,
    /// Ceiling on the delay.
    pub max: Duration,
    /// Give up after this many consecutive failures. `None` = retry
    /// forever (with the delay capped at `max`).
    pub max_attempts: Option<u32>,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
            max_attempts: Some(5),
        }
    }
}

impl BackoffPolicy {
    /// Delay before retry number `attempt` (1-based): `base * 2^(n-1)`
    /// capped at `max`. Deterministic (no jitter) so it is testable;
    /// the production launcher can add jitter at the sleep site.
    pub fn delay_for(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return self.base;
        }
        let shift = attempt.saturating_sub(1).min(20);
        let scaled = self.base.saturating_mul(1u32 << shift);
        scaled.min(self.max)
    }

    /// Whether another attempt is allowed after `attempts` failures.
    pub fn should_retry(&self, attempts: u32) -> bool {
        match self.max_attempts {
            Some(cap) => attempts < cap,
            None => true,
        }
    }
}

/// Clock and sleep boundary used by managed-engine retry supervision.
#[async_trait]
pub trait SupervisorClock: Send + Sync {
    /// Wait for one retry delay.
    async fn sleep(&self, duration: Duration);
    /// Current Unix timestamp in milliseconds.
    fn now_ms(&self) -> u64;
}

/// Production supervisor clock backed by Tokio and the system wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioSupervisorClock;

#[async_trait]
impl SupervisorClock for TokioSupervisorClock {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
            .unwrap_or(0)
    }
}

/// Errors the supervisor surfaces to a caller.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SupervisorError {
    /// The engine exhausted its restart budget.
    #[error("engine gave up after {attempts} failed launch attempts: {reason}")]
    LaunchGaveUp {
        /// Consecutive failures.
        attempts: u32,
        /// Last error.
        reason: String,
    },
}

/// A single supervised engine: its current state plus the backoff
/// policy. The state transitions are driven by [`Supervisor::ensure_ready`]
/// and [`Supervisor::evict`]; concurrency (one loader, queued waiters)
/// is layered on by the runtime with a lock + notify around this.
#[derive(Debug)]
pub struct Supervisor<L: EngineLauncher> {
    launcher: L,
    backoff: BackoffPolicy,
    state: EngineState,
    spec: LaunchSpec,
}

impl<L: EngineLauncher> Supervisor<L> {
    /// Create a supervisor for `spec`, initially Idle.
    pub fn new(launcher: L, spec: LaunchSpec, backoff: BackoffPolicy) -> Self {
        Self {
            launcher,
            backoff,
            state: EngineState::Idle,
            spec,
        }
    }

    /// Current state (a clone; state is small).
    pub fn state(&self) -> EngineState {
        self.state.clone()
    }

    /// Bring the engine to Ready, launching (and retrying with
    /// backoff) as needed. Returns the serving port. Already-Ready is
    /// a no-op fast path. Retries wait for the policy delay and stop at
    /// the configured attempt budget.
    pub async fn ensure_ready(&mut self) -> Result<u16, SupervisorError> {
        if let EngineState::Ready { port } = self.state {
            return Ok(port);
        }
        let mut attempts = match &self.state {
            EngineState::Failed { attempts, .. } => *attempts,
            _ => 0,
        };
        loop {
            self.state = EngineState::Loading;
            match self.launcher.launch(&self.spec).await {
                Ok(port) => {
                    self.state = EngineState::Ready { port };
                    return Ok(port);
                }
                Err(reason) => {
                    attempts += 1;
                    self.state = EngineState::Failed {
                        attempts,
                        reason: reason.clone(),
                    };
                    if !self.backoff.should_retry(attempts) {
                        return Err(SupervisorError::LaunchGaveUp { attempts, reason });
                    }
                    tokio::time::sleep(self.backoff.delay_for(attempts)).await;
                }
            }
        }
    }

    /// Evict the engine: kill it and mark Evicted (frees VRAM, no
    /// restart). Idempotent.
    pub async fn evict(&mut self) {
        if matches!(self.state, EngineState::Evicted | EngineState::Idle) {
            self.state = EngineState::Evicted;
            return;
        }
        self.launcher.kill().await;
        self.state = EngineState::Evicted;
    }

    /// VRAM this engine holds when loaded (from its launch spec).
    pub fn vram_bytes(&self) -> u64 {
        self.spec.vram_bytes
    }
}

/// Retained terminal launch failure. No automatic launch is attempted while present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CrashLoopState {
    /// Consecutive failed launch attempts.
    pub attempts: u32,
    /// Stable reason reported by the last attempt.
    pub reason: EngineFailureReason,
    /// Bounded operator-safe message from the last attempt.
    pub last_error: String,
    /// Bounded, credential-redacted engine diagnostic tail.
    pub stderr_tail: Option<String>,
    /// Timestamp of the first failure in this retry sequence.
    pub first_failure_at_ms: u64,
    /// Timestamp of the terminal failure in this retry sequence.
    pub last_failure_at_ms: u64,
    /// Operator action required before retrying.
    pub next_remediation: String,
    /// Durable terminal load job associated with this crash loop.
    pub last_job_id: Option<String>,
}

/// Typed managed-engine supervisor used by the process-wide runtime manager.
pub struct EngineSupervisor {
    deployment: String,
    driver: Arc<dyn EngineDriver>,
    backoff: BackoffPolicy,
    clock: Arc<dyn SupervisorClock>,
    job_store: Option<FileJobStore>,
    last_job_id: Mutex<Option<String>>,
    running: Option<RunningEngine>,
    crash_loop: Option<CrashLoopState>,
}

impl std::fmt::Debug for EngineSupervisor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EngineSupervisor")
            .field("deployment", &self.deployment)
            .field("driver_kind", &self.driver.kind())
            .field("backoff", &self.backoff)
            .field("running", &self.running)
            .field("crash_loop", &self.crash_loop)
            .finish_non_exhaustive()
    }
}

impl EngineSupervisor {
    /// Construct an idle supervisor for one canonical deployment.
    pub fn new(
        deployment: impl Into<String>,
        driver: Arc<dyn EngineDriver>,
        backoff: BackoffPolicy,
        job_store: Option<FileJobStore>,
    ) -> Self {
        Self {
            deployment: deployment.into(),
            driver,
            backoff,
            clock: Arc::new(TokioSupervisorClock),
            job_store,
            last_job_id: Mutex::new(None),
            running: None,
            crash_loop: None,
        }
    }

    /// Override the retry clock for deterministic tests.
    pub fn with_clock(mut self, clock: Arc<dyn SupervisorClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Currently running engine generation, when ready.
    pub fn running(&self) -> Option<&RunningEngine> {
        self.running.as_ref()
    }

    /// Retained terminal crash loop, when reset is required.
    pub fn crash_loop(&self) -> Option<&CrashLoopState> {
        self.crash_loop.as_ref()
    }

    /// Most recently created durable engine lifecycle job.
    pub fn last_job_id(&self) -> Option<String> {
        self.last_job_id
            .lock()
            .expect("engine supervisor job mutex poisoned")
            .clone()
    }

    /// Provision one exact managed engine and retain a durable lifecycle job.
    pub async fn provision(
        &self,
        request: &ProvisionRequest,
    ) -> Result<ProvisionedEngine, EngineDriverError> {
        self.validate_deployment()?;
        let job = self.begin_job(OperationKind::Provision)?;
        match self.driver.provision(request).await {
            Ok(provisioned) => {
                self.finish_job(job.as_ref(), None)?;
                Ok(provisioned)
            }
            Err(error) => {
                self.finish_job(job.as_ref(), Some(&error))?;
                Err(error)
            }
        }
    }

    /// Launch a provisioned engine with bounded delayed retries.
    ///
    /// A terminal failure is retained and every later call fails as
    /// `crash_loop` without invoking the driver until [`Self::reset`].
    pub async fn ensure_ready(
        &mut self,
        provisioned: &ProvisionedEngine,
        request: &LaunchRequest,
    ) -> Result<RunningEngine, EngineDriverError> {
        self.validate_deployment()?;
        if request.deployment != self.deployment {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                format!(
                    "launch deployment {:?} does not match supervisor {:?}",
                    request.deployment, self.deployment
                ),
                "reconcile the launch through the matching deployment slot",
                false,
            ));
        }
        if let Some(running) = &self.running {
            return Ok(running.clone());
        }
        if let Some(crash_loop) = &self.crash_loop {
            return Err(self.crash_loop_error(crash_loop));
        }

        let launch_job = self.begin_job(OperationKind::Launch)?;
        let load_job = match self.begin_job(OperationKind::Load) {
            Ok(job) => job,
            Err(error) => {
                let _ = self.finish_job(launch_job.as_ref(), Some(&error));
                return Err(error);
            }
        };
        let mut attempts = 0u32;
        let mut retained: Option<CrashLoopState> = None;
        loop {
            match self.driver.launch(provisioned, request).await {
                Ok(running) => {
                    let launch_result = self.finish_job(launch_job.as_ref(), None);
                    let load_result = self.finish_job(load_job.as_ref(), None);
                    if let Err(error) = launch_result.and(load_result) {
                        let _ = self
                            .driver
                            .shutdown(running.clone(), Duration::from_secs(1))
                            .await;
                        return Err(error);
                    }
                    self.crash_loop = None;
                    self.running = Some(running.clone());
                    return Ok(running);
                }
                Err(error) => {
                    attempts = attempts.saturating_add(1);
                    let now_ms = self.clock.now_ms();
                    let first_failure_at_ms = retained
                        .as_ref()
                        .map_or(now_ms, |state| state.first_failure_at_ms);
                    retained = Some(CrashLoopState {
                        attempts,
                        reason: error.reason(),
                        last_error: error.message().to_string(),
                        stderr_tail: error.diagnostic_tail().map(str::to_string),
                        first_failure_at_ms,
                        last_failure_at_ms: now_ms.max(first_failure_at_ms),
                        next_remediation: error.remediation().to_string(),
                        last_job_id: load_job.as_ref().map(|job| job.id.clone()),
                    });
                    if error.retryable() && self.backoff.should_retry(attempts) {
                        self.clock.sleep(self.backoff.delay_for(attempts)).await;
                        continue;
                    }
                    self.crash_loop = retained;
                    let launch_result = self.finish_job(launch_job.as_ref(), Some(&error));
                    let load_result = self.finish_job(load_job.as_ref(), Some(&error));
                    launch_result.and(load_result)?;
                    return Err(error);
                }
            }
        }
    }

    /// Clear a retained crash loop and persist the explicit reset event.
    pub fn reset(&mut self) -> Result<Option<OperationJob>, EngineDriverError> {
        self.validate_deployment()?;
        let job = self.begin_job(OperationKind::Reset)?;
        let previous = self.crash_loop.take();
        match self.finish_job(job.as_ref(), None) {
            Ok(terminal) => Ok(terminal),
            Err(error) => {
                self.crash_loop = previous;
                Err(error)
            }
        }
    }

    /// Stop the running generation and persist a terminal stop job.
    pub async fn shutdown(
        &mut self,
        grace: Duration,
    ) -> Result<Option<OperationJob>, EngineDriverError> {
        self.validate_deployment()?;
        let job = self.begin_job(OperationKind::Stop)?;
        if let Some(running) = self.running.clone() {
            if let Err(error) = self.driver.shutdown(running, grace).await {
                self.finish_job(job.as_ref(), Some(&error))?;
                return Err(error);
            }
            self.running = None;
        }
        self.finish_job(job.as_ref(), None)
    }

    /// Begin a durable drain operation for the admission layer.
    pub fn begin_drain_job(&self) -> Result<Option<OperationJob>, EngineDriverError> {
        self.validate_deployment()?;
        self.begin_job(OperationKind::Drain)
    }

    /// Finish a durable drain operation after active requests leave.
    pub fn finish_drain_job(
        &self,
        job: Option<&OperationJob>,
        failure: Option<&EngineDriverError>,
    ) -> Result<Option<OperationJob>, EngineDriverError> {
        if job.is_some_and(|job| job.kind != OperationKind::Drain) {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "finish_drain_job received a non-drain operation",
                "retain and finish the drain job returned by begin_drain_job",
                false,
            ));
        }
        self.finish_job(job, failure)
    }

    fn validate_deployment(&self) -> Result<(), EngineDriverError> {
        if self.deployment.trim().is_empty()
            || self.deployment.len() > 128
            || self.deployment.chars().any(char::is_control)
        {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "engine supervisor deployment ID is invalid",
                "reconcile a canonical deployment ID before provisioning",
                false,
            ));
        }
        Ok(())
    }

    fn crash_loop_error(&self, state: &CrashLoopState) -> EngineDriverError {
        EngineDriverError::new(
            EngineFailureReason::CrashLoop,
            format!(
                "deployment {:?} exhausted {} launch attempts",
                self.deployment, state.attempts
            ),
            &state.next_remediation,
            false,
        )
    }

    fn begin_job(&self, kind: OperationKind) -> Result<Option<OperationJob>, EngineDriverError> {
        let job = self
            .job_store
            .as_ref()
            .map(|store| {
                store
                    .create(kind, format!("deployment:{}", self.deployment))
                    .map_err(|error| lifecycle_job_error("create", error))
            })
            .transpose()?;
        if let Some(job) = &job {
            *self
                .last_job_id
                .lock()
                .expect("engine supervisor job mutex poisoned") = Some(job.id.clone());
        }
        Ok(job)
    }

    fn finish_job(
        &self,
        job: Option<&OperationJob>,
        failure: Option<&EngineDriverError>,
    ) -> Result<Option<OperationJob>, EngineDriverError> {
        let (Some(store), Some(job)) = (&self.job_store, job) else {
            return Ok(None);
        };
        let state = if failure.is_some() {
            OperationState::Failed
        } else {
            OperationState::Ready
        };
        let detail = failure
            .map(|error| format!("{}; remediation: {}", error.reason(), error.remediation()));
        store
            .transition(
                &job.id,
                state,
                OperationProgress::default(),
                detail.as_deref(),
            )
            .map(Some)
            .map_err(|error| lifecycle_job_error("finish", error))
    }
}

fn lifecycle_job_error(operation: &str, error: crate::JobError) -> EngineDriverError {
    EngineDriverError::new(
        EngineFailureReason::EngineInternal,
        format!("{operation} durable engine lifecycle job: {error}"),
        "repair the model-host job store before retrying the lifecycle operation",
        false,
    )
}

/// Choose which resident engine to evict under LRU: the entry with
/// the oldest `last_used` tick among `candidates` (index, last_used).
/// Returns the index to evict, or `None` when there is nothing to
/// evict. A pure helper so the residency policy is unit-testable.
pub fn lru_victim(candidates: &[(usize, u64)]) -> Option<usize> {
    candidates
        .iter()
        .min_by_key(|(_, last_used)| *last_used)
        .map(|(idx, _)| *idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A fake launcher: fails its first `fail_first` launches, then
    /// succeeds on `port`. Records launch + kill counts.
    struct FakeLauncher {
        fail_first: u32,
        port: u16,
        launches: Arc<AtomicU32>,
        kills: Arc<AtomicU32>,
    }

    impl FakeLauncher {
        fn new(fail_first: u32, port: u16) -> Self {
            Self {
                fail_first,
                port,
                launches: Arc::new(AtomicU32::new(0)),
                kills: Arc::new(AtomicU32::new(0)),
            }
        }
    }

    impl EngineLauncher for FakeLauncher {
        async fn launch(&self, _spec: &LaunchSpec) -> Result<u16, String> {
            let n = self.launches.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_first {
                Err(format!("synthetic launch failure #{}", n + 1))
            } else {
                Ok(self.port)
            }
        }
        async fn kill(&self) {
            self.kills.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn spec() -> LaunchSpec {
        LaunchSpec {
            engine: crate::config::EngineKind::Vllm,
            program: "vllm".into(),
            args: vec!["serve".into(), "Qwen/Qwen3-14B".into()],
            env: vec![],
            vram_bytes: 12 * super::super::fit::GIB,
        }
    }

    #[tokio::test]
    async fn happy_path_reaches_ready() {
        let mut sup = Supervisor::new(FakeLauncher::new(0, 8001), spec(), BackoffPolicy::default());
        assert_eq!(sup.state(), EngineState::Idle);
        let port = sup.ensure_ready().await.expect("ready");
        assert_eq!(port, 8001);
        assert!(sup.state().is_ready());
        assert_eq!(sup.state().port(), Some(8001));
    }

    #[tokio::test]
    async fn already_ready_is_a_noop() {
        let launcher = FakeLauncher::new(0, 8002);
        let launches = launcher.launches.clone();
        let mut sup = Supervisor::new(launcher, spec(), BackoffPolicy::default());
        sup.ensure_ready().await.unwrap();
        sup.ensure_ready().await.unwrap();
        assert_eq!(
            launches.load(Ordering::SeqCst),
            1,
            "second call must not relaunch"
        );
    }

    #[tokio::test]
    async fn retries_then_succeeds() {
        // Fail twice, succeed on the third; within the default budget of 5.
        let backoff = BackoffPolicy {
            base: Duration::from_millis(1),
            max: Duration::from_millis(2),
            max_attempts: Some(5),
        };
        let mut sup = Supervisor::new(FakeLauncher::new(2, 8003), spec(), backoff);
        let port = sup.ensure_ready().await.expect("eventually ready");
        assert_eq!(port, 8003);
        assert!(sup.state().is_ready());
    }

    #[tokio::test(start_paused = true)]
    async fn retries_wait_for_base_exponential_and_capped_delays() {
        let backoff = BackoffPolicy {
            base: Duration::from_millis(10),
            max: Duration::from_millis(25),
            max_attempts: Some(4),
        };
        let mut sup = Supervisor::new(FakeLauncher::new(3, 8007), spec(), backoff);
        let started = tokio::time::Instant::now();

        assert_eq!(sup.ensure_ready().await.unwrap(), 8007);

        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            Duration::from_millis(55)
        );
    }

    #[tokio::test]
    async fn gives_up_after_max_attempts() {
        let backoff = BackoffPolicy {
            base: Duration::from_millis(1),
            max: Duration::from_millis(2),
            max_attempts: Some(3),
        };
        // Always fails.
        let mut sup = Supervisor::new(FakeLauncher::new(u32::MAX, 8004), spec(), backoff);
        let err = sup.ensure_ready().await.unwrap_err();
        match err {
            SupervisorError::LaunchGaveUp { attempts, .. } => assert_eq!(attempts, 3),
        }
        assert!(matches!(
            sup.state(),
            EngineState::Failed { attempts: 3, .. }
        ));
    }

    #[tokio::test]
    async fn evict_kills_and_marks_evicted() {
        let launcher = FakeLauncher::new(0, 8005);
        let kills = launcher.kills.clone();
        let mut sup = Supervisor::new(launcher, spec(), BackoffPolicy::default());
        sup.ensure_ready().await.unwrap();
        sup.evict().await;
        assert_eq!(sup.state(), EngineState::Evicted);
        assert_eq!(kills.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn evict_idle_does_not_kill() {
        let launcher = FakeLauncher::new(0, 8006);
        let kills = launcher.kills.clone();
        let mut sup = Supervisor::new(launcher, spec(), BackoffPolicy::default());
        sup.evict().await; // never launched
        assert_eq!(sup.state(), EngineState::Evicted);
        assert_eq!(kills.load(Ordering::SeqCst), 0, "nothing to kill when Idle");
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let b = BackoffPolicy {
            base: Duration::from_secs(1),
            max: Duration::from_secs(10),
            max_attempts: None,
        };
        assert_eq!(b.delay_for(1), Duration::from_secs(1));
        assert_eq!(b.delay_for(2), Duration::from_secs(2));
        assert_eq!(b.delay_for(3), Duration::from_secs(4));
        assert_eq!(b.delay_for(4), Duration::from_secs(8));
        assert_eq!(b.delay_for(5), Duration::from_secs(10)); // capped
        assert_eq!(b.delay_for(50), Duration::from_secs(10)); // still capped, no overflow
    }

    #[test]
    fn lru_victim_picks_oldest() {
        // (index, last_used_tick)
        let resident = [(0usize, 100u64), (1, 20), (2, 75)];
        assert_eq!(lru_victim(&resident), Some(1));
        assert_eq!(lru_victim(&[]), None);
    }
}
