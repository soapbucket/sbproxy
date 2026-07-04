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

use std::time::Duration;

use serde::{Deserialize, Serialize};

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
    /// Executable resolved from PATH (or a pinned release).
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
    /// a no-op fast path. This does NOT sleep between retries itself,
    /// so it stays synchronous-friendly for tests; the retry cadence
    /// is [`BackoffPolicy::delay_for`], which the runtime honors at
    /// the call site. Gives up per the backoff's `max_attempts`.
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
                    // Retry immediately in the loop; the runtime sleeps
                    // delay_for(attempts) before calling back in prod.
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
        let mut sup = Supervisor::new(FakeLauncher::new(2, 8003), spec(), BackoffPolicy::default());
        let port = sup.ensure_ready().await.expect("eventually ready");
        assert_eq!(port, 8003);
        assert!(sup.state().is_ready());
    }

    #[tokio::test]
    async fn gives_up_after_max_attempts() {
        let backoff = BackoffPolicy {
            max_attempts: Some(3),
            ..BackoffPolicy::default()
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
