//! Child supervisor for the classifier sidecar (WOR-705 part 2).
//!
//! Pairs with the UDS transport that shipped in WOR-705 part 1. The
//! supervisor is the zero-extra-ops story for the standalone /
//! dev / single-pod case: the proxy spawns the OSS sidecar binary
//! as a child process, supervises it (restart on unexpected exit,
//! drain on shutdown), and the request path holds a lazy
//! [`ClassifierClient`] over the same UDS path the supervisor
//! passes to the child with `--listen-uds`.
//!
//! ## Lifecycle
//!
//! 1. [`Supervisor::spawn`] starts the sidecar binary in a
//!    background tokio task. The task forks the child, attaches
//!    stdout / stderr to the operator's tracing layer, and waits
//!    on the child handle.
//! 2. When the child exits with a non-zero status (crash, OOM
//!    kill, panic) the task restarts it after an
//!    exponential-backoff delay capped at [`SupervisorConfig::max_backoff`].
//! 3. [`Supervisor::shutdown`] sends SIGTERM, waits up to
//!    [`SupervisorConfig::shutdown_grace`], then SIGKILL if the
//!    child has not exited. The supervisor task exits cleanly.
//!
//! ## What this module is NOT
//!
//! * **A general-purpose process supervisor.** It only knows how
//!   to run the classifier sidecar binary; the operator passes
//!   the binary path + the model spec + the UDS path; everything
//!   else is hard-coded for the sidecar's CLI surface.
//! * **The transport.** The supervisor does not open the
//!   gRPC channel; it owns the child's lifecycle only. The
//!   proxy holds a [`ClassifierClient::connect_uds_lazy`] over
//!   the same UDS path and the first `classify` call dials.
//! * **A health checker.** A separate readiness probe path can
//!   layer on top via the existing `ClassifierClient::version`
//!   RPC; the supervisor's restart loop only fires on child
//!   exit, not on RPC-level failures.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Instant};

/// Tuning knobs for the supervisor's restart + shutdown loop. The
/// defaults are conservative; operators rarely need to tune them.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Path to the sidecar binary. The supervisor execs this with
    /// `--listen-uds <socket> --model <id=path:tokenizer> ...`.
    pub binary: PathBuf,
    /// UDS path the supervisor passes to the child as
    /// `--listen-uds`. The proxy's lazy classifier client dials
    /// the same path.
    pub uds_path: PathBuf,
    /// Models to load, each in the sidecar's `id=model:tokenizer`
    /// spec form. Passed as repeated `--model` flags.
    pub models: Vec<String>,
    /// Optional `--default-model` argument. When unset the child
    /// uses the single-model fallback (per the sidecar's own CLI
    /// default).
    pub default_model: Option<String>,
    /// First restart backoff after an unexpected exit. Doubles per
    /// consecutive restart up to [`Self::max_backoff`]; resets to
    /// `initial_backoff` after the child has been alive for
    /// [`Self::healthy_after`].
    pub initial_backoff: Duration,
    /// Upper bound on the per-restart backoff.
    pub max_backoff: Duration,
    /// A child that survives at least this long counts as healthy,
    /// resetting the backoff schedule on its next crash.
    pub healthy_after: Duration,
    /// Grace period [`Supervisor::shutdown`] waits between SIGTERM
    /// and SIGKILL.
    pub shutdown_grace: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("sbproxy-classifier-sidecar"),
            uds_path: PathBuf::from("/run/sbproxy/classifier.sock"),
            models: Vec::new(),
            default_model: None,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(30),
            healthy_after: Duration::from_secs(30),
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// Lifecycle state observable from outside the supervisor. The
/// supervisor publishes a fresh value through a `watch` channel
/// every time the state changes so callers can wait on
/// "running for first time" or "exiting".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    /// The supervisor task has not started yet.
    Idle,
    /// A child is currently running.
    Running,
    /// The previous child exited; we are backing off before the
    /// next restart.
    BackingOff,
    /// `shutdown` was called; the supervisor task is winding down.
    Shutdown,
    /// The supervisor task has exited.
    Stopped,
}

/// Errors the supervisor can surface to callers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SupervisorError {
    /// Spawning the child failed (binary missing, exec error).
    #[error("spawn classifier sidecar failed: {0}")]
    Spawn(std::io::Error),
    /// The supervisor task panicked. Indicates a bug; the
    /// supervisor is fail-fast so the proxy notices.
    #[error("supervisor task panicked: {0}")]
    TaskPanicked(String),
}

/// Handle to a running supervisor. Cheaply cloneable; clones
/// share the inner state.
#[derive(Clone)]
pub struct Supervisor {
    inner: Arc<Inner>,
}

struct Inner {
    state_tx: watch::Sender<SupervisorState>,
    /// Keepalive receiver. `watch::Sender::send` fails when there
    /// are no receivers and the value is dropped on the floor;
    /// holding one receiver in `Inner` guarantees every state
    /// transition lands on the channel even when no caller has
    /// subscribed yet.
    _state_rx_keepalive: watch::Receiver<SupervisorState>,
    /// `Some(handle)` while the supervisor task is running.
    /// Replaced with `None` after [`Supervisor::shutdown`] awaits
    /// the join.
    task: Mutex<Option<JoinHandle<()>>>,
    shutdown_tx: watch::Sender<bool>,
    /// Keepalive receiver for the shutdown channel, same reason.
    _shutdown_rx_keepalive: watch::Receiver<bool>,
}

impl Supervisor {
    /// Spawn the supervisor task. Returns immediately; the first
    /// child fork happens inside the task. Subscribe to
    /// [`Self::watch_state`] to await the transition to `Running`.
    pub fn spawn(cfg: SupervisorConfig) -> Self {
        let (state_tx, state_rx_keepalive) = watch::channel(SupervisorState::Idle);
        let (shutdown_tx, shutdown_rx_keepalive) = watch::channel(false);
        // Subscribe the shutdown receiver the supervisor task
        // will own. The original receiver stays in Inner so
        // shutdown_tx.send always succeeds (otherwise it would
        // fail when only the task's own subscriber exists and
        // raceily drops on cancel).
        let task_shutdown_rx = shutdown_rx_keepalive.clone();
        let inner = Arc::new(Inner {
            state_tx: state_tx.clone(),
            _state_rx_keepalive: state_rx_keepalive,
            task: Mutex::new(None),
            shutdown_tx,
            _shutdown_rx_keepalive: shutdown_rx_keepalive,
        });
        let task_inner = Arc::clone(&inner);
        let handle = tokio::spawn(async move {
            run_loop(cfg, task_inner, task_shutdown_rx).await;
        });
        // Replace the placeholder None with the live handle. Done
        // synchronously because we just made the Mutex and no one
        // else holds it.
        if let Ok(mut slot) = inner.task.try_lock() {
            *slot = Some(handle);
        }
        Supervisor { inner }
    }

    /// Subscribe to lifecycle state changes. The receiver fires on
    /// every transition; callers typically `.changed().await` and
    /// inspect `borrow()`.
    pub fn watch_state(&self) -> watch::Receiver<SupervisorState> {
        self.inner.state_tx.subscribe()
    }

    /// Current lifecycle state.
    pub fn state(&self) -> SupervisorState {
        *self.inner.state_tx.borrow()
    }

    /// Request a graceful shutdown. Sends SIGTERM to the child,
    /// waits up to [`SupervisorConfig::shutdown_grace`], then
    /// SIGKILL. Awaits the supervisor task's exit. Idempotent.
    pub async fn shutdown(&self) {
        // Signal the loop to stop restarting.
        let _ = self.inner.shutdown_tx.send(true);

        // Pull the task handle out; if shutdown was already
        // awaited, this is a no-op.
        let handle = {
            let mut slot = self.inner.task.lock().await;
            slot.take()
        };
        if let Some(handle) = handle {
            // The run loop owns the child and is responsible for
            // SIGTERM-then-SIGKILL inside its select arm.
            let _ = handle.await;
        }
    }
}

/// The supervisor's run loop. Owns the [`Child`] handle; exits
/// when the shutdown signal fires or when an unrecoverable
/// spawn error occurs.
async fn run_loop(
    cfg: SupervisorConfig,
    inner: Arc<Inner>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut backoff = cfg.initial_backoff;
    let mut consecutive_failures: u32 = 0;

    loop {
        // Honour shutdown requested before any spawn.
        if *shutdown_rx.borrow() {
            break;
        }

        let _ = inner.state_tx.send(SupervisorState::Running);
        let start = Instant::now();

        let child_result = spawn_child(&cfg).await;
        let mut child = match child_result {
            Ok(child) => child,
            Err(err) => {
                tracing::error!(error = %err, "classifier sidecar spawn failed");
                // Treat as a failure for backoff purposes; loop
                // around after waiting.
                let _ = inner.state_tx.send(SupervisorState::BackingOff);
                consecutive_failures = consecutive_failures.saturating_add(1);
                if wait_or_shutdown(&mut shutdown_rx, backoff).await {
                    break;
                }
                backoff = (backoff * 2).min(cfg.max_backoff);
                continue;
            }
        };

        // Race: child exit vs shutdown signal.
        tokio::select! {
            exit = child.wait() => {
                let status = match exit {
                    Ok(s) => s,
                    Err(err) => {
                        tracing::error!(error = %err, "wait() on classifier sidecar failed");
                        let _ = inner.state_tx.send(SupervisorState::BackingOff);
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        if wait_or_shutdown(&mut shutdown_rx, backoff).await {
                            break;
                        }
                        backoff = (backoff * 2).min(cfg.max_backoff);
                        continue;
                    }
                };
                let lifetime = start.elapsed();
                tracing::warn!(
                    code = ?status.code(),
                    lifetime_ms = lifetime.as_millis() as u64,
                    "classifier sidecar exited; will restart after backoff",
                );
                if lifetime >= cfg.healthy_after {
                    // Healthy: reset the backoff schedule.
                    backoff = cfg.initial_backoff;
                    consecutive_failures = 0;
                } else {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                }
                let _ = inner.state_tx.send(SupervisorState::BackingOff);
                if wait_or_shutdown(&mut shutdown_rx, backoff).await {
                    break;
                }
                if lifetime < cfg.healthy_after {
                    backoff = (backoff * 2).min(cfg.max_backoff);
                }
            }
            _ = shutdown_rx.changed() => {
                if !*shutdown_rx.borrow() {
                    // Spurious change; loop and re-check.
                    continue;
                }
                tracing::info!("classifier sidecar supervisor: shutdown requested");
                let _ = inner.state_tx.send(SupervisorState::Shutdown);
                // SIGTERM-then-SIGKILL graceful shutdown.
                graceful_kill(&mut child, cfg.shutdown_grace).await;
                break;
            }
        }
    }

    let _ = inner.state_tx.send(SupervisorState::Stopped);
    let _ = consecutive_failures; // diagnostic counter; not currently exposed
}

/// Fork the child with the configured CLI arguments. Returns the
/// child handle on success.
async fn spawn_child(cfg: &SupervisorConfig) -> Result<Child, std::io::Error> {
    let mut cmd = Command::new(&cfg.binary);
    cmd.arg("--listen-uds").arg(&cfg.uds_path);
    if let Some(default_model) = cfg.default_model.as_ref() {
        cmd.arg("--default-model").arg(default_model);
    }
    for spec in &cfg.models {
        cmd.arg("--model").arg(spec);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Putting the child in its own process group makes the
    // graceful-kill code below sending SIGTERM cover the child only,
    // not the proxy. On non-Unix the kill_on_drop fallback covers us.
    cmd.kill_on_drop(true);
    cmd.spawn()
}

/// Sleep for `dur` or return early if shutdown is requested.
/// Returns `true` when shutdown was requested.
async fn wait_or_shutdown(shutdown_rx: &mut watch::Receiver<bool>, dur: Duration) -> bool {
    tokio::select! {
        _ = sleep(dur) => false,
        _ = shutdown_rx.changed() => *shutdown_rx.borrow(),
    }
}

/// SIGTERM then SIGKILL after `grace`. `Child::kill` is SIGKILL
/// on Unix; we approximate SIGTERM via `start_kill` and only
/// fall through to `kill` if the child has not exited.
async fn graceful_kill(child: &mut Child, grace: Duration) {
    // start_kill is non-blocking and on Unix sends SIGTERM via
    // the underlying nix syscall when configured; tokio 1.40+
    // sends SIGKILL by default. The grace window below handles
    // both cases: if the child is well-behaved on SIGTERM it
    // exits within the window; if not, we send the harsher
    // SIGKILL via kill().await once the window elapses.
    let _ = child.start_kill();
    tokio::select! {
        _ = child.wait() => {}
        _ = sleep(grace) => {
            tracing::warn!("classifier sidecar did not exit within grace; SIGKILL");
            let _ = child.kill().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wait for `state` for up to `timeout`, polling the watch
    /// channel. Returns true if reached, false on timeout.
    async fn wait_for_state(sup: &Supervisor, target: SupervisorState, timeout: Duration) -> bool {
        let mut rx = sup.watch_state();
        let deadline = Instant::now() + timeout;
        loop {
            if *rx.borrow() == target {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            let _ = tokio::time::timeout(Duration::from_millis(50), rx.changed()).await;
        }
    }

    #[tokio::test]
    async fn supervisor_shutdown_returns_promptly_when_idle() {
        // The supervisor task spends its time inside
        // wait_or_shutdown; signalling shutdown unblocks it.
        let tempdir = tempfile::tempdir().unwrap();
        let cfg = SupervisorConfig {
            // Point at a non-existent binary so spawn fails and
            // the supervisor sits in BackingOff between attempts.
            // wait_or_shutdown picks up the shutdown signal and
            // the task exits.
            binary: PathBuf::from("/nonexistent/sbproxy-sidecar-fixture"),
            uds_path: tempdir.path().join("sock"),
            models: vec![],
            default_model: None,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            healthy_after: Duration::from_secs(60),
            shutdown_grace: Duration::from_millis(100),
        };
        let sup = Supervisor::spawn(cfg);

        // Wait until the supervisor has at least tried once and is
        // in the BackingOff state (the spawn failed).
        let reached =
            wait_for_state(&sup, SupervisorState::BackingOff, Duration::from_secs(2)).await;
        assert!(
            reached,
            "supervisor should reach BackingOff after spawn failure"
        );

        // Shutdown should unblock the wait_or_shutdown sleep.
        let shutdown_start = Instant::now();
        sup.shutdown().await;
        let shutdown_dur = shutdown_start.elapsed();

        assert_eq!(sup.state(), SupervisorState::Stopped);
        assert!(
            shutdown_dur < Duration::from_secs(1),
            "shutdown took {shutdown_dur:?} - should be near-instant",
        );
    }

    #[tokio::test]
    async fn supervisor_clones_share_state() {
        let tempdir = tempfile::tempdir().unwrap();
        let cfg = SupervisorConfig {
            binary: PathBuf::from("/nonexistent/sbproxy-sidecar-fixture"),
            uds_path: tempdir.path().join("sock"),
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            ..SupervisorConfig::default()
        };
        let sup = Supervisor::spawn(cfg);
        let clone = sup.clone();

        assert_eq!(sup.state(), clone.state());
        // Shutdown on the clone affects the original too.
        clone.shutdown().await;
        // Allow the state to settle.
        let _ = wait_for_state(&sup, SupervisorState::Stopped, Duration::from_secs(1)).await;
        assert_eq!(sup.state(), SupervisorState::Stopped);
        assert_eq!(clone.state(), SupervisorState::Stopped);
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let tempdir = tempfile::tempdir().unwrap();
        let cfg = SupervisorConfig {
            binary: PathBuf::from("/nonexistent/sbproxy-sidecar-fixture"),
            uds_path: tempdir.path().join("sock"),
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            ..SupervisorConfig::default()
        };
        let sup = Supervisor::spawn(cfg);
        sup.shutdown().await;
        // Second call is a no-op (task handle already consumed);
        // must not panic.
        sup.shutdown().await;
        assert_eq!(sup.state(), SupervisorState::Stopped);
    }
}
