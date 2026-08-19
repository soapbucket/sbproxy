//! Supervised persistent stdio sessions for local MCP servers (WOR-2453).
//!
//! One configured `transport: stdio` server gets ONE long-lived child
//! process for the lifetime of the compiled origin chain, not one
//! process per JSON-RPC exchange. Requests are written as
//! newline-delimited JSON to the child's stdin and responses are
//! correlated back to their callers by a session-scoped wire id, so
//! concurrent exchanges share the pipe safely. Server-side session
//! state survives between calls, and the per-call process startup cost
//! is paid once per child rather than once per exchange.
//!
//! # Lifecycle
//!
//! The supervision shape mirrors the engine supervisor in
//! `sbproxy-model-host` (`supervisor.rs`, WOR-1653): spawn on demand,
//! health-probe, bounded exponential-backoff restart on failure, kill
//! on removal. The differences are forced by the transport: the pipe
//! replaces the port, an MCP `ping` replaces the HTTP `/health` poll,
//! and the probe runs periodically while the session is idle rather
//! than at launch, because a legacy one-shot server (one that answers
//! a single line and exits, which is all the previous spawn-per-exchange
//! transport ever required) would consume its only exchange on a
//! launch-time probe.
//!
//! * A child is spawned lazily on the first exchange that needs it.
//! * A child that dies after proving itself (at least one correlated
//!   response) is respawned immediately on the next call, which keeps
//!   legacy one-shot servers working with no added latency.
//! * A child that dies without ever answering is a crash loop:
//!   respawns are rate-limited by exponential backoff (base times
//!   2^(n-1), capped), the same policy the engine supervisor's
//!   `BackoffPolicy` uses with `max_attempts: None`. Calls arriving
//!   inside the backoff window fail closed with a typed error rather
//!   than piling up behind a spawn storm.
//! * Dropping the pool (config removal or hot reload rebuilding the
//!   action) kills every supervised child.
//!
//! # What a crash means
//!
//! A crashed, hung, or protocol-violating child loses everything: the
//! session is closed, the child is killed, and every in-flight call on
//! it fails closed with a typed [`StdioSessionError`] rather than
//! hanging. Server-side state the child held (in-memory caches, open
//! handles) is gone; the supervisor replays the MCP `initialize`
//! handshake on the replacement child so protocol state is restored,
//! but tool-side state is not.
//!
//! # Handshake
//!
//! MCP requires `initialize` once per connection followed by a
//! `notifications/initialized` notification before normal traffic
//! (MCP 2025-06-18, basic/lifecycle). With a persistent child that
//! means: the first `initialize` the federation sends is forwarded and
//! its result cached, the required `notifications/initialized` is
//! written on its heels, and later `initialize` requests on the same
//! child (the federation re-handshakes on every catalog refresh
//! cycle) are answered from the cache, because a running child's
//! capabilities cannot change. On respawn the cached `initialize` is
//! replayed to the new child before the triggering call is written.
//!
//! # Trace context
//!
//! There is no header surface here at all. A local child process gets
//! one thing from the gateway, a line of JSON on stdin, which is why
//! `dispatch_request` refuses to route run-as-user credentials over
//! this transport. SEP-414 trace context reaches the child anyway,
//! because it travels inside that line: the federation merges it into
//! `params._meta` when it builds the request, before any transport
//! sees it. Nothing needs doing at this layer, and nothing should be
//! added; a second carrier here would exist on one transport and not
//! the others.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::oneshot;
use tracing::{debug, warn};

use super::types::{JsonRpcRequest, JsonRpcResponse};

/// Local stdio process command.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StdioCommand {
    /// Executable path or name resolved by the OS.
    pub command: String,
    /// Command arguments.
    #[serde(default)]
    pub args: Vec<String>,
}

/// Encode a stdio command into the existing server-url slot.
pub fn encode_stdio_url(command: &str, args: &[String]) -> String {
    let payload = StdioCommand {
        command: command.to_string(),
        args: args.to_vec(),
    };
    format!(
        "stdio:{}",
        serde_json::to_string(&payload).expect("stdio command serializes")
    )
}

fn decode_stdio_url(raw: &str) -> anyhow::Result<StdioCommand> {
    let payload = raw
        .strip_prefix("stdio:")
        .ok_or_else(|| anyhow::anyhow!("stdio transport url must start with stdio:"))?;
    serde_json::from_str(payload).map_err(|e| anyhow::anyhow!("invalid stdio transport url: {e}"))
}

/// Typed, fail-closed failure surface for supervised stdio exchanges.
///
/// Every variant means the call did NOT reach a healthy child and the
/// caller must treat the tool call as failed; none of them hang.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StdioSessionError {
    /// The child process could not be spawned (bad command, missing
    /// binary, resource exhaustion).
    #[error("stdio MCP server '{server}' could not be spawned: {reason}")]
    Spawn {
        /// Configured server name.
        server: String,
        /// Human-readable spawn failure.
        reason: String,
    },
    /// The server is inside its restart-backoff window after
    /// consecutive failures; the call is refused fail-closed rather
    /// than triggering another spawn.
    #[error(
        "stdio MCP server '{server}' is in restart backoff for another {retry_in_ms}ms \
         after {failures} consecutive failures"
    )]
    Backoff {
        /// Configured server name.
        server: String,
        /// Consecutive unproven failures so far.
        failures: u32,
        /// Milliseconds until the next spawn attempt is allowed.
        retry_in_ms: u64,
    },
    /// The exchange deadline elapsed. The child is treated as hung:
    /// it is killed and the session closed, so the failure cannot
    /// silently absorb every later call too.
    #[error(
        "stdio MCP exchange with '{server}' timed out after {timeout_ms}ms; \
         the child was killed and the session closed"
    )]
    Timeout {
        /// Configured server name.
        server: String,
        /// The elapsed deadline in milliseconds.
        timeout_ms: u64,
    },
    /// The session closed with the call in flight: the child exited,
    /// broke line framing, exceeded the byte cap, or was removed from
    /// configuration.
    #[error("stdio MCP session with '{server}' closed with the call in flight: {reason}")]
    SessionClosed {
        /// Configured server name.
        server: String,
        /// Why the session closed.
        reason: String,
    },
}

impl StdioSessionError {
    /// Label for `sbproxy_mcp_upstream_io_failures_total{kind=...}`.
    /// `Timeout` reuses the existing `timeout` kind the HTTP
    /// transports already record.
    pub(crate) fn metric_kind(&self) -> &'static str {
        match self {
            StdioSessionError::Spawn { .. } => "stdio_spawn",
            StdioSessionError::Backoff { .. } => "stdio_backoff",
            StdioSessionError::Timeout { .. } => "timeout",
            StdioSessionError::SessionClosed { .. } => "stdio_session_closed",
        }
    }
}

/// Bounded exponential restart backoff: delay before spawn attempt
/// `n` (1-based) is `base * 2^(n-1)` capped at `max`. Mirrors the
/// engine supervisor's `BackoffPolicy` (`sbproxy-model-host`,
/// `supervisor.rs`) in its `max_attempts: None` mode: the proxy never
/// permanently gives up on a configured server (that would demand a
/// config reload to recover), it bounds the spawn RATE instead, and
/// calls inside the window fail closed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StdioRestartPolicy {
    /// Delay before the first retry.
    pub(crate) base: Duration,
    /// Ceiling on the delay.
    pub(crate) max: Duration,
}

impl Default for StdioRestartPolicy {
    fn default() -> Self {
        // Same base/max the engine supervisor defaults to.
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
        }
    }
}

impl StdioRestartPolicy {
    /// Delay before retry number `failures` (1-based), deterministic
    /// (no jitter) so it is testable, same as the engine supervisor.
    fn delay_for(&self, failures: u32) -> Duration {
        if failures == 0 {
            return self.base;
        }
        let shift = failures.saturating_sub(1).min(20);
        let scaled = self.base.saturating_mul(1u32 << shift);
        scaled.min(self.max)
    }
}

/// How often an idle session is health-probed with an MCP `ping`.
const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// The cached `initialize` exchange for one configured server,
/// replayed to a replacement child on respawn and served back to the
/// federation's periodic re-handshakes without disturbing the child.
#[derive(Clone)]
struct CachedHandshake {
    /// The `initialize` request as the federation last sent it
    /// (params and all); the id is rewritten per exchange anyway.
    /// "Params and all" includes any `_meta` trace context the
    /// original carried: a replay after a respawn reuses it, so the
    /// replayed handshake is attributed to the exchange that first
    /// performed it rather than to a live trace. Accepted: the replay
    /// is supervisor-originated and has no live caller to attribute.
    request: JsonRpcRequest,
    /// The child's `initialize` result. Safe to cache per child: a
    /// running process's capabilities cannot change under it.
    response: JsonRpcResponse,
}

/// Supervision state for one configured stdio server.
#[derive(Default)]
struct Slot {
    /// The live session, when one exists.
    session: Option<Arc<StdioSession>>,
    /// Consecutive spawn failures or unproven deaths since the last
    /// exchange that round-tripped. Reset by a proven session.
    failures: u32,
    /// Earliest wall-clock instant the next spawn attempt is allowed.
    next_spawn_at: Option<Instant>,
    /// Cached `initialize` exchange; survives child restarts.
    handshake: Option<CachedHandshake>,
}

/// One supervised child per configured stdio server, keyed by server
/// name. Owned by `McpFederation`; dropping the pool (config removal,
/// hot reload) kills every child.
pub(crate) struct StdioSessionPool {
    slots: Mutex<HashMap<String, Slot>>,
    /// Cap on one response line's bytes; an oversized line kills the
    /// session (line framing cannot be resynchronized past it).
    max_line_bytes: usize,
    /// Deadline for one exchange (write + correlated response).
    exchange_timeout: Duration,
    /// Idle interval between `ping` health probes.
    probe_interval: Duration,
    restart: StdioRestartPolicy,
}

impl StdioSessionPool {
    /// Production pool: default probe interval and restart policy.
    pub(crate) fn new(max_line_bytes: usize, exchange_timeout: Duration) -> Self {
        Self::with_settings(
            max_line_bytes,
            exchange_timeout,
            DEFAULT_PROBE_INTERVAL,
            StdioRestartPolicy::default(),
        )
    }

    /// Fully parameterized constructor (`new` delegates here; tests
    /// tighten the intervals through the same code path production
    /// runs).
    pub(crate) fn with_settings(
        max_line_bytes: usize,
        exchange_timeout: Duration,
        probe_interval: Duration,
        restart: StdioRestartPolicy,
    ) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            max_line_bytes,
            exchange_timeout,
            probe_interval,
            restart,
        }
    }

    /// Send one JSON-RPC request through the server's supervised
    /// session, spawning or respawning the child as the restart
    /// policy allows. This is the single entry point the federation's
    /// `dispatch_request` uses for `transport: stdio`.
    pub(crate) async fn send(
        &self,
        server: &str,
        server_url: &str,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcResponse, StdioSessionError> {
        let session = self.checkout(server, server_url)?;
        if request.method == "initialize" {
            return self.initialize_exchange(server, &session, request).await;
        }
        self.ensure_handshake(server, &session).await?;
        session.exchange(request, self.exchange_timeout).await
    }

    /// Get the live session for `server`, or spawn one if the restart
    /// policy allows. Synchronous: death observation, backoff
    /// accounting, and spawn all happen under the slot lock so two
    /// concurrent callers cannot double-spawn.
    fn checkout(
        &self,
        server: &str,
        server_url: &str,
    ) -> Result<Arc<StdioSession>, StdioSessionError> {
        let mut slots = self.slots.lock();
        let slot = slots.entry(server.to_string()).or_default();
        if let Some(session) = &slot.session {
            if session.is_alive() {
                return Ok(Arc::clone(session));
            }
            // First observation of this child's death. A proven child
            // (it answered at least once) respawns immediately, which
            // is what keeps legacy one-shot servers working; an
            // unproven death is a crash loop and arms the backoff.
            if session.proven.load(Ordering::Acquire) {
                slot.failures = 0;
                slot.next_spawn_at = None;
            } else {
                slot.failures = slot.failures.saturating_add(1);
                slot.next_spawn_at = Some(Instant::now() + self.restart.delay_for(slot.failures));
            }
            slot.session = None;
        }
        if let Some(at) = slot.next_spawn_at {
            let now = Instant::now();
            if now < at {
                return Err(StdioSessionError::Backoff {
                    server: server.to_string(),
                    failures: slot.failures,
                    retry_in_ms: u64::try_from(at.duration_since(now).as_millis())
                        .unwrap_or(u64::MAX),
                });
            }
        }
        match self.spawn_session(server, server_url) {
            Ok(session) => {
                slot.session = Some(Arc::clone(&session));
                slot.next_spawn_at = None;
                Ok(session)
            }
            Err(e) => {
                slot.failures = slot.failures.saturating_add(1);
                slot.next_spawn_at = Some(Instant::now() + self.restart.delay_for(slot.failures));
                Err(e)
            }
        }
    }

    /// Spawn the child and its reader + health-probe tasks.
    fn spawn_session(
        &self,
        server: &str,
        server_url: &str,
    ) -> Result<Arc<StdioSession>, StdioSessionError> {
        let spawn_err = |reason: String| StdioSessionError::Spawn {
            server: server.to_string(),
            reason,
        };
        let cfg = decode_stdio_url(server_url).map_err(|e| spawn_err(e.to_string()))?;
        let mut child = Command::new(&cfg.command)
            .args(&cfg.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| spawn_err(format!("starting '{}': {e}", cfg.command)))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| spawn_err("stdin unavailable".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| spawn_err("stdout unavailable".to_string()))?;
        let pid = child.id();
        let session = Arc::new(StdioSession {
            server: server.to_string(),
            pid,
            alive: AtomicBool::new(true),
            proven: AtomicBool::new(false),
            next_wire_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            stdin: tokio::sync::Mutex::new(stdin),
            child: Mutex::new(Some(child)),
            close_reason: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            reader_task: Mutex::new(None),
            probe_task: Mutex::new(None),
            handshake_done: tokio::sync::Mutex::new(false),
        });
        let reader = tokio::spawn(run_reader(
            Arc::clone(&session),
            stdout,
            self.max_line_bytes,
        ));
        *session.reader_task.lock() = Some(reader);
        session.spawn_probe(self.probe_interval, self.exchange_timeout);
        debug!(server, pid, "stdio MCP session spawned");
        Ok(session)
    }

    /// Forward or replay-serve an `initialize` request. The first one
    /// per child is forwarded, completed with the required
    /// `notifications/initialized` (MCP 2025-06-18, basic/lifecycle),
    /// and cached; later ones on the same child are served from the
    /// cache, since a running child's capabilities cannot change and
    /// the spec allows `initialize` only once per connection.
    async fn initialize_exchange(
        &self,
        server: &str,
        session: &Arc<StdioSession>,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcResponse, StdioSessionError> {
        let mut done = session.handshake_done.lock().await;
        if *done {
            let cached = self
                .slots
                .lock()
                .get(server)
                .and_then(|s| s.handshake.as_ref().map(|h| h.response.clone()));
            if let Some(mut resp) = cached {
                resp.id = request.id.clone();
                return Ok(resp);
            }
            // Defensive: handshake marked done with no cache. Fall
            // through and forward, which re-caches.
        }
        let mut guard = HandshakeGuard {
            session: Some(session.as_ref()),
        };
        let resp = session.exchange(request, self.exchange_timeout).await?;
        if resp.error.is_none() {
            session
                .send_initialized_notification(self.exchange_timeout)
                .await?;
            let mut cache_req = request.clone();
            cache_req.id = None;
            if let Some(slot) = self.slots.lock().get_mut(server) {
                slot.handshake = Some(CachedHandshake {
                    request: cache_req,
                    response: resp.clone(),
                });
            }
            *done = true;
        }
        // Reached on completion (`*done` set) or on a refused
        // `initialize` (error response), which did not advance the
        // child's state; every other exit path leaves the guard armed.
        guard.disarm();
        Ok(resp)
    }

    /// Restore protocol state on a fresh child before normal traffic:
    /// replay the cached `initialize` handshake if one exists. A child
    /// that never saw `initialize` (nothing cached) gets raw traffic,
    /// exactly like the previous per-exchange transport delivered.
    async fn ensure_handshake(
        &self,
        server: &str,
        session: &Arc<StdioSession>,
    ) -> Result<(), StdioSessionError> {
        let mut done = session.handshake_done.lock().await;
        if *done {
            return Ok(());
        }
        let cached = self
            .slots
            .lock()
            .get(server)
            .and_then(|s| s.handshake.clone());
        let Some(handshake) = cached else {
            *done = true;
            return Ok(());
        };
        let mut replay = handshake.request.clone();
        replay.id = Some(serde_json::json!(0));
        let mut guard = HandshakeGuard {
            session: Some(session.as_ref()),
        };
        let resp = session.exchange(&replay, self.exchange_timeout).await?;
        if let Some(err) = &resp.error {
            // The replacement child refused the very handshake it
            // needs to serve anything; fail closed rather than send
            // it traffic it will misinterpret.
            let reason = format!(
                "initialize replay refused by respawned child: {} (code {})",
                err.message, err.code
            );
            session.close(&reason);
            return Err(StdioSessionError::SessionClosed {
                server: server.to_string(),
                reason,
            });
        }
        session
            .send_initialized_notification(self.exchange_timeout)
            .await?;
        if let Some(slot) = self.slots.lock().get_mut(server) {
            slot.handshake = Some(CachedHandshake {
                request: handshake.request,
                response: resp,
            });
        }
        *done = true;
        guard.disarm();
        Ok(())
    }
}

impl Drop for StdioSessionPool {
    fn drop(&mut self) {
        // Config removal or hot reload drops the federation and this
        // pool with it: kill every supervised child rather than
        // orphaning long-lived processes.
        for slot in self.slots.get_mut().values_mut() {
            if let Some(session) = slot.session.take() {
                session.close("stdio server removed from configuration");
            }
        }
    }
}

/// One live supervised child: the process, its serialized stdin, the
/// wire-id correlation table, and the reader + probe tasks.
struct StdioSession {
    server: String,
    /// OS pid, for logs; `None` if the child exited before it was read.
    pid: Option<u32>,
    alive: AtomicBool,
    /// Set once any exchange round-trips; decides restart policy.
    proven: AtomicBool,
    /// Session-scoped wire ids. Callers' JSON-RPC ids are rewritten
    /// to these on the pipe and restored on the way back, so
    /// concurrent exchanges (which today all carry `id: 1`) cannot
    /// collide.
    next_wire_id: AtomicU64,
    /// wire id -> the waiting caller.
    pending: Mutex<HashMap<u64, oneshot::Sender<JsonRpcResponse>>>,
    /// Serialized writes: one request line at a time.
    stdin: tokio::sync::Mutex<ChildStdin>,
    /// The child handle, taken by `close` to deliver the kill.
    child: Mutex<Option<Child>>,
    close_reason: Mutex<Option<String>>,
    /// Last completed exchange; gates the idle health probe.
    last_activity: Mutex<Instant>,
    reader_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    probe_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Whether THIS child has completed the `initialize` handshake
    /// (forwarded or replayed). Async mutex: it stays locked across
    /// the replay exchange so concurrent callers wait for one
    /// handshake instead of racing their own.
    handshake_done: tokio::sync::Mutex<bool>,
}

impl StdioSession {
    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn close_reason_text(&self) -> String {
        self.close_reason
            .lock()
            .clone()
            .unwrap_or_else(|| "session closed".to_string())
    }

    /// Close the session fail-closed: kill the child, drop every
    /// pending caller's sender (their `exchange` returns a typed
    /// error), and stop the reader + probe tasks. Idempotent.
    fn close(&self, reason: &str) {
        if self.alive.swap(false, Ordering::AcqRel) {
            *self.close_reason.lock() = Some(reason.to_string());
            warn!(
                server = %self.server,
                pid = self.pid,
                reason,
                "stdio MCP session closed"
            );
        }
        if let Some(mut child) = self.child.lock().take() {
            // Best-effort kill now; `kill_on_drop(true)` backstops it
            // and tokio reaps the exit status in the background.
            let _ = child.start_kill();
        }
        self.pending.lock().clear();
        if let Some(handle) = self.probe_task.lock().take() {
            handle.abort();
        }
        if let Some(handle) = self.reader_task.lock().take() {
            // The reader normally exits on its own via EOF once the
            // child dies; abort is the backstop (safe when `close` is
            // called FROM the reader: cancellation lands at its next
            // await, after it has already finished its work).
            handle.abort();
        }
    }

    /// One correlated exchange: rewrite the caller's id to a wire id,
    /// write the line, await the matching response, restore the id.
    /// The deadline covers the write too (a hung child eventually
    /// stops draining its stdin pipe). A JSON-RPC notification
    /// (`id: null`) is written and acknowledged locally; per JSON-RPC
    /// 2.0 no response will come.
    async fn exchange(
        &self,
        request: &JsonRpcRequest,
        timeout: Duration,
    ) -> Result<JsonRpcResponse, StdioSessionError> {
        let closed = |reason: String| StdioSessionError::SessionClosed {
            server: self.server.clone(),
            reason,
        };
        if !self.is_alive() {
            return Err(closed(self.close_reason_text()));
        }
        let Some(original_id) = request.id.clone() else {
            let line = self
                .render_line(request, None)
                .map_err(|e| closed(format!("request serialization failed: {e}")))?;
            return match tokio::time::timeout(timeout, self.write_line(line)).await {
                Ok(Ok(())) => Ok(notification_ack()),
                Ok(Err(e)) => Err(e),
                Err(_) => {
                    self.close("notification write deadline elapsed; child killed");
                    Err(StdioSessionError::Timeout {
                        server: self.server.clone(),
                        timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                    })
                }
            };
        };

        let wire_id = self.next_wire_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(wire_id, tx);
        // Re-check after registering: `close` may have drained the map
        // between the aliveness check above and the insert, in which
        // case nobody would ever complete this sender.
        if !self.is_alive() {
            self.pending.lock().remove(&wire_id);
            return Err(closed(self.close_reason_text()));
        }
        let guard = PendingGuard {
            pending: &self.pending,
            wire_id,
        };
        let line = match self.render_line(request, Some(wire_id)) {
            Ok(line) => line,
            Err(e) => return Err(closed(format!("request serialization failed: {e}"))),
        };
        let io = async {
            self.write_line(line).await?;
            rx.await.map_err(|_| closed(self.close_reason_text()))
        };
        match tokio::time::timeout(timeout, io).await {
            Ok(Ok(mut resp)) => {
                drop(guard); // reader already removed the entry; no-op
                resp.id = Some(original_id);
                self.proven.store(true, Ordering::Release);
                *self.last_activity.lock() = Instant::now();
                Ok(resp)
            }
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => {
                // A deadline elapsing on a shared pipe means a hung
                // child; kill it so the hang cannot absorb every later
                // call, and fail this one closed.
                self.close("exchange deadline elapsed; child killed");
                Err(StdioSessionError::Timeout {
                    server: self.server.clone(),
                    timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                })
            }
        }
    }

    /// Serialize `request` as one line, with the wire id substituted
    /// (`None` keeps `id: null`, the notification spelling).
    fn render_line(
        &self,
        request: &JsonRpcRequest,
        wire_id: Option<u64>,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = serde_json::to_value(request)?;
        if let Some(id) = wire_id {
            value["id"] = serde_json::json!(id);
        }
        // serde_json never emits raw newlines (they are escaped inside
        // strings), so one message is always exactly one line.
        serde_json::to_vec(&value)
    }

    /// Write one already-serialized line to the child, serialized
    /// against concurrent writers.
    async fn write_line(&self, line: Vec<u8>) -> Result<(), StdioSessionError> {
        let mut stdin = self.stdin.lock().await;
        let result = async {
            stdin.write_all(&line).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await
        }
        .await;
        result.map_err(|e| {
            let reason = format!("stdin write failed: {e}");
            self.close(&reason);
            StdioSessionError::SessionClosed {
                server: self.server.clone(),
                reason,
            }
        })
    }

    /// Complete the lifecycle handshake: MCP 2025-06-18
    /// (basic/lifecycle) requires `notifications/initialized` from the
    /// client after a successful `initialize` response, before normal
    /// traffic. The federation itself never sends it (its HTTP
    /// transports are stateless per exchange), so the session layer
    /// owns it here.
    async fn send_initialized_notification(
        &self,
        timeout: Duration,
    ) -> Result<(), StdioSessionError> {
        let note = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "notifications/initialized".to_string(),
            params: None,
            id: None,
        };
        self.exchange(&note, timeout).await.map(|_| ())
    }

    /// Start the idle health probe: an MCP `ping` every `interval` of
    /// idleness. Per MCP 2025-06-18 (basic/utilities/ping) the
    /// receiver must respond promptly; ANY well-formed response line
    /// with the matching id, an error object included, proves the
    /// pipe and the child's event loop are live, so `exchange`
    /// returning `Ok` is the only health signal. A probe timeout
    /// closes the session (the next call respawns under the restart
    /// policy).
    fn spawn_probe(self: &Arc<Self>, interval: Duration, timeout: Duration) {
        let session = Arc::clone(self);
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if !session.is_alive() {
                    break;
                }
                if session.last_activity.lock().elapsed() < interval {
                    continue;
                }
                let probe = JsonRpcRequest {
                    jsonrpc: "2.0".to_string(),
                    method: "ping".to_string(),
                    params: None,
                    id: Some(serde_json::json!("sbproxy-stdio-health-probe")),
                };
                if let Err(e) = session.exchange(&probe, timeout).await {
                    // A probe failure never passes through
                    // `dispatch_request`, so record it here or the
                    // respawn would be a log-only event.
                    sbproxy_observe::metrics::record_mcp_upstream_io_failure(e.metric_kind());
                    // Timeout already closed the session; close again
                    // is idempotent and covers the other error paths.
                    session.close(&format!("health probe failed: {e}"));
                    break;
                }
            }
        });
        *self.probe_task.lock() = Some(handle);
    }
}

/// A pending-map entry that unregisters itself if the exchange future
/// is dropped early (per-server `timeout:` wrappers cancel futures),
/// so an abandoned call cannot leak its correlation slot.
struct PendingGuard<'a> {
    pending: &'a Mutex<HashMap<u64, oneshot::Sender<JsonRpcResponse>>>,
    wire_id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.pending.lock().remove(&self.wire_id);
    }
}

/// Kills the child unless a handshake scope completes cleanly.
///
/// Forwarding or replaying `initialize` mutates the child's protocol
/// state the moment the line is written. If the scope is left before
/// the session records that (`*done = true`), the two states diverge:
/// the child has accepted an `initialize` the session does not know
/// about, and the next attempt would send it a second one, which
/// strict servers refuse. The two ways out of the scope early are a
/// cancelled future (the per-server `timeout:` wrapper in the core
/// dispatch drops the whole call chain at its deadline) and a
/// part-way failure (the `notifications/initialized` write erroring
/// after a successful `initialize`). Both leave the child's state
/// unknowable, so the guard closes the session: the child dies, and
/// the next call respawns a fresh one whose handshake starts from
/// scratch. Disarm only after `*done` is set, or after a refused
/// `initialize` (an error response), which does not advance the
/// child's state and is safe to retry on the same child.
struct HandshakeGuard<'a> {
    session: Option<&'a StdioSession>,
}

impl HandshakeGuard<'_> {
    fn disarm(&mut self) {
        self.session = None;
    }
}

impl Drop for HandshakeGuard<'_> {
    fn drop(&mut self) {
        if let Some(session) = self.session {
            session
                .close("handshake interrupted before completion; child killed for a clean respawn");
        }
    }
}

/// The synthesized local acknowledgement for a written notification.
fn notification_ack() -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: Some(serde_json::Value::Null),
        error: None,
        id: None,
    }
}

/// One capped line read.
enum LineRead {
    /// A complete line (newline stripped). At EOF a trailing unterminated
    /// line is returned as a line, matching `read_until` semantics.
    Line(Vec<u8>),
    /// Clean end of stream.
    Eof,
    /// The line exceeded the cap before its newline arrived.
    TooLong,
}

/// Read one newline-delimited line without ever buffering more than
/// `cap` bytes (the previous transport buffered the whole line first
/// and checked after, which let a runaway child exhaust memory before
/// the cap fired).
async fn read_line_capped<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    cap: usize,
) -> std::io::Result<LineRead> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(if buf.is_empty() {
                LineRead::Eof
            } else {
                LineRead::Line(buf)
            });
        }
        match chunk.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                if buf.len() + pos > cap {
                    reader.consume(pos + 1);
                    return Ok(LineRead::TooLong);
                }
                buf.extend_from_slice(&chunk[..pos]);
                reader.consume(pos + 1);
                return Ok(LineRead::Line(buf));
            }
            None => {
                let len = chunk.len();
                if buf.len() + len > cap {
                    reader.consume(len);
                    return Ok(LineRead::TooLong);
                }
                buf.extend_from_slice(chunk);
                reader.consume(len);
            }
        }
    }
}

/// The reader task: owns the child's stdout for the session's
/// lifetime, correlates response lines back to waiting callers by
/// wire id, and closes the session fail-closed on EOF (child died),
/// an oversized line, or a framing violation. Server-initiated
/// requests and notifications (lines carrying a `method`) are dropped
/// with a debug log: the gateway does not support server-initiated
/// MCP flows, and treating them as fatal would kill sessions with
/// chatty-but-legal servers.
async fn run_reader(session: Arc<StdioSession>, stdout: ChildStdout, cap: usize) {
    let mut reader = BufReader::new(stdout);
    loop {
        match read_line_capped(&mut reader, cap).await {
            Ok(LineRead::Eof) => {
                session.close("child exited (stdout closed)");
                break;
            }
            Ok(LineRead::TooLong) => {
                session.close(&format!("response exceeded byte cap ({cap} bytes)"));
                break;
            }
            Ok(LineRead::Line(line)) => {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let value: serde_json::Value = match serde_json::from_slice(&line) {
                    Ok(v) => v,
                    Err(e) => {
                        // Not JSON: line framing can no longer be
                        // trusted, so this is fatal, fail-closed.
                        session.close(&format!("non-JSON line on stdout: {e}"));
                        break;
                    }
                };
                if value.get("method").is_some() {
                    debug!(
                        server = %session.server,
                        "dropping server-initiated stdio message (unsupported)"
                    );
                    continue;
                }
                let Some(wire_id) = value.get("id").and_then(serde_json::Value::as_u64) else {
                    debug!(
                        server = %session.server,
                        "dropping stdio response with no numeric wire id"
                    );
                    continue;
                };
                let resp: JsonRpcResponse = match serde_json::from_value(value) {
                    Ok(r) => r,
                    Err(e) => {
                        session.close(&format!("malformed JSON-RPC response: {e}"));
                        break;
                    }
                };
                let sender = session.pending.lock().remove(&wire_id);
                match sender {
                    Some(tx) => {
                        let _ = tx.send(resp);
                    }
                    None => {
                        debug!(
                            server = %session.server,
                            wire_id,
                            "dropping stdio response for unknown wire id"
                        );
                    }
                }
            }
            Err(e) => {
                session.close(&format!("stdout read error: {e}"));
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn py(script: &str) -> String {
        encode_stdio_url("python3", &["-c".to_string(), script.to_string()])
    }

    fn req(method: &str) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: None,
            // Deliberately the constant id every federation exchange
            // uses today; correlation must come from wire ids.
            id: Some(json!(1)),
        }
    }

    fn pool(timeout: Duration) -> StdioSessionPool {
        StdioSessionPool::new(1 << 20, timeout)
    }

    /// A server loop that answers every request line with its pid.
    /// Written as a raw string with column-0 content: Python is
    /// indentation-sensitive and Rust's `\` line continuation strips
    /// leading whitespace.
    const PID_LOOP: &str = r#"
import sys, os, json
for line in sys.stdin:
    m = json.loads(line)
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "result": {"pid": os.getpid(), "method": m.get("method")}, "id": m.get("id")}) + "\n")
    sys.stdout.flush()
"#;

    fn pid_of(resp: &JsonRpcResponse) -> u64 {
        resp.result
            .as_ref()
            .and_then(|r| r.get("pid"))
            .and_then(|p| p.as_u64())
            .expect("pid in response")
    }

    /// WOR-2453 acceptance: one process per configured stdio server
    /// for the lifetime of the pool, not one per exchange.
    #[tokio::test]
    async fn two_sequential_calls_share_one_child() {
        let p = pool(Duration::from_secs(5));
        let url = py(PID_LOOP);
        let a = p.send("s", &url, &req("ping")).await.expect("first call");
        let b = p.send("s", &url, &req("ping")).await.expect("second call");
        assert_eq!(pid_of(&a), pid_of(&b), "both exchanges must hit one child");
        assert_eq!(a.id, Some(json!(1)), "caller id restored");
    }

    /// WOR-2453 acceptance: a hung child's call fails closed with a
    /// typed error inside the deadline instead of hanging.
    #[tokio::test]
    async fn hung_child_call_times_out_closed_with_typed_error() {
        let p = pool(Duration::from_millis(300));
        let url = py("import sys, time\nsys.stdin.readline()\ntime.sleep(3600)\n");
        let started = Instant::now();
        let err = p
            .send("s", &url, &req("ping"))
            .await
            .expect_err("hung child must not produce a response");
        assert!(
            matches!(err, StdioSessionError::Timeout { .. }),
            "expected Timeout, got: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "timeout must be enforced promptly, took {:?}",
            started.elapsed()
        );
    }

    /// WOR-2453 acceptance: a child that dies after serving is
    /// respawned and the server serves again (this is also what keeps
    /// legacy one-shot servers working under the persistent session).
    #[tokio::test]
    async fn dead_child_is_restarted_and_serves_again() {
        let p = pool(Duration::from_secs(5));
        // One-shot: answer a single request, then exit.
        let url = py(
            "import sys, os, json\n\
m = json.loads(sys.stdin.readline())\n\
sys.stdout.write(json.dumps({\"jsonrpc\": \"2.0\", \"result\": {\"pid\": os.getpid()}, \"id\": m.get(\"id\")}) + \"\\n\")\n\
sys.stdout.flush()\n",
        );
        let first = p.send("s", &url, &req("ping")).await.expect("first call");
        let first_pid = pid_of(&first);
        // The death is observed asynchronously (reader EOF); a call in
        // the race window fails closed, then the respawn (immediate,
        // because the child was proven) serves again.
        let mut second_pid = None;
        for _ in 0..50 {
            match p.send("s", &url, &req("ping")).await {
                Ok(resp) => {
                    second_pid = Some(pid_of(&resp));
                    break;
                }
                Err(StdioSessionError::SessionClosed { .. }) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(other) => panic!("unexpected error while awaiting respawn: {other}"),
            }
        }
        let second_pid = second_pid.expect("a respawned child must serve again");
        assert_ne!(first_pid, second_pid, "the dead child must be replaced");
    }

    /// An unproven child (spawn fails outright) arms the bounded
    /// exponential backoff, and calls inside the window fail closed
    /// with a typed error instead of triggering a spawn storm.
    #[tokio::test]
    async fn spawn_failure_enters_bounded_backoff_and_fails_closed() {
        let p = StdioSessionPool::with_settings(
            1 << 20,
            Duration::from_secs(1),
            Duration::from_secs(3600),
            StdioRestartPolicy {
                base: Duration::from_millis(200),
                max: Duration::from_secs(1),
            },
        );
        let url = encode_stdio_url("/nonexistent-sbproxy-wor2453-binary", &[]);
        let err = p
            .send("s", &url, &req("ping"))
            .await
            .expect_err("spawn fails");
        assert!(
            matches!(err, StdioSessionError::Spawn { .. }),
            "expected Spawn, got: {err}"
        );
        let err = p
            .send("s", &url, &req("ping"))
            .await
            .expect_err("second call inside the window is refused");
        assert!(
            matches!(err, StdioSessionError::Backoff { .. }),
            "expected Backoff, got: {err}"
        );
        // After the window a fresh attempt is allowed (and fails the
        // same way: the policy bounds the rate, it never bricks the
        // server permanently).
        tokio::time::sleep(Duration::from_millis(250)).await;
        let err = p
            .send("s", &url, &req("ping"))
            .await
            .expect_err("retry after the window attempts a spawn again");
        assert!(
            matches!(err, StdioSessionError::Spawn { .. }),
            "expected Spawn after backoff, got: {err}"
        );
    }

    /// WOR-2453 acceptance: a crash with the call in flight fails the
    /// call closed promptly (typed error, no deadline-length hang).
    #[tokio::test]
    async fn child_death_fails_inflight_call_closed() {
        let p = pool(Duration::from_secs(10));
        let url = py("import sys\nsys.stdin.readline()\nsys.exit(0)\n");
        let started = Instant::now();
        let err = p
            .send("s", &url, &req("ping"))
            .await
            .expect_err("silent exit must fail the in-flight call");
        assert!(
            matches!(err, StdioSessionError::SessionClosed { .. }),
            "expected SessionClosed, got: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the failure must come from death detection, not the deadline; took {:?}",
            started.elapsed()
        );
    }

    /// Two concurrent exchanges carrying the SAME caller id (all
    /// federation exchanges use `id: 1` today) are correlated by wire
    /// id even when the child answers out of order.
    #[tokio::test]
    async fn concurrent_calls_correlate_by_wire_id() {
        let p = pool(Duration::from_secs(5));
        // Read two requests, answer them in reverse order.
        let url = py(r#"
import sys, json
a = json.loads(sys.stdin.readline())
b = json.loads(sys.stdin.readline())
for m in (b, a):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "result": {"method": m["method"]}, "id": m["id"]}) + "\n")
sys.stdout.flush()
"#);
        let alpha_req = req("alpha");
        let beta_req = req("beta");
        let (alpha, beta) =
            tokio::join!(p.send("s", &url, &alpha_req), p.send("s", &url, &beta_req),);
        let alpha = alpha.expect("alpha response");
        let beta = beta.expect("beta response");
        let echoed = |r: &JsonRpcResponse| {
            r.result
                .as_ref()
                .and_then(|v| v.get("method"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
                .expect("echoed method")
        };
        assert_eq!(echoed(&alpha), "alpha", "alpha caller got beta's response");
        assert_eq!(echoed(&beta), "beta", "beta caller got alpha's response");
        assert_eq!(alpha.id, Some(json!(1)));
        assert_eq!(beta.id, Some(json!(1)));
    }

    /// An oversized response line kills the session fail-closed: line
    /// framing cannot be resynchronized past it.
    #[tokio::test]
    async fn oversized_response_line_closes_the_session() {
        let p = StdioSessionPool::with_settings(
            4096,
            Duration::from_secs(5),
            Duration::from_secs(3600),
            StdioRestartPolicy::default(),
        );
        let url = py(
            "import sys, json, time\n\
m = json.loads(sys.stdin.readline())\n\
sys.stdout.write(json.dumps({\"jsonrpc\": \"2.0\", \"result\": {\"pad\": \"x\" * 20000}, \"id\": m[\"id\"]}) + \"\\n\")\n\
sys.stdout.flush()\n\
time.sleep(10)\n",
        );
        let err = p
            .send("s", &url, &req("ping"))
            .await
            .expect_err("oversized line must fail closed");
        match err {
            StdioSessionError::SessionClosed { reason, .. } => {
                assert!(
                    reason.contains("byte cap"),
                    "reason must name the cap: {reason}"
                );
            }
            other => panic!("expected SessionClosed, got: {other}"),
        }
    }

    /// A non-JSON line on stdout is a framing violation and closes the
    /// session fail-closed.
    #[tokio::test]
    async fn non_json_stdout_closes_the_session() {
        let p = pool(Duration::from_secs(5));
        let url = py("import sys, time\n\
sys.stdin.readline()\n\
sys.stdout.write(\"this is not json\\n\")\n\
sys.stdout.flush()\n\
time.sleep(10)\n");
        let err = p
            .send("s", &url, &req("ping"))
            .await
            .expect_err("garbage stdout must fail closed");
        match err {
            StdioSessionError::SessionClosed { reason, .. } => {
                assert!(
                    reason.contains("non-JSON"),
                    "reason must name the violation: {reason}"
                );
            }
            other => panic!("expected SessionClosed, got: {other}"),
        }
    }

    /// Server-initiated notifications interleaved on stdout (legal
    /// under MCP) are skipped; the correlated response still arrives.
    #[tokio::test]
    async fn server_initiated_messages_are_skipped() {
        let p = pool(Duration::from_secs(5));
        let url = py(
            "import sys, json\n\
m = json.loads(sys.stdin.readline())\n\
sys.stdout.write(json.dumps({\"jsonrpc\": \"2.0\", \"method\": \"notifications/progress\", \"params\": {}}) + \"\\n\")\n\
sys.stdout.write(json.dumps({\"jsonrpc\": \"2.0\", \"result\": \"ok\", \"id\": m[\"id\"]}) + \"\\n\")\n\
sys.stdout.flush()\n",
        );
        let resp = p.send("s", &url, &req("ping")).await.expect("response");
        assert_eq!(resp.result, Some(json!("ok")));
    }

    /// The first `initialize` is forwarded and completed with
    /// `notifications/initialized`; later ones on the same child are
    /// served from the cache without disturbing the child.
    #[tokio::test]
    async fn initialize_is_forwarded_once_then_served_from_cache() {
        let p = pool(Duration::from_secs(5));
        let url = py(r#"
import sys, json
init_count = 0
notified = 0
for line in sys.stdin:
    m = json.loads(line)
    meth = m.get("method")
    if meth == "notifications/initialized":
        notified += 1
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "result": {"init_count": init_count + (1 if meth == "initialize" else 0), "notified": notified}, "id": m["id"]}) + "\n")
    if meth == "initialize":
        init_count += 1
    sys.stdout.flush()
"#);
        let mut init = req("initialize");
        init.id = Some(json!(7));
        let first = p.send("s", &url, &init).await.expect("first initialize");
        assert_eq!(
            first.result.as_ref().and_then(|r| r.get("init_count")),
            Some(&json!(1))
        );
        assert_eq!(first.id, Some(json!(7)));

        let mut again = req("initialize");
        again.id = Some(json!(8));
        let second = p.send("s", &url, &again).await.expect("second initialize");
        assert_eq!(
            second.result.as_ref().and_then(|r| r.get("init_count")),
            Some(&json!(1)),
            "the second initialize must be served from the cache"
        );
        assert_eq!(
            second.id,
            Some(json!(8)),
            "cached response carries the caller's id"
        );

        let tool = p.send("s", &url, &req("tools/x")).await.expect("tool call");
        let result = tool.result.expect("tool result");
        assert_eq!(
            result.get("init_count"),
            Some(&json!(1)),
            "the child must have seen exactly one initialize"
        );
        assert_eq!(
            result.get("notified"),
            Some(&json!(1)),
            "notifications/initialized must have been written exactly once"
        );
    }

    /// A respawned child gets the cached `initialize` handshake
    /// replayed before the triggering call: a strict server that
    /// refuses pre-initialize traffic keeps working across a crash.
    #[tokio::test]
    async fn handshake_is_replayed_on_respawn() {
        let p = pool(Duration::from_secs(5));
        // Strict server: refuses everything before initialize; exits
        // after answering one post-initialize request.
        let url = py(r#"
import sys, json, os
initialized = False
for line in sys.stdin:
    m = json.loads(line)
    meth = m.get("method")
    if meth == "notifications/initialized":
        continue
    if meth == "initialize":
        initialized = True
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "result": {"pid": os.getpid()}, "id": m["id"]}) + "\n")
        sys.stdout.flush()
        continue
    if not initialized:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "error": {"code": -32002, "message": "not initialized"}, "id": m["id"]}) + "\n")
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "result": {"pid": os.getpid()}, "id": m["id"]}) + "\n")
    sys.stdout.flush()
    sys.exit(0)
"#);
        let init_resp = p
            .send("s", &url, &req("initialize"))
            .await
            .expect("initialize");
        let first_pid = pid_of(&init_resp);
        let first_tool = p
            .send("s", &url, &req("tools/x"))
            .await
            .expect("first tool call");
        assert_eq!(pid_of(&first_tool), first_pid);
        // The child exits after that call. The next successful call
        // must come from a replacement child that was re-initialized
        // first, or the strict server would have answered with the
        // -32002 error object instead of a result.
        let mut replay_pid = None;
        for _ in 0..50 {
            match p.send("s", &url, &req("tools/x")).await {
                Ok(resp) => {
                    assert!(
                        resp.error.is_none(),
                        "a respawned child answered without the handshake replay: {:?}",
                        resp.error
                    );
                    replay_pid = Some(pid_of(&resp));
                    break;
                }
                Err(StdioSessionError::SessionClosed { .. }) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(other) => panic!("unexpected error while awaiting respawn: {other}"),
            }
        }
        let replay_pid = replay_pid.expect("the respawned strict server must serve again");
        assert_ne!(first_pid, replay_pid, "a new child must have been spawned");
    }

    /// Dropping the pool (config removal, hot reload) kills the
    /// supervised child rather than orphaning it.
    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_the_pool_kills_the_child() {
        let p = pool(Duration::from_secs(5));
        let url = py(PID_LOOP);
        let resp = p.send("s", &url, &req("ping")).await.expect("call");
        let pid = pid_of(&resp);
        drop(p);
        // The kill is delivered synchronously in Drop; reaping is
        // asynchronous, so accept either "gone" or "zombie".
        let mut dead = false;
        for _ in 0..40 {
            let out = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .expect("ps runs");
            let stat = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !out.status.success() || stat.starts_with('Z') {
                dead = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(dead, "child {pid} must be killed when the pool drops");
    }

    /// A child that stops answering the idle `ping` health probe is
    /// closed and replaced on the next call.
    #[tokio::test]
    async fn failed_health_probe_closes_the_session_and_next_call_respawns() {
        let p = StdioSessionPool::with_settings(
            1 << 20,
            Duration::from_millis(500),
            Duration::from_millis(100),
            StdioRestartPolicy::default(),
        );
        // Answers everything except ping.
        let url = py(r#"
import sys, json, os
for line in sys.stdin:
    m = json.loads(line)
    if m.get("method") == "ping":
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "result": {"pid": os.getpid()}, "id": m.get("id")}) + "\n")
    sys.stdout.flush()
"#);
        let first = p
            .send("s", &url, &req("tools/x"))
            .await
            .expect("first call");
        let first_pid = pid_of(&first);
        // Idle long enough for the probe to fire (100ms) and its
        // deadline to elapse (500ms), with generous slack for CI load.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let second = p
            .send("s", &url, &req("tools/x"))
            .await
            .expect("respawned call");
        assert_ne!(
            first_pid,
            pid_of(&second),
            "the probe-deaf child must have been replaced"
        );
    }

    /// A healthy child that answers the probe is left alone: the
    /// session survives idleness.
    #[tokio::test]
    async fn healthy_probe_keeps_the_session() {
        let p = StdioSessionPool::with_settings(
            1 << 20,
            Duration::from_millis(500),
            Duration::from_millis(100),
            StdioRestartPolicy::default(),
        );
        let url = py(PID_LOOP);
        let first = p
            .send("s", &url, &req("tools/x"))
            .await
            .expect("first call");
        tokio::time::sleep(Duration::from_millis(600)).await;
        let second = p
            .send("s", &url, &req("tools/x"))
            .await
            .expect("second call");
        assert_eq!(
            pid_of(&first),
            pid_of(&second),
            "a probe-healthy child must not be replaced"
        );
    }

    /// A handshake cancelled mid-flight (a per-server `timeout:`
    /// wrapper dropping the future) must not leave a live child that
    /// already saw `initialize` while the session believes it has
    /// not: the guard kills the child, and the retry lands on a
    /// fresh one. Red before `HandshakeGuard` landed: the retried
    /// initialize below reached the SAME child, whose init_count
    /// then read 2.
    #[tokio::test]
    async fn cancelled_initialize_kills_the_child_instead_of_replaying_onto_it() {
        let p = pool(Duration::from_secs(5));
        // Counts initializes; the first one answers slowly so the
        // caller can cancel while it is in flight.
        let url = py(r#"
import sys, json, os, time
init_count = 0
for line in sys.stdin:
    m = json.loads(line)
    meth = m.get("method")
    if meth == "notifications/initialized":
        continue
    if meth == "initialize":
        init_count += 1
        if init_count == 1:
            time.sleep(2)
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "result": {"pid": os.getpid(), "init_count": init_count}, "id": m.get("id")}) + "\n")
    sys.stdout.flush()
"#);
        let init_req = req("initialize");
        let cancelled =
            tokio::time::timeout(Duration::from_millis(200), p.send("s", &url, &init_req)).await;
        assert!(
            cancelled.is_err(),
            "the outer wrapper must cancel the slow handshake"
        );
        // The guard killed the first child. The retry must be served
        // by a fresh child seeing its FIRST initialize (the unproven
        // death arms the backoff, so tolerate Backoff while looping).
        let mut init_count = None;
        for _ in 0..60 {
            match p.send("s", &url, &req("initialize")).await {
                Ok(resp) => {
                    init_count = resp
                        .result
                        .as_ref()
                        .and_then(|r| r.get("init_count"))
                        .and_then(|c| c.as_u64());
                    break;
                }
                Err(
                    StdioSessionError::SessionClosed { .. } | StdioSessionError::Backoff { .. },
                ) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(other) => panic!("unexpected error: {other}"),
            }
        }
        assert_eq!(
            init_count,
            Some(1),
            "the retried initialize must land on a fresh child, not replay onto the old one"
        );
    }

    /// A JSON-RPC notification (`id: null`) is written and locally
    /// acknowledged without waiting for a response that will never
    /// come.
    #[tokio::test]
    async fn notification_returns_local_ack_without_waiting() {
        let p = pool(Duration::from_secs(5));
        let url = py(PID_LOOP);
        let mut note = req("notifications/whatever");
        note.id = None;
        let started = Instant::now();
        let resp = p.send("s", &url, &note).await.expect("notification ack");
        assert_eq!(resp.id, None);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a notification must not wait for a response"
        );
    }
}
