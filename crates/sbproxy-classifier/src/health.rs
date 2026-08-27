//! HTTP endpoints for health probes and metrics scraping.
//!
//! Ported from the enterprise `sbproxy-classifier` crate's `health.rs`, with
//! the metrics half adapted from `metrics-exporter-prometheus` to the
//! `prometheus` crate (see `crate::metrics` for why). Exposes:
//!
//! - `GET /healthz` - liveness probe. Always 200 once the server is up.
//! - `GET /readyz` - readiness probe. 200 once startup has finished; 503
//!   before that.
//! - `GET /metrics` - Prometheus text exposition of every family in
//!   `crate::metrics`, gathered from the process-global default registry.
//! - `GET /tenants` - bounded, cursor-paginated JSON tenant metadata for a
//!   quick operator check without reaching for the TCP `list` command.

use crate::auth::AdminAuth;
use crate::registry::Registry;
#[cfg(test)]
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::debug;

/// Readiness flag. Starts `false`; flipped to `true` exactly once by the
/// startup driver in `main.rs` once the servers are bound.
#[derive(Clone, Debug, Default)]
pub struct ReadyState {
    flag: Arc<AtomicBool>,
}

impl ReadyState {
    /// Build a fresh `ReadyState` in the not-ready position.
    pub fn new() -> Self {
        Self::default()
    }

    /// Flip the readiness flag to `true`. Idempotent.
    pub fn mark_ready(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Read the current readiness state.
    pub fn is_ready(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

/// Serve `/healthz`, `/readyz`, `/metrics`, and authenticated `/tenants` on a
/// pre-bound listener until
/// the process exits or the listener errors.
pub const DEFAULT_MAX_CONNECTIONS: usize = 128;
pub const DEFAULT_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const MAX_REQUEST_BYTES: u64 = 8192;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DEFAULT_LISTENER_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    pub max_connections: usize,
    pub io_timeout: std::time::Duration,
}

impl HttpLimits {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(1..=100_000).contains(&self.max_connections) {
            anyhow::bail!("HTTP max_connections must be in 1..=100000");
        }
        if self.io_timeout.is_zero() || self.io_timeout > std::time::Duration::from_secs(60) {
            anyhow::bail!("HTTP io_timeout must be in 1..=60000ms");
        }
        Ok(())
    }

    #[cfg(test)]
    fn with_test_clock(self, clock: Arc<HttpTestClock>) -> HttpServeOptions {
        HttpServeOptions::from(self).with_test_clock(clock)
    }

    #[cfg(test)]
    pub(crate) fn with_test_control(self, control: Arc<HttpTestControl>) -> HttpServeOptions {
        HttpServeOptions::from(self).with_test_control(control)
    }
}

#[derive(Clone, Debug)]
pub struct HttpServeOptions {
    limits: HttpLimits,
    shutdown_handle: Option<HttpShutdownHandle>,
    #[cfg(test)]
    test_clock: Option<Arc<HttpTestClock>>,
    #[cfg(test)]
    test_control: Option<Arc<HttpTestControl>>,
}

impl From<HttpLimits> for HttpServeOptions {
    fn from(limits: HttpLimits) -> Self {
        Self {
            limits,
            shutdown_handle: None,
            #[cfg(test)]
            test_clock: None,
            #[cfg(test)]
            test_control: None,
        }
    }
}

impl HttpServeOptions {
    pub(crate) fn with_shutdown_handle(mut self, shutdown_handle: HttpShutdownHandle) -> Self {
        self.shutdown_handle = Some(shutdown_handle);
        self
    }

    #[cfg(test)]
    fn with_test_clock(mut self, clock: Arc<HttpTestClock>) -> Self {
        self.test_clock = Some(clock);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_control(mut self, control: Arc<HttpTestControl>) -> Self {
        self.test_control = Some(control);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpCommand {
    Healthz,
    Readyz,
    Metrics,
    Tenants,
    Decode,
    Unknown,
}

impl HttpCommand {
    fn from_path(path: &str) -> Self {
        match path.split_once('?').map_or(path, |(route, _)| route) {
            "/healthz" => Self::Healthz,
            "/readyz" => Self::Readyz,
            "/metrics" => Self::Metrics,
            "/tenants" => Self::Tenants,
            _ => Self::Unknown,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Healthz => "healthz",
            Self::Readyz => "readyz",
            Self::Metrics => "metrics",
            Self::Tenants => "tenants",
            Self::Decode => "decode",
            Self::Unknown => "unknown",
        }
    }
}

const DEFAULT_TENANT_PAGE_SIZE: usize = 32;

fn tenant_page_parameters(path: &str) -> Result<(usize, Option<&str>), String> {
    let Some((_, query)) = path.split_once('?') else {
        return Ok((DEFAULT_TENANT_PAGE_SIZE, None));
    };
    let mut page_size = None;
    let mut cursor = None;
    for parameter in query.split('&') {
        let (name, value) = parameter
            .split_once('=')
            .ok_or_else(|| "tenant query parameters require name=value".to_string())?;
        match name {
            "page_size" if page_size.is_none() => {
                page_size = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| "page_size must be a positive integer".to_string())?,
                );
            }
            "cursor" if cursor.is_none() => {
                if value.is_empty()
                    || value.len() > 128
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
                {
                    return Err("cursor is not a valid tenant id".to_string());
                }
                cursor = Some(value);
            }
            "page_size" | "cursor" => {
                return Err(format!("duplicate tenant query parameter: {name}"));
            }
            _ => return Err(format!("unknown tenant query parameter: {name}")),
        }
    }
    Ok((page_size.unwrap_or(DEFAULT_TENANT_PAGE_SIZE), cursor))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpTerminalOutcome {
    RequestLimit,
    MalformedRequest,
}

fn http_metric_command(command: HttpCommand) -> crate::metrics::Command {
    match command {
        HttpCommand::Healthz => crate::metrics::Command::Healthz,
        HttpCommand::Readyz => crate::metrics::Command::Readyz,
        HttpCommand::Metrics => crate::metrics::Command::Metrics,
        HttpCommand::Tenants => crate::metrics::Command::Tenants,
        HttpCommand::Decode => crate::metrics::Command::Decode,
        HttpCommand::Unknown => crate::metrics::Command::Unknown,
    }
}

fn start_http_outcome(outcome: &mut Option<crate::metrics::OutcomeGuard>, command: HttpCommand) {
    outcome.get_or_insert_with(|| {
        crate::metrics::begin_outcome(
            crate::metrics::Transport::Http,
            http_metric_command(command),
        )
    });
}

fn finish_http_failure(
    outcome: &mut Option<crate::metrics::OutcomeGuard>,
    command: HttpCommand,
    stage: crate::metrics::Stage,
    reason: crate::metrics::Reason,
) {
    let guard = outcome.take().unwrap_or_else(|| {
        crate::metrics::begin_outcome(
            crate::metrics::Transport::Http,
            http_metric_command(command),
        )
    });
    guard.failure(stage, reason);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpChildFailure {
    Cancelled,
    Panic,
}

fn collect_http_child_result(
    exit: &mut HttpListenerExitReport,
    joined: Result<(), tokio::task::JoinError>,
) -> Option<HttpChildFailure> {
    exit.connection_children_finished += 1;
    exit.connection_child_results_collected += 1;
    match joined {
        Ok(()) => None,
        Err(join_error) if join_error.is_cancelled() => Some(HttpChildFailure::Cancelled),
        Err(_) => {
            exit.connection_child_panics += 1;
            Some(HttpChildFailure::Panic)
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum HttpResponseOutcome {
    Success,
    Failure(crate::metrics::Stage, crate::metrics::Reason),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpFault {
    ReadIo,
    Handler,
    Encode,
    Write,
    Flush,
}

#[cfg(test)]
#[derive(Debug)]
struct ArmedHttpFault {
    consumed: AtomicUsize,
}

#[cfg(test)]
impl ArmedHttpFault {
    fn mark_consumed(&self) {
        self.consumed.fetch_add(1, Ordering::SeqCst);
    }

    fn assert_consumed_exactly_once(&self) {
        assert_eq!(
            self.consumed.load(Ordering::SeqCst),
            1,
            "HTTP test fault must be consumed exactly once"
        );
    }
}

#[cfg(test)]
#[derive(Debug)]
struct PendingHttpFault {
    fault: HttpFault,
    armed: Arc<ArmedHttpFault>,
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct HttpTestControl {
    faults: Mutex<VecDeque<PendingHttpFault>>,
    observed_routes: Mutex<Vec<HttpCommand>>,
    active_connections: AtomicUsize,
    shutdown: AtomicBool,
    shutdown_notify: tokio::sync::Notify,
    shutdown_deadline: Mutex<Option<tokio::time::Instant>>,
    shutdown_deadline_id: AtomicU64,
}

#[cfg(test)]
impl HttpTestControl {
    fn arm_next(&self, fault: HttpFault) -> Arc<ArmedHttpFault> {
        let armed = Arc::new(ArmedHttpFault {
            consumed: AtomicUsize::new(0),
        });
        self.faults
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push_back(PendingHttpFault {
                fault,
                armed: Arc::clone(&armed),
            });
        armed
    }

    fn take_matching_fault(&self, expected: HttpFault) -> bool {
        let mut faults = self
            .faults
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match faults.front() {
            Some(pending) if pending.fault == expected => {
                if let Some(pending) = faults.pop_front() {
                    pending.armed.mark_consumed();
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn observe_route(&self, command: HttpCommand) {
        self.observed_routes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(command);
    }

    fn increment_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
    }

    fn decrement_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    fn route_observation_count(&self) -> usize {
        self.observed_routes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }

    async fn wait_for_route_after(
        &self,
        expected: crate::metrics::Command,
        after: usize,
        within: std::time::Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        let expected = match expected {
            crate::metrics::Command::Healthz => HttpCommand::Healthz,
            crate::metrics::Command::Readyz => HttpCommand::Readyz,
            crate::metrics::Command::Metrics => HttpCommand::Metrics,
            crate::metrics::Command::Tenants => HttpCommand::Tenants,
            crate::metrics::Command::Decode => HttpCommand::Decode,
            crate::metrics::Command::Unknown => HttpCommand::Unknown,
            _ => HttpCommand::Unknown,
        };
        loop {
            if self
                .observed_routes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .skip(after)
                .copied()
                .any(|observed| observed == expected)
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("HTTP route {expected:?} was not observed before its deadline");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    async fn wait_for_active_connections(
        &self,
        expected: usize,
        within: std::time::Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if self.active_connections.load(Ordering::SeqCst) == expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "HTTP active connections did not reach {expected}; current value is {}",
                    self.active_connections.load(Ordering::SeqCst)
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    pub(crate) fn request_graceful_shutdown_before(&self, deadline: tokio::time::Instant) {
        let deadline = {
            let mut slot = self
                .shutdown_deadline
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            match *slot {
                Some(current) if current <= deadline => current,
                _ => {
                    *slot = Some(deadline);
                    deadline
                }
            }
        };
        self.shutdown_deadline_id
            .store(instant_id(deadline), Ordering::SeqCst);
        self.shutdown.store(true, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();
    }

    #[cfg(test)]
    fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    async fn wait_for_shutdown(&self) {
        loop {
            let mut notified = Box::pin(self.shutdown_notify.notified());
            notified.as_mut().enable();
            if self.shutdown_requested() {
                return;
            }
            notified.as_mut().await;
        }
    }

    fn shutdown_deadline(&self) -> Option<tokio::time::Instant> {
        *self
            .shutdown_deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn shutdown_deadline_id(&self) -> u64 {
        self.shutdown_deadline_id.load(Ordering::SeqCst)
    }

    async fn wait_for_deadline_update(&self, deadline_id: u64) {
        loop {
            let mut notified = Box::pin(self.shutdown_notify.notified());
            notified.as_mut().enable();
            if self.shutdown_deadline_id() != deadline_id {
                return;
            }
            notified.as_mut().await;
        }
    }
}

#[derive(Debug, Default)]
struct HttpShutdownState {
    shutdown: AtomicBool,
    shutdown_deadline_id: AtomicU64,
    shutdown_deadline: Mutex<Option<tokio::time::Instant>>,
    shutdown_notify: tokio::sync::Notify,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct HttpShutdownHandle {
    inner: Arc<HttpShutdownState>,
}

impl HttpShutdownHandle {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn request_graceful_shutdown_before(&self, deadline: tokio::time::Instant) {
        let deadline = {
            let mut slot = self
                .inner
                .shutdown_deadline
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            match *slot {
                Some(current) if current <= deadline => current,
                _ => {
                    *slot = Some(deadline);
                    deadline
                }
            }
        };
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner
            .shutdown_deadline_id
            .store(instant_id(deadline), Ordering::SeqCst);
        self.inner.shutdown_notify.notify_waiters();
    }

    fn shutdown_requested(&self) -> bool {
        self.inner.shutdown.load(Ordering::SeqCst)
    }

    async fn wait_for_shutdown(&self) {
        loop {
            let mut notified = Box::pin(self.inner.shutdown_notify.notified());
            notified.as_mut().enable();
            if self.shutdown_requested() {
                return;
            }
            notified.as_mut().await;
        }
    }

    fn shutdown_deadline(&self) -> Option<tokio::time::Instant> {
        *self
            .inner
            .shutdown_deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn shutdown_deadline_id(&self) -> u64 {
        self.inner.shutdown_deadline_id.load(Ordering::SeqCst)
    }

    async fn wait_for_deadline_update(&self, deadline_id: u64) {
        loop {
            let mut notified = Box::pin(self.inner.shutdown_notify.notified());
            notified.as_mut().enable();
            if self.shutdown_deadline_id() != deadline_id {
                return;
            }
            notified.as_mut().await;
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
enum HttpCleanupProbe {
    None,
    Shutdown(HttpShutdownHandle),
    Test(Arc<HttpTestControl>),
    Both {
        shutdown: HttpShutdownHandle,
        control: Arc<HttpTestControl>,
    },
}

#[cfg(not(test))]
#[derive(Clone, Debug)]
enum HttpCleanupProbe {
    None,
    Shutdown(HttpShutdownHandle),
}

impl HttpCleanupProbe {
    #[cfg(test)]
    fn new(shutdown: Option<HttpShutdownHandle>, control: Option<Arc<HttpTestControl>>) -> Self {
        match (shutdown, control) {
            (Some(shutdown), Some(control)) => Self::Both { shutdown, control },
            (Some(shutdown), None) => Self::Shutdown(shutdown),
            (None, Some(control)) => Self::Test(control),
            (None, None) => Self::None,
        }
    }

    #[cfg(not(test))]
    fn new(shutdown: Option<HttpShutdownHandle>) -> Self {
        match shutdown {
            Some(shutdown) => Self::Shutdown(shutdown),
            None => Self::None,
        }
    }

    fn request_graceful_shutdown_before(&self, deadline: tokio::time::Instant) {
        match self {
            Self::None => {}
            Self::Shutdown(shutdown) => shutdown.request_graceful_shutdown_before(deadline),
            #[cfg(test)]
            Self::Test(control) => control.request_graceful_shutdown_before(deadline),
            #[cfg(test)]
            Self::Both { shutdown, control } => {
                shutdown.request_graceful_shutdown_before(deadline);
                control.request_graceful_shutdown_before(deadline);
            }
        }
    }

    #[cfg(test)]
    fn shutdown_requested(&self) -> bool {
        match self {
            Self::None => false,
            Self::Shutdown(shutdown) => shutdown.shutdown_requested(),
            #[cfg(test)]
            Self::Test(control) => control.shutdown_requested(),
            #[cfg(test)]
            Self::Both { shutdown, control } => {
                shutdown.shutdown_requested() || control.shutdown_requested()
            }
        }
    }

    async fn wait_for_shutdown(&self) {
        loop {
            match self {
                Self::None => std::future::pending::<()>().await,
                Self::Shutdown(shutdown) => return shutdown.wait_for_shutdown().await,
                #[cfg(test)]
                Self::Test(control) => return control.wait_for_shutdown().await,
                #[cfg(test)]
                Self::Both { shutdown, control } => {
                    let mut shutdown_notified = Box::pin(shutdown.inner.shutdown_notify.notified());
                    let mut control_notified = Box::pin(control.shutdown_notify.notified());
                    shutdown_notified.as_mut().enable();
                    control_notified.as_mut().enable();
                    if self.shutdown_requested() {
                        return;
                    }
                    tokio::select! {
                        _ = shutdown_notified.as_mut() => {}
                        _ = control_notified.as_mut() => {}
                    }
                }
            }
        }
    }

    fn collection_deadline(&self) -> Option<tokio::time::Instant> {
        match self {
            Self::None => None,
            Self::Shutdown(shutdown) => shutdown.shutdown_deadline(),
            #[cfg(test)]
            Self::Test(control) => control.shutdown_deadline(),
            #[cfg(test)]
            Self::Both { shutdown, control } => {
                match (shutdown.shutdown_deadline(), control.shutdown_deadline()) {
                    (Some(left), Some(right)) => Some(std::cmp::min(left, right)),
                    (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
                    (None, None) => None,
                }
            }
        }
    }

    async fn wait_for_deadline_update(&self, deadline_id: u64) {
        loop {
            match self {
                Self::None => std::future::pending::<()>().await,
                Self::Shutdown(shutdown) => {
                    return shutdown.wait_for_deadline_update(deadline_id).await;
                }
                #[cfg(test)]
                Self::Test(control) => {
                    return control.wait_for_deadline_update(deadline_id).await;
                }
                #[cfg(test)]
                Self::Both { shutdown, control } => {
                    let mut shutdown_notified = Box::pin(shutdown.inner.shutdown_notify.notified());
                    let mut control_notified = Box::pin(control.shutdown_notify.notified());
                    shutdown_notified.as_mut().enable();
                    control_notified.as_mut().enable();
                    if self.collection_deadline().map(instant_id).unwrap_or(0) != deadline_id {
                        return;
                    }
                    tokio::select! {
                        _ = shutdown_notified.as_mut() => {}
                        _ = control_notified.as_mut() => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct HttpTestClock {
    now_ms: AtomicU64,
    notify: tokio::sync::Notify,
}

#[cfg(test)]
impl HttpTestClock {
    fn paused() -> Self {
        Self::default()
    }

    fn advance(&self, delta: std::time::Duration) {
        self.now_ms
            .fetch_add(delta.as_millis() as u64, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn sleep(&self, duration: std::time::Duration) {
        let target = self.now_ms.load(Ordering::SeqCst) + duration.as_millis() as u64;
        loop {
            let mut notified = Box::pin(self.notify.notified());
            notified.as_mut().enable();
            if self.now_ms.load(Ordering::SeqCst) >= target {
                return;
            }
            notified.as_mut().await;
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ConnectionReport {
    command: Arc<AtomicUsize>,
}

impl ConnectionReport {
    fn set_command(&self, command: HttpCommand) {
        let code = match command {
            HttpCommand::Unknown => 0,
            HttpCommand::Healthz => 1,
            HttpCommand::Readyz => 2,
            HttpCommand::Metrics => 3,
            HttpCommand::Tenants => 4,
            HttpCommand::Decode => 5,
        };
        self.command.store(code, Ordering::SeqCst);
    }

    fn command(&self) -> HttpCommand {
        match self.command.load(Ordering::SeqCst) {
            1 => HttpCommand::Healthz,
            2 => HttpCommand::Readyz,
            3 => HttpCommand::Metrics,
            4 => HttpCommand::Tenants,
            5 => HttpCommand::Decode,
            _ => HttpCommand::Unknown,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct HttpListenerExitReport {
    connection_children_spawned: usize,
    connection_children_finished: usize,
    connection_child_results_collected: usize,
    connection_child_panics: usize,
    collection_deadline_id: u64,
}

impl HttpListenerExitReport {
    pub(crate) fn assert_quiescent_at_return(&self) -> anyhow::Result<()> {
        if self.active_connection_children() != 0 {
            anyhow::bail!("HTTP listener returned while connection children were still active");
        }
        if self.connection_children_spawned != self.connection_children_finished {
            anyhow::bail!("HTTP listener returned before every connection child finished");
        }
        if self.connection_child_results_collected != self.connection_children_finished {
            anyhow::bail!("HTTP listener returned before collecting every child result");
        }
        Ok(())
    }

    pub(crate) fn active_connection_children(&self) -> usize {
        self.connection_children_spawned
            .saturating_sub(self.connection_children_finished)
    }

    #[cfg(test)]
    pub(crate) fn connection_children_spawned(&self) -> usize {
        self.connection_children_spawned
    }

    #[cfg(test)]
    pub(crate) fn connection_children_finished(&self) -> usize {
        self.connection_children_finished
    }

    #[cfg(test)]
    pub(crate) fn connection_child_results_collected(&self) -> usize {
        self.connection_child_results_collected
    }

    pub(crate) fn connection_child_panics(&self) -> usize {
        self.connection_child_panics
    }

    #[cfg(test)]
    pub(crate) fn connection_child_events_after_owner_return(&self) -> usize {
        0
    }

    pub(crate) fn collection_deadline_id(&self) -> u64 {
        self.collection_deadline_id
    }
}

#[derive(Debug)]
pub(crate) enum HttpListenerError {
    InvalidConfig(anyhow::Error),
    Listener {
        error: std::io::Error,
        exit: HttpListenerExitReport,
    },
    CleanupDeadlineExceeded(HttpListenerExitReport),
    ConnectionChildCancelled(HttpListenerExitReport),
    ConnectionChildPanic(HttpListenerExitReport),
}

impl HttpListenerError {
    pub(crate) fn exit_report(&self) -> Option<&HttpListenerExitReport> {
        match self {
            Self::InvalidConfig(_) => None,
            Self::Listener { exit, .. }
            | Self::CleanupDeadlineExceeded(exit)
            | Self::ConnectionChildCancelled(exit)
            | Self::ConnectionChildPanic(exit) => Some(exit),
        }
    }
}

impl std::fmt::Display for HttpListenerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(error) => write!(formatter, "{error}"),
            Self::Listener { error, .. } => write!(formatter, "{error}"),
            Self::CleanupDeadlineExceeded(_) => {
                write!(
                    formatter,
                    "HTTP listener cleanup exceeded its absolute deadline"
                )
            }
            Self::ConnectionChildCancelled(_) => {
                write!(formatter, "HTTP connection child was cancelled")
            }
            Self::ConnectionChildPanic(_) => write!(formatter, "HTTP connection child panicked"),
        }
    }
}

impl std::error::Error for HttpListenerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(error) => Some(error.root_cause()),
            Self::Listener { error, .. } => Some(error),
            Self::CleanupDeadlineExceeded(_)
            | Self::ConnectionChildCancelled(_)
            | Self::ConnectionChildPanic(_) => None,
        }
    }
}

#[cfg(test)]
pub(crate) async fn serve_on(
    listener: TcpListener,
    registry: Arc<Registry>,
    ready: ReadyState,
    auth: Option<Arc<AdminAuth>>,
    limits: impl Into<HttpServeOptions>,
) -> Result<HttpListenerExitReport, Box<dyn std::error::Error + Send + Sync>> {
    serve_on_with_options(listener, registry, ready, auth, limits.into())
        .await
        .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })
}

pub(crate) async fn serve_on_with_options(
    listener: TcpListener,
    registry: Arc<Registry>,
    ready: ReadyState,
    auth: Option<Arc<AdminAuth>>,
    options: HttpServeOptions,
) -> Result<HttpListenerExitReport, HttpListenerError> {
    enum PendingOwnerFailure {
        Listener(std::io::Error),
        ConnectionChildCancelled,
        ConnectionChildPanic,
    }

    enum OwnerEvent {
        Shutdown,
        Accepted(Result<(tokio::net::TcpStream, std::net::SocketAddr), std::io::Error>),
        ChildFinished(Result<(), tokio::task::JoinError>),
        ChildSetDrained,
    }

    let limits = options.limits;
    limits
        .validate()
        .map_err(HttpListenerError::InvalidConfig)?;
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let cleanup = {
        #[cfg(test)]
        {
            HttpCleanupProbe::new(
                options.shutdown_handle.clone(),
                options.test_control.clone(),
            )
        }
        #[cfg(not(test))]
        {
            HttpCleanupProbe::new(options.shutdown_handle.clone())
        }
    };
    #[cfg(test)]
    let test_clock = options.test_clock.clone();
    #[cfg(test)]
    let test_control = options.test_control.clone();
    let mut children = tokio::task::JoinSet::new();
    let mut exit = HttpListenerExitReport::default();
    let mut owner_failure = None;
    let mut fallback_collection_deadline = None;
    loop {
        let has_active_children = !children.is_empty();
        let event = if has_active_children {
            tokio::select! {
                _ = cleanup.wait_for_shutdown() => OwnerEvent::Shutdown,
                joined = children.join_next() => match joined {
                    Some(joined) => OwnerEvent::ChildFinished(joined),
                    None => OwnerEvent::ChildSetDrained,
                },
                accepted = listener.accept() => OwnerEvent::Accepted(accepted),
            }
        } else {
            tokio::select! {
                _ = cleanup.wait_for_shutdown() => OwnerEvent::Shutdown,
                accepted = listener.accept() => OwnerEvent::Accepted(accepted),
            }
        };
        let stream = match event {
            OwnerEvent::Shutdown => break,
            OwnerEvent::ChildSetDrained => continue,
            OwnerEvent::ChildFinished(joined) => {
                if let Some(failure) = collect_http_child_result(&mut exit, joined) {
                    if owner_failure.is_none() {
                        owner_failure = Some(match failure {
                            HttpChildFailure::Cancelled => {
                                PendingOwnerFailure::ConnectionChildCancelled
                            }
                            HttpChildFailure::Panic => PendingOwnerFailure::ConnectionChildPanic,
                        });
                        if cleanup.collection_deadline().is_none() {
                            let deadline =
                                tokio::time::Instant::now() + DEFAULT_LISTENER_CLEANUP_TIMEOUT;
                            cleanup.request_graceful_shutdown_before(deadline);
                            if cleanup.collection_deadline().is_none() {
                                fallback_collection_deadline = Some(deadline);
                            }
                        }
                    }
                    break;
                }
                continue;
            }
            OwnerEvent::Accepted(Ok((stream, _))) => stream,
            OwnerEvent::Accepted(Err(error)) => {
                if owner_failure.is_none() {
                    owner_failure = Some(PendingOwnerFailure::Listener(error));
                    if cleanup.collection_deadline().is_none() {
                        let deadline =
                            tokio::time::Instant::now() + DEFAULT_LISTENER_CLEANUP_TIMEOUT;
                        cleanup.request_graceful_shutdown_before(deadline);
                        if cleanup.collection_deadline().is_none() {
                            fallback_collection_deadline = Some(deadline);
                        }
                    }
                }
                break;
            }
        };
        let permit = match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                abort_http_stream(stream);
                let mut outcome = None;
                finish_http_failure(
                    &mut outcome,
                    HttpCommand::Unknown,
                    crate::metrics::Stage::Admission,
                    crate::metrics::Reason::ResourceLimit,
                );
                continue;
            }
        };
        let registry = Arc::clone(&registry);
        let ready = ready.clone();
        let auth = auth.clone();
        #[cfg(test)]
        let control = test_control.clone();
        #[cfg(test)]
        let connection_clock = test_clock.clone();
        children.spawn(async move {
            let report = ConnectionReport::default();
            #[cfg(test)]
            if let Some(control) = &control {
                control.increment_active_connections();
            }
            let result = serve_connection(
                stream,
                &registry,
                &ready,
                auth.as_deref(),
                limits.io_timeout,
                report.clone(),
                #[cfg(test)]
                control.clone(),
                #[cfg(test)]
                connection_clock,
            )
            .await;
            if let Err(error) = result {
                debug!(error = %error, "health connection ended");
            }
            drop(permit);
            #[cfg(test)]
            if let Some(control) = &control {
                control.decrement_active_connections();
            }
        });
        exit.connection_children_spawned += 1;
    }
    let mut cleanup_deadline_exceeded = false;
    let mut deadline_enforced = false;
    while !children.is_empty() {
        let collection_deadline =
            match (cleanup.collection_deadline(), fallback_collection_deadline) {
                (Some(left), Some(right)) => Some(std::cmp::min(left, right)),
                (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
                (None, None) => None,
            };
        exit.collection_deadline_id = collection_deadline.map(instant_id).unwrap_or(0);
        tokio::select! {
            _ = async {
                if let Some(deadline) = collection_deadline {
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline) => {}
                        _ = cleanup.wait_for_deadline_update(exit.collection_deadline_id) => {}
                    }
                } else {
                    std::future::pending::<()>().await;
                }
            }, if !deadline_enforced && collection_deadline.is_some() => {
                if collection_deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                    children.abort_all();
                    deadline_enforced = true;
                    cleanup_deadline_exceeded = true;
                }
            }
            joined = children.join_next(), if !children.is_empty() => {
                if let Some(joined) = joined {
                    if let Some(failure) = collect_http_child_result(&mut exit, joined) {
                        if !deadline_enforced && owner_failure.is_none() {
                            owner_failure = Some(match failure {
                                HttpChildFailure::Cancelled => PendingOwnerFailure::ConnectionChildCancelled,
                                HttpChildFailure::Panic => PendingOwnerFailure::ConnectionChildPanic,
                            });
                            if cleanup.collection_deadline().is_none() && fallback_collection_deadline.is_none() {
                                fallback_collection_deadline = Some(
                                    tokio::time::Instant::now() + DEFAULT_LISTENER_CLEANUP_TIMEOUT,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    exit.collection_deadline_id =
        match (cleanup.collection_deadline(), fallback_collection_deadline) {
            (Some(left), Some(right)) => instant_id(std::cmp::min(left, right)),
            (Some(deadline), None) | (None, Some(deadline)) => instant_id(deadline),
            (None, None) => 0,
        };
    exit.assert_quiescent_at_return()
        .map_err(|_| match owner_failure {
            Some(PendingOwnerFailure::ConnectionChildPanic) => {
                HttpListenerError::ConnectionChildPanic(exit.clone())
            }
            Some(PendingOwnerFailure::ConnectionChildCancelled) => {
                HttpListenerError::ConnectionChildCancelled(exit.clone())
            }
            Some(PendingOwnerFailure::Listener(_)) | None => {
                HttpListenerError::CleanupDeadlineExceeded(exit.clone())
            }
        })?;
    if cleanup_deadline_exceeded {
        return Err(HttpListenerError::CleanupDeadlineExceeded(exit));
    }
    if let Some(failure) = owner_failure {
        return Err(match failure {
            PendingOwnerFailure::Listener(error) => HttpListenerError::Listener { error, exit },
            PendingOwnerFailure::ConnectionChildCancelled => {
                HttpListenerError::ConnectionChildCancelled(exit)
            }
            PendingOwnerFailure::ConnectionChildPanic => {
                HttpListenerError::ConnectionChildPanic(exit)
            }
        });
    }
    Ok(exit)
}

fn instant_id(instant: tokio::time::Instant) -> u64 {
    crate::startup::deadline_id(instant)
}

#[cfg(test)]
async fn handle_health(
    mut stream: tokio::net::TcpStream,
    registry: &Registry,
    ready: &ReadyState,
    auth: Option<&AdminAuth>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut outcome = None;
    handle_health_internal(
        &mut stream,
        registry,
        ready,
        auth,
        ConnectionReport::default(),
        &mut outcome,
        #[cfg(test)]
        None,
    )
    .await
}

// Six shipped parameters, within the limit; the `#[cfg(test)]` probe handles
// push the test build over it. Bundling them would reshape the production
// signature to satisfy a count only the test build reaches.
#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    mut stream: tokio::net::TcpStream,
    registry: &Registry,
    ready: &ReadyState,
    auth: Option<&AdminAuth>,
    io_timeout: std::time::Duration,
    report: ConnectionReport,
    #[cfg(test)] control: Option<Arc<HttpTestControl>>,
    #[cfg(test)] test_clock: Option<Arc<HttpTestClock>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let result = {
        #[cfg(test)]
        {
            let mut outcome = None;
            if let Some(test_clock) = test_clock {
                tokio::select! {
                    result = handle_health_internal(&mut stream, registry, ready, auth, report.clone(), &mut outcome, control.clone()) => result,
                    _ = test_clock.sleep(io_timeout) => {
                        let command = report.command();
                        if !matches!(command, HttpCommand::Unknown) {
                            crate::metrics::record_error("http", HttpCommand::Unknown.label(), "deadline");
                        }
                        finish_http_failure(
                            &mut outcome,
                            command,
                            crate::metrics::Stage::Read,
                            crate::metrics::Reason::Deadline,
                        );
                        Ok(())
                    }
                }
            } else {
                match tokio::time::timeout(
                    io_timeout,
                    handle_health_internal(
                        &mut stream,
                        registry,
                        ready,
                        auth,
                        report.clone(),
                        &mut outcome,
                        control.clone(),
                    ),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        let command = report.command();
                        if !matches!(command, HttpCommand::Unknown) {
                            crate::metrics::record_error(
                                "http",
                                HttpCommand::Unknown.label(),
                                "deadline",
                            );
                        }
                        finish_http_failure(
                            &mut outcome,
                            command,
                            crate::metrics::Stage::Read,
                            crate::metrics::Reason::Deadline,
                        );
                        Ok(())
                    }
                }
            }
        }
        #[cfg(not(test))]
        {
            let mut outcome = None;
            match tokio::time::timeout(
                io_timeout,
                handle_health_internal(
                    &mut stream,
                    registry,
                    ready,
                    auth,
                    report.clone(),
                    &mut outcome,
                    #[cfg(test)]
                    None,
                ),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    let command = report.command();
                    if !matches!(command, HttpCommand::Unknown) {
                        crate::metrics::record_error(
                            "http",
                            HttpCommand::Unknown.label(),
                            "deadline",
                        );
                    }
                    finish_http_failure(
                        &mut outcome,
                        command,
                        crate::metrics::Stage::Read,
                        crate::metrics::Reason::Deadline,
                    );
                    Ok(())
                }
            }
        }
    };
    if result.is_err() {
        abort_http_stream(stream);
    } else {
        close_http_stream(stream);
    }
    result
}

fn abort_http_stream(stream: tokio::net::TcpStream) {
    let _ = stream.set_zero_linger();
}

fn close_http_stream(stream: tokio::net::TcpStream) {
    if let Ok(std_stream) = stream.into_std() {
        let _ = std_stream.shutdown(std::net::Shutdown::Both);
    }
}

async fn handle_health_internal(
    stream: &mut tokio::net::TcpStream,
    registry: &Registry,
    ready: &ReadyState,
    auth: Option<&AdminAuth>,
    report: ConnectionReport,
    outcome: &mut Option<crate::metrics::OutcomeGuard>,
    #[cfg(test)] control: Option<Arc<HttpTestControl>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader).take(MAX_REQUEST_BYTES);

    #[cfg(test)]
    if control
        .as_ref()
        .is_some_and(|control| control.take_matching_fault(HttpFault::ReadIo))
    {
        let buffered = reader.fill_buf().await?;
        let buffered_len = buffered.len();
        reader.consume(buffered_len);
        finish_http_failure(
            outcome,
            HttpCommand::Unknown,
            crate::metrics::Stage::Read,
            crate::metrics::Reason::Io,
        );
        return Err(std::io::Error::other("synthetic read fault").into());
    }

    let mut request_line = String::new();
    let request_line_bytes = reader.read_line(&mut request_line).await?;
    if request_line_bytes == 0 {
        finish_http_failure(
            outcome,
            HttpCommand::Unknown,
            crate::metrics::Stage::Decode,
            crate::metrics::Reason::MalformedFrame,
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "HTTP request line is missing",
        )
        .into());
    }
    if !request_line.ends_with('\n') {
        let terminal = if reader.limit() == 0 {
            HttpTerminalOutcome::RequestLimit
        } else {
            HttpTerminalOutcome::MalformedRequest
        };
        let reason = match terminal {
            HttpTerminalOutcome::RequestLimit => crate::metrics::Reason::ResourceLimit,
            HttpTerminalOutcome::MalformedRequest => crate::metrics::Reason::MalformedFrame,
        };
        finish_http_failure(
            outcome,
            HttpCommand::Unknown,
            crate::metrics::Stage::Decode,
            reason,
        );
        let (kind, message) = if reader.limit() == 0 {
            (
                std::io::ErrorKind::InvalidData,
                "HTTP request headers exceed 8192-byte limit",
            )
        } else {
            (
                std::io::ErrorKind::UnexpectedEof,
                "HTTP request headers ended before blank line",
            )
        };
        return Err(std::io::Error::new(kind, message).into());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next();
    let path = parts.next();
    let version = parts.next();
    if method != Some("GET")
        || path.is_none()
        || version != Some("HTTP/1.1")
        || parts.next().is_some()
    {
        report.set_command(HttpCommand::Decode);
        finish_http_failure(
            outcome,
            HttpCommand::Decode,
            crate::metrics::Stage::Decode,
            crate::metrics::Reason::MalformedFrame,
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP request line is malformed",
        )
        .into());
    }
    let Some(path) = path else {
        finish_http_failure(
            outcome,
            HttpCommand::Decode,
            crate::metrics::Stage::Decode,
            crate::metrics::Reason::MalformedFrame,
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP request line is malformed",
        )
        .into());
    };
    let path = path.to_string();
    let command = HttpCommand::from_path(&path);
    report.set_command(command);
    start_http_outcome(outcome, command);
    #[cfg(test)]
    if let Some(control) = &control {
        control.observe_route(command);
        if control.take_matching_fault(HttpFault::Handler) {
            return write_response(
                &mut writer,
                500,
                "application/json",
                r#"{"error":"internal"}"#.to_string(),
                command,
                HttpResponseOutcome::Failure(
                    crate::metrics::Stage::Handler,
                    crate::metrics::Reason::Internal,
                ),
                outcome,
                Some(control.as_ref()),
            )
            .await;
        }
        if control.take_matching_fault(HttpFault::Encode) {
            return write_response(
                &mut writer,
                500,
                "application/json",
                r#"{"error":"internal"}"#.to_string(),
                command,
                HttpResponseOutcome::Failure(
                    crate::metrics::Stage::Encode,
                    crate::metrics::Reason::Internal,
                ),
                outcome,
                Some(control.as_ref()),
            )
            .await;
        }
    }

    // Drain the rest of the request headers; nothing here reads a body.
    let mut header = String::new();
    let mut bearer = None;
    loop {
        header.clear();
        let header_bytes = reader.read_line(&mut header).await?;
        if header_bytes == 0 || !header.ends_with('\n') {
            let reason = if reader.limit() == 0 {
                crate::metrics::Reason::ResourceLimit
            } else {
                crate::metrics::Reason::MalformedFrame
            };
            if !matches!(command, HttpCommand::Unknown | HttpCommand::Decode) {
                crate::metrics::record_error(
                    "http",
                    HttpCommand::Decode.label(),
                    match reason {
                        crate::metrics::Reason::ResourceLimit => "resource_limit",
                        crate::metrics::Reason::MalformedFrame => "malformed_frame",
                        _ => {
                            unreachable!("HTTP header decode failures map to closed legacy labels")
                        }
                    },
                );
            }
            finish_http_failure(outcome, command, crate::metrics::Stage::Decode, reason);
            let (kind, message) = if reader.limit() == 0 {
                (
                    std::io::ErrorKind::InvalidData,
                    "HTTP request headers exceed 8192-byte limit",
                )
            } else {
                (
                    std::io::ErrorKind::UnexpectedEof,
                    "HTTP request headers ended before blank line",
                )
            };
            return Err(std::io::Error::new(kind, message).into());
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                bearer = value.trim().strip_prefix("Bearer ").map(str::to_string);
            }
        }
    }

    let route = path
        .split_once('?')
        .map_or(path.as_str(), |(route, _)| route);
    let (status, content_type, body, response_outcome): (u16, String, String, HttpResponseOutcome) =
        match route {
            "/healthz" => (
                200,
                "application/json".to_string(),
                r#"{"status":"ok"}"#.to_string(),
                HttpResponseOutcome::Success,
            ),
            "/readyz" => {
                if ready.is_ready() {
                    (
                        200,
                        "application/json".to_string(),
                        r#"{"ready":true}"#.to_string(),
                        HttpResponseOutcome::Success,
                    )
                } else {
                    (
                        503,
                        "application/json".to_string(),
                        r#"{"ready":false}"#.to_string(),
                        HttpResponseOutcome::Failure(
                            crate::metrics::Stage::Handler,
                            crate::metrics::Reason::Unavailable,
                        ),
                    )
                }
            }
            "/tenants" => {
                let Some(auth) = auth.filter(|auth| auth.authenticated(bearer.as_deref())) else {
                    return write_response(
                        &mut writer,
                        401,
                        "application/json",
                        r#"{"error":"unauthorized"}"#.to_string(),
                        command,
                        HttpResponseOutcome::Failure(
                            crate::metrics::Stage::Authorize,
                            crate::metrics::Reason::Unauthorized,
                        ),
                        outcome,
                        #[cfg(test)]
                        control.as_deref(),
                    )
                    .await;
                };
                match tenant_page_parameters(&path).and_then(|(page_size, cursor)| {
                    registry.list_page_where(
                        crate::registry::TenantPageBoundary::Http,
                        page_size,
                        cursor,
                        |tenant| auth.authorize(bearer.as_deref(), Some(tenant)),
                    )
                }) {
                    Ok(page) => match serde_json::to_string(&page.into_http_response()) {
                        Ok(body) => (
                            200,
                            "application/json".to_string(),
                            body,
                            HttpResponseOutcome::Success,
                        ),
                        Err(error) => (
                            500,
                            "application/json".to_string(),
                            format!(r#"{{"error":"tenant page encoding failed: {error}"}}"#),
                            HttpResponseOutcome::Failure(
                                crate::metrics::Stage::Encode,
                                crate::metrics::Reason::Internal,
                            ),
                        ),
                    },
                    Err(error) => {
                        let status = if error.contains("response budget")
                            || error.contains("materialization budget")
                        {
                            507
                        } else {
                            400
                        };
                        (
                            status,
                            "application/json".to_string(),
                            serde_json::json!({ "error": error }).to_string(),
                            if status == 507 {
                                HttpResponseOutcome::Failure(
                                    crate::metrics::Stage::Limit,
                                    crate::metrics::Reason::ResourceLimit,
                                )
                            } else {
                                HttpResponseOutcome::Failure(
                                    crate::metrics::Stage::Handler,
                                    crate::metrics::Reason::InvalidConfig,
                                )
                            },
                        )
                    }
                }
            }
            "/metrics" => {
                use prometheus::Encoder;
                let encoder = prometheus::TextEncoder::new();
                let content_type = encoder.format_type().to_string();
                let metric_families = prometheus::gather();
                let mut buf = Vec::new();
                match encoder.encode(&metric_families, &mut buf) {
                    Ok(()) => (
                        200,
                        content_type,
                        String::from_utf8_lossy(&buf).into_owned(),
                        HttpResponseOutcome::Success,
                    ),
                    Err(e) => (
                        500,
                        "text/plain".to_string(),
                        format!("encode error: {e}"),
                        HttpResponseOutcome::Failure(
                            crate::metrics::Stage::Encode,
                            crate::metrics::Reason::Internal,
                        ),
                    ),
                }
            }
            _ => (
                404,
                "text/plain".to_string(),
                "not found".to_string(),
                HttpResponseOutcome::Failure(
                    crate::metrics::Stage::Route,
                    crate::metrics::Reason::NotFound,
                ),
            ),
        };
    write_response(
        &mut writer,
        status,
        &content_type,
        body,
        command,
        response_outcome,
        outcome,
        #[cfg(test)]
        control.as_deref(),
    )
    .await
}

// Seven shipped parameters, exactly at the limit; the `#[cfg(test)]` control
// handle pushes the test build over it. Same call as `serve_connection`.
#[allow(clippy::too_many_arguments)]
async fn write_response(
    writer: &mut tokio::net::tcp::WriteHalf<'_>,
    status: u16,
    content_type: &str,
    body: String,
    command: HttpCommand,
    response_outcome: HttpResponseOutcome,
    outcome: &mut Option<crate::metrics::OutcomeGuard>,
    #[cfg(test)] control: Option<&HttpTestControl>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // An over-cap body used to close the socket with nothing written, so a
    // Prometheus scrape of an oversized registry saw an empty reply and
    // marked the target down with no status to explain it. Say 507 with a
    // fixed body instead; the failure is still recorded either way.
    let (status, content_type, body, response_outcome) = if body.len() > MAX_RESPONSE_BYTES {
        (
            507u16,
            "text/plain",
            format!("response exceeds the {MAX_RESPONSE_BYTES}-byte limit\n"),
            HttpResponseOutcome::Failure(
                crate::metrics::Stage::Limit,
                crate::metrics::Reason::ResourceLimit,
            ),
        )
    } else {
        (status, content_type, body, response_outcome)
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        reason = status_reason(status),
        len = body.len(),
    );
    #[cfg(test)]
    if let Some(control) = control {
        if control.take_matching_fault(HttpFault::Write) {
            finish_http_failure(
                outcome,
                command,
                crate::metrics::Stage::Write,
                crate::metrics::Reason::Io,
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "synthetic write fault",
            )
            .into());
        }
    }
    if let Err(error) = writer.write_all(response.as_bytes()).await {
        finish_http_failure(
            outcome,
            command,
            crate::metrics::Stage::Write,
            crate::metrics::Reason::Io,
        );
        return Err(error.into());
    }
    #[cfg(test)]
    if let Some(control) = control {
        if control.take_matching_fault(HttpFault::Flush) {
            finish_http_failure(
                outcome,
                command,
                crate::metrics::Stage::Write,
                crate::metrics::Reason::Io,
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "synthetic flush fault",
            )
            .into());
        }
    }
    if let Err(error) = writer.flush().await {
        finish_http_failure(
            outcome,
            command,
            crate::metrics::Stage::Write,
            crate::metrics::Reason::Io,
        );
        return Err(error.into());
    }
    match response_outcome {
        HttpResponseOutcome::Success => {
            let guard = outcome.take().unwrap_or_else(|| {
                crate::metrics::begin_outcome(
                    crate::metrics::Transport::Http,
                    http_metric_command(command),
                )
            });
            guard.success();
        }
        HttpResponseOutcome::Failure(stage, reason) => {
            finish_http_failure(outcome, command, stage, reason);
        }
    }
    Ok(())
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_TEST_HTTP_RESPONSE_BYTES: usize = MAX_RESPONSE_BYTES;

    fn extend_http_capture(response: &mut Vec<u8>, bytes: &[u8]) {
        let next = response
            .len()
            .checked_add(bytes.len())
            .expect("HTTP test response length cannot overflow usize");
        assert!(
            next <= MAX_TEST_HTTP_RESPONSE_BYTES,
            "HTTP test response exceeded its {MAX_TEST_HTTP_RESPONSE_BYTES}-byte capture ceiling"
        );
        response.extend_from_slice(bytes);
    }

    #[test]
    fn ready_state_starts_false_and_flips_once() {
        let ready = ReadyState::new();
        assert!(!ready.is_ready());
        ready.mark_ready();
        assert!(ready.is_ready());
        // Idempotent: marking again does not panic or change the state.
        ready.mark_ready();
        assert!(ready.is_ready());
    }

    #[tokio::test]
    async fn healthz_returns_ok_before_readiness() {
        let registry = Arc::new(Registry::new_empty());
        let ready = ReadyState::new();
        let addr = "127.0.0.1:0";
        let listener = TcpListener::bind(addr).await.unwrap();
        let bound = listener.local_addr().unwrap();
        let registry_task = Arc::clone(&registry);
        let ready_task = ready.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let registry = Arc::clone(&registry_task);
                let ready = ready_task.clone();
                tokio::spawn(async move {
                    let _ = handle_health(stream, &registry, &ready, None).await;
                });
            }
        });

        let response = http_get(bound, "/healthz").await;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains(r#"{"status":"ok"}"#));

        let response = http_get(bound, "/readyz").await;
        assert!(response.starts_with("HTTP/1.1 503"));
    }

    #[tokio::test]
    async fn tenants_requires_a_valid_bearer_token() {
        let registry = Registry::new_empty();
        let ready = ReadyState::new();
        let auth =
            AdminAuth::from_json(br#"{"tokens":[{"token":"secret","tenants":["tenant-a"]}]}"#)
                .unwrap();

        let unauthorized = health_round_trip(&registry, &ready, Some(&auth), None).await;
        assert!(unauthorized.starts_with("HTTP/1.1 401"));

        let authorized = health_round_trip(&registry, &ready, Some(&auth), Some("secret")).await;
        assert!(authorized.starts_with("HTTP/1.1 200"));
        assert!(authorized.ends_with(r#"{"tenants":[]}"#));
    }

    async fn health_parse_result(
        request: Vec<u8>,
    ) -> (Result<(), Box<dyn std::error::Error + Send + Sync>>, String) {
        let registry = Registry::new_empty();
        let ready = ReadyState::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
                let _ = stream.write_all(&request).await;
                let _ = stream.shutdown().await;
                let mut response = Vec::new();
                let mut buffer = [0u8; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(read) => extend_http_capture(&mut response, &buffer[..read]),
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::ConnectionAborted
                                    | std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::NotConnected
                            ) =>
                        {
                            break;
                        }
                        Err(_) => break,
                    }
                }
                String::from_utf8_lossy(&response).into_owned()
            })
            .await
            .expect("direct HTTP parser client has an absolute deadline")
        });

        let (stream, _) = listener.accept().await.unwrap();
        let result = handle_health(stream, &registry, &ready, None).await;
        let response = client.await.unwrap();
        (result, response)
    }

    async fn read_http_connection_to_end(stream: &mut tokio::net::TcpStream) -> String {
        let mut response = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut buffer = [0u8; 1024];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(read) => extend_http_capture(&mut response, &buffer[..read]),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::NotConnected
                        ) =>
                    {
                        break;
                    }
                    Err(error) => panic!("HTTP client read failed: {error}"),
                }
            }
        })
        .await
        .expect("HTTP refusal must close the connection promptly");
        String::from_utf8_lossy(&response).into_owned()
    }

    async fn listener_request(address: std::net::SocketAddr, request: Vec<u8>) -> String {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let _ = stream.write_all(&request).await;
        let _ = stream.shutdown().await;
        read_http_connection_to_end(&mut stream).await
    }

    fn assert_parser_error(
        error: &(dyn std::error::Error + Send + Sync + 'static),
        expected_kind: std::io::ErrorKind,
        expected_message: &str,
    ) {
        let error = error
            .downcast_ref::<std::io::Error>()
            .expect("malformed headers must return an I/O parser error");
        assert_eq!(error.kind(), expected_kind);
        assert_eq!(error.to_string(), expected_message);
    }

    #[tokio::test]
    async fn header_byte_cap_returns_an_exact_parser_error() {
        let request = format!(
            "GET /healthz HTTP/1.1\r\nX-Fill: {}",
            "x".repeat(MAX_REQUEST_BYTES as usize)
        );
        let (result, response) = health_parse_result(request.into_bytes()).await;
        let error = result.expect_err("capped header block must return a parser error");

        assert!(
            response.is_empty(),
            "parser refusal must not return HTTP 200"
        );
        assert_parser_error(
            error.as_ref(),
            std::io::ErrorKind::InvalidData,
            "HTTP request headers exceed 8192-byte limit",
        );
    }

    #[tokio::test]
    async fn truncated_headers_return_an_exact_parser_error() {
        let request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        let (result, response) = health_parse_result(request).await;
        let error = result.expect_err("EOF before the blank header terminator must be refused");

        assert!(
            response.is_empty(),
            "parser refusal must not return HTTP 200"
        );
        assert_parser_error(
            error.as_ref(),
            std::io::ErrorKind::UnexpectedEof,
            "HTTP request headers ended before blank line",
        );
    }

    #[tokio::test]
    async fn http_connection_slot_refusal_records_closed_error_labels() {
        let before = crate::metrics::error_count("http", "unknown", "resource_limit");
        let registry = Arc::new(Registry::new_empty());
        let ready = ReadyState::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_on(
            listener,
            registry,
            ready.clone(),
            None,
            HttpLimits {
                max_connections: 1,
                io_timeout: std::time::Duration::from_secs(60),
            },
        ));

        let mut occupying = tokio::net::TcpStream::connect(address).await.unwrap();
        occupying
            .write_all(b"GET /healthz HTTP/1.1\r\nX-Stall:")
            .await
            .unwrap();
        tokio::task::yield_now().await;
        let refused = listener_request(
            address,
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        )
        .await;
        let after = crate::metrics::error_count("http", "unknown", "resource_limit");

        occupying.write_all(b" value\r\n\r\n").await.unwrap();
        let occupying_response = read_http_connection_to_end(&mut occupying).await;
        server.abort();
        let _ = server.await;

        assert!(
            refused.is_empty(),
            "a saturated listener must drop the socket"
        );
        assert!(occupying_response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            after - before,
            1,
            "HTTP slot saturation must increment http/unknown/resource_limit"
        );
    }

    async fn listener_refusal_metric_delta(
        request: Vec<u8>,
        command: &str,
        reason: &str,
    ) -> (String, u64) {
        let before = crate::metrics::error_count("http", command, reason);
        let registry = Arc::new(Registry::new_empty());
        let ready = ReadyState::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_on(
            listener,
            registry,
            ready,
            None,
            HttpLimits {
                max_connections: 2,
                io_timeout: std::time::Duration::from_secs(1),
            },
        ));

        let response = listener_request(address, request).await;
        let after = crate::metrics::error_count("http", command, reason);
        server.abort();
        let _ = server.await;
        (response, after - before)
    }

    #[tokio::test]
    async fn http_header_cap_refusal_records_closed_error_labels() {
        let capped = format!(
            "GET /healthz HTTP/1.1\r\nX-Fill: {}",
            "x".repeat(MAX_REQUEST_BYTES as usize)
        );
        let (response, delta) =
            listener_refusal_metric_delta(capped.into_bytes(), "decode", "resource_limit").await;

        assert!(response.is_empty());
        assert_eq!(
            delta, 1,
            "header-cap refusals must increment http/decode/resource_limit"
        );
    }

    #[tokio::test]
    async fn http_truncated_header_refusal_records_closed_error_labels() {
        let (response, delta) = listener_refusal_metric_delta(
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n".to_vec(),
            "decode",
            "malformed_frame",
        )
        .await;

        assert!(response.is_empty());
        assert_eq!(
            delta, 1,
            "truncated headers must increment http/decode/malformed_frame"
        );
    }

    #[tokio::test]
    async fn serve_on_defensively_rejects_each_http_limit_boundary() {
        let cases = [
            (
                HttpLimits {
                    max_connections: 0,
                    io_timeout: std::time::Duration::from_millis(1),
                },
                "HTTP max_connections must be in 1..=100000",
            ),
            (
                HttpLimits {
                    max_connections: 100_001,
                    io_timeout: std::time::Duration::from_millis(1),
                },
                "HTTP max_connections must be in 1..=100000",
            ),
            (
                HttpLimits {
                    max_connections: 1,
                    io_timeout: std::time::Duration::ZERO,
                },
                "HTTP io_timeout must be in 1..=60000ms",
            ),
            (
                HttpLimits {
                    max_connections: 1,
                    io_timeout: std::time::Duration::from_millis(60_001),
                },
                "HTTP io_timeout must be in 1..=60000ms",
            ),
        ];

        for (limits, expected) in cases {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let _ = started_tx.send(());
                serve_on(
                    listener,
                    Arc::new(Registry::new_empty()),
                    ReadyState::new(),
                    None,
                    limits,
                )
                .await
            });

            tokio::time::timeout(std::time::Duration::from_secs(3), started_rx)
                .await
                .expect("HTTP validation task startup signal has a deadline")
                .unwrap();
            tokio::task::yield_now().await;
            if !server.is_finished() {
                server.abort();
                let _join = tokio::time::timeout(std::time::Duration::from_secs(3), server)
                    .await
                    .expect("invalid HTTP listener task joins after abort");
                panic!("health::serve_on accepted invalid limits: {limits:?}");
            }
            let error = server
                .await
                .unwrap()
                .expect_err("health::serve_on must validate before accept");
            assert_eq!(error.to_string(), expected);
        }
    }

    #[tokio::test]
    async fn slowloris_deadline_releases_http_admission_slot() {
        let before = crate::metrics::error_count("http", "unknown", "deadline");
        let registry = Arc::new(Registry::new_empty());
        let ready = ReadyState::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_on(
            listener,
            registry,
            ready,
            None,
            HttpLimits {
                max_connections: 1,
                io_timeout: std::time::Duration::from_millis(20),
            },
        ));

        let mut slow = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            slow.write_all(b"GET /healthz HTTP/1.1\r\nX-Stall:"),
        )
        .await
        .expect("slow HTTP request prefix write has a deadline")
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut closed = [0u8; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), slow.read(&mut closed))
            .await
            .expect("slow connection must be closed by its deadline");
        match read {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("slow connection remained open after its deadline: {other:?}"),
        }

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            http_get(address, "/healthz"),
        )
        .await
        .expect("released HTTP admission slot must serve the next request");
        assert!(response.starts_with("HTTP/1.1 200"));
        let after = crate::metrics::error_count("http", "unknown", "deadline");
        server.abort();
        let _ = server.await;
        assert_eq!(
            after - before,
            1,
            "HTTP whole-connection expiry must increment http/unknown/deadline"
        );
    }

    #[tokio::test]
    async fn http_terminal_outcome_matrix_is_exhaustive_and_exactly_once() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Reason, Stage, Transport,
        };

        let outcomes = OutcomeProbe::acquire_unique().await;
        let controls = Arc::new(HttpTestControl::default());

        macro_rules! assert_http_case {
            ($name:literal, $expected:expr, $active:expr, $future:expr, $check:expr) => {{
                let before = outcomes.snapshot();
                let response = tokio::time::timeout(std::time::Duration::from_secs(3), $future)
                    .await
                    .unwrap_or_else(|_| panic!("HTTP matrix case timed out: {}", $name));
                ($check)(&response);
                controls
                    .wait_for_active_connections($active, std::time::Duration::from_secs(3))
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "HTTP matrix case {} did not reach {} active connections: {error}",
                            $name, $active
                        )
                    });
                before.assert_exact_terminal_delta($expected, $name);
            }};
            ($name:literal, $expected:expr, $future:expr, $check:expr) => {{
                assert_http_case!($name, $expected, 0usize, $future, $check);
            }};
        }

        // `OutcomeProbe::acquire_unique` serializes the process-global
        // Prometheus families and snapshots every sibling child.  A success
        // assertion therefore requires attempt=1, completion=1, and every
        // error delta=0; a failure requires attempt=1, completion=0, exactly
        // one typed error=1, and every sibling=0.
        let registry = Arc::new(Registry::new_empty());
        let ready = ReadyState::new();
        let auth = Arc::new(
            AdminAuth::from_json(br#"{"tokens":[{"token":"secret","tenants":["tenant-a"]}]}"#)
                .unwrap(),
        );
        let deadline_clock = Arc::new(HttpTestClock::paused());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_on(
            listener,
            registry,
            ready.clone(),
            Some(auth),
            HttpLimits {
                max_connections: 1,
                io_timeout: std::time::Duration::from_millis(150),
            }
            .with_test_clock(Arc::clone(&deadline_clock))
            .with_test_control(Arc::clone(&controls)),
        ));

        assert_http_case!(
            "healthz success",
            OutcomeExpectation::success(Transport::Http, MetricCommand::Healthz),
            listener_request(
                address,
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ),
            |response: &String| assert!(response.starts_with("HTTP/1.1 200"))
        );
        assert_http_case!(
            "readyz unavailable",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Readyz,
                Stage::Handler,
                Reason::Unavailable,
            ),
            listener_request(
                address,
                b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ),
            |response: &String| assert!(response.starts_with("HTTP/1.1 503"))
        );
        ready.mark_ready();
        assert_http_case!(
            "readyz success",
            OutcomeExpectation::success(Transport::Http, MetricCommand::Readyz),
            listener_request(
                address,
                b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ),
            |response: &String| assert!(response.starts_with("HTTP/1.1 200"))
        );
        assert_http_case!(
            "metrics success",
            OutcomeExpectation::success(Transport::Http, MetricCommand::Metrics),
            listener_request(
                address,
                b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ),
            |response: &String| assert!(response.starts_with("HTTP/1.1 200"))
        );
        assert_http_case!(
            "tenants unauthorized",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Tenants,
                Stage::Authorize,
                Reason::Unauthorized,
            ),
            listener_request(
                address,
                b"GET /tenants HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ),
            |response: &String| assert!(response.starts_with("HTTP/1.1 401"))
        );
        assert_http_case!(
            "tenants invalid bearer",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Tenants,
                Stage::Authorize,
                Reason::Unauthorized,
            ),
            listener_request(
                address,
                b"GET /tenants HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong\r\n\r\n"
                    .to_vec(),
            ),
            |response: &String| assert!(response.starts_with("HTTP/1.1 401"))
        );
        assert_http_case!(
            "tenants authorized",
            OutcomeExpectation::success(Transport::Http, MetricCommand::Tenants),
            listener_request(
                address,
                b"GET /tenants HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n"
                    .to_vec(),
            ),
            |response: &String| assert!(response.starts_with("HTTP/1.1 200"))
        );
        assert_http_case!(
            "not found",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Unknown,
                Stage::Route,
                Reason::NotFound,
            ),
            listener_request(
                address,
                b"GET /does-not-exist HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ),
            |response: &String| assert!(response.starts_with("HTTP/1.1 404"))
        );

        assert_http_case!(
            "empty request",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Unknown,
                Stage::Decode,
                Reason::MalformedFrame,
            ),
            listener_request(address, vec![b'x']),
            |response: &String| assert!(response.is_empty())
        );
        assert_http_case!(
            "malformed request line",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Decode,
                Stage::Decode,
                Reason::MalformedFrame,
            ),
            listener_request(address, b"NOPE\r\n\r\n".to_vec()),
            |response: &String| assert!(response.is_empty())
        );
        assert_http_case!(
            "healthz truncated headers retain route attribution",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Healthz,
                Stage::Decode,
                Reason::MalformedFrame,
            ),
            listener_request(
                address,
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n".to_vec(),
            ),
            |response: &String| assert!(response.is_empty())
        );
        assert_http_case!(
            "healthz header cap retains route attribution",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Healthz,
                Stage::Decode,
                Reason::ResourceLimit,
            ),
            listener_request(
                address,
                format!(
                    "GET /healthz HTTP/1.1\r\nX-Fill: {}",
                    "x".repeat(MAX_REQUEST_BYTES as usize)
                )
                .into_bytes(),
            ),
            |response: &String| assert!(response.is_empty())
        );

        let read_fault = controls.arm_next(HttpFault::ReadIo);
        assert_http_case!(
            "read failure",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Unknown,
                Stage::Read,
                Reason::Io,
            ),
            listener_request(address, vec![b'x']),
            |response: &String| assert!(response.is_empty())
        );
        read_fault.assert_consumed_exactly_once();

        let before = outcomes.snapshot();
        let route_watermark = controls.route_observation_count();
        let mut slow = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::TcpStream::connect(address),
        )
        .await
        .expect("slow HTTP connection opens")
        .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            slow.write_all(b"GET /healthz HTTP/1.1\r\nX-Stall:"),
        )
        .await
        .expect("HTTP matrix slow-prefix write has a deadline")
        .unwrap();
        controls
            .wait_for_route_after(
                MetricCommand::Healthz,
                route_watermark,
                std::time::Duration::from_secs(3),
            )
            .await
            .expect("route identity becomes observable before the timeout");
        deadline_clock.advance(std::time::Duration::from_millis(151));
        let slow_response = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            read_http_connection_to_end(&mut slow),
        )
        .await
        .expect("slow HTTP connection reaches its server deadline");
        assert!(slow_response.is_empty());
        before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Healthz,
                Stage::Read,
                Reason::Deadline,
            ),
            "whole-connection deadline after route",
        );

        let encode_fault = controls.arm_next(HttpFault::Encode);
        assert_http_case!(
            "encode failure",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Healthz,
                Stage::Encode,
                Reason::Internal,
            ),
            listener_request(
                address,
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ),
            |response: &String| assert!(response.starts_with("HTTP/1.1 500"))
        );
        encode_fault.assert_consumed_exactly_once();

        let handler_fault = controls.arm_next(HttpFault::Handler);
        assert_http_case!(
            "handler failure",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Healthz,
                Stage::Handler,
                Reason::Internal,
            ),
            listener_request(
                address,
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ),
            |response: &String| assert!(response.starts_with("HTTP/1.1 500"))
        );
        handler_fault.assert_consumed_exactly_once();

        for (name, fault, response_was_written) in [
            ("response write failure", HttpFault::Write, false),
            ("response flush failure", HttpFault::Flush, true),
        ] {
            let armed = controls.arm_next(fault);
            let before = outcomes.snapshot();
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                listener_request(
                    address,
                    b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
                ),
            )
            .await
            .expect("HTTP response fault reaches a bounded terminal state");
            if response_was_written {
                assert!(response.starts_with("HTTP/1.1 200"), "{name}");
            } else {
                assert!(response.is_empty(), "{name}");
            }
            armed.assert_consumed_exactly_once();
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    Transport::Http,
                    MetricCommand::Healthz,
                    Stage::Write,
                    Reason::Io,
                ),
                name,
            );
        }

        let mut occupying = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::TcpStream::connect(address),
        )
        .await
        .expect("slot-holder connects")
        .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            occupying.write_all(b"GET /healthz HTTP/1.1\r\nX-Stall:"),
        )
        .await
        .expect("HTTP slot-holder prefix write has a deadline")
        .unwrap();
        controls
            .wait_for_active_connections(1, std::time::Duration::from_secs(3))
            .await
            .expect("the exact connection permit is held before plus-one");
        assert_http_case!(
            "connection slot full",
            OutcomeExpectation::failure(
                Transport::Http,
                MetricCommand::Unknown,
                Stage::Admission,
                Reason::ResourceLimit,
            ),
            1usize,
            listener_request(
                address,
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ),
            |response: &String| assert!(response.is_empty())
        );
        drop(occupying);
        assert!(
            !server.is_finished(),
            "production HTTP listener exited before explicit cleanup"
        );

        let shutdown_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        controls.request_graceful_shutdown_before(shutdown_deadline);
        let join = tokio::time::timeout_at(shutdown_deadline, server)
            .await
            .expect("production HTTP listener joins before cleanup deadline")
            .expect("production HTTP listener task must not panic");
        let exit = join.expect("production HTTP listener reports clean graceful shutdown");
        exit.assert_quiescent_at_return()
            .expect("HTTP owner cannot return before its connection JoinSet is empty");
        assert_eq!(exit.active_connection_children(), 0);
        assert_eq!(
            exit.connection_children_spawned(),
            exit.connection_children_finished(),
            "every HTTP success/refusal path must join its response child"
        );
        assert_eq!(
            exit.connection_child_results_collected(),
            exit.connection_children_spawned(),
            "HTTP listener shutdown collects and inspects every connection child"
        );
        assert_eq!(exit.connection_child_panics(), 0);
        assert_eq!(
            exit.connection_child_events_after_owner_return(),
            0,
            "a detached HTTP reaper cannot catch up after owner return"
        );
        assert_eq!(
            exit.collection_deadline_id(),
            controls.shutdown_deadline_id()
        );
    }

    async fn health_round_trip(
        registry: &Registry,
        ready: &ReadyState,
        auth: Option<&AdminAuth>,
        token: Option<&str>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = token.map(str::to_string);
        let client = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
                let authorization = token
                    .map(|token| format!("Authorization: Bearer {token}\r\n"))
                    .unwrap_or_default();
                stream
                    .write_all(
                        format!("GET /tenants HTTP/1.1\r\nHost: localhost\r\n{authorization}\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                read_http_connection_to_end(&mut stream).await
            })
            .await
            .expect("direct tenants HTTP client has an absolute deadline")
        });
        let (stream, _) = listener.accept().await.unwrap();
        handle_health(stream, registry, ready, auth).await.unwrap();
        client.await.unwrap()
    }

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
                .await
                .unwrap();
            read_http_connection_to_end(&mut stream).await
        })
        .await
        .expect("HTTP GET helper has an absolute deadline")
    }
}
