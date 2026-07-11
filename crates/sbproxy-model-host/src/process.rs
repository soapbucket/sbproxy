// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Opaque process boundary used by every managed engine driver.

use std::collections::{BTreeMap, VecDeque};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{mpsc, Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{EngineDriverError, EngineFailureReason};

const MAX_STDERR_TAIL_BYTES: usize = 64 * 1024;

/// Process operations available to engine drivers after a typed spawn.
#[async_trait]
pub trait EngineProcess: std::fmt::Debug + Send + Sync {
    /// Operating-system process ID, when the engine is a subprocess.
    fn id(&self) -> Option<u32>;

    /// Whether the engine process has already exited.
    async fn has_exited(&self) -> Result<bool, EngineDriverError>;

    /// Request graceful shutdown, then force termination after `grace`.
    async fn shutdown(&self, grace: Duration) -> Result<(), EngineDriverError>;

    /// Bounded, operator-safe stderr tail captured for diagnostics.
    fn stderr_tail(&self) -> String;
}

/// Exact tokenized command accepted by the managed process boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineCommand {
    /// Executable selected by a managed driver.
    pub executable: PathBuf,
    /// Already-tokenized argument vector. No shell parsing occurs.
    pub arguments: Vec<String>,
    /// Explicit environment overrides.
    pub environment: BTreeMap<String, String>,
    /// Allocated loopback port.
    pub port: u16,
    /// HTTP readiness path.
    pub health_path: String,
    /// Maximum duration to wait for readiness.
    pub ready_timeout: Duration,
    /// Maximum nonempty stderr lines retained in diagnostics.
    pub stderr_tail_lines: usize,
}

/// Side-effecting command executor. Implementations receive tokens, never a shell string.
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Spawn one executable with exact argv and environment overrides.
    async fn spawn(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError>;

    /// Run one fixed command to completion with bounded output and timeout.
    async fn output(
        &self,
        _executable: &Path,
        _arguments: &[String],
        _environment: &BTreeMap<String, String>,
        _timeout: Duration,
        _max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        Err(EngineDriverError::blocked(
            "bounded command output is unavailable from this executor",
            "configure a command executor that supports compatibility probes",
        ))
    }
}

/// Bounded output from one fixed, shell-free compatibility command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Whether the process exited successfully.
    pub success: bool,
    /// Redacted and size-bounded standard output.
    pub stdout: String,
    /// Redacted and size-bounded standard error.
    pub stderr: String,
}

/// Readiness probe injected into the process runner for deterministic tests.
#[async_trait]
pub trait EngineReadinessProbe: Send + Sync {
    /// Return whether the loopback health endpoint is ready.
    async fn ready(&self, port: u16, path: &str) -> Result<bool, EngineDriverError>;
}

/// Shared process spawn, early-exit, readiness, and shutdown boundary.
#[derive(Clone)]
pub struct EngineProcessRunner {
    executor: Arc<dyn CommandExecutor>,
    probe: Arc<dyn EngineReadinessProbe>,
    poll_interval: Duration,
}

impl std::fmt::Debug for EngineProcessRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EngineProcessRunner")
            .field("poll_interval", &self.poll_interval)
            .finish_non_exhaustive()
    }
}

impl EngineProcessRunner {
    /// Construct a runner from explicit command and health adapters.
    pub fn new(executor: Arc<dyn CommandExecutor>, probe: Arc<dyn EngineReadinessProbe>) -> Self {
        Self {
            executor,
            probe,
            poll_interval: Duration::from_millis(100),
        }
    }

    /// Override the readiness poll interval.
    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval.max(Duration::from_millis(1));
        self
    }

    /// Spawn one typed command and wait until ready, exited, or timed out.
    pub async fn launch(
        &self,
        command: &EngineCommand,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        validate_command(command)?;
        let process = self
            .executor
            .spawn(
                &command.executable,
                &command.arguments,
                &command.environment,
                command.stderr_tail_lines,
            )
            .await?;
        let deadline = tokio::time::Instant::now() + command.ready_timeout;
        loop {
            if process.has_exited().await? {
                let tail = process.stderr_tail();
                let error = EngineDriverError::new(
                    EngineFailureReason::EngineEarlyExit,
                    format!("engine {:?} exited before readiness", command.executable),
                    "inspect the bounded stderr tail, correct engine compatibility, and retry",
                    true,
                );
                return Err(if tail.is_empty() {
                    error
                } else {
                    error.with_diagnostic_tail(tail)
                });
            }
            if self.probe.ready(command.port, &command.health_path).await? {
                return Ok(process);
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = process.shutdown(Duration::from_secs(1)).await;
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineReadinessTimeout,
                    format!(
                        "engine {:?} was not ready within {:?}",
                        command.executable, command.ready_timeout
                    ),
                    "inspect engine health and resource fit, then increase the typed readiness deadline only if startup is expected to take longer",
                    true,
                ));
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// Perform one readiness probe through the injected health boundary.
    pub async fn ready(&self, port: u16, path: &str) -> Result<bool, EngineDriverError> {
        self.probe.ready(port, path).await
    }

    /// Run one fixed compatibility command through the shared command boundary.
    pub async fn output(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        self.executor
            .output(
                executable,
                arguments,
                environment,
                timeout,
                max_output_bytes,
            )
            .await
    }
}

impl Default for EngineProcessRunner {
    fn default() -> Self {
        Self::new(
            Arc::new(TokioCommandExecutor),
            Arc::new(LoopbackReadinessProbe),
        )
    }
}

fn validate_command(command: &EngineCommand) -> Result<(), EngineDriverError> {
    if command.executable.as_os_str().is_empty() {
        return Err(EngineDriverError::new(
            EngineFailureReason::EngineSpawnFailed,
            "engine executable must not be empty",
            "select a detected or provisioned engine executable",
            false,
        ));
    }
    if command.port == 0 || command.ready_timeout.is_zero() || command.health_path.is_empty() {
        return Err(EngineDriverError::new(
            EngineFailureReason::EngineInternal,
            "engine command has invalid readiness settings",
            "allocate a loopback port, health path, and positive readiness deadline",
            false,
        ));
    }
    if command.stderr_tail_lines == 0 || command.stderr_tail_lines > 100 {
        return Err(EngineDriverError::new(
            EngineFailureReason::EngineInternal,
            "stderr_tail_lines must be between 1 and 100",
            "use a bounded stderr diagnostic tail",
            false,
        ));
    }
    if command
        .arguments
        .iter()
        .any(|argument| argument.contains('\0'))
        || command
            .environment
            .iter()
            .any(|(key, value)| key.is_empty() || key.contains('=') || value.contains('\0'))
    {
        return Err(EngineDriverError::unsafe_argument(
            "command tokens or environment contain invalid bytes",
        ));
    }
    Ok(())
}

/// Tokio subprocess executor used by production engine drivers.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioCommandExecutor;

#[async_trait]
impl CommandExecutor for TokioCommandExecutor {
    async fn spawn(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        let mut child =
            spawn_engine_child(executable, arguments, environment).map_err(|error| {
                EngineDriverError::new(
                    EngineFailureReason::EngineSpawnFailed,
                    format!("spawn engine {:?}: {error}", executable),
                    "run model-host doctor and provision a compatible engine",
                    true,
                )
            })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            EngineDriverError::new(
                EngineFailureReason::EngineSpawnFailed,
                "engine stderr pipe was unavailable after spawn",
                "retry with a process boundary that supports piped diagnostics",
                true,
            )
        })?;
        let stderr_tail = Arc::new(StdMutex::new(BoundedStderrTail::default()));
        let capture = Arc::clone(&stderr_tail);
        let stderr_drain = std::thread::Builder::new()
            .name(format!("sbproxy-engine-stderr-{}", child.id()))
            .spawn(move || {
                let mut stderr = stderr;
                let mut buffer = [0u8; 4096];
                loop {
                    match stderr.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => capture
                            .lock()
                            .expect("engine stderr tail mutex poisoned")
                            .push(&buffer[..count]),
                    }
                }
            });
        let stderr_drain = match stderr_drain {
            Ok(stderr_drain) => stderr_drain,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineSpawnFailed,
                    format!("spawn engine stderr drain: {error}"),
                    "retry after restoring operating-system thread capacity",
                    true,
                ));
            }
        };
        Ok(Arc::new(NativeEngineProcess {
            #[cfg(unix)]
            process_group: child.id(),
            child: StdMutex::new(child),
            stderr_tail,
            stderr_tail_lines,
            stderr_drain: StdMutex::new(Some(stderr_drain)),
        }))
    }

    async fn output(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        if timeout.is_zero() || max_output_bytes == 0 || max_output_bytes > 1024 * 1024 {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "compatibility command bounds are invalid",
                "use a positive timeout and an output limit no larger than 1 MiB",
                false,
            ));
        }
        let mut command = tokio::process::Command::new(executable);
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        apply_engine_environment(command.as_std_mut(), environment);
        let output = tokio::time::timeout(timeout, command.output())
            .await
            .map_err(|_| {
                EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    format!("compatibility command {:?} timed out", executable),
                    "repair the engine environment or select another provisioning mode",
                    false,
                )
            })?
            .map_err(|error| {
                EngineDriverError::new(
                    EngineFailureReason::EngineIncompatible,
                    format!("run compatibility command {:?}: {error}", executable),
                    "install a compatible engine environment and retry doctor",
                    false,
                )
            })?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: bounded_output(&output.stdout, max_output_bytes),
            stderr: bounded_output(&output.stderr, max_output_bytes),
        })
    }
}

struct EngineSpawnRequest {
    executable: PathBuf,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    response: mpsc::SyncSender<Result<std::process::Child, String>>,
}

static ENGINE_SPAWNER: OnceLock<Result<mpsc::Sender<EngineSpawnRequest>, String>> = OnceLock::new();

fn spawn_engine_child(
    executable: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
) -> Result<std::process::Child, String> {
    let spawner = ENGINE_SPAWNER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<EngineSpawnRequest>();
        std::thread::Builder::new()
            .name("sbproxy-engine-spawner".to_string())
            .spawn(move || {
                for request in receiver {
                    let result = spawn_engine_command(
                        &request.executable,
                        &request.arguments,
                        &request.environment,
                    )
                    .map_err(|error| error.to_string());
                    let _ = request.response.send(result);
                }
            })
            .map(|_| sender)
            .map_err(|error| format!("start permanent engine spawner: {error}"))
    });
    let spawner = spawner.as_ref().map_err(Clone::clone)?;
    let (response, result) = mpsc::sync_channel(1);
    spawner
        .send(EngineSpawnRequest {
            executable: executable.to_path_buf(),
            arguments: arguments.to_vec(),
            environment: environment.clone(),
            response,
        })
        .map_err(|_| "permanent engine spawner stopped unexpectedly".to_string())?;
    result
        .recv()
        .map_err(|_| "permanent engine spawner dropped its response".to_string())?
}

fn spawn_engine_command(
    executable: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
) -> std::io::Result<std::process::Child> {
    let mut command = std::process::Command::new(executable);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    apply_engine_environment(&mut command, environment);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt as _;

        // The permanent spawner is the child's parent thread, so this signal
        // tracks gateway-process death instead of a short-lived reconcile runtime.
        // SAFETY: pre_exec performs one async-signal-safe prctl call and
        // returns its OS error without allocating in the child.
        unsafe {
            command.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    command.spawn()
}

fn apply_engine_environment(
    command: &mut std::process::Command,
    overrides: &BTreeMap<String, String>,
) {
    const BASELINE: &[&str] = &[
        "PATH",
        "HOME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "TZ",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "SYSTEMROOT",
        "WINDIR",
    ];
    command.env_clear();
    for key in BASELINE {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.envs(overrides);
}

#[derive(Debug)]
struct NativeEngineProcess {
    #[cfg(unix)]
    process_group: u32,
    child: StdMutex<std::process::Child>,
    stderr_tail: Arc<StdMutex<BoundedStderrTail>>,
    stderr_tail_lines: usize,
    stderr_drain: StdMutex<Option<std::thread::JoinHandle<()>>>,
}

#[derive(Debug, Default)]
struct BoundedStderrTail {
    bytes: VecDeque<u8>,
}

impl BoundedStderrTail {
    fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes.iter().copied());
        while self.bytes.len() > MAX_STDERR_TAIL_BYTES {
            self.bytes.pop_front();
        }
    }

    fn render(&self, lines: usize) -> String {
        let bytes = self.bytes.iter().copied().collect::<Vec<_>>();
        bounded_stderr_tail(&String::from_utf8_lossy(&bytes), lines)
    }
}

impl NativeEngineProcess {
    fn join_finished_stderr_drain(&self) {
        let mut drain = self
            .stderr_drain
            .lock()
            .expect("engine stderr drain mutex poisoned");
        if drain
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
        {
            if let Some(drain) = drain.take() {
                let _ = drain.join();
            }
        }
    }

    fn try_wait(&self) -> Result<bool, EngineDriverError> {
        let exited = self
            .child
            .lock()
            .expect("engine child mutex poisoned")
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|error| {
                EngineDriverError::new(
                    EngineFailureReason::EngineHealthFailed,
                    format!("inspect engine process status: {error}"),
                    "retry the health check or restart the deployment",
                    true,
                )
            })?;
        if exited {
            self.join_finished_stderr_drain();
        }
        Ok(exited)
    }
}

#[async_trait]
impl EngineProcess for NativeEngineProcess {
    fn id(&self) -> Option<u32> {
        self.child.lock().ok().map(|child| child.id())
    }

    async fn has_exited(&self) -> Result<bool, EngineDriverError> {
        self.try_wait()
    }

    async fn shutdown(&self, grace: Duration) -> Result<(), EngineDriverError> {
        if self.try_wait()? {
            return Ok(());
        }
        #[cfg(unix)]
        signal_isolated_process_group(self.process_group, libc::SIGTERM);
        #[cfg(not(unix))]
        self.child
            .lock()
            .expect("engine child mutex poisoned")
            .kill()
            .map_err(shutdown_error)?;

        let deadline = tokio::time::Instant::now() + grace;
        while tokio::time::Instant::now() < deadline {
            if self.try_wait()? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        #[cfg(unix)]
        signal_isolated_process_group(self.process_group, libc::SIGKILL);
        self.child
            .lock()
            .expect("engine child mutex poisoned")
            .kill()
            .map_err(shutdown_error)?;
        let forced_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < forced_deadline {
            if self.try_wait()? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(EngineDriverError::new(
            EngineFailureReason::EngineShutdownFailed,
            "engine process did not exit after forced termination",
            "terminate the isolated engine process group and retry the operation",
            true,
        ))
    }

    fn stderr_tail(&self) -> String {
        self.stderr_tail
            .lock()
            .expect("engine stderr tail mutex poisoned")
            .render(self.stderr_tail_lines)
    }
}

impl Drop for NativeEngineProcess {
    fn drop(&mut self) {
        let drain = self
            .stderr_drain
            .get_mut()
            .expect("engine stderr drain mutex poisoned during drop");
        let child = self
            .child
            .get_mut()
            .expect("engine child mutex poisoned during drop");
        let child_exited = child.try_wait().ok().flatten().is_some();
        let drain_finished = drain
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished);
        if !child_exited || !drain_finished {
            #[cfg(unix)]
            signal_isolated_process_group(self.process_group, libc::SIGKILL);
        }
        if !child_exited {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(drain) = drain.take() {
            let _ = drain.join();
        }
    }
}

fn shutdown_error(error: std::io::Error) -> EngineDriverError {
    EngineDriverError::new(
        EngineFailureReason::EngineShutdownFailed,
        format!("stop engine process: {error}"),
        "stop the deployment again or terminate the isolated engine process group",
        true,
    )
}

/// Production loopback HTTP readiness probe.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoopbackReadinessProbe;

#[async_trait]
impl EngineReadinessProbe for LoopbackReadinessProbe {
    async fn ready(&self, port: u16, path: &str) -> Result<bool, EngineDriverError> {
        let attempt = async {
            let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .ok()?;
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes()).await.ok()?;
            let mut buffer = [0u8; 64];
            let count = stream.read(&mut buffer).await.ok()?;
            let head = String::from_utf8_lossy(&buffer[..count]);
            Some(head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200"))
        };
        Ok(matches!(
            tokio::time::timeout(Duration::from_secs(2), attempt).await,
            Ok(Some(true))
        ))
    }
}

fn bounded_stderr_tail(contents: &str, lines: usize) -> String {
    let retained = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .rev()
        .take(lines)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    redact_engine_output(&retained.chars().take(8_192).collect::<String>())
}

fn redact_engine_output(output: &str) -> String {
    let mut tokens = output.split_whitespace().peekable();
    let mut redacted = Vec::new();
    while let Some(token) = tokens.next() {
        redacted.push(token.to_string());
        if (token.eq_ignore_ascii_case("bearer")
            || matches!(token, "--api-key" | "--token" | "--hf-token"))
            && tokens.next().is_some()
        {
            redacted.push("[REDACTED]".to_string());
        }
    }
    redacted.join(" ")
}

fn bounded_output(output: &[u8], max_output_bytes: usize) -> String {
    let end = output.len().min(max_output_bytes);
    redact_engine_output(&String::from_utf8_lossy(&output[..end]))
}

#[cfg(unix)]
fn signal_isolated_process_group(process_group: u32, signal: i32) {
    let process_group = process_group as libc::pid_t;
    // SAFETY: getpgrp has no preconditions, and kill receives the negative
    // process-group ID created for this managed engine.
    unsafe {
        if process_group > 0 && process_group != libc::getpgrp() {
            let _ = libc::kill(-process_group, signal);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn compatibility_process_receives_only_baseline_and_typed_environment() {
        let _guard = ENV_LOCK.lock().await;
        std::env::set_var("SBPROXY_ENGINE_SECRET_SENTINEL", "must-not-leak");
        let output = TokioCommandExecutor
            .output(
                Path::new("/usr/bin/env"),
                &[],
                &BTreeMap::from([("SBPROXY_TYPED_VISIBLE".to_string(), "yes".to_string())]),
                Duration::from_secs(2),
                64 * 1024,
            )
            .await
            .unwrap();
        std::env::remove_var("SBPROXY_ENGINE_SECRET_SENTINEL");

        assert!(output.stdout.contains("SBPROXY_TYPED_VISIBLE=yes"));
        assert!(!output.stdout.contains("SBPROXY_ENGINE_SECRET_SENTINEL"));
        assert!(!output.stdout.contains("must-not-leak"));
    }

    #[tokio::test]
    async fn engine_stderr_is_retained_only_in_a_bounded_memory_tail() {
        let process = TokioCommandExecutor
            .spawn(
                Path::new("/bin/sh"),
                &[
                    "-c".to_string(),
                    "i=0; while [ $i -lt 12000 ]; do echo noise-$i >&2; i=$((i+1)); done; echo FINAL-MARKER >&2"
                        .to_string(),
                ],
                &BTreeMap::new(),
                20,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !process.has_exited().await.unwrap() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let tail = process.stderr_tail();
        assert!(tail.contains("FINAL-MARKER"));
        assert!(tail.len() <= 8_192);
        assert!(tail.lines().count() <= 20);
    }

    #[test]
    fn engine_stderr_capture_survives_the_launch_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let release = directory.path().join("release");
        let release_arg = release.display().to_string();
        let process = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(TokioCommandExecutor.spawn(
                Path::new("/bin/sh"),
                &[
                    "-c".to_string(),
                    "echo BEFORE-RUNTIME-DROP >&2; while [ ! -f \"$1\" ]; do sleep 0.01; done; echo AFTER-RUNTIME-DROP >&2; sleep 5"
                        .to_string(),
                    "sbproxy-stderr-fixture".to_string(),
                    release_arg,
                ],
                &BTreeMap::new(),
                20,
            ))
        })
        .join()
        .unwrap()
        .unwrap();

        std::fs::write(&release, b"release").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), async {
                while !process.stderr_tail().contains("AFTER-RUNTIME-DROP") {
                    assert!(
                        !process.has_exited().await.unwrap(),
                        "engine exited when its launch runtime dropped"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("stderr emitted after runtime drop must remain readable");
            assert!(!process.has_exited().await.unwrap());
            process.shutdown(Duration::from_millis(100)).await.unwrap();
        });
    }
}
