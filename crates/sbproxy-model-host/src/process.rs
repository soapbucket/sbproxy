// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Opaque process boundary used by every managed engine driver.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{EngineDriverError, EngineFailureReason};

static LOG_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
        let sequence = LOG_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let stderr_path = std::env::temp_dir().join(format!(
            "sbproxy-engine-{}-{sequence}.log",
            std::process::id()
        ));
        let stderr = std::fs::File::create(&stderr_path).map_err(|error| {
            EngineDriverError::new(
                EngineFailureReason::EngineSpawnFailed,
                format!("create bounded engine stderr log: {error}"),
                "verify the process temporary directory is writable",
                true,
            )
        })?;
        let mut command = tokio::process::Command::new(executable);
        command
            .args(arguments)
            .envs(environment)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        let child = command.spawn().map_err(|error| {
            EngineDriverError::new(
                EngineFailureReason::EngineSpawnFailed,
                format!("spawn engine {:?}: {error}", executable),
                "run model-host doctor and provision a compatible engine",
                true,
            )
        })?;
        Ok(Arc::new(TokioEngineProcess {
            child: tokio::sync::Mutex::new(child),
            stderr_path,
            stderr_tail_lines,
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
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
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

#[derive(Debug)]
struct TokioEngineProcess {
    child: tokio::sync::Mutex<tokio::process::Child>,
    stderr_path: PathBuf,
    stderr_tail_lines: usize,
}

#[async_trait]
impl EngineProcess for TokioEngineProcess {
    fn id(&self) -> Option<u32> {
        self.child.try_lock().ok().and_then(|child| child.id())
    }

    async fn has_exited(&self) -> Result<bool, EngineDriverError> {
        self.child
            .lock()
            .await
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|error| {
                EngineDriverError::new(
                    EngineFailureReason::EngineHealthFailed,
                    format!("inspect engine process status: {error}"),
                    "retry the health check or restart the deployment",
                    true,
                )
            })
    }

    async fn shutdown(&self, grace: Duration) -> Result<(), EngineDriverError> {
        let mut child = self.child.lock().await;
        if child.try_wait().map_err(shutdown_error)?.is_some() {
            return Ok(());
        }
        #[cfg(unix)]
        if let Some(pid) = child.id() {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
        #[cfg(not(unix))]
        child.start_kill().map_err(shutdown_error)?;

        match tokio::time::timeout(grace, child.wait()).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(shutdown_error(error)),
            Err(_) => {
                #[cfg(unix)]
                if let Some(pid) = child.id() {
                    match (pgid_of(pid), pgid_of(std::process::id())) {
                        (Some(child_pgid), Some(our_pgid))
                            if child_pgid == pid && child_pgid != our_pgid =>
                        {
                            let _ = std::process::Command::new("kill")
                                .args(["-KILL", &format!("-{child_pgid}")])
                                .status();
                        }
                        _ => {}
                    }
                }
                child.start_kill().map_err(shutdown_error)?;
                child.wait().await.map_err(shutdown_error)?;
                Ok(())
            }
        }
    }

    fn stderr_tail(&self) -> String {
        std::fs::read_to_string(&self.stderr_path)
            .ok()
            .map(|contents| bounded_stderr_tail(&contents, self.stderr_tail_lines))
            .unwrap_or_default()
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
fn pgid_of(pid: u32) -> Option<u32> {
    let output = std::process::Command::new("ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}
