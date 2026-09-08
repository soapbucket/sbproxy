// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Shell-free process execution and cancellation-safe readiness.

use std::collections::BTreeMap;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::VecDeque;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::CString;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::{Read, Write as _};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd as _;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::FromRawFd as _;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use sb_runtime_core::{EngineDriverError, EngineFailureReason};
use tokio::io::AsyncReadExt as _;

use crate::command::EngineCommand;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use crate::ownership::ProcessOwnershipStore;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::ownership::{
    capture_process_group_leader, owner_still_leads_process_group, process_group_exists,
    signal_group, wait_for_group_exit, ManagedEngineOwner, OpenDirectory, ProcessOwnershipStore,
    StoredOwnership,
};
use crate::probe::EngineReadinessProbe;

const MAX_STDERR_TAIL_BYTES: usize = 64 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const WARM_UP_OUTPUT_LIMIT: usize = 4 * 1024;
const SLOW_WARM_UP: Duration = Duration::from_secs(2);

/// Process operations available after a typed spawn.
#[async_trait]
pub trait EngineProcess: std::fmt::Debug + Send + Sync {
    /// Operating-system process ID, when this is a subprocess.
    fn id(&self) -> Option<u32>;

    /// Return whether the process and its isolated process group have exited.
    async fn has_exited(&self) -> Result<bool, EngineDriverError>;

    /// Request graceful group shutdown, then force termination after `grace`.
    async fn shutdown(&self, grace: Duration) -> Result<(), EngineDriverError>;

    /// Return the bounded, operator-safe stderr tail.
    fn stderr_tail(&self) -> String;
}

/// Bounded output from one fixed tokenized command.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Whether the child exited successfully.
    pub success: bool,
    /// Bounded and redacted standard output.
    pub stdout: String,
    /// Bounded and redacted standard error.
    pub stderr: String,
}

impl std::fmt::Debug for CommandOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandOutput")
            .field("success", &self.success)
            .field("stdout", &redact_output(&self.stdout))
            .field("stderr", &redact_output(&self.stderr))
            .finish()
    }
}

/// Side-effecting executor that accepts exact tokens rather than a shell string.
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Spawn an executable with the exact argv and environment overrides.
    async fn spawn(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError>;

    /// Run a fixed command to completion with bounded output and time.
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
            "configure an executor that supports compatibility probes",
        ))
    }
}

/// Shared spawn, early-exit, readiness, and bounded-command boundary.
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
    /// Construct a runner from explicit process and probe adapters.
    pub fn new(executor: Arc<dyn CommandExecutor>, probe: Arc<dyn EngineReadinessProbe>) -> Self {
        Self {
            executor,
            probe,
            poll_interval: Duration::from_millis(100),
        }
    }

    /// Override the readiness polling interval, clamped to one millisecond.
    #[must_use]
    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval.max(Duration::from_millis(1));
        self
    }

    /// Spawn one typed command and return only after readiness.
    pub async fn launch(
        &self,
        command: &EngineCommand,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        command.validate()?;
        let process = self
            .executor
            .spawn(
                &command.executable,
                &command.arguments,
                &command.environment,
                command.stderr_tail_lines,
            )
            .await?;
        let mut cleanup = LaunchCleanup::new(Arc::clone(&process));
        let deadline = tokio::time::Instant::now() + command.ready_timeout;
        loop {
            if process.has_exited().await? {
                cleanup.disarm();
                let tail = process.stderr_tail();
                let error = EngineDriverError::new(
                    EngineFailureReason::EngineEarlyExit,
                    format!("engine {:?} exited before readiness", command.executable),
                    "inspect the bounded stderr tail, correct compatibility, and retry",
                    true,
                );
                return Err(if tail.is_empty() {
                    error
                } else {
                    error.with_diagnostic_tail(tail)
                });
            }
            if self.probe.ready(command.port, &command.health_path).await? {
                cleanup.disarm();
                return Ok(process);
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = process.shutdown(Duration::from_secs(1)).await;
                cleanup.disarm();
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineReadinessTimeout,
                    format!(
                        "engine {:?} was not ready within {:?}",
                        command.executable, command.ready_timeout
                    ),
                    "inspect engine health and resource fit, then retry with an appropriate deadline",
                    true,
                ));
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// Perform one readiness probe through the injected boundary.
    pub async fn ready(&self, port: u16, path: &str) -> Result<bool, EngineDriverError> {
        self.probe.ready(port, path).await
    }

    /// Run one fixed compatibility command through the shared executor.
    pub async fn output(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        let output = self
            .executor
            .output(
                executable,
                arguments,
                environment,
                timeout,
                max_output_bytes,
            )
            .await?;
        Ok(CommandOutput {
            success: output.success,
            stdout: bounded_redacted_output(&output.stdout, max_output_bytes),
            stderr: bounded_redacted_output(&output.stderr, max_output_bytes),
        })
    }

    /// Pay a fresh executable's first-exec cost before a readiness deadline.
    pub async fn warm_first_exec(
        &self,
        executable: &Path,
        arguments: &[String],
        hang_guard: Duration,
    ) -> Result<(), EngineDriverError> {
        let started = std::time::Instant::now();
        let outcome = self
            .executor
            .output(
                executable,
                arguments,
                &BTreeMap::new(),
                hang_guard,
                WARM_UP_OUTPUT_LIMIT,
            )
            .await;
        let elapsed = started.elapsed();
        if outcome.is_ok() && elapsed >= SLOW_WARM_UP {
            tracing::info!(
                executable = %executable.display(),
                elapsed_secs = elapsed.as_secs_f64(),
                "engine binary first-exec assessment paid before the readiness deadline"
            );
        }
        outcome.map(|_| ())
    }
}

struct LaunchCleanup {
    process: Option<Arc<dyn EngineProcess>>,
}

impl LaunchCleanup {
    fn new(process: Arc<dyn EngineProcess>) -> Self {
        Self {
            process: Some(process),
        }
    }

    fn disarm(&mut self) {
        self.process = None;
    }
}

impl Drop for LaunchCleanup {
    fn drop(&mut self) {
        let Some(process) = self.process.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = process.shutdown(Duration::from_secs(1)).await;
            });
        }
    }
}

/// Native executor with an explicit durable ownership directory.
#[derive(Debug, Clone)]
pub struct TokioCommandExecutor {
    ownership_store: ProcessOwnershipStore,
}

impl TokioCommandExecutor {
    /// Construct a native executor using only the supplied ownership directory.
    pub fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            ownership_store: ProcessOwnershipStore::at(directory),
        }
    }
}

#[async_trait]
impl CommandExecutor for TokioCommandExecutor {
    async fn spawn(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (executable, arguments, environment, stderr_tail_lines);
            return Err(spawn_error(
                "native durable process ownership is unavailable on this platform",
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if executable.as_os_str().is_empty()
                || stderr_tail_lines == 0
                || stderr_tail_lines > 100
            {
                return Err(spawn_error("invalid executable or stderr bound"));
            }
            let directory = self.ownership_store.open_or_create()?;
            let mut child = spawn_gated(&directory, executable, arguments, environment)
                .map_err(|error| spawn_error(error.to_string()))?;
            let process_group = child.id();
            let stderr = child
                .take_stderr()
                .ok_or_else(|| spawn_error("stderr pipe was unavailable"))?;
            let tail = Arc::new(Mutex::new(BoundedTail::default()));
            let capture = Arc::clone(&tail);
            let (stderr_cancel, drain_cancel) =
                UnixStream::pair().map_err(|error| spawn_error(error.to_string()))?;
            drain_cancel
                .set_nonblocking(true)
                .map_err(|error| spawn_error(error.to_string()))?;
            // Read through FIFO EOF before waiting for readiness. In particular,
            // Darwin's FIFO poll need not report a separate event after the last
            // bytes have been consumed. The descriptor is exclusively ours.
            let flags = unsafe { libc::fcntl(stderr.as_raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe {
                    libc::fcntl(stderr.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                } < 0
            {
                return Err(spawn_error(std::io::Error::last_os_error()));
            }
            let drain = std::thread::Builder::new()
                .name(format!("managed-engine-stderr-{}", child.id()))
                .spawn(move || drain_stderr(stderr, capture, drain_cancel))
                .map_err(|error| spawn_error(error.to_string()))?;
            let ownership = self.ownership_store.persist_current_engine_in(
                directory,
                child.id(),
                process_group,
                executable,
            )?;
            if let Err(error) = child.release() {
                let _ = child.kill();
                let _ = child.wait();
                drop(stderr_cancel);
                let _ = drain.join();
                ownership.clear_after_exit()?;
                return Err(spawn_error(format!("release executable gate: {error}")));
            }
            Ok(Arc::new(NativeEngineProcess {
                process_group,
                ownership,
                child: Mutex::new(child),
                stderr_tail: tail,
                stderr_tail_lines,
                stderr_drain: Mutex::new(Some(drain)),
                stderr_cancel: Mutex::new(Some(stderr_cancel)),
            }))
        }
    }

    async fn output(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        if timeout.is_zero() || max_output_bytes == 0 || max_output_bytes > MAX_COMMAND_OUTPUT_BYTES
        {
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
        apply_environment(command.as_std_mut(), environment);
        let mut child = command
            .spawn()
            .map_err(|error| compatibility_error(error.to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| compatibility_error("stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| compatibility_error("stderr unavailable"))?;
        let completed = tokio::time::timeout(timeout, async {
            let (stdout, stderr, status) = tokio::try_join!(
                read_bounded(stdout, max_output_bytes),
                read_bounded(stderr, max_output_bytes),
                child.wait()
            )?;
            Ok::<_, std::io::Error>((stdout, stderr, status))
        })
        .await
        .map_err(|_| compatibility_error("compatibility command timed out"))?
        .map_err(|error| compatibility_error(error.to_string()))?;
        Ok(CommandOutput {
            success: completed.2.success(),
            stdout: redact_output(&String::from_utf8_lossy(&completed.0)),
            stderr: redact_output(&String::from_utf8_lossy(&completed.1)),
        })
    }
}

async fn read_bounded(
    reader: impl tokio::io::AsyncRead + Unpin,
    maximum: usize,
) -> std::io::Result<Vec<u8>> {
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = reader.take(limit);
    let mut bytes = Vec::with_capacity(maximum.min(8 * 1024));
    reader.read_to_end(&mut bytes).await?;
    if bytes.len() > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "command output exceeded its configured bound",
        ));
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct GatedChild {
    pid: libc::pid_t,
    release: Option<std::fs::File>,
    stderr: Option<std::fs::File>,
    status: Option<std::process::ExitStatus>,
    exact_identity: Option<ManagedEngineOwner>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl GatedChild {
    fn id(&self) -> u32 {
        u32::try_from(self.pid).unwrap_or_default()
    }

    fn take_stderr(&mut self) -> Option<std::fs::File> {
        self.stderr.take()
    }

    fn release(&mut self) -> std::io::Result<()> {
        let mut release = self.release.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "release gate unavailable")
        })?;
        release.write_all(b"1\n")?;
        release.flush()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.wait_with_options(libc::WNOHANG)
    }

    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        loop {
            if let Some(status) = self.wait_with_options(0)? {
                return Ok(status);
            }
        }
    }

    fn wait_with_options(
        &mut self,
        options: libc::c_int,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        use std::os::unix::process::ExitStatusExt as _;

        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(self.pid, &mut status, options) };
            if waited == self.pid {
                let status = std::process::ExitStatus::from_raw(status);
                self.status = Some(status);
                return Ok(Some(status));
            }
            if waited == 0 {
                return Ok(None);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                let status = std::process::ExitStatus::from_raw(0);
                self.status = Some(status);
                return Ok(Some(status));
            }
            return Err(error);
        }
    }

    fn kill(&mut self) -> std::io::Result<()> {
        if self.status.is_some() || unsafe { libc::kill(self.pid, libc::SIGKILL) } == 0 {
            return Ok(());
        }
        Err(std::io::Error::last_os_error())
    }

    fn signal_group_if_exact(&self, signal: i32) {
        if self
            .exact_identity
            .as_ref()
            .is_some_and(owner_still_leads_process_group)
        {
            signal_group(self.id(), signal);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for GatedChild {
    fn drop(&mut self) {
        self.release.take();
        if matches!(self.try_wait(), Ok(None)) {
            self.signal_group_if_exact(libc::SIGKILL);
            let _ = self.kill();
            let _ = self.wait();
        }
    }
}

#[cfg(target_os = "linux")]
fn spawn_gated(
    _directory: &OpenDirectory,
    executable: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
) -> std::io::Result<GatedChild> {
    let (gate_read, gate_write) = cloexec_pipe()?;
    let (stderr_read, stderr_write) = match cloexec_pipe() {
        Ok(descriptors) => descriptors,
        Err(error) => {
            unsafe {
                libc::close(gate_read);
                libc::close(gate_write);
            }
            return Err(error);
        }
    };
    let pipes = LinuxChildPipes {
        gate_read,
        gate_write,
        stderr_read,
        stderr_write,
    };
    let executable = CString::new(executable.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "executable contains NUL")
    })?;
    let mut argument_values = vec![executable.clone()];
    for argument in arguments {
        argument_values.push(CString::new(argument.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "argument contains NUL")
        })?);
    }
    let mut argument_pointers = argument_values
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    argument_pointers.push(std::ptr::null_mut());
    let environment_values = unix_environment(environment)?;
    let mut environment_pointers = environment_values
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    environment_pointers.push(std::ptr::null_mut());
    let parent_pid = unsafe { libc::getpid() };
    let mask = ParentSignalMask::block_all()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        close_four(
            pipes.gate_read,
            pipes.gate_write,
            pipes.stderr_read,
            pipes.stderr_write,
        );
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            linux_child(
                parent_pid,
                pipes,
                executable.as_ptr(),
                argument_pointers.as_ptr().cast(),
                environment_pointers.as_ptr().cast(),
            );
        }
    }
    if unsafe { libc::setpgid(pid, pid) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EACCES) {
            close_four(
                pipes.gate_read,
                pipes.gate_write,
                pipes.stderr_read,
                pipes.stderr_write,
            );
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            let _ = mask.restore();
            return Err(error);
        }
    }
    if let Err(error) = mask.restore() {
        close_four(
            pipes.gate_read,
            pipes.gate_write,
            pipes.stderr_read,
            pipes.stderr_write,
        );
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        return Err(error);
    }
    unsafe {
        libc::close(pipes.gate_read);
        libc::close(pipes.stderr_write);
    }
    Ok(GatedChild {
        pid,
        release: Some(unsafe { std::fs::File::from_raw_fd(pipes.gate_write) }),
        stderr: Some(unsafe { std::fs::File::from_raw_fd(pipes.stderr_read) }),
        status: None,
        exact_identity: capture_process_group_leader(u32::try_from(pid).unwrap_or_default()),
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct LinuxChildPipes {
    gate_read: RawFd,
    gate_write: RawFd,
    stderr_read: RawFd,
    stderr_write: RawFd,
}

#[cfg(target_os = "linux")]
fn cloexec_pipe() -> std::io::Result<(RawFd, RawFd)> {
    let mut descriptors = [0; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((descriptors[0], descriptors[1]))
}

#[cfg(target_os = "linux")]
fn close_four(first: RawFd, second: RawFd, third: RawFd, fourth: RawFd) {
    unsafe {
        libc::close(first);
        libc::close(second);
        libc::close(third);
        libc::close(fourth);
    }
}

#[cfg(target_os = "linux")]
struct ParentSignalMask {
    previous: libc::sigset_t,
    restored: bool,
}

#[cfg(target_os = "linux")]
impl ParentSignalMask {
    fn block_all() -> std::io::Result<Self> {
        let mut all = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        if unsafe { libc::sigfillset(&mut all) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let result = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut previous) };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
        Ok(Self {
            previous,
            restored: false,
        })
    }

    fn restore(mut self) -> std::io::Result<()> {
        let result = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut())
        };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
        self.restored = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for ParentSignalMask {
    fn drop(&mut self) {
        if !self.restored {
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
            }
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn linux_child(
    parent_pid: libc::pid_t,
    pipes: LinuxChildPipes,
    executable: *const libc::c_char,
    arguments: *const *const libc::c_char,
    environment: *const *const libc::c_char,
) -> ! {
    if libc::setpgid(0, 0) != 0
        || libc::dup2(pipes.gate_read, libc::STDIN_FILENO) < 0
        || libc::dup2(pipes.stderr_write, libc::STDERR_FILENO) < 0
    {
        libc::_exit(125);
    }
    libc::close(pipes.gate_read);
    libc::close(pipes.gate_write);
    libc::close(pipes.stderr_read);
    libc::close(pipes.stderr_write);
    let null_path = b"/dev/null\0";
    let null_fd = libc::open(null_path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC);
    if null_fd < 0 || libc::dup2(null_fd, libc::STDOUT_FILENO) < 0 {
        libc::_exit(125);
    }
    libc::close(null_fd);
    if reset_linux_child_signals(parent_pid).is_err() || wait_for_release().is_err() {
        libc::_exit(125);
    }
    libc::execvpe(executable, arguments, environment);
    // Preserve the legacy shell-compatible exec diagnostic on the captured
    // stderr pipe without allocating or taking a lock after fork.
    linux_write_all(libc::STDERR_FILENO, b"exec: ");
    linux_write_cstr(libc::STDERR_FILENO, executable);
    linux_write_all(libc::STDERR_FILENO, b": not found\n");
    libc::_exit(127);
}

#[cfg(target_os = "linux")]
unsafe fn linux_write_all(fd: libc::c_int, bytes: &[u8]) {
    let mut offset = 0;
    while offset < bytes.len() {
        let wrote = libc::write(fd, bytes.as_ptr().add(offset).cast(), bytes.len() - offset);
        if wrote <= 0 {
            return;
        }
        offset += wrote as usize;
    }
}

#[cfg(target_os = "linux")]
unsafe fn linux_write_cstr(fd: libc::c_int, value: *const libc::c_char) {
    let mut length = 0;
    while *value.add(length) != 0 {
        length += 1;
    }
    if length > 0 {
        let _ = libc::write(fd, value.cast(), length);
    }
}

#[cfg(target_os = "linux")]
unsafe fn reset_linux_child_signals(parent_pid: libc::pid_t) -> std::io::Result<()> {
    let mut default_action = std::mem::zeroed::<libc::sigaction>();
    default_action.sa_sigaction = libc::SIG_DFL;
    libc::sigemptyset(&mut default_action.sa_mask);
    for signal in 1..=128 {
        if signal != libc::SIGKILL
            && signal != libc::SIGSTOP
            && libc::sigaction(signal, &default_action, std::ptr::null_mut()) != 0
        {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
        }
    }
    if libc::getppid() != parent_pid {
        libc::_exit(125);
    }
    let mut empty = std::mem::zeroed::<libc::sigset_t>();
    if libc::sigemptyset(&mut empty) != 0
        || libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn wait_for_release() -> std::io::Result<()> {
    let mut bytes = [0_u8; 2];
    let mut read = 0;
    while read < bytes.len() {
        let count = libc::read(
            libc::STDIN_FILENO,
            bytes.as_mut_ptr().add(read).cast(),
            bytes.len() - read,
        );
        if count <= 0 {
            return Err(std::io::Error::last_os_error());
        }
        read += usize::try_from(count).unwrap_or_default();
    }
    if bytes != *b"1\n" {
        libc::_exit(125);
    }
    let path = b"/dev/null\0";
    let fd = libc::open(path.as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC);
    if fd < 0 || libc::dup2(fd, libc::STDIN_FILENO) < 0 {
        return Err(std::io::Error::last_os_error());
    }
    libc::close(fd);
    Ok(())
}

#[cfg(target_os = "macos")]
fn spawn_gated(
    directory: &OpenDirectory,
    executable: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
) -> std::io::Result<GatedChild> {
    const GATE: &str = "IFS= read -r release || exit 125\n\
        [ \"$release\" = 1 ] || exit 125\n\
        exec </dev/null\n\
        exec \"$@\"";
    let (release_reader, release_writer) = directory.create_cloexec_fifo_pair("release")?;
    let (stderr_reader, stderr_writer) = directory.create_cloexec_fifo_pair("stderr")?;
    let null = CString::new("/dev/null").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fixed null path is invalid",
        )
    })?;
    let null_fd = unsafe { libc::open(null.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if null_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let null_file = unsafe { std::fs::File::from_raw_fd(null_fd) };
    let mut actions = MacSpawnFileActions::new()?;
    actions.dup2(release_reader.as_raw_fd(), libc::STDIN_FILENO)?;
    actions.dup2(null_file.as_raw_fd(), libc::STDOUT_FILENO)?;
    actions.dup2(stderr_writer.as_raw_fd(), libc::STDERR_FILENO)?;
    actions.close(release_reader.as_raw_fd())?;
    actions.close(null_file.as_raw_fd())?;
    actions.close(stderr_writer.as_raw_fd())?;
    let mut attributes = MacSpawnAttributes::new()?;
    attributes.configure()?;
    let fixed = ["/bin/sh", "-c", GATE, "managed-engine-gate"];
    let mut values = fixed
        .iter()
        .map(|value| CString::new(*value))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    values.push(
        CString::new(executable.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "executable contains NUL")
        })?,
    );
    for argument in arguments {
        values.push(CString::new(argument.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "argument contains NUL")
        })?);
    }
    let mut pointers = values
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    pointers.push(std::ptr::null_mut());
    let environment_values = unix_environment(environment)?;
    let mut environment_pointers = environment_values
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    environment_pointers.push(std::ptr::null_mut());
    let shell = CString::new("/bin/sh")
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut pid = 0;
    let result = unsafe {
        libc::posix_spawn(
            &mut pid,
            shell.as_ptr(),
            &actions.0,
            &attributes.0,
            pointers.as_ptr(),
            environment_pointers.as_ptr(),
        )
    };
    posix_spawn_check(result)?;
    drop(release_reader);
    drop(stderr_writer);
    Ok(GatedChild {
        pid,
        release: Some(release_writer),
        stderr: Some(stderr_reader),
        status: None,
        exact_identity: capture_process_group_leader(u32::try_from(pid).unwrap_or_default()),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unix_environment(environment: &BTreeMap<String, String>) -> std::io::Result<Vec<CString>> {
    let mut values = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    for key in ENVIRONMENT_BASELINE {
        if let Some(value) = std::env::var_os(key) {
            values.insert(
                key.as_bytes().to_vec(),
                value.as_os_str().as_bytes().to_vec(),
            );
        }
    }
    for (key, value) in environment {
        if key.is_empty()
            || key.as_bytes().contains(&0)
            || key.as_bytes().contains(&b'=')
            || value.as_bytes().contains(&0)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "environment contains an invalid key or value",
            ));
        }
        values.insert(key.as_bytes().to_vec(), value.as_bytes().to_vec());
    }
    values
        .into_iter()
        .map(|(mut key, value)| {
            key.push(b'=');
            key.extend(value);
            CString::new(key).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "environment contains NUL")
            })
        })
        .collect()
}

#[cfg(target_os = "macos")]
struct MacSpawnFileActions(libc::posix_spawn_file_actions_t);

#[cfg(target_os = "macos")]
impl MacSpawnFileActions {
    fn new() -> std::io::Result<Self> {
        let mut actions = std::ptr::null_mut();
        posix_spawn_check(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
        Ok(Self(actions))
    }

    fn dup2(&mut self, source: i32, target: i32) -> std::io::Result<()> {
        posix_spawn_check(unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut self.0, source, target)
        })
    }

    fn close(&mut self, descriptor: i32) -> std::io::Result<()> {
        posix_spawn_check(unsafe {
            libc::posix_spawn_file_actions_addclose(&mut self.0, descriptor)
        })
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacSpawnFileActions {
    fn drop(&mut self) {
        unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}

#[cfg(target_os = "macos")]
struct MacSpawnAttributes(libc::posix_spawnattr_t);

#[cfg(target_os = "macos")]
impl MacSpawnAttributes {
    fn new() -> std::io::Result<Self> {
        let mut attributes = std::ptr::null_mut();
        posix_spawn_check(unsafe { libc::posix_spawnattr_init(&mut attributes) })?;
        Ok(Self(attributes))
    }

    fn configure(&mut self) -> std::io::Result<()> {
        let mut defaults = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mut empty = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        if unsafe { libc::sigfillset(&mut defaults) } != 0
            || unsafe { libc::sigdelset(&mut defaults, libc::SIGKILL) } != 0
            || unsafe { libc::sigdelset(&mut defaults, libc::SIGSTOP) } != 0
            || unsafe { libc::sigemptyset(&mut empty) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        posix_spawn_check(unsafe { libc::posix_spawnattr_setsigdefault(&mut self.0, &defaults) })?;
        posix_spawn_check(unsafe { libc::posix_spawnattr_setsigmask(&mut self.0, &empty) })?;
        posix_spawn_check(unsafe { libc::posix_spawnattr_setpgroup(&mut self.0, 0) })?;
        let flags = libc::POSIX_SPAWN_CLOEXEC_DEFAULT
            | libc::POSIX_SPAWN_SETPGROUP
            | libc::POSIX_SPAWN_SETSIGDEF
            | libc::POSIX_SPAWN_SETSIGMASK;
        let flags = libc::c_short::try_from(flags)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        posix_spawn_check(unsafe { libc::posix_spawnattr_setflags(&mut self.0, flags) })
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacSpawnAttributes {
    fn drop(&mut self) {
        unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
    }
}

#[cfg(target_os = "macos")]
fn posix_spawn_check(result: i32) -> std::io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(result))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct NativeEngineProcess {
    process_group: u32,
    ownership: StoredOwnership,
    child: Mutex<GatedChild>,
    stderr_tail: Arc<Mutex<BoundedTail>>,
    stderr_tail_lines: usize,
    stderr_drain: Mutex<Option<std::thread::JoinHandle<()>>>,
    stderr_cancel: Mutex<Option<UnixStream>>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl NativeEngineProcess {
    fn try_wait(&self) -> Result<bool, EngineDriverError> {
        let exited = match self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .try_wait()
        {
            Ok(status) => status.is_some(),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => true,
            Err(error) => return Err(health_error(error.to_string())),
        };
        if exited && !process_group_exists(self.process_group) {
            self.join_stderr();
            self.ownership.clear_after_exit()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn join_stderr(&self) {
        if let Some(mut cancel) = self
            .stderr_cancel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            // The exact group has exited. Wake the reader and ask it to retain
            // already queued diagnostics without waiting for another FIFO event.
            let _ = cancel.write_all(b"1");
        }
        if let Some(drain) = self
            .stderr_drain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = drain.join();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[async_trait]
impl EngineProcess for NativeEngineProcess {
    fn id(&self) -> Option<u32> {
        Some(
            self.child
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .id(),
        )
    }

    async fn has_exited(&self) -> Result<bool, EngineDriverError> {
        self.try_wait()
    }

    async fn shutdown(&self, grace: Duration) -> Result<(), EngineDriverError> {
        if self.try_wait()? {
            return Ok(());
        }
        self.ownership.signal_if_exact(libc::SIGTERM)?;
        if !wait_for_group_exit(self.process_group, grace) {
            self.ownership.signal_if_exact(libc::SIGKILL)?;
            if !wait_for_group_exit(self.process_group, Duration::from_secs(5)) {
                return Err(shutdown_error(
                    "process group remained after forced termination",
                ));
            }
        }
        let _ = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .wait();
        self.join_stderr();
        self.ownership.clear_after_exit()
    }

    fn stderr_tail(&self) -> String {
        self.stderr_tail
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .render(self.stderr_tail_lines)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for NativeEngineProcess {
    fn drop(&mut self) {
        if self.ownership.exact_engine_owns_group() {
            signal_group(self.process_group, libc::SIGKILL);
            let _ = wait_for_group_exit(self.process_group, Duration::from_secs(5));
        }
        let child = self
            .child
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = child.kill();
        let _ = child.wait();
        let _ = self.ownership.clear_after_exit();
        // A descendant can retain stderr after the exact group leader exits.
        // Wake our own reader, without signalling that ambiguous group or
        // leaving a detached drain thread waiting for a possibly permanent EOF.
        // Ordinary shutdown first collects its bounded queued diagnostics.
        self.stderr_cancel
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(drain) = self
            .stderr_drain
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = drain.join();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Default)]
struct BoundedTail {
    bytes: VecDeque<u8>,
    preceding: VecDeque<u8>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl BoundedTail {
    fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes.iter().copied());
        while self.bytes.len() > MAX_STDERR_TAIL_BYTES {
            if let Some(discarded) = self.bytes.pop_front() {
                self.preceding.push_back(discarded);
                while self.preceding.len() > 256 {
                    self.preceding.pop_front();
                }
            }
        }
    }

    fn render(&self, lines: usize) -> String {
        let bytes = self
            .preceding
            .iter()
            .chain(self.bytes.iter())
            .copied()
            .collect::<Vec<_>>();
        let retained = String::from_utf8_lossy(&bytes)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .rev()
            .take(lines)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        let redacted = redact_output(&retained);
        let mut tail = redacted.chars().rev().take(8_192).collect::<Vec<_>>();
        tail.reverse();
        tail.into_iter().collect()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn drain_stderr(
    mut stderr: impl Read + std::os::fd::AsRawFd,
    tail: Arc<Mutex<BoundedTail>>,
    mut cancel: UnixStream,
) {
    let mut buffer = [0_u8; 4_096];
    let mut finishing = false;
    let mut remaining = MAX_STDERR_TAIL_BYTES;
    loop {
        // Only the peer's lifetime is a signal. A one-byte nonblocking read
        // observes EOF even while a noisy descendant keeps stderr readable.
        if !finishing {
            match cancel.read(&mut [0_u8; 1]) {
                Ok(0) => return,
                Ok(_) => finishing = true,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
        let limit = if finishing {
            buffer.len().min(remaining)
        } else {
            buffer.len()
        };
        if limit == 0 {
            return;
        }
        match stderr.read(&mut buffer[..limit]) {
            Ok(0) => return,
            Ok(count) => {
                tail.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(&buffer[..count]);
                if finishing {
                    remaining -= count;
                }
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if finishing {
                    return;
                }
            }
            Err(_) => return,
        }
        let mut descriptors = [
            libc::pollfd {
                fd: stderr.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: cancel.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // Both descriptors remain owned by this thread. Wait only after a read
        // would block; closing the peer wakes poll without periodic polling.
        let ready = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
    }
}

fn bounded_redacted_output(output: &str, maximum: usize) -> String {
    let mut end = output.len().min(maximum);
    while !output.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    redact_output(&output[..end])
}

fn redact_output(output: &str) -> String {
    redact_output_with_pending(output, false)
}

fn redact_output_with_pending(output: &str, mut redact_next: bool) -> String {
    let mut tokens = output.split_whitespace();
    let mut redacted = Vec::new();
    for token in tokens.by_ref() {
        if redact_next {
            redacted.push("[REDACTED]".to_string());
            redact_next = false;
        } else if is_sensitive_marker(token) {
            redacted.push(token.to_string());
            redact_next = true;
        } else if let Some((key, _)) = token
            .split_once('=')
            .filter(|(key, _)| matches!(*key, "--api-key" | "--token" | "--hf-token"))
        {
            redacted.push(format!("{key}=[REDACTED]"));
        } else {
            redacted.push(token.to_string());
        }
    }
    redacted.join(" ")
}

fn is_sensitive_marker(token: &str) -> bool {
    if matches!(token, "--api-key" | "--token" | "--hf-token") {
        return true;
    }
    let split = token.len().saturating_sub("bearer".len());
    token
        .get(split..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case("bearer"))
        && token
            .get(..split)
            .is_some_and(|prefix| matches!(prefix.chars().next_back(), None | Some('"' | '\'')))
}

const ENVIRONMENT_BASELINE: &[&str] = &[
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

fn apply_environment(command: &mut std::process::Command, overrides: &BTreeMap<String, String>) {
    command.env_clear();
    for key in ENVIRONMENT_BASELINE {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.envs(overrides);
}

fn spawn_error(detail: impl std::fmt::Display) -> EngineDriverError {
    EngineDriverError::new(
        EngineFailureReason::EngineSpawnFailed,
        format!("spawn managed engine: {detail}"),
        "provision a compatible executable and retry",
        true,
    )
}

fn compatibility_error(detail: impl std::fmt::Display) -> EngineDriverError {
    EngineDriverError::new(
        EngineFailureReason::EngineIncompatible,
        format!("run bounded compatibility command: {detail}"),
        "repair the engine environment or select another provisioning mode",
        false,
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn health_error(detail: impl std::fmt::Display) -> EngineDriverError {
    EngineDriverError::new(
        EngineFailureReason::EngineHealthFailed,
        format!("inspect managed-engine process status: {detail}"),
        "retry the health check or restart the deployment",
        true,
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn shutdown_error(detail: impl std::fmt::Display) -> EngineDriverError {
    EngineDriverError::new(
        EngineFailureReason::EngineShutdownFailed,
        format!("stop managed-engine process: {detail}"),
        "retry shutdown or terminate the isolated process group",
        true,
    )
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod native_gate_tests {
    use super::*;

    fn gate_directory(root: &tempfile::TempDir) -> Arc<OpenDirectory> {
        ProcessOwnershipStore::at(root.path().join("gate-ownership"))
            .open_or_create()
            .expect("open private gate directory")
    }

    #[test]
    fn startup_control_eof_exits_without_executing_the_engine() {
        let root = tempfile::tempdir().expect("temporary directory");
        let directory = gate_directory(&root);
        let marker = root.path().join("engine-executed");
        let mut child = spawn_gated(
            directory.as_ref(),
            Path::new("/bin/sh"),
            &[
                "-c".to_string(),
                "printf executed > \"$1\"".to_string(),
                "neutral-parent-death-fixture".to_string(),
                marker.display().to_string(),
            ],
            &BTreeMap::new(),
        )
        .expect("prepare managed child");

        child.release.take();
        let status = child.wait().expect("wait after startup-control EOF");

        assert!(!status.success());
        assert!(!marker.exists(), "EOF must exit before engine exec");
    }

    #[test]
    fn unreleased_group_signal_requires_the_captured_start_fingerprint() {
        let root = tempfile::tempdir().expect("temporary directory");
        let directory = gate_directory(&root);
        let mut child = spawn_gated(
            directory.as_ref(),
            Path::new("/bin/sleep"),
            &["30".to_string()],
            &BTreeMap::new(),
        )
        .expect("prepare managed child");
        let mut identity = serde_json::to_value(
            child
                .exact_identity
                .as_ref()
                .expect("capture gated child identity"),
        )
        .expect("serialize identity");
        let fingerprint = identity["start_fingerprint"]
            .as_u64()
            .expect("start fingerprint");
        identity["start_fingerprint"] = serde_json::json!(fingerprint.wrapping_add(1));
        child.exact_identity = Some(serde_json::from_value(identity).expect("changed identity"));

        child.signal_group_if_exact(libc::SIGKILL);
        std::thread::sleep(Duration::from_millis(50));

        assert!(
            child.try_wait().expect("inspect gated child").is_none(),
            "group signalling must fail closed after an identity mismatch"
        );
        child.kill().expect("kill fixture PID");
        child.wait().expect("reap fixture PID");
    }

    #[test]
    fn concurrent_spawn_gates_keep_release_handles_isolated() {
        let root = tempfile::tempdir().expect("temporary directory");
        let directory = gate_directory(&root);
        let mut workers = Vec::new();
        for index in 0..8 {
            let marker = root.path().join(format!("engine-{index}-executed"));
            let directory = Arc::clone(&directory);
            workers.push((
                marker.clone(),
                std::thread::spawn(move || {
                    spawn_gated(
                        directory.as_ref(),
                        Path::new("/bin/sh"),
                        &[
                            "-c".to_string(),
                            "printf executed > \"$1\"".to_string(),
                            format!("neutral-concurrent-gate-{index}"),
                            marker.display().to_string(),
                        ],
                        &BTreeMap::new(),
                    )
                    .expect("spawn isolated startup gate")
                }),
            ));
        }
        let mut children = workers
            .into_iter()
            .map(|(marker, worker)| (marker, worker.join().expect("spawn thread")))
            .collect::<Vec<_>>();
        std::thread::sleep(Duration::from_millis(100));
        assert!(children.iter().all(|(marker, _)| !marker.exists()));

        for (_, child) in &mut children {
            child.release().expect("release exact child gate");
        }
        for (marker, child) in &mut children {
            assert!(child.wait().expect("wait for child").success());
            assert!(marker.exists());
        }
    }

    #[test]
    fn dropping_an_unreleased_gated_child_reaps_its_exact_process() {
        let root = tempfile::tempdir().expect("temporary directory");
        let directory = gate_directory(&root);
        let child = spawn_gated(
            directory.as_ref(),
            Path::new("/bin/sleep"),
            &["30".to_string()],
            &BTreeMap::new(),
        )
        .expect("prepare managed child");
        let pid = child.id();
        let identity = child
            .exact_identity
            .clone()
            .expect("capture gated child identity");

        drop(child);

        assert!(
            crate::capture_managed_engine_owner(pid)
                .as_ref()
                .is_none_or(|actual| !identity.same_process_generation(actual)),
            "unreleased child generation survived gated-child cleanup"
        );
    }
}
