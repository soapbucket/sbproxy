// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Opaque process boundary used by every managed engine driver.

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{mpsc, Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
#[cfg(unix)]
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{EngineDriverError, EngineFailureReason};

const MAX_STDERR_TAIL_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const PROCESS_OWNERSHIP_SCHEMA_VERSION: u32 = 1;

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessIdentity {
    pid: u32,
    start_fingerprint: u64,
    executable: Option<PathBuf>,
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedProcessOwnership {
    schema_version: u32,
    owner: ProcessIdentity,
    engine: ProcessIdentity,
    process_group: u32,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct ProcessOwnershipStore {
    directory: PathBuf,
}

#[cfg(unix)]
impl ProcessOwnershipStore {
    fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn production() -> Self {
        #[cfg(test)]
        {
            return Self::at(std::env::temp_dir().join(format!(
                "sbproxy-managed-engine-tests-{}",
                std::process::id()
            )));
        }
        #[cfg(not(test))]
        if let Some(path) =
            std::env::var_os("SBPROXY_ENGINE_OWNERSHIP_DIR").filter(|path| !path.is_empty())
        {
            return Self::at(path);
        }
        #[cfg(all(not(test), target_os = "macos"))]
        if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
            return Self::at(
                PathBuf::from(home).join("Library/Application Support/sbproxy/managed-engines"),
            );
        }
        #[cfg(all(not(test), target_os = "linux"))]
        {
            if let Some(state) =
                std::env::var_os("XDG_STATE_HOME").filter(|state| !state.is_empty())
            {
                return Self::at(PathBuf::from(state).join("sbproxy/managed-engines"));
            }
            if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
                return Self::at(PathBuf::from(home).join(".local/state/sbproxy/managed-engines"));
            }
        }
        #[cfg(not(test))]
        {
            // A missing home/state environment is unusual for a service, but
            // it must not disable exact ownership. Scope the fallback by
            // effective user so two accounts never share records.
            // SAFETY: geteuid takes no arguments and has no preconditions.
            let uid = unsafe { libc::geteuid() };
            Self::at(std::env::temp_dir().join(format!("sbproxy-managed-engines-{uid}")))
        }
    }

    fn persist(
        &self,
        record: ManagedProcessOwnership,
    ) -> Result<StoredProcessOwnership, EngineDriverError> {
        if record.schema_version != PROCESS_OWNERSHIP_SCHEMA_VERSION
            || record.engine.pid == 0
            || record.process_group != record.engine.pid
        {
            return Err(process_ownership_error(
                "persist managed-engine ownership",
                "record identity or process group is invalid",
            ));
        }
        std::fs::create_dir_all(&self.directory).map_err(|error| {
            process_ownership_error(
                "create managed-engine ownership directory",
                error.to_string(),
            )
        })?;
        let path = self.directory.join(format!(
            "{}-{}.json",
            record.engine.pid, record.engine.start_fingerprint
        ));
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = self.directory.join(format!(
            ".{}-{}-{nonce}.tmp",
            record.engine.pid,
            std::process::id()
        ));
        let bytes = serde_json::to_vec_pretty(&record).map_err(|error| {
            process_ownership_error("encode managed-engine ownership", error.to_string())
        })?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
        let mut file = options.open(&temporary).map_err(|error| {
            process_ownership_error("create managed-engine ownership record", error.to_string())
        })?;
        let write_result = (|| -> std::io::Result<()> {
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            std::fs::rename(&temporary, &path)?;
            sync_directory(&self.directory)?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temporary);
            return Err(process_ownership_error(
                "atomically persist managed-engine ownership",
                error.to_string(),
            ));
        }
        Ok(StoredProcessOwnership { path, record })
    }

    fn record_paths(&self) -> Result<Vec<PathBuf>, EngineDriverError> {
        let entries = match std::fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(process_ownership_error(
                    "read managed-engine ownership directory",
                    error.to_string(),
                ))
            }
        };
        let mut paths = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        paths.sort();
        Ok(paths)
    }

    fn reap_stale(&self, grace: Duration) -> Result<usize, EngineDriverError> {
        let mut reaped = 0;
        for path in self.record_paths()? {
            let record = read_ownership_record(&path)?;
            if process_identity(record.owner.pid)
                .as_ref()
                .is_some_and(|actual| identity_matches(&record.owner, actual))
            {
                continue;
            }
            let Some(actual_engine) = process_identity(record.engine.pid) else {
                clear_ownership_path(&path)?;
                continue;
            };
            if !identity_matches(&record.engine, &actual_engine) {
                // The recorded process is gone and its PID has been reused.
                // Removing this obsolete record is safe; signalling is not.
                clear_ownership_path(&path)?;
                continue;
            }

            signal_isolated_process_group(record.process_group, libc::SIGTERM);
            if !wait_for_identity_change(&record.engine, grace) {
                signal_isolated_process_group(record.process_group, libc::SIGKILL);
                if !wait_for_identity_change(&record.engine, Duration::from_secs(5)) {
                    return Err(process_ownership_error(
                        format!("reap managed engine pid {}", record.engine.pid),
                        "exact process remained alive after SIGKILL",
                    ));
                }
            }
            clear_ownership_path(&path)?;
            reaped += 1;
        }
        Ok(reaped)
    }

    fn reap_owned_by(
        &self,
        owner_pid: u32,
        owner_exit_timeout: Duration,
        engine_grace: Duration,
    ) -> Result<usize, EngineDriverError> {
        let records = self
            .record_paths()?
            .into_iter()
            .map(|path| read_ownership_record(&path))
            .collect::<Result<Vec<_>, _>>()?;
        let owners = records
            .iter()
            .filter(|record| record.owner.pid == owner_pid)
            .map(|record| &record.owner)
            .collect::<Vec<_>>();
        for owner in owners {
            if !wait_for_identity_change(owner, owner_exit_timeout) {
                return Err(process_ownership_error(
                    format!("wait for managed-engine owner pid {owner_pid}"),
                    "owner retained its recorded start fingerprint after service unload",
                ));
            }
        }
        self.reap_stale(engine_grace)
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct StoredProcessOwnership {
    path: PathBuf,
    record: ManagedProcessOwnership,
}

#[cfg(unix)]
impl StoredProcessOwnership {
    fn clear_after_verified_exit(&self) -> Result<(), EngineDriverError> {
        if process_identity(self.record.engine.pid)
            .as_ref()
            .is_some_and(|actual| identity_matches(&self.record.engine, actual))
        {
            return Err(process_ownership_error(
                format!(
                    "clear managed-engine ownership pid {}",
                    self.record.engine.pid
                ),
                "process still has the recorded start fingerprint",
            ));
        }
        clear_ownership_path(&self.path)
    }
}

#[cfg(unix)]
fn identity_matches(expected: &ProcessIdentity, actual: &ProcessIdentity) -> bool {
    expected.pid == actual.pid
        && expected.start_fingerprint == actual.start_fingerprint
        && expected
            .executable
            .as_ref()
            .is_none_or(|executable| actual.executable.as_ref() == Some(executable))
}

#[cfg(unix)]
fn wait_for_identity_change(identity: &ProcessIdentity, duration: Duration) -> bool {
    let deadline = std::time::Instant::now() + duration;
    loop {
        if process_identity(identity.pid)
            .as_ref()
            .is_none_or(|actual| !identity_matches(identity, actual))
        {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn clear_ownership_path(path: &Path) -> Result<(), EngineDriverError> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_directory(parent).map_err(|error| {
                    process_ownership_error(
                        "sync managed-engine ownership directory",
                        error.to_string(),
                    )
                })?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(process_ownership_error(
            format!("remove managed-engine ownership '{}'", path.display()),
            error.to_string(),
        )),
    }
}

#[cfg(unix)]
fn read_ownership_record(path: &Path) -> Result<ManagedProcessOwnership, EngineDriverError> {
    let bytes = std::fs::read(path).map_err(|error| {
        process_ownership_error(
            format!("read managed-engine ownership '{}'", path.display()),
            error.to_string(),
        )
    })?;
    let record: ManagedProcessOwnership = serde_json::from_slice(&bytes).map_err(|error| {
        process_ownership_error(
            format!("parse managed-engine ownership '{}'", path.display()),
            error.to_string(),
        )
    })?;
    if record.schema_version != PROCESS_OWNERSHIP_SCHEMA_VERSION
        || record.engine.pid == 0
        || record.process_group != record.engine.pid
    {
        return Err(process_ownership_error(
            format!("validate managed-engine ownership '{}'", path.display()),
            "unsupported schema or unsafe process group",
        ));
    }
    Ok(record)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(unix)]
fn process_ownership_error(
    action: impl std::fmt::Display,
    detail: impl std::fmt::Display,
) -> EngineDriverError {
    EngineDriverError::new(
        EngineFailureReason::EngineShutdownFailed,
        format!("{action}: {detail}"),
        "inspect the managed-engine ownership directory and retry",
        true,
    )
}

/// Reap only engines whose durable owner identity is no longer alive.
///
/// PID reuse is guarded by the recorded process-start fingerprint; executable
/// identity is retained as audit evidence. This function never scans or
/// signals by process name.
#[cfg(unix)]
pub fn reap_stale_managed_engines(grace: Duration) -> Result<usize, EngineDriverError> {
    ProcessOwnershipStore::production().reap_stale(grace)
}

/// Wait for one exact recorded owner to exit, then reap its exact engines.
#[cfg(unix)]
pub fn reap_managed_engines_owned_by(
    owner_pid: u32,
    owner_exit_timeout: Duration,
    engine_grace: Duration,
) -> Result<usize, EngineDriverError> {
    ProcessOwnershipStore::production().reap_owned_by(owner_pid, owner_exit_timeout, engine_grace)
}

/// Non-Unix engines use their platform process handle and have no process group.
#[cfg(not(unix))]
pub fn reap_stale_managed_engines(_grace: Duration) -> Result<usize, EngineDriverError> {
    Ok(0)
}

#[cfg(not(unix))]
pub fn reap_managed_engines_owned_by(
    _owner_pid: u32,
    _owner_exit_timeout: Duration,
    _engine_grace: Duration,
) -> Result<usize, EngineDriverError> {
    Ok(0)
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> Option<ProcessIdentity> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_name = stat.rsplit_once(") ")?.1;
    let fields = after_name.split_whitespace().collect::<Vec<_>>();
    if fields.first().copied() == Some("Z") {
        return None;
    }
    let start_fingerprint = fields.get(19)?.parse().ok()?;
    Some(ProcessIdentity {
        pid,
        start_fingerprint,
        executable: std::fs::read_link(format!("/proc/{pid}/exe")).ok(),
    })
}

#[cfg(target_os = "macos")]
fn process_identity(pid: u32) -> Option<ProcessIdentity> {
    use std::os::unix::ffi::OsStringExt as _;

    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
    const SZOMB: u32 = 5;

    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [u8; 16],
        pbi_name: [u8; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    #[link(name = "proc")]
    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: i32,
        ) -> i32;
        fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;
    }

    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::zeroed();
    let expected = std::mem::size_of::<ProcBsdInfo>();
    let read = unsafe {
        proc_pidinfo(
            i32::try_from(pid).ok()?,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(expected).ok()?,
        )
    };
    if usize::try_from(read).ok()? != expected {
        return None;
    }
    let info = unsafe { info.assume_init() };
    if info.pbi_status == SZOMB {
        return None;
    }
    let mut path_buffer = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE];
    let path_length = unsafe {
        proc_pidpath(
            i32::try_from(pid).ok()?,
            path_buffer.as_mut_ptr().cast(),
            u32::try_from(path_buffer.len()).ok()?,
        )
    };
    let executable = usize::try_from(path_length)
        .ok()
        .filter(|length| *length > 0 && *length <= path_buffer.len())
        .map(|length| {
            path_buffer.truncate(length);
            PathBuf::from(std::ffi::OsString::from_vec(path_buffer))
        });
    Some(ProcessIdentity {
        pid,
        start_fingerprint: info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec),
        executable,
    })
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn process_identity(_pid: u32) -> Option<ProcessIdentity> {
    None
}

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

impl TokioCommandExecutor {
    #[cfg(unix)]
    async fn spawn_with_store(
        store: &ProcessOwnershipStore,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        stderr_tail_lines: usize,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        Self::spawn_native(store, executable, arguments, environment, stderr_tail_lines).await
    }

    async fn spawn_native(
        #[cfg(unix)] store: &ProcessOwnershipStore,
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
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(EngineDriverError::new(
                    EngineFailureReason::EngineSpawnFailed,
                    "engine stderr pipe was unavailable after spawn",
                    "retry with a process boundary that supports piped diagnostics",
                    true,
                ));
            }
        };
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
        #[cfg(unix)]
        let ownership = {
            let record = process_identity(child.id())
                .zip(process_identity(std::process::id()))
                .map(|(engine, owner)| ManagedProcessOwnership {
                    schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                    owner,
                    process_group: engine.pid,
                    engine,
                })
                .ok_or_else(|| {
                    process_ownership_error(
                        "capture managed-engine ownership",
                        "process identity was unavailable immediately after spawn",
                    )
                })
                .and_then(|record| store.persist(record));
            match record {
                Ok(ownership) => ownership,
                Err(error) => {
                    signal_isolated_process_group(child.id(), libc::SIGKILL);
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stderr_drain.join();
                    return Err(error);
                }
            }
        };
        Ok(Arc::new(NativeEngineProcess {
            #[cfg(unix)]
            process_group: child.id(),
            #[cfg(unix)]
            ownership,
            child: StdMutex::new(child),
            stderr_tail,
            stderr_tail_lines,
            stderr_drain: StdMutex::new(Some(stderr_drain)),
        }))
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
        #[cfg(unix)]
        {
            let store = ProcessOwnershipStore::production();
            store.reap_stale(Duration::from_secs(2))?;
            Self::spawn_with_store(
                &store,
                executable,
                arguments,
                environment,
                stderr_tail_lines,
            )
            .await
        }
        #[cfg(not(unix))]
        {
            Self::spawn_native(executable, arguments, environment, stderr_tail_lines).await
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
    #[cfg(unix)]
    ownership: StoredProcessOwnership,
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
            #[cfg(unix)]
            self.ownership.clear_after_verified_exit()?;
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
        #[cfg(unix)]
        if child.try_wait().ok().flatten().is_some() {
            if let Err(error) = self.ownership.clear_after_verified_exit() {
                tracing::warn!(error = %error, "failed to clear verified managed-engine ownership");
            }
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
    use std::os::unix::process::CommandExt as _;

    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct IsolatedChild(std::process::Child);

    impl IsolatedChild {
        fn sleep() -> Self {
            let mut command = std::process::Command::new("/bin/sleep");
            command.arg("60").process_group(0);
            Self(command.spawn().expect("spawn isolated sleep fixture"))
        }

        fn id(&self) -> u32 {
            self.0.id()
        }

        fn is_running(&mut self) -> bool {
            self.0.try_wait().expect("poll fixture").is_none()
        }
    }

    impl Drop for IsolatedChild {
        fn drop(&mut self) {
            signal_isolated_process_group(self.0.id(), libc::SIGKILL);
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn missing_owner_identity() -> ProcessIdentity {
        ProcessIdentity {
            pid: u32::MAX,
            start_fingerprint: u64::MAX,
            executable: None,
        }
    }

    #[test]
    fn stale_exact_owned_process_is_reaped_without_a_name_sweep() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path());
        let mut engine = IsolatedChild::sleep();
        let engine_identity = process_identity(engine.id()).expect("engine identity");
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: engine_identity,
                process_group: engine.id(),
            })
            .expect("persist stale ownership");

        assert_eq!(
            store
                .reap_stale(Duration::from_millis(100))
                .expect("reap exact stale engine"),
            1
        );
        assert!(!engine.is_running(), "exact stale engine must exit");
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[test]
    fn reused_pid_with_wrong_start_fingerprint_is_never_signalled() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path());
        let mut unrelated = IsolatedChild::sleep();
        let mut mismatched = process_identity(unrelated.id()).expect("unrelated identity");
        mismatched.start_fingerprint = mismatched.start_fingerprint.wrapping_add(1);
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: mismatched,
                process_group: unrelated.id(),
            })
            .expect("persist reused-pid fixture");

        assert_eq!(
            store
                .reap_stale(Duration::from_millis(50))
                .expect("inspect reused pid"),
            0
        );
        assert!(
            unrelated.is_running(),
            "fingerprint mismatch must preserve unrelated process"
        );
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[test]
    fn matching_pid_and_start_with_wrong_executable_is_never_signalled() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path());
        let mut unrelated = IsolatedChild::sleep();
        let mut mismatched = process_identity(unrelated.id()).expect("unrelated identity");
        mismatched.executable = Some(PathBuf::from("/definitely/not/the-running-executable"));
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: missing_owner_identity(),
                engine: mismatched,
                process_group: unrelated.id(),
            })
            .expect("persist executable-mismatch fixture");

        assert_eq!(
            store
                .reap_stale(Duration::from_millis(50))
                .expect("inspect executable mismatch"),
            0
        );
        assert!(
            unrelated.is_running(),
            "executable mismatch must preserve unrelated process"
        );
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[test]
    fn exact_live_owner_prevents_reaping() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path());
        let mut engine = IsolatedChild::sleep();
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: process_identity(std::process::id()).expect("test owner identity"),
                engine: process_identity(engine.id()).expect("engine identity"),
                process_group: engine.id(),
            })
            .expect("persist live ownership");

        assert_eq!(
            store
                .reap_stale(Duration::from_millis(50))
                .expect("inspect live owner"),
            0
        );
        assert!(engine.is_running(), "live owner's engine must be preserved");
        assert_eq!(store.record_paths().unwrap().len(), 1);
    }

    #[test]
    fn killed_owner_allows_exact_engine_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path());
        let mut owner = IsolatedChild::sleep();
        let mut engine = IsolatedChild::sleep();
        let owner_pid = owner.id();
        store
            .persist(ManagedProcessOwnership {
                schema_version: PROCESS_OWNERSHIP_SCHEMA_VERSION,
                owner: process_identity(owner.id()).expect("owner identity"),
                engine: process_identity(engine.id()).expect("engine identity"),
                process_group: engine.id(),
            })
            .expect("persist subprocess ownership");

        owner.0.kill().expect("SIGKILL owner fixture");
        owner.0.wait().expect("reap owner fixture");
        assert_eq!(
            store
                .reap_owned_by(
                    owner_pid,
                    Duration::from_millis(100),
                    Duration::from_millis(100),
                )
                .expect("recover after killed owner"),
            1
        );
        assert!(!engine.is_running(), "killed owner's engine must be reaped");
        assert!(store.record_paths().unwrap().is_empty());
    }

    #[tokio::test]
    async fn verified_normal_shutdown_clears_durable_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProcessOwnershipStore::at(directory.path());
        let process = TokioCommandExecutor::spawn_with_store(
            &store,
            Path::new("/bin/sleep"),
            &["60".to_string()],
            &BTreeMap::new(),
            20,
        )
        .await
        .expect("spawn managed fixture");

        assert_eq!(store.record_paths().unwrap().len(), 1);
        process
            .shutdown(Duration::from_millis(100))
            .await
            .expect("shutdown managed fixture");
        assert!(process.has_exited().await.unwrap());
        assert!(store.record_paths().unwrap().is_empty());
    }

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
