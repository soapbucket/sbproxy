// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! SBproxy compatibility adapters for the neutral managed-process host.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::EngineDriverError;

pub use sb_runtime_host::{
    CommandExecutor, CommandOutput, EngineCommand, EngineProcess, EngineReadinessProbe,
    LoopbackReadinessProbe, ManagedEngineOwner,
};

/// SBproxy's native command executor compatibility adapter.
///
/// The neutral executor requires an explicit ownership directory. This adapter
/// alone resolves the legacy SBproxy environment and platform defaults before
/// delegating process execution.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioCommandExecutor;

impl TokioCommandExecutor {
    fn neutral(self) -> sb_runtime_host::TokioCommandExecutor {
        sb_runtime_host::TokioCommandExecutor::at(production_ownership_directory())
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
        self.neutral()
            .spawn(executable, arguments, environment, stderr_tail_lines)
            .await
    }

    async fn output(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        self.neutral()
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

/// Compatibility wrapper around the neutral spawn/readiness boundary.
#[derive(Clone)]
pub struct EngineProcessRunner {
    inner: sb_runtime_host::EngineProcessRunner,
}

impl std::fmt::Debug for EngineProcessRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl EngineProcessRunner {
    /// Construct a runner from explicit command and health adapters.
    pub fn new(executor: Arc<dyn CommandExecutor>, probe: Arc<dyn EngineReadinessProbe>) -> Self {
        Self {
            inner: sb_runtime_host::EngineProcessRunner::new(executor, probe),
        }
    }

    /// Override the readiness polling interval.
    #[must_use]
    pub fn with_poll_interval(self, poll_interval: Duration) -> Self {
        Self {
            inner: self.inner.with_poll_interval(poll_interval),
        }
    }

    /// Spawn one typed command and return only after readiness.
    pub async fn launch(
        &self,
        command: &EngineCommand,
    ) -> Result<Arc<dyn EngineProcess>, EngineDriverError> {
        self.inner.launch(command).await
    }

    /// Perform one readiness probe through the injected boundary.
    pub async fn ready(&self, port: u16, path: &str) -> Result<bool, EngineDriverError> {
        self.inner.ready(port, path).await
    }

    /// Run one fixed compatibility command through the shared boundary.
    pub async fn output(
        &self,
        executable: &Path,
        arguments: &[String],
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<CommandOutput, EngineDriverError> {
        self.inner
            .output(
                executable,
                arguments,
                environment,
                timeout,
                max_output_bytes,
            )
            .await
    }

    /// Pay a fresh binary's first-exec cost before readiness timing begins.
    pub async fn warm_first_exec(
        &self,
        executable: &Path,
        arguments: &[String],
        hang_guard: Duration,
    ) -> Result<(), EngineDriverError> {
        self.inner
            .warm_first_exec(executable, arguments, hang_guard)
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

/// Reap engines whose durable owner generation is no longer alive.
pub fn reap_stale_managed_engines(grace: Duration) -> Result<usize, EngineDriverError> {
    sb_runtime_host::reap_stale_managed_engines_at(&production_ownership_directory(), grace)
}

/// Capture the exact process generation for a managed-engine owner.
pub fn capture_managed_engine_owner(pid: u32) -> Option<ManagedEngineOwner> {
    sb_runtime_host::capture_managed_engine_owner(pid)
}

/// Reap records for one exact owner from an explicit store.
pub fn reap_managed_engines_owned_by_identity_at(
    directory: &Path,
    owner: &ManagedEngineOwner,
    owner_exit_timeout: Duration,
    engine_grace: Duration,
) -> Result<usize, EngineDriverError> {
    sb_runtime_host::reap_managed_engines_owned_by_identity_at(
        directory,
        owner,
        owner_exit_timeout,
        engine_grace,
    )
}

/// Wait for one recorded owner PID to exit, then reap its exact engines.
pub fn reap_managed_engines_owned_by(
    owner_pid: u32,
    owner_exit_timeout: Duration,
    engine_grace: Duration,
) -> Result<usize, EngineDriverError> {
    sb_runtime_host::reap_managed_engines_owned_by_at(
        &production_ownership_directory(),
        owner_pid,
        owner_exit_timeout,
        engine_grace,
    )
}

fn production_ownership_directory() -> PathBuf {
    if let Some(path) =
        std::env::var_os("SBPROXY_ENGINE_OWNERSHIP_DIR").filter(|path| !path.is_empty())
    {
        return PathBuf::from(path);
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
        return PathBuf::from(home).join("Library/Application Support/sbproxy/managed-engines");
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(state) = std::env::var_os("XDG_STATE_HOME").filter(|state| !state.is_empty()) {
            return PathBuf::from(state).join("sbproxy/managed-engines");
        }
        if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
            return PathBuf::from(home).join(".local/state/sbproxy/managed-engines");
        }
    }
    #[cfg(unix)]
    {
        // SAFETY: geteuid takes no arguments and has no preconditions.
        let uid = unsafe { libc::geteuid() };
        std::env::temp_dir().join(format!("sbproxy-managed-engines-{uid}"))
    }
    #[cfg(not(unix))]
    std::env::temp_dir().join("sbproxy-managed-engines")
}
