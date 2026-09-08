// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Tokenized commands and validation for the managed process boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use sb_runtime_core::{EngineDriverError, EngineFailureReason};

/// Exact tokenized command selected by a managed-runtime driver.
///
/// This type performs no shell parsing and confers no artifact or execution
/// authority. The consumer remains responsible for selecting the executable
/// and authorizing each argument and environment override before construction.
#[derive(Clone, PartialEq, Eq)]
pub struct EngineCommand {
    /// Executable selected by the consumer's managed driver.
    pub executable: PathBuf,
    /// Already-tokenized arguments, passed without shell interpretation.
    pub arguments: Vec<String>,
    /// Explicit environment overrides; values are never included in Debug output.
    pub environment: BTreeMap<String, String>,
    /// Allocated loopback serving port.
    pub port: u16,
    /// HTTP readiness path selected by the driver.
    pub health_path: String,
    /// Maximum duration to wait for readiness.
    pub ready_timeout: Duration,
    /// Maximum nonempty stderr lines retained in diagnostics, from 1 through 100.
    pub stderr_tail_lines: usize,
}

impl EngineCommand {
    /// Refuse invalid process/readiness inputs before a command can spawn.
    ///
    /// Preserves refusal order: executable, readiness, diagnostic-tail limit,
    /// then token and environment encoding. Driver-specific argument and trust
    /// validation belongs to the consumer, not this process-neutral envelope.
    pub fn validate(&self) -> Result<(), EngineDriverError> {
        if self.executable.as_os_str().is_empty() {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineSpawnFailed,
                "engine executable must not be empty",
                "select a detected or provisioned engine executable",
                false,
            ));
        }
        if self.port == 0 || self.ready_timeout.is_zero() || self.health_path.is_empty() {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "engine command has invalid readiness settings",
                "allocate a loopback port, health path, and positive readiness deadline",
                false,
            ));
        }
        if self.stderr_tail_lines == 0 || self.stderr_tail_lines > 100 {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "stderr_tail_lines must be between 1 and 100",
                "use a bounded stderr diagnostic tail",
                false,
            ));
        }
        if self
            .arguments
            .iter()
            .any(|argument| argument.contains('\0'))
            || self
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
}

impl fmt::Debug for EngineCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Arguments, environment entries and readiness paths can contain secrets.
        formatter
            .debug_struct("EngineCommand")
            .field("executable", &self.executable)
            .field("argument_count", &self.arguments.len())
            .field("environment_count", &self.environment.len())
            .field("port", &self.port)
            .field("ready_timeout", &self.ready_timeout)
            .field("stderr_tail_lines", &self.stderr_tail_lines)
            .finish_non_exhaustive()
    }
}
