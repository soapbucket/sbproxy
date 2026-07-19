// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Shared typed lifecycle for every managed inference engine.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AcceleratorKind, ArtifactFormat, ChunkedPrefill, EngineKind, EngineProcess, EngineProvisioning,
    FileJobStore, FitPlan, ReadyArtifact, ResolvedArtifact, WorkerProfile,
};

/// Whether an engine can run on the detected worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EngineAvailability {
    /// A compatible engine is installed and ready for use.
    Available,
    /// A compatible, pinned engine can be provisioned automatically.
    Acquirable,
    /// The engine exists but cannot run on this worker or artifact.
    Incompatible,
    /// Host policy prevents otherwise supported provisioning or launch.
    Blocked,
}

/// Stable detection result shared by CLI, admin, and reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EngineDetection {
    /// Managed engine kind.
    pub kind: EngineKind,
    /// Current availability state.
    pub availability: EngineAvailability,
    /// Detected or pinned version, when known.
    pub version: Option<String>,
    /// Concise operator-safe reason.
    pub reason: String,
    /// Action that makes a non-available engine usable.
    pub remediation: Option<String>,
}

/// Static capabilities declared by one engine driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineCapabilities {
    /// Artifact formats the engine can consume.
    pub artifact_formats: Vec<ArtifactFormat>,
    /// Accelerator families supported by this build path.
    pub accelerators: Vec<AcceleratorKind>,
    /// Whether the driver implements isolated container launch.
    pub supports_container: bool,
    /// Whether the driver implements a managed uv environment.
    pub supports_uv: bool,
}

/// Typed provisioning input for one resolved artifact and worker.
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    /// Exact catalog artifact selected for this replica.
    pub artifact: ResolvedArtifact,
    /// Worker compatibility facts.
    pub worker: WorkerProfile,
    /// Operator provisioning policy for the selected engine.
    pub provisioning: EngineProvisioning,
    /// Root for managed engine binaries and environments.
    pub engine_cache_dir: PathBuf,
    /// Optional durable job store for provisioning progress.
    pub job_store: Option<FileJobStore>,
}

/// Immutable engine installation selected by provisioning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedEngine {
    /// Managed engine kind.
    pub kind: EngineKind,
    /// Executable or container-runtime binary invoked by the process boundary.
    pub executable: PathBuf,
    /// Exact engine version, when discoverable.
    pub version: Option<String>,
    /// Stable identity of the verified installation or image.
    pub fingerprint: String,
    /// Provisioning policy that produced this installation.
    pub provisioning: EngineProvisioning,
}

/// Runtime-owned engine tuning knobs sourced from the served-model config
/// and emitted by the driver after the operator allowlist, so operators
/// cannot set them directly (the flags are not on the `extra_args`
/// allowlist). These are vLLM passthroughs today; a non-vLLM driver
/// ignores them and the desired-state validator rejects a non-vLLM model
/// that sets them. `Default` leaves every knob unset.
#[derive(Debug, Clone, Default)]
pub struct EngineTuning {
    /// Chunked prefill: `--enable-chunked-prefill` plus
    /// `--max-num-batched-tokens` from the explicit chunk size or, when
    /// only `target_ttft_ms` is set, from the driver's conservative TTFT
    /// auto-tune (WOR-1678). Neither set leaves the engine default.
    pub chunked_prefill: Option<ChunkedPrefill>,
    /// vLLM auto tool-choice parser: `--enable-auto-tool-choice
    /// --tool-call-parser <name>`.
    pub tool_call_parser: Option<String>,
    /// CPU KV-cache tier in GiB: `--swap-space`.
    pub swap_space_gib: Option<u64>,
    /// Weights kept in CPU RAM in GiB: `--cpu-offload-gb`.
    pub cpu_offload_gib: Option<u64>,
}

/// Typed launch input that can only be constructed from verified local bytes.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    /// Canonical deployment ID.
    pub deployment: String,
    /// Monotonic deployment generation.
    pub generation: u64,
    /// Fully verified local artifact snapshot.
    pub artifact: ReadyArtifact,
    /// Device and memory fit selected for this replica.
    pub fit: FitPlan,
    /// Loopback serving port allocated by the runtime.
    pub port: u16,
    /// Accelerator selected during worker compatibility and fit.
    pub accelerator: AcceleratorKind,
    /// Worker-local device indices assigned to this replica.
    pub selected_devices: Vec<u32>,
    /// Typed KV-cache precision selected for the engine.
    pub kv_quant: crate::KvCacheQuant,
    /// Additional allowlisted engine arguments.
    pub extra_args: Vec<String>,
    /// Runtime-owned engine tuning knobs (chunked prefill, tool-call
    /// parser, CPU KV swap, weight offload) emitted after the operator
    /// allowlist.
    pub engine_tuning: EngineTuning,
    /// Maximum concurrent sequences accounted for by admission and KV memory.
    pub max_concurrency: u32,
    /// The task the served model performs (WOR-1908). Drives the engine's
    /// runtime-owned `--task` flag; defaults to chat.
    pub modality: crate::catalog::Modality,
    /// Maximum wait for the engine's readiness endpoint.
    pub ready_timeout: Duration,
}

/// Live managed engine process and its routing identity.
#[derive(Clone)]
pub struct RunningEngine {
    /// Canonical deployment ID.
    pub deployment: String,
    /// Active deployment generation.
    pub generation: u64,
    /// Managed engine kind.
    pub kind: EngineKind,
    /// Loopback serving port.
    pub port: u16,
    /// Worker-local device indices assigned to the process.
    pub selected_devices: Vec<u32>,
    /// Accelerator used by this process.
    pub accelerator: AcceleratorKind,
    /// Process start time as Unix milliseconds.
    pub started_at_ms: u64,
    /// Canonical digest of the verified artifact snapshot.
    pub artifact_digest: String,
    /// Resolved engine version this process runs, when the provisioner
    /// discovered or pinned one. Answers "what served this request".
    pub engine_version: Option<String>,
    /// Device-specific memory reserved for this generation.
    pub memory: crate::MemoryEstimate,
    /// Opaque process handle owned by the low-level process boundary.
    pub process: Arc<dyn EngineProcess>,
}

impl fmt::Debug for RunningEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunningEngine")
            .field("deployment", &self.deployment)
            .field("generation", &self.generation)
            .field("kind", &self.kind)
            .field("port", &self.port)
            .field("selected_devices", &self.selected_devices)
            .field("accelerator", &self.accelerator)
            .field("started_at_ms", &self.started_at_ms)
            .field("artifact_digest", &self.artifact_digest)
            .field("memory", &self.memory)
            .field("process_id", &self.process.id())
            .finish()
    }
}

/// Current health of a launched engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EngineHealth {
    /// Process is alive but its readiness endpoint is not ready yet.
    Starting,
    /// Process is alive and its readiness endpoint is healthy.
    Ready,
    /// Process is alive but its health endpoint reports an error.
    Unhealthy,
    /// Process has exited.
    Stopped,
}

/// Stable engine failure taxonomy exposed by jobs and status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EngineFailureReason {
    /// Host policy blocks the requested action.
    EngineBlocked,
    /// Engine, artifact, or worker capabilities are incompatible.
    EngineIncompatible,
    /// Engine provisioning failed.
    EngineProvisionFailed,
    /// The local artifact is missing or not verified.
    ArtifactNotReady,
    /// An operator argument attempts to override a runtime-owned field.
    UnsafeArgument,
    /// The process could not be spawned.
    EngineSpawnFailed,
    /// The process exited before becoming ready.
    EngineEarlyExit,
    /// The readiness deadline elapsed.
    EngineReadinessTimeout,
    /// A live health check failed.
    EngineHealthFailed,
    /// Graceful and forced shutdown failed.
    EngineShutdownFailed,
    /// The bounded launch retry budget is exhausted until explicit reset.
    CrashLoop,
    /// Internal invariant or clock failure.
    EngineInternal,
}

impl EngineFailureReason {
    /// Stable snake-case reason code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EngineBlocked => "engine_blocked",
            Self::EngineIncompatible => "engine_incompatible",
            Self::EngineProvisionFailed => "engine_provision_failed",
            Self::ArtifactNotReady => "artifact_not_ready",
            Self::UnsafeArgument => "unsafe_argument",
            Self::EngineSpawnFailed => "engine_spawn_failed",
            Self::EngineEarlyExit => "engine_early_exit",
            Self::EngineReadinessTimeout => "engine_readiness_timeout",
            Self::EngineHealthFailed => "engine_health_failed",
            Self::EngineShutdownFailed => "engine_shutdown_failed",
            Self::CrashLoop => "crash_loop",
            Self::EngineInternal => "engine_internal",
        }
    }
}

impl fmt::Display for EngineFailureReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Operator-safe managed-engine failure with required remediation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineDriverError {
    reason: EngineFailureReason,
    message: String,
    remediation: String,
    retryable: bool,
    diagnostic_tail: Option<String>,
}

impl EngineDriverError {
    /// Construct a typed error. Empty remediation is replaced with a safe fallback.
    pub fn new(
        reason: EngineFailureReason,
        message: impl Into<String>,
        remediation: impl Into<String>,
        retryable: bool,
    ) -> Self {
        let message = bounded_operator_text(&message.into(), 2_048);
        let remediation = bounded_operator_text(&remediation.into(), 1_024);
        Self {
            reason,
            message: if message.trim().is_empty() {
                "managed engine operation failed".to_string()
            } else {
                message
            },
            remediation: if remediation.trim().is_empty() {
                "inspect the model-host operation job and retry after correcting the cause"
                    .to_string()
            } else {
                remediation
            },
            retryable,
            diagnostic_tail: None,
        }
    }

    /// Construct a policy-blocked failure.
    pub fn blocked(message: impl Into<String>, remediation: impl Into<String>) -> Self {
        Self::new(
            EngineFailureReason::EngineBlocked,
            message,
            remediation,
            false,
        )
    }

    /// Construct an artifact-verification failure.
    pub fn artifact_not_ready(message: impl Into<String>) -> Self {
        Self::new(
            EngineFailureReason::ArtifactNotReady,
            message,
            "pull and verify the exact catalog artifact before launching the deployment",
            false,
        )
    }

    /// Construct a rejected argument failure.
    pub fn unsafe_argument(message: impl Into<String>) -> Self {
        Self::new(
            EngineFailureReason::UnsafeArgument,
            message,
            "remove the argument and use the typed model-host configuration field instead",
            false,
        )
    }

    /// Stable reason code.
    pub const fn reason(&self) -> EngineFailureReason {
        self.reason
    }

    /// Operator action that can resolve the failure.
    pub fn remediation(&self) -> &str {
        &self.remediation
    }

    /// Whether bounded retry can succeed without changing desired state.
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// Concise operator-safe failure message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Attach a bounded, credential-redacted diagnostic tail.
    pub fn with_diagnostic_tail(mut self, diagnostic: impl AsRef<str>) -> Self {
        let diagnostic = sanitize_diagnostic_tail(diagnostic.as_ref());
        self.diagnostic_tail = (!diagnostic.is_empty()).then_some(diagnostic);
        self
    }

    /// Bounded, credential-redacted diagnostic retained for crash-loop status.
    pub fn diagnostic_tail(&self) -> Option<&str> {
        self.diagnostic_tail.as_deref()
    }
}

impl fmt::Display for EngineDriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}; remediation: {}",
            self.reason, self.message, self.remediation
        )
    }
}

impl std::error::Error for EngineDriverError {}

fn sanitize_diagnostic_tail(diagnostic: &str) -> String {
    let bounded = diagnostic
        .lines()
        .rev()
        .take(100)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
        .chars()
        .take(8_192)
        .collect::<String>();
    redact_sensitive_tokens(&bounded)
        .chars()
        .take(8_192)
        .collect()
}

fn bounded_operator_text(text: &str, max_chars: usize) -> String {
    let printable = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(max_chars)
        .collect::<String>();
    redact_sensitive_tokens(&printable)
        .chars()
        .take(max_chars)
        .collect()
}

fn redact_sensitive_tokens(text: &str) -> String {
    let mut tokens = text.split_whitespace().peekable();
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

impl LaunchRequest {
    /// Validate verified artifact identity, paths, runtime identity, and extra arguments.
    pub fn validate(&self, kind: EngineKind) -> Result<(), EngineDriverError> {
        if self.deployment.trim().is_empty() {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "launch deployment must not be empty",
                "reconcile a valid canonical deployment before launching",
                false,
            ));
        }
        if self.generation == 0 {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "launch generation must be positive",
                "reconcile a numbered deployment generation before launching",
                false,
            ));
        }
        if self.port == 0 {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "launch port must be positive",
                "allocate an unused loopback port before launching",
                true,
            ));
        }
        if self.ready_timeout.is_zero() {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "readiness timeout must be positive",
                "configure a positive engine readiness deadline",
                false,
            ));
        }
        if self.max_concurrency == 0 {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "launch max_concurrency must be positive",
                "compile a positive managed deployment concurrency limit",
                false,
            ));
        }
        // A repo-mode (unpinned raw `hf:`) artifact has no verified local
        // bytes: the engine self-downloads the weights at launch, so the
        // trust and file-verification invariants below apply only to
        // pinned, content-addressed snapshots.
        let repo_mode = self.artifact.repo.is_some();
        if !repo_mode && self.artifact.metadata.trust != "verified" {
            return Err(EngineDriverError::artifact_not_ready(format!(
                "artifact {} has trust state {:?}",
                self.artifact.artifact_digest, self.artifact.metadata.trust
            )));
        }
        if self.artifact.artifact_digest != self.artifact.metadata.artifact_digest {
            return Err(EngineDriverError::artifact_not_ready(
                "ready artifact digest does not match its verified metadata",
            ));
        }
        if self.artifact.job.state != crate::OperationState::Ready {
            return Err(EngineDriverError::artifact_not_ready(format!(
                "artifact operation {} is not ready",
                self.artifact.job.id
            )));
        }
        if !self.artifact.snapshot_path.is_absolute() {
            return Err(EngineDriverError::artifact_not_ready(
                "verified snapshot path must be absolute",
            ));
        }
        if !repo_mode && self.artifact.files.len() != self.artifact.metadata.files.len() {
            return Err(EngineDriverError::artifact_not_ready(
                "verified file map does not match artifact metadata",
            ));
        }
        for file in &self.artifact.metadata.files {
            let relative = std::path::Path::new(&file.path);
            if relative.is_absolute()
                || relative.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                return Err(EngineDriverError::artifact_not_ready(format!(
                    "artifact file {:?} is not a safe relative path",
                    file.path
                )));
            }
            let expected = self.artifact.snapshot_path.join(relative);
            if self.artifact.files.get(&file.path) != Some(&expected) {
                return Err(EngineDriverError::artifact_not_ready(format!(
                    "artifact file {:?} is outside the verified snapshot",
                    file.path
                )));
            }
        }
        let compatible = match kind {
            EngineKind::Vllm => matches!(
                self.artifact.metadata.format,
                ArtifactFormat::Safetensors | ArtifactFormat::Pickle
            ),
            // SGLang mirrors vLLM here: it loads the same safetensors and
            // approved-pickle formats.
            EngineKind::SGLang => matches!(
                self.artifact.metadata.format,
                ArtifactFormat::Safetensors | ArtifactFormat::Pickle
            ),
            EngineKind::LlamaCpp => self.artifact.metadata.format == ArtifactFormat::Gguf,
            EngineKind::Embedded => self.artifact.metadata.format == ArtifactFormat::Safetensors,
        };
        if !compatible {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineIncompatible,
                format!(
                    "engine {kind:?} cannot consume {:?}",
                    self.artifact.metadata.format
                ),
                "select a catalog variant compatible with the requested engine",
                false,
            ));
        }
        if self
            .selected_devices
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != self.selected_devices.len()
        {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "selected device indices must be unique",
                "recompute placement before launching the engine",
                false,
            ));
        }
        if self.accelerator == AcceleratorKind::Cpu && !self.selected_devices.is_empty() {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "CPU launch cannot select accelerator device indices",
                "clear selected devices for a CPU deployment",
                false,
            ));
        }
        if self.accelerator == AcceleratorKind::Metal && self.selected_devices.len() != 1 {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "Metal launch requires one unified-memory device",
                "select one Apple accelerator device",
                false,
            ));
        }
        if self.accelerator == AcceleratorKind::Cuda && self.selected_devices.is_empty() {
            return Err(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                "CUDA launch requires at least one accelerator device",
                "select one or more NVIDIA accelerator devices",
                false,
            ));
        }
        validate_engine_args(kind, &self.extra_args)?;
        Ok(())
    }
}

/// Validate and copy additional arguments from the engine-specific stable allowlist.
pub fn validate_engine_args(
    kind: EngineKind,
    arguments: &[String],
) -> Result<Vec<String>, EngineDriverError> {
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument.is_empty()
            || argument.contains('\0')
            || argument.contains('\n')
            || argument.contains('\r')
        {
            return Err(EngineDriverError::unsafe_argument(
                "engine arguments must be nonempty single tokens",
            ));
        }
        let (flag, inline_value) = match argument.split_once('=') {
            Some((flag, value)) => (flag, Some(value)),
            None => (argument.as_str(), None),
        };
        let rule = argument_rule(kind, flag).ok_or_else(|| {
            EngineDriverError::unsafe_argument(format!(
                "engine argument {flag:?} is not in the stable allowlist"
            ))
        })?;
        match (rule, inline_value) {
            (ArgumentRule::Boolean, None) => {}
            (ArgumentRule::Boolean, Some(_)) => {
                return Err(EngineDriverError::unsafe_argument(format!(
                    "boolean engine argument {flag:?} does not accept a value"
                )));
            }
            (ArgumentRule::Value(validator), Some(value)) => {
                validate_argument_value(flag, value, validator)?
            }
            (ArgumentRule::Value(validator), None) => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    EngineDriverError::unsafe_argument(format!(
                        "engine argument {flag:?} requires a value"
                    ))
                })?;
                validate_argument_value(flag, value, validator)?;
                index += 1;
            }
        }
        index += 1;
    }
    Ok(arguments.to_vec())
}

#[derive(Clone, Copy)]
enum ArgumentRule {
    Boolean,
    Value(ArgumentValue),
}

#[derive(Clone, Copy)]
enum ArgumentValue {
    Unsigned,
    VllmDtype,
    /// A finite, non-negative float, for tuning knobs such as SGLang's
    /// `--schedule-conservativeness` (default 1.0, values may exceed 1).
    NonNegativeFloat,
}

fn argument_rule(kind: EngineKind, flag: &str) -> Option<ArgumentRule> {
    match (kind, flag) {
        (
            EngineKind::Vllm,
            "--enable-prefix-caching" | "--disable-log-requests" | "--enforce-eager",
        ) => Some(ArgumentRule::Boolean),
        (EngineKind::Vllm, "--seed") => Some(ArgumentRule::Value(ArgumentValue::Unsigned)),
        (EngineKind::Vllm, "--dtype") => Some(ArgumentRule::Value(ArgumentValue::VllmDtype)),
        // SGLang's stable allowlist. `--model-path`, `--host`, `--port`,
        // `--tp-size`, and `--mem-fraction-static` stay off it: they are
        // runtime-owned, the same way vLLM keeps `--tensor-parallel-size`
        // and `--gpu-memory-utilization` off. The runtime derives the
        // static memory fraction from the fit plan, so an operator flag
        // would either duplicate or fight it.
        (EngineKind::SGLang, "--enable-torch-compile" | "--disable-radix-cache") => {
            Some(ArgumentRule::Boolean)
        }
        (EngineKind::SGLang, "--schedule-conservativeness") => {
            Some(ArgumentRule::Value(ArgumentValue::NonNegativeFloat))
        }
        (EngineKind::LlamaCpp, "--flash-attn" | "--no-mmap" | "--mlock") => {
            Some(ArgumentRule::Boolean)
        }
        (EngineKind::LlamaCpp, "--threads" | "--batch-size" | "--ubatch-size" | "--seed") => {
            Some(ArgumentRule::Value(ArgumentValue::Unsigned))
        }
        _ => None,
    }
}

fn validate_argument_value(
    flag: &str,
    value: &str,
    validator: ArgumentValue,
) -> Result<(), EngineDriverError> {
    if value.is_empty()
        || value.starts_with('-')
        || value.contains('\0')
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(EngineDriverError::unsafe_argument(format!(
            "engine argument {flag:?} has an invalid value"
        )));
    }
    let valid = match validator {
        ArgumentValue::Unsigned => value.parse::<u64>().is_ok(),
        ArgumentValue::VllmDtype => {
            matches!(value, "auto" | "half" | "float16" | "bfloat16" | "float32")
        }
        ArgumentValue::NonNegativeFloat => value
            .parse::<f64>()
            .is_ok_and(|parsed| parsed.is_finite() && parsed >= 0.0),
    };
    if !valid {
        return Err(EngineDriverError::unsafe_argument(format!(
            "engine argument {flag:?} has an unsupported value {value:?}"
        )));
    }
    Ok(())
}

/// Engine-specific lifecycle driven by process-wide reconciliation.
#[async_trait]
pub trait EngineDriver: Send + Sync {
    /// Managed engine kind implemented by this driver.
    fn kind(&self) -> EngineKind;

    /// Static driver capabilities.
    fn capabilities(&self) -> EngineCapabilities;

    /// Detect installed and automatically acquirable engine paths.
    fn detect(&self, worker: &WorkerProfile, provisioning: &EngineProvisioning) -> EngineDetection;

    /// Provision or select one exact engine installation.
    async fn provision(
        &self,
        request: &ProvisionRequest,
    ) -> Result<ProvisionedEngine, EngineDriverError>;

    /// Launch verified local artifact bytes and wait for readiness.
    async fn launch(
        &self,
        provisioned: &ProvisionedEngine,
        request: &LaunchRequest,
    ) -> Result<RunningEngine, EngineDriverError>;

    /// Check a launched engine without mutating desired state.
    async fn health(&self, running: &RunningEngine) -> Result<EngineHealth, EngineDriverError>;

    /// Gracefully stop one launched engine, forcing termination after `grace`.
    async fn shutdown(
        &self,
        running: RunningEngine,
        grace: Duration,
    ) -> Result<(), EngineDriverError>;
}
