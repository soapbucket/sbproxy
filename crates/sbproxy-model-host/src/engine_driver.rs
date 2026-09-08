// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Shared typed lifecycle for every managed inference engine.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub use sb_runtime_core::{
    EngineAvailability, EngineDetection, EngineDriverError, EngineExecutionIdentity,
    EngineFailureReason, EngineHealth,
};
pub use sb_runtime_host::EngineDriver;

use crate::{
    AcceleratorKind, ArtifactFormat, ChunkedPrefill, EngineKind, EngineProcess, EngineProvisioning,
    FileJobStore, FitPlan, ReadyArtifact, ResolvedArtifact, WorkerProfile,
};

/// Static compatibility facts declared by one model-host engine driver.
pub type EngineCapabilities = sb_runtime_core::EngineCapabilities<ArtifactFormat, AcceleratorKind>;

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
    /// CPU swap pool in GiB: `--swap-space`.
    pub swap_space_gib: Option<u64>,
    /// Weights kept in CPU RAM in GiB: `--cpu-offload-gb`.
    pub cpu_offload_gib: Option<u64>,
    /// LoRA adapters served over the base model (WOR-1945): each becomes a
    /// vLLM `--lora-modules <name>=<path>` alongside `--enable-lora`, so a
    /// client can request the adapter by name over one resident base.
    /// Empty leaves LoRA off.
    pub lora_adapters: Vec<crate::config::LoraAdapter>,
    /// vLLM adapter-slot capacity (`--max-loras`): the maximum adapters
    /// resident at once. Ignored when `lora_adapters` is empty.
    pub max_loras: usize,
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

impl RunningEngine {
    /// Data-only execution identity shared with control-plane consumers.
    pub fn execution_identity(&self) -> EngineExecutionIdentity {
        EngineExecutionIdentity {
            deployment: self.deployment.clone(),
            generation: self.generation,
            kind: self.kind,
            port: self.port,
        }
    }
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

/// Object-safe compatibility surface for SBproxy's concrete managed-runtime types.
///
/// The neutral host trait keeps consumer-owned artifact, placement, provisioning,
/// and process types explicit. SBproxy binds those associated types once here so
/// its runtime registry does not repeat or erase the contract at every use site.
pub type DynEngineDriver = dyn EngineDriver<
    ArtifactFormat = ArtifactFormat,
    Accelerator = AcceleratorKind,
    Worker = WorkerProfile,
    Provisioning = EngineProvisioning,
    ProvisionRequest = ProvisionRequest,
    ProvisionedEngine = ProvisionedEngine,
    LaunchRequest = LaunchRequest,
    RunningEngine = RunningEngine,
>;

impl LaunchRequest {
    /// Data-only identity validated before host-specific launch inputs.
    pub fn execution_identity(&self, kind: EngineKind) -> EngineExecutionIdentity {
        EngineExecutionIdentity {
            deployment: self.deployment.clone(),
            generation: self.generation,
            kind,
            port: self.port,
        }
    }

    /// Validate verified artifact identity, paths, runtime identity, and extra arguments.
    pub fn validate(&self, kind: EngineKind) -> Result<(), EngineDriverError> {
        self.execution_identity(kind).validate()?;
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
            // Safetensors-only for now: GGUF stays llama.cpp's certified
            // lane (WOR-1861).
            EngineKind::MistralRs => self.artifact.metadata.format == ArtifactFormat::Safetensors,
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
        // mistral.rs's stable allowlist (WOR-1861). `-m`, `--host`,
        // `--port`, `--max-seq-len`, `--max-seqs`, and `--cpu` stay off
        // it: they are runtime-owned, derived from the fit plan and the
        // launch request.
        (EngineKind::MistralRs, "--no-kv-cache") => Some(ArgumentRule::Boolean),
        (EngineKind::MistralRs, "--prefix-cache-n") => {
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
