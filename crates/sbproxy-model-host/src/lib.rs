// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Local model serving for sbproxy (WOR-1652).
//!
//! The model host lets the gateway resolve a model name to a set of
//! weights, fit an inference engine to the local GPU, spawn and
//! supervise that engine as a subprocess, and register it as a local
//! provider in the existing routing/guardrail/budget/ledger planes.
//! This is the single-node OSS wedge; fleet placement is a separate
//! effort.
//!
//! This crate is the **hardware-independent core**: everything here
//! runs and is unit-tested on a CPU with no GPU, no engine binary,
//! and no network. The pieces that need real hardware or a real
//! engine (NVML discovery, Hugging Face weight download, spawning
//! vLLM / llama.cpp) plug in behind the traits defined here
//! ([`fit::GpuProbe`], [`supervisor::EngineLauncher`]); those
//! implementations and their GPU certification land in later phases
//! of the epic.
//!
//! ## Modules
//!
//! - [`catalog`] - the certified `catalog_id -> HF repo + quant`
//!   registry and its resolver.
//! - [`fit`] - GPU capability model, the VRAM fit planner (KV +
//!   tensor-size math), and capability-aware quant selection.
//! - [`supervisor`] - the engine lifecycle state machine (load,
//!   ready, evict, restart) over an abstract launcher.
//! - [`config`] - the `serve:` config block an operator writes.

pub mod acquire;
pub mod admission;
pub mod artifact;
pub mod artifact_spec;
pub mod capabilities;
pub mod catalog;
pub mod config;
pub mod cuda_build;
pub mod deployment;
pub mod deployment_store;
pub mod desired;
pub mod device_residency;
#[cfg(feature = "embedded")]
pub mod embedded;
pub mod engine_driver;
pub mod fit;
pub mod hybrid;
pub mod jobs;
pub mod kv_tiering;
pub mod launch;
pub mod llama_driver;
pub mod llama_release;
pub mod lora;
pub mod manifest;
pub mod probe_cpu;
#[cfg(all(target_os = "macos", feature = "gpu-apple"))]
pub mod probe_metal;
#[cfg(feature = "gpu-nvidia")]
pub mod probe_nvidia;
pub mod process;
pub mod pull;
pub mod report;
pub mod residency;
pub mod runtime;
pub mod runtime_manager;
pub mod scheduling;
pub mod sleep_wake;
pub mod supervisor;
pub mod supply_chain;
#[cfg(feature = "tokenizer")]
pub mod tokenize;
pub mod uv_release;
pub mod vllm_driver;
pub mod weights;

pub use acquire::{plan_binary_acquire, plan_binary_acquire_with_cuda, BinaryAcquirePlan};
pub use admission::{
    AdmissionCounts, AdmissionGate, AdmissionPermit, AdmissionReason, AdmissionRejection,
    DrainReport,
};
#[cfg(feature = "weights")]
pub use artifact::HttpArtifactTransport;
pub use artifact::{
    AcquisitionContext, ArtifactCacheMetadata, ArtifactCacheState, ArtifactError, ArtifactManager,
    ArtifactObserver, ArtifactTransport, CacheProtection, GcReport, NetworkPolicy, PullIntent,
    ReadyArtifact, ResponseDisposition, SourceCredential, TransportRequest, TransportResponse,
    UnavailableArtifactTransport,
};
pub use artifact_spec::{
    AcceleratorKind, ArtifactFile, ArtifactFormat, ArtifactVariant, ComputeCapability,
    ResolveArtifactRequest, ResolvedArtifact, VariantRequirements, WorkerProfile,
};
pub use capabilities::{
    capability_registry, CapabilityDomain, CapabilityEntry, CapabilityFinding, CapabilityRegistry,
    ConfigFieldCapability, ConsumerContract, SupportLevel, CAPABILITY_REGISTRY_VERSION,
};
pub use catalog::{
    ArtifactResolveError, Catalog, CatalogDiagnostic, CatalogEntry, CatalogError, CatalogLoad,
    ModelRef, PullPolicy, ResolveError,
};
pub use config::{
    AcquireSource, ChunkedPrefill, EngineAccel, EngineAcquire, EngineChoice, EngineDoctor,
    EngineEnv, EngineKind, EngineLaunchMethod, EngineProvisioning, EvictionPolicy, KvCacheQuant,
    LoraAdapter, ModelHostConfig, ServeEntry, SpecMethod, SpeculativeConfig,
};
pub use cuda_build::{
    CudaBuildPlan, CudaBuildPrerequisites, CudaLlamaBuilder, CudaSourceFetcher,
    HttpCudaSourceFetcher, DEFAULT_LLAMA_SOURCE_COMMIT, DEFAULT_LLAMA_SOURCE_SHA256,
    MAX_LLAMA_SOURCE_BYTES,
};
pub use deployment::{
    DeploymentError, DeploymentRevision, DeploymentRevisionDraft, DeploymentSourceMode,
    ModelDeployment, RolloutPolicy, DEPLOYMENT_SCHEMA_VERSION,
};
pub use deployment_store::{DeploymentStoreError, FileDeploymentRevisionStore};
pub use desired::{
    compile_desired_state, CompiledDeployment, DeploymentRoute, DesiredDeploymentOrigin,
    DesiredStateError, LegacyHostPolicy, LegacyServeInput, ManagedProviderInput,
    RuntimeDesiredInput, RuntimeDesiredState,
};
pub use device_residency::{
    DeviceReservation, DeviceReservationResult, DeviceResidencySet, ResidencyProtection,
};
pub use engine_driver::{
    validate_engine_args, EngineAvailability, EngineCapabilities, EngineDetection, EngineDriver,
    EngineDriverError, EngineFailureReason, EngineHealth, LaunchRequest, ProvisionRequest,
    ProvisionedEngine, RunningEngine,
};
pub use fit::{
    estimate_throughput, fp8_supported, memory_occupancy, plan_fit_auto_kv_with_margin,
    plan_fit_kv_with_margin, FitError, FitPlan, GpuDescriptor, GpuProbe, GpuVendor, MemoryEstimate,
    ModelMetadata, Quant, StaticGpuProbe, ThroughputEstimate,
};
pub use hybrid::{savings_micros, AliasTable, CloudPrice, LaneSplit};
pub use jobs::{
    FileJobStore, JobError, OperationJob, OperationKind, OperationProgress, OperationState,
};
pub use kv_tiering::{KvTier, KvTieringPolicy, TierDecision};
pub use launch::{
    build_launch_spec, chunk_size_for_ttft, serving_flags, should_speculate, ProcessEngineLauncher,
};
pub use llama_driver::{
    LlamaBinarySource, LlamaCppDriver, LlamaDetection, LlamaProvisioned, SystemLlamaBinarySource,
};
pub use llama_release::{
    asset_url as llama_asset_url, asset_url_accel as llama_asset_url_accel, is_executable_file,
    resolve_on_path, Platform, DEFAULT_LLAMA_RELEASE_TAG,
};
#[cfg(feature = "weights")]
pub use llama_release::{ensure_llama_server, ensure_llama_server_blocking};
pub use lora::{AdapterRoute, LoraCache};
pub use manifest::{
    resolve_cache_dir, resolve_cache_dir_default, validate_serve_against_manifest, SourceScheme,
    SERVICE_CACHE_DIR,
};
pub use probe_cpu::{detect_total_memory_bytes, CpuProbe};
#[cfg(all(target_os = "macos", feature = "gpu-apple"))]
pub use probe_metal::MetalGpuProbe;
#[cfg(feature = "gpu-nvidia")]
pub use probe_nvidia::NvmlGpuProbe;
pub use process::{
    CommandExecutor, CommandOutput, EngineCommand, EngineProcess, EngineProcessRunner,
    EngineReadinessProbe, LoopbackReadinessProbe, TokioCommandExecutor,
};
pub use pull::{pull_plan, PullItem, PullMode};
pub use report::{ModelValue, ValueReport};
pub use residency::{Admission, ResidencyManager, Resident};
pub use runtime::{
    parse_params, ConfigDirMetadataProvider, DeviceVram, ModelHostObserver, ModelHostRuntime,
    ModelHostStatus, ModelMetadataProvider, ModelStatus, NoopObserver, RuntimeError, VramStatus,
};
pub use runtime_manager::{
    DeploymentPrepareRequest, DeploymentPreparer, DeploymentRuntimeState, DeploymentRuntimeStatus,
    ModelRuntimeManager, PreparedDeploymentRuntime, PreparedRevision, PreparedRuntimePhase,
    PreparedRuntimeTelemetry, ProductionDeploymentPreparer, ReconcilePlan, ReconcileReport,
    RuntimeManagerError,
};
pub use scheduling::{admit, next_to_admit, PriorityClass, SchedulingDecision};
pub use sleep_wake::{is_sleeping, sleep, wake_up, SleepLevel};
pub use supervisor::{
    BackoffPolicy, CrashLoopState, EngineLauncher, EngineState, EngineSupervisor, LaunchSpec,
    SupervisorClock, SupervisorError, TokioSupervisorClock,
};
pub use supply_chain::{scan_pickle, select_weight_file, SupplyChainError, WeightFormat};
#[cfg(feature = "tokenizer")]
pub use tokenize::{count_tokens, render_chat_template, ChatMessage};
pub use vllm_driver::{
    build_vllm_container_plan, ContainerRuntime, SystemVllmHost, VllmCompatibilityReport,
    VllmComponentStatus, VllmContainerPlan, VllmDriver, VllmHost, VllmLaunchMode,
    DEFAULT_VLLM_VERSION,
};
