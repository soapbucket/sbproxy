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

pub mod catalog;
pub mod config;
pub mod fit;
pub mod hybrid;
pub mod launch;
#[cfg(feature = "gpu-nvidia")]
pub mod probe_nvidia;
pub mod residency;
pub mod supervisor;
pub mod supply_chain;
pub mod weights;

pub use catalog::{Catalog, CatalogEntry, ModelRef, ResolveError};
pub use config::{EngineKind, EvictionPolicy, KvCacheQuant, ModelHostConfig, ServeEntry};
pub use fit::{
    estimate_throughput, fp8_supported, FitError, FitPlan, GpuDescriptor, GpuProbe, GpuVendor,
    ModelMetadata, Quant, StaticGpuProbe, ThroughputEstimate,
};
pub use hybrid::{savings_micros, AliasTable, CloudPrice, LaneSplit};
pub use launch::{build_launch_spec, parse_duration, ProcessEngineLauncher};
#[cfg(feature = "gpu-nvidia")]
pub use probe_nvidia::NvmlGpuProbe;
pub use residency::{Admission, ResidencyManager, Resident};
pub use supervisor::{EngineLauncher, EngineState, LaunchSpec, SupervisorError};
pub use supply_chain::{scan_pickle, select_weight_file, SupplyChainError, WeightFormat};
