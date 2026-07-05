// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The `serve:` configuration block (WOR-1653 core).
//!
//! An operator adds a `serve:` block to an `ai_proxy` provider to
//! turn the gateway into the host for one or more local models. The
//! config is deliberately not a free-form command line: engines are
//! an allowlisted enum with argument templates, so config cannot ask
//! the gateway (which also holds provider keys) to spawn an arbitrary
//! binary. See the security review child of the epic.
//!
//! These types derive `JsonSchema` so the `serve:` surface appears in
//! `sb-config.schema.json`.

use serde::{Deserialize, Serialize};

/// Which inference engine serves a model. An allowlisted enum, not a
/// `cmd:` string: the runtime owns the argument template for each
/// engine, so config chooses an engine and its knobs, never an
/// arbitrary executable.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    /// vLLM, the datacenter default, driven as a supervised
    /// subprocess over its OpenAI-compatible HTTP surface.
    #[default]
    Vllm,
    /// llama.cpp `llama-server`, the low-VRAM / GGUF / edge path.
    LlamaCpp,
    /// In-process engine (WOR-1658): no subprocess, no external binary.
    /// The model runs inside the gateway behind the `embedded` cargo
    /// feature (candle backend), serving over a loopback HTTP port like
    /// the others so the runtime routes to it unchanged. A build without
    /// the `embedded` feature accepts the config but fails the launch
    /// with a clear "rebuild with --features embedded" error.
    Embedded,
}

impl EngineKind {
    /// The binary name looked up on `PATH` for this engine. For
    /// [`EngineKind::Embedded`] this is a sentinel, not a real
    /// executable: the embedded engine runs in-process and never spawns
    /// a subprocess, so the name is never resolved on `PATH`.
    pub fn binary_name(self) -> &'static str {
        match self {
            EngineKind::Vllm => "vllm",
            EngineKind::LlamaCpp => "llama-server",
            EngineKind::Embedded => "embedded",
        }
    }

    /// Whether this engine runs in-process (no subprocess spawn). Only
    /// [`EngineKind::Embedded`] does; the launcher dispatches on it.
    pub fn is_in_process(self) -> bool {
        matches!(self, EngineKind::Embedded)
    }
}

/// The engine an operator asks for on a model (WOR-1684). Unlike
/// [`EngineKind`] (the resolved identity), this includes `Auto`, which
/// the runtime resolves per model at boot from the weight format and
/// what is installed. `Auto` is the default so a minimal `serve:`
/// block does not have to name an engine.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EngineChoice {
    /// Resolve the engine from the weights and the environment.
    #[default]
    Auto,
    /// Force vLLM.
    Vllm,
    /// Force llama.cpp.
    LlamaCpp,
    /// Force the in-process embedded engine (WOR-1658). `Auto` never
    /// resolves to this; the embedded engine is an explicit opt-in
    /// because it changes the deployment model (no subprocess) and is
    /// only present when the `embedded` feature is compiled.
    Embedded,
}

impl EngineChoice {
    /// Resolve to a concrete [`EngineKind`]. `Auto` picks llama.cpp for
    /// GGUF weights or when no container runtime is available (the
    /// zero-dependency path), and vLLM otherwise (safetensors / FP8 /
    /// tensor parallelism, which is the datacenter default). A forced
    /// choice is returned unchanged.
    pub fn resolve(self, is_gguf: bool, container_runtime: bool) -> EngineKind {
        match self {
            EngineChoice::Vllm => EngineKind::Vllm,
            EngineChoice::LlamaCpp => EngineKind::LlamaCpp,
            EngineChoice::Embedded => EngineKind::Embedded,
            EngineChoice::Auto => {
                if is_gguf || !container_runtime {
                    EngineKind::LlamaCpp
                } else {
                    EngineKind::Vllm
                }
            }
        }
    }

    /// A short human-readable reason for the `Auto` resolution, for the
    /// plan-time engine doctor.
    pub fn resolve_reason(self, is_gguf: bool, container_runtime: bool) -> &'static str {
        match self {
            EngineChoice::Vllm => "engine: vllm (forced)",
            EngineChoice::LlamaCpp => "engine: llama_cpp (forced)",
            EngineChoice::Embedded => "engine: embedded (forced, in-process)",
            EngineChoice::Auto if is_gguf => "auto -> llama_cpp (GGUF weights)",
            EngineChoice::Auto if !container_runtime => {
                "auto -> llama_cpp (no container runtime for vLLM)"
            }
            EngineChoice::Auto => "auto -> vllm (safetensors, container runtime present)",
        }
    }
}

/// How an engine binary is acquired (WOR-1684). Engine *identity*
/// stays the allowlisted [`EngineKind`]; only the acquisition method
/// is configurable, so the config-spawn security posture (no arbitrary
/// `cmd:`) is unchanged.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EngineLaunchMethod {
    /// Resolve the engine binary from `PATH`.
    #[default]
    Binary,
    /// Run the engine from a pinned container image.
    Container,
    /// Run the engine from a managed uv/venv (vLLM's Python path).
    Venv,
}

/// Provisioning for one engine (how to acquire it), keyed by engine in
/// [`ModelHostConfig::engines`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EngineProvisioning {
    /// How the binary is acquired.
    #[serde(default)]
    pub launch: EngineLaunchMethod,
    /// Pinned container image (a tag or digest, never `:latest`) for
    /// [`EngineLaunchMethod::Container`]. Rejected at plan time if it
    /// ends in `:latest` or has no tag.
    #[serde(default)]
    pub image: Option<String>,
}

impl EngineProvisioning {
    /// Whether `image` is acceptably pinned (has a tag or digest that
    /// is not `latest`). Only meaningful for the container method.
    pub fn image_is_pinned(&self) -> bool {
        match &self.image {
            None => true, // no image is fine for non-container methods
            Some(img) => {
                if let Some((_, tag)) = img.rsplit_once('@') {
                    // digest form repo@sha256:...
                    return tag.starts_with("sha256:") && tag.len() > "sha256:".len();
                }
                match img.rsplit_once(':') {
                    Some((repo, tag)) => !repo.is_empty() && !tag.is_empty() && tag != "latest",
                    None => false, // no tag at all
                }
            }
        }
    }
}

/// What to do when VRAM is needed and an idle model is resident.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EvictionPolicy {
    /// Evict the least-recently-used idle model to make room (default).
    #[default]
    Lru,
    /// Never evict; reject a new model when VRAM is full. Predictable
    /// residency for a pinned single model.
    Never,
}

/// KV-cache quantization for a served model (WOR-1676). Quantizing
/// the KV cache multiplies effective KV capacity, so a model can fit a
/// longer context or a larger batch on the same VRAM at some quality
/// cost. `Auto` keeps the cache at the weight quant's default (f16 for
/// most, fp8 when serving FP8).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum KvCacheQuant {
    /// Follow the weight quant's default KV dtype.
    #[default]
    Auto,
    /// 16-bit KV (the safe, full-quality default).
    F16,
    /// 8-bit float KV. Needs FP8-capable kernels.
    Fp8,
    /// 8-bit integer KV.
    Int8,
    /// 4-bit KV (maximum capacity, largest quality hit).
    Int4,
}

impl KvCacheQuant {
    /// Bytes per KV element for this mode, or `None` for `Auto` (the
    /// caller uses the weight quant's default instead).
    pub fn bytes_per_element(self) -> Option<f64> {
        match self {
            KvCacheQuant::Auto => None,
            KvCacheQuant::F16 => Some(2.0),
            KvCacheQuant::Fp8 => Some(1.0),
            KvCacheQuant::Int8 => Some(1.0),
            KvCacheQuant::Int4 => Some(0.5),
        }
    }

    /// Whether this KV mode needs FP8 kernels (so the fit planner can
    /// gate it on GPU capability, like FP8 weights).
    pub fn needs_fp8(self) -> bool {
        matches!(self, KvCacheQuant::Fp8)
    }
}

/// How a model does speculative decoding (WOR-1674). Speculation
/// wins when the batch is memory-bound (low load) and loses when it is
/// compute-bound (full batch), so the runtime load-gates it; this is
/// the config that says which method to use when it is on.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SpecMethod {
    /// A separate small draft model proposes tokens.
    DraftModel,
    /// N-gram / prompt-lookup speculation (no draft model).
    #[default]
    Ngram,
}

/// Speculative-decoding settings for a served model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpeculativeConfig {
    /// Which speculation method.
    #[serde(default)]
    pub method: SpecMethod,
    /// Draft model repo/id, required for [`SpecMethod::DraftModel`].
    #[serde(default)]
    pub draft_model: Option<String>,
    /// How many tokens to propose per step.
    #[serde(default = "default_spec_tokens")]
    pub num_speculative_tokens: u32,
}

fn default_spec_tokens() -> u32 {
    5
}

/// Chunked-prefill settings (WOR-1678). Chunked prefill trades a
/// larger prefill chunk (higher throughput) against time-to-first-token
/// (lower with smaller chunks). Set `max_batched_tokens` directly, or
/// set `target_ttft_ms` to have the planner pick a chunk size.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ChunkedPrefill {
    /// Explicit prefill chunk size (engine `max-num-batched-tokens`).
    /// `None` leaves it to the auto-tune or the engine default.
    #[serde(default)]
    pub max_batched_tokens: Option<u64>,
    /// A TTFT SLO in milliseconds; when set (and no explicit chunk
    /// size), the planner chooses a chunk size to hold it.
    #[serde(default)]
    pub target_ttft_ms: Option<u64>,
}

/// A LoRA adapter served over a base model (WOR-1673). Clients request
/// it by `name`; the runtime hot-loads it over the resident base with
/// an LRU adapter cache rather than swapping the base model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoraAdapter {
    /// The model name clients request to hit this adapter.
    pub name: String,
    /// Adapter source: an `hf:Org/Repo` reference or a local path.
    pub source: String,
}

/// One model an operator wants the gateway to serve locally.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServeEntry {
    /// Catalog id (`qwen3-32b`) or an explicit `hf:Org/Repo:QUANT`
    /// reference. Resolved by [`crate::catalog`].
    pub model: String,
    /// The model id every other plane sees (WOR-1683): routing,
    /// `allowed_models`, rate limits, budgets, aliases. Defaults to the
    /// catalog id in `model`; **required** when `model` is a raw `hf:`
    /// reference (there is no catalog id to borrow). See
    /// [`Self::effective_name`].
    #[serde(default)]
    pub name: Option<String>,
    /// Engine to serve it with. Defaults to `auto` (resolved per model
    /// at boot from the weight format and what is installed).
    #[serde(default)]
    pub engine: EngineChoice,
    /// Idle time before the engine is unloaded to free VRAM. Go
    /// duration syntax (`10m`, `1h`); `None` means never auto-unload.
    #[serde(default)]
    pub keep_alive: Option<String>,
    /// Context length to plan VRAM for and pass to the engine.
    /// `None` uses the model's declared max (clamped by the fit
    /// planner to what actually fits).
    #[serde(default)]
    pub max_context: Option<u64>,
    /// Extra engine flags appended to the templated args. Values only,
    /// no shell: each entry is passed as one argv element.
    #[serde(default)]
    pub extra_args: Vec<String>,
    /// KV-cache quantization. Defaults to `Auto` (the weight quant's
    /// default KV dtype).
    #[serde(default)]
    pub kv_quant: KvCacheQuant,
    /// Speculative decoding. `None` disables it.
    #[serde(default)]
    pub speculative: Option<SpeculativeConfig>,
    /// Chunked-prefill settings. `None` uses the engine default.
    #[serde(default)]
    pub chunked_prefill: Option<ChunkedPrefill>,
    /// LoRA adapters served over this base model.
    #[serde(default)]
    pub lora_adapters: Vec<LoraAdapter>,
    /// Keep this model resident: it is never evicted to make room for
    /// another (WOR-1672). Use for a latency-critical model that must
    /// stay hot. A set of pinned models is therefore never split.
    /// Admitting a new model that only fits by evicting a pinned one is
    /// rejected instead.
    #[serde(default)]
    pub pinned: bool,
    /// vLLM tool-call parser to enable auto tool-choice (WOR-1668), e.g.
    /// `hermes` (Qwen), `llama3_json`, `mistral`. When set, the engine
    /// launches with `--enable-auto-tool-choice --tool-call-parser
    /// <name>` so `tool_choice: auto` requests work; without it vLLM
    /// rejects auto tool-choice. `None` leaves tool calling off.
    #[serde(default)]
    pub tool_call_parser: Option<String>,
    /// CPU KV-cache tier size in GiB (WOR-1687): vLLM's `--swap-space`,
    /// the CPU pool it spills GPU KV blocks to under pressure so a
    /// longer effective context / larger batch survives beyond GPU
    /// VRAM. `None` uses the engine default.
    #[serde(default)]
    pub swap_space_gib: Option<u64>,
    /// GiB of model weights to keep in CPU RAM (WOR-1687): vLLM's
    /// `--cpu-offload-gb`, trading PCIe bandwidth for VRAM so a model
    /// that does not fit can still load. `None` disables offload.
    #[serde(default)]
    pub cpu_offload_gib: Option<u64>,
    /// Max LoRA adapters resident on the engine at once (WOR-1673).
    /// When set below the number of configured `lora_adapters`, the
    /// engine loads adapters on demand and evicts the least-recently
    /// used past this cap (dynamic paging), rather than preloading all
    /// of them. `None` preloads every configured adapter (static), which
    /// suits a small, fixed adapter set.
    #[serde(default)]
    pub max_loras: Option<usize>,
}

/// The `serve:` block: the local models plus host-wide policy.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelHostConfig {
    /// Models to serve locally. Registered as local providers ahead
    /// of any cloud fallback.
    #[serde(default)]
    pub models: Vec<ServeEntry>,
    /// Optional path to an operator catalog file, replacing the
    /// built-in certified catalog for id resolution.
    #[serde(default)]
    pub catalog_file: Option<String>,
    /// Directory for the content-addressed weight cache. `None` uses
    /// the platform default (`$HF_HOME` / `~/.cache/sbproxy/models`).
    #[serde(default)]
    pub cache_dir: Option<String>,
    /// Disk budget in GiB for the weight cache before GC. `None`
    /// means unbounded (operator manages the disk).
    #[serde(default)]
    pub cache_budget_gib: Option<f64>,
    /// What to do under VRAM pressure. Defaults to LRU eviction.
    #[serde(default)]
    pub eviction: EvictionPolicy,
    /// Per-engine provisioning (how to acquire each engine binary).
    /// Absent engines use the default (resolve from `PATH`).
    #[serde(default)]
    pub engines: std::collections::BTreeMap<EngineKind, EngineProvisioning>,
}

impl ServeEntry {
    /// The parsed keep-alive idle timeout, or `None` when unset or
    /// unparseable. Uses the compact duration form (`30m`, `1h30m`).
    pub fn keep_alive_duration(&self) -> Option<std::time::Duration> {
        self.keep_alive
            .as_deref()
            .and_then(crate::launch::parse_duration)
    }

    /// The model id this entry registers under (WOR-1683): the explicit
    /// `name`, else the catalog id in `model`. Returns an error when
    /// `model` is a raw `hf:` reference (or otherwise not a plain
    /// catalog id) and no `name` was given, since a bare ref must not
    /// leak into routing config as a model id.
    pub fn effective_name(&self) -> Result<String, String> {
        if let Some(n) = &self.name {
            if n.trim().is_empty() {
                return Err(format!(
                    "serve entry for '{}' has an empty name",
                    self.model
                ));
            }
            return Ok(n.clone());
        }
        // A plain catalog id has no scheme prefix and no colon-quant.
        if self.model.starts_with("hf:") || self.model.contains(':') || self.model.contains('/') {
            return Err(format!(
                "serve entry '{}' is a raw reference; give it a `name:` to use as the model id",
                self.model
            ));
        }
        Ok(self.model.clone())
    }

    /// Whether this entry serves `name`, i.e. `name` is its effective
    /// name or one of its LoRA adapter names (WOR-1673). An adapter is
    /// served by its base model's engine, so a request addressing an
    /// adapter routes to the base entry.
    pub fn serves(&self, name: &str) -> bool {
        self.effective_name().ok().as_deref() == Some(name)
            || self.lora_adapters.iter().any(|a| a.name == name)
    }

    /// Whether this entry pages LoRA adapters dynamically (WOR-1673):
    /// `max_loras` is set below the configured adapter count, so the
    /// engine loads adapters on demand and evicts the LRU past the cap
    /// rather than preloading all of them.
    pub fn dynamic_lora(&self) -> bool {
        matches!(self.max_loras, Some(cap) if cap < self.lora_adapters.len())
    }

    /// The engine adapter-slot capacity: the configured `max_loras`, or
    /// the number of adapters when unset (preload-all). At least 1 when
    /// any adapter is configured.
    pub fn lora_capacity(&self) -> usize {
        self.max_loras.unwrap_or(self.lora_adapters.len()).max(1)
    }
}

impl ModelHostConfig {
    /// True when no models are configured (the block is inert).
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// The registered model names, in order (WOR-1683): each serve
    /// entry's name plus its LoRA adapter names (WOR-1673), since a
    /// request may address an adapter directly. The provider's
    /// `models:` list is derived from this when `serve:` is present.
    /// Errors on a nameless raw reference or a duplicate name (base or
    /// adapter).
    pub fn model_names(&self) -> Result<Vec<String>, String> {
        let mut names = Vec::with_capacity(self.models.len());
        let mut seen = std::collections::HashSet::new();
        for entry in &self.models {
            let name = entry.effective_name()?;
            if !seen.insert(name.clone()) {
                return Err(format!("duplicate serve model name '{name}'"));
            }
            names.push(name);
            for adapter in &entry.lora_adapters {
                if !seen.insert(adapter.name.clone()) {
                    return Err(format!(
                        "duplicate serve model name '{}' (LoRA adapter)",
                        adapter.name
                    ));
                }
                names.push(adapter.name.clone());
            }
        }
        Ok(names)
    }

    /// Validate the whole `serve:` block at config-load / `plan` time
    /// so a bad block is rejected before boot rather than failing at a
    /// request. Checks (WOR-1683 / WOR-1684 / WOR-1681):
    /// - model names are unique and no raw `hf:`/`file:` ref leaks in
    ///   without an explicit `name` (via [`Self::model_names`]);
    /// - every `keep_alive` parses as a duration;
    /// - each `engines` entry is coherent: a container launch needs a
    ///   pinned image (no `:latest`, no untagged).
    pub fn validate(&self) -> Result<(), String> {
        // Names: unique, no nameless raw refs.
        self.model_names()?;
        // keep_alive durations parse.
        for e in &self.models {
            if let Some(ka) = &e.keep_alive {
                if crate::launch::parse_duration(ka).is_none() {
                    return Err(format!(
                        "serve model '{}' has an invalid keep_alive '{ka}'",
                        e.model
                    ));
                }
            }
        }
        // Engine provisioning coherence.
        for (kind, prov) in &self.engines {
            if prov.launch == EngineLaunchMethod::Container {
                if prov.image.is_none() {
                    return Err(format!(
                        "engine {kind:?} uses container launch but names no image"
                    ));
                }
                if !prov.image_is_pinned() {
                    return Err(format!(
                        "engine {kind:?} image is not pinned (avoid :latest / untagged): {:?}",
                        prov.image
                    ));
                }
            }
        }
        Ok(())
    }
}

/// What the environment offers, for the plan-time engine doctor
/// (WOR-1684). The runtime fills this from `PATH` lookups + GPU probe;
/// the report logic ([`EngineDoctor::for_entry`]) is pure so it is
/// testable against a synthetic environment with no real box.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineEnv {
    /// The `vllm` binary is on `PATH`.
    pub vllm_on_path: bool,
    /// The `llama-server` binary is on `PATH`.
    pub llama_server_on_path: bool,
    /// A container runtime (docker/podman) is available.
    pub container_runtime: bool,
    /// At least one GPU was discovered.
    pub gpu_present: bool,
}

/// One serve entry's engine resolution + whether the box can run it,
/// reported by `sbproxy plan` before anything spawns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineDoctor {
    /// The registered model name (or the raw `model` when unnamed).
    pub model: String,
    /// The engine `auto`/forced resolved to.
    pub resolved: EngineKind,
    /// The one-line reason for the resolution.
    pub reason: String,
    /// Whether the resolved engine's binary is available on the box.
    pub runnable: bool,
    /// A note when not runnable (what is missing).
    pub blocker: Option<String>,
}

impl EngineDoctor {
    /// Diagnose one serve entry against the environment. `is_gguf` is
    /// whether the resolved weights are GGUF (from the fit planner /
    /// catalog); the caller knows it, the doctor does not fetch.
    pub fn for_entry(entry: &ServeEntry, is_gguf: bool, env: &EngineEnv) -> Self {
        let resolved = entry.engine.resolve(is_gguf, env.container_runtime);
        let reason = entry
            .engine
            .resolve_reason(is_gguf, env.container_runtime)
            .to_string();
        let (runnable, blocker) = match resolved {
            EngineKind::LlamaCpp => (
                env.llama_server_on_path,
                (!env.llama_server_on_path).then(|| "llama-server not found on PATH".to_string()),
            ),
            EngineKind::Vllm => {
                // vLLM runs from PATH or a container; either satisfies.
                let ok = env.vllm_on_path || env.container_runtime;
                (
                    ok,
                    (!ok).then(|| {
                        "vLLM needs the `vllm` binary on PATH or a container runtime".to_string()
                    }),
                )
            }
            EngineKind::Embedded => {
                // The in-process engine needs no binary; it needs the
                // `embedded` feature compiled into this build (WOR-1658).
                let compiled = cfg!(feature = "embedded");
                (
                    compiled,
                    (!compiled).then(|| {
                        "engine: embedded needs a build with --features embedded".to_string()
                    }),
                )
            }
        };
        Self {
            model: entry
                .effective_name()
                .unwrap_or_else(|_| entry.model.clone()),
            resolved,
            reason,
            runnable,
            blocker,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_serve_block_parses() {
        let cfg: ModelHostConfig = serde_yaml::from_str(
            "\
models:
  - model: qwen3-32b
",
        )
        .expect("parse");
        assert_eq!(cfg.models.len(), 1);
        assert_eq!(cfg.models[0].model, "qwen3-32b");
        // Defaults: engine resolves at boot, so config default is Auto.
        assert_eq!(cfg.models[0].engine, EngineChoice::Auto);
        assert_eq!(cfg.eviction, EvictionPolicy::Lru);
        // A plain catalog id is its own model name.
        assert_eq!(cfg.models[0].effective_name().unwrap(), "qwen3-32b");
    }

    #[test]
    fn full_serve_block_parses() {
        let cfg: ModelHostConfig = serde_yaml::from_str(
            "\
cache_dir: /var/lib/sbproxy/models
cache_budget_gib: 500
eviction: never
models:
  - model: hf:Org/Repo:Q4_K_M
    engine: llama_cpp
    keep_alive: 30m
    max_context: 8192
    extra_args: [\"--flash-attn\"]
",
        )
        .expect("parse");
        assert_eq!(cfg.eviction, EvictionPolicy::Never);
        let e = &cfg.models[0];
        assert_eq!(e.engine, EngineChoice::LlamaCpp);
        assert_eq!(e.keep_alive.as_deref(), Some("30m"));
        assert_eq!(e.max_context, Some(8192));
        assert_eq!(e.extra_args, vec!["--flash-attn"]);
    }

    #[test]
    fn engine_binary_names() {
        assert_eq!(EngineKind::Vllm.binary_name(), "vllm");
        assert_eq!(EngineKind::LlamaCpp.binary_name(), "llama-server");
        assert_eq!(EngineKind::Embedded.binary_name(), "embedded");
    }

    #[test]
    fn unknown_engine_is_rejected() {
        let r: Result<ModelHostConfig, _> =
            serde_yaml::from_str("models:\n  - model: x\n    engine: sglang\n");
        assert!(
            r.is_err(),
            "engine is an allowlisted enum; sglang must reject"
        );
    }

    #[test]
    fn lora_dynamic_vs_static_and_capacity() {
        // WOR-1673: max_loras below the adapter count pages dynamically;
        // unset (or >= count) preloads all.
        let dyn_cfg: ModelHostConfig = serde_yaml::from_str(
            "models:\n  - model: base\n    max_loras: 1\n    lora_adapters:\n      - name: a\n        source: hf:o/a\n      - name: b\n        source: hf:o/b\n",
        )
        .unwrap();
        let e = &dyn_cfg.models[0];
        assert!(e.dynamic_lora());
        assert_eq!(e.lora_capacity(), 1);

        let static_cfg: ModelHostConfig = serde_yaml::from_str(
            "models:\n  - model: base\n    lora_adapters:\n      - name: a\n        source: hf:o/a\n      - name: b\n        source: hf:o/b\n",
        )
        .unwrap();
        let s = &static_cfg.models[0];
        assert!(!s.dynamic_lora());
        assert_eq!(s.lora_capacity(), 2);
    }

    #[test]
    fn embedded_engine_resolves_and_is_in_process() {
        // WOR-1658: `engine: embedded` parses, is a forced choice (Auto
        // never picks it), and marks the in-process launch path.
        let cfg: ModelHostConfig =
            serde_yaml::from_str("models:\n  - model: qwen3-0.6b\n    engine: embedded\n")
                .expect("embedded parses");
        assert_eq!(cfg.models[0].engine, EngineChoice::Embedded);
        assert_eq!(
            EngineChoice::Embedded.resolve(false, true),
            EngineKind::Embedded
        );
        assert!(EngineKind::Embedded.is_in_process());
        assert!(!EngineKind::Vllm.is_in_process());
        assert!(!EngineKind::LlamaCpp.is_in_process());
    }

    #[test]
    fn embedded_doctor_gated_on_feature() {
        // The plan-time doctor reports an embedded model as runnable only
        // when the `embedded` feature is compiled; otherwise it blocks
        // with a clear rebuild hint (WOR-1658).
        let cfg: ModelHostConfig =
            serde_yaml::from_str("models:\n  - model: qwen3-0.6b\n    engine: embedded\n").unwrap();
        let env = EngineEnv::default();
        let doc = EngineDoctor::for_entry(&cfg.models[0], false, &env);
        if cfg!(feature = "embedded") {
            assert!(doc.runnable);
        } else {
            assert!(!doc.runnable);
            assert!(doc
                .blocker
                .as_deref()
                .unwrap()
                .contains("--features embedded"));
        }
    }

    #[test]
    fn serving_knobs_parse() {
        let cfg: ModelHostConfig = serde_yaml::from_str(
            "\
models:
  - model: qwen3-8b
    speculative:
      method: draft_model
      draft_model: Qwen/Qwen3-0.6B
      num_speculative_tokens: 4
    chunked_prefill:
      target_ttft_ms: 250
    lora_adapters:
      - name: support-bot
        source: hf:acme/support-lora
      - name: sql-helper
        source: /models/sql-lora
",
        )
        .expect("parse");
        let e = &cfg.models[0];
        let spec = e.speculative.as_ref().unwrap();
        assert_eq!(spec.method, SpecMethod::DraftModel);
        assert_eq!(spec.draft_model.as_deref(), Some("Qwen/Qwen3-0.6B"));
        assert_eq!(spec.num_speculative_tokens, 4);
        assert_eq!(e.chunked_prefill.unwrap().target_ttft_ms, Some(250));
        assert_eq!(e.lora_adapters.len(), 2);
        assert_eq!(e.lora_adapters[0].name, "support-bot");
    }

    #[test]
    fn spec_defaults_to_ngram_five_tokens() {
        let cfg: ModelHostConfig =
            serde_yaml::from_str("models:\n  - model: x\n    speculative: {}\n").expect("parse");
        let spec = cfg.models[0].speculative.as_ref().unwrap();
        assert_eq!(spec.method, SpecMethod::Ngram);
        assert_eq!(spec.num_speculative_tokens, 5);
    }

    // --- WOR-1663: config-spawn surface guards ---

    #[test]
    fn no_arbitrary_command_field() {
        // The config type has no `cmd`/`command`/`program`/`binary`
        // field, so config cannot name an executable. A YAML that
        // tries to smuggle one is a deserialize error (unknown field
        // is not silently accepted into ServeEntry), or at minimum
        // does not become a runnable command. We assert the type
        // simply has no such surface: a serialized default ServeEntry
        // carries only the known keys.
        let e = ServeEntry {
            model: "qwen3-8b".into(),
            name: None,
            engine: EngineChoice::Vllm,
            keep_alive: None,
            max_context: None,
            extra_args: vec![],
            kv_quant: KvCacheQuant::Auto,
            speculative: None,
            chunked_prefill: None,
            lora_adapters: vec![],
            pinned: false,
            tool_call_parser: None,
            swap_space_gib: None,
            cpu_offload_gib: None,
            max_loras: None,
        };
        let json = serde_json::to_value(&e).expect("serialize");
        let obj = json.as_object().expect("object");
        for forbidden in ["cmd", "command", "program", "binary", "exec", "shell"] {
            assert!(
                !obj.contains_key(forbidden),
                "ServeEntry must not expose a `{forbidden}` field"
            );
        }
        // The only executable-selecting key is the allowlisted enum.
        assert!(obj.contains_key("engine"));
    }

    #[test]
    fn extra_args_are_opaque_argv_not_shell() {
        // extra_args must be preserved verbatim as individual argv
        // elements. Shell metacharacters are data, never interpreted:
        // the runtime passes each element as one arg, so there is no
        // shell to expand `$(...)`, `;`, `&&`, or a redirect.
        let cfg: ModelHostConfig = serde_yaml::from_str(
            "models:\n  - model: x\n    extra_args:\n      - \"--flag=$(rm -rf /)\"\n      - \"; curl evil\"\n      - \"&& reboot\"\n",
        )
        .expect("parse");
        let args = &cfg.models[0].extra_args;
        assert_eq!(args.len(), 3);
        // Stored verbatim, one element each, not split on the shell
        // metacharacters, proving they are argv values not a command line.
        assert_eq!(args[0], "--flag=$(rm -rf /)");
        assert_eq!(args[1], "; curl evil");
        assert_eq!(args[2], "&& reboot");
    }

    #[test]
    fn engine_kind_maps_to_a_fixed_binary_only() {
        // The engine-to-binary mapping is closed: every EngineKind
        // resolves to one hard-coded binary name, so config chooses
        // among a fixed set and can never inject an executable path.
        for (kind, expect) in [
            (EngineKind::Vllm, "vllm"),
            (EngineKind::LlamaCpp, "llama-server"),
            (EngineKind::Embedded, "embedded"),
        ] {
            assert_eq!(kind.binary_name(), expect);
        }
    }

    // --- WOR-1683: named serve entries ---

    #[test]
    fn name_defaults_to_catalog_id_and_hf_ref_requires_name() {
        let cfg: ModelHostConfig = serde_yaml::from_str(
            "\
models:
  - model: qwen3-14b
  - model: hf:Qwen/Qwen3-8B-GGUF:Q4_K_M
    name: local-coder
",
        )
        .expect("parse");
        assert_eq!(cfg.models[0].effective_name().unwrap(), "qwen3-14b");
        assert_eq!(cfg.models[1].effective_name().unwrap(), "local-coder");
        assert_eq!(
            cfg.model_names().unwrap(),
            vec!["qwen3-14b".to_string(), "local-coder".to_string()]
        );
    }

    #[test]
    fn nameless_hf_ref_is_a_plan_error() {
        let cfg: ModelHostConfig =
            serde_yaml::from_str("models:\n  - model: hf:Qwen/Qwen3-8B:Q4_K_M\n").expect("parse");
        assert!(cfg.models[0].effective_name().is_err());
        assert!(cfg.model_names().is_err());
    }

    #[test]
    fn duplicate_names_rejected() {
        let cfg: ModelHostConfig = serde_yaml::from_str(
            "\
models:
  - model: qwen3-14b
  - model: hf:Org/Other:Q4
    name: qwen3-14b
",
        )
        .expect("parse");
        let err = cfg.model_names().unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn same_weights_two_names_two_contexts() {
        // The same catalog model served twice under different names /
        // context lengths (WOR-1683 acceptance).
        let cfg: ModelHostConfig = serde_yaml::from_str(
            "\
models:
  - model: qwen3-14b
    name: qwen-short
    max_context: 8192
  - model: qwen3-14b
    name: qwen-long
    max_context: 131072
",
        )
        .expect("parse");
        assert_eq!(
            cfg.model_names().unwrap(),
            vec!["qwen-short".to_string(), "qwen-long".to_string()]
        );
    }

    // --- WOR-1684: engine auto-resolution + provisioning + doctor ---

    #[test]
    fn engine_auto_resolves_by_format_and_runtime() {
        // GGUF -> llama.cpp regardless of runtime.
        assert_eq!(EngineChoice::Auto.resolve(true, true), EngineKind::LlamaCpp);
        // safetensors + container runtime -> vLLM.
        assert_eq!(EngineChoice::Auto.resolve(false, true), EngineKind::Vllm);
        // safetensors but no container runtime -> llama.cpp (zero-dep).
        assert_eq!(
            EngineChoice::Auto.resolve(false, false),
            EngineKind::LlamaCpp
        );
        // A forced choice ignores the environment.
        assert_eq!(EngineChoice::Vllm.resolve(true, false), EngineKind::Vllm);
    }

    #[test]
    fn engines_block_parses_and_pins_images() {
        let cfg: ModelHostConfig = serde_yaml::from_str(
            "\
engines:
  vllm:
    launch: container
    image: vllm/vllm-openai:v0.24.0
models:
  - model: qwen3-14b
",
        )
        .expect("parse");
        let vllm = cfg.engines.get(&EngineKind::Vllm).unwrap();
        assert_eq!(vllm.launch, EngineLaunchMethod::Container);
        assert!(vllm.image_is_pinned());
        // :latest and untagged are not pinned.
        let bad = EngineProvisioning {
            launch: EngineLaunchMethod::Container,
            image: Some("vllm/vllm-openai:latest".into()),
        };
        assert!(!bad.image_is_pinned());
        let untagged = EngineProvisioning {
            launch: EngineLaunchMethod::Container,
            image: Some("vllm/vllm-openai".into()),
        };
        assert!(!untagged.image_is_pinned());
        // A digest is pinned.
        let digest = EngineProvisioning {
            launch: EngineLaunchMethod::Container,
            image: Some("vllm/vllm-openai@sha256:abc123".into()),
        };
        assert!(digest.image_is_pinned());
    }

    #[test]
    fn validate_accepts_a_good_block_and_rejects_bad_ones() {
        // Good: unique names, valid keep_alive, pinned container image.
        let good: ModelHostConfig = serde_yaml::from_str(
            "\
engines:
  vllm:
    launch: container
    image: vllm/vllm-openai:v0.24.0
models:
  - model: qwen3-14b
    keep_alive: 30m
  - model: hf:Org/Coder:Q4
    name: coder
",
        )
        .expect("parse");
        assert!(good.validate().is_ok());

        // Duplicate names.
        let dup: ModelHostConfig = serde_yaml::from_str(
            "models:\n  - model: qwen3-14b\n  - model: hf:O/R:Q4\n    name: qwen3-14b\n",
        )
        .unwrap();
        assert!(dup.validate().unwrap_err().contains("duplicate"));

        // Nameless raw ref.
        let nameless: ModelHostConfig =
            serde_yaml::from_str("models:\n  - model: hf:Org/Repo:Q4\n").unwrap();
        assert!(nameless.validate().is_err());

        // Bad keep_alive.
        let bad_ka: ModelHostConfig =
            serde_yaml::from_str("models:\n  - model: qwen3-14b\n    keep_alive: soon\n").unwrap();
        assert!(bad_ka.validate().unwrap_err().contains("keep_alive"));

        // Container engine with an unpinned image.
        let latest: ModelHostConfig = serde_yaml::from_str(
            "engines:\n  vllm:\n    launch: container\n    image: vllm/vllm-openai:latest\nmodels:\n  - model: qwen3-14b\n",
        )
        .unwrap();
        assert!(latest.validate().unwrap_err().contains("pinned"));

        // Container engine with no image.
        let noimg: ModelHostConfig = serde_yaml::from_str(
            "engines:\n  vllm:\n    launch: container\nmodels:\n  - model: qwen3-14b\n",
        )
        .unwrap();
        assert!(noimg.validate().unwrap_err().contains("no image"));
    }

    #[test]
    fn engine_doctor_reports_resolution_and_blockers() {
        let entry: ServeEntry = serde_yaml::from_str("model: qwen3-14b\nname: q\n").expect("entry");
        // Box with only llama-server, no container runtime: auto +
        // GGUF resolves to llama.cpp and is runnable.
        let env = EngineEnv {
            vllm_on_path: false,
            llama_server_on_path: true,
            container_runtime: false,
            gpu_present: true,
        };
        let d = EngineDoctor::for_entry(&entry, true, &env);
        assert_eq!(d.resolved, EngineKind::LlamaCpp);
        assert!(d.runnable);
        assert!(d.reason.contains("llama_cpp"));

        // Box with nothing: safetensors + no runtime -> llama.cpp, and
        // llama-server is absent, so it is not runnable with a blocker.
        let bare = EngineEnv::default();
        let d2 = EngineDoctor::for_entry(&entry, false, &bare);
        assert!(!d2.runnable);
        assert!(d2.blocker.is_some());
    }
}
