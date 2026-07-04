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
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    /// vLLM, the datacenter default, driven as a supervised
    /// subprocess over its OpenAI-compatible HTTP surface.
    #[default]
    Vllm,
    /// llama.cpp `llama-server`, the low-VRAM / GGUF / edge path.
    LlamaCpp,
}

impl EngineKind {
    /// The binary name looked up on `PATH` for this engine.
    pub fn binary_name(self) -> &'static str {
        match self {
            EngineKind::Vllm => "vllm",
            EngineKind::LlamaCpp => "llama-server",
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
    /// Engine to serve it with. Defaults to vLLM.
    #[serde(default)]
    pub engine: EngineKind,
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
}

impl ServeEntry {
    /// The parsed keep-alive idle timeout, or `None` when unset or
    /// unparseable. Uses the compact duration form (`30m`, `1h30m`).
    pub fn keep_alive_duration(&self) -> Option<std::time::Duration> {
        self.keep_alive
            .as_deref()
            .and_then(crate::launch::parse_duration)
    }
}

impl ModelHostConfig {
    /// True when no models are configured (the block is inert).
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
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
        // Defaults.
        assert_eq!(cfg.models[0].engine, EngineKind::Vllm);
        assert_eq!(cfg.eviction, EvictionPolicy::Lru);
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
        assert_eq!(e.engine, EngineKind::LlamaCpp);
        assert_eq!(e.keep_alive.as_deref(), Some("30m"));
        assert_eq!(e.max_context, Some(8192));
        assert_eq!(e.extra_args, vec!["--flash-attn"]);
    }

    #[test]
    fn engine_binary_names() {
        assert_eq!(EngineKind::Vllm.binary_name(), "vllm");
        assert_eq!(EngineKind::LlamaCpp.binary_name(), "llama-server");
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
            engine: EngineKind::Vllm,
            keep_alive: None,
            max_context: None,
            extra_args: vec![],
            kv_quant: KvCacheQuant::Auto,
            speculative: None,
            chunked_prefill: None,
            lora_adapters: vec![],
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
        ] {
            assert_eq!(kind.binary_name(), expect);
        }
    }
}
