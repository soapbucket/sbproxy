// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! GPU fit planner (WOR-1654).
//!
//! Answers "which quant of this model fits this GPU, and will it
//! actually run on this card." Two failure modes it must prevent:
//! picking a quant whose weights + KV cache do not fit VRAM, and
//! picking a quant the card's compute capability cannot execute (a
//! Turing T4 has no FP8 or Marlin kernels, so an FP8 pick that "fits"
//! by size would still fail at load). So the gate is
//! capability-aware, not just size-aware.
//!
//! Everything here is pure and CPU-testable. GPU discovery is behind
//! the [`GpuProbe`] trait; tests drive it with [`StaticGpuProbe`]
//! synthetic descriptors (a T4 that refuses FP8, an L4 that accepts
//! it). The real NVML/Metal/AMD probes implement the same trait in a
//! later phase and change none of this math.

use serde::{Deserialize, Serialize};

/// GPU vendor, enough to route discovery and reason about kernels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GpuVendor {
    /// NVIDIA (CUDA); `compute_capability` is meaningful.
    Nvidia,
    /// Apple Silicon (Metal, unified memory).
    Apple,
    /// AMD (ROCm).
    Amd,
    /// CPU-only or an unrecognized device.
    Cpu,
}

/// A discovered GPU. Capability, not just capacity: `compute_capability`
/// and `supports_fp8` gate which quants can run, independent of whether
/// they fit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GpuDescriptor {
    /// Stable device index for logs and metric labels.
    pub index: u32,
    /// Vendor.
    pub vendor: GpuVendor,
    /// Human-readable name, e.g. `Tesla T4`, `NVIDIA L4`.
    pub name: String,
    /// Total device memory in bytes.
    pub total_vram_bytes: u64,
    /// Free device memory in bytes at probe time.
    pub free_vram_bytes: u64,
    /// CUDA compute capability as `(major, minor)`, e.g. `(7, 5)` for
    /// Turing (T4), `(8, 9)` for Ada (L4). `None` for non-NVIDIA.
    pub compute_capability: Option<(u32, u32)>,
    /// Whether the card has usable FP8 tensor-core kernels. Turing
    /// (7.5) does not; Ada (8.9) and Hopper (9.0+) do.
    pub supports_fp8: bool,
}

impl GpuDescriptor {
    /// A synthetic NVIDIA T4 (16 GiB, Turing 7.5, no FP8): the
    /// low-end cloud-GPU floor the epic certifies against.
    pub fn t4() -> Self {
        Self {
            index: 0,
            vendor: GpuVendor::Nvidia,
            name: "Tesla T4".to_string(),
            total_vram_bytes: 16 * GIB,
            free_vram_bytes: 15 * GIB,
            compute_capability: Some((7, 5)),
            supports_fp8: false,
        }
    }

    /// A synthetic NVIDIA L4 (24 GiB, Ada 8.9, FP8-capable).
    pub fn l4() -> Self {
        Self {
            index: 0,
            vendor: GpuVendor::Nvidia,
            name: "NVIDIA L4".to_string(),
            total_vram_bytes: 24 * GIB,
            free_vram_bytes: 23 * GIB,
            compute_capability: Some((8, 9)),
            supports_fp8: true,
        }
    }
}

/// One GiB in bytes.
pub const GIB: u64 = 1024 * 1024 * 1024;

/// A source of GPU descriptors. The real implementations (NVML,
/// Metal, ROCm) live in a GPU-feature-gated phase; this trait keeps
/// the planner testable with synthetic hardware.
pub trait GpuProbe: Send + Sync {
    /// Enumerate the visible GPUs. An empty vec means CPU-only.
    fn probe(&self) -> Vec<GpuDescriptor>;
}

/// A fixed list of descriptors, for tests and CPU-only deployments.
#[derive(Debug, Clone, Default)]
pub struct StaticGpuProbe {
    /// The descriptors this probe reports.
    pub gpus: Vec<GpuDescriptor>,
}

impl StaticGpuProbe {
    /// Build a probe reporting exactly these GPUs.
    pub fn new(gpus: Vec<GpuDescriptor>) -> Self {
        Self { gpus }
    }
}

impl GpuProbe for StaticGpuProbe {
    fn probe(&self) -> Vec<GpuDescriptor> {
        self.gpus.clone()
    }
}

/// A quant classified into what the capability gate cares about:
/// its bytes-per-weight and whether it needs FP8 kernels. The catalog
/// carries quant *names* (`Q4_K_M`, `FP8`, `AWQ`, `bf16`); this maps a
/// name to its class.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Quant {
    /// 8-bit floating point. Needs FP8 tensor-core kernels.
    Fp8,
    /// 16-bit (bf16/fp16) full-ish precision.
    F16,
    /// 4-bit weight-only (GPTQ/AWQ/GGUF Q4). Runs anywhere.
    Int4,
    /// 5-bit GGUF (Q5_*).
    Int5,
    /// 8-bit weight-only (int8/GGUF Q8). Not FP8.
    Int8,
}

impl Quant {
    /// Classify a catalog quant name. Unknown names default to
    /// [`Quant::F16`] (the conservative, always-runnable-if-it-fits
    /// assumption).
    pub fn classify(name: &str) -> Self {
        let n = name.to_ascii_lowercase();
        if n.contains("fp8") {
            Quant::Fp8
        } else if n.starts_with("q4")
            || n.contains("int4")
            || n.contains("awq")
            || n.contains("gptq")
        {
            Quant::Int4
        } else if n.starts_with("q5") {
            Quant::Int5
        } else if n.starts_with("q8") || n.contains("int8") {
            Quant::Int8
        } else {
            // bf16, fp16, f16, "bf16", safetensors default.
            Quant::F16
        }
    }

    /// Bytes per weight parameter for this quant. GGUF K-quants carry
    /// block overhead, so the 4/5/8-bit figures are the effective
    /// per-weight cost, not the nominal bit width / 8.
    pub fn bytes_per_weight(self) -> f64 {
        match self {
            Quant::F16 => 2.0,
            Quant::Fp8 => 1.0,
            Quant::Int8 => 1.06, // Q8_0 ~= 8.5 bits/weight
            Quant::Int5 => 0.69, // Q5_K_M ~= 5.5 bits/weight
            Quant::Int4 => 0.56, // Q4_K_M ~= 4.5 bits/weight
        }
    }

    /// Bytes per element for the KV cache in this quant regime. KV is
    /// kept in f16 for every weight quant except FP8 serving, which
    /// commonly keeps an fp8 KV cache.
    pub fn kv_bytes_per_element(self) -> f64 {
        match self {
            Quant::Fp8 => 1.0,
            _ => 2.0,
        }
    }
}

/// The model shape the planner needs, parsed from model metadata
/// (`config.json` for safetensors, the GGUF header for GGUF). Only
/// the fields the VRAM math uses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelMetadata {
    /// Total parameter count.
    pub params: u64,
    /// Transformer layer count.
    pub layers: u64,
    /// Number of key/value attention heads (GQA: < attention heads).
    pub kv_heads: u64,
    /// Per-head dimension.
    pub head_dim: u64,
    /// Max context length the weights declare.
    pub max_context: u64,
}

impl ModelMetadata {
    /// Parse the subset the planner needs from a HF `config.json`
    /// value. Falls back sensibly: `num_key_value_heads` defaults to
    /// `num_attention_heads` (no GQA), `head_dim` to
    /// `hidden_size / num_attention_heads`.
    pub fn from_hf_config(v: &serde_json::Value, params: u64) -> Option<Self> {
        let layers = v.get("num_hidden_layers")?.as_u64()?;
        let attn_heads = v.get("num_attention_heads")?.as_u64()?;
        let kv_heads = v
            .get("num_key_value_heads")
            .and_then(|x| x.as_u64())
            .unwrap_or(attn_heads);
        let hidden = v.get("hidden_size").and_then(|x| x.as_u64());
        let head_dim = v
            .get("head_dim")
            .and_then(|x| x.as_u64())
            .or_else(|| hidden.map(|h| h / attn_heads))?;
        let max_context = v
            .get("max_position_embeddings")
            .and_then(|x| x.as_u64())
            .unwrap_or(8192);
        Some(Self {
            params,
            layers,
            kv_heads,
            head_dim,
            max_context,
        })
    }

    /// Weight bytes for a given quant.
    pub fn weight_bytes(&self, quant: Quant) -> f64 {
        self.params as f64 * quant.bytes_per_weight()
    }

    /// KV-cache bytes for `seq_len` tokens in this quant regime:
    /// `2 (K+V) x layers x kv_heads x head_dim x bytes x seq_len`.
    pub fn kv_bytes(&self, quant: Quant, seq_len: u64) -> f64 {
        2.0 * self.layers as f64
            * self.kv_heads as f64
            * self.head_dim as f64
            * quant.kv_bytes_per_element()
            * seq_len as f64
    }

    /// Total estimated VRAM for weights + KV at `seq_len`, plus a
    /// framework overhead factor (CUDA context, activations, engine
    /// working set). `overhead` is a multiplier on the sum, e.g.
    /// 1.15 for a 15% headroom.
    pub fn vram_estimate_bytes(&self, quant: Quant, seq_len: u64, overhead: f64) -> f64 {
        (self.weight_bytes(quant) + self.kv_bytes(quant, seq_len)) * overhead
    }
}

/// A chosen plan: the quant that fits and runs, with the estimate.
#[derive(Debug, Clone, PartialEq)]
pub struct FitPlan {
    /// The selected quant name (as it appeared in the candidate list).
    pub quant_name: String,
    /// Its capability class.
    pub quant: Quant,
    /// Estimated VRAM in bytes at the planned context length.
    pub estimated_vram_bytes: u64,
    /// The GPU it was fit to.
    pub gpu_index: u32,
    /// Context length the estimate assumed.
    pub seq_len: u64,
}

/// Why no quant could be fit.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum FitError {
    /// No GPU was visible at all.
    #[error(
        "no GPU available; the model host needs a GPU (or an embedded/CPU engine, a later phase)"
    )]
    NoGpu,
    /// Candidate quants all failed the capability gate on this card.
    #[error("no candidate quant runs on {gpu}: {detail}")]
    Incompatible {
        /// GPU name.
        gpu: String,
        /// What was rejected and why (e.g. FP8 on a Turing card).
        detail: String,
    },
    /// Candidate quants all fit the capability gate but not VRAM.
    #[error("no candidate quant fits {free_gib:.1} GiB free on {gpu}: smallest estimate was {smallest_gib:.1} GiB")]
    TooLarge {
        /// GPU name.
        gpu: String,
        /// Free VRAM in GiB.
        free_gib: f64,
        /// Smallest candidate estimate in GiB.
        smallest_gib: f64,
    },
}

/// Default framework-overhead multiplier on weights + KV.
pub const DEFAULT_OVERHEAD: f64 = 1.15;

/// Pick the best quant for a model on a specific GPU.
///
/// `candidates` is the catalog's quant list, most-preferred first.
/// The planner walks it in order and returns the first quant that
/// (a) the card can run (capability gate) and (b) fits free VRAM at
/// `seq_len` with `overhead` headroom. Capability rejections and size
/// rejections are reported distinctly so the operator sees "your T4
/// cannot run FP8" rather than a generic "does not fit".
pub fn plan_fit(
    gpu: &GpuDescriptor,
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
) -> Result<FitPlan, FitError> {
    let seq_len = seq_len.min(meta.max_context).max(1);
    let free = gpu.free_vram_bytes as f64;

    let mut capability_reject: Option<String> = None;
    let mut smallest_fit_candidate: Option<f64> = None;

    for name in candidates {
        let quant = Quant::classify(name);
        // Capability gate: FP8 needs FP8 kernels.
        if quant == Quant::Fp8 && !gpu.supports_fp8 {
            capability_reject.get_or_insert_with(|| {
                format!(
                    "{name} needs FP8 kernels but {} (compute {}) has none",
                    gpu.name,
                    gpu.compute_capability
                        .map(|(a, b)| format!("{a}.{b}"))
                        .unwrap_or_else(|| "n/a".to_string())
                )
            });
            continue;
        }
        let est = meta.vram_estimate_bytes(quant, seq_len, overhead);
        smallest_fit_candidate = Some(match smallest_fit_candidate {
            Some(s) => s.min(est),
            None => est,
        });
        if est <= free {
            return Ok(FitPlan {
                quant_name: name.clone(),
                quant,
                estimated_vram_bytes: est as u64,
                gpu_index: gpu.index,
                seq_len,
            });
        }
    }

    // Nothing fit. Distinguish "cannot run" from "does not fit".
    match (smallest_fit_candidate, capability_reject) {
        (None, Some(detail)) => Err(FitError::Incompatible {
            gpu: gpu.name.clone(),
            detail,
        }),
        (Some(smallest), _) => Err(FitError::TooLarge {
            gpu: gpu.name.clone(),
            free_gib: free / GIB as f64,
            smallest_gib: smallest / GIB as f64,
        }),
        (None, None) => Err(FitError::Incompatible {
            gpu: gpu.name.clone(),
            detail: "no candidate quants provided".to_string(),
        }),
    }
}

/// Plan a fit across every GPU a probe reports, choosing the GPU with
/// the most free VRAM. Returns [`FitError::NoGpu`] when the probe is
/// empty.
pub fn plan_fit_auto(
    probe: &dyn GpuProbe,
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
) -> Result<FitPlan, FitError> {
    let mut gpus = probe.probe();
    if gpus.is_empty() {
        return Err(FitError::NoGpu);
    }
    gpus.sort_by_key(|g| std::cmp::Reverse(g.free_vram_bytes));
    // Try GPUs in free-VRAM order; return the first successful fit,
    // else the error from the most-free GPU (the most informative).
    let mut first_err = None;
    for gpu in &gpus {
        match plan_fit(gpu, meta, candidates, seq_len, overhead) {
            Ok(plan) => return Ok(plan),
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    Err(first_err.unwrap_or(FitError::NoGpu))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A ~14B dense model (Qwen3-14B-ish): 40 layers, 8 KV heads, 128
    // head dim, 40960 max context.
    fn meta_14b() -> ModelMetadata {
        ModelMetadata {
            params: 14_000_000_000,
            layers: 40,
            kv_heads: 8,
            head_dim: 128,
            max_context: 40960,
        }
    }

    #[test]
    fn quant_classification() {
        assert_eq!(Quant::classify("FP8"), Quant::Fp8);
        assert_eq!(Quant::classify("Q4_K_M"), Quant::Int4);
        assert_eq!(Quant::classify("AWQ"), Quant::Int4);
        assert_eq!(Quant::classify("Q5_K_M"), Quant::Int5);
        assert_eq!(Quant::classify("Q8_0"), Quant::Int8);
        assert_eq!(Quant::classify("bf16"), Quant::F16);
    }

    #[test]
    fn t4_refuses_fp8_and_picks_int4() {
        // FP8 first, then Q4. The T4 has no FP8 kernels, so the
        // planner must skip FP8 and land on Q4 (which fits 16 GiB).
        let plan = plan_fit(
            &GpuDescriptor::t4(),
            &meta_14b(),
            &["FP8".into(), "Q4_K_M".into()],
            4096,
            DEFAULT_OVERHEAD,
        )
        .expect("Q4 should fit a T4");
        assert_eq!(plan.quant, Quant::Int4);
        assert_eq!(plan.quant_name, "Q4_K_M");
    }

    #[test]
    fn l4_accepts_fp8() {
        // The L4 has FP8 kernels; 14B FP8 (~14 GiB weights) fits 24 GiB.
        let plan = plan_fit(
            &GpuDescriptor::l4(),
            &meta_14b(),
            &["FP8".into(), "Q4_K_M".into()],
            4096,
            DEFAULT_OVERHEAD,
        )
        .expect("FP8 should fit an L4");
        assert_eq!(plan.quant, Quant::Fp8);
    }

    #[test]
    fn fp8_only_on_t4_is_incompatible_not_too_large() {
        // A model offered ONLY in FP8, on a T4: the error must name
        // the capability gap, not a size problem.
        let err = plan_fit(
            &GpuDescriptor::t4(),
            &meta_14b(),
            &["FP8".into()],
            4096,
            DEFAULT_OVERHEAD,
        )
        .unwrap_err();
        match err {
            FitError::Incompatible { detail, .. } => assert!(detail.contains("FP8")),
            other => panic!("expected Incompatible, got {other:?}"),
        }
    }

    #[test]
    fn oversized_model_reports_too_large() {
        // A 200B model in Q4 (~112 GiB) cannot fit a 16 GiB T4.
        let huge = ModelMetadata {
            params: 200_000_000_000,
            layers: 96,
            kv_heads: 8,
            head_dim: 128,
            max_context: 8192,
        };
        let err = plan_fit(
            &GpuDescriptor::t4(),
            &huge,
            &["Q4_K_M".into()],
            4096,
            DEFAULT_OVERHEAD,
        )
        .unwrap_err();
        assert!(matches!(err, FitError::TooLarge { .. }));
    }

    #[test]
    fn kv_grows_with_context() {
        let m = meta_14b();
        let short = m.kv_bytes(Quant::F16, 4096);
        let long = m.kv_bytes(Quant::F16, 40960);
        assert!(long > short * 9.0, "KV should scale ~linearly with seq_len");
    }

    #[test]
    fn seq_len_is_clamped_to_max_context() {
        // Asking for more than the model supports clamps to max_context.
        let plan = plan_fit(
            &GpuDescriptor::l4(),
            &meta_14b(),
            &["Q4_K_M".into()],
            1_000_000,
            DEFAULT_OVERHEAD,
        )
        .expect("fits");
        assert_eq!(plan.seq_len, 40960);
    }

    #[test]
    fn auto_picks_gpu_with_most_free_vram() {
        let mut t4 = GpuDescriptor::t4();
        t4.index = 0;
        t4.free_vram_bytes = 4 * GIB; // nearly full
        let mut l4 = GpuDescriptor::l4();
        l4.index = 1;
        let probe = StaticGpuProbe::new(vec![t4, l4]);
        let plan = plan_fit_auto(
            &probe,
            &meta_14b(),
            &["Q4_K_M".into()],
            4096,
            DEFAULT_OVERHEAD,
        )
        .expect("fits on the L4");
        assert_eq!(plan.gpu_index, 1);
    }

    #[test]
    fn no_gpu_is_an_error() {
        let probe = StaticGpuProbe::default();
        let err = plan_fit_auto(
            &probe,
            &meta_14b(),
            &["Q4_K_M".into()],
            4096,
            DEFAULT_OVERHEAD,
        )
        .unwrap_err();
        assert_eq!(err, FitError::NoGpu);
    }

    #[test]
    fn config_json_parse_with_gqa() {
        let cfg = serde_json::json!({
            "num_hidden_layers": 40,
            "num_attention_heads": 40,
            "num_key_value_heads": 8,
            "hidden_size": 5120,
            "max_position_embeddings": 40960
        });
        let m = ModelMetadata::from_hf_config(&cfg, 14_000_000_000).expect("parse");
        assert_eq!(m.layers, 40);
        assert_eq!(m.kv_heads, 8);
        assert_eq!(m.head_dim, 128); // 5120 / 40
        assert_eq!(m.max_context, 40960);
    }

    #[test]
    fn config_json_defaults_head_dim_and_kv_heads() {
        // No GQA field, no explicit head_dim: kv_heads defaults to
        // attention heads, head_dim to hidden/heads.
        let cfg = serde_json::json!({
            "num_hidden_layers": 32,
            "num_attention_heads": 32,
            "hidden_size": 4096
        });
        let m = ModelMetadata::from_hf_config(&cfg, 8_000_000_000).expect("parse");
        assert_eq!(m.kv_heads, 32);
        assert_eq!(m.head_dim, 128);
        assert_eq!(m.max_context, 8192); // fallback
    }
}
