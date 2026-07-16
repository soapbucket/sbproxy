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
    /// Device compute-engine utilization as a fraction in `[0, 1]`.
    /// `None` means the platform probe could not report it.
    #[serde(default)]
    pub compute_utilization: Option<f64>,
    /// Occupied device memory as a fraction in `[0, 1]`, derived only
    /// from total and free memory. `None` means total memory was zero.
    #[serde(default)]
    pub memory_occupancy: Option<f64>,
    /// CUDA compute capability as `(major, minor)`, e.g. `(7, 5)` for
    /// Turing (T4), `(8, 9)` for Ada (L4). `None` for non-NVIDIA.
    pub compute_capability: Option<(u32, u32)>,
    /// Whether the card has usable FP8 tensor-core kernels. Turing
    /// (7.5) does not; Ada (8.9) and Hopper (9.0+) do.
    pub supports_fp8: bool,
    /// Peak memory bandwidth in GB/s, when known. Decode is
    /// memory-bandwidth bound, so this drives the throughput estimate
    /// ([`estimate_throughput`]). `None` when the probe cannot report
    /// it (throughput estimation is then skipped).
    #[serde(default)]
    pub mem_bandwidth_gbps: Option<f64>,
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
            compute_utilization: None,
            memory_occupancy: memory_occupancy(16 * GIB, 15 * GIB),
            compute_capability: Some((7, 5)),
            supports_fp8: false,
            mem_bandwidth_gbps: Some(320.0),
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
            compute_utilization: None,
            memory_occupancy: memory_occupancy(24 * GIB, 23 * GIB),
            compute_capability: Some((8, 9)),
            supports_fp8: true,
            mem_bandwidth_gbps: Some(300.0),
        }
    }
}

/// Derive occupied-memory fraction from total and free bytes.
pub fn memory_occupancy(total_bytes: u64, free_bytes: u64) -> Option<f64> {
    (total_bytes > 0).then(|| total_bytes.saturating_sub(free_bytes) as f64 / total_bytes as f64)
}

/// One GiB in bytes.
pub const GIB: u64 = 1024 * 1024 * 1024;

/// Whether a CUDA compute capability has usable FP8 tensor-core
/// kernels. FP8 arrived with Ada Lovelace (8.9) and Hopper (9.0);
/// Ampere (8.0 A100, 8.6) and Turing (7.5 T4) do not have it. A pure
/// helper so the capability gate is identical whether the descriptor
/// comes from a synthetic probe or a real NVML read.
pub fn fp8_supported(cc: (u32, u32)) -> bool {
    let (major, minor) = cc;
    major > 8 || (major == 8 && minor >= 9)
}

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

    /// Parse the shape from a GGUF file header (WOR-1654).
    ///
    /// GGUF stores the model shape as architecture-prefixed metadata
    /// (`<arch>.block_count`, `<arch>.attention.head_count[_kv]`,
    /// `<arch>.embedding_length`, `<arch>.context_length`). We match
    /// on the key suffix so it works across architectures without
    /// knowing the arch string. Only the header is needed, so a caller
    /// can pass just the first N KiB of a large GGUF (a ranged read).
    /// Returns `None` on a bad magic, an unsupported version, a
    /// truncated header, or a missing required field. `params_fallback`
    /// is used when the file has no `general.parameter_count`.
    pub fn from_gguf(bytes: &[u8], params_fallback: u64) -> Option<Self> {
        let mut r = GgufReader::new(bytes);
        if r.take(4)? != b"GGUF" {
            return None;
        }
        let version = r.u32()?;
        if !(2..=3).contains(&version) {
            return None; // only GGUF v2/v3 layouts are handled
        }
        let _tensor_count = r.u64()?;
        let kv_count = r.u64()?;

        let mut layers = None;
        let mut head_count = None;
        let mut head_count_kv = None;
        let mut embedding_length = None;
        let mut context_length = None;
        let mut key_length = None;
        let mut param_count = None;

        for _ in 0..kv_count {
            let key = r.gguf_string()?;
            let vtype = r.u32()?;
            // Advance past the value. The outer `?` aborts on a
            // truncated/malformed value (cursor cannot advance); the
            // inner Option is `Some(int)` only for an unsigned scalar
            // and `None` for a string/array/float we skip over.
            let scalar = r.read_value(vtype)?;
            match () {
                _ if key.ends_with(".block_count") => layers = scalar,
                _ if key.ends_with(".attention.head_count_kv") => head_count_kv = scalar,
                _ if key.ends_with(".attention.head_count") => head_count = scalar,
                _ if key.ends_with(".embedding_length") => embedding_length = scalar,
                _ if key.ends_with(".context_length") => context_length = scalar,
                _ if key.ends_with(".attention.key_length") => key_length = scalar,
                _ if key == "general.parameter_count" => param_count = scalar,
                _ => {}
            }
        }

        let layers = layers?;
        let heads = head_count?;
        let kv_heads = head_count_kv.unwrap_or(heads);
        let head_dim = key_length.or_else(|| embedding_length.map(|e| e / heads.max(1)))?;
        Some(Self {
            params: param_count.unwrap_or(params_fallback),
            layers,
            kv_heads,
            head_dim,
            max_context: context_length.unwrap_or(8192),
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

    /// KV-cache bytes at `seq_len` using an explicit bytes-per-element
    /// (from a KV-quant override) instead of the weight quant's
    /// default. `2 x layers x kv_heads x head_dim x bytes x seq_len`.
    pub fn kv_bytes_with(&self, kv_bytes_per_element: f64, seq_len: u64) -> f64 {
        2.0 * self.layers as f64
            * self.kv_heads as f64
            * self.head_dim as f64
            * kv_bytes_per_element
            * seq_len as f64
    }

    /// VRAM estimate with a KV-quant override (WOR-1676): weights at
    /// the weight quant, KV at `kv_bytes_per_element`. `None` for the
    /// KV bpe falls back to the weight quant's default KV dtype, which
    /// is exactly [`Self::vram_estimate_bytes`].
    pub fn vram_estimate_with_kv(
        &self,
        quant: Quant,
        kv_bytes_per_element: Option<f64>,
        seq_len: u64,
        overhead: f64,
    ) -> f64 {
        match kv_bytes_per_element {
            None => self.vram_estimate_bytes(quant, seq_len, overhead),
            Some(bpe) => (self.weight_bytes(quant) + self.kv_bytes_with(bpe, seq_len)) * overhead,
        }
    }
}

/// A little-endian, bounds-checked cursor over a GGUF header. Every
/// read returns `None` past the end, so a truncated or malformed file
/// (including a ranged read that stopped mid-value) fails cleanly
/// instead of panicking.
struct GgufReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> GgufReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A GGUF string: u64 length prefix then that many bytes.
    fn gguf_string(&mut self) -> Option<String> {
        let len = self.u64()? as usize;
        let bytes = self.take(len)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    /// Byte width of a fixed-size GGUF scalar value type, or `None`
    /// for the variable-length types (string=8, array=9) handled
    /// separately.
    fn scalar_width(vtype: u32) -> Option<usize> {
        match vtype {
            0 | 1 | 7 => Some(1), // u8, i8, bool
            2 | 3 => Some(2),     // u16, i16
            4..=6 => Some(4),     // u32, i32, f32
            10..=12 => Some(8),   // u64, i64, f64
            _ => None,
        }
    }

    /// Advance the cursor past a value of `vtype`. Returns
    /// `Some(Some(n))` for an unsigned scalar (the shape value),
    /// `Some(None)` for a value skipped but well-formed (string,
    /// array, signed, float), and `None` when the buffer is too short
    /// to hold the value (truncation, which the caller treats as a
    /// hard parse failure).
    fn read_value(&mut self, vtype: u32) -> Option<Option<u64>> {
        match vtype {
            8 => {
                // string
                self.gguf_string()?;
                Some(None)
            }
            9 => {
                // array: elem type (u32) + count (u64) + elements
                let elem_type = self.u32()?;
                let count = self.u64()? as usize;
                for _ in 0..count {
                    if elem_type == 8 {
                        self.gguf_string()?;
                    } else if elem_type == 9 {
                        // Nested arrays do not occur in model-shape
                        // metadata; refuse rather than recurse blindly.
                        return None;
                    } else {
                        let w = Self::scalar_width(elem_type)?;
                        self.take(w)?;
                    }
                }
                Some(None)
            }
            _ => {
                let w = Self::scalar_width(vtype)?;
                let bytes = self.take(w)?;
                // Only unsigned integer types carry a shape value.
                let v = match vtype {
                    0 => Some(bytes[0] as u64),
                    2 => Some(u16::from_le_bytes([bytes[0], bytes[1]]) as u64),
                    4 => Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64),
                    10 => Some(u64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ])),
                    _ => None, // signed / float / bool: not a shape field
                };
                Some(v)
            }
        }
    }
}

/// A chosen plan: the quant that fits and runs, with the estimate.
#[derive(Debug, Clone, PartialEq)]
pub struct FitPlan {
    /// The selected quant name (as it appeared in the candidate list).
    pub quant_name: String,
    /// Its capability class.
    pub quant: Quant,
    /// Estimated VRAM in bytes on each device at the planned context length.
    pub estimated_vram_bytes: u64,
    /// The GPU(s) it was fit to: one for single-GPU, the tensor-parallel group
    /// for multi-GPU. Mirrors `memory.device_indexes`.
    pub gpu_indexes: Vec<u32>,
    /// Context length the estimate assumed.
    pub seq_len: u64,
    /// Exact components used by admission and status.
    pub memory: MemoryEstimate,
}

impl FitPlan {
    /// Tensor-parallel degree: the number of GPUs the plan spans.
    pub fn tp_degree(&self) -> usize {
        self.gpu_indexes.len().max(1)
    }

    /// The first GPU in the plan.
    pub fn primary_gpu(&self) -> u32 {
        self.gpu_indexes.first().copied().unwrap_or(0)
    }
}

/// Device-specific memory requirement for one deployment generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MemoryEstimate {
    /// Worker-local device indexes this generation occupies: one for a
    /// single-GPU deployment, the tensor-parallel group for multi-GPU. Every
    /// device in the set carries the same per-device requirement below, because
    /// tensor parallelism shards weights and KV evenly across identical cards.
    pub device_indexes: Vec<u32>,
    /// Quantized model weight bytes, per device (full weights / tp degree).
    pub weight_bytes: u64,
    /// KV-cache bytes at the selected context and dtype, per device.
    pub kv_bytes: u64,
    /// Framework, activation, and device-context overhead, per device.
    pub runtime_overhead_bytes: u64,
    /// Configured headroom added after runtime overhead, per device.
    pub safety_margin_bytes: u64,
    /// Sum of every component above: the bytes reserved on each device in the set.
    pub total_bytes: u64,
}

impl MemoryEstimate {
    /// Construct a single-device compatibility estimate when only a total is known.
    pub fn from_total(device_index: u32, total_bytes: u64) -> Self {
        Self {
            device_indexes: vec![device_index],
            weight_bytes: total_bytes,
            kv_bytes: 0,
            runtime_overhead_bytes: 0,
            safety_margin_bytes: 0,
            total_bytes,
        }
    }

    /// The first device in the set. Reservation bookkeeping that predates
    /// multi-device selection keys on this.
    pub fn primary_device(&self) -> u32 {
        self.device_indexes.first().copied().unwrap_or(0)
    }

    /// Tensor-parallel degree: the number of devices this generation spans.
    pub fn tp_degree(&self) -> usize {
        self.device_indexes.len().max(1)
    }
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
    /// A fixed tensor-parallel degree or replica count cannot be placed on
    /// the available devices (wrong device count, a degree that does not
    /// divide the KV heads, or more replicas than the node can host).
    #[error("{0}")]
    Unsatisfiable(String),
}

/// Default framework-overhead multiplier on weights + KV.
pub const DEFAULT_OVERHEAD: f64 = 1.15;

/// A rough throughput prediction for a model + quant on a GPU
/// (WOR-1670). Decode is memory-bandwidth bound, so single-stream
/// tokens/sec is the achievable bandwidth divided by the bytes read
/// per generated token (the weights, at the chosen quant). A real
/// profiled model (Vidur/Dooly) would be more accurate; this roofline
/// estimate needs only device specs and catches "this quant fits but
/// will be painfully slow" before an engine ever starts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThroughputEstimate {
    /// Estimated single-stream decode tokens/sec.
    pub decode_tokens_per_sec: f64,
    /// The bytes read per generated token (weights at this quant).
    pub bytes_per_token: u64,
    /// How many concurrent sequences the free VRAM can hold KV for at
    /// the planned context (a coarse safe-batch ceiling).
    pub safe_max_batch: u64,
}

/// Fraction of peak memory bandwidth a real engine sustains during
/// decode. Empirically 60-80%; use a conservative midpoint.
pub const DECODE_BANDWIDTH_EFFICIENCY: f64 = 0.7;

/// Estimate decode throughput and a safe batch ceiling for a model +
/// quant on a GPU. Returns `None` when the GPU does not report memory
/// bandwidth. Note: for MoE models this is pessimistic, since decode
/// reads only the active experts, not all weights; treat it as a
/// lower bound.
pub fn estimate_throughput(
    gpu: &GpuDescriptor,
    meta: &ModelMetadata,
    quant: Quant,
    seq_len: u64,
) -> Option<ThroughputEstimate> {
    let bw_gbps = gpu.mem_bandwidth_gbps?;
    let bytes_per_token = meta.weight_bytes(quant).max(1.0);
    let bw_bytes_per_sec = bw_gbps * 1e9 * DECODE_BANDWIDTH_EFFICIENCY;
    let decode_tps = bw_bytes_per_sec / bytes_per_token;

    // KV per sequence at the planned context; how many fit in the
    // VRAM left after the weights.
    let seq_len = seq_len.min(meta.max_context).max(1);
    let kv_per_seq = meta.kv_bytes(quant, seq_len).max(1.0);
    let free_after_weights = (gpu.free_vram_bytes as f64 - bytes_per_token).max(0.0);
    let safe_max_batch = (free_after_weights / kv_per_seq).floor().max(0.0) as u64;

    Some(ThroughputEstimate {
        decode_tokens_per_sec: decode_tps,
        bytes_per_token: bytes_per_token as u64,
        safe_max_batch,
    })
}

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
    plan_fit_kv(gpu, meta, candidates, seq_len, overhead, None)
}

/// Like [`plan_fit`], but with a KV-cache quantization lever
/// (WOR-1676). `kv_bytes_per_element` overrides the bytes-per-KV-element
/// in the fit math: `Some(0.5)` for int4 KV, `Some(1.0)` for fp8/int8,
/// `None` to follow the weight quant's default. Quantizing the KV cache
/// shrinks the KV term, so a card that could not hold a long context at
/// f16 KV may fit it here. Only the fit math changes; making the engine
/// use that KV dtype is [`crate::launch::build_launch_spec`]'s
/// `--kv-cache-dtype`.
pub fn plan_fit_kv(
    gpu: &GpuDescriptor,
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
    kv_bytes_per_element: Option<f64>,
) -> Result<FitPlan, FitError> {
    plan_fit_kv_with_margin(
        gpu,
        meta,
        candidates,
        seq_len,
        overhead,
        0.0,
        kv_bytes_per_element,
    )
}

/// Like [`plan_fit_kv`], with an explicit additive safety margin.
#[allow(clippy::too_many_arguments)]
pub fn plan_fit_kv_with_margin(
    gpu: &GpuDescriptor,
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
    safety_margin: f64,
    kv_bytes_per_element: Option<f64>,
) -> Result<FitPlan, FitError> {
    plan_fit_kv_with_margin_and_concurrency(
        gpu,
        meta,
        candidates,
        seq_len,
        overhead,
        safety_margin,
        kv_bytes_per_element,
        1,
    )
}

/// Like [`plan_fit_kv_with_margin`], with KV capacity for every concurrent sequence.
#[allow(clippy::too_many_arguments)]
pub fn plan_fit_kv_with_margin_and_concurrency(
    gpu: &GpuDescriptor,
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
    safety_margin: f64,
    kv_bytes_per_element: Option<f64>,
    concurrency: u32,
) -> Result<FitPlan, FitError> {
    plan_fit_sharded(
        gpu,
        std::slice::from_ref(&gpu.index),
        meta,
        candidates,
        seq_len,
        overhead,
        safety_margin,
        kv_bytes_per_element,
        concurrency,
    )
}

/// The fit core: place a model on a homogeneous set of `devices` at
/// tensor-parallel degree `devices.len()`. Weights and the KV cache both shard
/// evenly across the group, so the per-device requirement is the full estimate
/// divided by the degree, checked against `gpu` (which the caller sets to the
/// tightest device in the group: the one with the least free VRAM). A
/// single-element `devices` is the ordinary single-GPU plan.
#[allow(clippy::too_many_arguments)]
fn plan_fit_sharded(
    gpu: &GpuDescriptor,
    devices: &[u32],
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
    safety_margin: f64,
    kv_bytes_per_element: Option<f64>,
    concurrency: u32,
) -> Result<FitPlan, FitError> {
    let seq_len = seq_len.min(meta.max_context).max(1);
    let free = gpu.free_vram_bytes as f64;
    let tp = devices.len().max(1) as f64;

    if concurrency == 0 {
        return Err(FitError::Incompatible {
            gpu: gpu.name.clone(),
            detail: "concurrency must be positive".to_string(),
        });
    }
    if !safety_margin.is_finite() || !(0.0..1.0).contains(&safety_margin) {
        return Err(FitError::Incompatible {
            gpu: gpu.name.clone(),
            detail: "safety margin must be finite and in [0, 1)".to_string(),
        });
    }

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
        let weight_bytes = meta.weight_bytes(quant) / tp;
        let kv_bytes_per_sequence = match kv_bytes_per_element {
            Some(bytes) => meta.kv_bytes_with(bytes, seq_len),
            None => meta.kv_bytes(quant, seq_len),
        };
        let kv_bytes = kv_bytes_per_sequence * f64::from(concurrency) / tp;
        let base = weight_bytes + kv_bytes;
        let runtime_overhead = base * (overhead.max(1.0) - 1.0);
        let subtotal = base + runtime_overhead;
        let margin = subtotal * safety_margin;
        let est = subtotal + margin;
        smallest_fit_candidate = Some(match smallest_fit_candidate {
            Some(s) => s.min(est),
            None => est,
        });
        if est <= free {
            let weight_bytes = weight_bytes as u64;
            let kv_bytes = kv_bytes as u64;
            let runtime_overhead_bytes = runtime_overhead as u64;
            let safety_margin_bytes = margin as u64;
            let total_bytes = weight_bytes
                .saturating_add(kv_bytes)
                .saturating_add(runtime_overhead_bytes)
                .saturating_add(safety_margin_bytes);
            let memory = MemoryEstimate {
                device_indexes: devices.to_vec(),
                weight_bytes,
                kv_bytes,
                runtime_overhead_bytes,
                safety_margin_bytes,
                total_bytes,
            };
            return Ok(FitPlan {
                quant_name: name.clone(),
                quant,
                estimated_vram_bytes: memory.total_bytes,
                gpu_indexes: devices.to_vec(),
                seq_len,
                memory,
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
    plan_fit_auto_kv(probe, meta, candidates, seq_len, overhead, None)
}

/// Like [`plan_fit_auto`], with the KV-quant lever (see [`plan_fit_kv`]).
pub fn plan_fit_auto_kv(
    probe: &dyn GpuProbe,
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
    kv_bytes_per_element: Option<f64>,
) -> Result<FitPlan, FitError> {
    plan_fit_auto_kv_with_margin(
        probe,
        meta,
        candidates,
        seq_len,
        overhead,
        0.0,
        kv_bytes_per_element,
    )
}

/// Like [`plan_fit_auto_kv`], with an explicit additive safety margin.
#[allow(clippy::too_many_arguments)]
pub fn plan_fit_auto_kv_with_margin(
    probe: &dyn GpuProbe,
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
    safety_margin: f64,
    kv_bytes_per_element: Option<f64>,
) -> Result<FitPlan, FitError> {
    plan_fit_auto_kv_with_margin_and_concurrency(
        probe,
        meta,
        candidates,
        seq_len,
        overhead,
        safety_margin,
        kv_bytes_per_element,
        1,
        None,
    )
}

/// Like [`plan_fit_auto_kv_with_margin`], with KV capacity for concurrent sequences.
#[allow(clippy::too_many_arguments)]
pub fn plan_fit_auto_kv_with_margin_and_concurrency(
    probe: &dyn GpuProbe,
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
    safety_margin: f64,
    kv_bytes_per_element: Option<f64>,
    concurrency: u32,
    forced_tp: Option<usize>,
) -> Result<FitPlan, FitError> {
    plan_fit_over_set(
        &probe.probe(),
        meta,
        candidates,
        seq_len,
        overhead,
        safety_margin,
        kv_bytes_per_element,
        concurrency,
        forced_tp,
    )
}

/// Plan a fit across a set of GPUs, searching tensor-parallel degrees.
///
/// Tries tp = 1, 2, 4, 8 in order and returns the smallest degree at which a
/// candidate quant fits, since tensor parallelism costs interconnect bandwidth
/// and a single card is always cheaper. A tp group must be homogeneous
/// (identical model and total VRAM) and tp must divide the model's KV heads
/// evenly. Weights and the KV cache both shard across the group, so a model too
/// large for any one card can fit on several. Cross-node tensor parallelism is
/// a non-goal; every device here is on one host.
#[allow(clippy::too_many_arguments)]
pub fn plan_fit_over_set(
    gpus: &[GpuDescriptor],
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
    safety_margin: f64,
    kv_bytes_per_element: Option<f64>,
    concurrency: u32,
    forced_tp: Option<usize>,
) -> Result<FitPlan, FitError> {
    if gpus.is_empty() {
        return Err(FitError::NoGpu);
    }
    // A fixed degree must be a sane, satisfiable request before searching.
    if let Some(tp) = forced_tp {
        if tp == 0 {
            return Err(FitError::Unsatisfiable(
                "tensor_parallel must be at least 1".to_string(),
            ));
        }
        if tp > 1 && !meta.kv_heads.is_multiple_of(tp as u64) {
            return Err(FitError::Unsatisfiable(format!(
                "tensor_parallel {tp} does not divide the model's {} KV heads",
                meta.kv_heads
            )));
        }
        if gpus.len() < tp {
            return Err(FitError::Unsatisfiable(format!(
                "tensor_parallel {tp} needs {tp} devices, {} available",
                gpus.len()
            )));
        }
    }
    let mut first_err: Option<FitError> = None;

    let forced_slot;
    let tp_candidates: &[usize] = match forced_tp {
        Some(tp) => {
            forced_slot = [tp];
            &forced_slot
        }
        None => &[1usize, 2, 4, 8],
    };
    for &tp in tp_candidates {
        if tp == 1 {
            // Single GPU: try cards in free-VRAM order, the cheapest placement.
            let mut singles: Vec<&GpuDescriptor> = gpus.iter().collect();
            singles.sort_by_key(|g| std::cmp::Reverse(g.free_vram_bytes));
            for gpu in singles {
                match plan_fit_sharded(
                    gpu,
                    std::slice::from_ref(&gpu.index),
                    meta,
                    candidates,
                    seq_len,
                    overhead,
                    safety_margin,
                    kv_bytes_per_element,
                    concurrency,
                ) {
                    Ok(plan) => return Ok(plan),
                    Err(e) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    }
                }
            }
            continue;
        }
        // Tensor parallelism requires the KV heads to divide evenly across ranks.
        if !meta.kv_heads.is_multiple_of(tp as u64) {
            continue;
        }
        // Homogeneous classes keyed by (name, total VRAM): TP needs identical cards.
        let mut classes: std::collections::BTreeMap<(&str, u64), Vec<&GpuDescriptor>> =
            std::collections::BTreeMap::new();
        for gpu in gpus {
            classes
                .entry((gpu.name.as_str(), gpu.total_vram_bytes))
                .or_default()
                .push(gpu);
        }
        for members in classes.values() {
            if members.len() < tp {
                continue;
            }
            // The tp emptiest identical cards; the fit is gated on the tightest.
            let mut group: Vec<&GpuDescriptor> = members.clone();
            group.sort_by_key(|g| std::cmp::Reverse(g.free_vram_bytes));
            let group = &group[..tp];
            let min_free = group.iter().map(|g| g.free_vram_bytes).min().unwrap_or(0);
            let representative = GpuDescriptor {
                free_vram_bytes: min_free,
                ..group[0].clone()
            };
            let devices: Vec<u32> = group.iter().map(|g| g.index).collect();
            match plan_fit_sharded(
                &representative,
                &devices,
                meta,
                candidates,
                seq_len,
                overhead,
                safety_margin,
                kv_bytes_per_element,
                concurrency,
            ) {
                Ok(plan) => return Ok(plan),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
    }
    Err(first_err.unwrap_or_else(|| match forced_tp {
        Some(tp) => FitError::Unsatisfiable(format!(
            "no homogeneous group of {tp} identical devices has enough free VRAM"
        )),
        None => FitError::NoGpu,
    }))
}

/// Pack `replicas` replicas of one model onto disjoint device sets.
///
/// Each replica claims its own device set (of `tensor_parallel` size when
/// set, else the smallest degree that fits), and no two replicas share a
/// device, so replicas never contend for VRAM. Devices are consumed
/// greedily replica by replica; the first replica that cannot fit on the
/// remaining devices fails with a legible reason instead of silently
/// dropping replicas. Returns one [`FitPlan`] per replica.
#[allow(clippy::too_many_arguments)]
pub fn plan_replica_fits(
    gpus: &[GpuDescriptor],
    meta: &ModelMetadata,
    candidates: &[String],
    seq_len: u64,
    overhead: f64,
    safety_margin: f64,
    kv_bytes_per_element: Option<f64>,
    concurrency: u32,
    replicas: u32,
    tensor_parallel: Option<usize>,
) -> Result<Vec<FitPlan>, FitError> {
    let replicas = replicas.max(1) as usize;
    let mut remaining: Vec<GpuDescriptor> = gpus.to_vec();
    let mut plans = Vec::with_capacity(replicas);
    for replica in 0..replicas {
        let plan = plan_fit_over_set(
            &remaining,
            meta,
            candidates,
            seq_len,
            overhead,
            safety_margin,
            kv_bytes_per_element,
            concurrency,
            tensor_parallel,
        )
        .map_err(|error| {
            FitError::Unsatisfiable(format!(
                "cannot place replica {} of {replicas}: {error} ({} device(s) still free)",
                replica + 1,
                remaining.len()
            ))
        })?;
        let claimed: std::collections::BTreeSet<u32> = plan.gpu_indexes.iter().copied().collect();
        remaining.retain(|gpu| !claimed.contains(&gpu.index));
        plans.push(plan);
    }
    Ok(plans)
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

    // A ~0.6B model (Qwen3-0.6B-ish): small enough to serve on CPU / a
    // laptop's unified memory.
    fn meta_small() -> ModelMetadata {
        ModelMetadata {
            params: 600_000_000,
            layers: 28,
            kv_heads: 8,
            head_dim: 128,
            max_context: 32768,
        }
    }

    #[test]
    fn cpu_budget_admits_a_small_gguf_and_rejects_a_big_one() {
        // WOR-1800: a CPU-only host (no NVIDIA, no Metal) reports a
        // system-RAM budget through CpuProbe, and the fit planner admits
        // a small GGUF against it rather than returning NoGpu. An 8 GiB
        // CPU budget fits a 0.6B Q4 model, but not a 14B one.
        use crate::probe_cpu::CpuProbe;
        let probe = CpuProbe::with_budget(8 * GIB);
        let candidates = ["Q4_K_M".to_string()];

        let ok = plan_fit_auto(&probe, &meta_small(), &candidates, 4096, DEFAULT_OVERHEAD)
            .expect("a small Q4 model fits an 8 GiB CPU budget");
        assert_eq!(ok.quant, Quant::Int4);

        let too_big = plan_fit_auto(&probe, &meta_14b(), &candidates, 4096, DEFAULT_OVERHEAD);
        assert!(
            matches!(too_big, Err(FitError::TooLarge { .. })),
            "a 14B model must not fit an 8 GiB CPU budget: {too_big:?}"
        );
    }

    #[test]
    fn cpu_budget_refuses_fp8_by_capability_not_size() {
        // The CPU device reports no FP8 kernels, so an FP8-only model is
        // capability-refused (as on a T4), never silently admitted.
        use crate::probe_cpu::CpuProbe;
        let probe = CpuProbe::with_budget(64 * GIB);
        let err = plan_fit_auto(
            &probe,
            &meta_small(),
            &["FP8".to_string()],
            4096,
            DEFAULT_OVERHEAD,
        )
        .unwrap_err();
        assert!(
            matches!(err, FitError::Incompatible { .. }),
            "FP8 on CPU is a capability refusal: {err:?}"
        );
    }

    #[test]
    fn empty_cpu_budget_still_reports_no_gpu() {
        // Opting out (fraction 0) reverts to the pre-WOR-1800 behaviour:
        // no device, so admission returns NoGpu.
        use crate::probe_cpu::CpuProbe;
        let probe = CpuProbe::with_budget(0);
        let err = plan_fit_auto(
            &probe,
            &meta_small(),
            &["Q4_K_M".to_string()],
            4096,
            DEFAULT_OVERHEAD,
        )
        .unwrap_err();
        assert_eq!(err, FitError::NoGpu);
    }

    #[test]
    fn a_model_too_big_for_one_gpu_fits_across_a_homogeneous_pair() {
        // 14B at f16 needs ~26 GiB of weights, over one 24 GiB L4, but shards
        // across two L4s at tp=2.
        let mut a = GpuDescriptor::l4();
        a.index = 0;
        let mut b = GpuDescriptor::l4();
        b.index = 1;
        let candidates = ["F16".to_string()];

        let single = plan_fit_over_set(
            std::slice::from_ref(&a),
            &meta_14b(),
            &candidates,
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            None,
        );
        assert!(
            matches!(single, Err(FitError::TooLarge { .. })),
            "14B f16 must not fit one L4: {single:?}"
        );

        let pair = plan_fit_over_set(
            &[a.clone(), b.clone()],
            &meta_14b(),
            &candidates,
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            None,
        )
        .expect("14B f16 fits two L4 at tp=2");
        assert_eq!(pair.tp_degree(), 2);
        assert_eq!(pair.gpu_indexes, vec![0, 1]);
        assert_eq!(pair.memory.device_indexes, vec![0, 1]);
        // Weights shard, so each device holds roughly half.
        assert!(pair.memory.weight_bytes < 20 * GIB);
    }

    #[test]
    fn a_model_that_fits_one_gpu_stays_at_tp_1() {
        // The planner prefers the smallest degree: a model that fits one card is
        // never sharded, even with several available.
        let mut a = GpuDescriptor::l4();
        a.index = 0;
        let mut b = GpuDescriptor::l4();
        b.index = 1;
        let plan = plan_fit_over_set(
            &[a, b],
            &meta_small(),
            &["Q4_K_M".to_string()],
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            None,
        )
        .expect("0.6B fits one L4");
        assert_eq!(plan.tp_degree(), 1);
    }

    #[test]
    fn a_heterogeneous_pair_cannot_form_a_tp_group() {
        // Tensor parallelism needs identical cards, so a T4 + L4 pair cannot
        // shard the 14B model and it is rejected rather than run on a mix.
        let mut t4 = GpuDescriptor::t4();
        t4.index = 0;
        let mut l4 = GpuDescriptor::l4();
        l4.index = 1;
        let err = plan_fit_over_set(
            &[t4, l4],
            &meta_14b(),
            &["F16".to_string()],
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                FitError::TooLarge { .. } | FitError::Incompatible { .. }
            ),
            "a heterogeneous pair cannot host a tp group: {err:?}"
        );
    }

    #[test]
    fn tensor_parallel_degree_must_divide_the_kv_heads() {
        // KV heads that do not divide evenly forbid every power-of-two degree,
        // so even two identical big cards cannot admit the model.
        let mut meta = meta_14b();
        meta.kv_heads = 3;
        let mut a = GpuDescriptor::l4();
        a.index = 0;
        let mut b = GpuDescriptor::l4();
        b.index = 1;
        let err = plan_fit_over_set(
            &[a, b],
            &meta,
            &["F16".to_string()],
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, FitError::TooLarge { .. }),
            "kv_heads=3 forbids every power-of-two tp, so 14B stays unservable: {err:?}"
        );
    }

    #[test]
    fn fp8_capability_gate() {
        assert!(!fp8_supported((7, 5)), "Turing T4 has no FP8");
        assert!(!fp8_supported((8, 0)), "Ampere A100 has no FP8");
        assert!(!fp8_supported((8, 6)), "Ampere 8.6 has no FP8");
        assert!(fp8_supported((8, 9)), "Ada L4 has FP8");
        assert!(fp8_supported((9, 0)), "Hopper H100 has FP8");
        assert!(fp8_supported((10, 0)), "Blackwell has FP8");
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
    fn kv_quant_lets_a_long_context_fit() {
        // WOR-1676: at a long context the KV term dominates. A 14B model
        // with a 128k window does not fit the L4 at f16 KV (~21 GiB KV +
        // ~14 GiB FP8 weights > 24 GiB), but int4 KV (a quarter) brings
        // it back inside. The planner now spends that lever.
        let meta = ModelMetadata {
            params: 14_000_000_000,
            layers: 40,
            kv_heads: 8,
            head_dim: 128,
            max_context: 131072,
        };
        let long = 131072;
        let candidates = ["FP8".to_string()];
        let default = plan_fit(
            &GpuDescriptor::l4(),
            &meta,
            &candidates,
            long,
            DEFAULT_OVERHEAD,
        );
        let quantized = plan_fit_kv(
            &GpuDescriptor::l4(),
            &meta,
            &candidates,
            long,
            DEFAULT_OVERHEAD,
            Some(0.5),
        );
        assert!(
            default.is_err(),
            "long context should not fit at default KV"
        );
        assert!(
            quantized.is_ok(),
            "int4 KV should let the long context fit: {quantized:?}"
        );
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
    fn non_decode_modality_charges_no_kv() {
        // WOR-1908: an embedder holds no KV cache, so its fit must size on
        // weights + overhead only. A chat model at the same shape/context
        // reserves a positive KV term; the non-decode override zeroes it.
        use crate::catalog::Modality;
        let candidates = ["Q4_K_M".to_string()];
        let chat = plan_fit_kv(
            &GpuDescriptor::l4(),
            &meta_14b(),
            &candidates,
            40960,
            DEFAULT_OVERHEAD,
            Modality::Chat.kv_bytes_per_element_override(None),
        )
        .expect("chat fits");
        let embed = plan_fit_kv(
            &GpuDescriptor::l4(),
            &meta_14b(),
            &candidates,
            40960,
            DEFAULT_OVERHEAD,
            Modality::Embedding.kv_bytes_per_element_override(None),
        )
        .expect("embedder fits");
        assert!(chat.memory.kv_bytes > 0, "a chat model reserves KV");
        assert_eq!(embed.memory.kv_bytes, 0, "an embedder reserves no KV");
        assert!(
            embed.estimated_vram_bytes < chat.estimated_vram_bytes,
            "dropping KV shrinks the embedder estimate ({} vs {})",
            embed.estimated_vram_bytes,
            chat.estimated_vram_bytes
        );
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
        assert_eq!(plan.gpu_indexes, vec![1]);
        assert_eq!(plan.tp_degree(), 1);
    }

    #[test]
    fn throughput_decode_is_bandwidth_bound() {
        // 14B model at Q4 (~0.56 bytes/param -> ~7.84 GB/token read).
        // L4 at 300 GB/s * 0.7 efficiency = 210 GB/s effective.
        // decode tps ~= 210e9 / 7.84e9 ~= 26-27 tok/s.
        let est = estimate_throughput(&GpuDescriptor::l4(), &meta_14b(), Quant::Int4, 4096)
            .expect("L4 reports bandwidth");
        assert!(
            est.decode_tokens_per_sec > 15.0 && est.decode_tokens_per_sec < 45.0,
            "got {} tok/s",
            est.decode_tokens_per_sec
        );
        assert!(est.safe_max_batch >= 1, "should fit at least one sequence");
    }

    #[test]
    fn throughput_higher_for_smaller_quant() {
        // A smaller quant reads fewer bytes per token, so decode is faster.
        let q4 = estimate_throughput(&GpuDescriptor::l4(), &meta_14b(), Quant::Int4, 4096).unwrap();
        let f16 = estimate_throughput(&GpuDescriptor::l4(), &meta_14b(), Quant::F16, 4096).unwrap();
        assert!(q4.decode_tokens_per_sec > f16.decode_tokens_per_sec);
    }

    #[test]
    fn kv_quant_shrinks_the_estimate_and_fits_more_context() {
        // A model whose f16-KV estimate exceeds free VRAM should fit
        // once KV is quantized to int4 (0.5 bytes/element).
        let m = ModelMetadata {
            params: 14_000_000_000,
            layers: 40,
            kv_heads: 8,
            head_dim: 128,
            max_context: 131072,
        };
        // Long context so KV dominates.
        let seq = 131072;
        let f16 = m.vram_estimate_with_kv(Quant::Int4, None, seq, DEFAULT_OVERHEAD);
        let int4_kv = m.vram_estimate_with_kv(Quant::Int4, Some(0.5), seq, DEFAULT_OVERHEAD);
        assert!(int4_kv < f16, "int4 KV must be smaller than default KV");
        // The KV term is 4x smaller (2.0 -> 0.5), so the saving is large.
        assert!(f16 - int4_kv > 10.0 * GIB as f64);
    }

    #[test]
    fn throughput_none_without_bandwidth() {
        let mut gpu = GpuDescriptor::l4();
        gpu.mem_bandwidth_gbps = None;
        assert!(estimate_throughput(&gpu, &meta_14b(), Quant::Int4, 4096).is_none());
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

    // --- GGUF header parsing (WOR-1654) ---

    /// Build a minimal but valid GGUF v3 header with the given
    /// architecture-prefixed shape fields, plus one string KV and one
    /// array KV interleaved to prove the skip logic keeps the cursor
    /// aligned. All shape values are encoded as u32 (GGUF type 4).
    fn synth_gguf(
        arch: &str,
        layers: u32,
        heads: u32,
        kv_heads: u32,
        hidden: u32,
        ctx: u32,
    ) -> Vec<u8> {
        fn push_str(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u64).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        fn push_u32_kv(out: &mut Vec<u8>, key: &str, v: u32) {
            push_str(out, key);
            out.extend_from_slice(&4u32.to_le_bytes()); // type u32
            out.extend_from_slice(&v.to_le_bytes());
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"GGUF");
        out.extend_from_slice(&3u32.to_le_bytes()); // version
        out.extend_from_slice(&0u64.to_le_bytes()); // tensor_count
                                                    // KV count: 5 shape ints + arch string + a decoy string + a decoy array = 8.
        out.extend_from_slice(&8u64.to_le_bytes());
        // A string KV (general.architecture).
        push_str(&mut out, "general.architecture");
        out.extend_from_slice(&8u32.to_le_bytes()); // type string
        push_str(&mut out, arch);
        // Shape ints, arch-prefixed.
        push_u32_kv(&mut out, &format!("{arch}.block_count"), layers);
        push_u32_kv(&mut out, &format!("{arch}.attention.head_count"), heads);
        push_u32_kv(
            &mut out,
            &format!("{arch}.attention.head_count_kv"),
            kv_heads,
        );
        push_u32_kv(&mut out, &format!("{arch}.embedding_length"), hidden);
        push_u32_kv(&mut out, &format!("{arch}.context_length"), ctx);
        // A decoy string KV.
        push_str(&mut out, "general.name");
        out.extend_from_slice(&8u32.to_le_bytes());
        push_str(&mut out, "Test Model");
        // A decoy array KV (u32 array of 3) the parser must skip past.
        push_str(&mut out, "some.array");
        out.extend_from_slice(&9u32.to_le_bytes()); // type array
        out.extend_from_slice(&4u32.to_le_bytes()); // elem type u32
        out.extend_from_slice(&3u64.to_le_bytes()); // count
        for v in [1u32, 2, 3] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    #[test]
    fn gguf_header_parses_shape() {
        // arch qwen3, 40 layers, 40 heads, 8 kv heads, hidden 5120, ctx 40960.
        let bytes = synth_gguf("qwen3", 40, 40, 8, 5120, 40960);
        let m = ModelMetadata::from_gguf(&bytes, 14_000_000_000).expect("parse gguf");
        assert_eq!(m.layers, 40);
        assert_eq!(m.kv_heads, 8);
        assert_eq!(m.head_dim, 128); // 5120 / 40
        assert_eq!(m.max_context, 40960);
        assert_eq!(m.params, 14_000_000_000); // fallback (no parameter_count KV)
    }

    #[test]
    fn gguf_bad_magic_is_none() {
        let mut bytes = synth_gguf("llama", 32, 32, 8, 4096, 8192);
        bytes[0] = b'X';
        assert!(ModelMetadata::from_gguf(&bytes, 1).is_none());
    }

    #[test]
    fn gguf_truncated_header_is_none_not_panic() {
        let bytes = synth_gguf("llama", 32, 32, 8, 4096, 8192);
        // Cut the file mid-metadata: must return None, never panic.
        for cut in [4, 12, 24, bytes.len() / 2] {
            assert!(
                ModelMetadata::from_gguf(&bytes[..cut], 1).is_none(),
                "truncated at {cut} should be None"
            );
        }
    }

    #[test]
    fn gguf_missing_gqa_defaults_kv_to_heads() {
        // A header without head_count_kv: kv_heads should default to heads.
        // Rebuild with kv==heads and confirm.
        let bytes = synth_gguf("mistral", 32, 32, 32, 4096, 32768);
        let m = ModelMetadata::from_gguf(&bytes, 7_000_000_000).unwrap();
        assert_eq!(m.kv_heads, 32);
        assert_eq!(m.head_dim, 128);
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

    fn indexed_l4s(count: u32) -> Vec<GpuDescriptor> {
        (0..count)
            .map(|index| {
                let mut gpu = GpuDescriptor::l4();
                gpu.index = index;
                gpu
            })
            .collect()
    }

    #[test]
    fn a_forced_degree_pins_tensor_parallel_even_when_one_card_would_do() {
        // A 0.6B model fits one L4, but a pinned degree of two shards it
        // across both cards instead of picking the cheapest single-card fit.
        let gpus = indexed_l4s(2);
        let plan = plan_fit_over_set(
            &gpus,
            &meta_small(),
            &["Q4_K_M".to_string()],
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            Some(2),
        )
        .expect("0.6B pins to tp=2 across two L4");
        assert_eq!(plan.tp_degree(), 2);
        assert_eq!(plan.gpu_indexes, vec![0, 1]);
    }

    #[test]
    fn a_forced_degree_that_does_not_divide_kv_heads_is_unsatisfiable() {
        let mut meta = meta_14b();
        meta.kv_heads = 3;
        let gpus = indexed_l4s(2);
        let error = plan_fit_over_set(
            &gpus,
            &meta,
            &["F16".to_string()],
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            Some(2),
        )
        .unwrap_err();
        assert!(
            matches!(error, FitError::Unsatisfiable(_)),
            "tp=2 cannot divide 3 KV heads: {error:?}"
        );
    }

    #[test]
    fn a_forced_degree_larger_than_the_device_count_is_unsatisfiable() {
        let gpus = indexed_l4s(1);
        let error = plan_fit_over_set(
            &gpus,
            &meta_small(),
            &["Q4_K_M".to_string()],
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            Some(2),
        )
        .unwrap_err();
        assert!(
            matches!(error, FitError::Unsatisfiable(ref message) if message.contains("needs 2 devices")),
            "tp=2 needs two devices when only one is present",
        );
    }

    #[test]
    fn packing_replicas_assigns_disjoint_device_sets() {
        // Four single-card replicas take one distinct device each.
        let gpus = indexed_l4s(4);
        let plans = plan_replica_fits(
            &gpus,
            &meta_small(),
            &["Q4_K_M".to_string()],
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            4,
            Some(1),
        )
        .expect("four 0.6B replicas fit four L4");
        assert_eq!(plans.len(), 4);
        let mut devices: Vec<u32> = plans.iter().flat_map(|p| p.gpu_indexes.clone()).collect();
        devices.sort_unstable();
        assert_eq!(devices, vec![0, 1, 2, 3], "replicas claim distinct devices");

        // Two tp=2 replicas take two disjoint pairs.
        let pairs = plan_replica_fits(
            &gpus,
            &meta_14b(),
            &["F16".to_string()],
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            2,
            Some(2),
        )
        .expect("two 14B replicas fit four L4 at tp=2");
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].tp_degree(), 2);
        let mut paired: Vec<u32> = pairs.iter().flat_map(|p| p.gpu_indexes.clone()).collect();
        paired.sort_unstable();
        assert_eq!(paired, vec![0, 1, 2, 3], "the two pairs are disjoint");
    }

    #[test]
    fn packing_more_replicas_than_devices_fails_legibly() {
        // Four L4 at tp=2 host two replicas; a third has no devices left.
        let gpus = indexed_l4s(4);
        let error = plan_replica_fits(
            &gpus,
            &meta_14b(),
            &["F16".to_string()],
            4096,
            DEFAULT_OVERHEAD,
            0.0,
            None,
            1,
            4,
            Some(2),
        )
        .unwrap_err();
        assert!(
            matches!(error, FitError::Unsatisfiable(ref message)
                if message.contains("replica 3")),
            "the third replica cannot be placed: {error:?}"
        );
    }
}
