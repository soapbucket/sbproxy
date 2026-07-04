// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Utility-based KV-cache tiering (WOR-1687).
//!
//! The [`crate::residency::ResidencyManager`] decides which whole
//! models are resident. This is the finer layer beneath it: which KV
//! *contexts* live at full precision in GPU, which are compressed in
//! GPU, which spill to CPU, and which go to disk, scored by a utility
//! function rather than evicted whole. It follows EvicPress
//! (2512.14946): each context's utility rises with reuse frequency and
//! latency sensitivity, and under pressure the lowest-utility context
//! is demoted a tier (full -> quantized -> CPU -> disk) instead of
//! dropped. The KV-quant compression axis is the shipped
//! [`crate::config::KvCacheQuant`] lever (WOR-1676).
//!
//! Pure and deterministic, like the residency manager: it decides
//! against a set of context descriptors with a logical clock; the
//! actual GPU/CPU/disk moves are runtime.

/// Where a context's KV cache lives, in descending desirability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvTier {
    /// Full-precision KV resident in GPU (fastest, largest).
    GpuFull,
    /// Quantized KV resident in GPU (still on-device, ~1/4 the bytes).
    GpuQuant,
    /// KV offloaded to CPU RAM (fast wake, off the GPU).
    Cpu,
    /// KV serialized to disk (coldest, cheapest).
    Disk,
}

/// One KV context the policy places.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvContext {
    /// Stable id (a session / prefix key).
    pub id: String,
    /// Full-precision KV size in bytes.
    pub kv_bytes: u64,
    /// How many times this context has been reused (frequency).
    pub reuse_count: u64,
    /// Logical last-used tick; higher is more recent.
    pub last_used: u64,
    /// Whether this context is on a latency-sensitive (interactive)
    /// path, which raises its utility (TTFT matters more).
    pub ttft_sensitive: bool,
}

impl KvContext {
    /// The EvicPress-style utility score: frequency scaled by latency
    /// sensitivity, with recency as a tiebreaker. Higher stays hotter.
    fn utility(&self) -> u128 {
        let sensitivity = if self.ttft_sensitive { 2 } else { 1 };
        // reuse dominates; recency only breaks ties among equal reuse.
        (self.reuse_count as u128 * sensitivity) << 20 | (self.last_used as u128 & 0xF_FFFF)
    }
}

/// The placement of one context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierDecision {
    /// Context id.
    pub id: String,
    /// The tier it was placed in.
    pub tier: KvTier,
}

/// Byte budgets for the GPU and CPU tiers (disk is unbounded). The
/// policy fills GPU-full first by utility, compresses the next band
/// into GPU-quant, spills the next to CPU, and sends the coldest to
/// disk.
#[derive(Debug, Clone, Copy)]
pub struct KvTieringPolicy {
    /// GPU VRAM available for KV, in bytes.
    pub gpu_budget_bytes: u64,
    /// CPU RAM available for offloaded KV, in bytes.
    pub cpu_budget_bytes: u64,
    /// Bytes-per-element ratio of quantized vs full KV (e.g. 0.25 for
    /// int4 over f16). Used to size the GPU-quant band.
    pub quant_ratio: f64,
}

impl Default for KvTieringPolicy {
    fn default() -> Self {
        Self {
            gpu_budget_bytes: 0,
            cpu_budget_bytes: 0,
            quant_ratio: 0.25,
        }
    }
}

impl KvTieringPolicy {
    /// Place every context into a tier by descending utility. The
    /// hottest contexts stay full-precision in GPU until the budget is
    /// tight; the next band is quantized (still in GPU) while it fits;
    /// then CPU while its budget lasts; the coldest go to disk. A
    /// reused (higher-utility) context promotes on the next call, and a
    /// cooled one demotes, without evicting the whole model.
    pub fn place(&self, contexts: &[KvContext]) -> Vec<TierDecision> {
        let mut ordered: Vec<&KvContext> = contexts.iter().collect();
        // Descending utility; stable so equal-utility keeps input order.
        ordered.sort_by_key(|c| std::cmp::Reverse(c.utility()));

        let mut gpu_used = 0u64;
        let mut cpu_used = 0u64;
        let mut out = Vec::with_capacity(contexts.len());
        for ctx in ordered {
            let full = ctx.kv_bytes;
            let quant = ((ctx.kv_bytes as f64) * self.quant_ratio).ceil() as u64;
            let tier = if gpu_used + full <= self.gpu_budget_bytes {
                gpu_used += full;
                KvTier::GpuFull
            } else if gpu_used + quant <= self.gpu_budget_bytes {
                gpu_used += quant;
                KvTier::GpuQuant
            } else if cpu_used + full <= self.cpu_budget_bytes {
                cpu_used += full;
                KvTier::Cpu
            } else {
                KvTier::Disk
            };
            out.push(TierDecision {
                id: ctx.id.clone(),
                tier,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(id: &str, kv_gib: u64, reuse: u64, last: u64, ttft: bool) -> KvContext {
        KvContext {
            id: id.into(),
            kv_bytes: kv_gib * 1024 * 1024 * 1024,
            reuse_count: reuse,
            last_used: last,
            ttft_sensitive: ttft,
        }
    }

    fn tier_of<'a>(decisions: &'a [TierDecision], id: &str) -> &'a KvTier {
        &decisions.iter().find(|d| d.id == id).unwrap().tier
    }

    #[test]
    fn hottest_stays_gpu_full_coldest_spills() {
        // 8 GiB GPU, 10 GiB CPU. Three 6 GiB contexts of decreasing
        // utility: the hottest fits GPU-full (6 <= 8); the next fits as
        // quant (6 + 1.5 <= 8); the third (would be 7.5 + 1.5 = 9 > 8)
        // spills to CPU.
        let policy = KvTieringPolicy {
            gpu_budget_bytes: 8 * 1024 * 1024 * 1024,
            cpu_budget_bytes: 10 * 1024 * 1024 * 1024,
            quant_ratio: 0.25,
        };
        let ctxs = vec![
            ctx("hot", 6, 100, 9, true),
            ctx("warm", 6, 50, 8, false),
            ctx("cold", 6, 1, 1, false),
        ];
        let d = policy.place(&ctxs);
        assert_eq!(tier_of(&d, "hot"), &KvTier::GpuFull);
        assert_eq!(tier_of(&d, "warm"), &KvTier::GpuQuant);
        assert_eq!(tier_of(&d, "cold"), &KvTier::Cpu);
    }

    #[test]
    fn overflow_goes_to_disk() {
        // Tiny budgets: only one fits GPU-full, nothing else fits GPU or
        // CPU, so the rest go to disk.
        let policy = KvTieringPolicy {
            gpu_budget_bytes: 6 * 1024 * 1024 * 1024,
            cpu_budget_bytes: 0,
            quant_ratio: 0.25,
        };
        let ctxs = vec![ctx("a", 6, 100, 9, true), ctx("b", 6, 10, 8, false)];
        let d = policy.place(&ctxs);
        assert_eq!(tier_of(&d, "a"), &KvTier::GpuFull);
        assert_eq!(tier_of(&d, "b"), &KvTier::Disk);
    }

    #[test]
    fn ttft_sensitivity_raises_a_context() {
        // Equal reuse, but the interactive one wins the GPU-full slot.
        let policy = KvTieringPolicy {
            gpu_budget_bytes: 6 * 1024 * 1024 * 1024,
            cpu_budget_bytes: 6 * 1024 * 1024 * 1024,
            quant_ratio: 0.25,
        };
        let ctxs = vec![
            ctx("batch", 6, 50, 9, false),
            ctx("interactive", 6, 50, 8, true),
        ];
        let d = policy.place(&ctxs);
        assert_eq!(tier_of(&d, "interactive"), &KvTier::GpuFull);
    }

    #[test]
    fn reuse_promotes_a_cold_context_on_the_next_pass() {
        let policy = KvTieringPolicy {
            gpu_budget_bytes: 6 * 1024 * 1024 * 1024,
            cpu_budget_bytes: 6 * 1024 * 1024 * 1024,
            quant_ratio: 0.25,
        };
        // First pass: "b" is cold, spills below "a".
        let before = vec![ctx("a", 6, 100, 9, false), ctx("b", 6, 1, 2, false)];
        assert_eq!(tier_of(&policy.place(&before), "b"), &KvTier::Cpu);
        // "b" gets reused a lot and becomes the hottest -> promoted to GPU.
        let after = vec![ctx("a", 6, 100, 9, false), ctx("b", 6, 500, 12, false)];
        assert_eq!(tier_of(&policy.place(&after), "b"), &KvTier::GpuFull);
    }
}
