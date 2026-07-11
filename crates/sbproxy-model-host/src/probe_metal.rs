// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Apple Silicon (Metal) GPU probe (WOR-1800).
//!
//! Apple Silicon shares one pool of memory between CPU and GPU (unified
//! memory), so the "VRAM" budget for a served model is a fraction of
//! total system memory: Metal's `recommendedMaxWorkingSetSize` is about
//! three quarters of it. This probe reports that working-set as the
//! device budget with [`GpuVendor::Apple`], so the fit planner admits
//! GGUF models that fit unified memory and rejects ones that do not, and
//! llama.cpp (Metal) or the embedded engine serve them.
//!
//! Detection reads `hw.memsize` for unified memory and
//! `machdep.cpu.brand_string` for the chip name, via the
//! `sysctlbyname(3)` syscall with a `sysctl` CLI fallback (WOR-1829:
//! sandboxed contexts block process spawn but not the syscall).
//! Querying Metal's exact `recommendedMaxWorkingSetSize` through
//! `objc2-metal` is a later refinement; the memory budget is the number
//! that gates admission and `sysctl` reports it directly with no extra
//! dependency.

use crate::fit::{memory_occupancy, GpuDescriptor, GpuProbe, GpuVendor};
use crate::probe_cpu::{sysctl_string, sysctl_u64};

/// Default fraction of unified memory offered as the Metal working-set
/// budget, matching Metal's `recommendedMaxWorkingSetSize` heuristic.
pub const DEFAULT_METAL_WORKING_SET_FRACTION: f64 = 0.75;

/// Environment override for [`DEFAULT_METAL_WORKING_SET_FRACTION`],
/// clamped to `[0.1, 0.95]`.
pub const METAL_WORKING_SET_FRACTION_ENV: &str = "SBPROXY_METAL_WORKING_SET_FRACTION";

/// The Metal probe. Reports one Apple Silicon device sized to the
/// unified-memory working-set, or nothing on a machine where `sysctl`
/// cannot report memory (never panics).
#[derive(Debug, Clone, Default)]
pub struct MetalGpuProbe;

impl MetalGpuProbe {
    /// Build a Metal probe.
    pub fn new() -> Self {
        Self
    }
}

impl GpuProbe for MetalGpuProbe {
    fn probe(&self) -> Vec<GpuDescriptor> {
        probe_metal().into_iter().collect()
    }
}

fn probe_metal() -> Option<GpuDescriptor> {
    let mem = sysctl_u64("hw.memsize")?;
    let fraction = resolve_fraction();
    let budget = (mem as f64 * fraction) as u64;
    if budget == 0 {
        return None;
    }
    let name = sysctl_string("machdep.cpu.brand_string")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Apple Silicon (Metal)".to_string());
    Some(GpuDescriptor {
        index: 0,
        vendor: GpuVendor::Apple,
        name,
        total_vram_bytes: budget,
        free_vram_bytes: budget,
        compute_utilization: None,
        memory_occupancy: memory_occupancy(budget, budget),
        compute_capability: None,
        supports_fp8: false,
        mem_bandwidth_gbps: None,
    })
}

fn resolve_fraction() -> f64 {
    match std::env::var(METAL_WORKING_SET_FRACTION_ENV) {
        Ok(v) => v
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|f| f.is_finite() && *f > 0.0)
            .map(|f| f.clamp(0.1, 0.95))
            .unwrap_or(DEFAULT_METAL_WORKING_SET_FRACTION),
        Err(_) => DEFAULT_METAL_WORKING_SET_FRACTION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_this_apple_machine() {
        // This test only compiles on macOS with the gpu-apple feature,
        // so when it runs it runs on real Apple Silicon: the probe must
        // report exactly one unified-memory device with a real budget.
        let gpus = MetalGpuProbe::new().probe();
        assert_eq!(gpus.len(), 1, "expected one Apple device");
        let d = &gpus[0];
        assert_eq!(d.vendor, GpuVendor::Apple);
        assert!(d.total_vram_bytes > 0);
        assert!(!d.supports_fp8);
    }
}
