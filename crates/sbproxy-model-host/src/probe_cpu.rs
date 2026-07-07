// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! CPU / system-RAM admission budget (WOR-1800).
//!
//! On a box with no discrete GPU (a plain server, or an Apple machine
//! when the Metal probe is not compiled) the fit planner still needs a
//! memory budget or it rejects every model with [`crate::FitError::NoGpu`].
//! This probe reports one synthetic device whose capacity is a fraction
//! of system RAM, so llama.cpp (CPU) and the embedded engine can serve
//! small models. It reports `supports_fp8: false` and no compute
//! capability, so the fit planner's capability gate keeps FP8 /
//! datacenter quants off CPU automatically; only formats that actually
//! run on CPU pass admission.
//!
//! Detection is dependency-free, mirroring the `nvidia-smi` CLI fallback
//! the NVIDIA probe uses: RAM is read from `/proc/meminfo` on Linux and
//! `sysctl hw.memsize` on macOS / BSD.

use std::process::Command;

use crate::fit::{GpuDescriptor, GpuProbe, GpuVendor};

/// Default fraction of total system RAM offered as the CPU serving
/// budget. Leaves headroom for the OS, the gateway process, and the KV
/// growth the fit math does not fully model.
pub const DEFAULT_CPU_MEMORY_FRACTION: f64 = 0.7;

/// Environment override for [`DEFAULT_CPU_MEMORY_FRACTION`]. Set it to
/// `0` to disable CPU admission entirely: the probe then reports no
/// device and a `serve:` block on this host rejects, the pre-WOR-1800
/// behaviour. Clamped to `[0.0, 0.95]`.
pub const CPU_MEMORY_FRACTION_ENV: &str = "SBPROXY_CPU_MEMORY_FRACTION";

// The default fraction must leave headroom and never exceed the clamp,
// enforced at compile time.
const _: () = assert!(DEFAULT_CPU_MEMORY_FRACTION > 0.0 && DEFAULT_CPU_MEMORY_FRACTION <= 0.95);

/// A CPU / system-RAM budget presented to the fit planner as a single
/// device. See the module docs.
#[derive(Debug, Clone)]
pub struct CpuProbe {
    budget_bytes: u64,
}

impl CpuProbe {
    /// Build from detected system RAM and the configured fraction (env
    /// override, else the default). Reports no device (a zero budget)
    /// when RAM cannot be read or the fraction resolves to zero, so a
    /// host that opts out still rejects admission cleanly.
    pub fn from_system() -> Self {
        let total = detect_total_memory_bytes().unwrap_or(0);
        let fraction = resolve_fraction();
        Self {
            budget_bytes: (total as f64 * fraction) as u64,
        }
    }

    /// Build with an explicit byte budget. For tests and callers that
    /// already know the cap.
    pub fn with_budget(budget_bytes: u64) -> Self {
        Self { budget_bytes }
    }

    /// The serving budget in bytes (0 means "reports no device").
    pub fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }
}

impl GpuProbe for CpuProbe {
    fn probe(&self) -> Vec<GpuDescriptor> {
        if self.budget_bytes == 0 {
            return Vec::new();
        }
        vec![GpuDescriptor {
            index: 0,
            vendor: GpuVendor::Cpu,
            name: "CPU (system RAM)".to_string(),
            total_vram_bytes: self.budget_bytes,
            free_vram_bytes: self.budget_bytes,
            compute_capability: None,
            supports_fp8: false,
            mem_bandwidth_gbps: None,
        }]
    }
}

/// Resolve the RAM fraction from the environment, clamped to a sane
/// range. Falls back to the default on any parse failure.
fn resolve_fraction() -> f64 {
    match std::env::var(CPU_MEMORY_FRACTION_ENV) {
        Ok(v) => v
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|f| f.is_finite() && *f >= 0.0)
            .map(|f| f.min(0.95))
            .unwrap_or(DEFAULT_CPU_MEMORY_FRACTION),
        Err(_) => DEFAULT_CPU_MEMORY_FRACTION,
    }
}

/// Total physical RAM in bytes, or `None` when it cannot be read.
/// Reads `/proc/meminfo` on Linux and `sysctl hw.memsize` elsewhere
/// (macOS / BSD). Never panics.
pub fn detect_total_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
            if let Some(kib) = parse_meminfo_memtotal_kib(&contents) {
                return Some(kib.saturating_mul(1024));
            }
        }
    }
    sysctl_u64("hw.memsize")
}

/// Read a `u64`-valued `sysctl` key (`sysctl -n <key>`). `None` when the
/// tool is absent, the key is unknown, or the value does not parse.
pub(crate) fn sysctl_u64(key: &str) -> Option<u64> {
    let out = Command::new("sysctl").arg("-n").arg(key).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .ok()
}

/// Parse the `MemTotal:` line of `/proc/meminfo` into kibibytes.
#[cfg(any(target_os = "linux", test))]
fn parse_meminfo_memtotal_kib(contents: &str) -> Option<u64> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            // Format: "MemTotal:       16305432 kB"
            let num = rest.split_whitespace().next()?;
            return num.parse::<u64>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_meminfo_memtotal() {
        let sample = "MemTotal:       16305432 kB\nMemFree:         1234 kB\n";
        assert_eq!(parse_meminfo_memtotal_kib(sample), Some(16_305_432));
        assert_eq!(parse_meminfo_memtotal_kib("MemFree: 10 kB"), None);
    }

    #[test]
    fn zero_budget_reports_no_device() {
        // Opting out (fraction 0 / undetectable RAM) rejects admission
        // exactly as the pre-WOR-1800 empty probe did.
        let probe = CpuProbe::with_budget(0);
        assert!(probe.probe().is_empty());
    }

    #[test]
    fn nonzero_budget_reports_one_cpu_device() {
        let eight_gib = 8 * crate::fit::GIB;
        let probe = CpuProbe::with_budget(eight_gib);
        let gpus = probe.probe();
        assert_eq!(gpus.len(), 1);
        let d = &gpus[0];
        assert_eq!(d.vendor, GpuVendor::Cpu);
        assert_eq!(d.total_vram_bytes, eight_gib);
        // CPU has no FP8 kernels and no CUDA compute capability, so the
        // capability gate keeps FP8 quants off it.
        assert!(!d.supports_fp8);
        assert!(d.compute_capability.is_none());
    }

    #[test]
    fn from_system_never_panics() {
        // On CI (Linux) this reads /proc/meminfo; on a dev Mac, sysctl.
        // Either way it must not panic and the budget is non-negative.
        let probe = CpuProbe::from_system();
        let _ = probe.budget_bytes();
        let _ = probe.probe();
    }
}
