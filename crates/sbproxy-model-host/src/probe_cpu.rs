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

use crate::fit::{memory_occupancy, GpuDescriptor, GpuProbe, GpuVendor};

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
            compute_utilization: None,
            memory_occupancy: memory_occupancy(self.budget_bytes, self.budget_bytes),
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

/// Read a `u64`-valued `sysctl` key. On macOS the `sysctlbyname(3)`
/// syscall is tried first: sandboxed contexts (Seatbelt profiles, some
/// launchd services) block spawning the `sysctl` binary while the
/// syscall itself still works, and without it the probe reported no
/// device and every `serve:` block rejected admission (WOR-1829). The
/// CLI (`sysctl -n <key>`) remains as the fallback and the only path
/// on other BSDs. `None` when the key is unknown or the value does not
/// parse.
pub(crate) fn sysctl_u64(key: &str) -> Option<u64> {
    #[cfg(target_os = "macos")]
    if let Some(v) = sysctlbyname_u64(key) {
        return Some(v);
    }
    let out = Command::new("sysctl").arg("-n").arg(key).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .ok()
}

/// Read a string-valued `sysctl` key, syscall first on macOS then the
/// CLI, mirroring [`sysctl_u64`]. Only the Metal probe needs strings
/// (the chip name), hence the feature gate.
#[cfg(all(target_os = "macos", feature = "gpu-apple"))]
pub(crate) fn sysctl_string(key: &str) -> Option<String> {
    if let Some(s) = sysctlbyname_string(key) {
        return Some(s);
    }
    let out = Command::new("sysctl").arg("-n").arg(key).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `sysctlbyname(3)` for an integer key. Handles both 8- and 4-byte
/// kernel values (`hw.memsize` is 64-bit, keys like `hw.ncpu` are
/// 32-bit) by writing into a zeroed u64.
#[cfg(target_os = "macos")]
fn sysctlbyname_u64(key: &str) -> Option<u64> {
    let name = std::ffi::CString::new(key).ok()?;
    let mut value: u64 = 0;
    let mut len: libc::size_t = std::mem::size_of::<u64>();
    // SAFETY: `name` is NUL-terminated, `value` is an aligned u64 the
    // kernel writes at most `len` (= 8) bytes into, and `len` is the
    // in/out size parameter per sysctlbyname(3).
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            &mut value as *mut u64 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    // A 4-byte value lands in the low bytes of the zeroed little-endian
    // u64, so no shift is needed.
    (rc == 0 && (len == 8 || len == 4)).then_some(value)
}

/// `sysctlbyname(3)` for a string key: query the length, then read.
#[cfg(all(target_os = "macos", any(feature = "gpu-apple", test)))]
fn sysctlbyname_string(key: &str) -> Option<String> {
    let name = std::ffi::CString::new(key).ok()?;
    let mut len: libc::size_t = 0;
    // SAFETY: a null buffer with a zeroed length asks the kernel for
    // the required size, per sysctlbyname(3).
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` owns `len` writable bytes and the kernel writes at
    // most `len` bytes into it.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(len);
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Some(String::from_utf8_lossy(&buf).trim().to_string())
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

    #[cfg(target_os = "macos")]
    #[test]
    fn sysctlbyname_reads_memsize_without_spawning() {
        // The syscall path must work on its own (WOR-1829: sandboxes
        // that block process spawn still allow the syscall), so call it
        // directly rather than through the CLI-fallback wrapper.
        let mem = sysctlbyname_u64("hw.memsize").expect("hw.memsize via syscall");
        assert!(mem > 1 << 30, "unified memory is at least 1 GiB");
        let brand =
            sysctlbyname_string("machdep.cpu.brand_string").expect("brand string via syscall");
        assert!(!brand.is_empty());
        // Unknown keys report None, never an error or panic.
        assert_eq!(sysctlbyname_u64("sbproxy.not.a.key"), None);
        assert_eq!(sysctlbyname_string("sbproxy.not.a.key"), None);
    }
}
