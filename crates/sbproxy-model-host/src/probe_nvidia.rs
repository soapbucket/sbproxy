// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Real NVIDIA GPU discovery (WOR-1654, `gpu-nvidia` feature).
//!
//! Implements [`GpuProbe`] against NVML (via `nvml-wrapper`, a runtime
//! `dlopen` of `libnvidia-ml`, so nothing CUDA is needed at build
//! time), with a shell-out to `nvidia-smi --query-gpu` as the fallback
//! when the NVML library is not loadable. Both produce the same
//! [`GpuDescriptor`] the synthetic probes do, so the fit planner and
//! metrics are unchanged.
//!
//! This module is behind the `gpu-nvidia` cargo feature and is only
//! meaningful on a machine with an NVIDIA driver. It is compiled in CI
//! but exercised on the GPU certification host; the capability math it
//! relies on ([`crate::fit::fp8_supported`]) is in the default build
//! and unit-tested there.

use crate::fit::{fp8_supported, GpuDescriptor, GpuProbe, GpuVendor};

/// A [`GpuProbe`] backed by NVML, falling back to `nvidia-smi`.
#[derive(Debug, Default)]
pub struct NvmlGpuProbe;

impl NvmlGpuProbe {
    /// Construct the probe. Cheap; the NVML handle is opened per
    /// [`GpuProbe::probe`] call so a driver that appears later (or a
    /// transient failure) is picked up without recreating the probe.
    pub fn new() -> Self {
        Self
    }
}

impl GpuProbe for NvmlGpuProbe {
    fn probe(&self) -> Vec<GpuDescriptor> {
        match probe_via_nvml() {
            Ok(gpus) if !gpus.is_empty() => gpus,
            // NVML absent or reported nothing: try the CLI.
            _ => probe_via_nvidia_smi(),
        }
    }
}

/// Enumerate GPUs through NVML.
fn probe_via_nvml() -> Result<Vec<GpuDescriptor>, nvml_wrapper::error::NvmlError> {
    let nvml = nvml_wrapper::Nvml::init()?;
    let count = nvml.device_count()?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let dev = nvml.device_by_index(i)?;
        let mem = dev.memory_info()?;
        let name = dev.name().unwrap_or_else(|_| format!("NVIDIA GPU {i}"));
        let cc = dev
            .cuda_compute_capability()
            .ok()
            .map(|c| (c.major as u32, c.minor as u32));
        let mem_bandwidth_gbps = bandwidth_for_name(&name);
        out.push(GpuDescriptor {
            index: i,
            vendor: GpuVendor::Nvidia,
            name,
            total_vram_bytes: mem.total,
            free_vram_bytes: mem.free,
            compute_capability: cc,
            supports_fp8: cc.map(fp8_supported).unwrap_or(false),
            mem_bandwidth_gbps,
        });
    }
    Ok(out)
}

/// Peak memory bandwidth (GB/s) for known NVIDIA cards, matched by a
/// substring of the reported device name. `None` for unknown cards, in
/// which case throughput estimation is skipped rather than guessed.
fn bandwidth_for_name(name: &str) -> Option<f64> {
    let n = name.to_ascii_uppercase();
    let table = [
        ("T4", 320.0),
        ("L4", 300.0),
        ("L40", 864.0),
        ("A10", 600.0),
        ("A100", 1555.0),
        ("H100", 3350.0),
        ("H200", 4800.0),
        ("4090", 1008.0),
    ];
    table.iter().find(|(k, _)| n.contains(k)).map(|(_, bw)| *bw)
}

/// Enumerate GPUs by parsing `nvidia-smi` CSV. Used when NVML cannot
/// be loaded (driver present but library path unusual, container
/// quirks). Returns an empty vec if `nvidia-smi` is absent or fails.
fn probe_via_nvidia_smi() -> Vec<GpuDescriptor> {
    let output = match std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=index,name,memory.total,memory.free,compute_cap",
            "--format=csv,noheader,nounits",
        ])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().filter_map(parse_smi_line).collect()
}

/// Parse one `nvidia-smi` CSV row:
/// `index, name, memory.total (MiB), memory.free (MiB), compute_cap`.
fn parse_smi_line(line: &str) -> Option<GpuDescriptor> {
    let cols: Vec<&str> = line.split(',').map(str::trim).collect();
    if cols.len() < 5 {
        return None;
    }
    let index: u32 = cols[0].parse().ok()?;
    let name = cols[1].to_string();
    // memory.total / free are MiB in this format.
    let total_mib: u64 = cols[2].parse().ok()?;
    let free_mib: u64 = cols[3].parse().ok()?;
    let cc = parse_compute_cap(cols[4]);
    let mem_bandwidth_gbps = bandwidth_for_name(&name);
    Some(GpuDescriptor {
        index,
        vendor: GpuVendor::Nvidia,
        name,
        total_vram_bytes: total_mib * 1024 * 1024,
        free_vram_bytes: free_mib * 1024 * 1024,
        compute_capability: cc,
        supports_fp8: cc.map(fp8_supported).unwrap_or(false),
        mem_bandwidth_gbps,
    })
}

/// Parse a `major.minor` compute-capability string (e.g. `8.9`).
fn parse_compute_cap(s: &str) -> Option<(u32, u32)> {
    let (maj, min) = s.split_once('.')?;
    Some((maj.trim().parse().ok()?, min.trim().parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_nvidia_smi_l4_row() {
        // What an L4 prints: 24 GiB total, most free, compute cap 8.9.
        let row = "0, NVIDIA L4, 23034, 22900, 8.9";
        let d = parse_smi_line(row).expect("parse");
        assert_eq!(d.index, 0);
        assert_eq!(d.name, "NVIDIA L4");
        assert_eq!(d.compute_capability, Some((8, 9)));
        assert!(d.supports_fp8, "L4 (8.9) supports FP8");
        assert_eq!(d.total_vram_bytes, 23034 * 1024 * 1024);
    }

    #[test]
    fn parses_a_t4_row_without_fp8() {
        let row = "0, Tesla T4, 15360, 15109, 7.5";
        let d = parse_smi_line(row).expect("parse");
        assert!(!d.supports_fp8, "T4 (7.5) has no FP8");
    }

    #[test]
    fn rejects_short_rows() {
        assert!(parse_smi_line("0, only, three").is_none());
        assert!(parse_smi_line("").is_none());
    }

    #[test]
    fn probe_never_panics_without_a_gpu() {
        // On a machine with no NVIDIA driver, probe() must return an
        // empty vec (NVML init fails, nvidia-smi absent), never panic.
        let gpus = NvmlGpuProbe::new().probe();
        // We cannot assert emptiness (CI host might, in theory, have a
        // GPU), only that the call completes.
        let _ = gpus.len();
    }
}
