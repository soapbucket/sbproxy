// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Host capability diagnostics behind `sbproxy doctor`.
//!
//! One released binary adapts to its host at runtime: the NVML GPU
//! probe is a dlopen (never a link-time dependency), inference engines
//! resolve from `PATH`, and a `serve:` provider on a host with no GPU
//! rejects admission instead of failing at startup. That flexibility
//! makes "what can this binary do *here*" a real operator question,
//! and this module answers it: which capability features the binary
//! was compiled with, which GPUs the admission path will see, which
//! engine binaries are reachable, and whether local model serving
//! (`serve:`) would admit anything on this host.
//!
//! Collection is read-only: no engine spawns, no directory is created,
//! nothing is written. The GPU list comes from the same probe the
//! model-host runtime uses (`make_probe` in the server's model-host
//! wiring), so `doctor` and admission can never disagree about the
//! hardware.

use std::path::PathBuf;

use serde::Serialize;

use sbproxy_model_host::GpuDescriptor;

/// Capability features compiled into this binary. Only the flags that
/// change what the binary can do on a given host are listed; pipeline
/// policy flags (tiered pricing, projections, ...) are host-independent
/// and stay out of the report.
#[derive(Debug, Clone, Serialize)]
pub struct BuildFeatures {
    /// Real NVIDIA GPU discovery (NVML dlopen + `nvidia-smi` fallback)
    /// for the local model host. Without it the probe reports zero
    /// GPUs and every `serve:` admission is rejected.
    pub gpu_nvidia: bool,
    /// sbproxy-managed Hugging Face weight download with sha256
    /// verification. Engines can still self-download (`vllm serve`,
    /// `llama-server --hf-repo`) when this is off.
    pub model_weights: bool,
    /// JA3 / JA4 / JA4H TLS fingerprint capture.
    pub tls_fingerprint: bool,
    /// In-process semantic-cache embedder.
    pub inprocess_embed: bool,
    /// Agent-class resolution on the request context.
    pub agent_class: bool,
}

impl BuildFeatures {
    /// The features this build of `sbproxy-core` was compiled with.
    /// The binary forwards its defaults here, so from `sbproxy doctor`
    /// this reflects the shipped artifact.
    pub fn current() -> Self {
        Self {
            gpu_nvidia: cfg!(feature = "gpu-nvidia"),
            model_weights: cfg!(feature = "model-weights"),
            tls_fingerprint: cfg!(feature = "tls-fingerprint"),
            inprocess_embed: cfg!(feature = "inprocess-embed"),
            agent_class: cfg!(feature = "agent-class"),
        }
    }
}

/// One inference engine binary the launcher would spawn, and where (or
/// whether) it resolves on `PATH`.
#[derive(Debug, Clone, Serialize)]
pub struct EngineBinary {
    /// The `engine:` value a `serve:` block uses (`vllm`, `llama_cpp`).
    pub engine: &'static str,
    /// The program the launcher execs (`vllm`, `llama-server`).
    pub program: &'static str,
    /// Resolved path, or `None` when the program is not on `PATH`.
    pub path: Option<PathBuf>,
}

/// Whether a `serve:` provider would admit a model on this host, and
/// if not, every reason it would be rejected.
#[derive(Debug, Clone, Serialize)]
pub struct LocalServing {
    /// True when the build, a GPU, and at least one engine are present.
    pub ready: bool,
    /// Human-readable blockers, empty when `ready`.
    pub blockers: Vec<String>,
}

/// The full diagnostics report. Serializes to the stable JSON shape
/// `sbproxy doctor --format json` emits.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// Capability features compiled into the binary.
    pub features: BuildFeatures,
    /// GPUs the model-host admission path sees right now.
    pub gpus: Vec<GpuDescriptor>,
    /// Resolved `nvidia-smi` path, `None` when absent. Informational:
    /// NVML is tried first and does not need the CLI.
    pub nvidia_smi: Option<PathBuf>,
    /// The allowlisted inference engines and their `PATH` resolution.
    pub engines: Vec<EngineBinary>,
    /// Resolved container runtime (docker or podman), `None` when
    /// absent. vLLM can run from a pinned container image instead of a
    /// `PATH` binary, so this counts toward serving readiness.
    pub container_runtime: Option<PathBuf>,
    /// Default model-weight cache directory and whether it exists yet.
    /// A `serve:` block's `cache_dir` overrides this at runtime.
    pub model_cache_dir: PathBuf,
    /// Whether `model_cache_dir` exists.
    pub model_cache_exists: bool,
    /// The `serve:` readiness verdict for this host.
    pub local_serving: LocalServing,
}

impl DoctorReport {
    /// Probe the current host. Read-only and infallible: a host with
    /// no driver, no engines, and no cache directory produces a report
    /// full of "absent", never an error.
    pub fn collect() -> Self {
        let features = BuildFeatures::current();
        let gpus = crate::server::model_host::make_probe().probe();
        let engines = vec![
            EngineBinary {
                engine: "vllm",
                program: "vllm",
                path: find_on_path("vllm"),
            },
            EngineBinary {
                engine: "llama_cpp",
                program: "llama-server",
                path: find_on_path("llama-server"),
            },
        ];
        let container_runtime = find_on_path("docker").or_else(|| find_on_path("podman"));
        let model_cache_dir = sbproxy_model_host::resolve_cache_dir(None, None);
        let model_cache_exists = model_cache_dir.is_dir();
        let local_serving =
            serving_verdict(&features, &gpus, &engines, container_runtime.is_some());
        Self {
            features,
            gpus,
            nvidia_smi: find_on_path("nvidia-smi"),
            engines,
            container_runtime,
            model_cache_dir,
            model_cache_exists,
            local_serving,
        }
    }

    /// Render the human-readable form `sbproxy doctor` prints.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let yn = |b: bool| if b { "yes" } else { "no" };

        out.push_str("build capabilities\n");
        out.push_str(&format!(
            "  gpu-nvidia      (GPU discovery for serve:)   {}\n",
            yn(self.features.gpu_nvidia)
        ));
        out.push_str(&format!(
            "  model-weights   (managed weight download)    {}\n",
            yn(self.features.model_weights)
        ));
        out.push_str(&format!(
            "  tls-fingerprint (JA3/JA4 capture)            {}\n",
            yn(self.features.tls_fingerprint)
        ));
        out.push_str(&format!(
            "  inprocess-embed (semantic-cache embedder)    {}\n",
            yn(self.features.inprocess_embed)
        ));
        out.push_str(&format!(
            "  agent-class     (agent-class resolution)     {}\n",
            yn(self.features.agent_class)
        ));

        out.push_str("\ngpus\n");
        if self.gpus.is_empty() {
            out.push_str("  none detected\n");
        }
        for gpu in &self.gpus {
            let cc = gpu
                .compute_capability
                .map(|(maj, min)| format!("compute {maj}.{min}"))
                .unwrap_or_else(|| "compute unknown".to_string());
            out.push_str(&format!(
                "  [{}] {}  {:.0} GiB total, {:.0} GiB free, {}, fp8 {}\n",
                gpu.index,
                gpu.name,
                gpu.total_vram_bytes as f64 / GIB,
                gpu.free_vram_bytes as f64 / GIB,
                cc,
                yn(gpu.supports_fp8),
            ));
        }
        out.push_str(&format!(
            "  nvidia-smi: {}\n",
            self.nvidia_smi
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "not found".to_string())
        ));

        out.push_str("\ninference engines on PATH\n");
        for engine in &self.engines {
            out.push_str(&format!(
                "  {:<14}{}\n",
                engine.program,
                engine
                    .path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "not found".to_string())
            ));
        }

        out.push_str(&format!(
            "  {:<14}{}\n",
            "container",
            self.container_runtime
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "not found (docker/podman)".to_string())
        ));

        out.push_str(&format!(
            "\nmodel cache\n  {}{}\n",
            self.model_cache_dir.display(),
            if self.model_cache_exists {
                ""
            } else {
                " (not created yet)"
            }
        ));

        if self.local_serving.ready {
            out.push_str("\nlocal model serving (serve:): ready\n");
        } else {
            out.push_str("\nlocal model serving (serve:): not available\n");
            for blocker in &self.local_serving.blockers {
                out.push_str(&format!("  - {blocker}\n"));
            }
        }
        out
    }
}

const GIB: f64 = (1024u64 * 1024 * 1024) as f64;

/// Decide whether a `serve:` block would admit a model here, mirroring
/// the runtime's requirements: the probe feature, at least one visible
/// GPU, and at least one way to run an engine (a binary on `PATH`, or
/// a container runtime for vLLM's pinned-image launch).
fn serving_verdict(
    features: &BuildFeatures,
    gpus: &[GpuDescriptor],
    engines: &[EngineBinary],
    container_runtime: bool,
) -> LocalServing {
    let mut blockers = Vec::new();
    if !features.gpu_nvidia {
        blockers.push(
            "binary was built without the gpu-nvidia feature, so the model host \
             sees zero GPUs; rebuild with --features gpu-nvidia"
                .to_string(),
        );
    } else if gpus.is_empty() {
        blockers.push(
            "no NVIDIA GPU detected (NVML not loadable and nvidia-smi absent or \
             reporting no devices)"
                .to_string(),
        );
    }
    if engines.iter().all(|e| e.path.is_none()) && !container_runtime {
        blockers.push(
            "no way to run an inference engine: neither vllm nor llama-server is \
             on PATH and no container runtime (docker/podman) is available; run \
             `sbproxy doctor --install vllm` or `sbproxy doctor --install llama-cpp`"
                .to_string(),
        );
    }
    LocalServing {
        ready: blockers.is_empty(),
        blockers,
    }
}

/// Resolve a program on `PATH`. Delegates to the model-host resolver
/// so `doctor`, the plan-time engine doctor, and the serve-preflight
/// warning all agree on what "installed" means.
fn find_on_path(program: &str) -> Option<PathBuf> {
    sbproxy_model_host::resolve_on_path(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpu(name: &str) -> GpuDescriptor {
        GpuDescriptor {
            index: 0,
            vendor: sbproxy_model_host::GpuVendor::Nvidia,
            name: name.to_string(),
            total_vram_bytes: 24 * 1024 * 1024 * 1024,
            free_vram_bytes: 20 * 1024 * 1024 * 1024,
            compute_capability: Some((8, 9)),
            supports_fp8: true,
            mem_bandwidth_gbps: Some(300.0),
        }
    }

    fn engine(found: bool) -> EngineBinary {
        EngineBinary {
            engine: "vllm",
            program: "vllm",
            path: found.then(|| PathBuf::from("/usr/bin/vllm")),
        }
    }

    #[test]
    fn collect_never_panics_and_serializes() {
        // On any host (CI has no GPU, a dev box might) collection must
        // complete and produce valid JSON with the stable top keys.
        let report = DoctorReport::collect();
        let json = serde_json::to_value(&report).expect("report serializes");
        for key in [
            "features",
            "gpus",
            "engines",
            "model_cache_dir",
            "local_serving",
        ] {
            assert!(json.get(key).is_some(), "missing key {key}");
        }
        let _ = report.render_text();
    }

    #[test]
    fn verdict_ready_with_gpu_and_engine() {
        let v = serving_verdict(
            &BuildFeatures::current(),
            &[gpu("NVIDIA L4")],
            &[engine(true)],
            false,
        );
        if cfg!(feature = "gpu-nvidia") {
            assert!(v.ready, "blockers: {:?}", v.blockers);
        } else {
            assert!(!v.ready, "without the feature the build itself blocks");
        }
    }

    #[test]
    fn verdict_blocks_without_gpu_and_engine() {
        let v = serving_verdict(&BuildFeatures::current(), &[], &[engine(false)], false);
        assert!(!v.ready);
        // Missing GPU (or missing feature) and missing engine are both
        // reported, not just the first.
        assert_eq!(v.blockers.len(), 2, "blockers: {:?}", v.blockers);
    }

    #[test]
    fn container_runtime_satisfies_the_engine_leg() {
        // No engine binary, but docker present: vLLM can launch from a
        // pinned image, so the engine blocker must not fire.
        let v = serving_verdict(
            &BuildFeatures::current(),
            &[gpu("NVIDIA L4")],
            &[engine(false)],
            true,
        );
        assert!(
            !v.blockers.iter().any(|b| b.contains("inference engine")),
            "blockers: {:?}",
            v.blockers
        );
    }

    #[test]
    fn text_report_names_the_verdict() {
        let report = DoctorReport::collect();
        let text = report.render_text();
        assert!(text.contains("local model serving (serve:):"));
        assert!(text.contains("build capabilities"));
    }
}
