// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Host capability diagnostics behind `sbproxy doctor` (WOR-1799).
//!
//! One released binary adapts to its host at runtime: GPU discovery is
//! layered (NVIDIA NVML, Apple Metal, then a CPU / system-RAM budget),
//! inference engines resolve from `PATH` or are acquired, and a `serve:`
//! provider on a host that cannot run it rejects admission instead of
//! failing at the first request. That flexibility makes "what can this
//! binary do *here*, and how do I make it serve" a real operator
//! question, and this module is the shared detection layer that answers
//! it. `sbproxy doctor`, engine acquisition, `sbproxy run`, and the
//! cloud spin-up all read the same report, so they can never disagree
//! about the hardware.
//!
//! It reports three things:
//! - the **environment**: OS + arch, CPU + RAM, free disk, the GPU the
//!   admission path sees, NVIDIA driver + CUDA / Metal / ROCm, container
//!   runtimes, package managers, Python + uv, and Hugging Face reach;
//! - the **options per engine**: which engine binaries are present (with
//!   version) and which acquisition sources are viable here, each with a
//!   reason;
//! - the **per-serve-entry resolution**: for a configured `serve:` block
//!   (or a `sbproxy run` argument), what `engine: auto` resolves to and a
//!   coarse fit preview.
//!
//! Collection is read-only: no engine spawns, no directory is created,
//! nothing is written. Local tools may be exec'd to read a version;
//! network reach and container-daemon liveness are only probed in the
//! `deep` pass the CLI runs, so the offline `DoctorReport::collect`
//! stays fast and side-effect-free for tests.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use sbproxy_model_host::{GpuDescriptor, GpuVendor, ModelHostConfig};

const GIB: f64 = (1024u64 * 1024 * 1024) as f64;

/// Capability features compiled into this binary. Only the flags that
/// change what the binary can do on a given host are listed; pipeline
/// policy flags (tiered pricing, projections, ...) are host-independent
/// and stay out of the report.
#[derive(Debug, Clone, Serialize)]
pub struct BuildFeatures {
    /// Real NVIDIA GPU discovery (NVML dlopen + `nvidia-smi` fallback).
    pub gpu_nvidia: bool,
    /// Apple Silicon (Metal) unified-memory discovery.
    pub gpu_apple: bool,
    /// The in-process embedded engine (no subprocess).
    pub embedded: bool,
    /// sbproxy-managed Hugging Face weight download with sha256
    /// verification. Engines can still self-download when this is off.
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
    pub fn current() -> Self {
        Self {
            gpu_nvidia: cfg!(feature = "gpu-nvidia"),
            gpu_apple: cfg!(feature = "gpu-apple"),
            embedded: cfg!(feature = "embedded"),
            model_weights: cfg!(feature = "model-weights"),
            tls_fingerprint: cfg!(feature = "tls-fingerprint"),
            inprocess_embed: cfg!(feature = "inprocess-embed"),
            agent_class: cfg!(feature = "agent-class"),
        }
    }
}

/// The host: OS, arch, and the resources that gate model serving.
#[derive(Debug, Clone, Serialize)]
pub struct HostInfo {
    /// Operating system (`linux`, `macos`, ...).
    pub os: String,
    /// CPU architecture (`x86_64`, `aarch64`, ...).
    pub arch: String,
    /// Logical CPU count.
    pub cpu_count: usize,
    /// Total physical RAM in bytes, when readable.
    pub total_ram_bytes: Option<u64>,
}

/// GPU drivers / runtimes present on the host, informational alongside
/// the probed GPU list.
#[derive(Debug, Clone, Serialize)]
pub struct DriverInfo {
    /// NVIDIA driver version (from `nvidia-smi`), when present.
    pub nvidia_driver: Option<String>,
    /// CUDA toolkit/runtime version, when present.
    pub cuda: Option<String>,
    /// Apple Metal is available (macOS).
    pub metal: bool,
    /// AMD ROCm tooling is on `PATH`.
    pub rocm: bool,
}

/// Container runtimes and whether a daemon answers.
#[derive(Debug, Clone, Serialize)]
pub struct ContainerInfo {
    /// Resolved `docker` path.
    pub docker: Option<PathBuf>,
    /// Resolved `podman` path.
    pub podman: Option<PathBuf>,
    /// A daemon responded to `info` (only checked in the deep pass).
    pub daemon_reachable: bool,
}

impl ContainerInfo {
    /// A container runtime binary is present (daemon liveness aside).
    pub fn present(&self) -> bool {
        self.docker.is_some() || self.podman.is_some()
    }
}

/// System package managers, for the acquisition hints.
#[derive(Debug, Clone, Serialize)]
pub struct PackageManagers {
    /// Homebrew (`brew`) path.
    pub brew: Option<PathBuf>,
    /// Debian/Ubuntu `apt-get` path.
    pub apt: Option<PathBuf>,
}

/// Python toolchain, for the vLLM acquisition path.
#[derive(Debug, Clone, Serialize)]
pub struct PythonInfo {
    /// `python3 --version`, when present.
    pub python3: Option<String>,
    /// `uv --version`, when present (the preferred vLLM installer).
    pub uv: Option<String>,
    /// `pip` / `pip3` is on `PATH`.
    pub pip: bool,
}

/// Hugging Face reachability + credentials.
#[derive(Debug, Clone, Serialize)]
pub struct HuggingFaceInfo {
    /// The endpoint weight downloads use (`HF_ENDPOINT` mirror or the
    /// public hub).
    pub endpoint: String,
    /// `HF_TOKEN` (or `HUGGING_FACE_HUB_TOKEN`) is set, for gated repos.
    pub token_present: bool,
    /// The endpoint answered a TLS connection. `None` when not probed
    /// (the offline pass); the CLI's deep pass fills it in.
    pub reachable: Option<bool>,
}

/// One way to acquire an engine here, and whether it is viable.
#[derive(Debug, Clone, Serialize)]
pub struct AcquisitionOption {
    /// Method id: `path`, `prebuilt-release`, `brew`, `container`,
    /// `uv`, `pip`, `source`, `built-in`.
    pub method: &'static str,
    /// Whether this method is viable on this host right now.
    pub available: bool,
    /// A one-line reason / command hint.
    pub detail: String,
}

/// One inference engine: its `PATH` resolution, version, and the
/// acquisition options viable on this host.
#[derive(Debug, Clone, Serialize)]
pub struct EngineBinary {
    /// The `engine:` value a `serve:` block uses (`vllm`, `llama_cpp`,
    /// `embedded`).
    pub engine: &'static str,
    /// The program the launcher execs (`vllm`, `llama-server`; a
    /// sentinel for the in-process embedded engine).
    pub program: &'static str,
    /// Resolved path, or `None` when the program is not on `PATH`.
    pub path: Option<PathBuf>,
    /// The engine's reported version, when resolvable.
    pub version: Option<String>,
    /// Acquisition options and their viability, best-first.
    pub acquisition: Vec<AcquisitionOption>,
}

impl EngineBinary {
    /// Whether this engine can run here by some viable acquisition
    /// option (already installed, or an available acquisition method).
    pub fn runnable(&self) -> bool {
        self.path.is_some() || self.acquisition.iter().any(|a| a.available)
    }

    /// The best available acquisition option (first viable), if any.
    pub fn best_option(&self) -> Option<&AcquisitionOption> {
        self.acquisition.iter().find(|a| a.available)
    }
}

/// A coarse fit verdict for a configured model, from the catalog hint
/// and the probed budget (the precise math needs weight metadata a
/// fresh box does not have yet).
#[derive(Debug, Clone, Serialize)]
pub struct FitPreview {
    /// `fits`, `too-large`, `capability-refused`, or `unknown`.
    pub verdict: &'static str,
    /// A human-readable explanation.
    pub detail: String,
    /// The catalog VRAM hint in GiB, when known.
    pub estimated_vram_gib: Option<f64>,
    /// The quant the preview assumed, when known.
    pub quant: Option<String>,
}

/// One serve entry's engine resolution and fit preview on this host.
#[derive(Debug, Clone, Serialize)]
pub struct ServeEntryReport {
    /// The registered model name (or the raw reference when unnamed).
    pub model: String,
    /// The model reference (`hf:` ref or catalog id).
    pub reference: String,
    /// The engine `auto`/forced resolved to.
    pub engine: String,
    /// The one-line reason for the resolution.
    pub engine_reason: String,
    /// Whether the resolved engine can run here.
    pub runnable: bool,
    /// What is missing, when not runnable, plus how to fix it.
    pub blocker: Option<String>,
    /// The coarse fit preview.
    pub fit: FitPreview,
}

/// Whether a `serve:` block would admit a model on this host, and if
/// not, every reason it would be rejected, plus the single best fix.
#[derive(Debug, Clone, Serialize)]
pub struct LocalServing {
    /// True when the host has a memory budget and at least one engine.
    pub ready: bool,
    /// Human-readable blockers, empty when `ready`.
    pub blockers: Vec<String>,
    /// The single recommended remediation command / path, when serving
    /// is not ready but could be made ready.
    pub recommendation: Option<String>,
}

/// The full diagnostics report. Serializes to the JSON shape
/// `sbproxy doctor --format json` emits.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// The host environment.
    pub host: HostInfo,
    /// Capability features compiled into the binary.
    pub features: BuildFeatures,
    /// GPUs (or the CPU / unified-memory budget) the admission path sees.
    pub gpus: Vec<GpuDescriptor>,
    /// GPU drivers / runtimes present.
    pub drivers: DriverInfo,
    /// Resolved `nvidia-smi` path, `None` when absent.
    pub nvidia_smi: Option<PathBuf>,
    /// The allowlisted inference engines, their `PATH` resolution, and
    /// acquisition options.
    pub engines: Vec<EngineBinary>,
    /// Resolved container runtime (docker or podman), `None` when
    /// absent. Kept for back-compat with the original report shape;
    /// `containers` has the fuller picture.
    pub container_runtime: Option<PathBuf>,
    /// Container runtimes + daemon liveness.
    pub containers: ContainerInfo,
    /// System package managers.
    pub package_managers: PackageManagers,
    /// Python toolchain.
    pub python: PythonInfo,
    /// Hugging Face endpoint, token, reach.
    pub huggingface: HuggingFaceInfo,
    /// Default model-weight cache directory.
    pub model_cache_dir: PathBuf,
    /// Whether `model_cache_dir` exists.
    pub model_cache_exists: bool,
    /// Free bytes on the filesystem holding the cache dir, when readable.
    pub model_cache_free_bytes: Option<u64>,
    /// Per-serve-entry resolution + fit, when a `serve:` config was
    /// supplied (empty otherwise).
    pub serve_entries: Vec<ServeEntryReport>,
    /// The `serve:` readiness verdict for this host.
    pub local_serving: LocalServing,
}

impl DoctorReport {
    /// Probe the current host, offline. Read-only and infallible: a host
    /// with no driver, no engines, and no cache directory produces a
    /// report full of "absent", never an error. Network reach and
    /// container-daemon liveness are left unprobed (`reachable: None`,
    /// `daemon_reachable: false`); use [`Self::collect_deep`]
    /// for those.
    pub fn collect() -> Self {
        Self::build(false)
    }

    /// Like [`collect`](Self::collect) but also probes Hugging Face
    /// reachability and container-daemon liveness (a short TLS connect
    /// and a local `info` call). The `sbproxy doctor` CLI uses this.
    pub fn collect_deep() -> Self {
        Self::build(true)
    }

    fn build(deep: bool) -> Self {
        let features = BuildFeatures::current();
        let gpus = crate::server::model_host::make_probe().probe();

        let host = HostInfo {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_count: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
            total_ram_bytes: sbproxy_model_host::detect_total_memory_bytes(),
        };

        let nvidia_smi = find_on_path("nvidia-smi");
        let drivers = DriverInfo {
            nvidia_driver: detect_nvidia_driver(),
            cuda: detect_cuda(),
            metal: host.os == "macos",
            rocm: find_on_path("rocminfo").is_some() || find_on_path("rocm-smi").is_some(),
        };

        let containers = ContainerInfo {
            docker: find_on_path("docker"),
            podman: find_on_path("podman"),
            daemon_reachable: false,
        };
        let containers = if deep {
            ContainerInfo {
                daemon_reachable: container_daemon_reachable(&containers),
                ..containers
            }
        } else {
            containers
        };
        let container_runtime = containers
            .docker
            .clone()
            .or_else(|| containers.podman.clone());

        let package_managers = PackageManagers {
            brew: find_on_path("brew"),
            apt: find_on_path("apt-get"),
        };
        let python = PythonInfo {
            python3: run_version("python3", &["--version"]),
            uv: run_version("uv", &["--version"]),
            pip: find_on_path("pip3").is_some() || find_on_path("pip").is_some(),
        };
        let hf_endpoint = std::env::var("HF_ENDPOINT")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "https://huggingface.co".to_string());
        let huggingface = HuggingFaceInfo {
            reachable: if deep {
                Some(endpoint_reachable(&hf_endpoint))
            } else {
                None
            },
            token_present: env_present("HF_TOKEN") || env_present("HUGGING_FACE_HUB_TOKEN"),
            endpoint: hf_endpoint,
        };

        let env = EngineEnvView {
            os: host.os.clone(),
            arch: host.arch.clone(),
            container: containers.present(),
            brew: package_managers.brew.is_some(),
            uv: python.uv.is_some(),
            pip: python.pip,
            embedded_feature: features.embedded,
        };
        let engines = vec![
            engine_report("llama_cpp", "llama-server", &env),
            engine_report("vllm", "vllm", &env),
            engine_report("embedded", "embedded", &env),
        ];

        let model_cache_dir = sbproxy_model_host::resolve_cache_dir_default(None);
        let model_cache_exists = model_cache_dir.is_dir();
        let model_cache_free_bytes = free_disk_bytes(&model_cache_dir);

        let local_serving = serving_verdict(&gpus, &engines);

        Self {
            host,
            features,
            gpus,
            drivers,
            nvidia_smi,
            engines,
            container_runtime,
            containers,
            package_managers,
            python,
            huggingface,
            model_cache_dir,
            model_cache_exists,
            model_cache_free_bytes,
            serve_entries: Vec::new(),
            local_serving,
        }
    }

    /// Evaluate a `serve:` block against this host: engine resolution
    /// (`auto` per entry) and a coarse fit preview per model. Populates
    /// [`serve_entries`](Self::serve_entries) and returns the report so
    /// the caller can chain it. Used by `sbproxy doctor <config>` and by
    /// `sbproxy run`, which builds an in-memory `serve:` block.
    pub fn with_serve_config(
        mut self,
        serve: &ModelHostConfig,
        catalog: &sbproxy_model_host::Catalog,
    ) -> Self {
        self.serve_entries = self.evaluate_serve(serve, catalog);
        self
    }

    /// The per-entry resolution + fit for a `serve:` block, without
    /// mutating the report (see [`with_serve_config`](Self::with_serve_config)).
    pub fn evaluate_serve(
        &self,
        serve: &ModelHostConfig,
        catalog: &sbproxy_model_host::Catalog,
    ) -> Vec<ServeEntryReport> {
        use sbproxy_model_host::{EngineDoctor, EngineEnv};
        // vLLM needs CUDA, which a macOS container cannot provide, so a
        // container runtime does not steer `auto` toward vLLM on a Mac:
        // there `auto` should resolve to llama.cpp (Metal) instead.
        let container_for_resolution = self.containers.present() && self.host.os != "macos";
        let env = EngineEnv {
            vllm_on_path: self.engine_path("vllm").is_some(),
            llama_server_on_path: self.engine_path("llama_cpp").is_some(),
            container_runtime: container_for_resolution,
            gpu_present: !self.gpus.is_empty(),
        };
        serve
            .models
            .iter()
            .map(|entry| {
                let is_gguf = looks_gguf(&entry.model);
                let doc = EngineDoctor::for_entry(entry, is_gguf, &env);
                // If the resolved engine's binary is absent from PATH but
                // an acquisition option exists, sbproxy can acquire it, so
                // reflect that in `runnable`.
                let acquirable = self
                    .engine_for_kind(doc.resolved)
                    .map(|e| e.runnable())
                    .unwrap_or(doc.runnable);
                let runnable = doc.runnable || acquirable;
                let blocker = if runnable { None } else { doc.blocker.clone() };
                ServeEntryReport {
                    model: doc.model.clone(),
                    reference: entry.model.clone(),
                    engine: format!("{:?}", doc.resolved).to_lowercase(),
                    engine_reason: doc.reason.clone(),
                    runnable,
                    blocker,
                    fit: self.fit_preview(&entry.model, catalog),
                }
            })
            .collect()
    }

    /// A coarse fit verdict for a model reference from the catalog hint
    /// and the probed budget.
    fn fit_preview(&self, reference: &str, catalog: &sbproxy_model_host::Catalog) -> FitPreview {
        // Only a catalog id carries a size hint; a raw hf: ref does not.
        let id = reference.split(':').next().unwrap_or(reference);
        let Some(entry) = catalog.get(id) else {
            return FitPreview {
                verdict: "unknown",
                detail: "size is not known without the weights metadata (a raw reference); \
                         the fit is verified when the model is pulled"
                    .to_string(),
                estimated_vram_gib: None,
                quant: None,
            };
        };
        let budget_gib = self
            .gpus
            .iter()
            .map(|g| g.total_vram_bytes)
            .max()
            .map(|b| b as f64 / GIB)
            .unwrap_or(0.0);
        let any_fp8 = self.gpus.iter().any(|g| g.supports_fp8);
        // A quant is runnable on this host if it is not FP8, or the
        // device has FP8 kernels.
        let runnable_quant = entry.quants.iter().find(|q| {
            let is_fp8 = q.to_ascii_lowercase().contains("fp8");
            !is_fp8 || any_fp8
        });
        if budget_gib <= 0.0 {
            return FitPreview {
                verdict: "too-large",
                detail: "no memory budget on this host (no GPU and CPU admission disabled)"
                    .to_string(),
                estimated_vram_gib: Some(entry.min_vram_hint_gib),
                quant: runnable_quant.cloned(),
            };
        }
        match runnable_quant {
            None => FitPreview {
                verdict: "capability-refused",
                detail: format!(
                    "the only listed quants need FP8 kernels this host lacks: {}",
                    entry.quants.join(", ")
                ),
                estimated_vram_gib: Some(entry.min_vram_hint_gib),
                quant: None,
            },
            Some(q) if entry.min_vram_hint_gib <= budget_gib => FitPreview {
                verdict: "fits",
                detail: format!(
                    "estimate {:.0} GiB (catalog hint) within the {:.0} GiB budget; \
                     the precise fit is planned when weights are pulled",
                    entry.min_vram_hint_gib, budget_gib
                ),
                estimated_vram_gib: Some(entry.min_vram_hint_gib),
                quant: Some(q.clone()),
            },
            Some(q) => FitPreview {
                verdict: "too-large",
                detail: format!(
                    "estimate {:.0} GiB (catalog hint) exceeds the {:.0} GiB budget; \
                     use a smaller quant, a longer-VRAM box, or KV quantization",
                    entry.min_vram_hint_gib, budget_gib
                ),
                estimated_vram_gib: Some(entry.min_vram_hint_gib),
                quant: Some(q.clone()),
            },
        }
    }

    /// Process exit code for the CLI: non-zero when a *configured* serve
    /// model has no viable engine on this host (WOR-1799 acceptance). A
    /// too-large fit is a sizing note, not an exit failure; a missing
    /// engine with no acquisition path is.
    pub fn exit_code(&self) -> i32 {
        if self.serve_entries.iter().any(|e| !e.runnable) {
            1
        } else {
            0
        }
    }

    fn engine_for_kind(&self, kind: sbproxy_model_host::EngineKind) -> Option<&EngineBinary> {
        let engine = match kind {
            sbproxy_model_host::EngineKind::Vllm => "vllm",
            sbproxy_model_host::EngineKind::LlamaCpp => "llama_cpp",
            sbproxy_model_host::EngineKind::Embedded => "embedded",
        };
        self.engines.iter().find(|e| e.engine == engine)
    }

    fn engine_path(&self, engine: &str) -> Option<&Path> {
        self.engines
            .iter()
            .find(|e| e.engine == engine)
            .and_then(|e| e.path.as_deref())
    }

    /// Render the human-readable form `sbproxy doctor` prints.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let yn = |b: bool| if b { "yes" } else { "no" };

        out.push_str("host\n");
        out.push_str(&format!(
            "  {} / {}, {} CPU{}",
            self.host.os,
            self.host.arch,
            self.host.cpu_count,
            if self.host.cpu_count == 1 { "" } else { "s" }
        ));
        if let Some(ram) = self.host.total_ram_bytes {
            out.push_str(&format!(", {:.0} GiB RAM", ram as f64 / GIB));
        }
        out.push('\n');

        out.push_str("\nbuild capabilities\n");
        out.push_str(&format!(
            "  gpu-nvidia      (NVIDIA discovery)            {}\n",
            yn(self.features.gpu_nvidia)
        ));
        out.push_str(&format!(
            "  gpu-apple       (Apple Metal discovery)       {}\n",
            yn(self.features.gpu_apple)
        ));
        out.push_str(&format!(
            "  model-weights   (managed weight download)     {}\n",
            yn(self.features.model_weights)
        ));
        out.push_str(&format!(
            "  embedded        (in-process engine)           {}\n",
            yn(self.features.embedded)
        ));

        out.push_str("\ngpus / memory budget\n");
        if self.gpus.is_empty() {
            out.push_str("  none detected (and CPU admission is disabled)\n");
        }
        for gpu in &self.gpus {
            let cc = gpu
                .compute_capability
                .map(|(maj, min)| format!(", compute {maj}.{min}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "  [{}] {} ({})  {:.0} GiB budget, fp8 {}{cc}\n",
                gpu.index,
                gpu.name,
                vendor_label(gpu.vendor),
                gpu.total_vram_bytes as f64 / GIB,
                yn(gpu.supports_fp8),
            ));
        }
        if let Some(drv) = &self.drivers.nvidia_driver {
            out.push_str(&format!("  nvidia driver: {drv}\n"));
        }
        if let Some(cuda) = &self.drivers.cuda {
            out.push_str(&format!("  cuda: {cuda}\n"));
        }
        if self.drivers.metal {
            out.push_str("  metal: available\n");
        }
        if self.drivers.rocm {
            out.push_str("  rocm: tooling present\n");
        }

        out.push_str("\ninference engines\n");
        for engine in &self.engines {
            let where_ = engine
                .path
                .as_ref()
                .map(|p| {
                    let v = engine
                        .version
                        .as_deref()
                        .map(|v| format!(" ({v})"))
                        .unwrap_or_default();
                    format!("{}{v}", p.display())
                })
                .unwrap_or_else(|| match engine.best_option() {
                    Some(opt) => format!("not installed; {}", opt.detail),
                    None => "not installed, no acquisition path on this host".to_string(),
                });
            out.push_str(&format!("  {:<12}{}\n", engine.engine, where_));
        }

        out.push_str("\ntooling\n");
        out.push_str(&format!(
            "  container   {}\n",
            self.container_runtime
                .as_ref()
                .map(|p| {
                    let live = if self.containers.daemon_reachable {
                        " (daemon up)"
                    } else {
                        ""
                    };
                    format!("{}{live}", p.display())
                })
                .unwrap_or_else(|| "not found (docker/podman)".to_string())
        ));
        out.push_str(&format!(
            "  python3     {}\n",
            self.python.python3.as_deref().unwrap_or("not found")
        ));
        out.push_str(&format!(
            "  uv          {}\n",
            self.python.uv.as_deref().unwrap_or("not found")
        ));
        out.push_str(&format!(
            "  brew        {}\n",
            self.package_managers
                .brew
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "not found".to_string())
        ));

        out.push_str("\nhugging face\n");
        out.push_str(&format!("  endpoint   {}\n", self.huggingface.endpoint));
        out.push_str(&format!(
            "  token      {}\n",
            if self.huggingface.token_present {
                "set"
            } else {
                "not set (only needed for gated repos)"
            }
        ));
        if let Some(r) = self.huggingface.reachable {
            out.push_str(&format!("  reachable  {}\n", yn(r)));
        }

        out.push_str(&format!(
            "\nmodel cache\n  {}{}",
            self.model_cache_dir.display(),
            if self.model_cache_exists {
                ""
            } else {
                " (not created yet)"
            }
        ));
        if let Some(free) = self.model_cache_free_bytes {
            out.push_str(&format!("  ({:.0} GiB free)", free as f64 / GIB));
        }
        out.push('\n');

        if !self.serve_entries.is_empty() {
            out.push_str("\nconfigured models\n");
            for e in &self.serve_entries {
                out.push_str(&format!(
                    "  {:<20} {} [{}] -> {}\n",
                    e.model, e.engine_reason, e.fit.verdict, e.fit.detail
                ));
                if let Some(b) = &e.blocker {
                    out.push_str(&format!("    blocked: {b}\n"));
                }
            }
        }

        if self.local_serving.ready {
            out.push_str("\nlocal model serving (serve:): ready\n");
        } else {
            out.push_str("\nlocal model serving (serve:): not available\n");
            for blocker in &self.local_serving.blockers {
                out.push_str(&format!("  - {blocker}\n"));
            }
            if let Some(rec) = &self.local_serving.recommendation {
                out.push_str(&format!("  recommended: {rec}\n"));
            }
        }
        out
    }
}

/// The subset of the environment the acquisition-option logic reads.
struct EngineEnvView {
    os: String,
    arch: String,
    container: bool,
    brew: bool,
    uv: bool,
    pip: bool,
    embedded_feature: bool,
}

/// Build one engine's report: `PATH` resolution, version, and the
/// acquisition options viable on this host, best-first.
fn engine_report(engine: &'static str, program: &'static str, env: &EngineEnvView) -> EngineBinary {
    let path = if program == "embedded" {
        None
    } else {
        find_on_path(program)
    };
    let version = path.as_ref().and_then(|_| match program {
        "llama-server" => run_version("llama-server", &["--version"]),
        "vllm" => run_version("vllm", &["--version"]),
        _ => None,
    });
    let acquisition = match engine {
        "llama_cpp" => llama_acquisition(env, path.is_some()),
        "vllm" => vllm_acquisition(env, path.is_some()),
        "embedded" => vec![AcquisitionOption {
            method: "built-in",
            available: env.embedded_feature,
            detail: if env.embedded_feature {
                "in-process engine compiled in (engine: embedded)".to_string()
            } else {
                "rebuild with --features embedded for the in-process engine".to_string()
            },
        }],
        _ => Vec::new(),
    };
    EngineBinary {
        engine,
        program,
        path,
        version,
        acquisition,
    }
}

fn llama_acquisition(env: &EngineEnvView, on_path: bool) -> Vec<AcquisitionOption> {
    let mut opts = Vec::new();
    if on_path {
        opts.push(AcquisitionOption {
            method: "path",
            available: true,
            detail: "already installed on PATH".to_string(),
        });
    }
    // Prebuilt ggml-org release for this platform, when one exists.
    let prebuilt = match (env.os.as_str(), env.arch.as_str()) {
        ("linux", "x86_64") => Some("ubuntu-x64"),
        ("macos", "aarch64") => Some("macos-arm64"),
        ("macos", "x86_64") => Some("macos-x64"),
        _ => None,
    };
    opts.push(AcquisitionOption {
        method: "prebuilt-release",
        available: prebuilt.is_some(),
        detail: match prebuilt {
            Some(infix) => {
                format!("sbproxy can fetch the pinned ggml-org llama.cpp {infix} release binary")
            }
            None => format!(
                "no prebuilt llama.cpp asset for {}/{}; build from source",
                env.os, env.arch
            ),
        },
    });
    if env.os == "macos" {
        opts.push(AcquisitionOption {
            method: "brew",
            available: env.brew,
            detail: if env.brew {
                "brew install llama.cpp".to_string()
            } else {
                "install Homebrew, then brew install llama.cpp".to_string()
            },
        });
    }
    opts.push(AcquisitionOption {
        method: "source",
        available: true,
        detail: if env.os == "macos" {
            "build from source with -DGGML_METAL=ON".to_string()
        } else {
            "build from source with -DGGML_CUDA=ON (or -DGGML_VULKAN=ON)".to_string()
        },
    });
    opts
}

fn vllm_acquisition(env: &EngineEnvView, on_path: bool) -> Vec<AcquisitionOption> {
    let mut opts = Vec::new();
    let linux = env.os == "linux";
    if on_path {
        opts.push(AcquisitionOption {
            method: "path",
            available: true,
            detail: "already installed on PATH".to_string(),
        });
    }
    // vLLM needs CUDA, so it is Linux-only in practice: a macOS host has
    // no GPU passthrough. uvx is the recommended native path: sbproxy
    // fetches the `uv` binary itself (it does not need to be
    // pre-installed) and runs vLLM via `uv tool run`, so a Linux box needs
    // only the NVIDIA driver. uv even brings its own Python. Set
    // engines.vllm.acquire.source: uvx.
    opts.push(AcquisitionOption {
        method: "uvx",
        available: linux,
        detail: if !linux {
            "vLLM's native install is Linux/CUDA only; use a container here".to_string()
        } else if env.uv {
            "uv present; sbproxy runs vLLM via `uv tool run` (engines.vllm.acquire.source: uvx). \
             Needs a C toolchain + python3 headers (build-essential, python3-dev) for vLLM's \
             Triton JIT"
                .to_string()
        } else {
            "sbproxy fetches uv and runs vLLM via `uv tool run` (engines.vllm.acquire.source: uvx). \
             Needs a C toolchain + python3 headers (build-essential, python3-dev) for vLLM's \
             Triton JIT"
                .to_string()
        },
    });
    // A container is the alternative when a runtime is present.
    opts.push(AcquisitionOption {
        method: "container",
        available: linux && env.container,
        detail: if !linux {
            format!("vLLM needs a Linux/CUDA host; not available on {}", env.os)
        } else if env.container {
            "run the pinned vLLM image via the serve: engines.launch: container path".to_string()
        } else {
            "install docker or podman, then run the pinned vLLM container image".to_string()
        },
    });
    opts.push(AcquisitionOption {
        method: "pip",
        available: linux && env.pip,
        detail: if linux {
            "pip install vllm (a virtualenv is recommended)".to_string()
        } else {
            "vLLM's pip install is Linux/CUDA only".to_string()
        },
    });
    opts
}

/// Decide whether a `serve:` block would admit a model here: the host
/// needs a memory budget (a GPU, Apple unified memory, or CPU RAM) and
/// at least one runnable engine. Produces the single best remediation.
fn serving_verdict(gpus: &[GpuDescriptor], engines: &[EngineBinary]) -> LocalServing {
    let mut blockers = Vec::new();
    let mut recommendation = None;

    if gpus.is_empty() {
        blockers.push(
            "no memory budget: no GPU is visible and CPU admission is disabled \
             (SBPROXY_CPU_MEMORY_FRACTION=0). Unset it, add a GPU, or run on a box \
             with RAM to spare"
                .to_string(),
        );
    }

    // "Installed" = a binary on PATH, or the embedded engine compiled
    // in. That is what can serve *right now*, before acquisition wiring.
    let any_installed = engines
        .iter()
        .any(|e| e.path.is_some() || (e.engine == "embedded" && e.runnable()));
    let any_acquirable = engines.iter().any(|e| e.runnable());

    if !any_installed {
        if any_acquirable {
            // Nothing installed yet, but something is acquirable: name
            // the single best path so the operator has one command.
            if let Some((eng, opt)) = engines
                .iter()
                .filter_map(|e| e.best_option().map(|o| (e, o)))
                .next()
            {
                recommendation = Some(format!("{}: {}", eng.engine, opt.detail));
            }
            blockers.push(
                "no inference engine is installed yet (one can be acquired; see recommendation)"
                    .to_string(),
            );
        } else {
            blockers.push(
                "no inference engine is installed and none can be acquired on this host"
                    .to_string(),
            );
        }
    }

    LocalServing {
        ready: blockers.is_empty(),
        blockers,
        recommendation,
    }
}

fn vendor_label(v: GpuVendor) -> &'static str {
    match v {
        GpuVendor::Nvidia => "NVIDIA",
        GpuVendor::Apple => "Apple",
        GpuVendor::Amd => "AMD",
        GpuVendor::Cpu => "CPU",
    }
}

/// Whether a model reference looks like GGUF weights (steers `auto`
/// toward llama.cpp). The reference string is the best signal before
/// the weights are resolved.
fn looks_gguf(reference: &str) -> bool {
    reference.to_ascii_lowercase().contains("gguf")
}

fn env_present(key: &str) -> bool {
    std::env::var(key)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// Resolve a program on `PATH`, via the model-host resolver so `doctor`,
/// the engine doctor, and the serve preflight agree on "installed".
fn find_on_path(program: &str) -> Option<PathBuf> {
    sbproxy_model_host::resolve_on_path(program)
}

/// Run `program args...` and return the trimmed first non-empty line of
/// output (stdout, then stderr, since many tools print `--version` to
/// stderr). `None` when the program is absent or fails.
fn run_version(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    for stream in [&out.stdout, &out.stderr] {
        let text = String::from_utf8_lossy(stream);
        if let Some(line) = text.lines().find(|l| !l.trim().is_empty()) {
            return Some(line.trim().to_string());
        }
    }
    None
}

fn detect_nvidia_driver() -> Option<String> {
    let out = Command::new("nvidia-smi")
        .args(["--query-gpu=driver_version", "--format=csv,noheader"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
}

fn detect_cuda() -> Option<String> {
    // Prefer nvcc (the toolkit); fall back to the runtime version
    // nvidia-smi reports. `nvcc --version` prints the release on a later
    // line ("Cuda compilation tools, release 12.4, V12.4.131"), so scan
    // the whole output, not just the first line.
    if let Ok(out) = Command::new("nvcc").arg("--version").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(idx) = line.find("release ") {
                let rest = &line[idx + "release ".len()..];
                let ver = rest.split([',', ' ']).next().unwrap_or(rest);
                if !ver.trim().is_empty() {
                    return Some(ver.trim().to_string());
                }
            }
        }
    }
    let out = Command::new("nvidia-smi")
        .args(["--query-gpu=cuda_version", "--format=csv,noheader"])
        .output()
        .ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = s.lines().find(|l| !l.trim().is_empty()) {
            let t = line.trim();
            if !t.is_empty() && t != "[N/A]" {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Whether a container daemon answers `info`. Only called in the deep
/// pass. Best-effort: a down or absent daemon returns false, never hangs
/// the report beyond the command's own exit.
fn container_daemon_reachable(c: &ContainerInfo) -> bool {
    for prog in [c.docker.as_ref(), c.podman.as_ref()].into_iter().flatten() {
        if let Ok(out) = Command::new(prog)
            .args(["info", "--format", "{{.ServerVersion}}"])
            .output()
        {
            if out.status.success() {
                return true;
            }
        }
    }
    false
}

/// A short TLS reachability check for the HF endpoint (deep pass only).
fn endpoint_reachable(endpoint: &str) -> bool {
    use std::net::TcpStream;
    use std::time::Duration;
    let host = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint);
    let host = host.split('/').next().unwrap_or(host);
    let port = if endpoint.starts_with("http://") {
        80
    } else {
        443
    };
    let addr = format!("{host}:{port}");
    // Resolve + connect with a short timeout so a firewalled box does
    // not stall the report.
    match std::net::ToSocketAddrs::to_socket_addrs(&addr) {
        Ok(mut addrs) => addrs
            .next()
            .map(|a| TcpStream::connect_timeout(&a, Duration::from_millis(1500)).is_ok())
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Free bytes on the filesystem that holds `dir` (or its nearest
/// existing ancestor), via `df -Pk`. `None` when it cannot be read.
fn free_disk_bytes(dir: &Path) -> Option<u64> {
    // df needs an existing path; walk up to the first ancestor that is.
    let mut probe = dir;
    while !probe.exists() {
        probe = probe.parent()?;
    }
    let out = Command::new("df").args(["-Pk"]).arg(probe).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Second line, 4th column = available 1K-blocks.
    let line = text.lines().nth(1)?;
    let avail_kib: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(avail_kib.saturating_mul(1024))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_model_host::Catalog;

    #[test]
    fn collect_never_panics_and_serializes() {
        let report = DoctorReport::collect();
        let json = serde_json::to_value(&report).expect("report serializes");
        for key in [
            "host",
            "features",
            "gpus",
            "engines",
            "model_cache_dir",
            "local_serving",
            "drivers",
            "huggingface",
        ] {
            assert!(json.get(key).is_some(), "missing key {key}");
        }
        let _ = report.render_text();
    }

    #[test]
    fn text_report_names_the_verdict_and_host() {
        let report = DoctorReport::collect();
        let text = report.render_text();
        assert!(text.contains("local model serving (serve:):"));
        assert!(text.contains("build capabilities"));
        assert!(text.contains("host\n"));
    }

    #[test]
    fn every_engine_reports_acquisition_options() {
        let report = DoctorReport::collect();
        assert_eq!(report.engines.len(), 3);
        for e in &report.engines {
            assert!(
                !e.acquisition.is_empty(),
                "engine {} has no acquisition options",
                e.engine
            );
        }
    }

    #[test]
    fn mac_recommends_metal_llama_and_marks_vllm_container_only() {
        // WOR-1799 acceptance: on an M-series Mac with nothing installed,
        // llama.cpp has a viable prebuilt/brew/source path and vLLM's
        // native install is not offered (container only).
        let env = EngineEnvView {
            os: "macos".into(),
            arch: "aarch64".into(),
            container: false,
            brew: false,
            uv: false,
            pip: false,
            embedded_feature: false,
        };
        let llama = engine_report("llama_cpp", "llama-server", &env);
        assert!(
            llama.acquisition.iter().any(|o| o.available),
            "llama.cpp must have a viable path on a Mac"
        );
        assert!(llama
            .acquisition
            .iter()
            .any(|o| o.method == "prebuilt-release" && o.available));

        // vLLM needs CUDA, so it is fully N/A on a Mac (no viable option),
        // even with a container runtime, uv, and pip all present.
        let mac_full = EngineEnvView {
            os: "macos".into(),
            arch: "aarch64".into(),
            container: true,
            brew: true,
            uv: true,
            pip: true,
            embedded_feature: false,
        };
        let vllm = engine_report("vllm", "vllm", &mac_full);
        assert!(
            !vllm.acquisition.iter().any(|o| o.available),
            "vLLM must be N/A on macOS: {:?}",
            vllm.acquisition
        );
    }

    #[test]
    fn exit_nonzero_only_when_a_configured_model_has_no_engine() {
        // A bare CPU/Mac report with a serve config for a GGUF model.
        let report = DoctorReport::collect();
        let serve: ModelHostConfig =
            serde_yaml::from_str("models:\n  - model: qwen3-0.6b\n").unwrap();
        let entries = report.evaluate_serve(&serve, &Catalog::builtin());
        assert_eq!(entries.len(), 1);
        // The exit code follows engine runnability, not fit.
        let with = report.with_serve_config(&serve, &Catalog::builtin());
        let code = with.exit_code();
        assert!(code == 0 || code == 1);
        if with.serve_entries[0].runnable {
            assert_eq!(code, 0);
        } else {
            assert_eq!(code, 1);
        }
    }

    #[test]
    fn fit_preview_marks_unknown_for_raw_ref() {
        let report = DoctorReport::collect();
        let serve: ModelHostConfig =
            serde_yaml::from_str("models:\n  - model: hf:Org/Repo:Q4_K_M\n    name: local\n")
                .unwrap();
        let entries = report.evaluate_serve(&serve, &Catalog::builtin());
        assert_eq!(entries[0].fit.verdict, "unknown");
    }
}
