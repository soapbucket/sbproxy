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
    /// The `engine:` value a `serve:` block uses (`vllm`, `llama_cpp`).
    pub engine: &'static str,
    /// The program the launcher execs (`vllm`, `llama-server`).
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

/// Whether the `git` binary is present, and what it reports.
///
/// A config that declares `source: {kind: git}` prefers `git` on PATH
/// and falls back to an in-process clone when the binary is missing.
/// `verify_signature: true` still needs git. Doctor reports the binary
/// so an operator can see which path a host will take.
#[derive(Debug, Clone, Serialize)]
pub struct GitBinary {
    /// Resolved path on `PATH`, `None` when absent.
    pub path: Option<PathBuf>,
    /// First line of `git --version`, when it could be run.
    pub version: Option<String>,
}

/// POSIX shared memory (`/dev/shm`), which vLLM's multiprocess
/// tensor-parallel workers use for cross-process tensor handles. A
/// too-small tmpfs there is invisible until a multi-worker vLLM launch
/// crashes with a shared-memory allocation failure, so `doctor` reports
/// it up front rather than at that crash. All fields are `None` on a
/// host with no `/dev/shm` (e.g. macOS): that is a fact, not an error.
#[derive(Debug, Clone, Serialize)]
pub struct SharedMemoryInfo {
    /// The mount checked, `None` when this host has no `/dev/shm`.
    pub path: Option<PathBuf>,
    /// Total size in bytes, when readable.
    pub total_bytes: Option<u64>,
    /// Available bytes, when readable.
    pub available_bytes: Option<u64>,
}

/// Whether the weight-cache mount has enough free space for
/// `serve.cache_budget_gib`, checked once a `serve:` config is
/// supplied (see [`DoctorReport::with_serve_config`]). `cache_budget_gib`
/// sizes the eviction threshold, not a hard cap the OS enforces, so
/// this is an early warning about a mount that cannot even hold the
/// configured budget, not a guarantee the cache will stay under it.
#[derive(Debug, Clone, Serialize)]
pub struct CacheBudgetCheck {
    /// The configured `serve.cache_budget_gib`, when set. `None` means
    /// the cache is unbounded and this check has nothing to compare.
    pub budget_gib: Option<f64>,
    /// Free space on `model_cache_dir`'s filesystem in GiB, when
    /// readable.
    pub free_gib: Option<f64>,
    /// `false` only when both values are known and free space is less
    /// than the configured budget.
    pub sufficient: bool,
}

/// What a `serve:` block demands of the host it was handed to, derived
/// from the config rather than guessed from the hardware present.
///
/// The strict startup gate ([`DoctorReport::strict_checks`]) compares
/// these demands against what the host actually has. Every field is a
/// statement about the *config*, so an empty demand set is the honest
/// answer for a gateway-only node that serves no models locally.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ServeDemand {
    /// The config asks for CUDA: an engine pinned to `acceleration: cuda`,
    /// or a vLLM / SGLang engine, both of which only run on NVIDIA.
    pub requires_cuda: bool,
    /// Engine kinds that drove [`requires_cuda`](Self::requires_cuda),
    /// so a failure can name the entry the operator has to change.
    pub cuda_engines: Vec<String>,
    /// Largest `engines.*.shm_size_gib` the config declares, in bytes.
    /// vLLM and SGLang pass this to the container runtime for their
    /// multiprocess tensor handles, so a `/dev/shm` smaller than this is
    /// a launch failure the operator can be told about at boot.
    pub required_shm_bytes: Option<u64>,
    /// Serve entries naming an unpinned raw reference, which the engine
    /// self-downloads in repo mode rather than loading from a verified
    /// local snapshot. Empty when every entry names a catalog artifact.
    pub unpinned_refs: Vec<String>,
    /// The config set `serve.allow_unpinned_refs`, accepting repo mode on
    /// a worker.
    pub allow_unpinned_refs: bool,
}

/// Peer identity a node needs before it can join the private model
/// plane, extracted from `proxy.cluster` by the caller.
///
/// The doctor deliberately takes this as a flat, pre-resolved input
/// rather than depending on the cluster config type: the only thing it
/// checks is whether the material this node was told to present exists
/// and is readable, which is the failure that turns a fresh worker into
/// a node that gossips but can never serve.
#[derive(Debug, Clone)]
pub struct ModelPlaneIdentity {
    /// This node performs the worker role, so it must be able to
    /// authenticate to the gateway that dispatches to it.
    pub worker_role: bool,
    /// Peer security is mTLS, so cert, key, and CA are all mandatory.
    pub mtls: bool,
    /// Files the config named, each with the config key that named it.
    /// Checked for existence and readability, never parsed here.
    pub files: Vec<(&'static str, PathBuf)>,
    /// mTLS keys the config left unset. Each one is a violation.
    pub missing_keys: Vec<&'static str>,
    /// Shared-key mode resolved a secret. `None` outside shared-key mode.
    pub shared_key_present: Option<bool>,
}

/// One named startup check and its verdict.
///
/// `check` is a stable snake-case id so a bootstrap script can grep for
/// a specific failure; `detail` is the human sentence. A check that does
/// not apply to this host is reported `skipped`, never silently dropped:
/// a certification lane has to be able to tell "passed" from "never ran".
#[derive(Debug, Clone, Serialize)]
pub struct StrictCheck {
    /// Stable check id: `driver`, `visible_devices`, `cuda_compatibility`,
    /// `shared_memory`, `cache_mount`, `model_plane_identity`.
    pub check: &'static str,
    /// `pass`, `fail`, or `skip`.
    pub status: &'static str,
    /// One sentence naming what was compared and what was found.
    pub detail: String,
}

impl StrictCheck {
    /// Whether this check failed, which is what the exit code keys on.
    pub fn failed(&self) -> bool {
        self.status == "fail"
    }
}

/// The full diagnostics report. Serializes to the JSON shape
/// `sbproxy doctor --format json` emits.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// The host environment.
    pub host: HostInfo,
    /// Capability features compiled into the binary.
    pub features: BuildFeatures,
    /// Extension bundles visible to this binary and optional inspected config.
    /// Doctor never presents this stopped-process view as a running generation.
    pub extensions: sbproxy_plugin::ExtensionInventorySnapshot,
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
    /// The `git` binary. Preferred for `source: {kind: git}`; an
    /// in-process fallback is used when it is absent.
    pub git: GitBinary,
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
    /// `/dev/shm` size, relevant to vLLM's multiprocess tensor-parallel
    /// workers.
    pub shared_memory: SharedMemoryInfo,
    /// Per-serve-entry resolution + fit, when a `serve:` config was
    /// supplied (empty otherwise).
    pub serve_entries: Vec<ServeEntryReport>,
    /// Whether the weight-cache mount has enough free space for
    /// `serve.cache_budget_gib`, when a `serve:` config was supplied
    /// (`None` otherwise).
    pub cache_budget_check: Option<CacheBudgetCheck>,
    /// What the supplied `serve:` block demands of this host. Default
    /// (all-empty) until a config is supplied.
    pub serve_demand: ServeDemand,
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
        let extensions = crate::extension_inventory::doctor_inventory(None, Path::new("."), None);
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
        let (git_path, git_version) = crate::config_source::git_binary_status();
        let git = GitBinary {
            path: git_path,
            version: git_version,
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
        };
        let engines = vec![
            engine_report("llama_cpp", "llama-server", &env),
            engine_report("vllm", "vllm", &env),
            engine_report("mistralrs", "mistralrs", &env),
        ];

        let model_cache_dir = sbproxy_model_host::resolve_cache_dir_default(None);
        let model_cache_exists = model_cache_dir.is_dir();
        let model_cache_free_bytes = free_disk_bytes(&model_cache_dir);
        let shared_memory = shared_memory_info();

        let local_serving = serving_verdict(&gpus, &drivers, &engines);

        Self {
            host,
            features,
            extensions,
            gpus,
            drivers,
            nvidia_smi,
            engines,
            container_runtime,
            containers,
            package_managers,
            git,
            python,
            huggingface,
            model_cache_dir,
            model_cache_exists,
            model_cache_free_bytes,
            shared_memory,
            serve_entries: Vec::new(),
            cache_budget_check: None,
            serve_demand: ServeDemand::default(),
            local_serving,
        }
    }

    /// Load extension bundles for a safe diagnostic when candidate construction fails.
    ///
    /// This loader-level fallback cannot prove pipeline attachment, so
    /// successful hooks remain `not_evaluated`. Prefer
    /// [`Self::with_extension_candidate`] after a validation pipeline compiles.
    /// This diagnostic does not alter the existing doctor exit-code rules.
    pub fn with_extension_config(
        mut self,
        config: &sbproxy_config::ExtensionBundlesConfig,
        base_dir: &Path,
        config_revision: Option<&str>,
    ) -> Self {
        self.extensions =
            crate::extension_inventory::doctor_inventory(Some(config), base_dir, config_revision);
        self
    }

    /// Use the attachment inventory owned by a successfully compiled candidate.
    ///
    /// Candidate `active` means the stopped candidate selected and wired the
    /// hook. It makes no claim about live traffic, runtime health, or a
    /// published generation.
    #[must_use]
    pub fn with_extension_candidate(
        mut self,
        candidate: &crate::pipeline::CompiledPipeline,
    ) -> Self {
        debug_assert_eq!(
            candidate.extension_inventory.scope.mode,
            sbproxy_plugin::ExtensionScopeMode::Doctor,
            "doctor must consume a validation candidate inventory"
        );
        self.extensions = candidate.extension_inventory.clone();
        self
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
        self.cache_budget_check = Some(cache_budget_check(
            serve.cache_budget_gib,
            self.model_cache_free_bytes,
        ));
        self.serve_demand = serve_demand(serve);
        self
    }

    /// Record what the canonical `proxy.model_host` block demands of this
    /// host, for the strict gate.
    ///
    /// Two config forms reach the model host: the inline provider-level
    /// `serve:` block, which [`with_serve_config`](Self::with_serve_config)
    /// covers, and `proxy.model_host`, which the examples and the
    /// self-host docs lead with. The strict gate has to see both, or it
    /// reports six cheerful `skip`s for a worker config it cannot serve,
    /// which is precisely the hollow pass the gate exists to prevent.
    ///
    /// Takes pre-extracted values rather than the config type so this
    /// crate keeps its current dependency direction; the caller reads
    /// them off the parsed config.
    pub fn with_control_plane_demand(
        mut self,
        demand: ServeDemand,
        cache_budget_gib: Option<f64>,
    ) -> Self {
        // Whichever form asks for more wins: a config can legitimately
        // carry both, and the host has to satisfy the union.
        self.serve_demand.requires_cuda |= demand.requires_cuda;
        self.serve_demand.cuda_engines.extend(demand.cuda_engines);
        self.serve_demand.cuda_engines.sort();
        self.serve_demand.cuda_engines.dedup();
        self.serve_demand.required_shm_bytes = match (
            self.serve_demand.required_shm_bytes,
            demand.required_shm_bytes,
        ) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        if cache_budget_gib.is_some() {
            let existing = self
                .cache_budget_check
                .as_ref()
                .and_then(|check| check.budget_gib);
            let budget = match (existing, cache_budget_gib) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            self.cache_budget_check = Some(cache_budget_check(budget, self.model_cache_free_bytes));
        }
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
            mistralrs_on_path: self.engine_path("mistralrs").is_some(),
            container_runtime: container_for_resolution,
            // uvx provisions vLLM on Linux (sbproxy fetches uv itself).
            vllm_uvx: self.host.os == "linux",
            gpu_present: !self.gpus.is_empty(),
        };
        serve
            .models
            .iter()
            .map(|entry| {
                let is_gguf = looks_gguf(&entry.model) || entry.gguf_file.is_some();
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

    /// The startup gate a managed worker boots behind (SH-19): the
    /// host conditions that no amount of later retrying can fix, each
    /// reported as a named [`StrictCheck`].
    ///
    /// This is deliberately narrower than the advisory report. `doctor`
    /// on its own answers "what does this host have"; the strict gate
    /// answers the single question a bootstrap script needs: "is booting
    /// this config on this host going to work, or should the boot stop
    /// now with a legible reason". So a missing engine binary is *not* a
    /// violation (acquisition fetches it at the first request), while a
    /// config that asks for CUDA on a box with no driver is: the engine
    /// will never start, and failing at boot beats failing at the first
    /// customer request.
    ///
    /// Checks that do not apply to the supplied config are reported
    /// `skip` rather than omitted, so a certification lane can prove a
    /// check ran instead of inferring it from silence.
    pub fn strict_checks(&self, plane: Option<&ModelPlaneIdentity>) -> Vec<StrictCheck> {
        let mut checks = Vec::new();
        let demand = &self.serve_demand;

        // 1. Driver. Only a CUDA config needs one; Metal and CPU do not.
        checks.push(if !demand.requires_cuda {
            StrictCheck {
                check: "driver",
                status: "skip",
                detail: "the config does not ask for CUDA, so no NVIDIA driver is required"
                    .to_string(),
            }
        } else {
            match &self.drivers.nvidia_driver {
                Some(version) => StrictCheck {
                    check: "driver",
                    status: "pass",
                    detail: format!("NVIDIA driver {version} present"),
                },
                None => StrictCheck {
                    check: "driver",
                    status: "fail",
                    detail: format!(
                        "the config asks for CUDA ({}) but no NVIDIA driver is installed; \
                         boot this on a driver-provided image or install the driver",
                        demand.cuda_engines.join(", ")
                    ),
                },
            }
        });

        // 2. Visible devices. A driver with no visible device is the
        //    classic container misconfiguration (`--gpus` omitted): the
        //    driver answers, the probe sees nothing, every launch fails.
        let cuda_devices = self
            .gpus
            .iter()
            .filter(|gpu| {
                gpu.total_vram_bytes > 0 && gpu.vendor == sbproxy_model_host::GpuVendor::Nvidia
            })
            .count();
        checks.push(if !demand.requires_cuda {
            StrictCheck {
                check: "visible_devices",
                status: "skip",
                detail: "the config does not ask for CUDA, so no accelerator is required"
                    .to_string(),
            }
        } else if cuda_devices > 0 {
            StrictCheck {
                check: "visible_devices",
                status: "pass",
                detail: format!("{cuda_devices} accelerator(s) visible to the probe"),
            }
        } else {
            StrictCheck {
                check: "visible_devices",
                status: "fail",
                detail: "the config asks for CUDA and a driver may be present, but the probe \
                         sees no accelerator; in a container check that the runtime was given \
                         the devices (docker --gpus, podman --device)"
                    .to_string(),
            }
        });

        // 3. CUDA compatibility. `runnable` already folds in compute
        //    capability and FP8 refusals per configured entry.
        let unrunnable: Vec<&ServeEntryReport> =
            self.serve_entries.iter().filter(|e| !e.runnable).collect();
        checks.push(if self.serve_entries.is_empty() {
            StrictCheck {
                check: "cuda_compatibility",
                status: "skip",
                detail: "the config declares no serve entries to resolve".to_string(),
            }
        } else if unrunnable.is_empty() {
            StrictCheck {
                check: "cuda_compatibility",
                status: "pass",
                detail: format!(
                    "all {} configured serve entries resolve to an engine this host can run",
                    self.serve_entries.len()
                ),
            }
        } else {
            StrictCheck {
                check: "cuda_compatibility",
                status: "fail",
                detail: unrunnable
                    .iter()
                    .map(|e| {
                        format!(
                            "{}: {}",
                            e.model,
                            e.blocker.as_deref().unwrap_or("no viable engine")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; "),
            }
        });

        // 4. IPC / shared memory. Compared against the size the config
        //    asked the container runtime for, not an invented floor.
        checks.push(
            match (demand.required_shm_bytes, self.shared_memory.total_bytes) {
                (None, _) => StrictCheck {
                    check: "shared_memory",
                    status: "skip",
                    detail:
                        "no engine declares shm_size_gib, so there is no requested size to check"
                            .to_string(),
                },
                (Some(required), None) => StrictCheck {
                    check: "shared_memory",
                    status: "fail",
                    detail: format!(
                        "the config asks for {:.1} GiB of shared memory but this host exposes no \
                     readable /dev/shm to satisfy it",
                        required as f64 / GIB
                    ),
                },
                (Some(required), Some(total)) if total >= required => StrictCheck {
                    check: "shared_memory",
                    status: "pass",
                    detail: format!(
                        "/dev/shm is {:.1} GiB, at or above the {:.1} GiB the config asks for",
                        total as f64 / GIB,
                        required as f64 / GIB
                    ),
                },
                (Some(required), Some(total)) => StrictCheck {
                    check: "shared_memory",
                    status: "fail",
                    detail: format!(
                        "/dev/shm is {:.1} GiB but the config asks for {:.1} GiB; a multiprocess \
                     engine launch will fail allocating cross-process tensor handles",
                        total as f64 / GIB,
                        required as f64 / GIB
                    ),
                },
            },
        );

        // 5. Cache mount. A mount that cannot hold the configured budget
        //    is a disk-full failure mid-pull, which is worse than a
        //    refusal at boot.
        checks.push(match &self.cache_budget_check {
            None => StrictCheck {
                check: "cache_mount",
                status: "skip",
                detail: "no serve config was supplied, so there is no cache budget to check"
                    .to_string(),
            },
            Some(check) if check.budget_gib.is_none() => StrictCheck {
                check: "cache_mount",
                status: "skip",
                detail: "serve.cache_budget_gib is unset, so the weight cache is unbounded and \
                         there is no budget to compare against the mount"
                    .to_string(),
            },
            Some(check) if check.sufficient => StrictCheck {
                check: "cache_mount",
                status: "pass",
                detail: format!(
                    "{} has {} free for the {} GiB cache budget",
                    self.model_cache_dir.display(),
                    check
                        .free_gib
                        .map(|g| format!("{g:.1} GiB"))
                        .unwrap_or_else(|| "an unreadable amount of space".to_string()),
                    check.budget_gib.unwrap_or_default()
                ),
            },
            Some(check) => StrictCheck {
                check: "cache_mount",
                status: "fail",
                detail: format!(
                    "{} has only {:.1} GiB free but serve.cache_budget_gib is {:.1} GiB; the \
                     mount cannot hold the configured cache",
                    self.model_cache_dir.display(),
                    check.free_gib.unwrap_or_default(),
                    check.budget_gib.unwrap_or_default()
                ),
            },
        });

        // 6. Model-plane identity. A worker that cannot present its
        //    identity joins gossip and then refuses every dispatch, which
        //    reads as a routing bug from the gateway side.
        checks.push(strict_model_plane_check(plane));

        // 7. Unpinned weights on a fleet worker.
        checks.push(strict_unpinned_refs_check(demand, plane));

        checks
    }

    /// Process exit code for `doctor --strict`: `3` when any startup
    /// check failed, otherwise [`exit_code`](Self::exit_code)'s verdict.
    ///
    /// `3` is distinct from `1` (a configured model has no viable engine)
    /// and `2` (the config could not be read) so a bootstrap can tell a
    /// hardware refusal from a config mistake without parsing output.
    pub fn strict_exit_code(&self, checks: &[StrictCheck]) -> i32 {
        if checks.iter().any(StrictCheck::failed) {
            3
        } else {
            self.exit_code()
        }
    }

    fn engine_for_kind(&self, kind: sbproxy_model_host::EngineKind) -> Option<&EngineBinary> {
        let engine = match kind {
            sbproxy_model_host::EngineKind::Vllm => "vllm",
            sbproxy_model_host::EngineKind::SGLang => "sglang",
            sbproxy_model_host::EngineKind::LlamaCpp => "llama_cpp",
            sbproxy_model_host::EngineKind::MistralRs => "mistralrs",
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
        out.push_str(&format!(
            "  git         {}\n",
            match (&self.git.path, &self.git.version) {
                (Some(path), Some(version)) => format!("{} ({version})", path.display()),
                (Some(path), None) => path.display().to_string(),
                (None, _) =>
                    "not found (in-process fallback used for `source: {kind: git}`)".to_string(),
            }
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

        if let Some(check) = &self.cache_budget_check {
            if let Some(budget) = check.budget_gib {
                out.push_str(&format!("  cache budget: {budget:.0} GiB configured"));
                if let Some(free) = check.free_gib {
                    out.push_str(&format!(", {free:.0} GiB free on the mount"));
                }
                out.push_str(if check.sufficient {
                    "\n"
                } else {
                    " (INSUFFICIENT: the mount cannot hold the configured budget)\n"
                });
            }
        }

        out.push_str("\nshared memory (/dev/shm)\n");
        match self.shared_memory.total_bytes {
            Some(total) => {
                out.push_str(&format!("  {:.1} GiB total", total as f64 / GIB));
                if let Some(avail) = self.shared_memory.available_bytes {
                    out.push_str(&format!(", {:.1} GiB available", avail as f64 / GIB));
                }
                out.push('\n');
            }
            None => out.push_str("  not present on this host\n"),
        }

        out.push_str("\nextensions\n");
        out.push_str(&format!(
            "  {} snapshot, schema {}",
            extension_wire_label(&self.extensions.scope.mode),
            self.extensions.schema_version
        ));
        if let Some(revision) = &self.extensions.scope.config_revision {
            out.push_str(&format!(", config revision {revision}"));
        }
        out.push('\n');
        out.push_str(&format!(
            "  {} bundle(s), {} hook(s), {} active, {} available, {} failed, {} collision(s)\n",
            self.extensions.summary.bundles,
            self.extensions.summary.hooks,
            self.extensions.summary.active,
            self.extensions.summary.available,
            self.extensions.summary.failed,
            self.extensions.summary.collisions,
        ));
        out.push_str(
            "  lifecycle: installed, available, active, failed, shadowed, unconsumed, not_evaluated\n",
        );
        if self.extensions.bundles.is_empty() {
            out.push_str("  no extension bundles found\n");
        }
        for bundle in &self.extensions.bundles {
            out.push_str(&format!(
                "  [{}] {} {} ({}, {})\n",
                extension_wire_label(&bundle.state),
                bundle.name,
                bundle.version,
                extension_wire_label(&bundle.runtime),
                extension_wire_label(&bundle.source),
            ));
            out.push_str(&format!(
                "    load: {}/{}",
                bundle.load.phase, bundle.load.status
            ));
            if let Some(detail) = &bundle.load.detail {
                out.push_str(&format!(" ({detail})"));
            }
            out.push('\n');
        }
        for hook in &self.extensions.hooks {
            out.push_str(&format!(
                "    [{}] {}: {} ({})\n",
                extension_wire_label(&hook.state),
                extension_wire_label(&hook.kind),
                hook.match_key,
                hook.id,
            ));
        }
        for collision in &self.extensions.collisions {
            out.push_str(&format!(
                "  collision {}: {} [{}]\n",
                collision.match_key,
                collision.resolution,
                collision.registrations.join(", "),
            ));
        }

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

fn extension_wire_label(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// The subset of the environment the acquisition-option logic reads.
struct EngineEnvView {
    os: String,
    arch: String,
    container: bool,
    brew: bool,
    uv: bool,
    pip: bool,
}

/// Build one engine's report: `PATH` resolution, version, and the
/// acquisition options viable on this host, best-first.
fn engine_report(engine: &'static str, program: &'static str, env: &EngineEnvView) -> EngineBinary {
    let path = find_on_path(program);
    let version = path.as_ref().and_then(|_| match program {
        "llama-server" => run_version("llama-server", &["--version"]),
        "vllm" => run_version("vllm", &["--version"]),
        "mistralrs" => run_version("mistralrs", &["--version"]),
        _ => None,
    });
    let acquisition = match engine {
        "llama_cpp" => llama_acquisition(env, path.is_some()),
        "vllm" => vllm_acquisition(env, path.is_some()),
        "mistralrs" => mistralrs_acquisition(env, path.is_some()),
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
            // The Linux prebuilt is a Vulkan build, which runs on CPU where
            // the GPU's Vulkan driver is absent (e.g. the GCP Deep Learning
            // VM). Say so, and point at the GPU paths.
            Some(infix) if env.os == "linux" => format!(
                "sbproxy fetches the pinned ggml-org llama.cpp {infix} prebuilt (a Vulkan build; \
                 it runs on CPU where the NVIDIA Vulkan driver is absent, e.g. the GCP Deep \
                 Learning VM). For GPU offload, build with CUDA (see the source option) or serve a \
                 safetensors model on vLLM"
            ),
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
            // The copy-pasteable GPU path for a GGUF on Linux/NVIDIA. On
            // PATH, sbproxy prefers this over the fetched Vulkan prebuilt.
            "GPU offload: git clone https://github.com/ggml-org/llama.cpp && \
             cmake llama.cpp -B build -DGGML_CUDA=ON && \
             cmake --build build -j --target llama-server && \
             export PATH=\"$PWD/build/bin:$PATH\""
                .to_string()
        },
    });
    opts
}

fn mistralrs_acquisition(env: &EngineEnvView, on_path: bool) -> Vec<AcquisitionOption> {
    let mut opts = Vec::new();
    if on_path {
        opts.push(AcquisitionOption {
            method: "path",
            available: true,
            detail: "already installed on PATH".to_string(),
        });
    }
    // Upstream v0.9 prebuilts: Metal on Apple Silicon; CPU and per-CUDA
    // compute-capability builds on Linux x86-64. No Intel-mac asset.
    let prebuilt = match (env.os.as_str(), env.arch.as_str()) {
        ("linux", "x86_64") => Some("cpu/cuda x86_64"),
        ("macos", "aarch64") => Some("metal aarch64"),
        _ => None,
    };
    opts.push(AcquisitionOption {
        method: "prebuilt-release",
        available: prebuilt.is_some(),
        detail: match prebuilt {
            Some(assets) if env.os == "linux" => format!(
                "sbproxy fetches the pinned mistral.rs {assets} prebuilt; the CUDA build is \
                 selected by GPU compute capability and needs an NVIDIA driver supporting \
                 CUDA 12.8 or newer"
            ),
            Some(assets) => {
                format!("sbproxy can fetch the pinned mistral.rs {assets} release binary")
            }
            None => format!(
                "no prebuilt mistral.rs asset for {}/{}; use upstream's installer \
                 (it builds from source there)",
                env.os, env.arch
            ),
        },
    });
    opts.push(AcquisitionOption {
        method: "source",
        available: true,
        detail: "curl -fsSL https://raw.githubusercontent.com/EricLBuehler/mistral.rs/master/install.sh | sh (upstream installer; prefers the same prebuilts, builds from source elsewhere)"
            .to_string(),
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
fn serving_verdict(
    gpus: &[GpuDescriptor],
    drivers: &DriverInfo,
    engines: &[EngineBinary],
) -> LocalServing {
    let mut blockers = Vec::new();
    let mut recommendation = None;

    if gpus.is_empty() {
        if drivers.metal {
            blockers.push(
                "Apple Metal is available, but the unified-memory probe reported no budget. \
                 The probe reads hw.memsize via the sysctlbyname syscall (with a sysctl CLI \
                 fallback), so this usually means the binary was built without the default \
                 gpu-apple feature, or SBPROXY_CPU_MEMORY_FRACTION=0 disabled the RAM \
                 fallback. Rebuild with default features, unset that variable, or tune the \
                 budget with SBPROXY_METAL_WORKING_SET_FRACTION (0.1-0.95, default 0.75)"
                    .to_string(),
            );
        } else {
            blockers.push(
                "no memory budget: no GPU is visible and CPU admission is disabled \
                 (SBPROXY_CPU_MEMORY_FRACTION=0). Unset it, add a GPU, or run on a box \
                 with RAM to spare"
                    .to_string(),
            );
        }
    }

    // "Installed" = a binary on PATH. That is what can serve *right
    // now*, before acquisition wiring.
    let any_installed = engines.iter().any(|e| e.path.is_some());
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

/// Probe `/dev/shm` via `df -Pk`, mirroring [`free_disk_bytes`]'s
/// approach but keeping the total column too. Every field is `None` on
/// a host with no `/dev/shm` (e.g. macOS) or where `df` cannot be
/// read; never an error.
fn shared_memory_info() -> SharedMemoryInfo {
    let path = Path::new("/dev/shm");
    if !path.exists() {
        return SharedMemoryInfo {
            path: None,
            total_bytes: None,
            available_bytes: None,
        };
    }
    let absent = SharedMemoryInfo {
        path: Some(path.to_path_buf()),
        total_bytes: None,
        available_bytes: None,
    };
    let Ok(out) = Command::new("df").args(["-Pk"]).arg(path).output() else {
        return absent;
    };
    if !out.status.success() {
        return absent;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Second line: 2nd column = total 1K-blocks, 4th column = available.
    let Some(line) = text.lines().nth(1) else {
        return absent;
    };
    let fields: Vec<&str> = line.split_whitespace().collect();
    let total_bytes = fields
        .get(1)
        .and_then(|s| s.parse::<u64>().ok())
        .map(|kib| kib.saturating_mul(1024));
    let available_bytes = fields
        .get(3)
        .and_then(|s| s.parse::<u64>().ok())
        .map(|kib| kib.saturating_mul(1024));
    SharedMemoryInfo {
        path: Some(path.to_path_buf()),
        total_bytes,
        available_bytes,
    }
}

/// What a `serve:` block demands of its host, read off the config.
///
/// vLLM and SGLang are counted as CUDA demands on their engine kind
/// alone: neither has a non-NVIDIA backend sbproxy can launch, so a
/// config naming them on a driverless box is asking for something that
/// cannot happen, whatever `accel` says.
fn serve_demand(serve: &ModelHostConfig) -> ServeDemand {
    use sbproxy_model_host::{EngineAccel, EngineKind};
    let mut demand = ServeDemand::default();
    for (kind, provisioning) in &serve.engines {
        let cuda_engine = matches!(kind, EngineKind::Vllm | EngineKind::SGLang);
        let cuda_accel = provisioning
            .acquire
            .as_ref()
            .is_some_and(|acquire| acquire.accel == EngineAccel::Cuda);
        if cuda_engine || cuda_accel {
            demand.requires_cuda = true;
            demand
                .cuda_engines
                .push(format!("engines.{kind:?}").to_lowercase());
        }
        if let Some(gib) = provisioning.shm_size_gib {
            let bytes = gib.saturating_mul(1024 * 1024 * 1024);
            demand.required_shm_bytes = Some(demand.required_shm_bytes.unwrap_or(0).max(bytes));
        }
    }
    demand.allow_unpinned_refs = serve.allow_unpinned_refs;
    // A scheme prefix is what makes a reference raw: a catalog id is a
    // bare name, and anything with `hf:` or `file:` in front of it
    // bypasses the catalog's per-file digests entirely.
    demand.unpinned_refs = serve
        .models
        .iter()
        .filter(|entry| is_unpinned_reference(&entry.model))
        .map(|entry| entry.model.clone())
        .collect();
    demand
}

/// Whether a serve entry's `model` is an unpinned raw reference rather
/// than a catalog id with certified per-file digests.
fn is_unpinned_reference(model: &str) -> bool {
    model.starts_with("hf:") || model.starts_with("file:")
}

/// Refuse unpinned raw references on a node that holds the `worker`
/// cluster role, unless the operator opted in.
///
/// Repo mode is not a lesser version of the pinned path, it is a
/// different security posture: the engine container gets DNS and external
/// egress instead of an `--internal` network, a writable cache mount
/// instead of a read-only one, and no digest verification at all, because
/// sbproxy never sees the download. That is the right trade for
/// `sbproxy run <model>` on a workstation and for evaluating a model with
/// no catalog entry. It is the wrong trade for a long-lived node holding
/// cluster identity that a certification lane makes claims about.
///
/// Scoped to the worker role deliberately. A workstation, a gateway-only
/// node, and `sbproxy run` all pass unchanged; only the fleet worker has
/// to say so explicitly.
fn strict_unpinned_refs_check(
    demand: &ServeDemand,
    plane: Option<&ModelPlaneIdentity>,
) -> StrictCheck {
    if demand.unpinned_refs.is_empty() {
        return StrictCheck {
            check: "unpinned_weights",
            status: "skip",
            detail: "every configured serve entry names a catalog artifact with verified digests"
                .to_string(),
        };
    }
    let worker = plane.is_some_and(|plane| plane.worker_role);
    if !worker {
        return StrictCheck {
            check: "unpinned_weights",
            status: "skip",
            detail: format!(
                "{} unpinned reference(s) configured, allowed because this node holds no worker \
                 role; the engine will self-download and no digest will be verified",
                demand.unpinned_refs.len()
            ),
        };
    }
    if demand.allow_unpinned_refs {
        return StrictCheck {
            check: "unpinned_weights",
            status: "pass",
            detail: format!(
                "worker node accepts {} unpinned reference(s) because \
                 serve.allow_unpinned_refs is set: {}",
                demand.unpinned_refs.len(),
                demand.unpinned_refs.join(", ")
            ),
        };
    }
    StrictCheck {
        check: "unpinned_weights",
        status: "fail",
        detail: format!(
            "this node holds the worker role and configures unpinned reference(s) ({}). The \
             engine self-downloads these, so the container runs with external egress and a \
             writable cache and no digest is verified. Give the model a catalog entry with \
             per-file digests, or set serve.allow_unpinned_refs to accept that on this worker",
            demand.unpinned_refs.join(", ")
        ),
    }
}

/// Evaluate the model-plane identity a node was told to present.
///
/// Absent input is a `skip`, not a pass: a config with no cluster block
/// has no model plane to join, and reporting that honestly is what lets
/// a certification lane tell a single-box run from a fleet run.
fn strict_model_plane_check(plane: Option<&ModelPlaneIdentity>) -> StrictCheck {
    let Some(plane) = plane else {
        return StrictCheck {
            check: "model_plane_identity",
            status: "skip",
            detail: "the config declares no proxy.cluster block, so this node joins no model plane"
                .to_string(),
        };
    };
    let mut problems = Vec::new();
    for key in &plane.missing_keys {
        problems.push(format!(
            "proxy.cluster.security.{key} is unset but mTLS requires it"
        ));
    }
    for (key, path) in &plane.files {
        match std::fs::File::open(path) {
            Ok(_) => {}
            Err(error) => problems.push(format!(
                "proxy.cluster.security.{key} names '{}' which is not readable: {error}",
                path.display()
            )),
        }
    }
    if plane.shared_key_present == Some(false) {
        problems.push(
            "proxy.cluster.security.mode is shared_key but no shared_key resolved".to_string(),
        );
    }
    if !problems.is_empty() {
        return StrictCheck {
            check: "model_plane_identity",
            status: "fail",
            detail: problems.join("; "),
        };
    }
    let mode = if plane.mtls { "mTLS" } else { "shared-key" };
    let role = if plane.worker_role {
        "worker"
    } else {
        "non-worker"
    };
    StrictCheck {
        check: "model_plane_identity",
        status: "pass",
        detail: format!(
            "{role} node presents complete {mode} identity material ({} file(s) readable)",
            plane.files.len()
        ),
    }
}

/// Whether the weight-cache mount has enough free space for
/// `serve.cache_budget_gib`. An unset budget and an unreadable
/// free-space probe both report `sufficient: true`: neither is
/// evidence of a problem, only of nothing to compare.
fn cache_budget_check(budget_gib: Option<f64>, free_bytes: Option<u64>) -> CacheBudgetCheck {
    let free_gib = free_bytes.map(|bytes| bytes as f64 / GIB);
    let sufficient = match (budget_gib, free_gib) {
        (Some(budget), Some(free)) => free >= budget,
        _ => true,
    };
    CacheBudgetCheck {
        budget_gib,
        free_gib,
        sufficient,
    }
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
            "shared_memory",
        ] {
            assert!(json.get(key).is_some(), "missing key {key}");
        }
        let _ = report.render_text();
    }

    #[test]
    fn doctor_extensions_json_includes_the_versioned_stopped_snapshot() {
        let report = DoctorReport::collect();
        let json = serde_json::to_value(&report).expect("report serializes");
        let extensions = json
            .get("extensions")
            .expect("doctor JSON should include extensions");

        assert_eq!(
            extensions["schema_version"],
            sbproxy_plugin::EXTENSION_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(extensions["scope"]["mode"], "doctor");
        assert_eq!(extensions["summary"]["active"], 0);
    }

    #[test]
    fn doctor_extensions_use_the_compiled_candidate_attachment_inventory() {
        let directory = tempfile::TempDir::new().expect("temporary extension directory");
        let bundle = directory.path().join("bundles").join("doctor-fixture");
        std::fs::create_dir_all(&bundle).expect("create bundle directory");
        std::fs::write(
            bundle.join("entry.js"),
            "export function enforce() { return { version: 'sbproxy-envelope/v1', decision: 'allow' }; }",
        )
        .expect("write bundle artifact");
        std::fs::write(
            bundle.join("bundle.yaml"),
            r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: doctor-fixture
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: policy
    type: doctor_fixture
    export: enforce
"#,
        )
        .expect("write bundle manifest");
        let config = sbproxy_config::compile_config(
            r#"proxy: {}
extensions:
  bundles_dir: bundles
origins:
  doctor.test:
    action:
      type: static
      body: ok
    policies:
      - type: doctor_fixture
"#,
        )
        .expect("compile doctor candidate config");
        let candidate = crate::pipeline::CompiledPipeline::from_config_for_validation_at(
            config,
            directory.path(),
        )
        .expect("construct stopped doctor candidate");

        let before = DoctorReport::collect();
        let exit_code = before.exit_code();
        let report = before.with_extension_candidate(&candidate);

        assert_eq!(report.exit_code(), exit_code);
        let bundle = report
            .extensions
            .bundles
            .iter()
            .find(|bundle| bundle.id == "doctor-fixture")
            .expect("configured bundle must be reported");
        let hook = report
            .extensions
            .hooks
            .iter()
            .find(|hook| hook.match_key == "doctor_fixture")
            .expect("configured hook must be reported");
        assert_eq!(
            report.extensions.scope.mode,
            sbproxy_plugin::ExtensionScopeMode::Doctor
        );
        assert_eq!(bundle.state, sbproxy_plugin::ExtensionState::Active);
        assert_eq!(hook.state, sbproxy_plugin::ExtensionState::Active);
        assert_eq!(report.extensions.summary.active, 1);
        assert_eq!(
            report.extensions.scope.config_revision.as_deref(),
            Some(candidate.config_revision.as_str())
        );
        assert_eq!(bundle.load.status, "validated");
    }

    #[test]
    fn doctor_extensions_reports_bounded_candidate_failure_without_changing_exit_code() {
        let directory = tempfile::TempDir::new().expect("temporary extension directory");
        let bundle = directory.path().join("bundles").join("broken");
        std::fs::create_dir_all(&bundle).expect("create bundle directory");
        std::fs::write(bundle.join("bundle.yaml"), "not: a bundle").expect("write broken manifest");
        let config = sbproxy_config::ExtensionBundlesConfig {
            bundles_dir: Some("bundles".to_owned()),
            sources: Vec::new(),
            grants: Default::default(),
        };
        let before = DoctorReport::collect();
        let exit_code = before.exit_code();

        let report = before.with_extension_config(&config, directory.path(), None);

        assert_eq!(report.exit_code(), exit_code);
        assert_eq!(report.extensions.summary.failed, 1);
        assert_eq!(report.extensions.bundles[0].id, "unattributed");
        assert_eq!(
            report.extensions.bundles[0].state,
            sbproxy_plugin::ExtensionState::Failed
        );
        let detail = report.extensions.bundles[0]
            .load
            .detail
            .as_deref()
            .expect("failure should carry safe detail");
        assert!(detail.len() <= 512);
        assert!(!detail.contains(directory.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn doctor_extensions_text_names_the_scope_and_lifecycle_state() {
        let report = DoctorReport::collect();
        let text = report.render_text();

        assert!(text.contains("\nextensions\n"), "{text}");
        assert!(text.contains("doctor snapshot"), "{text}");
        assert!(text.contains("not_evaluated"), "{text}");
    }

    /// Look one named check up out of a strict run, so a test asserts on
    /// the check it is about and fails loudly if the id ever moves.
    fn strict_check<'a>(checks: &'a [StrictCheck], name: &str) -> &'a StrictCheck {
        checks
            .iter()
            .find(|check| check.check == name)
            .unwrap_or_else(|| panic!("no strict check named {name}"))
    }

    /// A `serve:` block with one engine, for the demand-extraction tests.
    fn serve_with_engine(
        kind: sbproxy_model_host::EngineKind,
        provisioning: sbproxy_model_host::EngineProvisioning,
    ) -> ModelHostConfig {
        let mut serve = ModelHostConfig::default();
        serve.engines.insert(kind, provisioning);
        serve
    }

    #[test]
    fn strict_without_a_serve_config_skips_every_check_and_exits_zero() {
        // A gateway-only node has nothing local to validate. Every check
        // must say so explicitly rather than reporting a hollow pass.
        let report = DoctorReport::collect();
        let checks = report.strict_checks(None);
        assert_eq!(checks.len(), 7, "every check reports, none are dropped");
        for check in &checks {
            assert_eq!(
                check.status, "skip",
                "check {} should skip with no config, got {}: {}",
                check.check, check.status, check.detail
            );
        }
        assert_eq!(report.strict_exit_code(&checks), 0);
    }

    #[test]
    fn strict_fails_when_cuda_is_configured_without_a_driver() {
        let mut report = DoctorReport::collect();
        report.serve_demand = ServeDemand {
            requires_cuda: true,
            cuda_engines: vec!["engines.vllm".to_string()],
            ..ServeDemand::default()
        };
        report.drivers.nvidia_driver = None;
        report.gpus = Vec::new();

        let checks = report.strict_checks(None);
        let driver = strict_check(&checks, "driver");
        assert_eq!(driver.status, "fail", "{}", driver.detail);
        assert!(
            driver.detail.contains("engines.vllm"),
            "the failure names the offending engine: {}",
            driver.detail
        );
        assert_eq!(report.strict_exit_code(&checks), 3);
    }

    #[test]
    fn strict_fails_when_a_driver_is_present_but_no_device_is_visible() {
        // The `docker run` without `--gpus` case: the driver answers and
        // the probe still sees nothing.
        let mut report = DoctorReport::collect();
        report.serve_demand = ServeDemand {
            requires_cuda: true,
            cuda_engines: vec!["engines.vllm".to_string()],
            ..ServeDemand::default()
        };
        report.drivers.nvidia_driver = Some("550.54.15".to_string());
        report.gpus = Vec::new();

        let checks = report.strict_checks(None);
        assert_eq!(strict_check(&checks, "driver").status, "pass");
        let devices = strict_check(&checks, "visible_devices");
        assert_eq!(devices.status, "fail", "{}", devices.detail);
        assert!(
            devices.detail.contains("--gpus"),
            "the failure names the fix: {}",
            devices.detail
        );
    }

    #[test]
    fn strict_passes_visible_devices_on_a_real_nvidia_descriptor() {
        let mut report = DoctorReport::collect();
        report.serve_demand = ServeDemand {
            requires_cuda: true,
            cuda_engines: vec!["engines.vllm".to_string()],
            ..ServeDemand::default()
        };
        report.drivers.nvidia_driver = Some("550.54.15".to_string());
        report.gpus = vec![sbproxy_model_host::GpuDescriptor::t4()];

        let checks = report.strict_checks(None);
        assert_eq!(strict_check(&checks, "visible_devices").status, "pass");
    }

    #[test]
    fn strict_fails_when_dev_shm_is_smaller_than_the_engine_asked_for() {
        let mut report = DoctorReport::collect();
        report.serve_demand = ServeDemand {
            required_shm_bytes: Some(8 * 1024 * 1024 * 1024),
            ..ServeDemand::default()
        };
        report.shared_memory = SharedMemoryInfo {
            path: Some(PathBuf::from("/dev/shm")),
            total_bytes: Some(64 * 1024 * 1024),
            available_bytes: Some(64 * 1024 * 1024),
        };

        let checks = report.strict_checks(None);
        let shm = strict_check(&checks, "shared_memory");
        assert_eq!(shm.status, "fail", "{}", shm.detail);
        assert!(
            shm.detail.contains("8.0 GiB"),
            "the failure names the requested size: {}",
            shm.detail
        );

        // The same host with a large enough tmpfs passes.
        report.shared_memory.total_bytes = Some(16 * 1024 * 1024 * 1024);
        let checks = report.strict_checks(None);
        assert_eq!(strict_check(&checks, "shared_memory").status, "pass");
    }

    #[test]
    fn strict_fails_when_the_cache_mount_cannot_hold_the_budget() {
        let mut report = DoctorReport::collect();
        report.cache_budget_check = Some(CacheBudgetCheck {
            budget_gib: Some(200.0),
            free_gib: Some(12.5),
            sufficient: false,
        });

        let checks = report.strict_checks(None);
        let mount = strict_check(&checks, "cache_mount");
        assert_eq!(mount.status, "fail", "{}", mount.detail);
        assert!(
            mount.detail.contains("12.5") && mount.detail.contains("200.0"),
            "the failure names both sides of the comparison: {}",
            mount.detail
        );
    }

    #[test]
    fn strict_skips_the_cache_mount_when_the_budget_is_unset() {
        // An unbounded cache is a deliberate choice, not a blocker.
        let mut report = DoctorReport::collect();
        report.cache_budget_check = Some(CacheBudgetCheck {
            budget_gib: None,
            free_gib: Some(12.5),
            sufficient: true,
        });
        let checks = report.strict_checks(None);
        assert_eq!(strict_check(&checks, "cache_mount").status, "skip");
    }

    #[test]
    fn strict_fails_when_mtls_identity_material_is_missing_or_unreadable() {
        let report = DoctorReport::collect();

        // Config named no files at all under mTLS.
        let unset = ModelPlaneIdentity {
            worker_role: true,
            mtls: true,
            files: Vec::new(),
            missing_keys: vec!["cert_file", "key_file", "ca_file"],
            shared_key_present: None,
        };
        let checks = report.strict_checks(Some(&unset));
        let plane = strict_check(&checks, "model_plane_identity");
        assert_eq!(plane.status, "fail", "{}", plane.detail);
        assert!(plane.detail.contains("cert_file"), "{}", plane.detail);
        assert_eq!(report.strict_exit_code(&checks), 3);

        // Config named a file that is not on disk.
        let absent = ModelPlaneIdentity {
            worker_role: true,
            mtls: true,
            files: vec![("cert_file", PathBuf::from("/nonexistent/worker.crt"))],
            missing_keys: Vec::new(),
            shared_key_present: None,
        };
        let checks = report.strict_checks(Some(&absent));
        let plane = strict_check(&checks, "model_plane_identity");
        assert_eq!(plane.status, "fail", "{}", plane.detail);
        assert!(
            plane.detail.contains("worker.crt"),
            "the failure names the unreadable path: {}",
            plane.detail
        );
    }

    #[test]
    fn strict_passes_model_plane_identity_when_every_named_file_is_readable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = dir.path().join("worker.crt");
        let key = dir.path().join("worker.key");
        std::fs::write(&cert, b"pem").expect("write cert");
        std::fs::write(&key, b"pem").expect("write key");

        let report = DoctorReport::collect();
        let plane = ModelPlaneIdentity {
            worker_role: true,
            mtls: true,
            files: vec![("cert_file", cert), ("key_file", key)],
            missing_keys: Vec::new(),
            shared_key_present: None,
        };
        let checks = report.strict_checks(Some(&plane));
        let check = strict_check(&checks, "model_plane_identity");
        assert_eq!(check.status, "pass", "{}", check.detail);
        assert!(check.detail.contains("worker"), "{}", check.detail);
        assert_eq!(report.strict_exit_code(&checks), 0);
    }

    /// A cluster identity carrying only the worker-role bit, which is the
    /// only field the unpinned-weights check reads.
    fn plane_with_worker_role(worker_role: bool) -> ModelPlaneIdentity {
        ModelPlaneIdentity {
            worker_role,
            mtls: false,
            files: Vec::new(),
            missing_keys: Vec::new(),
            shared_key_present: Some(true),
        }
    }

    #[test]
    fn strict_refuses_unpinned_refs_on_a_worker_node() {
        let mut report = DoctorReport::collect();
        report.serve_demand = ServeDemand {
            unpinned_refs: vec!["hf:Qwen/Qwen3-0.6B".to_string()],
            ..ServeDemand::default()
        };

        let checks = report.strict_checks(Some(&plane_with_worker_role(true)));
        let check = strict_check(&checks, "unpinned_weights");
        assert_eq!(check.status, "fail", "{}", check.detail);
        assert!(
            check.detail.contains("hf:Qwen/Qwen3-0.6B"),
            "the failure names the offending entry: {}",
            check.detail
        );
        assert!(
            check.detail.contains("allow_unpinned_refs"),
            "the failure names the opt-out: {}",
            check.detail
        );
        assert_eq!(report.strict_exit_code(&checks), 3);
    }

    #[test]
    fn strict_allows_unpinned_refs_on_a_worker_that_opted_in() {
        // A default change, not a removal. An operator who wants repo mode
        // on a worker says so and owns it.
        let mut report = DoctorReport::collect();
        report.serve_demand = ServeDemand {
            unpinned_refs: vec!["hf:Qwen/Qwen3-0.6B".to_string()],
            allow_unpinned_refs: true,
            ..ServeDemand::default()
        };

        let checks = report.strict_checks(Some(&plane_with_worker_role(true)));
        let check = strict_check(&checks, "unpinned_weights");
        assert_eq!(check.status, "pass", "{}", check.detail);
        assert_eq!(report.strict_exit_code(&checks), 0);
    }

    #[test]
    fn strict_leaves_non_worker_nodes_alone() {
        // `sbproxy run` on a workstation, and a gateway-only node, are the
        // cases repo mode exists for. Neither may be broken by this gate.
        let mut report = DoctorReport::collect();
        report.serve_demand = ServeDemand {
            unpinned_refs: vec!["hf:Qwen/Qwen3-0.6B".to_string()],
            ..ServeDemand::default()
        };

        // No cluster block at all: a workstation.
        let checks = report.strict_checks(None);
        let check = strict_check(&checks, "unpinned_weights");
        assert_eq!(check.status, "skip", "{}", check.detail);
        assert_eq!(report.strict_exit_code(&checks), 0);

        // A cluster node without the worker role: a gateway.
        let checks = report.strict_checks(Some(&plane_with_worker_role(false)));
        let check = strict_check(&checks, "unpinned_weights");
        assert_eq!(check.status, "skip", "{}", check.detail);
        assert!(
            check.detail.contains("no worker role"),
            "the skip says why it did not apply: {}",
            check.detail
        );
        assert_eq!(report.strict_exit_code(&checks), 0);
    }

    #[test]
    fn strict_skips_unpinned_weights_when_every_entry_is_a_catalog_id() {
        let report = DoctorReport::collect();
        let checks = report.strict_checks(Some(&plane_with_worker_role(true)));
        let check = strict_check(&checks, "unpinned_weights");
        assert_eq!(check.status, "skip", "{}", check.detail);
    }

    #[test]
    fn serve_demand_collects_raw_references_and_leaves_catalog_ids_alone() {
        // Parsed from YAML rather than built field by field, so the test
        // exercises the same deserialization an operator's config takes.
        let serve: ModelHostConfig = serde_yaml::from_str(
            "models:\n  \
               - model: qwen2.5-0.5b-instruct\n  \
               - model: hf:Qwen/Qwen3-0.6B\n    name: raw-hf\n  \
               - model: file:/models/local.gguf\n    name: raw-file\n",
        )
        .expect("serve block parses");

        let demand = serve_demand(&serve);
        assert_eq!(
            demand.unpinned_refs,
            vec!["hf:Qwen/Qwen3-0.6B", "file:/models/local.gguf"],
            "a bare catalog id is pinned; a scheme prefix is not"
        );
        assert!(!demand.allow_unpinned_refs, "the default is refuse");
    }

    #[test]
    fn serve_demand_reads_the_allow_unpinned_refs_opt_in() {
        let serve: ModelHostConfig = serde_yaml::from_str(
            "allow_unpinned_refs: true\nmodels:\n  - model: hf:Qwen/Qwen3-0.6B\n    name: raw\n",
        )
        .expect("serve block parses");
        let demand = serve_demand(&serve);
        assert!(demand.allow_unpinned_refs);
        assert_eq!(demand.unpinned_refs.len(), 1);
    }

    #[test]
    fn strict_fails_shared_key_mode_with_no_resolved_secret() {
        let report = DoctorReport::collect();
        let plane = ModelPlaneIdentity {
            worker_role: true,
            mtls: false,
            files: Vec::new(),
            missing_keys: Vec::new(),
            shared_key_present: Some(false),
        };
        let checks = report.strict_checks(Some(&plane));
        let check = strict_check(&checks, "model_plane_identity");
        assert_eq!(check.status, "fail", "{}", check.detail);
        assert!(check.detail.contains("shared_key"), "{}", check.detail);
    }

    #[test]
    fn serve_demand_treats_vllm_and_sglang_as_cuda_demands() {
        use sbproxy_model_host::{EngineKind, EngineProvisioning};
        for kind in [EngineKind::Vllm, EngineKind::SGLang] {
            let serve = serve_with_engine(kind, EngineProvisioning::default());
            let demand = serve_demand(&serve);
            assert!(
                demand.requires_cuda,
                "{kind:?} has no non-NVIDIA backend sbproxy can launch"
            );
            assert_eq!(demand.cuda_engines.len(), 1);
        }
    }

    #[test]
    fn serve_demand_reads_cuda_acceleration_off_a_llama_cpp_acquire_block() {
        use sbproxy_model_host::{EngineAccel, EngineAcquire, EngineKind, EngineProvisioning};
        // llama.cpp is portable, so only an explicit `accel: cuda` makes
        // it a CUDA demand.
        let portable = serve_with_engine(EngineKind::LlamaCpp, EngineProvisioning::default());
        assert!(!serve_demand(&portable).requires_cuda);

        let pinned = serve_with_engine(
            EngineKind::LlamaCpp,
            EngineProvisioning {
                acquire: Some(EngineAcquire {
                    accel: EngineAccel::Cuda,
                    ..EngineAcquire::default()
                }),
                ..EngineProvisioning::default()
            },
        );
        assert!(serve_demand(&pinned).requires_cuda);
    }

    #[test]
    fn serve_demand_takes_the_largest_requested_shm_size() {
        use sbproxy_model_host::{EngineKind, EngineProvisioning};
        let mut serve = ModelHostConfig::default();
        serve.engines.insert(
            EngineKind::Vllm,
            EngineProvisioning {
                shm_size_gib: Some(4),
                ..EngineProvisioning::default()
            },
        );
        serve.engines.insert(
            EngineKind::SGLang,
            EngineProvisioning {
                shm_size_gib: Some(16),
                ..EngineProvisioning::default()
            },
        );
        assert_eq!(
            serve_demand(&serve).required_shm_bytes,
            Some(16 * 1024 * 1024 * 1024),
            "the gate has to satisfy the hungriest engine, not the first one"
        );
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
        };
        let vllm = engine_report("vllm", "vllm", &mac_full);
        assert!(
            !vllm.acquisition.iter().any(|o| o.available),
            "vLLM must be N/A on macOS: {:?}",
            vllm.acquisition
        );
    }

    #[test]
    fn serving_verdict_names_apple_unified_memory_gap() {
        let env = EngineEnvView {
            os: "macos".into(),
            arch: "aarch64".into(),
            container: false,
            brew: false,
            uv: false,
            pip: false,
        };
        let engines = vec![
            engine_report("llama_cpp", "llama-server", &env),
            engine_report("vllm", "vllm", &env),
        ];
        let verdict = serving_verdict(
            &[],
            &DriverInfo {
                nvidia_driver: None,
                cuda: None,
                metal: true,
                rocm: false,
            },
            &engines,
        );

        assert!(!verdict.ready);
        assert!(verdict
            .blockers
            .iter()
            .any(|b| b.contains("Apple Metal is available")));
        assert!(verdict
            .recommendation
            .as_deref()
            .unwrap_or_default()
            .contains("llama_cpp"));
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

    #[test]
    fn shared_memory_info_never_panics_and_serializes() {
        // Smoke test mirroring collect_never_panics_and_serializes: a host
        // with no /dev/shm (macOS) or an unreadable df must report `None`
        // fields, never panic.
        let info = shared_memory_info();
        let json = serde_json::to_value(&info).expect("shared memory info serializes");
        assert!(json.get("total_bytes").is_some());
        assert!(json.get("available_bytes").is_some());
    }

    #[test]
    fn cache_budget_check_flags_insufficient_free_space() {
        let five_gib: u64 = 5 * 1024 * 1024 * 1024;
        let fifty_gib: u64 = 50 * 1024 * 1024 * 1024;

        let insufficient = cache_budget_check(Some(20.0), Some(five_gib));
        assert!(
            !insufficient.sufficient,
            "5 GiB free must not cover a 20 GiB budget"
        );
        assert_eq!(insufficient.budget_gib, Some(20.0));

        let sufficient = cache_budget_check(Some(20.0), Some(fifty_gib));
        assert!(sufficient.sufficient, "50 GiB free covers a 20 GiB budget");

        // No configured budget (unbounded cache) has nothing to compare,
        // so it must not be reported as a problem.
        let unbounded = cache_budget_check(None, Some(five_gib));
        assert!(unbounded.sufficient);

        // An unreadable free-space probe is also not evidence of a
        // problem, only of nothing to compare.
        let unreadable = cache_budget_check(Some(20.0), None);
        assert!(unreadable.sufficient);
    }

    #[test]
    fn vulkan_prebuilt_on_linux_still_flags_cpu_bound_not_gpu_accelerated() {
        // Landmine regression (see llama_release.rs's asset_infix_accel,
        // and main.rs's `run_acceleration` CLI-level vulkan rejection):
        // llama.cpp's only Linux prebuilt is a Vulkan build that runs on
        // CPU where the NVIDIA Vulkan driver is absent -- the shape of
        // the GCP Deep Learning VM, which has the CUDA driver but no
        // Vulkan ICD. `available: true` on that acquisition option means
        // "sbproxy can fetch a working binary," never "this will be GPU
        // accelerated." The two checks added in this change (shared
        // memory, cache budget) are disk/IPC facts that must not blur
        // into a false "GPU ready" signal for this host shape.
        let env = EngineEnvView {
            os: "linux".into(),
            arch: "x86_64".into(),
            container: false,
            brew: false,
            uv: false,
            pip: false,
        };
        let llama = engine_report("llama_cpp", "llama-server", &env);
        let prebuilt = llama
            .acquisition
            .iter()
            .find(|o| o.method == "prebuilt-release")
            .expect("linux always offers the prebuilt-release option");
        assert!(
            prebuilt.available,
            "the Vulkan asset is still a viable acquisition"
        );
        assert!(
            prebuilt.detail.contains("Vulkan") && prebuilt.detail.contains("CPU"),
            "the detail must keep naming the CPU-bound Vulkan caveat: {}",
            prebuilt.detail
        );

        // Neither new check claims GPU acceleration: they are pure
        // disk/IPC facts, independent of the engine-acquisition path.
        let json = serde_json::to_value(shared_memory_info()).expect("serializes");
        assert!(
            json.get("total_bytes").is_some(),
            "shared memory check reports a fact field, not a readiness verdict"
        );
        let check = cache_budget_check(Some(20.0), Some(5 * 1024 * 1024 * 1024));
        assert!(
            !check.sufficient,
            "cache budget check is a disk-space fact and must not report ready just because a GPU was detected"
        );
    }
}
