// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Model-host runtime orchestration (WOR-1652 integration).
//!
//! This is the layer that ties the pieces together: given a `serve:`
//! block, [`ModelHostRuntime::ensure_ready`] resolves a model through
//! the [`crate::catalog`], fits a quant to the GPU with
//! [`crate::fit`], admits it against the VRAM budget
//! ([`crate::residency`]) evicting as needed, builds the engine argv
//! ([`crate::launch`]), spawns and supervises it
//! ([`crate::supervisor`]), and returns the loopback port the gateway
//! should route to. The gateway (sbproxy-ai / sbproxy-core) calls
//! `ensure_ready` before dispatching to a `serve:` provider and uses
//! [`ModelHostRuntime::resolved_base_url`] as that provider's upstream.
//!
//! It is generic over the [`EngineLauncher`] so it is exercised on a
//! CPU with a fake launcher, a synthetic GPU probe, and a fixture
//! metadata provider, with no real engine. In production it is
//! parameterized with [`crate::launch::ProcessEngineLauncher`], a real
//! GPU probe, and a metadata provider that reads the fetched
//! `config.json` / GGUF header.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::catalog::{Catalog, ModelRef};
use crate::config::ModelHostConfig;
use crate::fit::{plan_fit_auto, GpuProbe, ModelMetadata, DEFAULT_OVERHEAD};
use crate::launch::{build_launch_spec, serving_flags};
use crate::residency::ResidencyManager;
use crate::supervisor::{BackoffPolicy, EngineLauncher, Supervisor};

/// Supplies the model shape the fit planner needs. The real impl reads
/// the fetched `config.json` / GGUF header for the resolved weights;
/// tests inject a fixture.
pub trait ModelMetadataProvider: Send + Sync {
    /// Metadata for a resolved model, or `None` when it cannot be read.
    fn metadata(&self, model: &ModelRef) -> Option<ModelMetadata>;
}

/// Why bringing a model to ready failed.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// No `serve:` entry with this name.
    #[error("no served model named '{0}'")]
    UnknownModel(String),
    /// Catalog resolution failed.
    #[error("resolve '{model}': {reason}")]
    Resolve {
        /// The reference that failed.
        model: String,
        /// Why.
        reason: String,
    },
    /// No metadata for the resolved model.
    #[error("no model metadata for '{0}' (weights not fetched?)")]
    NoMetadata(String),
    /// The fit planner rejected every candidate.
    #[error("fit: {0}")]
    Fit(String),
    /// The residency budget rejected admission.
    #[error("residency: {0}")]
    Residency(String),
    /// A free loopback port could not be allocated.
    #[error("port allocation: {0}")]
    Port(String),
    /// The engine failed to reach ready.
    #[error("launch: {0}")]
    Launch(String),
}

/// A supervised, resident engine.
struct EngineHandle<L: EngineLauncher> {
    supervisor: Supervisor<L>,
    port: u16,
}

/// The model-host runtime. Owns the resident engines and the VRAM
/// residency for one node.
pub struct ModelHostRuntime<L: EngineLauncher> {
    config: ModelHostConfig,
    catalog: Catalog,
    probe: Arc<dyn GpuProbe>,
    metadata: Arc<dyn ModelMetadataProvider>,
    make_launcher: Box<dyn Fn() -> L + Send + Sync>,
    container_runtime: bool,
    engines: Mutex<HashMap<String, EngineHandle<L>>>,
    residency: Mutex<ResidencyManager>,
    /// Serializes spawns so concurrent `ensure_ready` calls do not
    /// double-start an engine (single-node; a per-model lock is a
    /// later refinement).
    spawn_lock: Mutex<()>,
    tick: AtomicU64,
}

impl<L: EngineLauncher> ModelHostRuntime<L> {
    /// Build a runtime from a `serve:` config, a catalog, a GPU probe,
    /// a metadata provider, and a launcher factory. The VRAM residency
    /// budget is the largest reported GPU's total memory (0 when there
    /// is no GPU, which makes admission reject cleanly on a CPU box).
    /// `container_runtime` is whether docker/podman is available, for
    /// `engine: auto` resolution.
    pub fn new(
        config: ModelHostConfig,
        catalog: Catalog,
        probe: Arc<dyn GpuProbe>,
        metadata: Arc<dyn ModelMetadataProvider>,
        make_launcher: Box<dyn Fn() -> L + Send + Sync>,
        container_runtime: bool,
    ) -> Self {
        let budget = probe
            .probe()
            .iter()
            .map(|g| g.total_vram_bytes)
            .max()
            .unwrap_or(0);
        let residency = ResidencyManager::new(budget, config.eviction);
        Self {
            config,
            catalog,
            probe,
            metadata,
            make_launcher,
            container_runtime,
            engines: Mutex::new(HashMap::new()),
            residency: Mutex::new(residency),
            spawn_lock: Mutex::new(()),
            tick: AtomicU64::new(0),
        }
    }

    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::SeqCst)
    }

    /// The serve entry registered under `name`.
    fn entry_for(&self, name: &str) -> Option<&crate::config::ServeEntry> {
        self.config
            .models
            .iter()
            .find(|e| e.effective_name().ok().as_deref() == Some(name))
    }

    /// The loopback base URL for a ready model, or `None` when it is
    /// not resident/ready.
    pub async fn resolved_base_url(&self, name: &str) -> Option<String> {
        let engines = self.engines.lock().await;
        engines
            .get(name)
            .filter(|h| h.supervisor.state().is_ready())
            .map(|h| format!("http://127.0.0.1:{}/v1", h.port))
    }

    /// Currently resident model names.
    pub async fn resident_models(&self) -> Vec<String> {
        self.engines.lock().await.keys().cloned().collect()
    }

    /// Bring `name` to ready, spawning (and evicting to make room) as
    /// needed, and return its loopback port. Idempotent: an
    /// already-ready model returns its port without respawning.
    pub async fn ensure_ready(&self, name: &str) -> Result<u16, RuntimeError> {
        // Fast path without the spawn lock.
        if let Some(port) = self.ready_port(name).await {
            return Ok(port);
        }
        let _guard = self.spawn_lock.lock().await;
        // Re-check now that we hold the lock.
        if let Some(port) = self.ready_port(name).await {
            return Ok(port);
        }

        let entry = self
            .entry_for(name)
            .ok_or_else(|| RuntimeError::UnknownModel(name.to_string()))?
            .clone();

        let model_ref = self
            .catalog
            .resolve(&entry.model)
            .map_err(|e| RuntimeError::Resolve {
                model: entry.model.clone(),
                reason: e.to_string(),
            })?;

        let meta = self
            .metadata
            .metadata(&model_ref)
            .ok_or_else(|| RuntimeError::NoMetadata(name.to_string()))?;

        let candidates = self.candidate_quants(&model_ref);
        let seq_len = entry.max_context.unwrap_or(meta.max_context);
        let plan = plan_fit_auto(&*self.probe, &meta, &candidates, seq_len, DEFAULT_OVERHEAD)
            .map_err(|e| RuntimeError::Fit(e.to_string()))?;

        let engine_kind = entry.engine.resolve(
            looks_gguf(&plan.quant_name, &model_ref.hf_repo),
            self.container_runtime,
        );

        // Admit against the VRAM budget, evicting the models the
        // residency manager chooses.
        let now = self.next_tick();
        let evicted = {
            let mut res = self.residency.lock().await;
            res.load(name, plan.estimated_vram_bytes, now)
                .map_err(RuntimeError::Residency)?
        };
        for victim in evicted {
            if let Some(mut handle) = self.engines.lock().await.remove(&victim) {
                handle.supervisor.evict().await;
            }
        }

        let port = alloc_port().map_err(RuntimeError::Port)?;
        let mut spec = build_launch_spec(
            engine_kind,
            &model_ref,
            &plan,
            port,
            entry.kv_quant,
            &entry.extra_args,
        );
        spec.args.extend(serving_flags(engine_kind, &entry));

        let mut supervisor =
            Supervisor::new((self.make_launcher)(), spec, BackoffPolicy::default());
        let bound = supervisor
            .ensure_ready()
            .await
            .map_err(|e| RuntimeError::Launch(e.to_string()))?;

        self.engines.lock().await.insert(
            name.to_string(),
            EngineHandle {
                supervisor,
                port: bound,
            },
        );
        Ok(bound)
    }

    /// Unload a model: evict its engine and free its VRAM. No-op when
    /// not resident.
    pub async fn unload(&self, name: &str) {
        if let Some(mut handle) = self.engines.lock().await.remove(name) {
            handle.supervisor.evict().await;
        }
        self.residency.lock().await.unload(name);
    }

    /// The port of a resident, ready model.
    async fn ready_port(&self, name: &str) -> Option<u16> {
        let engines = self.engines.lock().await;
        engines.get(name).and_then(|h| h.supervisor.state().port())
    }

    /// The quant candidates to fit, most-preferred first: the catalog
    /// entry's quant list for a catalog id, else the single quant from
    /// an explicit `hf:` reference (falling back to Q4_K_M).
    fn candidate_quants(&self, model_ref: &ModelRef) -> Vec<String> {
        if let Some(cid) = &model_ref.catalog_id {
            if let Some(entry) = self.catalog.get(cid) {
                if !entry.quants.is_empty() {
                    return entry.quants.clone();
                }
            }
        }
        if !model_ref.quant.is_empty() {
            vec![model_ref.quant.clone()]
        } else {
            vec!["Q4_K_M".to_string()]
        }
    }
}

/// Whether the resolved weights are GGUF (so `engine: auto` picks
/// llama.cpp): a GGUF-style quant name (`Q4_K_M`, `Q5_0`, ...) or a
/// repo whose name advertises GGUF.
fn looks_gguf(quant_name: &str, hf_repo: &str) -> bool {
    let q = quant_name.to_ascii_lowercase();
    let gguf_quant = q.starts_with('q')
        && (q.contains("_k") || q.ends_with("_0") || q.ends_with("_1") || q.contains("_k_"));
    gguf_quant || hf_repo.to_ascii_lowercase().contains("gguf")
}

/// Allocate a free loopback port by binding `:0` and releasing it. The
/// engine will bind it a moment later; the window is small and matches
/// the design's accepted approach.
fn alloc_port() -> Result<u16, String> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind :0: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?
        .port();
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fit::{GpuDescriptor, StaticGpuProbe};
    use crate::supervisor::LaunchSpec;

    /// A launcher that "starts" instantly and reports the port the spec
    /// asked for, recording how many launches happened.
    #[derive(Clone, Default)]
    struct SpecPortLauncher {
        launches: Arc<AtomicU64>,
    }

    impl EngineLauncher for SpecPortLauncher {
        async fn launch(&self, spec: &LaunchSpec) -> Result<u16, String> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            // Parse --port from the spec argv, like the real probe target.
            let mut it = spec.args.iter();
            while let Some(a) = it.next() {
                if a == "--port" {
                    return it
                        .next()
                        .and_then(|p| p.parse().ok())
                        .ok_or_else(|| "bad port".to_string());
                }
            }
            Err("no --port".to_string())
        }
        async fn kill(&self) {}
    }

    struct FixtureMeta;
    impl ModelMetadataProvider for FixtureMeta {
        fn metadata(&self, _m: &ModelRef) -> Option<ModelMetadata> {
            Some(ModelMetadata {
                params: 14_000_000_000,
                layers: 40,
                kv_heads: 8,
                head_dim: 128,
                max_context: 40960,
            })
        }
    }

    fn config(yaml: &str) -> ModelHostConfig {
        serde_yaml::from_str(yaml).expect("serve config")
    }

    fn l4_runtime(cfg: ModelHostConfig) -> ModelHostRuntime<SpecPortLauncher> {
        ModelHostRuntime::new(
            cfg,
            Catalog::builtin(),
            Arc::new(StaticGpuProbe::new(vec![GpuDescriptor::l4()])),
            Arc::new(FixtureMeta),
            Box::new(SpecPortLauncher::default),
            true, // container runtime present
        )
    }

    #[tokio::test]
    async fn ensure_ready_spawns_and_returns_a_port() {
        let rt = l4_runtime(config("models:\n  - model: qwen3-14b\n"));
        let port = rt.ensure_ready("qwen3-14b").await.expect("ready");
        assert!(port > 0);
        // Base URL points at the loopback port.
        let url = rt.resolved_base_url("qwen3-14b").await.unwrap();
        assert_eq!(url, format!("http://127.0.0.1:{port}/v1"));
        assert_eq!(rt.resident_models().await, vec!["qwen3-14b".to_string()]);
    }

    #[tokio::test]
    async fn ensure_ready_is_idempotent() {
        let cfg = config("models:\n  - model: qwen3-14b\n");
        let launcher_calls = Arc::new(AtomicU64::new(0));
        let calls = launcher_calls.clone();
        let rt = ModelHostRuntime::new(
            cfg,
            Catalog::builtin(),
            Arc::new(StaticGpuProbe::new(vec![GpuDescriptor::l4()])),
            Arc::new(FixtureMeta),
            Box::new(move || SpecPortLauncher {
                launches: calls.clone(),
            }),
            true,
        );
        let p1 = rt.ensure_ready("qwen3-14b").await.unwrap();
        let p2 = rt.ensure_ready("qwen3-14b").await.unwrap();
        assert_eq!(p1, p2);
        assert_eq!(launcher_calls.load(Ordering::SeqCst), 1, "spawned once");
    }

    #[tokio::test]
    async fn unknown_model_errors() {
        let rt = l4_runtime(config("models:\n  - model: qwen3-14b\n"));
        assert!(matches!(
            rt.ensure_ready("nope").await,
            Err(RuntimeError::UnknownModel(_))
        ));
    }

    #[tokio::test]
    async fn no_gpu_rejects_via_fit() {
        // Empty probe -> no GPU -> fit planner returns NoGpu.
        let rt = ModelHostRuntime::new(
            config("models:\n  - model: qwen3-14b\n"),
            Catalog::builtin(),
            Arc::new(StaticGpuProbe::default()),
            Arc::new(FixtureMeta),
            Box::new(SpecPortLauncher::default),
            false,
        );
        assert!(matches!(
            rt.ensure_ready("qwen3-14b").await,
            Err(RuntimeError::Fit(_))
        ));
    }

    #[tokio::test]
    async fn hf_ref_needs_a_name_and_serves_under_it() {
        // A raw hf: ref with an explicit name serves under the name.
        let rt = l4_runtime(config(
            "models:\n  - model: hf:Qwen/Qwen3-14B\n    name: local-14b\n",
        ));
        let port = rt.ensure_ready("local-14b").await.expect("ready");
        assert!(port > 0);
    }
}
