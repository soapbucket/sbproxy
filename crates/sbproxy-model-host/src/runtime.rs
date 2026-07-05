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
use crate::fit::{plan_fit_auto_kv, GpuProbe, ModelMetadata, DEFAULT_OVERHEAD};
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

/// Observes model-host lifecycle events so a host can emit metrics
/// (WOR-1659) without this crate depending on the metrics stack. The
/// runtime calls these at spawn / ready / evict points; the default
/// impls are no-ops so a test or embedder can implement only what it
/// needs. `sbproxy-core` provides an impl that records the
/// `sbproxy_model_host_*` metrics. All methods are synchronous (they
/// only touch counters/gauges) so they are safe to call inside the
/// runtime's async paths.
pub trait ModelHostObserver: Send + Sync {
    /// An engine reached ready `secs` after launch. `engine` is the
    /// resolved engine name, `model` the served name.
    fn on_engine_ready(&self, engine: &str, model: &str, secs: f64) {
        let _ = (engine, model, secs);
    }
    /// An engine failed to reach ready `secs` after launch.
    fn on_engine_failed(&self, engine: &str, model: &str, secs: f64) {
        let _ = (engine, model, secs);
    }
    /// A resident engine was evicted. `reason` is a short static label
    /// (`make_room`, `unload`, `restart`).
    fn on_eviction(&self, reason: &'static str) {
        let _ = reason;
    }
    /// The count of resident (loaded) models changed to `count`.
    fn set_resident_models(&self, count: i64) {
        let _ = count;
    }
    /// Current GPU stats for `device` (index), for the residency budget
    /// view: total and free VRAM in bytes and the used fraction.
    fn set_gpu_stats(&self, device: &str, total_bytes: u64, free_bytes: u64, utilization: f64) {
        let _ = (device, total_bytes, free_bytes, utilization);
    }
    /// A LoRA adapter was loaded onto a base engine (WOR-1709), i.e. a
    /// dynamic-paging cache miss that reached the engine.
    fn on_adapter_loaded(&self, base: &str, adapter: &str) {
        let _ = (base, adapter);
    }
    /// A LoRA adapter was paged out of a base engine's adapter cache to
    /// make room past `max_loras` (WOR-1709).
    fn on_adapter_evicted(&self, base: &str, adapter: &str) {
        let _ = (base, adapter);
    }
    /// The total count of resident (loaded) LoRA adapters across all base
    /// engines changed to `count` (WOR-1709).
    fn set_resident_adapters(&self, count: i64) {
        let _ = count;
    }
    /// Bringing `model` to ready failed (WOR-1711). `reason` is a short
    /// static category (`unknown_model`, `resolve`, `no_metadata`, `fit`,
    /// `residency`, `port`, `launch`), distinguishing a model that cannot
    /// fit the GPU from an engine that crash-loops.
    fn on_ensure_failed(&self, model: &str, reason: &'static str) {
        let _ = (model, reason);
    }
    /// A model-host weight pre-fetch completed (WOR-1712): `bytes`
    /// downloaded in `secs`, `ok` false on failure. Lets a slow or
    /// failing multi-GB GGUF pull surface before the launch times out.
    fn on_weight_download(&self, model: &str, bytes: u64, secs: f64, ok: bool) {
        let _ = (model, bytes, secs, ok);
    }
}

/// A [`ModelHostObserver`] that does nothing; the runtime default.
pub struct NoopObserver;
impl ModelHostObserver for NoopObserver {}

/// A point-in-time view of the model host for the status admin API
/// (WOR-1665): what is loaded now and the VRAM picture. Serializable so
/// an admin handler can return it as JSON.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelHostStatus {
    /// Currently resident models, one entry each, sorted by name.
    pub models: Vec<ModelStatus>,
    /// VRAM residency + per-device view.
    pub vram: VramStatus,
}

/// The status of one resident model.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelStatus {
    /// The served model name (the id every plane sees).
    pub name: String,
    /// Engine lifecycle state (loading / ready / failed / evicted).
    pub state: crate::supervisor::EngineState,
    /// The loopback port, when ready.
    pub port: Option<u16>,
    /// The fit-planner VRAM estimate for this engine, in bytes.
    pub vram_bytes: u64,
    /// Configured `keep_alive` TTL in seconds, if any (config value; TTL
    /// enforcement is a later refinement).
    pub keep_alive_secs: Option<u64>,
}

/// The residency + per-device VRAM view.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VramStatus {
    /// Residency budget (the largest device's total VRAM), in bytes.
    pub budget_bytes: u64,
    /// VRAM the resident set is estimated to use, in bytes.
    pub used_bytes: u64,
    /// Budget headroom, in bytes.
    pub free_bytes: u64,
    /// Per-device totals from the GPU probe.
    pub devices: Vec<DeviceVram>,
}

/// One GPU device's VRAM totals from the probe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceVram {
    /// Device index.
    pub index: u32,
    /// Device name.
    pub name: String,
    /// Total VRAM, in bytes.
    pub total_bytes: u64,
    /// Free VRAM at the last probe, in bytes.
    pub free_bytes: u64,
}

/// Parse a catalog `params` string (`14B`, `30B-A3B`, `120b`, `8M`)
/// into an approximate total parameter count. Reads the leading number
/// and its magnitude suffix; ignores any trailing shape detail (the
/// `-A3B` active-params note). Returns 0 when there is no leading
/// number.
pub fn parse_params(s: &str) -> u64 {
    let s = s.trim();
    let num: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let value: f64 = num.parse().unwrap_or(0.0);
    let rest = s[num.len()..].to_ascii_lowercase();
    let mult = if rest.starts_with('b') {
        1e9
    } else if rest.starts_with('m') {
        1e6
    } else if rest.starts_with('k') {
        1e3
    } else {
        1.0
    };
    (value * mult) as u64
}

/// A [`ModelMetadataProvider`] that reads the model's `config.json`
/// from the content-addressed weight cache and parses its shape. The
/// total parameter count comes from the catalog entry's `params`
/// string (or the config's own `num_parameters` when present). This is
/// the production provider: the weight manager fetches `config.json`,
/// this reads it, and the fit planner uses it.
pub struct ConfigDirMetadataProvider {
    /// Root of the content-addressed weight cache.
    pub cache_root: std::path::PathBuf,
    /// Revision the weights were fetched at.
    pub revision: String,
    /// Catalog, for the parameter-count lookup.
    pub catalog: Catalog,
}

impl ModelMetadataProvider for ConfigDirMetadataProvider {
    fn metadata(&self, model: &ModelRef) -> Option<ModelMetadata> {
        let path = crate::weights::cache_file(
            &self.cache_root,
            &model.hf_repo,
            &self.revision,
            "config.json",
        );
        let text = std::fs::read_to_string(&path).ok()?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        let params = model
            .catalog_id
            .as_ref()
            .and_then(|id| self.catalog.get(id))
            .map(|e| parse_params(&e.params))
            .filter(|p| *p > 0)
            .or_else(|| v.get("num_parameters").and_then(|x| x.as_u64()))
            .unwrap_or(0);
        ModelMetadata::from_hf_config(&v, params)
    }
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

impl RuntimeError {
    /// A short static label for the failure category (WOR-1711), for the
    /// `sbproxy_model_host_ensure_failures_total{reason}` metric.
    pub fn reason_label(&self) -> &'static str {
        match self {
            RuntimeError::UnknownModel(_) => "unknown_model",
            RuntimeError::Resolve { .. } => "resolve",
            RuntimeError::NoMetadata(_) => "no_metadata",
            RuntimeError::Fit(_) => "fit",
            RuntimeError::Residency(_) => "residency",
            RuntimeError::Port(_) => "port",
            RuntimeError::Launch(_) => "launch",
        }
    }
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
    /// When true, `ensure_ready` re-probes a cached-ready engine's
    /// `/health` and respawns it if the probe fails (so a `kill -9`ed
    /// engine comes back on the next request). Off by default so mock
    /// launchers with no real HTTP endpoint are not falsely respawned;
    /// the production runtime turns it on.
    health_recheck: bool,
    /// Lifecycle observer for metrics (WOR-1659). Defaults to a no-op;
    /// the host injects a metrics-recording impl.
    observer: Arc<dyn ModelHostObserver>,
    /// Per-base-model LoRA adapter LRU caches (WOR-1673), keyed by base
    /// name. Present only for entries that page adapters dynamically;
    /// tracks which adapters are loaded on each engine so a request for
    /// an adapter loads it (evicting the LRU) via the vLLM load/unload
    /// API. Cleared when the engine is dropped so a respawn reloads.
    lora_caches: Mutex<HashMap<String, crate::lora::LoraCache>>,
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
            health_recheck: false,
            observer: Arc::new(NoopObserver),
            lora_caches: Mutex::new(HashMap::new()),
        }
    }

    /// Turn on `/health` re-checking of cached-ready engines, so a
    /// dead engine is respawned on the next `ensure_ready`. The
    /// production runtime enables this; tests with mock launchers leave
    /// it off.
    pub fn with_health_recheck(mut self, on: bool) -> Self {
        self.health_recheck = on;
        self
    }

    /// Attach a lifecycle observer for metrics (WOR-1659). The
    /// production runtime injects an impl that records the
    /// `sbproxy_model_host_*` metrics.
    pub fn with_observer(mut self, observer: Arc<dyn ModelHostObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Emit the current GPU residency view (per device) to the observer.
    fn report_gpu_stats(&self) {
        for g in self.probe.probe() {
            let util = if g.total_vram_bytes > 0 {
                (g.total_vram_bytes.saturating_sub(g.free_vram_bytes)) as f64
                    / g.total_vram_bytes as f64
            } else {
                0.0
            };
            self.observer.set_gpu_stats(
                &g.index.to_string(),
                g.total_vram_bytes,
                g.free_vram_bytes,
                util,
            );
        }
    }

    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::SeqCst)
    }

    /// The serve entry that serves `name` (its base name or a LoRA
    /// adapter name, WOR-1673).
    fn entry_for(&self, name: &str) -> Option<&crate::config::ServeEntry> {
        self.config.models.iter().find(|e| e.serves(name))
    }

    /// The base engine key for `name`: `name`'s own base name, or, when
    /// `name` is a LoRA adapter, its base model's name. Engines are
    /// keyed by base name (one engine serves the base and all its
    /// adapters), so this is the lookup key for a request. `None` when
    /// nothing serves `name`.
    fn base_name_for(&self, name: &str) -> Option<String> {
        self.entry_for(name).and_then(|e| e.effective_name().ok())
    }

    /// The loopback base URL for a ready model (or a ready adapter of
    /// it), or `None` when it is not resident/ready.
    pub async fn resolved_base_url(&self, name: &str) -> Option<String> {
        let base = self.base_name_for(name)?;
        let engines = self.engines.lock().await;
        engines
            .get(&base)
            .filter(|h| h.supervisor.state().is_ready())
            .map(|h| format!("http://127.0.0.1:{}/v1", h.port))
    }

    /// Currently resident model names.
    pub async fn resident_models(&self) -> Vec<String> {
        self.engines.lock().await.keys().cloned().collect()
    }

    /// A point-in-time status snapshot for the admin API (WOR-1665):
    /// resident models with their engine state, port, and VRAM
    /// estimate, plus the residency budget and per-device totals.
    pub async fn status_snapshot(&self) -> ModelHostStatus {
        let mut models: Vec<ModelStatus> = {
            let engines = self.engines.lock().await;
            engines
                .iter()
                .map(|(name, handle)| {
                    let state = handle.supervisor.state();
                    let port = state.port();
                    let keep_alive_secs = self
                        .config
                        .models
                        .iter()
                        .find(|e| e.effective_name().ok().as_deref() == Some(name.as_str()))
                        .and_then(|e| e.keep_alive_duration())
                        .map(|d| d.as_secs());
                    ModelStatus {
                        name: name.clone(),
                        state,
                        port,
                        vram_bytes: handle.supervisor.vram_bytes(),
                        keep_alive_secs,
                    }
                })
                .collect()
        };
        models.sort_by(|a, b| a.name.cmp(&b.name));

        let (used_bytes, free_bytes) = {
            let res = self.residency.lock().await;
            (res.used_bytes(), res.free_bytes())
        };
        let devices = self
            .probe
            .probe()
            .into_iter()
            .map(|g| DeviceVram {
                index: g.index,
                name: g.name,
                total_bytes: g.total_vram_bytes,
                free_bytes: g.free_vram_bytes,
            })
            .collect();

        ModelHostStatus {
            models,
            vram: VramStatus {
                budget_bytes: used_bytes + free_bytes,
                used_bytes,
                free_bytes,
                devices,
            },
        }
    }

    /// Bring `name` to ready, spawning (and evicting to make room) as
    /// needed, and return its loopback port. Idempotent: an
    /// already-ready model returns its port without respawning.
    ///
    /// `name` may be a served model or one of its LoRA adapters
    /// (WOR-1673); an adapter request brings up (or reuses) the base
    /// model's engine and, in dynamic-paging mode, loads the adapter on
    /// that engine (evicting the LRU adapter past the cap).
    pub async fn ensure_ready(&self, name: &str) -> Result<u16, RuntimeError> {
        // Map an adapter name to its base model's engine key; unknown
        // names fall through to the base path and surface UnknownModel.
        let base = self.base_name_for(name).unwrap_or_else(|| name.to_string());
        // WOR-1711: record every failure category so a model that cannot
        // fit the GPU is distinguishable from an engine that crash-loops.
        let port = match self.ensure_base_ready(&base).await {
            Ok(p) => p,
            Err(e) => {
                self.observer.on_ensure_failed(name, e.reason_label());
                return Err(e);
            }
        };
        // Requested an adapter (not the base): ensure it is loaded on the
        // engine. A no-op for statically-preloaded adapters.
        if name != base {
            if let Err(e) = self.ensure_adapter_loaded(&base, name, port).await {
                self.observer.on_ensure_failed(name, e.reason_label());
                return Err(e);
            }
        }
        Ok(port)
    }

    /// Load the LoRA adapter `adapter` on the base engine at `port` if
    /// it is not already resident, paging out the LRU adapter past the
    /// engine's `max_loras` cap (WOR-1673). A no-op unless the base
    /// entry pages adapters dynamically (statically-preloaded adapters
    /// are already on the engine from launch).
    async fn ensure_adapter_loaded(
        &self,
        base: &str,
        adapter: &str,
        port: u16,
    ) -> Result<(), RuntimeError> {
        let Some(entry) = self.entry_for(base) else {
            return Ok(());
        };
        if !entry.dynamic_lora() {
            return Ok(()); // preloaded at launch; nothing to page.
        }
        let capacity = entry.lora_capacity();
        let adapters = entry.lora_adapters.clone();
        // Decide the load/evict under the cache lock, then release it
        // before the (slow) HTTP calls so we do not hold it across await
        // on the engine.
        let route = {
            let mut caches = self.lora_caches.lock().await;
            let cache = caches
                .entry(base.to_string())
                .or_insert_with(|| crate::lora::LoraCache::new(base, &adapters, capacity));
            cache.route(adapter)
        };
        use crate::lora::AdapterRoute;
        let (source, evict) = match route {
            AdapterRoute::Resident { .. } | AdapterRoute::Base => return Ok(()),
            AdapterRoute::Unknown => return Err(RuntimeError::UnknownModel(adapter.to_string())),
            AdapterRoute::Load { source, evict } => (source, evict),
        };
        // Free the slot first so a full engine accepts the new adapter,
        // then load. vLLM's path/name for load is the source with any
        // `hf:` scheme stripped (it takes an HF repo id or local path).
        if let Some(victim) = &evict {
            let body = format!("{{\"lora_name\":\"{victim}\"}}");
            let _ = crate::launch::post_json(
                port,
                "/v1/unload_lora_adapter",
                &body,
                std::time::Duration::from_secs(30),
            )
            .await;
        }
        let path = source.strip_prefix("hf:").unwrap_or(&source);
        let body = format!("{{\"lora_name\":\"{adapter}\",\"lora_path\":\"{path}\"}}");
        match crate::launch::post_json(
            port,
            "/v1/load_lora_adapter",
            &body,
            std::time::Duration::from_secs(120),
        )
        .await
        {
            Ok(()) => {
                // WOR-1709: the adapter reached the engine. Report the
                // load, any paged-out victim, and the new resident count.
                self.observer.on_adapter_loaded(base, adapter);
                if let Some(victim) = &evict {
                    self.observer.on_adapter_evicted(base, victim);
                }
                self.observer
                    .set_resident_adapters(self.resident_adapter_count().await);
                Ok(())
            }
            Err(e) => {
                // Roll the cache back so the next request retries the load
                // rather than assuming this adapter is resident.
                if let Some(c) = self.lora_caches.lock().await.get_mut(base) {
                    c.forget(adapter);
                }
                Err(RuntimeError::Launch(format!(
                    "load lora adapter '{adapter}': {e}"
                )))
            }
        }
    }

    /// Total resident (loaded) LoRA adapters across all base engines
    /// (WOR-1709), for the `resident_adapters` gauge.
    async fn resident_adapter_count(&self) -> i64 {
        self.lora_caches
            .lock()
            .await
            .values()
            .map(|c| c.loaded().len() as i64)
            .sum()
    }

    /// Pre-fetch the configured GGUF file for a llama.cpp model
    /// (WOR-1656) into the weight cache, returning its local path so the
    /// engine can load it with `--model` instead of downloading via
    /// `--hf-repo`. Returns `None` when no `gguf_file` is configured, the
    /// `weights` feature is off, or the fetch fails, in which case the
    /// caller falls back to the download path.
    #[cfg(feature = "weights")]
    async fn prefetch_gguf(
        &self,
        entry: &crate::config::ServeEntry,
        model_ref: &ModelRef,
    ) -> Option<std::path::PathBuf> {
        let file = entry.gguf_file.as_deref()?;
        let model = entry
            .effective_name()
            .unwrap_or_else(|_| model_ref.hf_repo.clone());
        let cache_root = crate::manifest::resolve_cache_dir(self.config.cache_dir.as_deref(), None);
        let started = std::time::Instant::now();
        let outcome =
            crate::weights::ensure_weight_file(&cache_root, &model_ref.hf_repo, "main", file, None)
                .await;
        let secs = started.elapsed().as_secs_f64();
        match outcome {
            Ok(path) => {
                // WOR-1712: report the pulled size so a slow multi-GB
                // download is visible. Stat the file (0 if unreadable).
                let bytes = tokio::fs::metadata(&path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0);
                self.observer.on_weight_download(&model, bytes, secs, true);
                Some(path)
            }
            Err(e) => {
                self.observer.on_weight_download(&model, 0, secs, false);
                tracing::warn!(
                    "model host: GGUF pre-fetch failed for {}/{file}: {e}; falling back to --hf-repo",
                    model_ref.hf_repo
                );
                None
            }
        }
    }

    #[cfg(not(feature = "weights"))]
    async fn prefetch_gguf(
        &self,
        _entry: &crate::config::ServeEntry,
        _model_ref: &ModelRef,
    ) -> Option<std::path::PathBuf> {
        None
    }

    /// Bring the base model `name`'s engine to ready, spawning (and
    /// evicting to make room) as needed, and return its loopback port.
    /// `name` here is always a base model name (adapter names are mapped
    /// to their base by [`Self::ensure_ready`]).
    async fn ensure_base_ready(&self, name: &str) -> Result<u16, RuntimeError> {
        // Fast path without the spawn lock.
        if let Some(port) = self.ready_and_live(name).await {
            return Ok(port);
        }
        let _guard = self.spawn_lock.lock().await;
        // Re-check now that we hold the lock.
        if let Some(port) = self.ready_and_live(name).await {
            return Ok(port);
        }
        // A cached engine that failed the liveness check (or a Failed
        // supervisor) is dropped so we respawn cleanly and free its
        // residency slot.
        self.drop_engine(name).await;

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
        // WOR-1676: if the entry quantizes the KV cache, the planner
        // spends the smaller KV term on the fit (so a card can hold a
        // context it could not at f16 KV). `bytes_per_element()` is
        // `None` for Auto/F16, which follows the weight quant's default.
        let kv_bpe = entry.kv_quant.bytes_per_element();
        let plan = plan_fit_auto_kv(
            &*self.probe,
            &meta,
            &candidates,
            seq_len,
            DEFAULT_OVERHEAD,
            kv_bpe,
        )
        .map_err(|e| RuntimeError::Fit(e.to_string()))?;

        let engine_kind = entry.engine.resolve(
            looks_gguf(&plan.quant_name, &model_ref.hf_repo),
            self.container_runtime,
        );

        // Admit against the VRAM budget, evicting the models the
        // residency manager chooses. WOR-1672: use the cost-minimizing
        // solver, not plain LRU. Reload cost is dominated by weight
        // size (a 2026 multi-model-scheduler study), so estimate it from
        // the planned VRAM; `pinned` entries are never evicted.
        let now = self.next_tick();
        let reload_cost_ms = reload_cost_ms_for(plan.estimated_vram_bytes);
        let evicted = {
            let mut res = self.residency.lock().await;
            res.load_managed(
                name,
                plan.estimated_vram_bytes,
                now,
                reload_cost_ms,
                entry.pinned,
            )
            .map_err(RuntimeError::Residency)?
        };
        for victim in evicted {
            if let Some(mut handle) = self.engines.lock().await.remove(&victim) {
                handle.supervisor.evict().await;
                self.observer.on_eviction("make_room");
            }
        }
        // The residency budget (and, on a GPU host, the live probe) is
        // where the VRAM view is freshest; report it as engines change.
        self.report_gpu_stats();

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
        // WOR-1673: dynamic adapter paging needs vLLM's runtime LoRA
        // update endpoints, which are gated behind this env var.
        if entry.dynamic_lora() {
            spec.env.push((
                "VLLM_ALLOW_RUNTIME_LORA_UPDATING".to_string(),
                "1".to_string(),
            ));
        }
        // WOR-1656: for llama.cpp, prefer a locally pre-fetched GGUF over
        // letting the engine download via `--hf-repo`. That needs a
        // curl-enabled llama.cpp and, for a multi-file repo, picks the
        // wrong file. Pre-fetching with our own weight manager and
        // passing `--model` removes both problems; if we cannot fetch
        // (the `weights` feature is off), fall back to `--hf-file` so a
        // curl build at least gets the right file.
        if engine_kind == crate::config::EngineKind::LlamaCpp {
            if let Some(local) = self.prefetch_gguf(&entry, &model_ref).await {
                crate::launch::llama_use_local_model(&mut spec.args, &local);
            } else if let Some(file) = &entry.gguf_file {
                crate::launch::llama_set_hf_file(&mut spec.args, file);
            }
        }

        let engine_label = engine_kind.binary_name();
        let started = std::time::Instant::now();
        let mut supervisor =
            Supervisor::new((self.make_launcher)(), spec, BackoffPolicy::default());
        let bound = match supervisor.ensure_ready().await {
            Ok(bound) => {
                self.observer
                    .on_engine_ready(engine_label, name, started.elapsed().as_secs_f64());
                bound
            }
            Err(e) => {
                self.observer
                    .on_engine_failed(engine_label, name, started.elapsed().as_secs_f64());
                return Err(RuntimeError::Launch(e.to_string()));
            }
        };

        let resident = {
            let mut engines = self.engines.lock().await;
            engines.insert(
                name.to_string(),
                EngineHandle {
                    supervisor,
                    port: bound,
                },
            );
            engines.len() as i64
        };
        self.observer.set_resident_models(resident);
        Ok(bound)
    }

    /// Unload a model: evict its engine and free its VRAM. No-op when
    /// not resident.
    pub async fn unload(&self, name: &str) {
        let resident = {
            let mut engines = self.engines.lock().await;
            if let Some(mut handle) = engines.remove(name) {
                handle.supervisor.evict().await;
                self.observer.on_eviction("unload");
            }
            engines.len() as i64
        };
        self.residency.lock().await.unload(name);
        // The engine is gone; drop its adapter cache so a respawn
        // reloads adapters rather than assuming stale residency.
        self.lora_caches.lock().await.remove(name);
        self.observer.set_resident_models(resident);
    }

    /// The port of a resident model that is ready and (when
    /// health-rechecking) actually answering `/health`. Returns `None`
    /// when there is no ready engine or the liveness probe fails, so
    /// the caller respawns.
    async fn ready_and_live(&self, name: &str) -> Option<u16> {
        let port = {
            let engines = self.engines.lock().await;
            engines
                .get(name)
                .and_then(|h| h.supervisor.state().port())?
        };
        if self.health_recheck && !crate::launch::probe_health(port, "/health").await {
            return None;
        }
        Some(port)
    }

    /// Drop a model's engine (kill + free residency) if present. Used
    /// before a respawn to clear a dead or Failed handle.
    async fn drop_engine(&self, name: &str) {
        let removed = {
            let mut engines = self.engines.lock().await;
            if let Some(mut handle) = engines.remove(name) {
                handle.supervisor.evict().await;
                Some(engines.len() as i64)
            } else {
                None
            }
        };
        self.residency.lock().await.unload(name);
        // Drop the adapter cache: the respawned engine starts with no
        // adapters loaded, so its cache must too.
        self.lora_caches.lock().await.remove(name);
        if let Some(resident) = removed {
            self.observer.on_eviction("restart");
            self.observer.set_resident_models(resident);
        }
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

/// Estimate an engine's reload cost from its VRAM footprint (WOR-1672).
/// Preemption cost is dominated by reloading the weights, so a bigger
/// model costs more to bring back; this is a size proxy (roughly
/// milliseconds at ~1 GB/s effective load bandwidth) that the residency
/// solver uses to break ties among equally-idle models. Recency still
/// dominates the eviction decision.
fn reload_cost_ms_for(vram_bytes: u64) -> u64 {
    vram_bytes / (1024 * 1024)
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

    /// Counts observer callbacks so a test can assert the runtime emits
    /// lifecycle events (WOR-1659 wiring).
    #[derive(Default)]
    struct CountingObserver {
        ready: AtomicU64,
        evictions: AtomicU64,
        resident_last: AtomicU64,
        gpu_reports: AtomicU64,
        adapter_loads: AtomicU64,
        adapter_evictions: AtomicU64,
        resident_adapters_last: AtomicU64,
        ensure_failures: AtomicU64,
        last_fail_reason: std::sync::Mutex<Option<String>>,
    }
    impl ModelHostObserver for CountingObserver {
        fn on_engine_ready(&self, _engine: &str, _model: &str, _secs: f64) {
            self.ready.fetch_add(1, Ordering::SeqCst);
        }
        fn on_eviction(&self, _reason: &'static str) {
            self.evictions.fetch_add(1, Ordering::SeqCst);
        }
        fn set_resident_models(&self, count: i64) {
            self.resident_last.store(count as u64, Ordering::SeqCst);
        }
        fn set_gpu_stats(&self, _d: &str, _t: u64, _f: u64, _u: f64) {
            self.gpu_reports.fetch_add(1, Ordering::SeqCst);
        }
        fn on_adapter_loaded(&self, _base: &str, _adapter: &str) {
            self.adapter_loads.fetch_add(1, Ordering::SeqCst);
        }
        fn on_adapter_evicted(&self, _base: &str, _adapter: &str) {
            self.adapter_evictions.fetch_add(1, Ordering::SeqCst);
        }
        fn set_resident_adapters(&self, count: i64) {
            self.resident_adapters_last
                .store(count as u64, Ordering::SeqCst);
        }
        fn on_ensure_failed(&self, _model: &str, reason: &'static str) {
            self.ensure_failures.fetch_add(1, Ordering::SeqCst);
            *self.last_fail_reason.lock().unwrap() = Some(reason.to_string());
        }
    }

    /// A launcher that binds a real loopback HTTP server on the spec's
    /// `--port` answering 200 to everything, so the adapter load/unload
    /// POSTs succeed and the runtime's LoRA instrumentation fires
    /// without a real engine (WOR-1709).
    #[derive(Default)]
    struct FakeServerLauncher {
        handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    }
    impl EngineLauncher for FakeServerLauncher {
        async fn launch(&self, spec: &LaunchSpec) -> Result<u16, String> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut port = 0u16;
            let mut it = spec.args.iter();
            while let Some(a) = it.next() {
                if a == "--port" {
                    port = it.next().and_then(|p| p.parse().ok()).unwrap_or(0);
                }
            }
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .map_err(|e| format!("bind {port}: {e}"))?;
            let h = tokio::spawn(async move {
                loop {
                    let Ok((mut s, _)) = listener.accept().await else {
                        return;
                    };
                    let mut buf = [0u8; 256];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                }
            });
            *self.handle.lock().await = Some(h);
            Ok(port)
        }
        async fn kill(&self) {
            if let Some(h) = self.handle.lock().await.take() {
                h.abort();
            }
        }
    }

    #[tokio::test]
    async fn adapter_request_routes_to_base_engine() {
        // WOR-1673: a request addressing a LoRA adapter brings up (and
        // reuses) the base model's engine and resolves to its port.
        let rt = l4_runtime(config(
            "models:\n  - model: qwen3-14b\n    lora_adapters:\n      - name: coder\n        source: hf:org/coder\n",
        ));
        let port = rt
            .ensure_ready("coder")
            .await
            .expect("adapter routes to base");
        // The engine is keyed by the base model, not the adapter.
        assert_eq!(rt.resident_models().await, vec!["qwen3-14b".to_string()]);
        // Both the adapter name and the base name resolve to that engine.
        assert_eq!(
            rt.resolved_base_url("coder").await,
            Some(format!("http://127.0.0.1:{port}/v1"))
        );
        assert_eq!(
            rt.resolved_base_url("qwen3-14b").await,
            Some(format!("http://127.0.0.1:{port}/v1"))
        );
        // A second adapter request reuses the same engine (no respawn).
        assert_eq!(rt.ensure_ready("coder").await.unwrap(), port);
    }

    #[tokio::test]
    async fn dynamic_lora_paging_brings_up_base_then_loads_adapter() {
        // WOR-1673: with max_loras below the adapter count, an adapter
        // request brings up the base engine and then pages the adapter
        // via the vLLM load API. The test launcher binds no HTTP server,
        // so the load attempt fails cleanly, proving the dynamic path is
        // taken (a static config would not attempt any HTTP load).
        let rt = l4_runtime(config(
            "models:\n  - model: qwen3-14b\n    max_loras: 1\n    lora_adapters:\n      - name: a\n        source: hf:org/a\n      - name: b\n        source: hf:org/b\n",
        ));
        let err = rt.ensure_ready("a").await.unwrap_err();
        assert!(
            format!("{err}").contains("load lora"),
            "expected an adapter-load error, got: {err}"
        );
        // The base engine did come up (only the adapter load failed).
        assert_eq!(rt.resident_models().await, vec!["qwen3-14b".to_string()]);
    }

    #[tokio::test]
    async fn lora_paging_emits_load_and_evict_metrics() {
        // WOR-1709: with a fake engine that answers 200, an adapter load
        // fires on_adapter_loaded + updates the resident-adapter gauge,
        // and loading past the cap fires on_adapter_evicted.
        let obs = Arc::new(CountingObserver::default());
        let rt = ModelHostRuntime::new(
            config(
                "models:\n  - model: qwen3-14b\n    max_loras: 1\n    lora_adapters:\n      - name: a\n        source: hf:org/a\n      - name: b\n        source: hf:org/b\n",
            ),
            Catalog::builtin(),
            Arc::new(StaticGpuProbe::new(vec![GpuDescriptor::l4()])),
            Arc::new(FixtureMeta),
            Box::new(FakeServerLauncher::default),
            true,
        )
        .with_observer(obs.clone());

        rt.ensure_ready("a").await.expect("adapter a loads");
        assert_eq!(obs.adapter_loads.load(Ordering::SeqCst), 1);
        assert_eq!(obs.adapter_evictions.load(Ordering::SeqCst), 0);
        assert_eq!(obs.resident_adapters_last.load(Ordering::SeqCst), 1);

        // Cap is 1; loading b pages a out.
        rt.ensure_ready("b").await.expect("adapter b loads");
        assert_eq!(obs.adapter_loads.load(Ordering::SeqCst), 2);
        assert_eq!(obs.adapter_evictions.load(Ordering::SeqCst), 1);
        assert_eq!(obs.resident_adapters_last.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ensure_failures_are_observed_by_reason() {
        // WOR-1711: an unknown model reports the unknown_model reason.
        let obs = Arc::new(CountingObserver::default());
        let rt = l4_runtime(config("models:\n  - model: qwen3-14b\n")).with_observer(obs.clone());
        assert!(rt.ensure_ready("no-such-model").await.is_err());
        assert_eq!(obs.ensure_failures.load(Ordering::SeqCst), 1);
        assert_eq!(
            obs.last_fail_reason.lock().unwrap().as_deref(),
            Some("unknown_model")
        );

        // A host with no GPU cannot fit or admit the model.
        let obs2 = Arc::new(CountingObserver::default());
        let rt2 = ModelHostRuntime::new(
            config("models:\n  - model: qwen3-14b\n"),
            Catalog::builtin(),
            Arc::new(StaticGpuProbe::new(vec![])),
            Arc::new(FixtureMeta),
            Box::new(SpecPortLauncher::default),
            true,
        )
        .with_observer(obs2.clone());
        assert!(rt2.ensure_ready("qwen3-14b").await.is_err());
        assert_eq!(obs2.ensure_failures.load(Ordering::SeqCst), 1);
        let r = obs2.last_fail_reason.lock().unwrap().clone().unwrap();
        assert!(r == "fit" || r == "residency", "unexpected reason: {r}");
    }

    #[tokio::test]
    async fn status_snapshot_reports_resident_models_and_vram() {
        let rt = l4_runtime(config(
            "models:\n  - model: qwen3-14b\n    keep_alive: 30m\n",
        ));
        // Nothing loaded yet.
        let empty = rt.status_snapshot().await;
        assert!(empty.models.is_empty());
        assert!(empty.vram.budget_bytes > 0, "L4 budget reported");
        assert!(!empty.vram.devices.is_empty(), "device listed");

        rt.ensure_ready("qwen3-14b").await.expect("ready");
        let s = rt.status_snapshot().await;
        assert_eq!(s.models.len(), 1);
        let m = &s.models[0];
        assert_eq!(m.name, "qwen3-14b");
        assert!(m.port.is_some(), "ready model has a port");
        assert_eq!(m.keep_alive_secs, Some(1800), "30m keep_alive surfaced");
        assert!(s.vram.used_bytes > 0, "resident model uses budget");
    }

    #[tokio::test]
    async fn lifecycle_emits_observer_events() {
        let obs = Arc::new(CountingObserver::default());
        let rt = l4_runtime(config("models:\n  - model: qwen3-14b\n")).with_observer(obs.clone());
        rt.ensure_ready("qwen3-14b").await.expect("ready");
        assert_eq!(obs.ready.load(Ordering::SeqCst), 1, "engine-ready recorded");
        assert_eq!(obs.resident_last.load(Ordering::SeqCst), 1, "resident=1");
        assert!(
            obs.gpu_reports.load(Ordering::SeqCst) >= 1,
            "gpu stats reported"
        );
        rt.unload("qwen3-14b").await;
        assert_eq!(obs.evictions.load(Ordering::SeqCst), 1, "eviction recorded");
        assert_eq!(obs.resident_last.load(Ordering::SeqCst), 0, "resident=0");
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

    #[test]
    fn parse_params_reads_magnitude() {
        assert_eq!(parse_params("14B"), 14_000_000_000);
        assert_eq!(parse_params("30B-A3B"), 30_000_000_000); // total, ignores active
        assert_eq!(parse_params("120b"), 120_000_000_000);
        assert_eq!(parse_params("8M"), 8_000_000);
        assert_eq!(parse_params("7.5B"), 7_500_000_000);
        assert_eq!(parse_params("nonsense"), 0);
    }

    #[test]
    fn config_dir_metadata_reads_config_json() {
        let dir = tempfile::tempdir().unwrap();
        // Write a config.json where the cache layout expects it.
        let cfg_path =
            crate::weights::cache_file(dir.path(), "Qwen/Qwen3-14B", "main", "config.json");
        std::fs::create_dir_all(cfg_path.parent().unwrap()).unwrap();
        std::fs::write(
            &cfg_path,
            r#"{"num_hidden_layers":40,"num_attention_heads":40,"num_key_value_heads":8,"hidden_size":5120,"max_position_embeddings":40960}"#,
        )
        .unwrap();
        let provider = ConfigDirMetadataProvider {
            cache_root: dir.path().to_path_buf(),
            revision: "main".to_string(),
            catalog: Catalog::builtin(),
        };
        let model = ModelRef {
            hf_repo: "Qwen/Qwen3-14B".to_string(),
            quant: "FP8".to_string(),
            catalog_id: Some("qwen3-14b".to_string()),
        };
        let meta = provider.metadata(&model).expect("reads config");
        assert_eq!(meta.layers, 40);
        assert_eq!(meta.kv_heads, 8);
        assert_eq!(meta.head_dim, 128);
        assert!(meta.params > 0, "params from catalog entry");
        // A missing config returns None (not a panic).
        let missing = ModelRef {
            hf_repo: "Org/Absent".to_string(),
            quant: String::new(),
            catalog_id: None,
        };
        assert!(provider.metadata(&missing).is_none());
    }

    /// A launcher whose "engine" binds a real `/health` server on the
    /// spec's port, so `probe_health` sees it live (for the
    /// health-recheck path).
    #[derive(Clone, Default)]
    struct HealthServerLauncher {
        launches: Arc<AtomicU64>,
    }

    impl EngineLauncher for HealthServerLauncher {
        async fn launch(&self, spec: &crate::supervisor::LaunchSpec) -> Result<u16, String> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio::net::TcpListener;
            self.launches.fetch_add(1, Ordering::SeqCst);
            let mut port = 0u16;
            let mut it = spec.args.iter();
            while let Some(a) = it.next() {
                if a == "--port" {
                    port = it.next().and_then(|p| p.parse().ok()).unwrap_or(0);
                }
            }
            // Bind the health server on the requested port.
            let listener = TcpListener::bind(("127.0.0.1", port))
                .await
                .map_err(|e| format!("bind {port}: {e}"))?;
            let bound = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((mut s, _)) = listener.accept().await else {
                        return;
                    };
                    let mut b = [0u8; 128];
                    let _ = s.read(&mut b).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                }
            });
            Ok(bound)
        }
        async fn kill(&self) {}
    }

    #[tokio::test]
    async fn health_recheck_returns_live_engine_without_respawn() {
        let launches = Arc::new(AtomicU64::new(0));
        let calls = launches.clone();
        let rt = ModelHostRuntime::new(
            config("models:\n  - model: qwen3-14b\n"),
            Catalog::builtin(),
            Arc::new(StaticGpuProbe::new(vec![GpuDescriptor::l4()])),
            Arc::new(FixtureMeta),
            Box::new(move || HealthServerLauncher {
                launches: calls.clone(),
            }),
            true,
        )
        .with_health_recheck(true);
        let Ok(p1) = rt.ensure_ready("qwen3-14b").await else {
            eprintln!("skipping: loopback bind denied");
            return;
        };
        // Second call: the health probe passes, so no respawn.
        let p2 = rt.ensure_ready("qwen3-14b").await.unwrap();
        assert_eq!(p1, p2);
        assert_eq!(
            launches.load(Ordering::SeqCst),
            1,
            "no respawn when healthy"
        );
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
