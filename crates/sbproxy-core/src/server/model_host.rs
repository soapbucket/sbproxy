// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Process-global local model host (WOR-1680).
//!
//! When any `ai_proxy` provider carries a `serve:` block, the gateway
//! itself hosts those models: it spawns and supervises an inference
//! engine and routes requests to its loopback port. The
//! [`ModelHostRuntime`] that does this owns child processes and VRAM
//! residency, so it must be built once and survive hot config reloads
//! (rebuilding it would kill and respawn a resident model on every
//! config touch). It lives here as a lazily-initialized global,
//! mirroring the `AI_CLIENT` global.
//!
//! [`served_upstream`] is the request-path entry point: given the AI
//! config, the selected provider, and the requested model, it resolves
//! a served provider to its live loopback base URL (bringing the engine
//! to ready on demand), or returns `Ok(None)` for a normal proxied
//! provider so the caller keeps its `base_url`.
//!
//! The GPU probe is feature-selected: with `gpu-nvidia` it is the real
//! NVML probe; without it a zero-GPU probe, so on a CPU-only build a
//! `serve:` provider fails admission with a clear residency error
//! rather than pretending to serve.

use std::sync::{Arc, OnceLock};

use sbproxy_ai::local_host::{resolve_served_base_url, LocalModelHost};
use sbproxy_ai::AiHandlerConfig;
use sbproxy_model_host::{
    Catalog, ConfigDirMetadataProvider, GpuProbe, ModelHostConfig, ModelHostRuntime,
    ProcessEngineLauncher,
};

/// Built once from the first config that declares any `serve:` block;
/// `None` when no provider serves locally. Survives hot reload so a
/// resident engine is not killed on an unrelated config change.
static MODEL_HOST: OnceLock<Option<Arc<ModelHostRuntime<ProcessEngineLauncher>>>> = OnceLock::new();

/// Records the model-host lifecycle into the `sbproxy_model_host_*`
/// metrics (WOR-1659). The model-host crate stays observe-free and
/// calls this seam; here we forward to the observe recording fns that
/// the Grafana dashboard (WOR-1664) and value report (WOR-1665) consume.
struct MetricsObserver;

impl sbproxy_model_host::ModelHostObserver for MetricsObserver {
    fn on_engine_ready(&self, engine: &str, model: &str, secs: f64) {
        sbproxy_observe::metrics::record_model_host_time_to_ready(engine, model, "ready", secs);
    }
    fn on_engine_failed(&self, engine: &str, model: &str, secs: f64) {
        sbproxy_observe::metrics::record_model_host_time_to_ready(engine, model, "failed", secs);
    }
    fn on_eviction(&self, reason: &'static str) {
        sbproxy_observe::metrics::record_model_host_eviction(reason);
    }
    fn set_resident_models(&self, count: i64) {
        sbproxy_observe::metrics::set_model_host_resident_models(count);
    }
    fn set_gpu_stats(&self, device: &str, total_bytes: u64, free_bytes: u64, utilization: f64) {
        sbproxy_observe::metrics::set_model_host_gpu_stats(
            device,
            total_bytes as i64,
            free_bytes as i64,
            utilization,
        );
    }
    fn on_adapter_loaded(&self, _base: &str, _adapter: &str) {
        sbproxy_observe::metrics::record_model_host_lora_load();
    }
    fn on_adapter_evicted(&self, _base: &str, _adapter: &str) {
        sbproxy_observe::metrics::record_model_host_lora_eviction();
    }
    fn set_resident_adapters(&self, count: i64) {
        sbproxy_observe::metrics::set_model_host_resident_adapters(count);
    }
    fn on_ensure_failed(&self, _model: &str, reason: &'static str) {
        sbproxy_observe::metrics::record_model_host_ensure_failure(reason);
    }
    fn on_weight_download(&self, _model: &str, bytes: u64, secs: f64, ok: bool) {
        sbproxy_observe::metrics::record_model_host_weight_download(bytes, secs, ok);
    }
}

/// The GPU probe for the runtime. Also used by [`crate::doctor`] so the
/// diagnostics report the same devices the admission path will see.
///
/// The probe is layered so one binary adapts to any host (WOR-1800):
/// NVIDIA discrete GPUs first (when the `gpu-nvidia` feature is
/// compiled and NVML sees cards), then Apple Silicon unified memory
/// (`gpu-apple` on macOS), then a CPU / system-RAM budget as the
/// universal fallback. The CPU budget means a `serve:` provider admits
/// small models on a Mac or a GPU-less server instead of rejecting
/// everything; set `SBPROXY_CPU_MEMORY_FRACTION=0` to opt back into
/// hard rejection.
pub(crate) fn make_probe() -> Arc<dyn GpuProbe> {
    #[cfg(feature = "gpu-nvidia")]
    {
        let nvml = sbproxy_model_host::NvmlGpuProbe::new();
        if !nvml.probe().is_empty() {
            return Arc::new(nvml);
        }
    }
    #[cfg(all(target_os = "macos", feature = "gpu-apple"))]
    {
        let metal = sbproxy_model_host::MetalGpuProbe::new();
        if !metal.probe().is_empty() {
            return Arc::new(metal);
        }
    }
    // Universal fallback: a fraction of system RAM as the serving
    // budget. Reports no device (so admission still rejects) when RAM
    // cannot be read or the operator set the fraction to 0.
    Arc::new(sbproxy_model_host::CpuProbe::from_system())
}

/// Warn, at pipeline load time (startup and every hot reload), about
/// every `serve:` prerequisite this host is missing: no visible GPU,
/// or a serve entry whose resolved engine has no binary (and no
/// container runtime) to run it with. The request path degrades
/// gracefully either way (admission rejects / the attempt fails over
/// to the next provider), but silently degrading at 3am is not
/// bulletproof; the operator finds out when the config lands, with a
/// pointer at `sbproxy doctor`.
///
/// Best-effort and read-only: probes never panic, and a pipeline with
/// no `serve:` block logs nothing.
pub(crate) fn preflight_serve_warnings(actions: &[sbproxy_modules::Action]) {
    for action in actions {
        if let sbproxy_modules::Action::AiProxy(ai) = action {
            warn_missing_serve_prereqs(&ai.config);
        }
    }
}

/// The per-config half of [`preflight_serve_warnings`].
fn warn_missing_serve_prereqs(config: &AiHandlerConfig) {
    let Some(merged) = merged_serve_config(config) else {
        return;
    };
    let gpus = make_probe().probe();
    let env = sbproxy_model_host::EngineEnv::probe_host(!gpus.is_empty());
    if gpus.is_empty() {
        tracing::warn!(
            "serve: is configured but no GPU is visible to this process; \
             local model serving will reject admission and requests will \
             fail over to the next provider (or 502 with no fallback). \
             Run `sbproxy doctor` for the full host report"
        );
    }
    for entry in &merged.models {
        // GGUF-ness steers the `auto` engine choice toward llama.cpp;
        // at this preflight the weights are not resolved yet, so the
        // reference string is the best available signal.
        let is_gguf =
            entry.model.to_ascii_lowercase().contains("gguf") || entry.gguf_file.is_some();
        let doctor = sbproxy_model_host::EngineDoctor::for_entry(entry, is_gguf, &env);
        if !doctor.runnable {
            // WOR-1827: the doctor's `runnable` only reflects a PATH
            // binary, but the runtime acquires engines on demand
            // (WOR-1801). When the acquire plan can supply the engine
            // (a pinned prebuilt fetch, an explicit path, uvx), the
            // honest message is "fetched on first use", not "cannot
            // start"; the hard warning stays for a genuinely blocked
            // engine.
            let prov = merged.engines.get(&doctor.resolved);
            let plan = sbproxy_model_host::plan_binary_acquire(doctor.resolved, prov, None);
            match plan {
                sbproxy_model_host::BinaryAcquirePlan::Blocked(reason) => {
                    tracing::warn!(
                        model = %doctor.model,
                        engine = ?doctor.resolved,
                        "serve: model cannot start on this host: {reason}. Run \
                         `sbproxy doctor` to see the prerequisites and how to install them",
                    );
                }
                _ => {
                    tracing::info!(
                        model = %doctor.model,
                        engine = ?doctor.resolved,
                        "serve: engine not on PATH; sbproxy acquires it on the first \
                         request (a PATH install is preferred when present)",
                    );
                }
            }
        }
    }
}

/// Merge every provider's `serve:` block into one host config. A single
/// node has one GPU and one residency budget, so all served models
/// share one runtime; a provider's models are concatenated and the
/// engine-provisioning maps unioned. The first serve block's host
/// policy (eviction, cache dir/budget) wins.
fn merged_serve_config(config: &AiHandlerConfig) -> Option<ModelHostConfig> {
    let mut merged: Option<ModelHostConfig> = None;
    for provider in &config.providers {
        let Some(serve) = &provider.serve else {
            continue;
        };
        match &mut merged {
            None => merged = Some(serve.clone()),
            Some(m) => {
                m.models.extend(serve.models.iter().cloned());
                for (k, v) in &serve.engines {
                    m.engines.entry(*k).or_insert_with(|| v.clone());
                }
            }
        }
    }
    merged
}

/// Build the runtime from the merged serve config, or `None` when no
/// provider serves locally or the merged config is invalid.
fn build_runtime(config: &AiHandlerConfig) -> Option<Arc<ModelHostRuntime<ProcessEngineLauncher>>> {
    let merged = merged_serve_config(config)?;
    // Reject a cross-provider duplicate/nameless model here; per-provider
    // validation ran at config load, this catches collisions across
    // several serve blocks.
    if let Err(e) = merged.validate() {
        tracing::error!("model host: merged serve config is invalid: {e}");
        return None;
    }
    let cache_root = sbproxy_model_host::resolve_cache_dir_default(merged.cache_dir.as_deref());
    let metadata = Arc::new(ConfigDirMetadataProvider {
        cache_root,
        revision: "main".to_string(),
        catalog: Catalog::builtin(),
    });
    let runtime = ModelHostRuntime::new(
        merged,
        Catalog::builtin(),
        make_probe(),
        metadata,
        // A cold weight-load + engine warm-up can take minutes; give the
        // readiness probe a generous budget so the first request does
        // not fail over while the engine is still loading.
        Box::new(|| ProcessEngineLauncher::with_timeout(std::time::Duration::from_secs(600))),
        // Real container-runtime detection (WOR-1801): a present
        // docker/podman lets `engine: auto` resolve to vLLM (its
        // container path) for safetensors weights, instead of always
        // falling back to llama.cpp.
        sbproxy_model_host::resolve_on_path("docker").is_some()
            || sbproxy_model_host::resolve_on_path("podman").is_some(),
    )
    .with_health_recheck(true)
    .with_observer(Arc::new(MetricsObserver));
    Some(Arc::new(runtime))
}

/// The process-global model host, built lazily from `config` on first
/// use and cached for the process lifetime.
fn model_host(config: &AiHandlerConfig) -> Option<Arc<ModelHostRuntime<ProcessEngineLauncher>>> {
    MODEL_HOST.get_or_init(|| build_runtime(config)).clone()
}

/// The current model host, resolved from the live compiled pipeline's
/// `ai_proxy` config, for read-only surfaces like the status admin API
/// (WOR-1665). Returns `None` when no provider serves locally. Builds
/// the runtime on first use (construction only, no engine spawn).
pub(crate) fn current_model_host() -> Option<Arc<ModelHostRuntime<ProcessEngineLauncher>>> {
    use sbproxy_modules::Action;
    let pipeline = crate::reload::current_pipeline();
    let cfg = pipeline.actions.iter().find_map(|a| match a {
        Action::AiProxy(ai) => Some(&ai.config),
        _ => None,
    })?;
    model_host(cfg)
}

/// Resolve a served provider's upstream to its live loopback base URL,
/// bringing the engine to ready on demand.
///
/// Returns `Ok(None)` for a provider with no `serve:` block (the caller
/// keeps the provider's normal `base_url`). For a served provider it
/// returns `Ok(Some(url))`, or an error string when no served models are
/// configured or the engine could not be brought to ready.
pub async fn served_upstream(
    config: &AiHandlerConfig,
    provider: &sbproxy_ai::provider::ProviderConfig,
    requested_model: Option<&str>,
) -> Result<Option<String>, String> {
    if provider.serve.is_none() {
        return Ok(None);
    }
    let runtime = model_host(config)
        .ok_or_else(|| "no local model host configured for this served provider".to_string())?;
    resolve_served_base_url(
        provider,
        requested_model,
        runtime.as_ref() as &dyn LocalModelHost,
    )
    .await
}

// --- Served-lane priority admission gate (WOR-1679, OSS subset) ---
//
// A single multi-priority queue in front of the local engine. The pure
// decision logic lives in `sbproxy_model_host::scheduling`; this is the
// request-path binding: a slot pool sized by `serve.max_concurrent_requests`,
// FIFO-within-class wakeups ordered by `next_to_admit`, and a spill signal
// so an interactive request with a cloud fallback in the same provider
// array overflows immediately instead of queuing behind batch work. True
// preemption of an in-flight generation is the enterprise extension; the
// OSS gate never cancels running work.

use sbproxy_model_host::scheduling::{next_to_admit, PriorityClass};

/// Result of asking the gate for a served-lane slot.
pub(crate) enum LaneAdmission {
    /// A slot is held; drop the permit to release it.
    Admitted(ServeLanePermit),
    /// The lane is saturated and the caller said a fallback exists:
    /// spill to it now rather than queuing (interactive only).
    Spill,
    /// Waited the configured queue timeout without getting a slot.
    TimedOut,
}

/// RAII slot on the served lane. Dropping it hands the slot to the
/// highest-priority waiter (FIFO within a class), or frees it. Public
/// only because it rides on `RequestContext`; there is no way to mint
/// one outside the gate.
pub struct ServeLanePermit {
    gate: Arc<ServeLaneGate>,
}

impl Drop for ServeLanePermit {
    fn drop(&mut self) {
        self.gate.release();
    }
}

struct LaneWaiter {
    class: PriorityClass,
    arrival: u64,
    id: u64,
    wake: tokio::sync::oneshot::Sender<()>,
}

#[derive(Default)]
struct LaneState {
    in_flight: usize,
    next_tick: u64,
    waiting: Vec<LaneWaiter>,
}

/// The process-wide served-lane gate. One per process, matching the
/// one-engine-runtime-per-node doctrine of `merged_serve_config`.
pub(crate) struct ServeLaneGate {
    capacity: usize,
    queue_timeout: std::time::Duration,
    state: parking_lot::Mutex<LaneState>,
}

impl ServeLaneGate {
    fn new(capacity: usize, queue_timeout: std::time::Duration) -> Self {
        Self {
            capacity,
            queue_timeout,
            state: parking_lot::Mutex::new(LaneState::default()),
        }
    }

    /// Acquire a slot for a request of `class`. `has_fallback` tells the
    /// gate whether the provider array carries another lane to spill to;
    /// only an interactive request uses it (standard and batch wait).
    pub(crate) async fn acquire(
        self: &Arc<Self>,
        class: PriorityClass,
        has_fallback: bool,
    ) -> LaneAdmission {
        let (rx, id) = {
            let mut st = self.state.lock();
            if st.in_flight < self.capacity {
                st.in_flight += 1;
                record_lane_decision(class, "admitted");
                return LaneAdmission::Admitted(ServeLanePermit { gate: self.clone() });
            }
            if class == PriorityClass::Interactive && has_fallback {
                record_lane_decision(class, "spilled");
                return LaneAdmission::Spill;
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            st.next_tick += 1;
            let id = st.next_tick;
            st.waiting.push(LaneWaiter {
                class,
                arrival: id,
                id,
                wake: tx,
            });
            (rx, id)
        };
        match tokio::time::timeout(self.queue_timeout, rx).await {
            // The releaser transferred its slot to us before waking.
            Ok(Ok(())) => {
                record_lane_decision(class, "queued_admitted");
                LaneAdmission::Admitted(ServeLanePermit { gate: self.clone() })
            }
            // Sender dropped (gate shutdown edge) or timeout: leave the
            // queue and report. On the timeout path the waiter entry must
            // be removed so the releaser never wakes a dead receiver.
            Ok(Err(_)) | Err(_) => {
                let mut st = self.state.lock();
                st.waiting.retain(|w| w.id != id);
                record_lane_decision(class, "timed_out");
                LaneAdmission::TimedOut
            }
        }
    }

    fn release(&self) {
        let mut st = self.state.lock();
        // Hand the slot to the best waiter whose receiver is still
        // alive; a send failure means that waiter timed out between
        // dropping the lock and now, so try the next one.
        loop {
            let Some(idx) = next_to_admit(
                &st.waiting
                    .iter()
                    .map(|w| (w.class, w.arrival))
                    .collect::<Vec<_>>(),
            ) else {
                st.in_flight = st.in_flight.saturating_sub(1);
                return;
            };
            let waiter = st.waiting.remove(idx);
            if waiter.wake.send(()).is_ok() {
                // Slot transferred: in_flight stays constant.
                return;
            }
        }
    }
}

static SERVE_LANE_GATE: OnceLock<Option<Arc<ServeLaneGate>>> = OnceLock::new();

/// The served-lane gate for this process, built from the first config
/// that carries `serve.max_concurrent_requests`. `None` when the merged
/// serve block sets no cap (gating disabled, the pre-WOR-1679 behavior).
pub(crate) fn serve_lane_gate(config: &AiHandlerConfig) -> Option<Arc<ServeLaneGate>> {
    SERVE_LANE_GATE
        .get_or_init(|| {
            let merged = merged_serve_config(config)?;
            let capacity = merged.max_concurrent_requests?;
            if capacity == 0 {
                return None;
            }
            let timeout =
                std::time::Duration::from_millis(merged.queue_timeout_ms.unwrap_or(30_000));
            Some(Arc::new(ServeLaneGate::new(capacity, timeout)))
        })
        .clone()
}

/// Map a virtual key's lane onto the scheduler's class. No key or no
/// declared lane both mean standard.
pub(crate) fn lane_class_for(priority: Option<sbproxy_ai::identity::KeyPriority>) -> PriorityClass {
    match priority {
        Some(sbproxy_ai::identity::KeyPriority::Interactive) => PriorityClass::Interactive,
        Some(sbproxy_ai::identity::KeyPriority::Batch) => PriorityClass::Batch,
        Some(sbproxy_ai::identity::KeyPriority::Standard) | None => PriorityClass::Standard,
    }
}

fn record_lane_decision(class: PriorityClass, decision: &'static str) {
    let priority = match class {
        PriorityClass::Interactive => "interactive",
        PriorityClass::Standard => "standard",
        PriorityClass::Batch => "batch",
    };
    sbproxy_observe::metrics::record_serve_lane_decision(priority, decision);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_serve(serve_yaml: Option<&str>) -> AiHandlerConfig {
        let providers = match serve_yaml {
            Some(y) => serde_json::json!([{
                "name": "local",
                "serve": serde_yaml::from_str::<serde_json::Value>(y).unwrap()
            }]),
            None => serde_json::json!([{"name": "openai", "api_key": "sk-x"}]),
        };
        AiHandlerConfig::from_config(serde_json::json!({ "providers": providers })).unwrap()
    }

    #[test]
    fn merged_serve_config_none_without_serve() {
        let cfg = config_with_serve(None);
        assert!(merged_serve_config(&cfg).is_none());
    }

    #[test]
    fn merged_serve_config_collects_models() {
        let cfg = config_with_serve(Some("models:\n  - model: qwen3-14b\n"));
        let merged = merged_serve_config(&cfg).expect("one serve block");
        assert_eq!(merged.models.len(), 1);
        assert!(merged.validate().is_ok());
    }

    #[tokio::test]
    async fn served_upstream_is_none_for_a_proxied_provider() {
        let cfg = config_with_serve(None);
        let provider = &cfg.providers[0];
        assert_eq!(
            served_upstream(&cfg, provider, Some("gpt-4o"))
                .await
                .unwrap(),
            None
        );
    }

    fn gate(capacity: usize, timeout_ms: u64) -> Arc<ServeLaneGate> {
        Arc::new(ServeLaneGate::new(
            capacity,
            std::time::Duration::from_millis(timeout_ms),
        ))
    }

    #[tokio::test]
    async fn gate_admits_under_capacity() {
        let g = gate(2, 50);
        let a = g.acquire(PriorityClass::Standard, false).await;
        let b = g.acquire(PriorityClass::Batch, false).await;
        assert!(matches!(a, LaneAdmission::Admitted(_)));
        assert!(matches!(b, LaneAdmission::Admitted(_)));
    }

    #[tokio::test]
    async fn gate_spills_interactive_with_fallback_when_full() {
        let g = gate(1, 5_000);
        let _held = g.acquire(PriorityClass::Batch, false).await;
        // Interactive with a fallback overflows immediately instead of
        // queuing behind the batch job.
        assert!(matches!(
            g.acquire(PriorityClass::Interactive, true).await,
            LaneAdmission::Spill
        ));
    }

    #[tokio::test]
    async fn gate_times_out_a_waiter_when_no_slot_frees() {
        let g = gate(1, 20);
        let _held = g.acquire(PriorityClass::Standard, false).await;
        assert!(matches!(
            g.acquire(PriorityClass::Standard, false).await,
            LaneAdmission::TimedOut
        ));
    }

    #[tokio::test]
    async fn gate_hands_freed_slot_to_higher_priority_waiter_first() {
        let g = gate(1, 5_000);
        let held = match g.acquire(PriorityClass::Standard, false).await {
            LaneAdmission::Admitted(p) => p,
            _ => panic!("first acquire admits"),
        };
        // Queue a batch waiter first, then an interactive one; the
        // freed slot must go to interactive despite arriving later.
        let g_batch = g.clone();
        let batch = tokio::spawn(async move { g_batch.acquire(PriorityClass::Batch, false).await });
        let g_inter = g.clone();
        let interactive =
            tokio::spawn(async move { g_inter.acquire(PriorityClass::Interactive, false).await });
        // Let both waiters park before releasing.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            if g.state.lock().waiting.len() == 2 {
                break;
            }
        }
        assert_eq!(g.state.lock().waiting.len(), 2, "both waiters parked");
        drop(held);
        let first = interactive.await.unwrap();
        assert!(matches!(first, LaneAdmission::Admitted(_)));
        // Releasing the interactive permit then admits the batch waiter.
        drop(first);
        assert!(matches!(batch.await.unwrap(), LaneAdmission::Admitted(_)));
    }

    #[test]
    fn lane_class_defaults_to_standard() {
        assert_eq!(lane_class_for(None), PriorityClass::Standard);
        assert_eq!(
            lane_class_for(Some(sbproxy_ai::identity::KeyPriority::Batch)),
            PriorityClass::Batch
        );
    }
}
