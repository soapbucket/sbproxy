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

/// The GPU probe for the runtime, selected at compile time. Also used
/// by [`crate::doctor`] so the diagnostics report the same devices the
/// admission path will see.
pub(crate) fn make_probe() -> Arc<dyn GpuProbe> {
    #[cfg(feature = "gpu-nvidia")]
    {
        Arc::new(sbproxy_model_host::NvmlGpuProbe::new())
    }
    #[cfg(not(feature = "gpu-nvidia"))]
    {
        // No GPUs reported -> residency budget 0 -> admission rejects,
        // so a serve: provider on a CPU-only build fails with a clear
        // "residency" error instead of launching an engine that cannot
        // fit. Building with --features gpu-nvidia enables real serving.
        Arc::new(sbproxy_model_host::StaticGpuProbe::new(Vec::new()))
    }
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
        let is_gguf = entry.model.to_ascii_lowercase().contains("gguf");
        let doctor = sbproxy_model_host::EngineDoctor::for_entry(entry, is_gguf, &env);
        if !doctor.runnable {
            tracing::warn!(
                model = %doctor.model,
                engine = ?doctor.resolved,
                "serve: model cannot start on this host: {}. Run \
                 `sbproxy doctor` to inspect, or `sbproxy doctor --install <engine>` \
                 to install the engine",
                doctor.blocker.as_deref().unwrap_or("engine unavailable"),
            );
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
    let cache_root = sbproxy_model_host::resolve_cache_dir(merged.cache_dir.as_deref(), None);
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
        // Container-runtime detection is a later refinement; the binary
        // path is the default and llama.cpp/vLLM resolve from PATH.
        false,
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
}
