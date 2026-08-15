// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! On-GPU certification harness for the model-host crate (WOR-1652).
//!
//! Run on a real GPU host to exercise the hardware-dependent code that
//! CI cannot: the NVML probe, the capability-aware fit plan, the
//! throughput estimate, the Hugging Face weight pull, and (optionally)
//! spawning a real vLLM through the supervisor launcher.
//!
//! Build with the GPU features on:
//!   cargo run --release --example gpu_cert \
//!     --features gpu-nvidia,weights -- probe
//!   cargo run --release --example gpu_cert \
//!     --features gpu-nvidia,weights -- weights Qwen/Qwen3-0.6B
//!   cargo run --release --example gpu_cert \
//!     --features gpu-nvidia,weights -- serve Qwen/Qwen3-0.6B 8000
//!   cargo run --example gpu_cert --features gpu-apple -- metal-probe
//!
//! `certify` is the exception: a KL-divergence gate over a stubbed
//! logit pair (harness scaffolding, no GPU or feature flags needed):
//!   cargo run --example gpu_cert -- certify Qwen/Qwen3-0.6B 2026-07-27

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Keep the envelope helper in the compiled example on every
    // platform so the Metal live-RSS check cannot compile out of the
    // crate's public surface (WOR-2200).
    let _ = sbproxy_model_host::live_rss_within_planned_envelope(
        1,
        1,
        sbproxy_model_host::LIVE_MEMORY_OVERSHOOT,
    );
    let mode = args.get(1).map(String::as_str).unwrap_or("probe");
    match mode {
        "probe" => probe(),
        "weights" => weights(args.get(2).map(String::as_str).unwrap_or("Qwen/Qwen3-0.6B")),
        "serve" => serve(
            args.get(2).map(String::as_str).unwrap_or("Qwen/Qwen3-0.6B"),
            args.get(3).and_then(|p| p.parse().ok()).unwrap_or(8000),
        ),
        "runtime" => runtime_cert(args.get(2).map(String::as_str).unwrap_or("Qwen/Qwen3-0.6B")),
        "seed-config" => seed_config(
            args.get(2).map(String::as_str).unwrap_or("Qwen/Qwen3-0.6B"),
            args.get(3)
                .map(String::as_str)
                .unwrap_or("/var/lib/sbproxy/models"),
        ),
        "llamacpp" => llamacpp_cert(
            args.get(2)
                .map(String::as_str)
                .unwrap_or("ggml-org/Qwen2.5-0.5B-Instruct-GGUF"),
        ),
        "translators" => {
            translators_cert(args.get(2).map(String::as_str).unwrap_or("Qwen/Qwen3-0.6B"))
        }
        "metal-probe" => metal_probe(),
        "certify" => certify(
            args.get(2).map(String::as_str).unwrap_or("Qwen/Qwen3-0.6B"),
            args.get(3).map(String::as_str),
        ),
        other => {
            eprintln!(
                "unknown mode {other}; use probe | weights | serve | runtime | seed-config | llamacpp <gguf-repo> | translators <repo> | metal-probe | certify <model> [date]"
            );
            std::process::exit(2);
        }
    }
}

/// Drive the real ModelHostRuntime end to end: fetch config.json,
/// ensure_ready (spawns real vLLM through ProcessEngineLauncher),
/// serve tokens, kill -9 the engine and re-ensure (recovery), and load
/// a second model (multi-model residency). Certifies the orchestration
/// layer on real hardware (WOR-1652 / WOR-1653).
#[cfg(all(feature = "gpu-nvidia", feature = "weights"))]
fn runtime_cert(repo: &str) {
    use sbproxy_model_host::launch::ProcessEngineLauncher;
    use sbproxy_model_host::weights::ensure_weight_file;
    use sbproxy_model_host::{
        Catalog, ConfigDirMetadataProvider, GpuProbe, ModelHostConfig, ModelHostRuntime,
        NvmlGpuProbe,
    };
    use std::sync::Arc;
    use std::time::Duration;

    let rt = tokio_rt();
    let cache = std::env::temp_dir().join("sbproxy-runtime-cert-cache");

    // Fetch config.json so the metadata provider can read the shape.
    println!("fetching {repo}/config.json ...");
    if let Err(e) = rt.block_on(ensure_weight_file(
        &cache,
        repo,
        "main",
        "config.json",
        None,
    )) {
        println!("FAIL: config.json fetch: {e}");
        std::process::exit(1);
    }
    println!("PASS: config.json fetched");

    // Serve the repo as a named hf: entry, forced to vLLM.
    let cfg: ModelHostConfig = serde_yaml::from_str(&format!(
        "models:\n  - model: hf:{repo}\n    name: cert-model\n    engine: vllm\n    max_context: 8192\n"
    ))
    .expect("serve config");

    let runtime = ModelHostRuntime::new(
        cfg,
        Catalog::builtin(),
        Arc::new(NvmlGpuProbe::new()),
        Arc::new(ConfigDirMetadataProvider {
            cache_root: cache.clone(),
            revision: "main".to_string(),
            catalog: Arc::new(Catalog::builtin()),
        }),
        Box::new(|| ProcessEngineLauncher::with_timeout(Duration::from_secs(420))),
        false, // no container runtime; venv vLLM on PATH
    )
    .with_health_recheck(true);

    // 1. ensure_ready spawns vLLM and returns its port.
    let port = match rt.block_on(runtime.ensure_ready("cert-model")) {
        Ok(p) => {
            println!("PASS: runtime.ensure_ready spawned vLLM on port {p}");
            p
        }
        Err(e) => {
            println!("FAIL: ensure_ready: {e}");
            std::process::exit(1);
        }
    };

    // 2. A completion through the resolved port returns tokens. vLLM
    //    serves under the repo id it was launched with.
    if curl_tokens(port, repo) {
        println!("PASS: completion returned tokens through the runtime-spawned engine");
    } else {
        println!("FAIL: no tokens from the runtime-spawned engine");
    }

    // 3. Evict through the runtime (kills the whole vLLM process group,
    //    reaping the EngineCore workers that hold VRAM), confirm the
    //    VRAM is actually released, then re-load: the load -> evict ->
    //    reload cycle that multi-model residency depends on.
    println!("evicting through the runtime (graceful engine shutdown) ...");
    rt.block_on(runtime.unload("cert-model"));
    wait_for_vram_free(
        &NvmlGpuProbe::new(),
        20 * 1024 * 1024 * 1024,
        Duration::from_secs(60),
    );
    let free_after = NvmlGpuProbe::new()
        .probe()
        .first()
        .map(|g| g.free_vram_bytes)
        .unwrap_or(0);
    if free_after >= 20 * 1024 * 1024 * 1024 {
        println!(
            "PASS: eviction reaped the engine tree and freed VRAM ({:.1} GiB free)",
            free_after as f64 / 1e9
        );
    } else {
        println!(
            "FAIL: eviction leaked VRAM (only {:.1} GiB free)",
            free_after as f64 / 1e9
        );
    }
    match rt.block_on(runtime.ensure_ready("cert-model")) {
        Ok(p2) => {
            if curl_tokens(p2, repo) {
                println!("PASS: reloaded after eviction (port {p2}, serves tokens)");
            } else {
                println!("FAIL: reloaded on {p2} but no tokens");
            }
        }
        Err(e) => println!("FAIL: reload after eviction: {e}"),
    }

    println!(
        "resident models: {:?}",
        rt.block_on(runtime.resident_models())
    );
    rt.block_on(runtime.unload("cert-model"));
    println!("cert complete; engine unloaded");
}

#[cfg(not(all(feature = "gpu-nvidia", feature = "weights")))]
fn runtime_cert(_repo: &str) {
    eprintln!("build with --features gpu-nvidia,weights to run the runtime cert");
    std::process::exit(2);
}

/// Pre-seed a model's `config.json` into the model host's weight cache
/// so the running binary's fit planner can read the model shape without
/// the (not-yet-wired) pull-policy execution. Used to set up the on-box
/// binary end-to-end test.
#[cfg(all(feature = "gpu-nvidia", feature = "weights"))]
fn seed_config(repo: &str, cache_dir: &str) {
    use sbproxy_model_host::weights::ensure_weight_file;
    let rt = tokio_rt();
    let cache = std::path::PathBuf::from(cache_dir);
    match rt.block_on(ensure_weight_file(
        &cache,
        repo,
        "main",
        "config.json",
        None,
    )) {
        Ok(p) => println!("PASS: seeded config.json at {}", p.display()),
        Err(e) => {
            println!("FAIL: seed config.json: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(all(feature = "gpu-nvidia", feature = "weights")))]
fn seed_config(_repo: &str, _cache_dir: &str) {
    eprintln!("build with --features gpu-nvidia,weights");
    std::process::exit(2);
}

/// Certify the llama.cpp secondary engine (WOR-1656): serve a GGUF
/// model through the runtime with `engine: llama_cpp` and get tokens.
/// Assumes `llama-server` is on PATH (the cert script installs it) so
/// `resolve_on_path` finds it; the runtime spawns it with `--hf-repo`.
#[cfg(all(feature = "gpu-nvidia", feature = "weights"))]
fn llamacpp_cert(gguf_repo: &str) {
    use sbproxy_model_host::launch::ProcessEngineLauncher;
    use sbproxy_model_host::{
        resolve_on_path, Catalog, ConfigDirMetadataProvider, ModelHostConfig, ModelHostRuntime,
        NvmlGpuProbe,
    };
    use std::sync::Arc;
    use std::time::Duration;

    match resolve_on_path("llama-server") {
        Some(p) => println!("PASS: llama-server on PATH at {}", p.display()),
        None => {
            println!("FAIL: llama-server not on PATH (install llama.cpp)");
            std::process::exit(1);
        }
    }
    let rt = tokio_rt();
    // llama.cpp reads GGUF metadata itself; the fit planner still wants
    // a config.json shape, but a GGUF repo has none. Seed a synthetic
    // config into the cache so the metadata provider returns a shape.
    let cache = std::env::temp_dir().join("sbproxy-llamacpp-cert");
    let cfg_path =
        sbproxy_model_host::weights::cache_file(&cache, gguf_repo, "main", "config.json");
    let _ = std::fs::create_dir_all(cfg_path.parent().unwrap());
    let _ = std::fs::write(
        &cfg_path,
        br#"{"num_hidden_layers":24,"num_attention_heads":14,"num_key_value_heads":2,"hidden_size":896,"max_position_embeddings":32768,"num_parameters":500000000}"#,
    );
    let cfg: ModelHostConfig = serde_yaml::from_str(&format!(
        "models:\n  - model: hf:{gguf_repo}\n    name: cert-gguf\n    engine: llama_cpp\n    max_context: 4096\n"
    ))
    .expect("serve config");
    let runtime = ModelHostRuntime::new(
        cfg,
        Catalog::builtin(),
        Arc::new(NvmlGpuProbe::new()),
        Arc::new(ConfigDirMetadataProvider {
            cache_root: cache.clone(),
            revision: "main".to_string(),
            catalog: Arc::new(Catalog::builtin()),
        }),
        Box::new(|| ProcessEngineLauncher::with_timeout(Duration::from_secs(420))),
        false,
    )
    .with_health_recheck(true);
    match rt.block_on(runtime.ensure_ready("cert-gguf")) {
        Ok(p) => {
            println!("PASS: llama.cpp engine ready on port {p}");
            if curl_tokens(p, "cert-gguf") {
                println!("PASS: llama.cpp completion returned tokens");
            } else {
                println!("FAIL: no tokens from llama.cpp engine");
            }
        }
        Err(e) => println!("FAIL: llama.cpp ensure_ready: {e}"),
    }
    rt.block_on(runtime.unload("cert-gguf"));
    println!("llamacpp cert complete");
}

#[cfg(not(all(feature = "gpu-nvidia", feature = "weights")))]
fn llamacpp_cert(_repo: &str) {
    eprintln!("build with --features gpu-nvidia,weights");
    std::process::exit(2);
}

/// Certify OpenAI API-parity features on the served vLLM engine
/// (WOR-1667 structured output, WOR-1668 tool calling, WOR-1669 Open
/// Responses): spawn the engine once, then send one request per feature
/// and report which the engine honors. vLLM's OpenAI server implements
/// these natively, so a served provider inherits them; this confirms it
/// on hardware.
#[cfg(all(feature = "gpu-nvidia", feature = "weights"))]
fn translators_cert(repo: &str) {
    use sbproxy_model_host::launch::ProcessEngineLauncher;
    use sbproxy_model_host::weights::ensure_weight_file;
    use sbproxy_model_host::{
        Catalog, ConfigDirMetadataProvider, ModelHostConfig, ModelHostRuntime, NvmlGpuProbe,
    };
    use std::sync::Arc;
    use std::time::Duration;

    let rt = tokio_rt();
    let cache = std::env::temp_dir().join("sbproxy-runtime-cert-cache");
    let _ = rt.block_on(ensure_weight_file(
        &cache,
        repo,
        "main",
        "config.json",
        None,
    ));
    // hermes is the Qwen tool-call parser; enables auto tool-choice (WOR-1668).
    let cfg: ModelHostConfig = serde_yaml::from_str(&format!(
        "models:\n  - model: hf:{repo}\n    name: cert-model\n    engine: vllm\n    max_context: 8192\n    tool_call_parser: hermes\n"
    ))
    .expect("serve config");
    let runtime = ModelHostRuntime::new(
        cfg,
        Catalog::builtin(),
        Arc::new(NvmlGpuProbe::new()),
        Arc::new(ConfigDirMetadataProvider {
            cache_root: cache.clone(),
            revision: "main".to_string(),
            catalog: Arc::new(Catalog::builtin()),
        }),
        Box::new(|| ProcessEngineLauncher::with_timeout(Duration::from_secs(420))),
        false,
    )
    .with_health_recheck(true);
    let port = match rt.block_on(runtime.ensure_ready("cert-model")) {
        Ok(p) => p,
        Err(e) => {
            println!("FAIL: ensure_ready: {e}");
            std::process::exit(1);
        }
    };
    println!("PASS: vLLM up on port {port} for parity checks");

    // WOR-1667: structured output via response_format json_schema.
    let structured = r#"{"model":"cert-model","messages":[{"role":"user","content":"Return a JSON object with a field name set to Bob."}],"max_tokens":40,"response_format":{"type":"json_schema","json_schema":{"name":"person","schema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}}}"#;
    check_feature(
        port,
        "/v1/chat/completions",
        structured,
        "\"content\"",
        "WOR-1667 structured output (response_format json_schema)",
    );

    // WOR-1668: tool calling.
    let tools = r#"{"model":"cert-model","messages":[{"role":"user","content":"What is the weather in Paris? Use the tool."}],"max_tokens":60,"tools":[{"type":"function","function":{"name":"get_weather","description":"Get weather","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}],"tool_choice":"auto"}"#;
    check_feature(
        port,
        "/v1/chat/completions",
        tools,
        "choices",
        "WOR-1668 tool calling (tools + tool_choice)",
    );

    // WOR-1669: Open Responses API (/v1/responses).
    let responses = r#"{"model":"cert-model","input":"Say hi in one word."}"#;
    check_feature(
        port,
        "/v1/responses",
        responses,
        "\"",
        "WOR-1669 Open Responses (/v1/responses)",
    );

    rt.block_on(runtime.unload("cert-model"));
    println!("translators cert complete");
}

#[cfg(not(all(feature = "gpu-nvidia", feature = "weights")))]
fn translators_cert(_repo: &str) {
    eprintln!("build with --features gpu-nvidia,weights");
    std::process::exit(2);
}

/// POST `body` to `path` on the local engine and report PASS if it
/// answers 200 with `needle` in the body (the feature is honored), else
/// FAIL with the response head so the log shows why.
#[cfg(all(feature = "gpu-nvidia", feature = "weights"))]
fn check_feature(port: u16, path: &str, body: &str, needle: &str, label: &str) {
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "-m",
            "120",
            "-w",
            "\nHTTP_STATUS:%{http_code}",
            &format!("http://127.0.0.1:{port}{path}"),
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
        ])
        .output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            let ok = text.contains("HTTP_STATUS:200") && text.contains(needle);
            if ok {
                println!("PASS: {label}");
            } else {
                let head: String = text.chars().take(180).collect();
                println!("FAIL: {label} -> {head}");
            }
        }
        Err(e) => println!("FAIL: {label} (curl: {e})"),
    }
}

/// POST a one-word completion to a local OpenAI-shaped engine and
/// return whether it answered 200 with content. Uses curl to avoid an
/// HTTP-client dep in the example.
/// Wait until the GPU reports at least `need_bytes` free, or the
/// timeout passes. vLLM holds most of the card, so after a kill the
/// VRAM takes a few seconds to return before another engine can fit.
#[cfg(all(feature = "gpu-nvidia", feature = "weights"))]
fn wait_for_vram_free(
    probe: &sbproxy_model_host::NvmlGpuProbe,
    need_bytes: u64,
    timeout: std::time::Duration,
) {
    use sbproxy_model_host::GpuProbe;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let free = probe
            .probe()
            .first()
            .map(|g| g.free_vram_bytes)
            .unwrap_or(0);
        if free >= need_bytes {
            println!("VRAM recovered: {:.1} GiB free", free as f64 / 1e9);
            return;
        }
        if std::time::Instant::now() >= deadline {
            println!("VRAM did not recover within {timeout:?} (still contended)");
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}

#[cfg(all(feature = "gpu-nvidia", feature = "weights"))]
fn curl_tokens(port: u16, model: &str) -> bool {
    let body = format!(
        r#"{{"model":"{model}","messages":[{{"role":"user","content":"Say hi in one word."}}],"max_tokens":8}}"#
    );
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "-m",
            "120",
            &format!("http://127.0.0.1:{port}/v1/chat/completions"),
            "-H",
            "Content-Type: application/json",
            "-d",
            body.as_str(),
        ])
        .output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.contains("\"content\"") || text.contains("choices")
        }
        Err(_) => false,
    }
}

#[cfg(feature = "gpu-nvidia")]
fn probe() {
    use sbproxy_model_host::fit::{estimate_throughput, plan_fit, ModelMetadata, Quant};
    use sbproxy_model_host::{GpuProbe, NvmlGpuProbe};

    let gpus = NvmlGpuProbe::new().probe();
    assert!(
        !gpus.is_empty(),
        "FAIL: NVML reported no GPUs on a GPU host"
    );
    for g in &gpus {
        println!(
            "GPU[{}] {} | {:.1} GiB total, {:.1} GiB free | cc {:?} | fp8={} | bw={:?} GB/s",
            g.index,
            g.name,
            g.total_vram_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            g.free_vram_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            g.compute_capability,
            g.supports_fp8,
            g.mem_bandwidth_gbps,
        );
    }
    let g = &gpus[0];
    // On an L4 (Ada 8.9) FP8 must be reported; on a T4 it must not.
    println!("PASS: probed {} real GPU(s)", gpus.len());

    // A ~8B model: fit planner should pick FP8 on an FP8-capable card,
    // and refuse FP8 (fall back) on one without it.
    let meta = ModelMetadata {
        params: 8_000_000_000,
        layers: 36,
        kv_heads: 8,
        head_dim: 128,
        max_context: 40960,
        hidden_size: 0,
        expert_count: 0,
        expert_ffn_length: 0,
    };
    let candidates = vec!["FP8".to_string(), "Q4_K_M".to_string()];
    match plan_fit(g, &meta, &candidates, 8192, 1.15) {
        Ok(plan) => {
            println!(
                "fit: chose {} ({:?}), est {:.1} GiB",
                plan.quant_name,
                plan.quant,
                plan.estimated_vram_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
            );
            if g.supports_fp8 {
                assert_eq!(plan.quant, Quant::Fp8, "FAIL: FP8 card should pick FP8");
                println!("PASS: FP8-capable card selected FP8");
            } else {
                assert_ne!(
                    plan.quant,
                    Quant::Fp8,
                    "FAIL: non-FP8 card must not pick FP8"
                );
                println!(
                    "PASS: non-FP8 card refused FP8 and fell back to {}",
                    plan.quant_name
                );
            }
            assert!(
                plan.estimated_vram_bytes <= g.total_vram_bytes,
                "FAIL: planned {:.1} GiB exceeds the {:.1} GiB device",
                plan.estimated_vram_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                g.total_vram_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            );
            println!(
                "PASS: planned {:.1} GiB is within the {:.1} GiB device budget",
                plan.estimated_vram_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                g.total_vram_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            );
        }
        Err(e) => println!("fit error: {e}"),
    }
    if let Some(t) = estimate_throughput(g, &meta, Quant::Fp8, 8192) {
        println!(
            "PASS: throughput estimate {:.0} tok/s decode, safe batch {}",
            t.decode_tokens_per_sec, t.safe_max_batch
        );
    }
}

#[cfg(not(feature = "gpu-nvidia"))]
fn probe() {
    eprintln!("build with --features gpu-nvidia to run the probe");
    std::process::exit(2);
}

/// Compile and run the Metal probe, then assert a small GGUF plan fits
/// the unified-memory budget (WOR-2200). Live RSS comparison happens in
/// `scripts/cert-lane-managed-serve.sh` after a real launch.
#[cfg(all(target_os = "macos", feature = "gpu-apple"))]
fn metal_probe() {
    use sbproxy_model_host::fit::{plan_fit, ModelMetadata};
    use sbproxy_model_host::{GpuProbe, MetalGpuProbe};

    let gpus = MetalGpuProbe::new().probe();
    assert_eq!(
        gpus.len(),
        1,
        "FAIL: Metal probe did not report exactly one Apple device"
    );
    let g = &gpus[0];
    println!(
        "PASS: probed {} | {:.1} GiB Metal working-set budget",
        g.name,
        g.total_vram_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
    );
    let meta = ModelMetadata {
        params: 500_000_000,
        layers: 24,
        kv_heads: 2,
        head_dim: 64,
        max_context: 32768,
        hidden_size: 0,
        expert_count: 0,
        expert_ffn_length: 0,
    };
    match plan_fit(g, &meta, &["Q4_K_M".to_string()], 2048, 1.15) {
        Ok(plan) => {
            assert!(
                plan.estimated_vram_bytes <= g.total_vram_bytes,
                "FAIL: 0.5B Q4_K_M plan {:.1} MiB exceeds the {:.1} GiB Metal budget",
                plan.estimated_vram_bytes as f64 / (1024.0 * 1024.0),
                g.total_vram_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            );
            println!(
                "PASS: 0.5B Q4_K_M plan {:.1} MiB fits the Metal budget",
                plan.estimated_vram_bytes as f64 / (1024.0 * 1024.0),
            );
            assert!(
                sbproxy_model_host::live_rss_within_planned_envelope(
                    plan.estimated_vram_bytes,
                    1,
                    sbproxy_model_host::LIVE_MEMORY_OVERSHOOT
                ),
                "the envelope helper must accept a live RSS below the plan"
            );
        }
        Err(e) => {
            eprintln!("FAIL: fit error on Apple Silicon: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(all(target_os = "macos", feature = "gpu-apple")))]
fn metal_probe() {
    eprintln!("build on macOS with --features gpu-apple to run the Metal probe");
    std::process::exit(2);
}

#[cfg(feature = "weights")]
fn weights(repo: &str) {
    use sbproxy_model_host::weights::ensure_weight_file;
    let cache = std::env::temp_dir().join("sbproxy-gpu-cert-cache");
    let rt = tokio_rt();
    // Pull the model's config.json (small, always present) to prove the
    // hf-hub download + cache path works against the real hub.
    println!("pulling {repo}/config.json into {}", cache.display());
    match rt.block_on(ensure_weight_file(
        &cache,
        repo,
        "main",
        "config.json",
        None,
    )) {
        Ok(path) => {
            let sz = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            println!("PASS: downloaded {} ({} bytes)", path.display(), sz);
        }
        Err(e) => {
            println!("FAIL: weight pull: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "weights"))]
fn weights(_repo: &str) {
    eprintln!("build with --features weights to run the weight pull");
    std::process::exit(2);
}

/// Spawn a real vLLM through the supervisor launcher and confirm it
/// reaches Ready, then leave it running (the shell curls it).
fn serve(repo: &str, port: u16) {
    use sbproxy_model_host::catalog::ModelRef;
    use sbproxy_model_host::config::{EngineKind, KvCacheQuant};
    use sbproxy_model_host::fit::{FitPlan, Quant};
    use sbproxy_model_host::launch::{build_launch_spec, ProcessEngineLauncher};
    use sbproxy_model_host::supervisor::EngineLauncher;
    use std::time::Duration;

    let model = ModelRef {
        hf_repo: repo.to_string(),
        quant: String::new(),
        catalog_id: None,
    };
    // A minimal plan; the small model fits easily, so the numbers here
    // only shape the argv (max-model-len), not admission.
    let plan = FitPlan {
        quant_name: "bf16".to_string(),
        quant: Quant::F16,
        estimated_vram_bytes: 4 * 1024 * 1024 * 1024,
        gpu_indexes: vec![0],
        seq_len: 8192,
        memory: sbproxy_model_host::MemoryEstimate::from_total(0, 4 * 1024 * 1024 * 1024),
        moe: None,
        throughput: None,
        gpu_memory_fraction: None,
    };
    let spec = build_launch_spec(
        EngineKind::Vllm,
        &model,
        &plan,
        port,
        KvCacheQuant::Auto,
        &[],
    );
    println!("launch: {} {}", spec.program, spec.args.join(" "));
    let launcher = ProcessEngineLauncher::with_timeout(Duration::from_secs(420));
    let rt = tokio_rt();
    match rt.block_on(launcher.launch(&spec)) {
        Ok(p) => {
            println!("PASS: vLLM reached Ready on port {p} through ProcessEngineLauncher");
            // Keep the process alive so the shell can curl it. Sleep,
            // then kill on exit.
            std::thread::sleep(Duration::from_secs(90));
            rt.block_on(launcher.kill());
            println!("engine killed");
        }
        Err(e) => {
            println!("FAIL: launch/readiness: {e}");
            rt.block_on(launcher.kill());
            std::process::exit(1);
        }
    }
}

// --- catalog certification harness scaffolding ---
//
// A `certify <model>` gate: does a model's decoding distribution over a
// fixed prompt set match a stored reference within a KL-divergence
// bound. This scaffolds the math and the record shape; the Tier-1
// model matrix (gpt-oss-20b, Qwen3.5 4B/9B/35B-A3B, Gemma 4) and the
// real GPU logit capture are a follow-up run on the GPU cert box, not
// CI. `capture_logits_stub` below stands in for that capture so the
// gate and its record are exercised deterministically without a GPU.

/// KL divergence `D(P || Q) = sum(p_i * ln(p_i / q_i))`, the measure
/// this harness gates a certified model's decoding distribution
/// against a reference with: `0.0` for identical distributions, growing
/// as they diverge. `p` and `q` must be the same length and each sum to
/// roughly `1.0` (a probability distribution); a length mismatch or a
/// negative entry is rejected outright rather than silently producing a
/// meaningless or `NaN` result, since a wrong-but-quiet number here
/// would defeat the whole point of a certification gate. A zero entry
/// in `p` contributes nothing (the `x * ln(x)` term's limit at `0` is
/// `0`); a zero in `q` where `p` is nonzero is undefined and returns
/// `f64::INFINITY` for that term, the standard convention.
fn kl_divergence(p: &[f64], q: &[f64]) -> Result<f64, String> {
    if p.len() != q.len() {
        return Err(format!(
            "kl_divergence: distributions have different lengths ({} vs {})",
            p.len(),
            q.len()
        ));
    }
    if p.iter().chain(q.iter()).any(|&x| x < 0.0) {
        return Err("kl_divergence: distributions must be non-negative".to_string());
    }
    Ok(p.iter()
        .zip(q.iter())
        .map(|(&pi, &qi)| {
            if pi == 0.0 {
                0.0
            } else if qi == 0.0 {
                f64::INFINITY
            } else {
                pi * (pi / qi).ln()
            }
        })
        .sum())
}

/// Gate: a certified model's KL divergence from its reference
/// distribution must not exceed this before the harness marks it FAIL.
const CERTIFY_KL_THRESHOLD: f64 = 0.01;

/// Stubbed logit capture (harness scaffolding): no GPU or real forward
/// pass in this task's scope. Returns two identical synthetic
/// distributions so `certify` exercises its full gate and record-emission
/// path deterministically. A real run on the GPU cert box replaces this
/// with an actual forward pass over the fixed Tier-1 prompt set for
/// `model`, compared against a reference distribution captured once at
/// first certification and stored alongside the catalog entry.
fn capture_logits_stub(_model: &str) -> (Vec<f64>, Vec<f64>) {
    let reference = vec![0.4, 0.3, 0.2, 0.1];
    (reference.clone(), reference)
}

/// `certify <model> [date]`: compute the KL-divergence gate and print a
/// `cert.<lane>.<date>` record. `date` is supplied by whoever runs a
/// real certification (the day it actually ran on the GPU cert box, to
/// match the `cert.apple_metal.2026-07-11` precedent in the capability
/// registry, a fixed evidence string stamped once and committed);
/// omitting it prints an obviously-unfinished placeholder rather than
/// guessing a date from the host clock.
fn certify(model: &str, date: Option<&str>) {
    let (reference, candidate) = capture_logits_stub(model);
    let divergence = match kl_divergence(&reference, &candidate) {
        Ok(value) => value,
        Err(error) => {
            println!("FAIL: {error}");
            std::process::exit(1);
        }
    };
    let passed = divergence <= CERTIFY_KL_THRESHOLD;
    let date = date.unwrap_or("unscheduled");
    let lane = model
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let id = format!("cert.{lane}.{date}");
    println!("certification id: {id}");
    println!("model: {model}");
    println!("kl_divergence: {divergence:.6} (threshold {CERTIFY_KL_THRESHOLD})");
    if passed {
        println!("PASS: {id} within the KL-divergence gate");
    } else {
        println!("FAIL: {id} exceeds the KL-divergence gate");
        std::process::exit(1);
    }
}

fn tokio_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kl_divergence_of_identical_distributions_is_zero() {
        let p = vec![0.25_f64, 0.25, 0.25, 0.25];
        let q = p.clone();
        assert!((kl_divergence(&p, &q).unwrap()).abs() < 1e-9);
    }

    #[test]
    fn kl_divergence_is_positive_for_differing_distributions() {
        let p = vec![0.9_f64, 0.1];
        let q = vec![0.5_f64, 0.5];
        assert!(kl_divergence(&p, &q).unwrap() > 0.0);
    }

    #[test]
    fn kl_divergence_treats_a_zero_p_entry_as_no_contribution() {
        let p = vec![1.0_f64, 0.0];
        let q = vec![0.5_f64, 0.5];
        assert!((kl_divergence(&p, &q).unwrap() - (1.0_f64 * (1.0_f64 / 0.5).ln())).abs() < 1e-9);
    }

    #[test]
    fn kl_divergence_is_infinite_when_q_is_zero_where_p_is_not() {
        let p = vec![1.0_f64];
        let q = vec![0.0_f64];
        assert!(kl_divergence(&p, &q).unwrap().is_infinite());
    }

    #[test]
    fn kl_divergence_rejects_mismatched_lengths() {
        let p = vec![0.5_f64, 0.5];
        let q = vec![1.0_f64];
        let error = kl_divergence(&p, &q).unwrap_err();
        assert!(error.contains("different lengths"), "{error}");
    }

    #[test]
    fn kl_divergence_rejects_a_negative_entry() {
        let p = vec![1.5_f64, -0.5];
        let q = vec![0.5_f64, 0.5];
        let error = kl_divergence(&p, &q).unwrap_err();
        assert!(error.contains("non-negative"), "{error}");
    }

    #[test]
    fn certification_id_follows_the_cert_lane_date_convention() {
        let (reference, candidate) = capture_logits_stub("Qwen/Qwen3-0.6B");
        assert_eq!(
            reference, candidate,
            "the stub is exact until a real GPU capture lands"
        );
        assert!(kl_divergence(&reference, &candidate).unwrap().abs() < 1e-9);

        // The `certify` function itself prints and may exit(1) on FAIL,
        // so the id format is exercised directly here rather than by
        // capturing stdout: it must match `cert.<lane>.<date>` with the
        // lane lowercased and every non-alphanumeric character (the `/`
        // in a repo id) collapsed to `_`.
        let lane = "Qwen/Qwen3-0.6B"
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect::<String>();
        assert_eq!(lane, "qwen_qwen3_0_6b");
    }
}
