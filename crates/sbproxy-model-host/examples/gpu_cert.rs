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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("probe");
    match mode {
        "probe" => probe(),
        "weights" => weights(args.get(2).map(String::as_str).unwrap_or("Qwen/Qwen3-0.6B")),
        "serve" => serve(
            args.get(2).map(String::as_str).unwrap_or("Qwen/Qwen3-0.6B"),
            args.get(3).and_then(|p| p.parse().ok()).unwrap_or(8000),
        ),
        "runtime" => runtime_cert(args.get(2).map(String::as_str).unwrap_or("Qwen/Qwen3-0.6B")),
        "sleepwake" => sleepwake_cert(args.get(2).map(String::as_str).unwrap_or("Qwen/Qwen3-0.6B")),
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
        "embedded" => embedded_cert(
            args.get(2)
                .map(String::as_str)
                .unwrap_or("google/gemma-2-2b-it"),
        ),
        other => {
            eprintln!(
                "unknown mode {other}; use probe | weights | serve | runtime | sleepwake | seed-config | llamacpp <gguf-repo> | translators <repo> | embedded <repo>"
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

/// Certify vLLM sleep/wake (WOR-1655) on a real engine: spawn a model
/// through the runtime (dev mode on, set by the launch spec), then
/// drive the sleep/wake client and verify `is_sleeping` flips.
#[cfg(all(feature = "gpu-nvidia", feature = "weights"))]
fn sleepwake_cert(repo: &str) {
    use sbproxy_model_host::launch::ProcessEngineLauncher;
    use sbproxy_model_host::weights::ensure_weight_file;
    use sbproxy_model_host::{
        is_sleeping, sleep, wake_up, Catalog, ConfigDirMetadataProvider, ModelHostConfig,
        ModelHostRuntime, NvmlGpuProbe, SleepLevel,
    };
    use std::sync::Arc;
    use std::time::Duration;

    let rt = tokio_rt();
    let cache = std::env::temp_dir().join("sbproxy-runtime-cert-cache");
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
        false,
    )
    .with_health_recheck(true);

    let port = match rt.block_on(runtime.ensure_ready("cert-model")) {
        Ok(p) => {
            println!("PASS: vLLM up on port {p} (dev mode for sleep/wake)");
            p
        }
        Err(e) => {
            println!("FAIL: ensure_ready: {e}");
            std::process::exit(1);
        }
    };

    match rt.block_on(sleep(port, SleepLevel::Weights)) {
        Ok(()) => println!("PASS: sleep(level 1) accepted"),
        Err(e) => println!("FAIL: sleep: {e}"),
    }
    // vLLM's sleep is async internally; give it a moment.
    std::thread::sleep(Duration::from_secs(3));
    match rt.block_on(is_sleeping(port)) {
        Ok(true) => println!("PASS: is_sleeping reports true after sleep"),
        Ok(false) => println!("FAIL: engine not sleeping after sleep()"),
        Err(e) => println!("FAIL: is_sleeping: {e}"),
    }
    match rt.block_on(wake_up(port, false)) {
        Ok(()) => println!("PASS: wake_up accepted"),
        Err(e) => println!("FAIL: wake_up: {e}"),
    }
    std::thread::sleep(Duration::from_secs(3));
    match rt.block_on(is_sleeping(port)) {
        Ok(false) => println!("PASS: engine awake after wake_up"),
        Ok(true) => println!("FAIL: still sleeping after wake_up"),
        Err(e) => println!("FAIL: is_sleeping: {e}"),
    }
    // A completion after wake proves the model is servable again.
    if curl_tokens(port, repo) {
        println!("PASS: completion after wake returned tokens");
    } else {
        println!("FAIL: no tokens after wake");
    }
    rt.block_on(runtime.unload("cert-model"));
    println!("sleepwake cert complete");
}

#[cfg(not(all(feature = "gpu-nvidia", feature = "weights")))]
fn sleepwake_cert(_repo: &str) {
    eprintln!("build with --features gpu-nvidia,weights");
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
        gpu_index: 0,
        seq_len: 8192,
        memory: sbproxy_model_host::MemoryEstimate::from_total(0, 4 * 1024 * 1024 * 1024),
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

/// Certify the in-process embedded engine (WOR-1658): load `repo` with
/// mistral.rs, serve it on a loopback port, and get a completion. The
/// default `repo` is a Gemma model (per the load-Gemma cert); Gemma is
/// HF-gated, so this needs `HF_TOKEN` in the env. Build with
/// `--features embedded` (add `gpu-nvidia` to run on the GPU).
#[cfg(feature = "embedded")]
fn embedded_cert(repo: &str) {
    use sbproxy_model_host::embedded::EmbeddedServer;
    let rt = tokio_rt();
    let port = 8123u16;
    println!("loading embedded model {repo} via mistral.rs (Gemma-capable) ...");
    match rt.block_on(EmbeddedServer::start(repo, port)) {
        Ok(server) => {
            println!("PASS: embedded model loaded + serving on {port}");
            let body = format!(
                "{{\"model\":\"{repo}\",\"messages\":[{{\"role\":\"user\",\"content\":\"Say hi in one word\"}}],\"max_tokens\":10}}"
            );
            let out = std::process::Command::new("curl")
                .args([
                    "-sS",
                    "-m",
                    "180",
                    "-w",
                    "\nHTTP_STATUS:%{http_code}",
                    &format!("http://127.0.0.1:{port}/v1/chat/completions"),
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    &body,
                ])
                .output();
            match out {
                Ok(o) => {
                    let text = String::from_utf8_lossy(&o.stdout);
                    if text.contains("HTTP_STATUS:200") && text.contains("\"content\"") {
                        println!("PASS: embedded completion returned tokens");
                    } else {
                        let head: String = text.chars().take(200).collect();
                        println!("FAIL: embedded completion -> {head}");
                    }
                }
                Err(e) => println!("FAIL: curl embedded endpoint: {e}"),
            }
            rt.block_on(server.shutdown());
        }
        Err(e) => println!("FAIL: embedded load: {e} (Gemma is HF-gated; set HF_TOKEN)"),
    }
    println!("embedded cert complete");
}

#[cfg(not(feature = "embedded"))]
fn embedded_cert(_repo: &str) {
    eprintln!("build with --features embedded (add gpu-nvidia to run on the GPU)");
    std::process::exit(2);
}

fn tokio_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}
