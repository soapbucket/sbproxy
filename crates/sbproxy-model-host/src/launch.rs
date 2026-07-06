// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Building and running engine launches (WOR-1653 runtime, WOR-1656).
//!
//! Two halves live here. [`build_launch_spec`] is the pure argument
//! template: given an engine, a resolved model, a fit plan, and a
//! port, it produces the exact argv the engine binary is spawned
//! with. [`ProcessEngineLauncher`] is the real [`EngineLauncher`]:
//! it spawns that argv as a supervised subprocess, polls a readiness
//! endpoint over loopback until the engine answers, and kills the
//! process on eviction.
//!
//! The launcher is engine-agnostic and needs no GPU, so its spawn /
//! probe / kill machinery is exercised here against a fake process
//! (a trivial listener) with no vLLM present. What it cannot prove
//! without hardware is that a real engine boots and serves tokens;
//! that is the GPU-phase certification. The readiness probe is a
//! minimal raw-HTTP GET so the crate keeps its lean dependency set
//! (no HTTP client, no TLS).

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::catalog::ModelRef;
use crate::config::{EngineKind, KvCacheQuant};
use crate::fit::FitPlan;
use crate::supervisor::{EngineLauncher, LaunchSpec};

/// Build the launch spec (program + argv + env) for an engine.
///
/// The argument templates are owned here, not in config, which is
/// what keeps config from naming an arbitrary command: the operator
/// chooses an [`EngineKind`] and knobs, and this function decides the
/// argv. `extra_args` from config are appended verbatim as trailing
/// argv elements.
pub fn build_launch_spec(
    engine: EngineKind,
    model: &ModelRef,
    plan: &FitPlan,
    port: u16,
    kv_quant: KvCacheQuant,
    extra_args: &[String],
) -> LaunchSpec {
    let mut args: Vec<String> = Vec::new();
    let mut env: Vec<(String, String)> = Vec::new();

    match engine {
        EngineKind::Vllm => {
            // `vllm serve <repo> --port <p> --host 127.0.0.1
            //   [--quantization <q>] --max-model-len <ctx>`
            args.push("serve".to_string());
            args.push(model.hf_repo.clone());
            args.push("--host".to_string());
            args.push("127.0.0.1".to_string());
            args.push("--port".to_string());
            args.push(port.to_string());
            if let Some(q) = vllm_quantization(&plan.quant_name) {
                args.push("--quantization".to_string());
                args.push(q.to_string());
            }
            if let Some(dtype) = vllm_kv_cache_dtype(kv_quant) {
                args.push("--kv-cache-dtype".to_string());
                args.push(dtype.to_string());
            }
            args.push("--max-model-len".to_string());
            args.push(plan.seq_len.to_string());
            // Enable the dev endpoints the sleep/wake phase drives.
            env.push(("VLLM_SERVER_DEV_MODE".to_string(), "1".to_string()));
        }
        EngineKind::LlamaCpp => {
            // `llama-server --hf-repo <repo> --host 127.0.0.1
            //   --port <p> --ctx-size <ctx> --n-gpu-layers 999` (GGUF
            // quant is selected by the file in the repo, not a flag).
            args.push("--hf-repo".to_string());
            args.push(model.hf_repo.clone());
            args.push("--host".to_string());
            args.push("127.0.0.1".to_string());
            args.push("--port".to_string());
            args.push(port.to_string());
            args.push("--ctx-size".to_string());
            args.push(plan.seq_len.to_string());
            // WOR-1656: offload all layers to the GPU. Without this
            // llama.cpp runs CPU-only; 999 means "as many as fit" and
            // llama.cpp clamps to the model's layer count. A build
            // without CUDA ignores it and stays on CPU, so it is safe on
            // any host.
            args.push("--n-gpu-layers".to_string());
            args.push("999".to_string());
            if let Some(t) = llama_cache_type(kv_quant) {
                // Quantize both K and V caches.
                args.push("--cache-type-k".to_string());
                args.push(t.to_string());
                args.push("--cache-type-v".to_string());
                args.push(t.to_string());
            }
        }
        EngineKind::Embedded => {
            // WOR-1658: in-process engine. No subprocess is spawned; the
            // launcher reads these args to load the model into the
            // gateway. The first arg is the model repo, then the loopback
            // port the in-process server binds (so the runtime routes to
            // it like any other engine), then the context window.
            args.push(model.hf_repo.clone());
            args.push("--host".to_string());
            args.push("127.0.0.1".to_string());
            args.push("--port".to_string());
            args.push(port.to_string());
            args.push("--ctx-size".to_string());
            args.push(plan.seq_len.to_string());
        }
    }

    args.extend(extra_args.iter().cloned());

    LaunchSpec {
        engine,
        program: engine.binary_name().to_string(),
        args,
        env,
        vram_bytes: plan.estimated_vram_bytes,
    }
}

/// Retarget a llama.cpp launch argv from a Hugging Face download to a
/// locally pre-fetched GGUF (WOR-1656). Replaces the `--hf-repo <repo>`
/// pair with `--model <path>`, so llama.cpp loads the file directly and
/// needs no curl-enabled build or `--hf-file` quant guess. A no-op if
/// there is no `--hf-repo` in the argv.
pub fn llama_use_local_model(args: &mut [String], model_path: &std::path::Path) {
    if let Some(i) = args.iter().position(|a| a == "--hf-repo") {
        // Replace "--hf-repo" and its value (the next element).
        args[i] = "--model".to_string();
        if i + 1 < args.len() {
            args[i + 1] = model_path.display().to_string();
        }
    }
}

/// Add `--hf-file <file>` to a llama.cpp launch argv (WOR-1656) so a
/// curl-enabled llama.cpp downloads the right GGUF from a multi-file
/// repo. Used only when the local pre-fetch is unavailable (the
/// `weights` feature is off). Inserted right after `--hf-repo`; a no-op
/// if `--hf-repo` is absent or `--hf-file` is already present.
pub fn llama_set_hf_file(args: &mut Vec<String>, file: &str) {
    if args.iter().any(|a| a == "--hf-file") {
        return;
    }
    if let Some(i) = args.iter().position(|a| a == "--hf-repo") {
        args.insert(i + 2, file.to_string());
        args.insert(i + 2, "--hf-file".to_string());
    }
}

/// Map a catalog quant name to vLLM's `--quantization` value, or
/// `None` when vLLM infers it from the weights (bf16/fp16 safetensors
/// need no flag).
fn vllm_quantization(quant_name: &str) -> Option<&'static str> {
    let n = quant_name.to_ascii_lowercase();
    if n.contains("fp8") {
        Some("fp8")
    } else if n.contains("awq") {
        Some("awq")
    } else if n.contains("gptq") {
        Some("gptq")
    } else {
        None
    }
}

/// Map a KV-quant mode to vLLM's `--kv-cache-dtype`, or `None` when no
/// flag is needed (`Auto` / `F16` are vLLM's default).
fn vllm_kv_cache_dtype(kv: KvCacheQuant) -> Option<&'static str> {
    match kv {
        KvCacheQuant::Auto | KvCacheQuant::F16 => None,
        KvCacheQuant::Fp8 => Some("fp8"),
        // vLLM exposes fp8 variants; int8/int4 KV map to the nearest
        // supported low-precision dtype it accepts.
        KvCacheQuant::Int8 => Some("fp8"),
        KvCacheQuant::Int4 => Some("fp8"),
    }
}

/// Map a KV-quant mode to llama.cpp's `--cache-type-{k,v}` value, or
/// `None` for the f16 default.
fn llama_cache_type(kv: KvCacheQuant) -> Option<&'static str> {
    match kv {
        KvCacheQuant::Auto | KvCacheQuant::F16 => None,
        KvCacheQuant::Fp8 => Some("q8_0"),
        KvCacheQuant::Int8 => Some("q8_0"),
        KvCacheQuant::Int4 => Some("q4_0"),
    }
}

/// Additional engine flags for the serving knobs on a
/// [`ServeEntry`](crate::config::ServeEntry):
/// speculative decoding (WOR-1674), chunked prefill (WOR-1678), and
/// LoRA adapters (WOR-1673). Returned separately from
/// [`build_launch_spec`] so the base argv template stays stable; the
/// runtime appends these to the spec's args. Only vLLM flags are
/// emitted today (llama.cpp has different surfaces); an llama.cpp entry
/// returns an empty vec for the vLLM-only knobs.
pub fn serving_flags(engine: EngineKind, entry: &crate::config::ServeEntry) -> Vec<String> {
    let mut args = Vec::new();
    if engine != EngineKind::Vllm {
        return args;
    }
    // WOR-1680/1683: the engine must answer to the served *name* (the id
    // every plane routes with), not the underlying HF repo id. Without
    // this vLLM serves under the repo path and a request for the served
    // name 404s. `--served-model-name` makes the engine accept the name.
    // WOR-1673: also list the LoRA adapter names, so a request that
    // addresses an adapter is accepted by the same engine.
    if let Ok(name) = entry.effective_name() {
        args.push("--served-model-name".to_string());
        args.push(name);
        for adapter in &entry.lora_adapters {
            args.push(adapter.name.clone());
        }
    }
    // WOR-1668: tool calling. vLLM rejects `tool_choice: auto` unless
    // launched with an auto-tool-choice parser; the parser is
    // model-specific (hermes for Qwen, llama3_json, mistral, ...), so
    // the operator declares it and we enable it here.
    if let Some(parser) = &entry.tool_call_parser {
        args.push("--enable-auto-tool-choice".to_string());
        args.push("--tool-call-parser".to_string());
        args.push(parser.clone());
    }
    // WOR-1687: KV-cache tiering to CPU. `--swap-space` sizes the CPU
    // pool vLLM spills GPU KV blocks into under pressure; `--cpu-offload-gb`
    // keeps that many GiB of weights in CPU RAM.
    if let Some(gib) = entry.swap_space_gib {
        args.push("--swap-space".to_string());
        args.push(gib.to_string());
    }
    if let Some(gib) = entry.cpu_offload_gib {
        args.push("--cpu-offload-gb".to_string());
        args.push(gib.to_string());
    }
    // Speculative decoding.
    if let Some(spec) = &entry.speculative {
        use crate::config::SpecMethod;
        match spec.method {
            SpecMethod::DraftModel => {
                if let Some(dm) = &spec.draft_model {
                    args.push("--speculative-model".to_string());
                    args.push(dm.clone());
                }
            }
            SpecMethod::Ngram => {
                args.push("--speculative-model".to_string());
                args.push("[ngram]".to_string());
            }
        }
        args.push("--num-speculative-tokens".to_string());
        args.push(spec.num_speculative_tokens.to_string());
    }
    // Chunked prefill.
    if let Some(cp) = &entry.chunked_prefill {
        args.push("--enable-chunked-prefill".to_string());
        if let Some(mbt) = cp.max_batched_tokens {
            args.push("--max-num-batched-tokens".to_string());
            args.push(mbt.to_string());
        }
    }
    // LoRA adapters (WOR-1673). `--max-loras` is the engine adapter-slot
    // capacity. In static mode (max_loras unset) every adapter is
    // preloaded with `--lora-modules`. In dynamic mode (max_loras below
    // the adapter count) adapters are loaded on demand at runtime, so no
    // `--lora-modules` is emitted; the runtime pages them via the vLLM
    // load/unload API (and sets VLLM_ALLOW_RUNTIME_LORA_UPDATING).
    if !entry.lora_adapters.is_empty() {
        args.push("--enable-lora".to_string());
        args.push("--max-loras".to_string());
        args.push(entry.lora_capacity().to_string());
        if !entry.dynamic_lora() {
            for a in &entry.lora_adapters {
                args.push("--lora-modules".to_string());
                args.push(format!("{}={}", a.name, a.source));
            }
        }
    }
    args
}

/// Whether speculation should be active right now, given the current
/// batch occupancy (running sequences / max batch). Speculation helps
/// when the batch is memory-bound (occupancy below the threshold) and
/// hurts when compute-bound (a full batch), so the runtime gates it on
/// live load rather than leaving it globally on (WOR-1674).
pub fn should_speculate(batch_occupancy: f64, threshold: f64) -> bool {
    batch_occupancy < threshold
}

/// Default batch-occupancy threshold below which speculation is on.
pub const SPECULATE_OCCUPANCY_THRESHOLD: f64 = 0.5;

/// Choose a chunked-prefill chunk size (`max-num-batched-tokens`) to
/// hold a target TTFT, given the engine's estimated prefill throughput
/// in tokens/sec (WOR-1678). Larger chunks raise throughput but push
/// TTFT out; the chunk that fits the SLO is `throughput * ttft`,
/// clamped to a sane floor so a tiny SLO does not starve prefill.
pub fn chunk_size_for_ttft(target_ttft_ms: u64, prefill_tokens_per_sec: f64) -> u64 {
    let budget = prefill_tokens_per_sec * (target_ttft_ms as f64 / 1000.0);
    (budget as u64).max(MIN_PREFILL_CHUNK)
}

/// Floor on an auto-tuned prefill chunk size.
pub const MIN_PREFILL_CHUNK: u64 = 512;

/// The production launcher: spawns the engine binary as a child
/// process, waits for its readiness endpoint, and kills it on evict.
#[derive(Debug, Clone)]
pub struct ProcessEngineLauncher {
    /// How long to wait for the readiness probe before declaring the
    /// launch failed.
    pub ready_timeout: Duration,
    /// Path polled for readiness (vLLM and llama-server both expose
    /// `/health`).
    pub health_path: String,
    /// Shared handle to the running child so `kill` can reach it.
    child: std::sync::Arc<tokio::sync::Mutex<Option<tokio::process::Child>>>,
    /// In-process embedded engine (WOR-1658), when the launched engine is
    /// `EngineKind::Embedded`. Present only under the `embedded` feature.
    #[cfg(feature = "embedded")]
    embedded: std::sync::Arc<tokio::sync::Mutex<Option<crate::embedded::EmbeddedServer>>>,
}

impl Default for ProcessEngineLauncher {
    fn default() -> Self {
        Self {
            ready_timeout: Duration::from_secs(300),
            health_path: "/health".to_string(),
            child: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            #[cfg(feature = "embedded")]
            embedded: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
}

impl ProcessEngineLauncher {
    /// A launcher with a custom readiness timeout.
    pub fn with_timeout(ready_timeout: Duration) -> Self {
        Self {
            ready_timeout,
            ..Self::default()
        }
    }

    /// The port the launch spec asked the engine to bind, parsed back
    /// out of its argv (`--port <p>`). Used to target the probe.
    fn port_from_spec(spec: &LaunchSpec) -> Option<u16> {
        let mut it = spec.args.iter();
        while let Some(a) = it.next() {
            if a == "--port" {
                return it.next().and_then(|p| p.parse().ok());
            }
        }
        None
    }

    /// Launch the in-process embedded engine (WOR-1658). With the
    /// `embedded` feature, loads the model with mistral.rs and serves an
    /// OpenAI endpoint on `port` (so the runtime routes to it like any
    /// other engine); the model id is the first argv element from
    /// `build_launch_spec`'s embedded arm. Without the feature it returns
    /// a state-accurate error (the plan-time
    /// [`EngineDoctor`](crate::config::EngineDoctor) also flags it).
    #[cfg(feature = "embedded")]
    async fn launch_embedded(&self, spec: &LaunchSpec, port: u16) -> Result<u16, String> {
        let repo = spec
            .args
            .first()
            .ok_or_else(|| "embedded launch spec has no model repo".to_string())?;
        let server = crate::embedded::EmbeddedServer::start(repo, port).await?;
        *self.embedded.lock().await = Some(server);
        Ok(port)
    }

    #[cfg(not(feature = "embedded"))]
    async fn launch_embedded(&self, _spec: &LaunchSpec, _port: u16) -> Result<u16, String> {
        Err("engine: embedded needs a build with --features embedded (WOR-1658)".to_string())
    }
}

/// Poll `127.0.0.1:port{path}` with a bare HTTP GET until it answers
/// `200`, or the deadline passes. A raw request keeps the crate free
/// of an HTTP-client dependency. Returns `Ok(())` on the first `200`.
pub async fn wait_for_ready(port: u16, path: &str, timeout: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    let addr = format!("127.0.0.1:{port}");
    let mut attempt = 0u32;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("readiness probe timed out after {timeout:?}"));
        }
        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await
        {
            let req =
                format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            if stream.write_all(req.as_bytes()).await.is_ok() {
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf).await {
                    let head = String::from_utf8_lossy(&buf[..n]);
                    if head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200") {
                        return Ok(());
                    }
                }
            }
        }
        // Backoff a little between polls; the engine takes seconds.
        attempt += 1;
        let delay = Duration::from_millis(100 * u64::from(attempt).min(20));
        tokio::time::sleep(delay).await;
    }
}

/// A single-shot health check: one `GET {path}` to `127.0.0.1:port`,
/// returning whether it answered `200`. Unlike [`wait_for_ready`] this
/// does not loop; the runtime uses it to detect an engine that died
/// under a cached-ready state so the next request respawns it.
pub async fn probe_health(port: u16, path: &str) -> bool {
    let addr = format!("127.0.0.1:{port}");
    let attempt = async {
        let mut stream = TcpStream::connect(&addr).await.ok()?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.ok()?;
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.ok()?;
        let head = String::from_utf8_lossy(&buf[..n]);
        Some(head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200"))
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(2), attempt).await,
        Ok(Some(true))
    )
}

/// POST a JSON `body` to `127.0.0.1:port{path}` with a bare HTTP
/// request (WOR-1673 LoRA load/unload), keeping the crate free of an
/// HTTP-client dependency. Returns `Ok(())` on a `2xx`, else an error
/// with the status line. `timeout` bounds the whole exchange because a
/// cold adapter load can take a few seconds.
pub async fn post_json(port: u16, path: &str, body: &str, timeout: Duration) -> Result<(), String> {
    let addr = format!("127.0.0.1:{port}");
    let attempt = async {
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("connect {addr}: {e}"))?;
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("write {path}: {e}"))?;
        let mut buf = [0u8; 128];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("read {path}: {e}"))?;
        let head = String::from_utf8_lossy(&buf[..n]);
        // Accept any 2xx; vLLM answers 200 on load/unload.
        if head.starts_with("HTTP/1.1 2") || head.starts_with("HTTP/1.0 2") {
            Ok(())
        } else {
            Err(format!(
                "{path}: {}",
                head.lines().next().unwrap_or("no status line")
            ))
        }
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(r) => r,
        Err(_) => Err(format!("{path}: timed out after {timeout:?}")),
    }
}

impl EngineLauncher for ProcessEngineLauncher {
    async fn launch(&self, spec: &LaunchSpec) -> Result<u16, String> {
        let port = Self::port_from_spec(spec)
            .ok_or_else(|| "launch spec has no --port to probe".to_string())?;
        // WOR-1658: an in-process engine is not a subprocess. Dispatch to
        // the embedded path, which starts a server inside the gateway on
        // `port` (behind the `embedded` feature) rather than spawning.
        if spec.engine.is_in_process() {
            return self.launch_embedded(spec, port).await;
        }
        let mut cmd = tokio::process::Command::new(&spec.program);
        cmd.args(&spec.args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        // Put the engine in its own process group so a later group
        // kill can reap the workers vLLM forks, and so it does not
        // receive signals aimed at the gateway. `process_group` is
        // tokio's inherent Unix method.
        #[cfg(unix)]
        cmd.process_group(0);
        // Capture the engine's stderr to a per-port log so a crash
        // reports why, not just that it died. A file sink needs no
        // draining (unlike a pipe), so it cannot deadlock the child.
        let log_path = std::env::temp_dir().join(format!("sbproxy-engine-{port}.log"));
        match std::fs::File::create(&log_path) {
            Ok(f) => {
                cmd.stderr(Stdio::from(f));
            }
            Err(_) => {
                cmd.stderr(Stdio::null());
            }
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", spec.program))?;

        // Race readiness against the child exiting. A crashed engine
        // (bad flag, OOM, missing CUDA) would otherwise be polled for
        // the full readiness timeout, and the supervisor would repeat
        // that for every retry: a broken model could block a request
        // for tens of minutes. Detecting the early exit fails fast.
        let outcome = tokio::select! {
            biased;
            exited = child.wait() => {
                let tail = std::fs::read_to_string(&log_path)
                    .ok()
                    .map(|s| last_lines(&s, 15))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "(no stderr captured)".to_string());
                Err(format!(
                    "engine '{}' exited before ready ({exited:?}); stderr tail:\n{tail}",
                    spec.program
                ))
            }
            ready = wait_for_ready(port, &self.health_path, self.ready_timeout) => {
                ready.map(|()| port)
            }
        };

        match outcome {
            Ok(p) => {
                *self.child.lock().await = Some(child);
                Ok(p)
            }
            Err(e) => {
                // Readiness failed or the engine exited; make sure the
                // child (and its group) is reaped, then report.
                let _ = child.start_kill();
                let _ = child.wait().await;
                Err(e)
            }
        }
    }

    async fn kill(&self) {
        // WOR-1658: an in-process embedded engine has no child process;
        // stop its server task and drop the model to free memory.
        #[cfg(feature = "embedded")]
        if let Some(server) = self.embedded.lock().await.take() {
            server.shutdown().await;
            return;
        }
        if let Some(mut child) = self.child.lock().await.take() {
            // vLLM forks worker processes (EngineCore) that hold the
            // VRAM, and it double-forks, so neither a parent SIGKILL nor
            // a child-group kill reliably reaps them. The reliable path
            // is graceful: SIGTERM the engine and let it tear down its
            // own workers (SIGKILL cannot be caught, so it would orphan
            // them). We SIGKILL only as a backstop if it does not exit,
            // and even then only its own process group, never ours (that
            // would take down the gateway).
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                let _ = std::process::Command::new("kill")
                    .args(["-TERM", &pid.to_string()])
                    .status();
            }
            // Give it a moment to shut its workers down cleanly.
            if tokio::time::timeout(Duration::from_secs(10), child.wait())
                .await
                .is_err()
            {
                #[cfg(unix)]
                if let Some(pid) = child.id() {
                    // Backstop: group-kill, but only a distinct group the
                    // child truly leads (pgid == pid), never our own.
                    match (pgid_of(pid), pgid_of(std::process::id())) {
                        (Some(child_pgid), Some(our_pgid))
                            if child_pgid == pid && child_pgid != our_pgid =>
                        {
                            let _ = std::process::Command::new("kill")
                                .args(["-KILL", &format!("-{child_pgid}")])
                                .status();
                        }
                        _ => {}
                    }
                }
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }
    }
}

/// The last `n` non-empty lines of `s`, joined, for a compact error
/// tail from an engine's captured stderr.
fn last_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// The process-group id of `pid` via `ps`, or `None` if it cannot be
/// read. Used to guard the backstop group kill so it never targets our
/// own group (which would SIGKILL the gateway).
#[cfg(unix)]
fn pgid_of(pid: u32) -> Option<u32> {
    let out = std::process::Command::new("ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fit::Quant;

    fn plan(quant_name: &str) -> FitPlan {
        FitPlan {
            quant_name: quant_name.to_string(),
            quant: Quant::classify(quant_name),
            estimated_vram_bytes: 12 * crate::fit::GIB,
            gpu_index: 0,
            seq_len: 8192,
        }
    }

    fn model() -> ModelRef {
        ModelRef {
            hf_repo: "Qwen/Qwen3-14B".to_string(),
            quant: "FP8".to_string(),
            catalog_id: Some("qwen3-14b".to_string()),
        }
    }

    #[test]
    fn vllm_argv_has_repo_port_and_quant() {
        let spec = build_launch_spec(
            EngineKind::Vllm,
            &model(),
            &plan("FP8"),
            8001,
            KvCacheQuant::Auto,
            &[],
        );
        assert_eq!(spec.program, "vllm");
        assert_eq!(spec.args[0], "serve");
        assert_eq!(spec.args[1], "Qwen/Qwen3-14B");
        // --port 8001 present
        let pi = spec.args.iter().position(|a| a == "--port").unwrap();
        assert_eq!(spec.args[pi + 1], "8001");
        // FP8 -> --quantization fp8
        let qi = spec
            .args
            .iter()
            .position(|a| a == "--quantization")
            .unwrap();
        assert_eq!(spec.args[qi + 1], "fp8");
        // dev mode env for the sleep/wake phase
        assert!(spec
            .env
            .iter()
            .any(|(k, v)| k == "VLLM_SERVER_DEV_MODE" && v == "1"));
        assert_eq!(spec.vram_bytes, 12 * crate::fit::GIB);
    }

    #[test]
    fn vllm_bf16_omits_quantization_flag() {
        let spec = build_launch_spec(
            EngineKind::Vllm,
            &model(),
            &plan("bf16"),
            8002,
            KvCacheQuant::Auto,
            &[],
        );
        assert!(!spec.args.iter().any(|a| a == "--quantization"));
        // Auto KV adds no --kv-cache-dtype flag.
        assert!(!spec.args.iter().any(|a| a == "--kv-cache-dtype"));
    }

    #[test]
    fn llama_cpp_argv_uses_hf_repo_and_ctx() {
        let spec = build_launch_spec(
            EngineKind::LlamaCpp,
            &model(),
            &plan("Q4_K_M"),
            8003,
            KvCacheQuant::Auto,
            &[],
        );
        assert_eq!(spec.program, "llama-server");
        let ri = spec.args.iter().position(|a| a == "--hf-repo").unwrap();
        assert_eq!(spec.args[ri + 1], "Qwen/Qwen3-14B");
        let ci = spec.args.iter().position(|a| a == "--ctx-size").unwrap();
        assert_eq!(spec.args[ci + 1], "8192");
        // WOR-1656: offload to the GPU.
        let gi = spec
            .args
            .iter()
            .position(|a| a == "--n-gpu-layers")
            .unwrap();
        assert_eq!(spec.args[gi + 1], "999");
    }

    #[test]
    fn llama_local_model_replaces_hf_repo() {
        // WOR-1656: a pre-fetched GGUF turns --hf-repo into a local
        // --model (no HF download, no curl needed).
        let spec = build_launch_spec(
            EngineKind::LlamaCpp,
            &model(),
            &plan("Q4_K_M"),
            8020,
            KvCacheQuant::Auto,
            &[],
        );
        let mut args = spec.args;
        llama_use_local_model(&mut args, std::path::Path::new("/cache/x.gguf"));
        assert!(!args.iter().any(|a| a == "--hf-repo"));
        let mi = args.iter().position(|a| a == "--model").unwrap();
        assert_eq!(args[mi + 1], "/cache/x.gguf");
    }

    #[test]
    fn llama_hf_file_inserted_once_after_hf_repo() {
        // WOR-1656: the download fallback disambiguates a multi-file repo.
        let spec = build_launch_spec(
            EngineKind::LlamaCpp,
            &model(),
            &plan("Q4_K_M"),
            8021,
            KvCacheQuant::Auto,
            &[],
        );
        let mut args = spec.args;
        llama_set_hf_file(&mut args, "x.gguf");
        let ri = args.iter().position(|a| a == "--hf-repo").unwrap();
        assert_eq!(args[ri + 2], "--hf-file");
        assert_eq!(args[ri + 3], "x.gguf");
        // Idempotent: a second call does not add a duplicate.
        llama_set_hf_file(&mut args, "y.gguf");
        assert_eq!(args.iter().filter(|a| *a == "--hf-file").count(), 1);
    }

    #[test]
    fn embedded_spec_carries_engine_repo_and_port() {
        // WOR-1658: the embedded spec is tagged as in-process and carries
        // the repo + loopback port the in-process server binds.
        let spec = build_launch_spec(
            EngineKind::Embedded,
            &model(),
            &plan("Q4_K_M"),
            8010,
            KvCacheQuant::Auto,
            &[],
        );
        assert_eq!(spec.engine, EngineKind::Embedded);
        assert!(spec.engine.is_in_process());
        assert_eq!(spec.args[0], "Qwen/Qwen3-14B");
        let pi = spec.args.iter().position(|a| a == "--port").unwrap();
        assert_eq!(spec.args[pi + 1], "8010");
    }

    #[tokio::test]
    async fn embedded_launch_reports_state_not_a_spawn_error() {
        // The launcher dispatches an in-process engine to the embedded
        // path; without the backend it returns a state-accurate error
        // (naming embedded / WOR-1658), never a generic spawn failure.
        let spec = build_launch_spec(
            EngineKind::Embedded,
            &model(),
            &plan("Q4_K_M"),
            8011,
            KvCacheQuant::Auto,
            &[],
        );
        let launcher = ProcessEngineLauncher::with_timeout(Duration::from_secs(1));
        let err = launcher.launch(&spec).await.unwrap_err();
        assert!(err.contains("embedded"), "unexpected error: {err}");
        assert!(!err.contains("spawn"), "should not be a spawn error: {err}");
    }

    #[test]
    fn kv_quant_adds_engine_flags() {
        // vLLM: Int4 KV maps to a --kv-cache-dtype flag.
        let v = build_launch_spec(
            EngineKind::Vllm,
            &model(),
            &plan("FP8"),
            8010,
            KvCacheQuant::Int4,
            &[],
        );
        let ki = v.args.iter().position(|a| a == "--kv-cache-dtype").unwrap();
        assert_eq!(v.args[ki + 1], "fp8");
        // llama.cpp: Int4 KV quantizes both K and V caches to q4_0.
        let l = build_launch_spec(
            EngineKind::LlamaCpp,
            &model(),
            &plan("Q4_K_M"),
            8011,
            KvCacheQuant::Int4,
            &[],
        );
        assert!(l.args.iter().any(|a| a == "--cache-type-k"));
        assert!(l.args.iter().any(|a| a == "--cache-type-v"));
        assert!(l.args.iter().any(|a| a == "q4_0"));
    }

    #[test]
    fn extra_args_appended_verbatim() {
        let spec = build_launch_spec(
            EngineKind::Vllm,
            &model(),
            &plan("FP8"),
            8004,
            KvCacheQuant::Auto,
            &[
                "--enable-prefix-caching".to_string(),
                "--seed=7".to_string(),
            ],
        );
        assert_eq!(
            &spec.args[spec.args.len() - 2..],
            &["--enable-prefix-caching", "--seed=7"]
        );
    }

    fn entry_with(
        spec: Option<crate::config::SpeculativeConfig>,
        cp: Option<crate::config::ChunkedPrefill>,
        loras: Vec<crate::config::LoraAdapter>,
    ) -> crate::config::ServeEntry {
        crate::config::ServeEntry {
            model: "qwen3-8b".into(),
            name: None,
            engine: crate::config::EngineChoice::Vllm,
            keep_alive: None,
            max_context: None,
            extra_args: vec![],
            kv_quant: KvCacheQuant::Auto,
            speculative: spec,
            chunked_prefill: cp,
            lora_adapters: loras,
            pinned: false,
            tool_call_parser: None,
            swap_space_gib: None,
            cpu_offload_gib: None,
            max_loras: None,
            gguf_file: None,
        }
    }

    #[test]
    fn serving_flags_speculative_draft_model() {
        use crate::config::{SpecMethod, SpeculativeConfig};
        let e = entry_with(
            Some(SpeculativeConfig {
                method: SpecMethod::DraftModel,
                draft_model: Some("Qwen/Qwen3-0.6B".into()),
                num_speculative_tokens: 4,
            }),
            None,
            vec![],
        );
        let f = serving_flags(EngineKind::Vllm, &e);
        let i = f.iter().position(|a| a == "--speculative-model").unwrap();
        assert_eq!(f[i + 1], "Qwen/Qwen3-0.6B");
        let n = f
            .iter()
            .position(|a| a == "--num-speculative-tokens")
            .unwrap();
        assert_eq!(f[n + 1], "4");
    }

    #[test]
    fn serving_flags_chunked_and_lora() {
        use crate::config::{ChunkedPrefill, LoraAdapter};
        let e = entry_with(
            None,
            Some(ChunkedPrefill {
                max_batched_tokens: Some(2048),
                target_ttft_ms: None,
            }),
            vec![LoraAdapter {
                name: "bot".into(),
                source: "hf:org/bot".into(),
            }],
        );
        let f = serving_flags(EngineKind::Vllm, &e);
        assert!(f.iter().any(|a| a == "--enable-chunked-prefill"));
        let m = f
            .iter()
            .position(|a| a == "--max-num-batched-tokens")
            .unwrap();
        assert_eq!(f[m + 1], "2048");
        assert!(f.iter().any(|a| a == "--enable-lora"));
        assert!(f.iter().any(|a| a == "bot=hf:org/bot"));
    }

    #[test]
    fn serving_flags_served_name_includes_adapters() {
        // WOR-1673: the engine answers to the base name and every
        // adapter name, so an adapter-addressed request is accepted.
        let e = entry_with(
            None,
            None,
            vec![crate::config::LoraAdapter {
                name: "coder".into(),
                source: "hf:org/coder".into(),
            }],
        );
        let f = serving_flags(EngineKind::Vllm, &e);
        let i = f.iter().position(|a| a == "--served-model-name").unwrap();
        assert_eq!(f[i + 1], "qwen3-8b");
        assert_eq!(f[i + 2], "coder");
    }

    #[test]
    fn serving_flags_lora_static_preloads_dynamic_pages() {
        // WOR-1673: static (max_loras unset) preloads via --lora-modules;
        // dynamic (max_loras below count) sets the cap and omits preload.
        let loras = vec![
            crate::config::LoraAdapter {
                name: "a".into(),
                source: "hf:o/a".into(),
            },
            crate::config::LoraAdapter {
                name: "b".into(),
                source: "hf:o/b".into(),
            },
        ];
        let mut stat = entry_with(None, None, loras.clone());
        let sf = serving_flags(EngineKind::Vllm, &stat);
        let mi = sf.iter().position(|a| a == "--max-loras").unwrap();
        assert_eq!(sf[mi + 1], "2");
        assert!(sf.iter().any(|a| a == "--lora-modules"));

        stat.max_loras = Some(1);
        let df = serving_flags(EngineKind::Vllm, &stat);
        let dmi = df.iter().position(|a| a == "--max-loras").unwrap();
        assert_eq!(df[dmi + 1], "1");
        assert!(
            !df.iter().any(|a| a == "--lora-modules"),
            "dynamic paging loads on demand, not via --lora-modules"
        );
    }

    #[test]
    fn serving_flags_kv_tiering() {
        // WOR-1687: swap_space / cpu_offload emit the CPU-tier flags.
        let mut e = entry_with(None, None, vec![]);
        e.swap_space_gib = Some(16);
        e.cpu_offload_gib = Some(8);
        let f = serving_flags(EngineKind::Vllm, &e);
        let s = f.iter().position(|a| a == "--swap-space").unwrap();
        assert_eq!(f[s + 1], "16");
        let c = f.iter().position(|a| a == "--cpu-offload-gb").unwrap();
        assert_eq!(f[c + 1], "8");
    }

    #[test]
    fn serving_flags_tool_call_parser() {
        // WOR-1668: setting a parser enables vLLM auto tool-choice.
        let mut e = entry_with(None, None, vec![]);
        e.tool_call_parser = Some("hermes".to_string());
        let f = serving_flags(EngineKind::Vllm, &e);
        assert!(f.iter().any(|a| a == "--enable-auto-tool-choice"));
        let i = f.iter().position(|a| a == "--tool-call-parser").unwrap();
        assert_eq!(f[i + 1], "hermes");
        // Absent by default.
        let none = entry_with(None, None, vec![]);
        assert!(!serving_flags(EngineKind::Vllm, &none)
            .iter()
            .any(|a| a == "--enable-auto-tool-choice"));
    }

    #[test]
    fn serving_flags_empty_for_llama_cpp() {
        use crate::config::{ChunkedPrefill, SpeculativeConfig};
        let e = entry_with(
            Some(SpeculativeConfig {
                method: crate::config::SpecMethod::Ngram,
                draft_model: None,
                num_speculative_tokens: 3,
            }),
            Some(ChunkedPrefill::default()),
            vec![],
        );
        // llama.cpp uses different surfaces; the vLLM-only knobs emit nothing.
        assert!(serving_flags(EngineKind::LlamaCpp, &e).is_empty());
    }

    #[test]
    fn speculation_load_gate() {
        // Below the threshold (memory-bound) speculation is on; a full
        // batch (compute-bound) turns it off.
        assert!(should_speculate(0.2, SPECULATE_OCCUPANCY_THRESHOLD));
        assert!(!should_speculate(0.9, SPECULATE_OCCUPANCY_THRESHOLD));
    }

    #[test]
    fn chunk_size_tracks_ttft_and_throughput() {
        // 10k tok/s prefill, 250ms SLO -> ~2500 token chunk.
        assert_eq!(chunk_size_for_ttft(250, 10_000.0), 2500);
        // A tiny SLO clamps to the floor.
        assert_eq!(chunk_size_for_ttft(1, 10_000.0), MIN_PREFILL_CHUNK);
    }

    // --- ProcessEngineLauncher against a fake process ---

    /// Bind a loopback listener that answers one HTTP GET with 200 on
    /// `/health`. Returns the port, or None if the sandbox denies the
    /// bind (in which case the caller skips, matching the classifier
    /// RPC test precedent).
    async fn fake_health_server() -> Option<(u16, tokio::task::JoinHandle<()>)> {
        use tokio::net::TcpListener;
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(_) => return None, // loopback bind denied; skip
        };
        let port = listener.local_addr().ok()?.port();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 256];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        });
        Some((port, handle))
    }

    #[tokio::test]
    async fn post_json_ok_on_200_and_err_on_no_server() {
        // WOR-1673: the raw-HTTP POST used for LoRA load/unload succeeds
        // against a 200 and errors (not panics) when nothing is bound.
        if let Some((port, handle)) = fake_health_server().await {
            let r = post_json(
                port,
                "/v1/load_lora_adapter",
                "{\"lora_name\":\"a\",\"lora_path\":\"o/a\"}",
                Duration::from_secs(5),
            )
            .await;
            assert!(r.is_ok(), "expected 200 to succeed: {r:?}");
            handle.abort();
        }
        // A port with nothing listening: a clean Err, no panic.
        let err = post_json(1, "/v1/load_lora_adapter", "{}", Duration::from_secs(1)).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn wait_for_ready_succeeds_against_a_live_endpoint() {
        let Some((port, handle)) = fake_health_server().await else {
            eprintln!("skipping: loopback bind denied in this environment");
            return;
        };
        let r = wait_for_ready(port, "/health", Duration::from_secs(3)).await;
        assert!(r.is_ok(), "should see 200: {r:?}");
        handle.abort();
    }

    #[tokio::test]
    async fn launch_fails_fast_when_engine_exits() {
        // A crashed engine must fail in well under the readiness
        // timeout: we detect the child exiting rather than polling a
        // dead port for the whole window (which, times the retry count,
        // could block a request for tens of minutes).
        let launcher = ProcessEngineLauncher::with_timeout(Duration::from_secs(60));
        let spec = LaunchSpec {
            engine: EngineKind::Vllm,
            program: "false".to_string(), // exits non-zero immediately
            args: vec!["--port".to_string(), "59997".to_string()],
            env: vec![],
            vram_bytes: 0,
        };
        let start = tokio::time::Instant::now();
        let r = launcher.launch(&spec).await;
        let elapsed = start.elapsed();
        assert!(r.is_err(), "a process that exits at once never gets ready");
        // The point of the fix: it did not wait out the 60s timeout.
        assert!(
            elapsed < Duration::from_secs(15),
            "launch failed fast, not after the readiness timeout ({elapsed:?})"
        );
    }

    #[test]
    fn last_lines_takes_the_tail() {
        assert_eq!(last_lines("a\nb\nc\nd", 2), "c\nd");
        assert_eq!(last_lines("only", 5), "only");
        assert_eq!(last_lines("\n\n  \n", 3), "");
    }

    #[tokio::test]
    async fn probe_health_true_when_live_false_when_dead() {
        let Some((port, handle)) = fake_health_server().await else {
            eprintln!("skipping: loopback bind denied");
            return;
        };
        assert!(probe_health(port, "/health").await, "live endpoint");
        handle.abort();
        // Nothing listening on port 1.
        assert!(!probe_health(1, "/health").await, "dead port");
    }

    #[tokio::test]
    async fn wait_for_ready_times_out_on_dead_port() {
        // A port nobody is listening on: must time out, not hang.
        let r = wait_for_ready(1, "/health", Duration::from_millis(300)).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn launcher_spawns_probes_and_kills() {
        // Use a portable long-lived process as the "engine" and a
        // separately-bound health endpoint as its readiness surface,
        // proving spawn + probe + kill without a real engine.
        let Some((port, handle)) = fake_health_server().await else {
            eprintln!("skipping: loopback bind denied in this environment");
            return;
        };
        // Spawn `sleep 30` as the child; if spawn is denied, skip.
        let launcher = ProcessEngineLauncher::with_timeout(Duration::from_secs(5));
        let spec = LaunchSpec {
            engine: EngineKind::Vllm,
            program: "sleep".to_string(),
            args: vec!["30".to_string(), "--port".to_string(), port.to_string()],
            env: vec![],
            vram_bytes: 0,
        };
        // launch() spawns `sleep` (ignoring its args) and probes the
        // health server on `port`.
        match launcher.launch(&spec).await {
            Ok(p) => {
                assert_eq!(p, port);
                // The child is tracked and killable.
                launcher.kill().await;
                assert!(launcher.child.lock().await.is_none());
            }
            Err(e) => {
                // Spawn may be denied by the sandbox; treat as skip.
                eprintln!("skipping: could not spawn child ({e})");
            }
        }
        handle.abort();
    }
}
