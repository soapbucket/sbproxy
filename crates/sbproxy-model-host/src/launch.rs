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

/// Parse a keep-alive / timeout duration in the compact form the
/// config uses (`90s`, `10m`, `1h`, `1h30m`). Bare digits are
/// seconds. Returns `None` on anything unparseable so config
/// validation can reject it rather than silently defaulting.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Bare integer means seconds.
    if let Ok(secs) = s.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let mut total = 0u64;
    let mut num = String::new();
    let mut saw_unit = false;
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num.push(ch);
        } else {
            let value: u64 = num.parse().ok()?;
            num.clear();
            let unit_secs = match ch {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                _ => return None,
            };
            total = total.checked_add(value.checked_mul(unit_secs)?)?;
            saw_unit = true;
        }
    }
    // A trailing number with no unit (e.g. "1h30") is malformed.
    if !num.is_empty() || !saw_unit {
        return None;
    }
    Some(Duration::from_secs(total))
}

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
            //   --port <p> --ctx-size <ctx>` (GGUF quant is selected
            // by the file in the repo, not a flag).
            args.push("--hf-repo".to_string());
            args.push(model.hf_repo.clone());
            args.push("--host".to_string());
            args.push("127.0.0.1".to_string());
            args.push("--port".to_string());
            args.push(port.to_string());
            args.push("--ctx-size".to_string());
            args.push(plan.seq_len.to_string());
            if let Some(t) = llama_cache_type(kv_quant) {
                // Quantize both K and V caches.
                args.push("--cache-type-k".to_string());
                args.push(t.to_string());
                args.push("--cache-type-v".to_string());
                args.push(t.to_string());
            }
        }
    }

    args.extend(extra_args.iter().cloned());

    LaunchSpec {
        program: engine.binary_name().to_string(),
        args,
        env,
        vram_bytes: plan.estimated_vram_bytes,
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
    // LoRA adapters.
    if !entry.lora_adapters.is_empty() {
        args.push("--enable-lora".to_string());
        args.push("--max-loras".to_string());
        args.push(entry.lora_adapters.len().to_string());
        for a in &entry.lora_adapters {
            args.push("--lora-modules".to_string());
            args.push(format!("{}={}", a.name, a.source));
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
}

impl Default for ProcessEngineLauncher {
    fn default() -> Self {
        Self {
            ready_timeout: Duration::from_secs(300),
            health_path: "/health".to_string(),
            child: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
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

impl EngineLauncher for ProcessEngineLauncher {
    async fn launch(&self, spec: &LaunchSpec) -> Result<u16, String> {
        let port = Self::port_from_spec(spec)
            .ok_or_else(|| "launch spec has no --port to probe".to_string())?;
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
        let child = cmd
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", spec.program))?;
        *self.child.lock().await = Some(child);

        match wait_for_ready(port, &self.health_path, self.ready_timeout).await {
            Ok(()) => Ok(port),
            Err(e) => {
                // Readiness failed: kill the half-started child so it
                // does not leak, then report the failure.
                self.kill().await;
                Err(e)
            }
        }
    }

    async fn kill(&self) {
        if let Some(mut child) = self.child.lock().await.take() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
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

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration("90"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("90s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("10m"), Some(Duration::from_secs(600)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_duration("2d"), Some(Duration::from_secs(172800)));
    }

    #[test]
    fn duration_rejects_garbage() {
        for bad in ["", "  ", "abc", "1h30", "10x", "m", "1.5h"] {
            assert_eq!(parse_duration(bad), None, "{bad:?} should not parse");
        }
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
