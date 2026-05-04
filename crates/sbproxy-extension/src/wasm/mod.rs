//! WASM runtime for sbproxy extensions.
//!
//! Sandboxed WebAssembly execution backed by [`wasmtime`] with the
//! [WASI preview-1] surface. Modules read their input on stdin and
//! write their output to stdout; nothing else is exposed by default.
//! That keeps the host-function ABI tiny (any wasm32-wasi binary just
//! works), avoids inventing a custom calling convention, and gives
//! module authors a familiar I/O model in Rust, TinyGo, AssemblyScript,
//! and any other language with a wasm32-wasi target.
//!
//! [WASI preview-1]: https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md
//!
//! ## Sandbox boundaries enforced here
//!
//! - **Memory.** `max_memory_pages` (each page is 64 KiB) caps the
//!   module's linear memory. Default 256 pages = 16 MiB, plenty for
//!   text transforms and far short of host-side memory pressure.
//! - **CPU time.** `timeout_ms` is enforced via wasmtime's
//!   epoch-interruption mechanism. A background thread bumps the
//!   engine's epoch once per millisecond; a module that runs past
//!   its deadline is aborted with `Trap`.
//! - **Filesystem.** No preopens. The module sees an empty FS.
//! - **Network.** Not exposed. `allowed_hosts` is reserved for a
//!   future WASI-sockets integration; today the field is parsed but
//!   the module cannot open sockets.
//!
//! ## Authoring guide
//!
//! See `docs/wasm-development.md` for the module-side contract,
//! Rust + TinyGo recipes, and known gotchas.

use anyhow::Result;
use serde::Deserialize;
use std::io::{self, Write};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use wasi_common::pipe::{ReadPipe, WritePipe};
use wasi_common::sync::WasiCtxBuilder;
use wasi_common::WasiCtx;
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Per-invocation cap on captured WASM stderr, in bytes.
const STDERR_CAPTURE_LIMIT: usize = 1024 * 1024;

/// `Write` adapter that buffers WASM-emitted stderr, emits each
/// completed line via `tracing::debug!`, and drops bytes past
/// `STDERR_CAPTURE_LIMIT` so a runaway module cannot exhaust host
/// memory or flood the host log pipeline.
#[derive(Default)]
struct StderrCapture {
    line_buf: Vec<u8>,
    written: usize,
    truncated: bool,
}

impl StderrCapture {
    fn flush_lines(&mut self) {
        while let Some(idx) = self.line_buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.line_buf.drain(..=idx).collect();
            let line = &line[..line.len() - 1];
            let line = String::from_utf8_lossy(line);
            tracing::debug!(target: "sbproxy::wasm::stderr", "{}", line);
        }
    }

    fn finish(&mut self) {
        if !self.line_buf.is_empty() {
            let line = std::mem::take(&mut self.line_buf);
            let line = String::from_utf8_lossy(&line);
            tracing::debug!(target: "sbproxy::wasm::stderr", "{}", line);
        }
        if self.truncated {
            tracing::debug!(
                target: "sbproxy::wasm::stderr",
                "WASM stderr truncated: module wrote past the {} byte per-call cap",
                STDERR_CAPTURE_LIMIT
            );
        }
    }
}

impl Write for StderrCapture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let reported = buf.len();
        let remaining = STDERR_CAPTURE_LIMIT.saturating_sub(self.written);
        if remaining == 0 {
            self.truncated = true;
            return Ok(reported);
        }
        let take = remaining.min(buf.len());
        self.line_buf.extend_from_slice(&buf[..take]);
        self.written += take;
        if take < buf.len() {
            self.truncated = true;
        }
        self.flush_lines();
        Ok(reported)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Configuration for a WASM extension module.
#[derive(Debug, Clone, Deserialize)]
pub struct WasmConfig {
    /// Filesystem path to a `.wasm` module.
    pub module_path: Option<String>,
    /// Raw bytes of a compiled WASM module (e.g. loaded from a config store).
    pub module_bytes: Option<Vec<u8>>,
    /// Hostnames the module would be permitted to contact via WASI
    /// networking. Reserved for future use; currently unused because
    /// WASI sockets are not wired in.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Upper bound on linear memory, in 64 KiB pages. Defaults to 256
    /// (16 MiB) when unset; the module aborts with a memory-exhausted
    /// trap on any allocation past this bound.
    #[serde(default)]
    pub max_memory_pages: Option<u32>,
    /// Maximum wall-clock execution time, in milliseconds. Defaults
    /// to 1000 ms when unset; the module aborts with an epoch-
    /// interruption trap when the deadline is hit.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl WasmConfig {
    fn max_pages(&self) -> u32 {
        self.max_memory_pages.unwrap_or(256)
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(1000))
    }
}

/// Per-store data the host shares with the running module.
struct HostState {
    wasi: WasiCtx,
    limits: StoreLimits,
}

/// Sandboxed WASM execution engine.
///
/// One `WasmRuntime` is created per configured module. The wasmtime
/// `Engine` and the compiled `Module` are cached on the runtime, so
/// per-call cost is one fresh `Store` + one `instantiate` + one
/// `_start` invocation.
pub struct WasmRuntime {
    config: WasmConfig,
    engine: Engine,
    module: Option<Module>,
}

impl std::fmt::Debug for WasmRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmRuntime")
            .field("module_loaded", &self.module.is_some())
            .field("max_memory_pages", &self.config.max_pages())
            .field("timeout_ms", &self.config.timeout().as_millis())
            .finish()
    }
}

impl WasmRuntime {
    /// Create a new runtime from the given configuration.
    ///
    /// When the config carries either `module_path` or `module_bytes`,
    /// the module is loaded and compiled eagerly. When neither is set,
    /// the runtime is constructed but every `execute` call returns an
    /// error so callers can surface the missing-module condition
    /// without having to special-case it themselves.
    pub fn new(config: WasmConfig) -> Result<Self> {
        let engine = build_engine()?;

        // wasmtime's own `Error` type does not implement `std::error::Error`,
        // so anyhow's `.context` adapter cannot attach. Format the wasmtime
        // error and rebuild via `anyhow::anyhow!` to keep messages chainable
        // through the rest of the proxy's error stack.
        let module = if let Some(bytes) = config.module_bytes.as_ref() {
            Some(
                Module::from_binary(&engine, bytes)
                    .map_err(|e| anyhow::anyhow!("compiling WASM bytes: {e:?}"))?,
            )
        } else if let Some(path) = config.module_path.as_ref() {
            Some(
                Module::from_file(&engine, path)
                    .map_err(|e| anyhow::anyhow!("loading WASM from {path}: {e:?}"))?,
            )
        } else {
            None
        };

        Ok(Self {
            config,
            engine,
            module,
        })
    }

    /// Returns `true` when a module has been loaded.
    pub fn is_available(&self) -> bool {
        self.module.is_some()
    }

    /// Invoke the module's `_start` function, passing `input` on stdin
    /// and returning whatever the module wrote to stdout.
    ///
    /// The `_function` argument is ignored for the WASI ABI; it is
    /// retained for source compatibility with the previous stub. A
    /// future ABI variant may dispatch on function names.
    pub fn execute(&self, _function: &str, input: &[u8]) -> Result<Vec<u8>> {
        let module = self
            .module
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("WASM runtime has no module loaded"))?;

        // Per-invocation stdin and stdout pipes.
        let stdin = ReadPipe::from(input.to_vec());
        let stdout = WritePipe::new_in_memory();

        // Per-invocation stderr capture (M3): module-emitted stderr is
        // routed to `tracing::debug!` and bounded to STDERR_CAPTURE_LIMIT
        // bytes so a misbehaving module cannot DoS the host or forge log
        // entries on the host's stderr stream.
        let stderr: WritePipe<StderrCapture> = WritePipe::new(StderrCapture::default());

        let wasi = WasiCtxBuilder::new()
            .stdin(Box::new(stdin))
            .stdout(Box::new(stdout.clone()))
            .stderr(Box::new(stderr.clone()))
            .build();

        let limits = StoreLimitsBuilder::new()
            .memory_size((self.config.max_pages() as usize).saturating_mul(64 * 1024))
            .instances(1)
            .tables(8)
            .build();

        let mut store: Store<HostState> = Store::new(&self.engine, HostState { wasi, limits });
        store.limiter(|s| &mut s.limits);

        // Epoch-based deadline. We bump the global ticker once per
        // millisecond; a module that does not yield within
        // `timeout_ms` ticks is interrupted on the next instruction
        // boundary.
        let deadline_ticks = self.config.timeout().as_millis().max(1) as u64;
        store.set_epoch_deadline(deadline_ticks);

        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        wasi_common::sync::add_to_linker(&mut linker, |s: &mut HostState| &mut s.wasi)
            .map_err(|e| anyhow::anyhow!("registering WASI imports: {e:?}"))?;

        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| anyhow::anyhow!("instantiating WASM module: {e:?}"))?;

        // WASI modules expose `_start` as the conventional entry
        // point. Modules that export a different entry have to be
        // wrapped, but every wasm32-wasi binary built by Rust or
        // TinyGo emits `_start` automatically.
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| anyhow::anyhow!("module is missing the WASI `_start` export: {e:?}"))?;

        start
            .call(&mut store, ())
            .map_err(|e| anyhow::anyhow!("WASM execution failed: {e:?}"))?;

        // Drop the store so the WritePipe handle's reference count
        // drops to one and we can take its inner buffer.
        drop(store);

        // Drain any trailing partial line and emit a truncation marker
        // if the module exceeded the per-call cap.
        if let Ok(mut capture) = stderr.try_into_inner() {
            capture.finish();
        }

        let buf = stdout
            .try_into_inner()
            .map_err(|_| anyhow::anyhow!("stdout pipe still has live references"))?
            .into_inner();
        Ok(buf)
    }
}

/// Build the JSON input passed to a WASM module's stdin for an HTTP
/// request transform (G1.4). Mirrors the Lua / JS `request` table
/// shape and includes the agent-class fields under `request.agent_*`
/// so wasm32-wasi modules can read the resolved agent identity from
/// `request.agent_id`, `request.agent_class`, `request.agent_vendor`,
/// etc., on stdin.
///
/// Modules consume the bytes off stdin, parse as JSON, branch on
/// agent fields if needed, and write the transformed JSON to stdout.
///
/// The function is intentionally narrow: it builds the JSON shape
/// that the OSS proxy passes today. Callers who need a different
/// shape can construct it directly and call [`WasmRuntime::execute`].
// Argument count exceeds the 7-arg clippy lint by two; each agent_*
// field is a flat optional drawn from RequestContext and bundling
// them into a struct adds an indirection layer with no readability
// gain at this single call site. Refactor if a third caller appears.
#[allow(clippy::too_many_arguments)]
pub fn build_request_input_with_agent_class(
    method: &str,
    path: &str,
    headers: &std::collections::HashMap<String, String>,
    body: Option<&str>,
    agent_id: Option<&str>,
    agent_vendor: Option<&str>,
    agent_purpose: Option<&str>,
    agent_id_source: Option<&str>,
    agent_rdns_hostname: Option<&str>,
) -> Vec<u8> {
    let mut req = serde_json::Map::new();
    req.insert(
        "method".to_string(),
        serde_json::Value::String(method.to_string()),
    );
    req.insert(
        "path".to_string(),
        serde_json::Value::String(path.to_string()),
    );
    req.insert("headers".to_string(), serde_json::json!(headers));
    if let Some(b) = body {
        req.insert("body".to_string(), serde_json::Value::String(b.to_string()));
    }
    let id = agent_id.unwrap_or("");
    req.insert(
        "agent_id".to_string(),
        serde_json::Value::String(id.to_string()),
    );
    req.insert(
        "agent_class".to_string(),
        serde_json::Value::String(id.to_string()),
    );
    req.insert(
        "agent_vendor".to_string(),
        serde_json::Value::String(agent_vendor.unwrap_or("").to_string()),
    );
    req.insert(
        "agent_purpose".to_string(),
        serde_json::Value::String(agent_purpose.unwrap_or("").to_string()),
    );
    req.insert(
        "agent_id_source".to_string(),
        serde_json::Value::String(agent_id_source.unwrap_or("").to_string()),
    );
    req.insert(
        "agent_rdns_hostname".to_string(),
        serde_json::Value::String(agent_rdns_hostname.unwrap_or("").to_string()),
    );
    let value = serde_json::Value::Object(req);
    serde_json::to_vec(&value).expect("serde_json::to_vec on built map cannot fail")
}

/// Build (or look up) the global wasmtime `Engine`.
///
/// One process-wide engine is fine because every module compiled
/// against it shares the same compilation cache; per-store state is
/// what isolates calls. Returning a fresh `Engine` per `WasmRuntime`
/// would burn cold-start cycles for no benefit.
///
/// `OnceLock::get_or_init` is used with `.expect` because Engine
/// creation only fails if the host's wasmtime configuration itself
/// is broken (e.g. unsupported architecture). That is a startup-time
/// invariant, not a runtime condition.
fn build_engine() -> Result<Engine> {
    static ENGINE: OnceLock<Arc<Engine>> = OnceLock::new();
    let engine = ENGINE.get_or_init(|| {
        let mut config = Config::new();
        config.epoch_interruption(true);
        config.consume_fuel(false);
        let engine = Engine::new(&config).expect("creating wasmtime engine");
        let engine = Arc::new(engine);

        // Background thread bumps the epoch once per millisecond so
        // `set_epoch_deadline(N)` enforces an N-millisecond budget.
        // The thread runs for the lifetime of the process; there is
        // no clean shutdown signal because the engine itself is a
        // singleton.
        let ticker = engine.clone();
        std::thread::Builder::new()
            .name("sbproxy-wasm-epoch".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(1));
                ticker.increment_epoch();
            })
            .expect("spawning wasm epoch ticker");

        engine
    });
    Ok((**engine).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal WASI module that copies stdin to stdout.
    ///
    /// Built once with `cargo build --release --target wasm32-wasi`
    /// from `examples/wasm/echo-rust/`; the resulting `.wasm` is
    /// embedded so unit tests do not need a wasm32-wasi toolchain.
    const ECHO_WASM: &[u8] = include_bytes!("testdata/echo.wasm");

    fn config_with(bytes: &[u8]) -> WasmConfig {
        WasmConfig {
            module_path: None,
            module_bytes: Some(bytes.to_vec()),
            allowed_hosts: vec![],
            max_memory_pages: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn config_deserializes() {
        let json = r#"{
            "module_path": "/opt/wasm/transform.wasm",
            "allowed_hosts": ["api.example.com"],
            "max_memory_pages": 256,
            "timeout_ms": 5000
        }"#;
        let config: WasmConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.module_path.as_deref(),
            Some("/opt/wasm/transform.wasm")
        );
        assert_eq!(config.allowed_hosts, vec!["api.example.com"]);
        assert_eq!(config.max_memory_pages, Some(256));
        assert_eq!(config.timeout_ms, Some(5000));
    }

    #[test]
    fn runtime_without_module_reports_unavailable() {
        let runtime = WasmRuntime::new(WasmConfig {
            module_path: None,
            module_bytes: None,
            allowed_hosts: vec![],
            max_memory_pages: None,
            timeout_ms: None,
        })
        .unwrap();
        assert!(!runtime.is_available());

        // Calling execute without a module yields a clean error rather
        // than a panic.
        let err = runtime.execute("transform", b"input").unwrap_err();
        assert!(format!("{err}").contains("no module loaded"));
    }

    #[test]
    fn echo_module_round_trips_stdin_to_stdout() {
        let runtime = WasmRuntime::new(config_with(ECHO_WASM)).expect("compile echo module");
        assert!(runtime.is_available());

        let input = b"hello, sbproxy wasm";
        let output = runtime.execute("transform", input).expect("execute");
        assert_eq!(output, input, "echo module must round-trip stdin -> stdout");
    }

    #[test]
    fn echo_module_handles_empty_input() {
        let runtime = WasmRuntime::new(config_with(ECHO_WASM)).expect("compile echo module");
        let output = runtime.execute("transform", b"").expect("execute");
        assert!(output.is_empty(), "empty input must produce empty output");
    }

    #[test]
    fn invalid_wasm_fails_to_compile() {
        let bad_bytes = b"this is not a wasm module";
        let err = WasmRuntime::new(config_with(bad_bytes)).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("compiling WASM bytes"),
            "expected compile context in error, got: {msg}"
        );
    }

    #[test]
    fn stderr_capture_truncates_at_limit() {
        // M3 regression: a runaway module writing 10 MiB to stderr must
        // be capped at STDERR_CAPTURE_LIMIT bytes so the host's memory
        // and log pipeline are unaffected. We exercise the captor
        // directly because the WAT echo fixture does not write to
        // stderr; the captor is what bounds host impact regardless of
        // the module producing it.
        let mut capture = StderrCapture::default();
        let chunk = vec![b'x'; 64 * 1024];
        let written_chunks = (10 * 1024 * 1024) / chunk.len();
        for _ in 0..written_chunks {
            // Returned `n` must always equal the input length so the
            // module believes its writes succeeded; otherwise WASI
            // surfaces a write error and the trap escapes to the host.
            let n = capture.write(&chunk).unwrap();
            assert_eq!(n, chunk.len());
        }
        assert!(
            capture.truncated,
            "10 MiB write must trip the truncation flag"
        );
        assert!(
            capture.written <= STDERR_CAPTURE_LIMIT,
            "captured bytes {} exceeded cap {}",
            capture.written,
            STDERR_CAPTURE_LIMIT
        );
        capture.finish();
    }

    #[test]
    fn stderr_capture_emits_lines() {
        let mut capture = StderrCapture::default();
        capture
            .write_all(b"first line\nsecond line\npartial")
            .unwrap();
        // Two complete lines have been flushed; the trailing fragment
        // is buffered until finish() is called.
        assert!(!capture.truncated);
        assert_eq!(capture.line_buf, b"partial");
        capture.finish();
    }

    // --- Agent-class input builder (G1.4) tests ---

    #[test]
    fn build_request_input_with_agent_class_sets_keys() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("user-agent".to_string(), "GPTBot/1.0".to_string());
        let bytes = build_request_input_with_agent_class(
            "POST",
            "/api/data",
            &headers,
            Some(r#"{"hello":"world"}"#),
            Some("openai-gptbot"),
            Some("OpenAI"),
            Some("training"),
            Some("user_agent"),
            None,
        );
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["method"], "POST");
        assert_eq!(v["agent_id"], "openai-gptbot");
        assert_eq!(v["agent_class"], "openai-gptbot");
        assert_eq!(v["agent_vendor"], "OpenAI");
        assert_eq!(v["agent_purpose"], "training");
        assert_eq!(v["agent_id_source"], "user_agent");
        // Unset rDNS becomes empty string.
        assert_eq!(v["agent_rdns_hostname"], "");
    }

    #[test]
    fn build_request_input_defaults_agent_to_empty_strings() {
        let headers = std::collections::HashMap::new();
        let bytes = build_request_input_with_agent_class(
            "GET", "/", &headers, None, None, None, None, None, None,
        );
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["agent_id"], "");
        assert_eq!(v["agent_class"], "");
        assert_eq!(v["agent_vendor"], "");
    }
}
