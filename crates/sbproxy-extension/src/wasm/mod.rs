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
//! - **Network.** Not exposed, and there is no key that pretends
//!   otherwise. A module gets no sockets: no WASI networking, no host
//!   callout function. The `allowed_hosts` field this config used to
//!   carry was parsed and never enforced, so the `wasm` transform now
//!   refuses it at config compile rather than accept an allowlist over
//!   a boundary that does not exist (WOR-2319). It comes back as an
//!   enforced key the day a host callout lands.
//!
//! ## Authoring guide
//!
//! See `docs/wasm-development.md` for the module-side contract,
//! Rust + TinyGo recipes, and known gotchas.

use anyhow::Result;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use wasi_common::pipe::{ReadPipe, WritePipe};
use wasi_common::sync::WasiCtxBuilder;
use wasi_common::WasiCtx;
use wasmtime::{
    Config, Engine, ExternType, InstancePre, Linker, Module, ResourceLimiter, Store, StoreLimits,
    StoreLimitsBuilder, Trap,
};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::p2::{OutputStream, Pollable, StreamError};

/// Prefix of the export a module uses to declare its envelope ABI.
///
/// The major version is encoded in the export **name**, so
/// `sbproxy_envelope_abi_v1` declares major 1.
const ENVELOPE_ABI_EXPORT_PREFIX: &str = "sbproxy_envelope_abi_v";

/// The export name this host serves.
const ENVELOPE_ABI_EXPORT: &str = "sbproxy_envelope_abi_v1";

/// Whether a module declares an envelope ABI at all, and whether the one
/// it declares is the one this host serves.
///
/// Returns `(declares_any, declares_ours)`.
///
/// **Why the version is in the name rather than in an i32 global.** OPA
/// exports `opa_wasm_abi_version` as a global, and that is the shape
/// WOR-2364 item 4 pointed at. It is not available to us: wasmtime does
/// not expose a global's initializer through `Module`, so reading the
/// value would require instantiating, and
/// `envelope_wasm_load_validation_does_not_execute_the_core_start` pins
/// that load validation must not instantiate. A module whose core
/// `start` section traps has to load cleanly and fail at call time.
///
/// Encoding the version in the export name keeps the property that
/// mattered, that the claim lives in the artifact rather than in the
/// manifest beside it, and it stays readable by `wasm-objdump` before
/// instantiation, which was OPA's actual goal.
fn module_abi_declaration(module: &Module) -> (bool, bool) {
    let mut declares_any = false;
    let mut declares_ours = false;
    for export in module.exports() {
        if export.name().starts_with(ENVELOPE_ABI_EXPORT_PREFIX) {
            declares_any = true;
            if export.name() == ENVELOPE_ABI_EXPORT {
                declares_ours = true;
            }
        }
    }
    (declares_any, declares_ours)
}

/// Per-invocation cap on captured WASM stderr, in bytes.
const STDERR_CAPTURE_LIMIT: usize = 1024 * 1024;

/// Identity a captured guest diagnostic line is attributed to.
///
/// One `WasmRuntime` is shared by every hook in a bundle, so the
/// identity travels with the call rather than with the runtime.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WasmGuestIdentity<'a> {
    /// Bundle the module was loaded from.
    pub(crate) bundle: &'a str,
    /// Hook kind label (`policy`, `transform`, `action`, ...).
    pub(crate) hook_kind: &'a str,
    /// Operator-facing `type:` string the hook is attached as.
    pub(crate) type_name: &'a str,
}

/// Bounded, non-trapping stderr sink for the envelope bundle path.
///
/// WOR-2364 §1: the envelope path used to hand the guest a
/// `SinkOutputStream`, so a WASM policy that refused a request could
/// not tell the operator why and every guest failure looked identical
/// from outside. OPA's WASM ABI makes a diagnostic channel a *required*
/// host import for exactly this reason.
///
/// `MemoryOutputPipe` is the obvious off-the-shelf choice and is the
/// wrong one: it returns `StreamError::Trap` past its capacity, so a
/// chatty guest would be killed by its own logging. This caps, marks
/// the truncation, and drops the overflow rather than failing the call.
///
/// It serves **both** module ABIs. `wasi_common`'s `WritePipe` wants a
/// `std::io::Write` and the WASIp2 path wants an `OutputStream`;
/// interior mutability satisfies both, so the legacy `type: wasm`
/// transform and the config-loaded bundle get the same cap, the same
/// truncation marker, and the same failed-means-warn rule instead of
/// two near-identical captors that drifted apart.
#[derive(Debug, Clone)]
struct BoundedStderrPipe {
    buffer: Arc<Mutex<BoundedStderrBuffer>>,
}

#[derive(Debug, Default)]
struct BoundedStderrBuffer {
    bytes: Vec<u8>,
    truncated: bool,
}

impl BoundedStderrPipe {
    fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(BoundedStderrBuffer::default())),
        }
    }

    /// Append what fits under the cap and mark the rest as dropped.
    /// Never fails: overflow is discarded rather than reported, so the
    /// guest is never punished for writing diagnostics.
    fn append(&self, bytes: &[u8]) {
        let mut guard = self
            .buffer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let remaining = STDERR_CAPTURE_LIMIT.saturating_sub(guard.bytes.len());
        if remaining < bytes.len() {
            guard.truncated = true;
        }
        let take = remaining.min(bytes.len());
        guard.bytes.extend_from_slice(&bytes[..take]);
    }

    /// Emit every captured line under the hook's identity and return
    /// how many lines were emitted.
    ///
    /// `failed` selects the level, and it is the whole reason this is
    /// useful in production. The workspace enables
    /// `tracing/release_max_level_info`, which compile-strips `debug!`
    /// out of release builds, so a capture that only ever emitted at
    /// debug would be a no-op in the binary operators actually run:
    /// they would set `--log-level debug`, get nothing, and be exactly
    /// where they started. A guest that failed is precisely when its
    /// diagnostics are worth a line, so those go out at `warn` and
    /// survive; a healthy guest's chatter stays at `debug`, where it
    /// costs nothing in release.
    fn drain_to_log(&self, identity: WasmGuestIdentity<'_>, failed: bool) -> usize {
        let mut guard = self
            .buffer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let truncated = guard.truncated;
        let bytes = std::mem::take(&mut guard.bytes);
        guard.truncated = false;
        drop(guard);

        let mut lines = 0;
        for line in bytes.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            lines += 1;
            let line = String::from_utf8_lossy(line);
            if failed {
                tracing::warn!(
                    target: "sbproxy::wasm::stderr",
                    bundle = identity.bundle,
                    hook_kind = identity.hook_kind,
                    type_name = identity.type_name,
                    "{line}",
                );
            } else {
                tracing::debug!(
                    target: "sbproxy::wasm::stderr",
                    bundle = identity.bundle,
                    hook_kind = identity.hook_kind,
                    type_name = identity.type_name,
                    "{line}",
                );
            }
        }
        if truncated {
            // Same level as the lines themselves. A warn stream that
            // ends mid-thought with the "and there was more" marker
            // compiled out gives the operator no reason to suspect a
            // cap.
            if failed {
                tracing::warn!(
                    target: "sbproxy::wasm::stderr",
                    bundle = identity.bundle,
                    hook_kind = identity.hook_kind,
                    type_name = identity.type_name,
                    "WASM stderr truncated: guest wrote past the {} byte per-call cap",
                    STDERR_CAPTURE_LIMIT,
                );
            } else {
                tracing::debug!(
                    target: "sbproxy::wasm::stderr",
                    bundle = identity.bundle,
                    hook_kind = identity.hook_kind,
                    type_name = identity.type_name,
                    "WASM stderr truncated: guest wrote past the {} byte per-call cap",
                    STDERR_CAPTURE_LIMIT,
                );
            }
        }
        lines
    }
}

impl Write for BoundedStderrPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.append(buf);
        // Report the full length. The bytes past the cap are dropped on
        // purpose, and a short write would make the guest retry them.
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl OutputStream for BoundedStderrPipe {
    fn write(&mut self, bytes: bytes::Bytes) -> Result<(), StreamError> {
        // Always `Ok`: dropping the overflow is the point. Returning an
        // error here would trap the guest for logging too much, which
        // is how `MemoryOutputPipe` behaves and why it is not used.
        self.append(&bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StreamError> {
        Ok(())
    }

    fn check_write(&mut self) -> Result<usize, StreamError> {
        // Never report closed. A full buffer still accepts and discards
        // writes, so the guest never sees back pressure from a channel
        // that exists only for the host's benefit.
        Ok(usize::MAX)
    }
}

#[async_trait::async_trait]
impl Pollable for BoundedStderrPipe {
    async fn ready(&mut self) {}
}

impl tokio::io::AsyncWrite for BoundedStderrPipe {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        self.append(buf);
        // Report the full length as written. The bytes past the cap are
        // deliberately dropped, and a short write would make the guest
        // retry them forever.
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl wasmtime_wasi::cli::IsTerminal for BoundedStderrPipe {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl wasmtime_wasi::cli::StdoutStream for BoundedStderrPipe {
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(self.clone())
    }

    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }
}

/// Configuration for a WASM extension module.
#[derive(Debug, Clone, Deserialize)]
pub struct WasmConfig {
    /// Filesystem path to a `.wasm` module.
    pub module_path: Option<String>,
    /// Raw bytes of a compiled WASM module (e.g. loaded from a config store).
    pub module_bytes: Option<Vec<u8>>,
    /// Optional lowercase SHA-256 assertion for the selected module bytes.
    #[serde(default)]
    pub sha256: Option<String>,
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
    /// Maximum fuel (roughly, wasm instructions) a single invocation
    /// may consume. Defaults to 1,000,000,000 when unset; the module
    /// aborts with an out-of-fuel trap once the budget is exhausted.
    ///
    /// Fuel is a deterministic, instruction-granular complement to the
    /// wall-clock `timeout_ms` epoch deadline (which is only accurate
    /// to the 1 ms epoch tick). The default is generous enough that a
    /// well-behaved request-path script never hits it; lower it to put
    /// a hard ceiling on per-call CPU.
    #[serde(default)]
    pub max_fuel: Option<u64>,
}

impl WasmConfig {
    fn max_pages(&self) -> u32 {
        self.max_memory_pages.unwrap_or(256)
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(1000))
    }

    /// Per-invocation fuel budget. See [`WasmConfig::max_fuel`].
    fn fuel(&self) -> u64 {
        self.max_fuel.unwrap_or(1_000_000_000)
    }
}

/// Per-store data the host shares with the running module.
struct HostState {
    wasi: WasiCtx,
    limits: StoreLimits,
}

/// Resource limits for one envelope WASM bundle.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WasmBundleLimits {
    pub(crate) budget: Duration,
    pub(crate) memory_bytes: usize,
    pub(crate) stack_bytes: usize,
    pub(crate) fuel: u64,
    pub(crate) max_input_bytes: usize,
    pub(crate) max_output_bytes: usize,
}

/// Stable load-time failure for an envelope WASM bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WasmLoadFailure {
    InvalidModule,
    InvalidImports,
    InvalidStart,
    /// The module exports an ABI version this host does not serve.
    AbiMismatch,
    RuntimeUnavailable,
}

impl WasmLoadFailure {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidModule => "invalid_module",
            Self::InvalidImports => "invalid_imports",
            Self::InvalidStart => "invalid_start",
            Self::AbiMismatch => "abi_mismatch",
            Self::RuntimeUnavailable => "runtime_unavailable",
        }
    }
}

/// Stable per-call failure for an envelope WASM bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WasmCallFailure {
    InputLimit,
    Cancelled,
    Timeout,
    FuelLimit,
    MemoryLimit,
    TableLimit,
    StackLimit,
    OutputLimit,
    GuestTrap,
    HostFailure,
}

impl WasmCallFailure {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InputLimit => "input_limit",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::FuelLimit => "instruction_cap",
            Self::MemoryLimit => "memory_cap",
            Self::TableLimit => "table_cap",
            Self::StackLimit => "stack_cap",
            Self::OutputLimit => "output_limit",
            Self::GuestTrap => "guest_exception",
            Self::HostFailure => "runtime_unavailable",
        }
    }
}

#[derive(Debug)]
pub(crate) struct WasmExecutionControl {
    deadline: Instant,
    cancelled: AtomicBool,
}

impl WasmExecutionControl {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            cancelled: AtomicBool::new(false),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn stop_reason(&self) -> Option<WasmCallFailure> {
        if self.cancelled.load(Ordering::Acquire) {
            Some(WasmCallFailure::Cancelled)
        } else if Instant::now() >= self.deadline {
            Some(WasmCallFailure::Timeout)
        } else {
            None
        }
    }
}

struct TrackingLimits {
    inner: StoreLimits,
    memory_denied: bool,
    table_denied: bool,
}

impl ResourceLimiter for TrackingLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let result = self.inner.memory_growing(current, desired, maximum);
        if !matches!(result, Ok(true)) {
            self.memory_denied = true;
        }
        result
    }

    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.memory_denied = true;
        self.inner.memory_grow_failed(error)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let result = self.inner.table_growing(current, desired, maximum);
        if !matches!(result, Ok(true)) {
            self.table_denied = true;
        }
        result
    }

    fn table_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.table_denied = true;
        self.inner.table_grow_failed(error)
    }

    fn instances(&self) -> usize {
        self.inner.instances()
    }

    fn tables(&self) -> usize {
        self.inner.tables()
    }

    fn memories(&self) -> usize {
        self.inner.memories()
    }
}

struct EnvelopeHostState {
    wasi: WasiP1Ctx,
    limits: TrackingLimits,
}

/// Sandboxed WASM execution engine.
///
/// One `WasmRuntime` is created per configured module. The wasmtime
/// `Engine` and the compiled `Module` are cached on the runtime, so
/// per-call cost is one fresh `Store` + one `instantiate` + one
/// `_start` invocation.
pub struct WasmRuntime {
    config: WasmConfig,
    engine: Arc<Engine>,
    module: Option<Module>,
    bundle_instance_pre: Option<InstancePre<EnvelopeHostState>>,
    bundle_limits: Option<WasmBundleLimits>,
    last_retained_stdout_bytes: AtomicUsize,
    /// Lines of guest stderr emitted by the most recent envelope call.
    /// Read by tests so the diagnostic channel can be asserted without
    /// installing a tracing subscriber.
    last_guest_stderr_lines: AtomicUsize,
}

impl std::fmt::Debug for WasmRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmRuntime")
            .field("module_loaded", &self.module.is_some())
            .field("max_memory_pages", &self.config.max_pages())
            .field("timeout_ms", &self.config.timeout().as_millis())
            .field("envelope", &self.bundle_limits.is_some())
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
        validate_optional_sha256_syntax(config.sha256.as_deref())?;
        let engine = build_engine(None)?;

        // wasmtime's own `Error` type does not implement `std::error::Error`,
        // so anyhow's `.context` adapter cannot attach. Format the wasmtime
        // error and rebuild via `anyhow::anyhow!` to keep messages chainable
        // through the rest of the proxy's error stack.
        let selected = if let Some(bytes) = config.module_bytes.as_ref() {
            Some((bytes.clone(), None))
        } else if let Some(path) = config.module_path.as_ref() {
            let bytes = std::fs::read(path)
                .map_err(|error| anyhow::anyhow!("loading WASM from {path}: {error}"))?;
            Some((bytes, Some(path.as_str())))
        } else {
            None
        };
        let module = if let Some((bytes, path)) = selected {
            verify_optional_sha256(config.sha256.as_deref(), &bytes)?;
            match Module::from_binary(&engine, &bytes) {
                Ok(m) => {
                    sbproxy_observe::metrics::record_script_compile("wasm", "ok");
                    Some(m)
                }
                Err(e) => {
                    sbproxy_observe::metrics::record_script_compile("wasm", "parse_error");
                    return if let Some(path) = path {
                        Err(anyhow::anyhow!("loading WASM from {path}: {e:?}"))
                    } else {
                        Err(anyhow::anyhow!("compiling WASM bytes: {e:?}"))
                    };
                }
            }
        } else {
            None
        };

        Ok(Self {
            config,
            engine,
            module,
            bundle_instance_pre: None,
            bundle_limits: None,
            last_guest_stderr_lines: AtomicUsize::new(0),
            last_retained_stdout_bytes: AtomicUsize::new(0),
        })
    }

    pub(crate) fn from_bundle_bytes(
        bytes: &[u8],
        limits: WasmBundleLimits,
    ) -> std::result::Result<Self, WasmLoadFailure> {
        let engine = build_engine(Some(limits.stack_bytes))
            .map_err(|_| WasmLoadFailure::RuntimeUnavailable)?;
        let module = match Module::from_binary(&engine, bytes) {
            Ok(module) => {
                sbproxy_observe::metrics::record_script_compile("wasm", "ok");
                module
            }
            Err(_) => {
                sbproxy_observe::metrics::record_script_compile("wasm", "parse_error");
                return Err(WasmLoadFailure::InvalidModule);
            }
        };
        let instance_pre = prepare_bundle_instance(&engine, &module)?;
        Ok(Self {
            config: WasmConfig {
                module_path: None,
                module_bytes: None,
                sha256: None,
                max_memory_pages: None,
                timeout_ms: None,
                max_fuel: None,
            },
            engine,
            module: Some(module),
            bundle_instance_pre: Some(instance_pre),
            bundle_limits: Some(limits),
            last_retained_stdout_bytes: AtomicUsize::new(0),
            last_guest_stderr_lines: AtomicUsize::new(0),
        })
    }

    /// Returns `true` when a module has been loaded.
    pub fn is_available(&self) -> bool {
        self.module.is_some()
    }

    pub(crate) fn bundle_budget(&self) -> Option<Duration> {
        self.bundle_limits.map(|limits| limits.budget)
    }

    /// Invoke the module's `_start` function, passing `input` on stdin
    /// and returning whatever the module wrote to stdout.
    ///
    /// The `_function` argument is ignored for the WASI ABI; it is
    /// retained for source compatibility with the previous stub. A
    /// future ABI variant may dispatch on function names.
    pub fn execute(&self, _function: &str, input: &[u8]) -> Result<Vec<u8>> {
        let start_ts = std::time::Instant::now();
        let out = self.execute_inner(input);
        let elapsed = start_ts.elapsed().as_secs_f64();
        sbproxy_observe::metrics::record_script_duration("wasm", elapsed);
        let label = match &out {
            Ok(_) => "ok",
            Err(e) => {
                let msg = format!("{e}");
                // Classify common wasmtime trap shapes so dashboards can
                // distinguish runaway scripts from genuine runtime errors.
                if msg.contains("epoch") || msg.contains("interrupt") {
                    "timeout"
                } else if msg.contains("fuel") {
                    "instruction_cap"
                } else if msg.contains("memory") {
                    "memory_cap"
                } else {
                    "runtime_error"
                }
            }
        };
        sbproxy_observe::metrics::record_script_invocation("wasm", label);
        out
    }

    fn execute_inner(&self, input: &[u8]) -> Result<Vec<u8>> {
        let module = self
            .module
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("WASM runtime has no module loaded"))?;

        // Per-invocation stdin and stdout pipes.
        let stdin = ReadPipe::from(input.to_vec());
        let stdout = WritePipe::new_in_memory();

        // Per-invocation stderr capture, bounded to
        // STDERR_CAPTURE_LIMIT bytes so a misbehaving module cannot DoS
        // the host or forge log entries on the host's stderr stream.
        // Same type the envelope bundle path uses, so both ABIs get the
        // same cap, the same truncation marker, and the same
        // failed-means-warn rule.
        let stderr_capture = BoundedStderrPipe::new();
        let stderr: WritePipe<BoundedStderrPipe> = WritePipe::new(stderr_capture.clone());

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

        // Fuel-based budget. The engine has `consume_fuel(true)`, so
        // the store must be given an explicit budget or the first instruction
        // traps. This bounds per-call CPU at instruction granularity,
        // independent of the 1 ms epoch tick.
        store
            .set_fuel(self.config.fuel())
            .map_err(|e| anyhow::anyhow!("setting WASM fuel budget: {e:?}"))?;

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

        let call_result = start.call(&mut store, ());

        // Drop the store so the WritePipe handle's reference count
        // drops to one and we can take its inner buffer.
        drop(store);

        // Drain before propagating. This used to sit after a `?` on the
        // call above, so a module that trapped, which is exactly the
        // module whose stderr explains the trap, lost its diagnostics
        // entirely: no trailing line, no truncation marker, nothing.
        let identity = WasmGuestIdentity {
            bundle: "",
            hook_kind: "transform",
            type_name: "wasm",
        };
        stderr_capture.drain_to_log(identity, call_result.is_err());
        call_result.map_err(|e| anyhow::anyhow!("WASM execution failed: {e:?}"))?;

        let buf = stdout
            .try_into_inner()
            .map_err(|_| anyhow::anyhow!("stdout pipe still has live references"))?
            .into_inner();
        Ok(buf)
    }

    #[cfg(test)]
    pub(crate) fn execute_bounded(
        &self,
        input: &[u8],
    ) -> std::result::Result<Vec<u8>, WasmCallFailure> {
        let deadline = Instant::now()
            .checked_add(
                self.bundle_limits
                    .map(|limits| limits.budget)
                    .ok_or(WasmCallFailure::HostFailure)?,
            )
            .ok_or(WasmCallFailure::HostFailure)?;
        self.execute_bounded_until(
            input,
            Arc::new(WasmExecutionControl::new(deadline)),
            WasmGuestIdentity {
                bundle: "test",
                hook_kind: "test",
                type_name: "test",
            },
        )
    }

    pub(crate) fn execute_bounded_until(
        &self,
        input: &[u8],
        execution: Arc<WasmExecutionControl>,
        identity: WasmGuestIdentity<'_>,
    ) -> std::result::Result<Vec<u8>, WasmCallFailure> {
        self.bundle_limits.ok_or(WasmCallFailure::HostFailure)?;
        self.execute_bounded_inner(input, execution, identity)
    }

    fn execute_bounded_inner(
        &self,
        input: &[u8],
        execution: Arc<WasmExecutionControl>,
        identity: WasmGuestIdentity<'_>,
    ) -> std::result::Result<Vec<u8>, WasmCallFailure> {
        if let Some(reason) = execution.stop_reason() {
            return Err(reason);
        }
        let limits = self.bundle_limits.ok_or(WasmCallFailure::HostFailure)?;
        if input.len() > limits.max_input_bytes {
            return Err(WasmCallFailure::InputLimit);
        }
        let instance_pre = self
            .bundle_instance_pre
            .as_ref()
            .ok_or(WasmCallFailure::HostFailure)?;
        let capacity = limits
            .max_output_bytes
            .checked_add(1)
            .ok_or(WasmCallFailure::HostFailure)?;
        let stdout = MemoryOutputPipe::new(capacity);
        // WOR-2364 §1: the bundle path is the extensibility story we
        // tell operators, and it was the one dropping guest
        // diagnostics while the internal module path kept them.
        let stderr = BoundedStderrPipe::new();
        let mut wasi_builder = wasmtime_wasi::WasiCtxBuilder::new();
        wasi_builder
            .stdin(MemoryInputPipe::new(input.to_vec()))
            .stdout(stdout.clone())
            .stderr(stderr.clone());
        let wasi = wasi_builder.build_p1();
        let limits_tracker = TrackingLimits {
            inner: envelope_store_limits(limits),
            memory_denied: false,
            table_denied: false,
        };
        let mut store = Store::new(
            &self.engine,
            EnvelopeHostState {
                wasi,
                limits: limits_tracker,
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(limits.fuel)
            .map_err(|_| WasmCallFailure::HostFailure)?;
        store.set_epoch_deadline(1);
        let callback_execution = Arc::clone(&execution);
        store.epoch_deadline_callback(move |_store| {
            Ok(match callback_execution.stop_reason() {
                Some(_) => wasmtime::UpdateDeadline::Interrupt,
                None => wasmtime::UpdateDeadline::Continue(1),
            })
        });

        let call_result = (|| -> wasmtime::Result<()> {
            let instance = instance_pre.instantiate(&mut store)?;
            let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
            start.call(&mut store, ())
        })();

        let memory_denied = store.data().limits.memory_denied;
        let table_denied = store.data().limits.table_denied;
        drop(store);
        // Resolve stdout before draining stderr, so the output-cap trip
        // is known while deciding the diagnostic level. A guest that
        // overran its output cap and exited cleanly is a failure the
        // caller sees as `output_limit`, and its stderr is the only
        // thing that explains what it was trying to emit.
        let output = stdout
            .try_into_inner()
            .ok_or(WasmCallFailure::HostFailure)?
            .freeze();
        self.last_retained_stdout_bytes
            .store(output.len(), Ordering::Relaxed);
        let output_too_large = output.len() > limits.max_output_bytes;

        // Drain before any of the limit checks below return early: a
        // guest that tripped a cap is exactly the one whose stderr
        // explains why, and a trap on the refusal path is the case
        // WOR-2364 opened this on.
        //
        // A clean `proc_exit(0)` surfaces as an `Err` carrying `I32Exit`
        // and is the normal way a WASI command returns, so it is not a
        // failure and its chatter stays at debug.
        let failed = memory_denied
            || table_denied
            || output_too_large
            || call_result
                .as_ref()
                .is_err_and(|error| !is_successful_exit(error));
        self.last_guest_stderr_lines
            .store(stderr.drain_to_log(identity, failed), Ordering::Relaxed);
        if output_too_large {
            return Err(WasmCallFailure::OutputLimit);
        }
        if memory_denied {
            return Err(WasmCallFailure::MemoryLimit);
        }
        if table_denied {
            return Err(WasmCallFailure::TableLimit);
        }

        match call_result {
            Ok(()) => Ok(output.to_vec()),
            Err(error) if is_successful_exit(&error) => Ok(output.to_vec()),
            Err(error) if matches!(error.downcast_ref::<Trap>(), Some(Trap::Interrupt)) => {
                Err(execution.stop_reason().unwrap_or(WasmCallFailure::Timeout))
            }
            Err(error) => Err(classify_call_error(&error)),
        }
    }

    #[cfg(test)]
    pub(crate) fn last_retained_stdout_bytes(&self) -> usize {
        self.last_retained_stdout_bytes.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn last_guest_stderr_lines(&self) -> usize {
        self.last_guest_stderr_lines.load(Ordering::Relaxed)
    }
}

fn prepare_bundle_instance(
    engine: &Engine,
    module: &Module,
) -> std::result::Result<InstancePre<EnvelopeHostState>, WasmLoadFailure> {
    // This allowlist is deliberately smaller than WASIp1. `fd_read` is backed
    // only by MemoryInputPipe, `fd_write` only by MemoryOutputPipe or the sink,
    // and `proc_exit` immediately raises I32Exit. None can wait on host I/O.
    // In particular, poll_oneoff and every filesystem or socket operation are
    // rejected before the module reaches an executor worker.
    //
    // This walk is also the manifest-vs-artifact capability check
    // (WOR-2364 item 2, via WOR-2424): manifest validation refuses any
    // capability declaration on a wasm-runtime bundle (the envelope ABI
    // carries no host imports), so for every loadable wasm bundle the
    // complete legal import set is exactly this list, and a module
    // importing anything else is refused here regardless of what its
    // manifest claims. When a wasm-grantable capability ships (an ABI
    // v2 host function), this check takes the declared set as input
    // rather than a constant.
    const NONBLOCKING_WASI_IMPORTS: &[&str] = &["fd_read", "fd_write", "proc_exit"];
    if module.imports().any(|import| {
        import.module() != "wasi_snapshot_preview1"
            || !NONBLOCKING_WASI_IMPORTS.contains(&import.name())
    }) {
        return Err(WasmLoadFailure::InvalidImports);
    }

    match module.get_export("_start") {
        Some(ExternType::Func(function))
            if function.params().len() == 0 && function.results().len() == 0 => {}
        _ => return Err(WasmLoadFailure::InvalidStart),
    }

    // WOR-2364 item 4: trust the artifact over the file beside it.
    //
    // The manifest carries `abi: sbproxy-envelope/v1`, and a manifest
    // sits next to the module rather than inside it, so it can be wrong:
    // a module built against a future ABI with a hand-edited manifest
    // loads clean and fails at first call, with an error that does not
    // name the cause. OPA solved this by exporting the ABI version as an
    // i32 global that `wasm-objdump` can read before instantiation.
    //
    // Declaring it is optional, because every bundle in the field
    // predates this and refusing them would be a breaking change for a
    // check that is meant to catch a mistake rather than create one. A
    // module that *does* declare it is held to it.
    //
    // Major and minor are split the way OPA splits them: a minor bump is
    // backward compatible, so a module built for an older minor of the
    // same major still loads. That is what lets an envelope field be
    // added without invalidating existing bundles.
    let (declares_any_abi, declares_our_abi) = module_abi_declaration(module);
    if declares_any_abi && !declares_our_abi {
        return Err(WasmLoadFailure::AbiMismatch);
    }

    let mut linker = Linker::new(engine);
    wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |state: &mut EnvelopeHostState| {
        &mut state.wasi
    })
    .map_err(|_| WasmLoadFailure::RuntimeUnavailable)?;
    linker
        .instantiate_pre(module)
        .map_err(|_| WasmLoadFailure::InvalidImports)
}

fn envelope_store_limits(limits: WasmBundleLimits) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(limits.memory_bytes)
        .memories(1)
        .instances(1)
        .tables(8)
        .table_elements(10_000)
        .trap_on_grow_failure(true)
        .build()
}

fn is_successful_exit(error: &wasmtime::Error) -> bool {
    error
        .downcast_ref::<wasmtime_wasi::I32Exit>()
        .is_some_and(|exit| exit.0 == 0)
}

fn classify_call_error(error: &wasmtime::Error) -> WasmCallFailure {
    match error.downcast_ref::<Trap>() {
        Some(Trap::Interrupt) => WasmCallFailure::Timeout,
        Some(Trap::OutOfFuel) => WasmCallFailure::FuelLimit,
        Some(Trap::StackOverflow) => WasmCallFailure::StackLimit,
        Some(_) => WasmCallFailure::GuestTrap,
        None if error.downcast_ref::<wasmtime_wasi::I32Exit>().is_some() => {
            WasmCallFailure::GuestTrap
        }
        None => WasmCallFailure::HostFailure,
    }
}

fn validate_optional_sha256_syntax(digest: Option<&str>) -> Result<()> {
    if digest.is_some_and(|digest| {
        digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }) {
        return Err(anyhow::anyhow!(
            "WASM module sha256 must contain exactly 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn verify_optional_sha256(digest: Option<&str>, bytes: &[u8]) -> Result<()> {
    if let Some(expected) = digest {
        let actual = hex::encode(Sha256::digest(bytes));
        if actual != expected {
            return Err(anyhow::anyhow!(
                "WASM module sha256 does not match configured digest"
            ));
        }
    }
    Ok(())
}

/// A `principal` builder for WASM deliberately does not exist here.
///
/// The WASM transform contract is raw bytes on stdin, raw bytes on
/// stdout (see [`WasmRuntime::execute`] and the transform docs). There
/// is no JSON input envelope to splice a principal into, and inventing
/// one would break every deployed module that parses its body off
/// stdin. A `build_principal_input` wrapper shipped here for a while
/// with zero callers for exactly that reason; it was removed under the
/// half-wired-features cleanup rather than left implying a capability
/// the wire contract cannot carry. If an envelope-based WASM surface
/// ever ships, build its principal object from
/// [`crate::lua::bindings::build_principal_table`], which is what the
/// Lua and JS surfaces render from today.
/// Build the JSON input passed to a WASM module's stdin for an HTTP
/// request transform. Mirrors the Lua / JS `request` table
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
//
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
pub(crate) fn build_engine(stack_bytes: Option<usize>) -> Result<Arc<Engine>> {
    static ENGINES: LazyLock<Mutex<BTreeMap<Option<usize>, Weak<Engine>>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));
    let mut engines = ENGINES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(engine) = engines.get(&stack_bytes).and_then(Weak::upgrade) {
        return Ok(engine);
    }

    let mut config = Config::new();
    config.epoch_interruption(true);
    config.consume_fuel(true);
    if let Some(stack_bytes) = stack_bytes {
        config.max_wasm_stack(stack_bytes);
    }
    let engine = Arc::new(
        Engine::new(&config)
            .map_err(|error| anyhow::anyhow!("creating wasmtime engine: {error:?}"))?,
    );
    register_epoch_engine(&engine)?;
    engines.insert(stack_bytes, Arc::downgrade(&engine));
    Ok(engine)
}

fn register_epoch_engine(engine: &Arc<Engine>) -> Result<()> {
    static TICKED_ENGINES: OnceLock<Arc<Mutex<Vec<Weak<Engine>>>>> = OnceLock::new();
    let ticked_engines = if let Some(engines) = TICKED_ENGINES.get() {
        Arc::clone(engines)
    } else {
        let engines = Arc::new(Mutex::new(Vec::<Weak<Engine>>::new()));
        start_epoch_ticker(Arc::clone(&engines), |ticker_engines| {
            std::thread::Builder::new()
                .name("sbproxy-wasm-epoch".into())
                .spawn(move || run_epoch_ticker(ticker_engines))
                .map(|_| ())
        })
        .map_err(|_| anyhow::anyhow!("starting wasmtime epoch ticker"))?;
        TICKED_ENGINES
            .set(Arc::clone(&engines))
            .map_err(|_| anyhow::anyhow!("registering wasmtime epoch ticker"))?;
        engines
    };
    ticked_engines
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(Arc::downgrade(engine));
    Ok(())
}

fn start_epoch_ticker<F>(engines: Arc<Mutex<Vec<Weak<Engine>>>>, spawn: F) -> io::Result<()>
where
    F: FnOnce(Arc<Mutex<Vec<Weak<Engine>>>>) -> io::Result<()>,
{
    spawn(engines)
}

fn run_epoch_ticker(engines: Arc<Mutex<Vec<Weak<Engine>>>>) -> ! {
    loop {
        std::thread::sleep(Duration::from_millis(1));
        let mut engines = engines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        engines.retain(|engine| {
            if let Some(engine) = engine.upgrade() {
                engine.increment_epoch();
                true
            } else {
                false
            }
        });
    }
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
    const POLL_ONEOFF_WASM: &[u8] = include_bytes!("../bundle/testdata/wasm/poll-oneoff.wasm");
    const CORE_START_TRAP_WASM: &[u8] =
        include_bytes!("../bundle/testdata/wasm/core-start-trap.wasm");
    const BAD_START_SIGNATURE_WASM: &[u8] =
        include_bytes!("../bundle/testdata/wasm/bad-start-signature.wasm");
    const PROC_EXIT_ZERO_WASM: &[u8] =
        include_bytes!("../bundle/testdata/wasm/proc-exit-zero.wasm");
    const PROC_EXIT_NONZERO_WASM: &[u8] =
        include_bytes!("../bundle/testdata/wasm/proc-exit-nonzero.wasm");
    const SENTINEL_TRAP_WASM: &[u8] = include_bytes!("../bundle/testdata/wasm/sentinel-trap.wasm");

    fn envelope_limits() -> WasmBundleLimits {
        WasmBundleLimits {
            budget: Duration::from_millis(50),
            memory_bytes: 16 * 1024 * 1024,
            stack_bytes: 512 * 1024,
            fuel: 100_000_000,
            max_input_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
        }
    }

    fn config_with(bytes: &[u8]) -> WasmConfig {
        WasmConfig {
            module_path: None,
            module_bytes: Some(bytes.to_vec()),
            sha256: None,
            max_memory_pages: None,
            timeout_ms: None,
            max_fuel: None,
        }
    }

    #[test]
    fn config_fuel_defaults_and_overrides() {
        let mut c = config_with(ECHO_WASM);
        assert_eq!(c.fuel(), 1_000_000_000, "default fuel budget");
        c.max_fuel = Some(50_000);
        assert_eq!(c.fuel(), 50_000, "configured fuel budget");
    }

    #[test]
    fn exhausting_fuel_traps_execution() {
        // WOR-613: a tiny fuel budget must abort execution. The echo module
        // runs fine under the default budget (see echo_module_round_trips),
        // so a 1-unit budget can only fail by running out of fuel.
        let mut config = config_with(ECHO_WASM);
        config.max_fuel = Some(1);
        let runtime = WasmRuntime::new(config).expect("compile echo module");
        let err = runtime
            .execute("transform", b"hello")
            .expect_err("a 1-unit fuel budget must trap");
        let msg = format!("{err:?}").to_lowercase();
        assert!(
            msg.contains("fuel"),
            "expected out-of-fuel error, got: {msg}"
        );
    }

    #[test]
    fn config_deserializes() {
        let json = r#"{
            "module_path": "/opt/wasm/transform.wasm",
            "max_memory_pages": 256,
            "timeout_ms": 5000
        }"#;
        let config: WasmConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.module_path.as_deref(),
            Some("/opt/wasm/transform.wasm")
        );
        assert_eq!(config.max_memory_pages, Some(256));
        assert_eq!(config.timeout_ms, Some(5000));
    }

    /// WOR-2319: the field is gone from the shape. The transform layer
    /// is what refuses an authored key (see
    /// `sbproxy_modules::transform::WasmTransform::from_config`); this
    /// only pins that nothing here silently rehydrates it.
    #[test]
    fn config_no_longer_carries_a_host_allowlist() {
        let json = r#"{
            "module_path": "/opt/wasm/transform.wasm",
            "allowed_hosts": ["api.example.com"]
        }"#;
        let config: WasmConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.module_path.as_deref(),
            Some("/opt/wasm/transform.wasm")
        );
        // Nothing on the runtime config describes a network boundary,
        // because the runtime does not have one.
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("allowed_hosts"),
            "the runtime config must not carry a host allowlist: {rendered}"
        );
    }

    #[test]
    fn runtime_without_module_reports_unavailable() {
        let runtime = WasmRuntime::new(WasmConfig {
            module_path: None,
            module_bytes: None,
            sha256: None,
            max_memory_pages: None,
            timeout_ms: None,
            max_fuel: None,
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
    fn envelope_wasm_rejects_blocking_wasi_poll_at_load_time() {
        let result = WasmRuntime::from_bundle_bytes(POLL_ONEOFF_WASM, envelope_limits());
        assert!(matches!(result, Err(WasmLoadFailure::InvalidImports)));
    }

    #[test]
    fn a_module_declaring_a_foreign_abi_is_refused_at_load() {
        // WOR-2364 item 4: trust the artifact over the file beside it.
        // The manifest's `abi:` sits next to the module and can be
        // hand-edited to claim anything, so a module built against a
        // future ABI used to load clean and fail at first call with an
        // error that did not name the cause.
        const ABI_V9_WASM: &[u8] = include_bytes!("../bundle/testdata/wasm/abi-v9.wasm");
        assert_eq!(
            WasmRuntime::from_bundle_bytes(ABI_V9_WASM, envelope_limits()).err(),
            Some(WasmLoadFailure::AbiMismatch),
            "a declared ABI this host does not serve must fail at load, not at first call"
        );
    }

    #[test]
    fn a_module_declaring_our_abi_loads_and_runs() {
        // The refusal must not be satisfiable by refusing every module
        // that declares anything.
        const ABI_V1_WASM: &[u8] = include_bytes!("../bundle/testdata/wasm/abi-v1.wasm");
        let runtime = WasmRuntime::from_bundle_bytes(ABI_V1_WASM, envelope_limits())
            .expect("a module declaring the served ABI must load");
        assert_eq!(
            runtime.execute_bounded(b"{}").unwrap(),
            br#"{"version":"sbproxy-envelope/v1","decision":"release"}"#
        );
    }

    #[test]
    fn a_module_declaring_nothing_still_loads() {
        // Declaring is optional. Every bundle in the field predates this
        // check, and refusing them would make a guard meant to catch a
        // mistake into one that creates a breaking change.
        const FRESH_GLOBAL_WASM: &[u8] =
            include_bytes!("../bundle/testdata/wasm/fresh-global.wasm");
        let runtime = WasmRuntime::from_bundle_bytes(FRESH_GLOBAL_WASM, envelope_limits());
        assert!(
            runtime.is_ok(),
            "an undeclared module must keep loading; the check is opt-in by construction"
        );
    }

    #[test]
    fn envelope_wasm_load_validation_does_not_execute_the_core_start() {
        let runtime = WasmRuntime::from_bundle_bytes(CORE_START_TRAP_WASM, envelope_limits())
            .expect("link validation must not instantiate the module");
        assert_eq!(
            runtime.execute_bounded(b"{}"),
            Err(WasmCallFailure::GuestTrap)
        );
    }

    #[test]
    fn envelope_wasm_checks_the_start_signature_without_instantiating() {
        let result = WasmRuntime::from_bundle_bytes(BAD_START_SIGNATURE_WASM, envelope_limits());
        assert!(matches!(result, Err(WasmLoadFailure::InvalidStart)));
    }

    #[test]
    fn envelope_wasm_accepts_proc_exit_zero_output() {
        let runtime = WasmRuntime::from_bundle_bytes(PROC_EXIT_ZERO_WASM, envelope_limits())
            .expect("proc_exit is an allowed immediate import");
        assert_eq!(
            runtime.execute_bounded(b"{}").unwrap(),
            br#"{"version":"sbproxy-envelope/v1","decision":"allow"}"#
        );
    }

    #[test]
    fn envelope_wasm_rejects_nonzero_proc_exit() {
        let runtime = WasmRuntime::from_bundle_bytes(PROC_EXIT_NONZERO_WASM, envelope_limits())
            .expect("proc_exit is an allowed immediate import");
        assert_eq!(
            runtime.execute_bounded(b"{}"),
            Err(WasmCallFailure::GuestTrap)
        );
    }

    #[test]
    fn envelope_wasm_discards_stdout_when_the_guest_errors() {
        let runtime = WasmRuntime::from_bundle_bytes(SENTINEL_TRAP_WASM, envelope_limits())
            .expect("fd_write is an allowed in-memory import");
        let result = runtime.execute_bounded(b"{}");
        assert_eq!(result, Err(WasmCallFailure::GuestTrap));
        assert!(!format!("{result:?}").contains("private-sentinel-output"));
    }

    #[test]
    fn matching_sha256_accepts_module_bytes() {
        let digest = hex::encode(sha2::Sha256::digest(ECHO_WASM));
        let mut config = config_with(ECHO_WASM);
        config.sha256 = Some(digest);
        let runtime = WasmRuntime::new(config).expect("matching digest should compile");
        assert_eq!(
            runtime.execute("transform", b"verified").unwrap(),
            b"verified"
        );
    }

    #[test]
    fn module_bytes_keep_precedence_when_sha256_and_path_are_both_present() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("ignored.wasm");
        std::fs::write(&path, b"not wasm").unwrap();
        let mut config = config_with(ECHO_WASM);
        config.module_path = Some(path.display().to_string());
        config.sha256 = Some(hex::encode(sha2::Sha256::digest(ECHO_WASM)));

        let runtime = WasmRuntime::new(config).expect("module bytes should retain precedence");
        assert_eq!(runtime.execute("transform", b"bytes").unwrap(), b"bytes");
    }

    #[test]
    fn matching_sha256_accepts_module_path() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("echo.wasm");
        std::fs::write(&path, ECHO_WASM).unwrap();
        let digest = hex::encode(sha2::Sha256::digest(ECHO_WASM));
        let runtime = WasmRuntime::new(WasmConfig {
            module_path: Some(path.display().to_string()),
            module_bytes: None,
            sha256: Some(digest),
            max_memory_pages: None,
            timeout_ms: None,
            max_fuel: None,
        })
        .expect("matching path digest should compile captured bytes");
        assert_eq!(
            runtime.execute("transform", b"verified").unwrap(),
            b"verified"
        );
    }

    #[test]
    fn sha256_mismatch_precedes_compilation_without_leaking_values_or_path() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("private-module.wasm");
        std::fs::write(&path, b"not wasm").unwrap();
        let expected = "0".repeat(64);
        let actual = hex::encode(sha2::Sha256::digest(b"not wasm"));
        let error = WasmRuntime::new(WasmConfig {
            module_path: Some(path.display().to_string()),
            module_bytes: None,
            sha256: Some(expected.clone()),
            max_memory_pages: None,
            timeout_ms: None,
            max_fuel: None,
        })
        .unwrap_err();
        let message = error.to_string();
        assert_eq!(
            message,
            "WASM module sha256 does not match configured digest"
        );
        assert!(!message.contains(&expected));
        assert!(!message.contains(&actual));
        assert!(!message.contains(&path.display().to_string()));
        assert!(!message.contains("compiling"));
    }

    #[test]
    fn sha256_requires_exact_lowercase_hex_syntax() {
        for digest in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
            let mut config = config_with(ECHO_WASM);
            config.sha256 = Some(digest);
            let error = WasmRuntime::new(config).unwrap_err();
            assert_eq!(
                error.to_string(),
                "WASM module sha256 must contain exactly 64 lowercase hexadecimal characters"
            );
        }
    }

    #[test]
    fn epoch_ticker_spawn_failure_returns_an_error() {
        let engines = Arc::new(Mutex::new(Vec::<Weak<Engine>>::new()));
        let error = start_epoch_ticker(engines, |_engines| {
            Err(io::Error::other("synthetic thread failure"))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    // --- Agent-class input builder tests ---

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
