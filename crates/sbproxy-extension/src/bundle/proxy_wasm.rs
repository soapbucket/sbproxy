//! Proxy-Wasm 0.2.1 HTTP filter host.

use std::{collections::BTreeMap, sync::Arc};

use bytes::Bytes;
use sbproxy_config::{BundleBodyMode, BundleHookKind, BundleRuntime};
use serde_json::Value;
use wasmtime::{
    Caller, Engine, Extern, ExternType, FuncType, Instance, Linker, Memory, Module,
    ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, Trap, ValType,
};

use crate::wasm::{build_engine, WasmBundleLimits};

use super::{BundleLoadError, LoadedBundleHook};

const STATUS_OK: i32 = 0;
const STATUS_NOT_FOUND: i32 = 1;
const STATUS_BAD_ARGUMENT: i32 = 2;
const STATUS_PARSE_FAILURE: i32 = 4;
const STATUS_INVALID_MEMORY_ACCESS: i32 = 6;
const STATUS_INTERNAL_FAILURE: i32 = 10;
const ROOT_CONTEXT_ID: u32 = 1;
const HTTP_CONTEXT_ID: u32 = 2;
const MAX_HEADER_COUNT: usize = 64;
const MAX_TABLE_COUNT: usize = 8;
const MAX_TABLE_ELEMENTS: usize = 10_000;

/// Stable candidate-load failure for a Proxy-Wasm bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyWasmLoadFailure {
    /// The executable is not a core WebAssembly module.
    InvalidModule,
    /// The module imports a function outside sbproxy's declared HTTP subset.
    UnsupportedImport,
    /// The module does not advertise the exact Proxy-Wasm ABI 0.2.1 marker.
    InvalidAbi,
    /// The module does not expose the memory contract required by host calls.
    InvalidMemory,
    /// An exported lifecycle or HTTP callback has the wrong ABI signature.
    InvalidCallback,
    /// The module's static tables exceed the host's per-instance ceiling.
    InvalidResource,
    /// Wasmtime could not create the configured sandbox engine.
    RuntimeUnavailable,
}

/// Stable per-callback failure for a Proxy-Wasm filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyWasmCallFailure {
    /// Host input exceeded the manifest's body or configuration cap.
    InputLimit,
    /// Guest output exceeded the manifest's output cap.
    OutputLimit,
    /// The configured wall-clock budget expired.
    Timeout,
    /// The configured instruction budget was exhausted.
    FuelLimit,
    /// The guest tried to grow linear memory beyond its configured ceiling.
    MemoryLimit,
    /// The guest tried to grow a table beyond the host ceiling.
    ResourceLimit,
    /// The configured WebAssembly stack was exhausted.
    StackLimit,
    /// The guest trapped or its core start section failed.
    GuestTrap,
    /// An exported callback has the wrong ABI signature or result.
    InvalidCallback,
    /// The guest rejected VM or plugin configuration.
    ConfigureRejected,
    /// A host value or guest-produced HTTP value is malformed.
    InvalidHostData,
    /// The runtime could not prepare or enter the sandbox.
    RuntimeUnavailable,
    /// The session has already completed context deletion.
    Finished,
}

impl ProxyWasmCallFailure {
    /// Return a bounded code suitable for logs, metrics, and load errors.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InputLimit => "input_limit",
            Self::OutputLimit => "output_limit",
            Self::Timeout => "timeout",
            Self::FuelLimit => "instruction_cap",
            Self::MemoryLimit => "memory_cap",
            Self::ResourceLimit => "resource_cap",
            Self::StackLimit => "stack_cap",
            Self::GuestTrap => "guest_exception",
            Self::InvalidCallback => "invalid_callback",
            Self::ConfigureRejected => "configuration_rejected",
            Self::InvalidHostData => "invalid_host_data",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::Finished => "session_finished",
        }
    }
}

/// Effective control action after a Proxy-Wasm callback returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyWasmAction {
    /// Release the current headers or body buffer to the next filter.
    Continue,
    /// Hold the current HTTP stream until a later callback resumes it.
    Pause,
    /// Stop the HTTP stream or emit the attached local response.
    Close,
}

/// Bounded local response requested by a Proxy-Wasm filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyWasmLocalResponse {
    /// Validated HTTP status code.
    pub status: u16,
    /// gRPC status supplied by the guest, absent for an ordinary HTTP response.
    pub grpc_status: Option<u32>,
    /// Validated response headers, with duplicates preserved.
    pub headers: Vec<(String, String)>,
    /// Response body bounded by the manifest output cap.
    pub body: Bytes,
}

/// Result of one request or response header callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyWasmHeaderResult {
    /// Effective stream action.
    pub action: ProxyWasmAction,
    /// Complete header map after guest mutations.
    pub headers: Vec<(String, String)>,
    /// Local response, when the guest stopped normal forwarding.
    pub local_response: Option<ProxyWasmLocalResponse>,
}

/// Result of one request or response body callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyWasmBodyResult {
    /// Effective stream action.
    pub action: ProxyWasmAction,
    /// Current body buffer after guest mutations.
    pub body: Bytes,
    /// Local response, when the guest stopped normal forwarding.
    pub local_response: Option<ProxyWasmLocalResponse>,
}

impl ProxyWasmLoadFailure {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidModule => "invalid_module",
            Self::UnsupportedImport => "unsupported_import",
            Self::InvalidAbi => "invalid_abi",
            Self::InvalidMemory => "invalid_memory",
            Self::InvalidCallback => "invalid_callback",
            Self::InvalidResource => "invalid_resource",
            Self::RuntimeUnavailable => "runtime_unavailable",
        }
    }
}

/// One compiled Proxy-Wasm 0.2.1 module shared by request-local instances.
pub struct ProxyWasmRuntime {
    engine: Arc<Engine>,
    module: Module,
    limits: WasmBundleLimits,
}

/// One configured Proxy-Wasm filter attachment.
#[derive(Clone)]
pub struct ProxyWasmFilter {
    type_name: String,
    body_mode: BundleBodyMode,
    runtime: Arc<ProxyWasmRuntime>,
    plugin_configuration: Arc<[u8]>,
}

impl std::fmt::Debug for ProxyWasmFilter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyWasmFilter")
            .field("type_name", &self.type_name)
            .field("body_mode", &self.body_mode)
            .finish_non_exhaustive()
    }
}

impl ProxyWasmFilter {
    /// Return the stable `type:` attachment name.
    #[must_use]
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// Return whether this filter accepts complete bodies or arriving chunks.
    #[must_use]
    pub const fn body_mode(&self) -> BundleBodyMode {
        self.body_mode
    }

    /// Create one isolated request session.
    pub fn start_session(&self) -> Result<ProxyWasmSession, ProxyWasmCallFailure> {
        self.runtime.start_session(&self.plugin_configuration)
    }
}

/// Build a Proxy-Wasm filter from a validated dynamic bundle hook.
pub fn build_proxy_wasm_filter(
    hook: &LoadedBundleHook,
    configuration: Value,
) -> Result<ProxyWasmFilter, BundleLoadError> {
    build_proxy_wasm_filter_for_kind(hook, BundleHookKind::ProxyWasm, configuration)
}

pub(super) fn build_proxy_wasm_filter_for_kind(
    hook: &LoadedBundleHook,
    expected_kind: BundleHookKind,
    configuration: Value,
) -> Result<ProxyWasmFilter, BundleLoadError> {
    if hook.manifest().runtime != BundleRuntime::ProxyWasm || hook.hook().kind != expected_kind {
        return Err(BundleLoadError::new(
            "proxy_wasm",
            "hook kind does not match the requested Proxy-Wasm adapter",
        ));
    }
    let plugin_configuration = serde_json::to_vec(&configuration)
        .map_err(|_| BundleLoadError::new("proxy_wasm", "plugin configuration is invalid"))?;
    let maximum = usize::try_from(hook.manifest().sandbox.max_buffer_bytes)
        .map_err(|_| BundleLoadError::new("proxy_wasm", "input limit is unsupported"))?;
    if plugin_configuration.len() > maximum {
        return Err(BundleLoadError::new(
            "proxy_wasm",
            "plugin configuration exceeds max_buffer_bytes",
        ));
    }
    let runtime = hook
        .prepared_proxy_wasm_runtime()
        .ok_or_else(|| BundleLoadError::new("proxy_wasm", "bundle has no prepared runtime"))?;
    Ok(ProxyWasmFilter {
        type_name: hook.hook().type_name.clone(),
        body_mode: hook.hook().execution.body_mode,
        runtime: Arc::clone(runtime),
        plugin_configuration: Arc::from(plugin_configuration),
    })
}

impl std::fmt::Debug for ProxyWasmRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyWasmRuntime")
            .field("budget_ms", &self.limits.budget.as_millis())
            .field("memory_bytes", &self.limits.memory_bytes)
            .finish_non_exhaustive()
    }
}

impl ProxyWasmRuntime {
    /// Compile and validate one immutable Proxy-Wasm executable.
    pub(crate) fn from_bundle_bytes(
        bytes: &[u8],
        limits: WasmBundleLimits,
    ) -> Result<Self, ProxyWasmLoadFailure> {
        let engine = build_engine(Some(limits.stack_bytes))
            .map_err(|_| ProxyWasmLoadFailure::RuntimeUnavailable)?;
        let module =
            Module::from_binary(&engine, bytes).map_err(|_| ProxyWasmLoadFailure::InvalidModule)?;
        validate_exports(&module, limits)?;
        proxy_wasm_linker(&engine)?
            .instantiate_pre(&module)
            .map_err(|_| ProxyWasmLoadFailure::UnsupportedImport)?;
        Ok(Self {
            engine,
            module,
            limits,
        })
    }

    /// Create one isolated root and HTTP context for a request.
    pub fn start_session(
        &self,
        plugin_configuration: &[u8],
    ) -> Result<ProxyWasmSession, ProxyWasmCallFailure> {
        if plugin_configuration.len() > self.limits.max_input_bytes {
            return Err(ProxyWasmCallFailure::InputLimit);
        }
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.memory_bytes)
            .memories(1)
            .instances(1)
            .tables(MAX_TABLE_COUNT)
            .table_elements(MAX_TABLE_ELEMENTS)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(
            &self.engine,
            ProxyWasmHostState::new(
                store_limits,
                self.limits.max_input_bytes,
                self.limits.max_output_bytes,
                plugin_configuration,
            ),
        );
        store.limiter(|state| &mut state.limits);
        prepare_budget(&mut store, self.limits)?;
        let instance = match proxy_wasm_linker(&self.engine)
            .map_err(|_| ProxyWasmCallFailure::RuntimeUnavailable)?
            .instantiate(&mut store, &self.module)
        {
            Ok(instance) => instance,
            Err(error) => return Err(classify_store_call_error(&store, &error)),
        };
        let mut session = ProxyWasmSession {
            _engine: Arc::clone(&self.engine),
            store,
            instance,
            limits: self.limits,
            finished: false,
            lifecycle_trace: Vec::new(),
        };
        session.initialize()?;
        Ok(session)
    }
}

fn validate_exports(module: &Module, limits: WasmBundleLimits) -> Result<(), ProxyWasmLoadFailure> {
    if exported_i32_signature(module, "proxy_abi_version_0_2_1", 0, 0) != Some(true) {
        return Err(ProxyWasmLoadFailure::InvalidAbi);
    }
    let resources = module.resources_required();
    if resources.num_memories != 1 {
        return Err(ProxyWasmLoadFailure::InvalidMemory);
    }
    if resources.num_tables > MAX_TABLE_COUNT as u32
        || resources
            .max_initial_table_size
            .is_some_and(|size| size > MAX_TABLE_ELEMENTS as u64)
    {
        return Err(ProxyWasmLoadFailure::InvalidResource);
    }
    let Some(ExternType::Memory(memory)) = module.get_export("memory") else {
        return Err(ProxyWasmLoadFailure::InvalidMemory);
    };
    if memory.is_64()
        || memory.is_shared()
        || memory.page_size() != 64 * 1024
        || usize::try_from(memory.minimum())
            .ok()
            .and_then(|pages| pages.checked_mul(64 * 1024))
            .is_none_or(|minimum| minimum > limits.memory_bytes)
    {
        return Err(ProxyWasmLoadFailure::InvalidMemory);
    }
    let allocator = if module.get_export("proxy_on_memory_allocate").is_some() {
        exported_i32_signature(module, "proxy_on_memory_allocate", 1, 1)
    } else {
        exported_i32_signature(module, "malloc", 1, 1)
    };
    if allocator != Some(true) {
        return Err(ProxyWasmLoadFailure::InvalidMemory);
    }

    const CALLBACKS: [(&str, usize, usize); 13] = [
        ("_initialize", 0, 0),
        ("_start", 0, 0),
        ("main", 2, 1),
        ("proxy_on_context_create", 2, 0),
        ("proxy_on_vm_start", 2, 1),
        ("proxy_on_configure", 2, 1),
        ("proxy_on_request_headers", 3, 1),
        ("proxy_on_request_body", 3, 1),
        ("proxy_on_response_headers", 3, 1),
        ("proxy_on_response_body", 3, 1),
        ("proxy_on_done", 1, 1),
        ("proxy_on_log", 1, 0),
        ("proxy_on_delete", 1, 0),
    ];
    if CALLBACKS.iter().any(|(name, params, results)| {
        exported_i32_signature(module, name, *params, *results) == Some(false)
    }) {
        return Err(ProxyWasmLoadFailure::InvalidCallback);
    }
    Ok(())
}

fn exported_i32_signature(
    module: &Module,
    name: &str,
    params: usize,
    results: usize,
) -> Option<bool> {
    match module.get_export(name) {
        Some(ExternType::Func(function)) => Some(is_i32_signature(&function, params, results)),
        Some(_) => Some(false),
        None => None,
    }
}

fn is_i32_signature(function: &FuncType, params: usize, results: usize) -> bool {
    let actual_params = function.params();
    let actual_results = function.results();
    actual_params.len() == params
        && actual_params
            .into_iter()
            .all(|value| matches!(value, ValType::I32))
        && actual_results.len() == results
        && actual_results
            .into_iter()
            .all(|value| matches!(value, ValType::I32))
}

/// One isolated Proxy-Wasm root and HTTP context.
pub struct ProxyWasmSession {
    // Keep the registered engine alive while the store can execute callbacks.
    _engine: Arc<Engine>,
    store: Store<ProxyWasmHostState>,
    instance: Instance,
    limits: WasmBundleLimits,
    finished: bool,
    lifecycle_trace: Vec<&'static str>,
}

impl std::fmt::Debug for ProxyWasmSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyWasmSession")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl ProxyWasmSession {
    fn initialize(&mut self) -> Result<(), ProxyWasmCallFailure> {
        if self.has_export("_initialize") {
            self.call_void0("_initialize")?;
            if self.has_export("main") {
                self.call_i32_i32("main", 0, 0)?;
            }
        } else if self.has_export("_start") {
            self.call_void0("_start")?;
        }

        self.begin_callback()?;
        self.store.data_mut().active_context = ROOT_CONTEXT_ID;
        if self.call_void2(
            "proxy_on_context_create",
            i32::try_from(ROOT_CONTEXT_ID).unwrap_or(1),
            0,
        )? {
            self.lifecycle_trace.push("root_create");
        }

        self.begin_callback()?;
        self.store.data_mut().active_context = ROOT_CONTEXT_ID;
        self.store.data_mut().set_buffer(6, Vec::new());
        let vm_started = self.call_bool2(
            "proxy_on_vm_start",
            i32::try_from(ROOT_CONTEXT_ID).unwrap_or(1),
            0,
        )?;
        if vm_started.is_some() {
            self.lifecycle_trace.push("vm_start");
        }
        if vm_started.is_some_and(|accepted| !accepted) {
            return Err(ProxyWasmCallFailure::ConfigureRejected);
        }

        self.begin_callback()?;
        let plugin_configuration = self.store.data().plugin_configuration.to_vec();
        let configuration_size = i32::try_from(plugin_configuration.len())
            .map_err(|_| ProxyWasmCallFailure::InputLimit)?;
        self.store.data_mut().active_context = ROOT_CONTEXT_ID;
        self.store.data_mut().set_buffer(7, plugin_configuration);
        let configured = self.call_bool2(
            "proxy_on_configure",
            i32::try_from(ROOT_CONTEXT_ID).unwrap_or(1),
            configuration_size,
        )?;
        if configured.is_some() {
            self.lifecycle_trace.push("configure");
        }
        if configured.is_some_and(|accepted| !accepted) {
            return Err(ProxyWasmCallFailure::ConfigureRejected);
        }

        self.begin_callback()?;
        self.store.data_mut().active_context = HTTP_CONTEXT_ID;
        if self.call_void2(
            "proxy_on_context_create",
            i32::try_from(HTTP_CONTEXT_ID).unwrap_or(2),
            i32::try_from(ROOT_CONTEXT_ID).unwrap_or(1),
        )? {
            self.lifecycle_trace.push("http_create");
        }
        Ok(())
    }

    /// Run the request-header callback with a complete mutable header map.
    pub fn on_request_headers(
        &mut self,
        headers: Vec<(String, String)>,
        end_of_stream: bool,
    ) -> Result<ProxyWasmHeaderResult, ProxyWasmCallFailure> {
        self.run_headers(
            "proxy_on_request_headers",
            "request_headers",
            0,
            headers,
            end_of_stream,
        )
    }

    /// Run the response-header callback with a complete mutable header map.
    pub fn on_response_headers(
        &mut self,
        headers: Vec<(String, String)>,
        end_of_stream: bool,
    ) -> Result<ProxyWasmHeaderResult, ProxyWasmCallFailure> {
        self.run_headers(
            "proxy_on_response_headers",
            "response_headers",
            2,
            headers,
            end_of_stream,
        )
    }

    /// Run one request-body callback.
    ///
    /// `body` may be empty without ending the stream. Callers pass
    /// `end_of_stream = true` only for the explicit terminal callback.
    pub fn on_request_body(
        &mut self,
        body: Bytes,
        end_of_stream: bool,
    ) -> Result<ProxyWasmBodyResult, ProxyWasmCallFailure> {
        self.run_body(
            "proxy_on_request_body",
            if end_of_stream {
                "request_body:eos"
            } else {
                "request_body:chunk"
            },
            0,
            body,
            end_of_stream,
        )
    }

    /// Run one response-body callback.
    ///
    /// Empty chunks and the terminal callback remain distinct, matching the
    /// request-body contract.
    pub fn on_response_body(
        &mut self,
        body: Bytes,
        end_of_stream: bool,
    ) -> Result<ProxyWasmBodyResult, ProxyWasmCallFailure> {
        self.run_body(
            "proxy_on_response_body",
            if end_of_stream {
                "response_body:eos"
            } else {
                "response_body:chunk"
            },
            1,
            body,
            end_of_stream,
        )
    }

    /// Complete HTTP and root contexts in the specified done, log, delete order.
    pub fn finish(&mut self) -> Result<(), ProxyWasmCallFailure> {
        self.ensure_live()?;
        if !self.finish_context(HTTP_CONTEXT_ID, "http_done", "http_log", "http_delete")? {
            return Ok(());
        }
        if !self.finish_context(ROOT_CONTEXT_ID, "root_done", "root_log", "root_delete")? {
            return Ok(());
        }
        self.finished = true;
        Ok(())
    }

    /// Return whether both HTTP and root contexts completed deletion.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    fn finish_context(
        &mut self,
        context_id: u32,
        done_label: &'static str,
        log_label: &'static str,
        delete_label: &'static str,
    ) -> Result<bool, ProxyWasmCallFailure> {
        match self
            .store
            .data()
            .context_finalization(context_id)
            .ok_or(ProxyWasmCallFailure::InvalidHostData)?
        {
            ContextFinalization::Deleted => return Ok(true),
            ContextFinalization::Pending => return Ok(false),
            ContextFinalization::Ready => {}
            ContextFinalization::Live => {
                self.begin_callback()?;
                self.store.data_mut().active_context = context_id;
                let abi_context_id =
                    i32::try_from(context_id).map_err(|_| ProxyWasmCallFailure::InvalidHostData)?;
                if let Some(done) = self.call_bool1("proxy_on_done", abi_context_id)? {
                    self.lifecycle_trace.push(done_label);
                    if !done {
                        self.store
                            .data_mut()
                            .set_context_finalization(context_id, ContextFinalization::Pending)
                            .ok_or(ProxyWasmCallFailure::InvalidHostData)?;
                        return Ok(false);
                    }
                }
                self.store
                    .data_mut()
                    .set_context_finalization(context_id, ContextFinalization::Ready)
                    .ok_or(ProxyWasmCallFailure::InvalidHostData)?;
            }
        }
        let abi_context_id =
            i32::try_from(context_id).map_err(|_| ProxyWasmCallFailure::InvalidHostData)?;
        self.begin_callback()?;
        self.store.data_mut().active_context = context_id;
        if self.call_void1("proxy_on_log", abi_context_id)? {
            self.lifecycle_trace.push(log_label);
        }
        self.begin_callback()?;
        self.store.data_mut().active_context = context_id;
        if self.call_void1("proxy_on_delete", abi_context_id)? {
            self.lifecycle_trace.push(delete_label);
        }
        self.store
            .data_mut()
            .set_context_finalization(context_id, ContextFinalization::Deleted)
            .ok_or(ProxyWasmCallFailure::InvalidHostData)?;
        Ok(true)
    }

    fn run_headers(
        &mut self,
        callback: &str,
        trace: &'static str,
        map_id: i32,
        headers: Vec<(String, String)>,
        end_of_stream: bool,
    ) -> Result<ProxyWasmHeaderResult, ProxyWasmCallFailure> {
        self.ensure_live()?;
        validate_headers(&headers, self.limits.max_input_bytes).map_err(
            |failure| match failure {
                ProxyWasmCallFailure::OutputLimit => ProxyWasmCallFailure::InputLimit,
                other => other,
            },
        )?;
        self.begin_callback()?;
        self.store.data_mut().active_context = HTTP_CONTEXT_ID;
        self.store.data_mut().set_map(map_id, headers);
        let header_count = self
            .store
            .data()
            .header_maps
            .get(&map_id)
            .map_or(0, Vec::len);
        let header_count =
            i32::try_from(header_count).map_err(|_| ProxyWasmCallFailure::InvalidHostData)?;
        let (raw_action, called) = self.call_action3(
            callback,
            i32::try_from(HTTP_CONTEXT_ID).unwrap_or(2),
            header_count,
            i32::from(end_of_stream),
        )?;
        if called {
            self.lifecycle_trace.push(trace);
        }
        self.check_host_failure()?;
        let headers = self
            .store
            .data()
            .header_maps
            .get(&map_id)
            .cloned()
            .unwrap_or_default();
        validate_headers(&headers, self.limits.max_output_bytes)?;
        let local_response = self.store.data_mut().local_response.take();
        let action = effective_action(self.store.data_mut(), raw_action)?;
        Ok(ProxyWasmHeaderResult {
            action: if local_response.is_some() {
                ProxyWasmAction::Close
            } else {
                action
            },
            headers,
            local_response,
        })
    }

    fn run_body(
        &mut self,
        callback: &str,
        trace: &'static str,
        buffer_id: i32,
        body: Bytes,
        end_of_stream: bool,
    ) -> Result<ProxyWasmBodyResult, ProxyWasmCallFailure> {
        self.ensure_live()?;
        if body.len() > self.limits.max_input_bytes {
            return Err(ProxyWasmCallFailure::InputLimit);
        }
        self.begin_callback()?;
        self.store.data_mut().active_context = HTTP_CONTEXT_ID;
        self.store.data_mut().set_buffer(buffer_id, body.to_vec());
        let body_size = i32::try_from(body.len()).map_err(|_| ProxyWasmCallFailure::InputLimit)?;
        let (raw_action, called) = self.call_action3(
            callback,
            i32::try_from(HTTP_CONTEXT_ID).unwrap_or(2),
            body_size,
            i32::from(end_of_stream),
        )?;
        if called {
            self.lifecycle_trace.push(trace);
        }
        self.check_host_failure()?;
        let body = self
            .store
            .data_mut()
            .current_buffer
            .take()
            .map_or_else(Bytes::new, |(_, body)| Bytes::from(body));
        if body.len() > self.limits.max_output_bytes {
            return Err(ProxyWasmCallFailure::OutputLimit);
        }
        let local_response = self.store.data_mut().local_response.take();
        let action = effective_action(self.store.data_mut(), raw_action)?;
        Ok(ProxyWasmBodyResult {
            action: if local_response.is_some() {
                ProxyWasmAction::Close
            } else {
                action
            },
            body,
            local_response,
        })
    }

    fn ensure_live(&self) -> Result<(), ProxyWasmCallFailure> {
        if self.finished {
            Err(ProxyWasmCallFailure::Finished)
        } else {
            Ok(())
        }
    }

    fn begin_callback(&mut self) -> Result<(), ProxyWasmCallFailure> {
        self.ensure_live()?;
        prepare_budget(&mut self.store, self.limits)?;
        self.store.data_mut().reset_callback();
        Ok(())
    }

    fn check_host_failure(&mut self) -> Result<(), ProxyWasmCallFailure> {
        match self.store.data_mut().failure.take() {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    fn has_export(&mut self, name: &str) -> bool {
        self.instance.get_func(&mut self.store, name).is_some()
    }

    fn call_void0(&mut self, name: &str) -> Result<(), ProxyWasmCallFailure> {
        prepare_budget(&mut self.store, self.limits)?;
        let function = self
            .instance
            .get_typed_func::<(), ()>(&mut self.store, name)
            .map_err(|_| ProxyWasmCallFailure::InvalidCallback)?;
        if let Err(error) = function.call(&mut self.store, ()) {
            return Err(classify_store_call_error(&self.store, &error));
        }
        self.check_host_failure()
    }

    fn call_i32_i32(
        &mut self,
        name: &str,
        first: i32,
        second: i32,
    ) -> Result<i32, ProxyWasmCallFailure> {
        prepare_budget(&mut self.store, self.limits)?;
        let function = self
            .instance
            .get_typed_func::<(i32, i32), i32>(&mut self.store, name)
            .map_err(|_| ProxyWasmCallFailure::InvalidCallback)?;
        let result = match function.call(&mut self.store, (first, second)) {
            Ok(result) => result,
            Err(error) => return Err(classify_store_call_error(&self.store, &error)),
        };
        self.check_host_failure()?;
        Ok(result)
    }

    fn call_void2(
        &mut self,
        name: &str,
        first: i32,
        second: i32,
    ) -> Result<bool, ProxyWasmCallFailure> {
        let Some(function) = self.instance.get_func(&mut self.store, name) else {
            return Ok(false);
        };
        prepare_budget(&mut self.store, self.limits)?;
        let function = function
            .typed::<(i32, i32), ()>(&self.store)
            .map_err(|_| ProxyWasmCallFailure::InvalidCallback)?;
        if let Err(error) = function.call(&mut self.store, (first, second)) {
            return Err(classify_store_call_error(&self.store, &error));
        }
        self.check_host_failure()?;
        Ok(true)
    }

    fn call_bool2(
        &mut self,
        name: &str,
        first: i32,
        second: i32,
    ) -> Result<Option<bool>, ProxyWasmCallFailure> {
        let Some(function) = self.instance.get_func(&mut self.store, name) else {
            return Ok(None);
        };
        prepare_budget(&mut self.store, self.limits)?;
        let function = function
            .typed::<(i32, i32), i32>(&self.store)
            .map_err(|_| ProxyWasmCallFailure::InvalidCallback)?;
        let result = match function.call(&mut self.store, (first, second)) {
            Ok(result) => result,
            Err(error) => return Err(classify_store_call_error(&self.store, &error)),
        };
        self.check_host_failure()?;
        Ok(Some(result != 0))
    }

    fn call_bool1(&mut self, name: &str, value: i32) -> Result<Option<bool>, ProxyWasmCallFailure> {
        let Some(function) = self.instance.get_func(&mut self.store, name) else {
            return Ok(None);
        };
        prepare_budget(&mut self.store, self.limits)?;
        let function = function
            .typed::<i32, i32>(&self.store)
            .map_err(|_| ProxyWasmCallFailure::InvalidCallback)?;
        let result = match function.call(&mut self.store, value) {
            Ok(result) => result,
            Err(error) => return Err(classify_store_call_error(&self.store, &error)),
        };
        self.check_host_failure()?;
        Ok(Some(result != 0))
    }

    fn call_void1(&mut self, name: &str, value: i32) -> Result<bool, ProxyWasmCallFailure> {
        let Some(function) = self.instance.get_func(&mut self.store, name) else {
            return Ok(false);
        };
        prepare_budget(&mut self.store, self.limits)?;
        let function = function
            .typed::<i32, ()>(&self.store)
            .map_err(|_| ProxyWasmCallFailure::InvalidCallback)?;
        if let Err(error) = function.call(&mut self.store, value) {
            return Err(classify_store_call_error(&self.store, &error));
        }
        self.check_host_failure()?;
        Ok(true)
    }

    fn call_action3(
        &mut self,
        name: &str,
        first: i32,
        second: i32,
        third: i32,
    ) -> Result<(i32, bool), ProxyWasmCallFailure> {
        let Some(function) = self.instance.get_func(&mut self.store, name) else {
            return Ok((0, false));
        };
        prepare_budget(&mut self.store, self.limits)?;
        let function = function
            .typed::<(i32, i32, i32), i32>(&self.store)
            .map_err(|_| ProxyWasmCallFailure::InvalidCallback)?;
        let result = match function.call(&mut self.store, (first, second, third)) {
            Ok(result) => result,
            Err(error) => return Err(classify_store_call_error(&self.store, &error)),
        };
        self.check_host_failure()?;
        Ok((result, true))
    }

    #[cfg(test)]
    fn lifecycle_trace(&self) -> &[&'static str] {
        &self.lifecycle_trace
    }
}

fn prepare_budget(
    store: &mut Store<ProxyWasmHostState>,
    limits: WasmBundleLimits,
) -> Result<(), ProxyWasmCallFailure> {
    store
        .set_fuel(limits.fuel)
        .map_err(|_| ProxyWasmCallFailure::RuntimeUnavailable)?;
    store.set_epoch_deadline(limits.budget.as_millis().max(1) as u64);
    Ok(())
}

fn classify_call_error(error: &wasmtime::Error) -> ProxyWasmCallFailure {
    match error.downcast_ref::<Trap>() {
        Some(Trap::Interrupt) => ProxyWasmCallFailure::Timeout,
        Some(Trap::OutOfFuel) => ProxyWasmCallFailure::FuelLimit,
        Some(Trap::StackOverflow) => ProxyWasmCallFailure::StackLimit,
        Some(_) => ProxyWasmCallFailure::GuestTrap,
        None => ProxyWasmCallFailure::RuntimeUnavailable,
    }
}

fn classify_store_call_error(
    store: &Store<ProxyWasmHostState>,
    error: &wasmtime::Error,
) -> ProxyWasmCallFailure {
    classify_host_call_error(store.data(), error)
}

fn classify_host_call_error(
    state: &ProxyWasmHostState,
    error: &wasmtime::Error,
) -> ProxyWasmCallFailure {
    if state.limits.memory_denied {
        ProxyWasmCallFailure::MemoryLimit
    } else if state.limits.table_denied {
        ProxyWasmCallFailure::ResourceLimit
    } else {
        classify_call_error(error)
    }
}

fn effective_action(
    state: &mut ProxyWasmHostState,
    raw_action: i32,
) -> Result<ProxyWasmAction, ProxyWasmCallFailure> {
    if state.close_requested {
        return Ok(ProxyWasmAction::Close);
    }
    if state.continue_requested {
        return Ok(ProxyWasmAction::Continue);
    }
    match raw_action {
        0 => Ok(ProxyWasmAction::Continue),
        1 => Ok(ProxyWasmAction::Pause),
        _ => Err(ProxyWasmCallFailure::InvalidCallback),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextFinalization {
    Live,
    Pending,
    Ready,
    Deleted,
}

fn context_index(context_id: u32) -> Option<usize> {
    match context_id {
        ROOT_CONTEXT_ID => Some(0),
        HTTP_CONTEXT_ID => Some(1),
        _ => None,
    }
}

struct ProxyWasmHostState {
    limits: ProxyWasmStoreLimits,
    max_input_bytes: usize,
    max_output_bytes: usize,
    plugin_configuration: Arc<[u8]>,
    active_context: u32,
    context_finalization: [ContextFinalization; 2],
    current_buffer: Option<(i32, Vec<u8>)>,
    header_maps: BTreeMap<i32, Vec<(String, String)>>,
    writable_map: Option<i32>,
    local_response: Option<ProxyWasmLocalResponse>,
    continue_requested: bool,
    close_requested: bool,
    failure: Option<ProxyWasmCallFailure>,
}

impl ProxyWasmHostState {
    fn new(
        limits: StoreLimits,
        max_input_bytes: usize,
        max_output_bytes: usize,
        plugin_configuration: &[u8],
    ) -> Self {
        Self {
            limits: ProxyWasmStoreLimits {
                inner: limits,
                memory_denied: false,
                table_denied: false,
            },
            max_input_bytes,
            max_output_bytes,
            plugin_configuration: Arc::from(plugin_configuration),
            active_context: 0,
            context_finalization: [ContextFinalization::Live; 2],
            current_buffer: None,
            header_maps: BTreeMap::new(),
            writable_map: None,
            local_response: None,
            continue_requested: false,
            close_requested: false,
            failure: None,
        }
    }

    fn reset_callback(&mut self) {
        self.limits.memory_denied = false;
        self.limits.table_denied = false;
        self.current_buffer = None;
        self.writable_map = None;
        self.local_response = None;
        self.continue_requested = false;
        self.close_requested = false;
        self.failure = None;
    }

    fn set_buffer(&mut self, buffer_id: i32, value: Vec<u8>) {
        self.current_buffer = Some((buffer_id, value));
    }

    fn set_map(&mut self, map_id: i32, value: Vec<(String, String)>) {
        self.header_maps.insert(map_id, value);
        self.writable_map = Some(map_id);
    }

    fn context_finalization(&self, context_id: u32) -> Option<ContextFinalization> {
        context_index(context_id).map(|index| self.context_finalization[index])
    }

    fn set_context_finalization(
        &mut self,
        context_id: u32,
        finalization: ContextFinalization,
    ) -> Option<()> {
        let index = context_index(context_id)?;
        self.context_finalization[index] = finalization;
        Some(())
    }

    fn fail(&mut self, failure: ProxyWasmCallFailure) {
        self.failure.get_or_insert(failure);
    }
}

struct ProxyWasmStoreLimits {
    inner: StoreLimits,
    memory_denied: bool,
    table_denied: bool,
}

impl ResourceLimiter for ProxyWasmStoreLimits {
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
}

fn abi_usize(value: i32) -> usize {
    value as u32 as usize
}

fn guest_memory(caller: &mut Caller<'_, ProxyWasmHostState>) -> Result<Memory, i32> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or(STATUS_INVALID_MEMORY_ACCESS)
}

fn read_guest(
    caller: &mut Caller<'_, ProxyWasmHostState>,
    pointer: i32,
    size: i32,
) -> Result<Vec<u8>, i32> {
    let start = abi_usize(pointer);
    let length = abi_usize(size);
    let end = start
        .checked_add(length)
        .ok_or(STATUS_INVALID_MEMORY_ACCESS)?;
    let memory = guest_memory(caller)?;
    memory
        .data(&*caller)
        .get(start..end)
        .map(<[u8]>::to_vec)
        .ok_or(STATUS_INVALID_MEMORY_ACCESS)
}

fn write_guest(
    caller: &mut Caller<'_, ProxyWasmHostState>,
    pointer: i32,
    value: &[u8],
) -> Result<(), i32> {
    let memory = guest_memory(caller)?;
    memory
        .write(&mut *caller, abi_usize(pointer), value)
        .map_err(|_| STATUS_INVALID_MEMORY_ACCESS)
}

fn write_u32(
    caller: &mut Caller<'_, ProxyWasmHostState>,
    pointer: i32,
    value: u32,
) -> Result<(), i32> {
    write_guest(caller, pointer, &value.to_le_bytes())
}

fn guest_allocate(caller: &mut Caller<'_, ProxyWasmHostState>, size: usize) -> Result<i32, i32> {
    if size == 0 {
        return Ok(0);
    }
    let size = i32::try_from(size).map_err(|_| STATUS_BAD_ARGUMENT)?;
    let allocation = caller
        .get_export("proxy_on_memory_allocate")
        .or_else(|| caller.get_export("malloc"))
        .and_then(Extern::into_func)
        .ok_or(STATUS_INTERNAL_FAILURE)?;
    let allocation = allocation
        .typed::<i32, i32>(&*caller)
        .map_err(|_| STATUS_INTERNAL_FAILURE)?;
    let pointer = match allocation.call(&mut *caller, size) {
        Ok(pointer) if pointer != 0 => pointer,
        Ok(_) => return Err(STATUS_INVALID_MEMORY_ACCESS),
        Err(error) => {
            let failure = classify_host_call_error(caller.data(), &error);
            caller.data_mut().fail(failure);
            return Err(STATUS_INTERNAL_FAILURE);
        }
    };
    Ok(pointer)
}

fn return_bytes(
    caller: &mut Caller<'_, ProxyWasmHostState>,
    value: &[u8],
    return_data: i32,
    return_size: i32,
) -> i32 {
    if value.len()
        > caller
            .data()
            .max_input_bytes
            .max(caller.data().max_output_bytes)
    {
        return STATUS_BAD_ARGUMENT;
    }
    let pointer = match guest_allocate(caller, value.len()) {
        Ok(pointer) => pointer,
        Err(status) => return status,
    };
    if (!value.is_empty() && write_guest(caller, pointer, value).is_err())
        || write_u32(caller, return_data, pointer as u32).is_err()
        || write_u32(caller, return_size, value.len() as u32).is_err()
    {
        return STATUS_INVALID_MEMORY_ACCESS;
    }
    STATUS_OK
}

fn current_buffer<'a>(
    caller: &'a Caller<'_, ProxyWasmHostState>,
    buffer_id: i32,
) -> Result<&'a [u8], i32> {
    match caller.data().current_buffer.as_ref() {
        Some((current_id, value)) if *current_id == buffer_id => Ok(value),
        Some(_) => Err(STATUS_BAD_ARGUMENT),
        None => Err(STATUS_NOT_FOUND),
    }
}

fn current_map<'a>(
    caller: &'a Caller<'_, ProxyWasmHostState>,
    map_id: i32,
) -> Result<&'a [(String, String)], i32> {
    if caller.data().active_context != HTTP_CONTEXT_ID {
        return Err(STATUS_NOT_FOUND);
    }
    caller
        .data()
        .header_maps
        .get(&map_id)
        .map(Vec::as_slice)
        .ok_or(STATUS_NOT_FOUND)
}

fn current_map_mut<'a>(
    caller: &'a mut Caller<'_, ProxyWasmHostState>,
    map_id: i32,
) -> Result<&'a mut Vec<(String, String)>, i32> {
    if caller.data().active_context != HTTP_CONTEXT_ID {
        return Err(STATUS_NOT_FOUND);
    }
    match caller.data().writable_map {
        Some(current_id) if current_id == map_id => caller
            .data_mut()
            .header_maps
            .get_mut(&map_id)
            .ok_or(STATUS_NOT_FOUND),
        Some(_) => Err(STATUS_BAD_ARGUMENT),
        None => Err(STATUS_NOT_FOUND),
    }
}

fn header_name_matches(left: &str, right: &str) -> bool {
    if left.starts_with(':') || right.starts_with(':') {
        left == right
    } else {
        left.eq_ignore_ascii_case(right)
    }
}

fn parse_guest_text(bytes: Vec<u8>) -> Result<String, i32> {
    String::from_utf8(bytes).map_err(|_| STATUS_PARSE_FAILURE)
}

fn validate_header(name: &str, value: &str) -> Result<(), ProxyWasmCallFailure> {
    let valid_pseudo = name.starts_with(':')
        && name.len() > 1
        && name[1..]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-');
    if (!valid_pseudo && http::HeaderName::from_bytes(name.as_bytes()).is_err())
        || http::HeaderValue::from_bytes(value.as_bytes()).is_err()
    {
        return Err(ProxyWasmCallFailure::InvalidHostData);
    }
    Ok(())
}

fn validate_headers(
    headers: &[(String, String)],
    maximum_bytes: usize,
) -> Result<(), ProxyWasmCallFailure> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(ProxyWasmCallFailure::OutputLimit);
    }
    let mut size = 0usize;
    for (name, value) in headers {
        validate_header(name, value)?;
        size = size
            .checked_add(name.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(ProxyWasmCallFailure::OutputLimit)?;
        if size > maximum_bytes {
            return Err(ProxyWasmCallFailure::OutputLimit);
        }
    }
    Ok(())
}

fn serialize_headers(headers: &[(String, String)]) -> Result<Vec<u8>, ProxyWasmCallFailure> {
    validate_headers(headers, usize::MAX)?;
    let count = u32::try_from(headers.len()).map_err(|_| ProxyWasmCallFailure::OutputLimit)?;
    let mut output = Vec::new();
    output.extend_from_slice(&count.to_le_bytes());
    for (name, value) in headers {
        output.extend_from_slice(
            &u32::try_from(name.len())
                .map_err(|_| ProxyWasmCallFailure::OutputLimit)?
                .to_le_bytes(),
        );
        output.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| ProxyWasmCallFailure::OutputLimit)?
                .to_le_bytes(),
        );
    }
    for (name, value) in headers {
        output.extend_from_slice(name.as_bytes());
        output.push(0);
        output.extend_from_slice(value.as_bytes());
        output.push(0);
    }
    Ok(output)
}

fn parse_headers(bytes: &[u8]) -> Result<Vec<(String, String)>, ProxyWasmCallFailure> {
    if bytes.is_empty() || bytes == [0] {
        return Ok(Vec::new());
    }
    let count = read_serialized_u32(bytes, 0)? as usize;
    if count > MAX_HEADER_COUNT {
        return Err(ProxyWasmCallFailure::OutputLimit);
    }
    let lengths_bytes = count
        .checked_mul(8)
        .and_then(|length| length.checked_add(4))
        .ok_or(ProxyWasmCallFailure::InvalidHostData)?;
    if lengths_bytes > bytes.len() {
        return Err(ProxyWasmCallFailure::InvalidHostData);
    }
    let mut lengths = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 4 + index * 8;
        lengths.push((
            read_serialized_u32(bytes, offset)? as usize,
            read_serialized_u32(bytes, offset + 4)? as usize,
        ));
    }
    let mut cursor = lengths_bytes;
    let mut headers = Vec::with_capacity(count);
    for (name_length, value_length) in lengths {
        let name_end = cursor
            .checked_add(name_length)
            .ok_or(ProxyWasmCallFailure::InvalidHostData)?;
        if bytes.get(name_end) != Some(&0) {
            return Err(ProxyWasmCallFailure::InvalidHostData);
        }
        let name = std::str::from_utf8(
            bytes
                .get(cursor..name_end)
                .ok_or(ProxyWasmCallFailure::InvalidHostData)?,
        )
        .map_err(|_| ProxyWasmCallFailure::InvalidHostData)?
        .to_owned();
        cursor = name_end + 1;
        let value_end = cursor
            .checked_add(value_length)
            .ok_or(ProxyWasmCallFailure::InvalidHostData)?;
        if bytes.get(value_end) != Some(&0) {
            return Err(ProxyWasmCallFailure::InvalidHostData);
        }
        let value = std::str::from_utf8(
            bytes
                .get(cursor..value_end)
                .ok_or(ProxyWasmCallFailure::InvalidHostData)?,
        )
        .map_err(|_| ProxyWasmCallFailure::InvalidHostData)?
        .to_owned();
        validate_header(&name, &value)?;
        headers.push((name, value));
        cursor = value_end + 1;
    }
    if cursor != bytes.len() {
        return Err(ProxyWasmCallFailure::InvalidHostData);
    }
    Ok(headers)
}

fn read_serialized_u32(bytes: &[u8], offset: usize) -> Result<u32, ProxyWasmCallFailure> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(ProxyWasmCallFailure::InvalidHostData)?
        .try_into()
        .map_err(|_| ProxyWasmCallFailure::InvalidHostData)?;
    Ok(u32::from_le_bytes(value))
}

fn read_guest_header(
    caller: &mut Caller<'_, ProxyWasmHostState>,
    key_data: i32,
    key_size: i32,
    value_data: i32,
    value_size: i32,
) -> Result<(String, String), i32> {
    let key = parse_guest_text(read_guest(caller, key_data, key_size)?)?;
    let value = parse_guest_text(read_guest(caller, value_data, value_size)?)?;
    validate_header(&key, &value).map_err(|_| STATUS_PARSE_FAILURE)?;
    Ok((key, value))
}

fn enforce_map_output_limit(caller: &mut Caller<'_, ProxyWasmHostState>) -> Result<(), i32> {
    let Some(map_id) = caller.data().writable_map else {
        return Err(STATUS_NOT_FOUND);
    };
    let Some(headers) = caller.data().header_maps.get(&map_id) else {
        return Err(STATUS_NOT_FOUND);
    };
    if validate_headers(headers, caller.data().max_output_bytes).is_err() {
        caller.data_mut().fail(ProxyWasmCallFailure::OutputLimit);
        return Err(STATUS_BAD_ARGUMENT);
    }
    Ok(())
}

fn host_log(mut caller: Caller<'_, ProxyWasmHostState>, level: i32, data: i32, size: i32) -> i32 {
    if !(0..=5).contains(&level) || abi_usize(size) > 4096 {
        return STATUS_BAD_ARGUMENT;
    }
    let message = match read_guest(&mut caller, data, size) {
        Ok(message) => String::from_utf8_lossy(&message).into_owned(),
        Err(status) => return status,
    };
    match level {
        0 => tracing::trace!(
            target: "sbproxy::proxy_wasm",
            log_level = level,
            context_id = caller.data().active_context,
            message = %message,
            "Proxy-Wasm guest log"
        ),
        1 => tracing::debug!(
            target: "sbproxy::proxy_wasm",
            log_level = level,
            context_id = caller.data().active_context,
            message = %message,
            "Proxy-Wasm guest log"
        ),
        2 => tracing::info!(
            target: "sbproxy::proxy_wasm",
            log_level = level,
            context_id = caller.data().active_context,
            message = %message,
            "Proxy-Wasm guest log"
        ),
        3 => tracing::warn!(
            target: "sbproxy::proxy_wasm",
            log_level = level,
            context_id = caller.data().active_context,
            message = %message,
            "Proxy-Wasm guest log"
        ),
        4 | 5 => tracing::error!(
            target: "sbproxy::proxy_wasm",
            log_level = level,
            context_id = caller.data().active_context,
            message = %message,
            "Proxy-Wasm guest log"
        ),
        _ => unreachable!("log level was validated"),
    }
    STATUS_OK
}

fn host_get_log_level(mut caller: Caller<'_, ProxyWasmHostState>, return_level: i32) -> i32 {
    write_u32(&mut caller, return_level, 2).map_or_else(|status| status, |()| STATUS_OK)
}

fn host_get_buffer_bytes(
    mut caller: Caller<'_, ProxyWasmHostState>,
    buffer_id: i32,
    start: i32,
    maximum: i32,
    return_data: i32,
    return_size: i32,
) -> i32 {
    let value = match current_buffer(&caller, buffer_id) {
        Ok(value) => value.to_vec(),
        Err(status) => return status,
    };
    let start = abi_usize(start);
    if start > value.len() {
        return STATUS_BAD_ARGUMENT;
    }
    let end = start.saturating_add(abi_usize(maximum)).min(value.len());
    return_bytes(&mut caller, &value[start..end], return_data, return_size)
}

fn host_set_buffer_bytes(
    mut caller: Caller<'_, ProxyWasmHostState>,
    buffer_id: i32,
    start: i32,
    remove_size: i32,
    value_data: i32,
    value_size: i32,
) -> i32 {
    let value_length = abi_usize(value_size);
    if value_length > caller.data().max_output_bytes {
        caller.data_mut().fail(ProxyWasmCallFailure::OutputLimit);
        return STATUS_BAD_ARGUMENT;
    }
    let value = match read_guest(&mut caller, value_data, value_size) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let maximum = caller.data().max_output_bytes;
    let Some((current_id, buffer)) = caller.data_mut().current_buffer.as_mut() else {
        return STATUS_NOT_FOUND;
    };
    if *current_id != buffer_id {
        return STATUS_BAD_ARGUMENT;
    }
    let configured_start = abi_usize(start);
    let start = configured_start.min(buffer.len());
    let end = if configured_start >= buffer.len() {
        buffer.len()
    } else {
        configured_start
            .saturating_add(abi_usize(remove_size))
            .min(buffer.len())
    };
    let new_length = buffer
        .len()
        .saturating_sub(end.saturating_sub(start))
        .saturating_add(value.len());
    if new_length > maximum {
        caller.data_mut().fail(ProxyWasmCallFailure::OutputLimit);
        return STATUS_BAD_ARGUMENT;
    }
    buffer.splice(start..end, value);
    STATUS_OK
}

fn host_get_buffer_status(
    mut caller: Caller<'_, ProxyWasmHostState>,
    buffer_id: i32,
    return_size: i32,
    return_unused: i32,
) -> i32 {
    let length = match current_buffer(&caller, buffer_id) {
        Ok(value) => value.len(),
        Err(status) => return status,
    };
    let Ok(length) = u32::try_from(length) else {
        return STATUS_BAD_ARGUMENT;
    };
    if write_u32(&mut caller, return_size, length).is_err()
        || write_u32(&mut caller, return_unused, 0).is_err()
    {
        STATUS_INVALID_MEMORY_ACCESS
    } else {
        STATUS_OK
    }
}

fn host_get_header_map_size(
    mut caller: Caller<'_, ProxyWasmHostState>,
    map_id: i32,
    return_size: i32,
) -> i32 {
    let serialized = match current_map(&caller, map_id)
        .and_then(|headers| serialize_headers(headers).map_err(|_| STATUS_INTERNAL_FAILURE))
    {
        Ok(serialized) => serialized,
        Err(status) => return status,
    };
    let Ok(length) = u32::try_from(serialized.len()) else {
        return STATUS_BAD_ARGUMENT;
    };
    write_u32(&mut caller, return_size, length).map_or_else(|status| status, |()| STATUS_OK)
}

fn host_get_header_map_pairs(
    mut caller: Caller<'_, ProxyWasmHostState>,
    map_id: i32,
    return_data: i32,
    return_size: i32,
) -> i32 {
    let serialized = match current_map(&caller, map_id)
        .and_then(|headers| serialize_headers(headers).map_err(|_| STATUS_INTERNAL_FAILURE))
    {
        Ok(serialized) => serialized,
        Err(status) => return status,
    };
    return_bytes(&mut caller, &serialized, return_data, return_size)
}

fn host_set_header_map_pairs(
    mut caller: Caller<'_, ProxyWasmHostState>,
    map_id: i32,
    data: i32,
    size: i32,
) -> i32 {
    if abi_usize(size) > caller.data().max_output_bytes {
        caller.data_mut().fail(ProxyWasmCallFailure::OutputLimit);
        return STATUS_BAD_ARGUMENT;
    }
    let bytes = match read_guest(&mut caller, data, size) {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let headers = match parse_headers(&bytes) {
        Ok(headers) => headers,
        Err(ProxyWasmCallFailure::OutputLimit) => {
            caller.data_mut().fail(ProxyWasmCallFailure::OutputLimit);
            return STATUS_BAD_ARGUMENT;
        }
        Err(_) => return STATUS_PARSE_FAILURE,
    };
    match current_map_mut(&mut caller, map_id) {
        Ok(current) => {
            *current = headers;
            STATUS_OK
        }
        Err(status) => status,
    }
}

fn host_get_header_map_value(
    mut caller: Caller<'_, ProxyWasmHostState>,
    map_id: i32,
    key_data: i32,
    key_size: i32,
    return_data: i32,
    return_size: i32,
) -> i32 {
    let key = match read_guest(&mut caller, key_data, key_size).and_then(parse_guest_text) {
        Ok(key) => key,
        Err(status) => return status,
    };
    let value = match current_map(&caller, map_id) {
        Ok(headers) => headers
            .iter()
            .find(|(name, _)| header_name_matches(name, &key))
            .map(|(_, value)| value.as_bytes().to_vec()),
        Err(status) => return status,
    };
    match value {
        Some(value) => return_bytes(&mut caller, &value, return_data, return_size),
        None => STATUS_NOT_FOUND,
    }
}

fn host_add_header_map_value(
    mut caller: Caller<'_, ProxyWasmHostState>,
    map_id: i32,
    key_data: i32,
    key_size: i32,
    value_data: i32,
    value_size: i32,
) -> i32 {
    let header = match read_guest_header(&mut caller, key_data, key_size, value_data, value_size) {
        Ok(header) => header,
        Err(status) => return status,
    };
    match current_map_mut(&mut caller, map_id) {
        Ok(headers) => headers.push(header),
        Err(status) => return status,
    }
    enforce_map_output_limit(&mut caller).map_or_else(|status| status, |()| STATUS_OK)
}

fn host_replace_header_map_value(
    mut caller: Caller<'_, ProxyWasmHostState>,
    map_id: i32,
    key_data: i32,
    key_size: i32,
    value_data: i32,
    value_size: i32,
) -> i32 {
    let (key, value) =
        match read_guest_header(&mut caller, key_data, key_size, value_data, value_size) {
            Ok(header) => header,
            Err(status) => return status,
        };
    let headers = match current_map_mut(&mut caller, map_id) {
        Ok(headers) => headers,
        Err(status) => return status,
    };
    headers.retain(|(name, _)| !header_name_matches(name, &key));
    headers.push((key, value));
    enforce_map_output_limit(&mut caller).map_or_else(|status| status, |()| STATUS_OK)
}

fn host_remove_header_map_value(
    mut caller: Caller<'_, ProxyWasmHostState>,
    map_id: i32,
    key_data: i32,
    key_size: i32,
) -> i32 {
    let key = match read_guest(&mut caller, key_data, key_size).and_then(parse_guest_text) {
        Ok(key) => key,
        Err(status) => return status,
    };
    match current_map_mut(&mut caller, map_id) {
        Ok(headers) => {
            headers.retain(|(name, _)| !header_name_matches(name, &key));
            STATUS_OK
        }
        Err(status) => status,
    }
}

fn host_continue_stream(mut caller: Caller<'_, ProxyWasmHostState>, stream_type: i32) -> i32 {
    if !matches!(stream_type, 0 | 1) {
        return STATUS_BAD_ARGUMENT;
    }
    caller.data_mut().continue_requested = true;
    STATUS_OK
}

fn host_close_stream(mut caller: Caller<'_, ProxyWasmHostState>, stream_type: i32) -> i32 {
    if !matches!(stream_type, 0 | 1) {
        return STATUS_BAD_ARGUMENT;
    }
    caller.data_mut().close_requested = true;
    STATUS_OK
}

fn host_set_effective_context(mut caller: Caller<'_, ProxyWasmHostState>, context_id: i32) -> i32 {
    let context_id = context_id as u32;
    if !matches!(context_id, ROOT_CONTEXT_ID | HTTP_CONTEXT_ID) {
        return STATUS_BAD_ARGUMENT;
    }
    caller.data_mut().active_context = context_id;
    STATUS_OK
}

// The eight arguments are fixed by Proxy-Wasm ABI 0.2.1.
#[allow(clippy::too_many_arguments)]
fn host_send_local_response(
    mut caller: Caller<'_, ProxyWasmHostState>,
    status: i32,
    details_data: i32,
    details_size: i32,
    body_data: i32,
    body_size: i32,
    headers_data: i32,
    headers_size: i32,
    grpc_status: i32,
) -> i32 {
    let Ok(status) = u16::try_from(status) else {
        return STATUS_BAD_ARGUMENT;
    };
    if !(100..=599).contains(&status) || caller.data().local_response.is_some() {
        return STATUS_BAD_ARGUMENT;
    }
    if abi_usize(details_size) > 512
        || abi_usize(body_size) > caller.data().max_output_bytes
        || abi_usize(headers_size) > caller.data().max_output_bytes
    {
        caller.data_mut().fail(ProxyWasmCallFailure::OutputLimit);
        return STATUS_BAD_ARGUMENT;
    }
    if read_guest(&mut caller, details_data, details_size).is_err() {
        return STATUS_INVALID_MEMORY_ACCESS;
    }
    let body = match read_guest(&mut caller, body_data, body_size) {
        Ok(body) => body,
        Err(status) => return status,
    };
    let serialized_headers = match read_guest(&mut caller, headers_data, headers_size) {
        Ok(headers) => headers,
        Err(status) => return status,
    };
    let headers = match parse_headers(&serialized_headers) {
        Ok(headers) => headers,
        Err(ProxyWasmCallFailure::OutputLimit) => {
            caller.data_mut().fail(ProxyWasmCallFailure::OutputLimit);
            return STATUS_BAD_ARGUMENT;
        }
        Err(_) => return STATUS_PARSE_FAILURE,
    };
    if validate_headers(&headers, caller.data().max_output_bytes).is_err() {
        caller.data_mut().fail(ProxyWasmCallFailure::OutputLimit);
        return STATUS_BAD_ARGUMENT;
    }
    let grpc_status = grpc_status as u32;
    caller.data_mut().local_response = Some(ProxyWasmLocalResponse {
        status,
        grpc_status: (grpc_status != u32::MAX).then_some(grpc_status),
        headers,
        body: Bytes::from(body),
    });
    caller.data_mut().close_requested = true;
    STATUS_OK
}

fn host_done(mut caller: Caller<'_, ProxyWasmHostState>) -> i32 {
    let context_id = caller.data().active_context;
    if caller.data().context_finalization(context_id) != Some(ContextFinalization::Pending) {
        return STATUS_NOT_FOUND;
    }
    if caller
        .data_mut()
        .set_context_finalization(context_id, ContextFinalization::Ready)
        .is_some()
    {
        STATUS_OK
    } else {
        STATUS_NOT_FOUND
    }
}

fn proxy_wasm_linker(engine: &Engine) -> Result<Linker<ProxyWasmHostState>, ProxyWasmLoadFailure> {
    let mut linker = Linker::new(engine);
    let map_link_error = |_| ProxyWasmLoadFailure::RuntimeUnavailable;
    linker
        .func_wrap("env", "proxy_log", host_log)
        .map_err(map_link_error)?;
    linker
        .func_wrap("env", "proxy_get_log_level", host_get_log_level)
        .map_err(map_link_error)?;
    linker
        .func_wrap("env", "proxy_get_buffer_bytes", host_get_buffer_bytes)
        .map_err(map_link_error)?;
    linker
        .func_wrap("env", "proxy_set_buffer_bytes", host_set_buffer_bytes)
        .map_err(map_link_error)?;
    linker
        .func_wrap("env", "proxy_get_buffer_status", host_get_buffer_status)
        .map_err(map_link_error)?;
    linker
        .func_wrap("env", "proxy_get_header_map_size", host_get_header_map_size)
        .map_err(map_link_error)?;
    linker
        .func_wrap(
            "env",
            "proxy_get_header_map_pairs",
            host_get_header_map_pairs,
        )
        .map_err(map_link_error)?;
    linker
        .func_wrap(
            "env",
            "proxy_set_header_map_pairs",
            host_set_header_map_pairs,
        )
        .map_err(map_link_error)?;
    linker
        .func_wrap(
            "env",
            "proxy_get_header_map_value",
            host_get_header_map_value,
        )
        .map_err(map_link_error)?;
    linker
        .func_wrap(
            "env",
            "proxy_add_header_map_value",
            host_add_header_map_value,
        )
        .map_err(map_link_error)?;
    linker
        .func_wrap(
            "env",
            "proxy_replace_header_map_value",
            host_replace_header_map_value,
        )
        .map_err(map_link_error)?;
    linker
        .func_wrap(
            "env",
            "proxy_remove_header_map_value",
            host_remove_header_map_value,
        )
        .map_err(map_link_error)?;
    linker
        .func_wrap("env", "proxy_continue_stream", host_continue_stream)
        .map_err(map_link_error)?;
    linker
        .func_wrap("env", "proxy_close_stream", host_close_stream)
        .map_err(map_link_error)?;
    linker
        .func_wrap(
            "env",
            "proxy_set_effective_context",
            host_set_effective_context,
        )
        .map_err(map_link_error)?;
    linker
        .func_wrap("env", "proxy_send_local_response", host_send_local_response)
        .map_err(map_link_error)?;
    linker
        .func_wrap("env", "proxy_done", host_done)
        .map_err(map_link_error)?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::*;

    fn limits() -> WasmBundleLimits {
        WasmBundleLimits {
            budget: Duration::from_millis(50),
            memory_bytes: 16 * 1024 * 1024,
            stack_bytes: 512 * 1024,
            fuel: 100_000_000,
            max_input_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn unsupported_import_fails_before_candidate_publication() {
        let error = ProxyWasmRuntime::from_bundle_bytes(
            include_bytes!("testdata/proxy_wasm/unsupported-import.wasm"),
            limits(),
        )
        .unwrap_err();

        assert_eq!(error, ProxyWasmLoadFailure::UnsupportedImport);
    }

    #[test]
    fn abi_marker_requires_the_exact_signature() {
        let error = ProxyWasmRuntime::from_bundle_bytes(
            include_bytes!("testdata/proxy_wasm/wrong-marker.wasm"),
            limits(),
        )
        .unwrap_err();

        assert_eq!(error, ProxyWasmLoadFailure::InvalidAbi);
    }

    #[test]
    fn exported_callbacks_require_the_exact_signature() {
        let error = ProxyWasmRuntime::from_bundle_bytes(
            include_bytes!("testdata/proxy_wasm/wrong-callback.wasm"),
            limits(),
        )
        .unwrap_err();

        assert_eq!(error, ProxyWasmLoadFailure::InvalidCallback);
    }

    #[test]
    fn modules_must_define_exactly_one_linear_memory() {
        let error = ProxyWasmRuntime::from_bundle_bytes(
            include_bytes!("testdata/proxy_wasm/two-memories.wasm"),
            limits(),
        )
        .unwrap_err();

        assert_eq!(error, ProxyWasmLoadFailure::InvalidMemory);
    }

    #[test]
    fn guest_allocator_requires_the_exact_signature() {
        let error = ProxyWasmRuntime::from_bundle_bytes(
            include_bytes!("testdata/proxy_wasm/wrong-allocator.wasm"),
            limits(),
        )
        .unwrap_err();

        assert_eq!(error, ProxyWasmLoadFailure::InvalidMemory);
    }

    #[test]
    fn static_tables_must_fit_the_per_instance_ceiling() {
        let error = ProxyWasmRuntime::from_bundle_bytes(
            include_bytes!("testdata/proxy_wasm/oversized-table.wasm"),
            limits(),
        )
        .unwrap_err();

        assert_eq!(error, ProxyWasmLoadFailure::InvalidResource);
    }

    fn runtime(fixture: &str, limits: WasmBundleLimits) -> ProxyWasmRuntime {
        let bytes: &[u8] = match fixture {
            "deferred-done" => include_bytes!("testdata/proxy_wasm/deferred-done.wasm"),
            "grpc-response" => include_bytes!("testdata/proxy_wasm/grpc-response.wasm"),
            "http" => include_bytes!("testdata/proxy_wasm/http.wasm"),
            "log-headers" => include_bytes!("testdata/proxy_wasm/log-headers.wasm"),
            "log-levels" => include_bytes!("testdata/proxy_wasm/log-levels.wasm"),
            "loop" => include_bytes!("testdata/proxy_wasm/loop.wasm"),
            "memory" => include_bytes!("testdata/proxy_wasm/memory.wasm"),
            "output-limit" => include_bytes!("testdata/proxy_wasm/output-limit.wasm"),
            "sdk-lifecycle" => include_bytes!("testdata/proxy_wasm/sdk-lifecycle.wasm"),
            "stack" => include_bytes!("testdata/proxy_wasm/stack.wasm"),
            "start-trap" => include_bytes!("testdata/proxy_wasm/start-trap.wasm"),
            "table-grow" => include_bytes!("testdata/proxy_wasm/table-grow.wasm"),
            _ => panic!("unknown fixture"),
        };
        ProxyWasmRuntime::from_bundle_bytes(bytes, limits).unwrap()
    }

    #[test]
    fn vm_start_uses_an_existing_sdk_root_context() {
        let runtime = runtime("sdk-lifecycle", limits());

        let session = runtime.start_session(b"{}").unwrap();

        assert_eq!(
            session.lifecycle_trace(),
            ["root_create", "vm_start", "configure", "http_create"]
        );
    }

    #[test]
    fn deferred_done_waits_for_proxy_done_before_log_and_delete() {
        let mut session = runtime("deferred-done", limits())
            .start_session(b"{}")
            .unwrap();

        session.finish().unwrap();
        assert!(!session.is_finished());
        assert_eq!(
            session.lifecycle_trace(),
            [
                "root_create",
                "vm_start",
                "configure",
                "http_create",
                "http_done"
            ]
        );

        session.begin_callback().unwrap();
        session.store.data_mut().active_context = HTTP_CONTEXT_ID;
        session.call_void0("complete_pending").unwrap();
        session.finish().unwrap();

        assert!(session.is_finished());
        assert_eq!(
            &session.lifecycle_trace()[5..],
            [
                "http_log",
                "http_delete",
                "root_done",
                "root_log",
                "root_delete"
            ]
        );
    }

    #[test]
    fn on_log_can_read_retained_request_and_response_headers() {
        let mut session = runtime("log-headers", limits())
            .start_session(b"{}")
            .unwrap();

        session
            .on_request_headers(vec![("x-request".into(), "request-value".into())], false)
            .unwrap();
        session
            .on_response_headers(vec![("x-response".into(), "response-value".into())], true)
            .unwrap();

        session.finish().unwrap();
    }

    #[derive(Clone)]
    struct GuestLogLevelCapture {
        levels: Arc<Mutex<Vec<tracing::Level>>>,
    }

    impl tracing::Subscriber for GuestLogLevelCapture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target() == "sbproxy::proxy_wasm"
        }

        fn register_callsite(
            &self,
            _metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() == "sbproxy::proxy_wasm" {
                self.levels.lock().unwrap().push(*event.metadata().level());
            }
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[test]
    fn guest_logs_preserve_proxy_wasm_severity() {
        let levels = Arc::new(Mutex::new(Vec::new()));
        let capture = GuestLogLevelCapture {
            levels: Arc::clone(&levels),
        };
        let mut session = runtime("log-levels", limits())
            .start_session(b"{}")
            .unwrap();

        tracing::subscriber::with_default(capture, || {
            session.on_request_headers(Vec::new(), true).unwrap();
        });

        assert_eq!(
            *levels.lock().unwrap(),
            [
                tracing::Level::TRACE,
                tracing::Level::DEBUG,
                tracing::Level::INFO,
                tracing::Level::WARN,
                tracing::Level::ERROR,
                tracing::Level::ERROR,
            ]
        );
    }

    #[test]
    fn request_local_lifecycle_mutates_http_state_and_deletes_contexts() {
        let runtime = runtime("http", limits());
        let mut session = runtime.start_session(br#"{"enabled":true}"#).unwrap();

        let headers = vec![("x-input".to_owned(), "hello".to_owned())];
        let request_headers = session.on_request_headers(headers, false).unwrap();
        assert_eq!(request_headers.action, ProxyWasmAction::Continue);
        assert!(request_headers
            .headers
            .contains(&("x-seen".to_owned(), "hello".to_owned())));

        let request_body = session
            .on_request_body(bytes::Bytes::from_static(b"request"), false)
            .unwrap();
        assert_eq!(request_body.body.as_ref(), b"request");

        let response_headers = session.on_response_headers(Vec::new(), false).unwrap();
        assert!(response_headers
            .headers
            .contains(&("x-response".to_owned(), "filtered".to_owned())));
        let response_body = session
            .on_response_body(bytes::Bytes::from_static(b"origin"), true)
            .unwrap();
        assert_eq!(response_body.body.as_ref(), b"filtered");

        session.finish().unwrap();
        assert_eq!(
            session.lifecycle_trace(),
            [
                "root_create",
                "vm_start",
                "configure",
                "http_create",
                "request_headers",
                "request_body:chunk",
                "response_headers",
                "response_body:eos",
                "http_done",
                "http_log",
                "http_delete",
                "root_done",
                "root_log",
                "root_delete",
            ]
        );
    }

    #[test]
    fn pause_continue_close_and_local_response_are_distinct() {
        let runtime = runtime("http", limits());

        let mut paused = runtime.start_session(b"{}").unwrap();
        let result = paused
            .on_request_headers(vec![("x-pause".into(), "1".into())], false)
            .unwrap();
        assert_eq!(result.action, ProxyWasmAction::Pause);
        assert!(result.local_response.is_none());

        let mut continued = runtime.start_session(b"{}").unwrap();
        let result = continued
            .on_request_headers(vec![("x-continue".into(), "1".into())], false)
            .unwrap();
        assert_eq!(result.action, ProxyWasmAction::Continue);

        let mut closed = runtime.start_session(b"{}").unwrap();
        let result = closed
            .on_request_headers(vec![("x-close".into(), "1".into())], false)
            .unwrap();
        assert_eq!(result.action, ProxyWasmAction::Close);

        let mut blocked = runtime.start_session(b"{}").unwrap();
        let result = blocked
            .on_request_headers(vec![("x-block".into(), "1".into())], false)
            .unwrap();
        assert_eq!(result.action, ProxyWasmAction::Close);
        let response = result.local_response.unwrap();
        assert_eq!(response.status, 403);
        assert_eq!(response.body.as_ref(), b"blocked");
        assert_eq!(
            response.headers,
            [("content-type".to_owned(), "text/plain".to_owned())]
        );
        assert_eq!(response.grpc_status, None);
    }

    #[test]
    fn local_response_preserves_grpc_status() {
        let mut session = runtime("grpc-response", limits())
            .start_session(b"{}")
            .unwrap();

        let result = session.on_request_headers(Vec::new(), true).unwrap();
        let response = result.local_response.unwrap();

        assert_eq!(response.grpc_status, Some(7));
    }

    #[test]
    fn streamed_chunks_preserve_empty_chunks_and_explicit_end_of_stream() {
        let runtime = runtime("http", limits());
        let mut session = runtime.start_session(b"{}").unwrap();
        let mut output = Vec::new();
        for chunk in [
            bytes::Bytes::from_static(b"ab"),
            bytes::Bytes::new(),
            bytes::Bytes::from_static(b"cd"),
        ] {
            output.extend_from_slice(&session.on_request_body(chunk, false).unwrap().body);
        }
        let end = session.on_request_body(bytes::Bytes::new(), true).unwrap();
        output.extend_from_slice(&end.body);

        assert_eq!(output, b"abcd");
        assert_eq!(
            session.lifecycle_trace(),
            [
                "root_create",
                "vm_start",
                "configure",
                "http_create",
                "request_body:chunk",
                "request_body:chunk",
                "request_body:chunk",
                "request_body:eos",
            ]
        );
    }

    #[test]
    fn output_expansion_over_the_manifest_cap_fails_the_callback() {
        let mut tiny_limits = limits();
        tiny_limits.max_output_bytes = 8;
        let runtime = runtime("output-limit", tiny_limits);
        let mut session = runtime.start_session(b"{}").unwrap();

        assert_eq!(
            session
                .on_request_body(bytes::Bytes::new(), true)
                .unwrap_err(),
            ProxyWasmCallFailure::OutputLimit
        );
    }

    #[test]
    fn oversized_request_headers_are_an_input_failure() {
        let mut tiny_limits = limits();
        tiny_limits.max_input_bytes = 8;
        let runtime = runtime("http", tiny_limits);
        let mut session = runtime.start_session(b"{}").unwrap();

        assert_eq!(
            session
                .on_request_headers(vec![("x-input".into(), "too-long".into())], false)
                .unwrap_err(),
            ProxyWasmCallFailure::InputLimit
        );
    }

    #[test]
    fn callbacks_enforce_the_fuel_limit() {
        let mut fuel_limits = limits();
        fuel_limits.fuel = 1;
        let mut session = runtime("loop", fuel_limits).start_session(b"{}").unwrap();
        assert_eq!(
            session.on_request_headers(Vec::new(), true).unwrap_err(),
            ProxyWasmCallFailure::FuelLimit
        );
    }

    #[test]
    fn callbacks_enforce_the_wall_clock_limit() {
        let mut timeout_limits = limits();
        timeout_limits.budget = Duration::from_millis(2);
        timeout_limits.fuel = 1_000_000_000;
        let mut session = runtime("loop", timeout_limits)
            .start_session(b"{}")
            .unwrap();
        assert_eq!(
            session.on_request_headers(Vec::new(), true).unwrap_err(),
            ProxyWasmCallFailure::Timeout
        );
    }

    #[test]
    fn callbacks_enforce_the_memory_limit() {
        let mut memory_limits = limits();
        memory_limits.memory_bytes = 1024 * 1024;
        let mut session = runtime("memory", memory_limits)
            .start_session(b"{}")
            .unwrap();
        assert_eq!(
            session.on_request_headers(Vec::new(), true).unwrap_err(),
            ProxyWasmCallFailure::MemoryLimit
        );
    }

    #[test]
    fn callbacks_enforce_the_table_limit() {
        let mut session = runtime("table-grow", limits())
            .start_session(b"{}")
            .unwrap();
        assert_eq!(
            session.on_request_headers(Vec::new(), true).unwrap_err(),
            ProxyWasmCallFailure::ResourceLimit
        );
    }

    #[test]
    fn callbacks_enforce_the_stack_limit() {
        let mut stack_limits = limits();
        stack_limits.stack_bytes = 64 * 1024;
        let mut session = runtime("stack", stack_limits).start_session(b"{}").unwrap();
        assert_eq!(
            session.on_request_headers(Vec::new(), true).unwrap_err(),
            ProxyWasmCallFailure::StackLimit
        );
    }

    #[test]
    fn candidate_validation_does_not_execute_a_core_start_section() {
        let runtime = runtime("start-trap", limits());
        assert_eq!(
            runtime.start_session(b"{}").unwrap_err(),
            ProxyWasmCallFailure::GuestTrap
        );
    }
}
