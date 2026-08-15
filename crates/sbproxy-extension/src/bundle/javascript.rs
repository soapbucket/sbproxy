use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use rquickjs::promise::MaybePromise;
use rquickjs::{Context, Function, Module, Object, Runtime, Value as JavascriptValue};
use sbproxy_config::{BundleHook, BundleHookKind, BundleRuntime, BundleSandbox};
use sbproxy_plugin::{
    ActionHandler, ActionOutcome, AuthDecision, AuthProvider, PluginError, PluginResult,
    PolicyDecision, PolicyEnforcer, TransformContext, TransformHandler,
};
use serde_json::{json, Value};
use swc_common::{sync::Lrc, FileName, Globals, Mark, SourceMap, GLOBALS};
use swc_ecma_ast::{Callee, EsVersion, ModuleDecl, Program};
use swc_ecma_codegen::{text_writer::JsWriter, Config as CodegenConfig, Emitter};
use swc_ecma_parser::{parse_file_as_module, EsSyntax, Syntax, TsSyntax};
use swc_ecma_transforms_base::{fixer::fixer, resolver};
use swc_ecma_transforms_typescript::strip;
use swc_ecma_visit::{Visit, VisitWith};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

use super::envelope::{self, EnvelopeError};
use super::{BundleLoadError, LoadedBundleHook};
use crate::js::{arm_watchdog, arm_watchdog_until};

/// Version placed on every JavaScript hook request and response envelope.
pub const JAVASCRIPT_ENVELOPE_VERSION: &str = envelope::ENVELOPE_VERSION;
const MAX_JAVASCRIPT_WORKERS: usize = 4;
const QUEUE_SLOTS_PER_WORKER: usize = 2;

#[derive(Clone, Copy)]
struct RuntimeLimits {
    budget_ms: u64,
    memory_bytes: usize,
    stack_bytes: usize,
    max_input_bytes: usize,
    max_output_bytes: usize,
}

impl RuntimeLimits {
    fn from_sandbox(sandbox: &BundleSandbox) -> Result<Self, BundleLoadError> {
        Ok(Self {
            budget_ms: sandbox.budget_ms,
            memory_bytes: checked_limit(sandbox.memory_mb, 1024 * 1024, "memory")?,
            stack_bytes: checked_limit(sandbox.stack_kb, 1024, "stack")?,
            max_input_bytes: usize::try_from(sandbox.max_buffer_bytes)
                .map_err(|_| BundleLoadError::new("javascript", "input limit is unsupported"))?,
            max_output_bytes: usize::try_from(sandbox.max_output_bytes)
                .map_err(|_| BundleLoadError::new("javascript", "output limit is unsupported"))?,
        })
    }
}

fn checked_limit(value: u64, multiplier: usize, name: &str) -> Result<usize, BundleLoadError> {
    usize::try_from(value)
        .ok()
        .and_then(|value| value.checked_mul(multiplier))
        .ok_or_else(|| BundleLoadError::new("javascript", format!("{name} limit is unsupported")))
}

#[derive(Clone)]
pub(super) struct JavascriptProgram {
    source: Arc<str>,
    export: Arc<str>,
    hook_kind: &'static str,
    type_name: Arc<str>,
    config: Arc<Value>,
    /// `secret_vars ∪ masked_vars` var names from this hook's manifest
    /// (WOR-2289). Never printed as-is; `Debug` masks exactly these
    /// vars so a resolved secret or a masked literal never reaches a
    /// log or panic message.
    masked_names: Arc<Vec<String>>,
    limits: RuntimeLimits,
    executor: Arc<JavascriptExecutor>,
    /// Host-mediated outbound HTTP, present only when this hook
    /// declared `net:outbound` destinations (all operator-granted by
    /// the time a program exists; load refused anything else).
    outbound: Option<Arc<super::outbound::BundleOutbound>>,
}

impl std::fmt::Debug for JavascriptProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JavascriptProgram")
            .field("source_bytes", &self.source.len())
            .field("export", &self.export)
            .field("hook_kind", &self.hook_kind)
            .field("type_name", &self.type_name)
            .field(
                "config",
                &envelope::mask_declared_vars(&self.config, &self.masked_names),
            )
            .finish_non_exhaustive()
    }
}

impl JavascriptProgram {
    pub(super) async fn invoke(
        &self,
        payload_name: &str,
        payload: Value,
    ) -> Result<Vec<u8>, PluginError> {
        invoke_program(self, hook_envelope(payload_name, self, payload)).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeFailure {
    Timeout,
    Code(&'static str),
}

impl RuntimeFailure {
    fn into_plugin_error(self) -> PluginError {
        match self {
            Self::Timeout => PluginError::Timeout,
            Self::Code(code) => {
                PluginError::Internal(anyhow::anyhow!("javascript bundle hook failed: {code}"))
            }
        }
    }
}

impl From<EnvelopeError> for RuntimeFailure {
    fn from(error: EnvelopeError) -> Self {
        Self::Code(error.code())
    }
}

struct JavascriptJob {
    program: JavascriptProgram,
    input: Vec<u8>,
    deadline: Instant,
    reply: oneshot::Sender<Result<Vec<u8>, RuntimeFailure>>,
    _permit: OwnedSemaphorePermit,
}

struct JavascriptExecutor {
    sender: mpsc::Sender<JavascriptJob>,
    admission: Arc<Semaphore>,
}

impl JavascriptExecutor {
    fn start(worker_count: usize, queue_capacity: usize) -> Self {
        let worker_count = worker_count.max(1);
        let queue_capacity = queue_capacity.max(1);
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_index in 0..worker_count {
            let receiver = Arc::clone(&receiver);
            std::thread::Builder::new()
                .name(format!("sbproxy-js-worker-{worker_index}"))
                .spawn(move || javascript_worker(receiver))
                .expect("JavaScript worker thread should start");
        }
        Self {
            sender,
            admission: Arc::new(Semaphore::new(worker_count + queue_capacity)),
        }
    }

    async fn execute(
        &self,
        program: JavascriptProgram,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, RuntimeFailure> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(program.limits.budget_ms))
            .ok_or(RuntimeFailure::Code("runtime_unavailable"))?;
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let permit = Arc::clone(&self.admission)
                .acquire_owned()
                .await
                .map_err(|_| RuntimeFailure::Code("runtime_unavailable"))?;
            let (reply, response) = oneshot::channel();
            self.sender
                .send(JavascriptJob {
                    program,
                    input,
                    deadline,
                    reply,
                    _permit: permit,
                })
                .await
                .map_err(|_| RuntimeFailure::Code("runtime_unavailable"))?;
            response
                .await
                .map_err(|_| RuntimeFailure::Code("runtime_unavailable"))?
        })
        .await;
        result.unwrap_or(Err(RuntimeFailure::Timeout))
    }

    #[cfg(test)]
    fn available_admission(&self) -> usize {
        self.admission.available_permits()
    }

    #[cfg(test)]
    fn available_queue(&self) -> usize {
        self.sender.capacity()
    }
}

fn default_executor() -> JavascriptExecutor {
    let worker_count = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(2)
        .clamp(1, MAX_JAVASCRIPT_WORKERS);
    JavascriptExecutor::start(worker_count, worker_count * QUEUE_SLOTS_PER_WORKER)
}

static JAVASCRIPT_EXECUTOR: LazyLock<Arc<JavascriptExecutor>> =
    LazyLock::new(|| Arc::new(default_executor()));

fn javascript_worker(receiver: Arc<Mutex<mpsc::Receiver<JavascriptJob>>>) {
    let mut runtime = None;
    loop {
        let job = {
            let mut receiver = receiver
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            receiver.blocking_recv()
        };
        let Some(job) = job else {
            return;
        };
        if runtime.is_none() {
            runtime = WorkerRuntime::new().ok();
        }
        let (result, poisoned) = match runtime.as_mut() {
            Some(runtime) => runtime.invoke(&job.program, &job.input, job.deadline),
            None => (Err(RuntimeFailure::Code("runtime_unavailable")), true),
        };
        if poisoned {
            runtime = None;
        }
        let _ = job.reply.send(result);
    }
}

struct WorkerRuntime {
    runtime: Runtime,
    interrupt: Arc<AtomicBool>,
}

enum InvokeFailure {
    Guest,
    Timeout,
    OutputLimit,
}

impl From<rquickjs::Error> for InvokeFailure {
    fn from(error: rquickjs::Error) -> Self {
        // Bundle guests have no host I/O or Rust futures. Once QuickJS has no
        // pending jobs, a still-pending Promise cannot make further progress.
        if matches!(error, rquickjs::Error::WouldBlock) {
            Self::Timeout
        } else {
            Self::Guest
        }
    }
}

impl WorkerRuntime {
    fn new() -> rquickjs::Result<Self> {
        let runtime = Runtime::new()?;
        let interrupt = Arc::new(AtomicBool::new(false));
        let handler_interrupt = Arc::clone(&interrupt);
        runtime.set_interrupt_handler(Some(Box::new(move || {
            handler_interrupt.load(Ordering::Relaxed)
        })));
        Ok(Self { runtime, interrupt })
    }

    fn invoke(
        &mut self,
        program: &JavascriptProgram,
        input: &[u8],
        deadline: Instant,
    ) -> (Result<Vec<u8>, RuntimeFailure>, bool) {
        if deadline <= Instant::now() {
            return (Err(RuntimeFailure::Timeout), false);
        }
        self.runtime.set_memory_limit(program.limits.memory_bytes);
        self.runtime.set_max_stack_size(program.limits.stack_bytes);
        let watchdog = match arm_watchdog_until(Arc::clone(&self.interrupt), deadline) {
            Ok(watchdog) => watchdog,
            Err(_) => return (Err(RuntimeFailure::Timeout), true),
        };
        let result = Context::full(&self.runtime)
            .map_err(InvokeFailure::from)
            .and_then(|context| {
                context.with(|context| {
                    invoke_in_context(
                        &context,
                        &program.source,
                        &program.export,
                        input,
                        program.limits.max_output_bytes,
                        program
                            .outbound
                            .as_ref()
                            .map(|outbound| (Arc::clone(outbound), deadline)),
                    )
                })
            })
            .map_err(|failure| match failure {
                InvokeFailure::Guest => RuntimeFailure::Code("guest_exception"),
                InvokeFailure::Timeout => RuntimeFailure::Timeout,
                InvokeFailure::OutputLimit => RuntimeFailure::Code("output_limit"),
            });
        let interrupted = watchdog.finish();
        self.interrupt.store(false, Ordering::Relaxed);
        if interrupted {
            return (Err(RuntimeFailure::Timeout), true);
        }
        let poisoned = result.is_err();
        (result, poisoned)
    }
}

fn invoke_in_context(
    context: &rquickjs::Ctx<'_>,
    source: &str,
    export: &str,
    input: &[u8],
    max_output_bytes: usize,
    outbound: Option<(Arc<super::outbound::BundleOutbound>, Instant)>,
) -> Result<Vec<u8>, InvokeFailure> {
    let globals = context.globals();
    globals.remove("eval")?;
    globals.remove("Function")?;
    if let Some((outbound, deadline)) = outbound {
        // Synchronous by design: the worker thread blocks in the host
        // for the duration of the call, bounded by the invocation's
        // remaining budget. The QuickJS interrupt watchdog cannot
        // preempt a host function, so the fetch's own deadline-derived
        // timeouts are the enforcement while control is out of the
        // interpreter. The reply is always a JSON envelope string;
        // refusals arrive as `{"error": "..."}` rather than
        // exceptions, so a guest cannot distinguish refusal shapes
        // beyond the bounded reason label.
        let host_fetch = rquickjs::function::Func::from(move |request: String| -> String {
            outbound.fetch(&request, deadline)
        });
        globals.set("sbproxy_fetch", host_fetch)?;
    }

    let module = Module::declare(context.clone(), "sbproxy-bundle.js", source.as_bytes())?;
    let (module, ready) = module.eval()?;
    ready.finish::<()>()?;
    let function: Function = module.get(export)?;

    let input = std::str::from_utf8(input).map_err(|_| InvokeFailure::Guest)?;
    let json: Object = globals.get("JSON")?;
    let parse: Function = json.get("parse")?;
    let input: JavascriptValue = parse.call((input,))?;
    let result: MaybePromise = function.call((input,))?;
    let result: JavascriptValue = result.finish()?;
    let stringify: Function = json.get("stringify")?;
    let serialized: JavascriptValue = stringify.call((result,))?;
    let serialized = serialized
        .into_string()
        .ok_or(rquickjs::Error::Unknown)?
        .to_string()?;
    if serialized.len() > max_output_bytes {
        return Err(InvokeFailure::OutputLimit);
    }
    Ok(serialized.into_bytes())
}

fn preflight_exports(
    source: &str,
    exports: &[&str],
    limits: RuntimeLimits,
) -> Result<(), BundleLoadError> {
    let runtime = WorkerRuntime::new()
        .map_err(|_| BundleLoadError::new("javascript", "QuickJS runtime could not be created"))?;
    runtime.runtime.set_memory_limit(limits.memory_bytes);
    runtime.runtime.set_max_stack_size(limits.stack_bytes);
    let watchdog = arm_watchdog(
        Arc::clone(&runtime.interrupt),
        Duration::from_millis(limits.budget_ms),
    )
    .map_err(|_| {
        BundleLoadError::new("javascript", "bundle initialization runtime is unavailable")
    })?;
    enum PreflightFailure {
        Module,
        Export,
    }
    let result = Context::full(&runtime.runtime)
        .map_err(|_| PreflightFailure::Module)
        .and_then(|context| {
            context.with(|context| {
                let globals = context.globals();
                globals
                    .remove("eval")
                    .map_err(|_| PreflightFailure::Module)?;
                globals
                    .remove("Function")
                    .map_err(|_| PreflightFailure::Module)?;
                let module =
                    Module::declare(context.clone(), "sbproxy-bundle.js", source.as_bytes())
                        .map_err(|_| PreflightFailure::Module)?;
                let (module, ready) = module.eval().map_err(|_| PreflightFailure::Module)?;
                ready.finish::<()>().map_err(|_| PreflightFailure::Module)?;
                for export in exports {
                    let _: Function = module.get(*export).map_err(|_| PreflightFailure::Export)?;
                }
                Ok(())
            })
        });
    let interrupted = watchdog.finish();
    if interrupted {
        return Err(BundleLoadError::new(
            "javascript",
            "bundle initialization exceeded its time budget",
        ));
    }
    result.map_err(|failure| match failure {
        PreflightFailure::Module => {
            BundleLoadError::new("javascript", "bundle module could not be evaluated")
        }
        PreflightFailure::Export => BundleLoadError::new(
            "javascript",
            "declared export is missing or is not a function",
        ),
    })
}

pub(super) fn prepare_javascript_artifact(
    artifact: &[u8],
    entry: &str,
    hooks: &[BundleHook],
    sandbox: &BundleSandbox,
) -> Result<Arc<str>, BundleLoadError> {
    let source = std::str::from_utf8(artifact)
        .map_err(|_| BundleLoadError::new("javascript", "source must be UTF-8"))?;
    let source = if entry.ends_with(".ts") {
        transpile_typescript(source, entry)?
    } else {
        validate_direct_javascript(source, entry)?;
        source.to_owned()
    };
    let exports = hooks
        .iter()
        .filter_map(|hook| hook.export.as_deref())
        .collect::<Vec<_>>();
    preflight_exports(&source, &exports, RuntimeLimits::from_sandbox(sandbox)?)?;
    Ok(Arc::from(source))
}

/// Transpile one dependency-free TypeScript module to ES2020 JavaScript.
///
/// Imports are rejected because the proxy has no package manager or module
/// resolver. A bundle that uses dependencies must supply one prebuilt flat
/// JavaScript artifact.
///
/// # Errors
///
/// Returns a bounded load error for invalid TypeScript, imports, or code
/// generation failures. Source text and filenames are not included in errors.
pub fn transpile_typescript(source: &str, filename: &str) -> Result<String, BundleLoadError> {
    let (source_map, program) =
        parse_javascript_program(source, filename, Syntax::Typescript(TsSyntax::default()))?;
    reject_imports(&program)?;
    let program = GLOBALS.set(&Globals::default(), || {
        let unresolved_mark = Mark::new();
        let top_level_mark = Mark::new();
        program
            .apply(resolver(unresolved_mark, top_level_mark, true))
            .apply(strip(unresolved_mark, top_level_mark))
            .apply(fixer(None))
    });

    let mut output = Vec::new();
    {
        let mut emitter = Emitter {
            cfg: CodegenConfig::default().with_target(EsVersion::Es2020),
            cm: source_map.clone(),
            comments: None,
            wr: JsWriter::new(source_map, "\n", &mut output, None),
        };
        emitter
            .emit_program(&program)
            .map_err(|_| BundleLoadError::new("javascript", "TypeScript code generation failed"))?;
    }
    String::from_utf8(output)
        .map_err(|_| BundleLoadError::new("javascript", "TypeScript output was not UTF-8"))
}

fn validate_direct_javascript(source: &str, filename: &str) -> Result<(), BundleLoadError> {
    let (_, program) = parse_javascript_program(source, filename, Syntax::Es(EsSyntax::default()))?;
    reject_imports(&program)
}

fn parse_javascript_program(
    source: &str,
    filename: &str,
    syntax: Syntax,
) -> Result<(Lrc<SourceMap>, Program), BundleLoadError> {
    let source_map: Lrc<SourceMap> = Default::default();
    let source_file = source_map.new_source_file(
        FileName::Custom(filename.to_owned()).into(),
        source.to_owned(),
    );
    let mut recovered = Vec::new();
    let module = parse_file_as_module(
        &source_file,
        syntax,
        EsVersion::Es2020,
        None,
        &mut recovered,
    )
    .map_err(|_| BundleLoadError::new("javascript", "source is not valid ES2020"))?;
    if !recovered.is_empty() {
        return Err(BundleLoadError::new(
            "javascript",
            "source is not valid ES2020",
        ));
    }
    Ok((source_map, Program::Module(module)))
}

#[derive(Default)]
struct ImportDetector {
    found: bool,
}

impl Visit for ImportDetector {
    fn visit_module_decl(&mut self, declaration: &ModuleDecl) {
        self.found |= match declaration {
            ModuleDecl::Import(_) | ModuleDecl::ExportAll(_) | ModuleDecl::TsImportEquals(_) => {
                true
            }
            ModuleDecl::ExportNamed(named) => named.src.is_some(),
            _ => false,
        };
        declaration.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, expression: &swc_ecma_ast::CallExpr) {
        self.found |= matches!(expression.callee, Callee::Import(_));
        expression.visit_children_with(self);
    }
}

fn reject_imports(program: &Program) -> Result<(), BundleLoadError> {
    let mut detector = ImportDetector::default();
    program.visit_with(&mut detector);
    if detector.found {
        return Err(BundleLoadError::new(
            "javascript",
            "imports are unavailable; bundle dependencies into one prebuilt single-file .js artifact",
        ));
    }
    Ok(())
}

pub(super) fn prepare_program(
    hook: &LoadedBundleHook,
    expected_kind: BundleHookKind,
    config: Value,
) -> Result<(String, JavascriptProgram), BundleLoadError> {
    if hook.manifest().runtime != BundleRuntime::Javascript || hook.hook().kind != expected_kind {
        return Err(BundleLoadError::new(
            "javascript",
            "hook kind does not match the requested JavaScript adapter",
        ));
    }
    let export = hook.hook().export.as_deref().ok_or_else(|| {
        BundleLoadError::new("javascript", "JavaScript hook needs a declared export")
    })?;
    let mut config = config;
    if let Some(schema) = hook.hook().config_schema.as_ref() {
        envelope::apply_schema_defaults(&mut config, schema);
    }
    // WOR-2289: resolve secret references in the hook's declared
    // `secret_vars` before it ever runs. Validation runs on the
    // resolved value (not the reference) so a schema constraint on the
    // value's shape (a `pattern`, for instance) checks the real secret
    // rather than the pointer to it.
    envelope::resolve_declared_secrets(&mut config, &hook.hook().secret_vars)
        .map_err(|detail| BundleLoadError::new("config", detail))?;
    hook.validate_config(&config)
        .map_err(|error| BundleLoadError::new("config", error.to_string()))?;

    let source = hook.prepared_javascript_source().ok_or_else(|| {
        BundleLoadError::new("javascript", "bundle has no prepared JavaScript artifact")
    })?;
    let limits = RuntimeLimits::from_sandbox(&hook.manifest().sandbox)?;
    let type_name = hook.hook().type_name.clone();
    let masked_names: Vec<String> = hook
        .hook()
        .secret_vars
        .iter()
        .chain(&hook.hook().masked_vars)
        .cloned()
        .collect();
    let destinations: Vec<sbproxy_config::OutboundDestination> = hook
        .hook()
        .permissions
        .iter()
        .filter_map(|entry| sbproxy_config::parse_permission_entry(entry).ok())
        .collect();
    let outbound = (!destinations.is_empty()).then(|| {
        super::outbound::BundleOutbound::new(
            &hook.manifest().name,
            &destinations,
            limits.max_input_bytes,
        )
    });
    Ok((
        type_name.clone(),
        JavascriptProgram {
            source: Arc::clone(source),
            export: Arc::from(export),
            hook_kind: envelope::hook_kind_label(expected_kind),
            type_name: Arc::from(type_name),
            config: Arc::new(config),
            masked_names: Arc::new(masked_names),
            limits,
            executor: Arc::clone(&JAVASCRIPT_EXECUTOR),
            outbound,
        },
    ))
}

fn request_value(request: &http::Request<Bytes>, maximum: usize) -> Result<Value, RuntimeFailure> {
    envelope::request_value(request, maximum).map_err(Into::into)
}

fn serialize_envelope(envelope: &Value, maximum: usize) -> Result<Vec<u8>, RuntimeFailure> {
    envelope::serialize_envelope(envelope, maximum).map_err(Into::into)
}

async fn invoke_program(
    program: &JavascriptProgram,
    envelope: Value,
) -> Result<Vec<u8>, PluginError> {
    let input = serialize_envelope(&envelope, program.limits.max_input_bytes)
        .map_err(RuntimeFailure::into_plugin_error)?;
    program
        .executor
        .execute(program.clone(), input)
        .await
        .map_err(RuntimeFailure::into_plugin_error)
}

fn hook_envelope(payload_name: &str, program: &JavascriptProgram, payload: Value) -> Value {
    envelope::hook_envelope(
        payload_name,
        program.hook_kind,
        program.type_name.as_ref(),
        program.config.as_ref(),
        payload,
    )
}

fn decode_policy(bytes: &[u8]) -> Result<PolicyDecision, RuntimeFailure> {
    envelope::decode_policy(bytes).map_err(Into::into)
}

fn decode_auth(bytes: &[u8]) -> Result<AuthDecision, RuntimeFailure> {
    envelope::decode_auth(bytes).map_err(Into::into)
}

fn decode_body(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, RuntimeFailure> {
    envelope::decode_body(bytes, maximum).map_err(Into::into)
}

fn decode_action(bytes: &[u8], maximum: usize) -> Result<ActionOutcome, RuntimeFailure> {
    envelope::decode_action(bytes, maximum).map_err(Into::into)
}

/// Buffered JavaScript policy adapter backed by the shared worker pool.
pub struct JavascriptPolicyAdapter {
    type_name: String,
    program: JavascriptProgram,
}

impl std::fmt::Debug for JavascriptPolicyAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JavascriptPolicyAdapter")
            .field("type_name", &self.type_name)
            .field("program", &self.program)
            .finish()
    }
}

/// Build a policy adapter from a validated JavaScript bundle hook.
///
/// # Errors
///
/// Returns a bounded load error for a mismatched hook, invalid attachment
/// config, invalid source, missing export, or failed module initialization.
pub fn build_javascript_policy(
    hook: &LoadedBundleHook,
    config: Value,
) -> Result<JavascriptPolicyAdapter, BundleLoadError> {
    let (type_name, program) = prepare_program(hook, BundleHookKind::Policy, config)?;
    Ok(JavascriptPolicyAdapter { type_name, program })
}

impl PolicyEnforcer for JavascriptPolicyAdapter {
    fn policy_type(&self) -> &str {
        &self.type_name
    }

    fn enforce(
        &self,
        request: &http::Request<Bytes>,
        _context: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn std::future::Future<Output = PluginResult<PolicyDecision>> + Send + '_>> {
        let request = request_value(request, self.program.limits.max_input_bytes);
        Box::pin(async move {
            let request = request.map_err(RuntimeFailure::into_plugin_error)?;
            let output = invoke_program(
                &self.program,
                hook_envelope("request", &self.program, request),
            )
            .await?;
            decode_policy(&output).map_err(RuntimeFailure::into_plugin_error)
        })
    }
}

/// Buffered JavaScript auth adapter backed by the shared worker pool.
pub struct JavascriptAuthAdapter {
    type_name: String,
    program: JavascriptProgram,
}

impl std::fmt::Debug for JavascriptAuthAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JavascriptAuthAdapter")
            .field("type_name", &self.type_name)
            .field("program", &self.program)
            .finish()
    }
}

/// Build an auth adapter from a validated JavaScript bundle hook.
///
/// # Errors
///
/// Returns a bounded load error for a mismatched hook, invalid attachment
/// config, invalid source, missing export, or failed module initialization.
pub fn build_javascript_auth(
    hook: &LoadedBundleHook,
    config: Value,
) -> Result<JavascriptAuthAdapter, BundleLoadError> {
    let (type_name, program) = prepare_program(hook, BundleHookKind::Auth, config)?;
    Ok(JavascriptAuthAdapter { type_name, program })
}

impl AuthProvider for JavascriptAuthAdapter {
    fn auth_type(&self) -> &str {
        &self.type_name
    }

    fn authenticate(
        &self,
        req: &http::Request<Bytes>,
        _ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn std::future::Future<Output = PluginResult<AuthDecision>> + Send + '_>> {
        let request = request_value(req, self.program.limits.max_input_bytes);
        Box::pin(async move {
            let request = request.map_err(RuntimeFailure::into_plugin_error)?;
            let output = invoke_program(
                &self.program,
                hook_envelope("request", &self.program, request),
            )
            .await?;
            decode_auth(&output).map_err(RuntimeFailure::into_plugin_error)
        })
    }
}

/// Buffered JavaScript body-transform adapter backed by the shared worker pool.
pub struct JavascriptTransformAdapter {
    type_name: String,
    program: JavascriptProgram,
}

impl std::fmt::Debug for JavascriptTransformAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JavascriptTransformAdapter")
            .field("type_name", &self.type_name)
            .field("program", &self.program)
            .finish()
    }
}

/// Build a transform adapter from a validated JavaScript bundle hook.
///
/// # Errors
///
/// Returns a bounded load error under the same contract as
/// [`build_javascript_policy`].
pub fn build_javascript_transform(
    hook: &LoadedBundleHook,
    config: Value,
) -> Result<JavascriptTransformAdapter, BundleLoadError> {
    let (type_name, program) = prepare_program(hook, BundleHookKind::Transform, config)?;
    Ok(JavascriptTransformAdapter { type_name, program })
}

impl TransformHandler for JavascriptTransformAdapter {
    fn transform_type(&self) -> &str {
        &self.type_name
    }

    fn apply<'a>(
        &'a self,
        body: &'a mut BytesMut,
        content_type: Option<&'a str>,
        context: &'a TransformContext<'a>,
    ) -> Pin<Box<dyn std::future::Future<Output = PluginResult<()>> + Send + 'a>> {
        let input = if body.len() > self.program.limits.max_input_bytes {
            Err(RuntimeFailure::Code("input_limit"))
        } else {
            Ok(json!({
                "body_base64": base64::engine::general_purpose::STANDARD.encode(&body[..]),
                "content_type": content_type,
                "origin": context.origin,
            }))
        };
        Box::pin(async move {
            let input = input.map_err(RuntimeFailure::into_plugin_error)?;
            let output =
                invoke_program(&self.program, hook_envelope("body", &self.program, input)).await?;
            let replacement = decode_body(&output, self.program.limits.max_output_bytes)
                .map_err(RuntimeFailure::into_plugin_error)?;
            body.clear();
            body.extend_from_slice(&replacement);
            Ok(())
        })
    }
}

/// Buffered JavaScript action adapter backed by the shared worker pool.
pub struct JavascriptActionAdapter {
    type_name: String,
    program: JavascriptProgram,
}

impl std::fmt::Debug for JavascriptActionAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JavascriptActionAdapter")
            .field("type_name", &self.type_name)
            .field("program", &self.program)
            .finish()
    }
}

/// Build an action adapter from a validated JavaScript bundle hook.
///
/// # Errors
///
/// Returns a bounded load error under the same contract as
/// [`build_javascript_policy`].
pub fn build_javascript_action(
    hook: &LoadedBundleHook,
    config: Value,
) -> Result<JavascriptActionAdapter, BundleLoadError> {
    let (type_name, program) = prepare_program(hook, BundleHookKind::Action, config)?;
    Ok(JavascriptActionAdapter { type_name, program })
}

impl ActionHandler for JavascriptActionAdapter {
    fn handler_type(&self) -> &str {
        &self.type_name
    }

    fn handle(
        &self,
        request: &mut http::Request<Bytes>,
        _context: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn std::future::Future<Output = PluginResult<ActionOutcome>> + Send + '_>> {
        let request = request_value(request, self.program.limits.max_input_bytes);
        Box::pin(async move {
            let request = request.map_err(RuntimeFailure::into_plugin_error)?;
            let output = invoke_program(
                &self.program,
                hook_envelope("request", &self.program, request),
            )
            .await?;
            decode_action(&output, self.program.limits.max_output_bytes)
                .map_err(RuntimeFailure::into_plugin_error)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::{Bytes, BytesMut};
    use sbproxy_config::{BundleHookKind, ExtensionBundlesConfig};
    use sbproxy_plugin::{
        ActionHandler, ActionOutcome, AuthDecision, AuthDenialKind, AuthProvider,
        AuthSubjectSource, PolicyDecision, PolicyEnforcer, TransformContext, TransformHandler,
    };
    use serde_json::{json, Value};
    use tempfile::TempDir;

    use super::{
        build_javascript_action, build_javascript_auth, build_javascript_policy,
        build_javascript_transform, decode_policy, hook_envelope, prepare_program, request_value,
        serialize_envelope, transpile_typescript, JavascriptExecutor, JAVASCRIPT_ENVELOPE_VERSION,
    };
    use crate::bundle::{BundleRegistry, DynamicBundleRegistry, LoadedBundleHook};

    struct HookFixture {
        _directory: TempDir,
        registry: Arc<DynamicBundleRegistry>,
        kind: BundleHookKind,
        type_name: String,
    }

    impl HookFixture {
        fn hook(&self) -> &LoadedBundleHook {
            match self.kind {
                BundleHookKind::Policy => self.registry.policy(&self.type_name),
                BundleHookKind::Auth => self.registry.auth(&self.type_name),
                BundleHookKind::Transform => self.registry.transform(&self.type_name),
                BundleHookKind::Action => self.registry.action(&self.type_name),
                _ => unreachable!("fixture supports request hooks only"),
            }
            .expect("fixture hook should be loaded")
        }
    }

    fn fixture(
        kind: BundleHookKind,
        entry: &str,
        source: &str,
        sandbox: &str,
        config_schema: &str,
    ) -> HookFixture {
        try_fixture(kind, entry, source, sandbox, config_schema).expect("fixture should load")
    }

    fn try_fixture(
        kind: BundleHookKind,
        entry: &str,
        source: &str,
        sandbox: &str,
        config_schema: &str,
    ) -> Result<HookFixture, crate::bundle::BundleLoadError> {
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir_all(&bundle).unwrap();
        let kind_name = match kind {
            BundleHookKind::Policy => "policy",
            BundleHookKind::Auth => "auth",
            BundleHookKind::Transform => "transform",
            BundleHookKind::Action => "action",
            _ => unreachable!("fixture supports request hooks only"),
        };
        let type_name = format!("javascript_{kind_name}_fixture");
        std::fs::write(bundle.join(entry), source).unwrap();
        std::fs::write(
            bundle.join("bundle.yaml"),
            format!(
                "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: javascript-fixture\nversion: 1.0.0\nruntime: javascript\nentry: {entry}\nhooks:\n  - kind: {kind_name}\n    type: {type_name}\n    export: run\n{config_schema}{sandbox}"
            ),
        )
        .unwrap();
        let config = ExtensionBundlesConfig {
            bundles_dir: Some(directory.path().display().to_string()),
            sources: Vec::new(),
            grants: Default::default(),
        };
        let registry = DynamicBundleRegistry::load(&config, directory.path(), &BTreeSet::new())?;
        Ok(HookFixture {
            _directory: directory,
            registry,
            kind,
            type_name,
        })
    }

    fn request(body: &'static [u8]) -> http::Request<Bytes> {
        http::Request::builder()
            .method("POST")
            .uri("https://test.sbproxy.dev/widgets")
            .header("x-plan", "free")
            .body(Bytes::from_static(body))
            .unwrap()
    }

    fn allow_source() -> &'static str {
        include_str!("testdata/javascript/direct-policy.js")
    }

    fn invocation_input(program: &super::JavascriptProgram) -> Vec<u8> {
        let request = request_value(&request(b""), program.limits.max_input_bytes).unwrap();
        let input = hook_envelope("request", program, request);
        serialize_envelope(&input, program.limits.max_input_bytes).unwrap()
    }

    async fn wait_until(description: &str, condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {description}"));
    }

    #[test]
    fn javascript_transpiles_typescript_once_for_es2020() {
        let output = transpile_typescript(
            r#"
                type Input = { user?: { plan?: string } };
                export function run(input: Input): string {
                    return input.user?.plan ?? "free";
                }
            "#,
            "entry.ts",
        )
        .unwrap();

        assert!(!output.contains("type Input"));
        assert!(!output.contains("input: Input"));
        assert!(output.contains("input.user?.plan ?? \"free\""));
    }

    #[test]
    fn javascript_candidate_keeps_one_prepared_typescript_artifact() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.ts",
            include_str!("testdata/javascript/typed-policy.ts"),
            "",
            "",
        );
        let prepared = fixture
            .hook()
            .prepared_javascript_source()
            .expect("JavaScript hook should retain prepared source");
        assert!(!prepared.contains("type Input"));
        assert!(prepared.contains("input.config?.enabled"));
    }

    #[test]
    fn javascript_rejects_typescript_imports_with_build_guidance() {
        let error = transpile_typescript(
            "import { thing } from 'dependency'; export function run() { return thing; }",
            "entry.ts",
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "bundle.javascript: imports are unavailable; bundle dependencies into one prebuilt single-file .js artifact"
        );
    }

    #[test]
    fn javascript_loads_a_direct_javascript_export() {
        let fixture = fixture(BundleHookKind::Policy, "entry.js", allow_source(), "", "");
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        assert_eq!(adapter.policy_type(), fixture.type_name);
    }

    #[test]
    fn javascript_rejects_direct_imports_reexports_and_dynamic_imports() {
        let sources = [
            "import { thing } from 'dependency'; export function run() { return thing; }",
            "export { thing } from 'dependency'; export function run() { return {}; }",
            "export function run() { return import('dependency'); }",
        ];
        for source in sources {
            let error = match try_fixture(BundleHookKind::Policy, "entry.js", source, "", "") {
                Ok(_) => panic!("importing fixture should fail candidate load"),
                Err(error) => error,
            };
            assert_eq!(
                error.to_string(),
                "bundle.javascript: imports are unavailable; bundle dependencies into one prebuilt single-file .js artifact"
            );
        }
    }

    #[test]
    fn javascript_rejects_a_missing_manifest_export() {
        let error = match try_fixture(
            BundleHookKind::Policy,
            "entry.js",
            "export function another_name() { return {}; }",
            "",
            "",
        ) {
            Ok(_) => panic!("missing export should fail candidate load"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "bundle.javascript: declared export is missing or is not a function"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_policy_allows_and_denies() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    const free = input.request.headers.some(
                        ([name, value]) => name === "x-plan" && value === "free"
                    );
                    return free
                        ? { version: "sbproxy-envelope/v1", decision: "deny", status: 403, message: "upgrade required" }
                        : { version: "sbproxy-envelope/v1", decision: "allow" };
                }
            "#,
            "",
            "",
        );
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        let mut context = ();

        let denied = adapter
            .enforce(&request(b"hello"), &mut context)
            .await
            .unwrap();
        assert_eq!(
            denied,
            PolicyDecision::Deny {
                status: 403,
                message: "upgrade required".to_owned(),
            }
        );

        let paid = http::Request::builder()
            .uri("https://test.sbproxy.dev/widgets")
            .header("x-plan", "paid")
            .body(Bytes::new())
            .unwrap();
        assert_eq!(
            adapter.enforce(&paid, &mut context).await.unwrap(),
            PolicyDecision::Allow
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_auth_allows_with_subject_and_denies_with_challenge() {
        // An HMAC-shaped auth hook: a request carrying the shared token in
        // `x-plan` authenticates and resolves a subject; anything else is
        // challenged with a `WWW-Authenticate` header.
        let fixture = fixture(
            BundleHookKind::Auth,
            "entry.js",
            r#"
                export function run(input) {
                    const token = input.request.headers.find(
                        ([name]) => name === "x-plan"
                    );
                    if (token && token[1] === "paid") {
                        return { version: "sbproxy-envelope/v1", decision: "allow", sub: "acct-42", source: "header" };
                    }
                    return {
                        version: "sbproxy-envelope/v1",
                        decision: "deny_with_headers",
                        status: 401,
                        message: "authentication required",
                        headers: [["WWW-Authenticate", "Bearer realm=\"sbproxy\""]],
                    };
                }
            "#,
            "",
            "",
        );
        let adapter = build_javascript_auth(fixture.hook(), json!({})).unwrap();
        assert_eq!(adapter.auth_type(), "javascript_auth_fixture");
        let mut context = ();

        let challenged = adapter
            .authenticate(&request(b"hello"), &mut context)
            .await
            .unwrap();
        assert_eq!(
            challenged,
            AuthDecision::DenyWithHeaders {
                status: 401,
                message: "authentication required".to_owned(),
                headers: vec![(
                    "WWW-Authenticate".to_owned(),
                    "Bearer realm=\"sbproxy\"".to_owned()
                )],
                kind: AuthDenialKind::Challenge,
            }
        );

        let paid = http::Request::builder()
            .uri("https://test.sbproxy.dev/widgets")
            .header("x-plan", "paid")
            .body(Bytes::new())
            .unwrap();
        assert_eq!(
            adapter.authenticate(&paid, &mut context).await.unwrap(),
            AuthDecision::allow_with_subject("acct-42", AuthSubjectSource::Header)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_envelope_identifies_hook_and_keeps_config_top_level() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    const valid = input.version === "sbproxy-envelope/v1"
                        && input.hook.kind === "policy"
                        && input.hook.type === "javascript_policy_fixture"
                        && !("config" in input.hook)
                        && input.config.threshold === 3
                        && input.request.method === "POST";
                    return valid
                        ? { version: "sbproxy-envelope/v1", decision: "allow" }
                        : { version: "sbproxy-envelope/v1", decision: "deny", status: 500, message: "wrong envelope" };
                }
            "#,
            "",
            "",
        );
        let adapter = build_javascript_policy(fixture.hook(), json!({"threshold": 3})).unwrap();
        let mut context = ();
        assert_eq!(
            adapter.enforce(&request(b""), &mut context).await.unwrap(),
            PolicyDecision::Allow
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_policy_supports_bounded_allow_headers() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run() {
                    return {
                        version: "sbproxy-envelope/v1",
                        decision: "allow_with_headers",
                        headers: [["sunset", "Wed, 21 Oct 2026 07:28:00 GMT"]]
                    };
                }
            "#,
            "",
            "",
        );
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        let mut context = ();
        assert_eq!(
            adapter.enforce(&request(b""), &mut context).await.unwrap(),
            PolicyDecision::AllowWithHeaders {
                headers: vec![(
                    "sunset".to_owned(),
                    "Wed, 21 Oct 2026 07:28:00 GMT".to_owned()
                )]
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_policy_rejects_unbounded_or_invalid_allow_headers() {
        let fixtures = [
            fixture(
                BundleHookKind::Policy,
                "entry.js",
                r#"
                    export function run() {
                        return {
                            version: "sbproxy-envelope/v1",
                            decision: "allow_with_headers",
                            headers: Array.from({ length: 65 }, () => ["x-bundle", "ok"])
                        };
                    }
                "#,
                "",
                "",
            ),
            fixture(
                BundleHookKind::Policy,
                "entry.js",
                r#"
                    export function run() {
                        return {
                            version: "sbproxy-envelope/v1",
                            decision: "allow_with_headers",
                            headers: [["bad header", "value"]]
                        };
                    }
                "#,
                "",
                "",
            ),
            fixture(
                BundleHookKind::Policy,
                "entry.js",
                r#"
                    export function run() {
                        return {
                            version: "sbproxy-envelope/v1",
                            decision: "allow_with_headers",
                            headers: [["x-bundle", "bad\r\nvalue"]]
                        };
                    }
                "#,
                "",
                "",
            ),
        ];
        for fixture in fixtures {
            let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
            let mut context = ();
            let error = adapter
                .enforce(&request(b""), &mut context)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "javascript bundle hook failed: invalid_envelope"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_transform_replaces_a_buffered_body() {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"rewritten");
        let fixture = fixture(
            BundleHookKind::Transform,
            "entry.js",
            &format!(
                "export function run(input) {{ return {{ version: \"{JAVASCRIPT_ENVELOPE_VERSION}\", body_base64: \"{encoded}\" }}; }}"
            ),
            "",
            "",
        );
        let adapter = build_javascript_transform(fixture.hook(), json!({})).unwrap();
        let mut body = BytesMut::from(&b"original"[..]);
        adapter
            .apply(
                &mut body,
                Some("text/plain"),
                &TransformContext::new("test.sbproxy.dev"),
            )
            .await
            .unwrap();
        assert_eq!(&body[..], b"rewritten");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_action_returns_a_bounded_structured_response() {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"queued");
        let fixture = fixture(
            BundleHookKind::Action,
            "entry.js",
            &format!(
                r#"export function run(input) {{
                    return {{
                        version: "{JAVASCRIPT_ENVELOPE_VERSION}",
                        outcome: "response",
                        status: 202,
                        headers: [["content-type", "text/plain"]],
                        body_base64: "{encoded}"
                    }};
                }}"#
            ),
            "",
            "",
        );
        let adapter = build_javascript_action(fixture.hook(), json!({})).unwrap();
        let mut req = request(b"");
        let mut context = ();
        let outcome = adapter.handle(&mut req, &mut context).await.unwrap();
        assert_eq!(
            outcome,
            ActionOutcome::Response {
                status: 202,
                headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
                body: Bytes::from_static(b"queued"),
            }
        );
    }

    #[test]
    fn javascript_applies_schema_defaults_before_validation() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    if (input.config.threshold === 3) {
                        return { version: "sbproxy-envelope/v1", decision: "allow" };
                    }
                    return { version: "sbproxy-envelope/v1", decision: "deny", status: 500, message: "default missing" };
                }
            "#,
            "",
            "    config_schema:\n      type: object\n      additionalProperties: false\n      required: [threshold]\n      properties:\n        threshold:\n          type: integer\n          default: 3\n",
        );
        build_javascript_policy(fixture.hook(), json!({})).unwrap();
    }

    #[test]
    fn javascript_rejects_attachment_config_that_misses_its_schema() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            allow_source(),
            "",
            "    config_schema:\n      type: object\n      additionalProperties: false\n      required: [threshold]\n      properties:\n        threshold:\n          type: integer\n",
        );
        let error =
            build_javascript_policy(fixture.hook(), json!({"threshold": "three"})).unwrap_err();
        assert!(error
            .to_string()
            .starts_with("bundle.config: bundle hook configuration is invalid: value at `"));
    }

    // --- WOR-2289: bundle config var secret resolution + masking ---

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_hook_receives_a_resolved_secret_not_the_reference() {
        let secret_dir = TempDir::new().unwrap();
        let secret_path = secret_dir.path().join("token");
        std::fs::write(&secret_path, "resolved-token-value").unwrap();

        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    if (input.config.token === "resolved-token-value") {
                        return { version: "sbproxy-envelope/v1", decision: "allow" };
                    }
                    return { version: "sbproxy-envelope/v1", decision: "deny", status: 500, message: "unresolved" };
                }
            "#,
            "",
            "    config_schema:\n      type: object\n      properties:\n        token:\n          type: string\n    secret_vars: [token]\n",
        );
        let adapter = build_javascript_policy(
            fixture.hook(),
            json!({ "token": format!("file:{}", secret_path.display()) }),
        )
        .unwrap();

        let mut context = ();
        let decision = adapter.enforce(&request(b""), &mut context).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_hook_leaves_a_reference_shaped_value_unresolved_when_not_declared_secret() {
        // No secret_vars declared, so "token" is never inspected for a
        // reference shape even though it looks like one: the guest
        // sees the literal reference text, unchanged.
        let secret_dir = TempDir::new().unwrap();
        let secret_path = secret_dir.path().join("token");
        std::fs::write(&secret_path, "resolved-token-value").unwrap();
        let literal = format!("file:{}", secret_path.display());

        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    if (input.config.token === input.config.expected_literal) {
                        return { version: "sbproxy-envelope/v1", decision: "allow" };
                    }
                    return { version: "sbproxy-envelope/v1", decision: "deny", status: 500, message: "resolved when it should not have been" };
                }
            "#,
            "",
            "",
        );
        let adapter = build_javascript_policy(
            fixture.hook(),
            json!({ "token": literal.clone(), "expected_literal": literal }),
        )
        .unwrap();

        let mut context = ();
        let decision = adapter.enforce(&request(b""), &mut context).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_hook_treats_a_plain_literal_config_value_as_is() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    if (input.config.token === "literal-value-not-a-reference") {
                        return { version: "sbproxy-envelope/v1", decision: "allow" };
                    }
                    return { version: "sbproxy-envelope/v1", decision: "deny", status: 500, message: "changed" };
                }
            "#,
            "",
            "    config_schema:\n      type: object\n      properties:\n        token:\n          type: string\n    secret_vars: [token]\n",
        );
        let adapter = build_javascript_policy(
            fixture.hook(),
            json!({ "token": "literal-value-not-a-reference" }),
        )
        .unwrap();

        let mut context = ();
        let decision = adapter.enforce(&request(b""), &mut context).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_hook_resolves_env_and_dollar_brace_bundle_config_secrets() {
        // Reads an environment variable every test process already has
        // rather than exporting a new one: sbproxy-extension has no
        // `src/test_env.rs` guard, and `scripts/check-env-mutation.sh`
        // rejects `std::env::set_var` outside that documented helper.
        let expected = std::env::var("PATH").expect("PATH is set in the test environment");
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    if (input.config.a === input.config.expected && input.config.b === input.config.expected) {
                        return { version: "sbproxy-envelope/v1", decision: "allow" };
                    }
                    return { version: "sbproxy-envelope/v1", decision: "deny", status: 500, message: "mismatch" };
                }
            "#,
            "",
            "    config_schema:\n      type: object\n      properties:\n        a:\n          type: string\n        b:\n          type: string\n        expected:\n          type: string\n    secret_vars: [a, b]\n",
        );
        let adapter = build_javascript_policy(
            fixture.hook(),
            json!({ "a": "env:PATH", "b": "${PATH}", "expected": expected }),
        )
        .unwrap();

        let mut context = ();
        let decision = adapter.enforce(&request(b""), &mut context).await.unwrap();
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn javascript_adapter_debug_never_echoes_a_resolved_bundle_secret() {
        let secret_dir = TempDir::new().unwrap();
        let secret_path = secret_dir.path().join("token");
        std::fs::write(&secret_path, "DISTINCTIVE_SECRET_7f3a").unwrap();

        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            allow_source(),
            "",
            "    config_schema:\n      type: object\n      properties:\n        token:\n          type: string\n    secret_vars: [token]\n",
        );
        let adapter = build_javascript_policy(
            fixture.hook(),
            json!({ "token": format!("file:{}", secret_path.display()) }),
        )
        .unwrap();

        let rendered = format!("{adapter:?}");
        assert!(!rendered.contains("DISTINCTIVE_SECRET_7f3a"), "{rendered}");
        assert!(rendered.contains("REDACTED:token"), "{rendered}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_reports_thrown_exceptions_without_guest_text() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            "export function run() { throw new Error('private guest detail'); }",
            "",
            "",
        );
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        let mut context = ();
        let error = adapter
            .enforce(&request(b""), &mut context)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "javascript bundle hook failed: guest_exception"
        );
        assert!(!error.to_string().contains("private guest detail"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_accepts_an_async_export_without_host_io() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export async function run() {
                    await Promise.resolve();
                    return { version: "sbproxy-envelope/v1", decision: "allow" };
                }
            "#,
            "",
            "",
        );
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        let mut context = ();
        assert_eq!(
            adapter.enforce(&request(b""), &mut context).await.unwrap(),
            PolicyDecision::Allow
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_times_out_a_promise_that_cannot_settle_and_replaces_its_worker() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    if (input.config.pending) return new Promise(() => {});
                    return { version: "sbproxy-envelope/v1", decision: "allow" };
                }
            "#,
            "sandbox:\n  budget_ms: 10\n",
            "",
        );
        let (_, pending) = prepare_program(
            fixture.hook(),
            BundleHookKind::Policy,
            json!({"pending": true}),
        )
        .unwrap();
        let (_, healthy) = prepare_program(
            fixture.hook(),
            BundleHookKind::Policy,
            json!({"pending": false}),
        )
        .unwrap();
        let executor = JavascriptExecutor::start(1, 1);
        let request = request_value(&request(b""), pending.limits.max_input_bytes).unwrap();
        let pending_input = hook_envelope("request", &pending, request.clone());
        let pending_input =
            serialize_envelope(&pending_input, pending.limits.max_input_bytes).unwrap();
        assert_eq!(
            executor.execute(pending, pending_input).await,
            Err(super::RuntimeFailure::Timeout)
        );

        let healthy_input = hook_envelope("request", &healthy, request);
        let healthy_input =
            serialize_envelope(&healthy_input, healthy.limits.max_input_bytes).unwrap();
        let output = executor.execute(healthy, healthy_input).await.unwrap();
        assert_eq!(decode_policy(&output).unwrap(), PolicyDecision::Allow);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_rejects_a_response_from_another_envelope_version() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run() {
                    return { version: "sbproxy-envelope/v2", decision: "allow" };
                }
            "#,
            "",
            "",
        );
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        let mut context = ();
        let error = adapter
            .enforce(&request(b""), &mut context)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "javascript bundle hook failed: invalid_version"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_interrupts_a_runaway_hook() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            "export function run() { while (true) {} }",
            "sandbox:\n  budget_ms: 10\n",
            "",
        );
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        let mut context = ();
        let started = Instant::now();
        let error = adapter
            .enforce(&request(b""), &mut context)
            .await
            .unwrap_err();
        assert!(matches!(error, sbproxy_plugin::PluginError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_enforces_the_output_cap() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run() {
                    return { version: "sbproxy-envelope/v1", decision: "allow", padding: "x".repeat(5000) };
                }
            "#,
            "sandbox:\n  max_output_bytes: 256\n",
            "",
        );
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        let mut context = ();
        let error = adapter
            .enforce(&request(b""), &mut context)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "javascript bundle hook failed: output_limit"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_enforces_the_serialized_input_cap() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            allow_source(),
            "sandbox:\n  max_buffer_bytes: 256\n",
            "",
        );
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        let request = http::Request::builder()
            .uri("https://test.sbproxy.dev/widgets")
            .body(Bytes::from(vec![b'x'; 300]))
            .unwrap();
        let mut context = ();
        let error = adapter.enforce(&request, &mut context).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "javascript bundle hook failed: input_limit"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_enforces_the_memory_ceiling_and_recovers() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    if (input.config.allocate) {
                        const chunks = [];
                        while (true) chunks.push(new ArrayBuffer(1048576));
                    }
                    return { version: "sbproxy-envelope/v1", decision: "allow" };
                }
            "#,
            "sandbox:\n  budget_ms: 500\n  memory_mb: 4\n",
            "",
        );
        let allocating =
            build_javascript_policy(fixture.hook(), json!({"allocate": true})).unwrap();
        let healthy = build_javascript_policy(fixture.hook(), json!({"allocate": false})).unwrap();
        let mut context = ();
        let error = allocating
            .enforce(&request(b""), &mut context)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "javascript bundle hook failed: guest_exception"
        );
        assert_eq!(
            healthy.enforce(&request(b""), &mut context).await.unwrap(),
            PolicyDecision::Allow
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_discards_a_poisoned_single_worker_runtime() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    if (input.config.runaway) while (true) {}
                    return { version: "sbproxy-envelope/v1", decision: "allow" };
                }
            "#,
            "sandbox:\n  budget_ms: 10\n",
            "",
        );
        let (_, runaway) = prepare_program(
            fixture.hook(),
            BundleHookKind::Policy,
            json!({"runaway": true}),
        )
        .unwrap();
        let (_, healthy) = prepare_program(
            fixture.hook(),
            BundleHookKind::Policy,
            json!({"runaway": false}),
        )
        .unwrap();
        let executor = JavascriptExecutor::start(1, 1);
        let request = request_value(&request(b""), runaway.limits.max_input_bytes).unwrap();
        let runaway_input = hook_envelope("request", &runaway, request.clone());
        let runaway_input =
            serialize_envelope(&runaway_input, runaway.limits.max_input_bytes).unwrap();
        assert_eq!(
            executor.execute(runaway, runaway_input).await,
            Err(super::RuntimeFailure::Timeout)
        );

        let healthy_input = hook_envelope("request", &healthy, request);
        let healthy_input =
            serialize_envelope(&healthy_input, healthy.limits.max_input_bytes).unwrap();
        let output = executor.execute(healthy, healthy_input).await.unwrap();
        assert_eq!(decode_policy(&output).unwrap(), PolicyDecision::Allow);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_queue_wait_consumes_the_hook_budget() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    const until = Date.now() + input.config.hold_ms;
                    while (Date.now() < until) {}
                    return { version: "sbproxy-envelope/v1", decision: "allow" };
                }
            "#,
            "sandbox:\n  budget_ms: 1000\n",
            "",
        );
        let (_, blocker) = prepare_program(
            fixture.hook(),
            BundleHookKind::Policy,
            json!({"hold_ms": 400}),
        )
        .unwrap();
        let (_, mut queued) = prepare_program(
            fixture.hook(),
            BundleHookKind::Policy,
            json!({"hold_ms": 1000}),
        )
        .unwrap();
        queued.limits.budget_ms = 200;
        let blocker_input = invocation_input(&blocker);
        let queued_input = invocation_input(&queued);
        let executor = Arc::new(JavascriptExecutor::start(1, 1));

        let blocker_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(blocker, blocker_input).await }
        });
        wait_until("running JavaScript blocker", || {
            executor.available_admission() == 1 && executor.available_queue() == 1
        })
        .await;

        let started = Instant::now();
        assert_eq!(
            executor.execute(queued, queued_input).await,
            Err(super::RuntimeFailure::Timeout)
        );
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "queued hook should time out before the blocker completes"
        );
        assert!(blocker_call.await.unwrap().is_ok());
        tokio::time::timeout(Duration::from_millis(100), async {
            while executor.available_admission() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("expired queued hook should not receive a fresh runtime budget");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_admission_wait_consumes_the_hook_budget() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run(input) {
                    const until = Date.now() + input.config.hold_ms;
                    while (Date.now() < until) {}
                    return { version: "sbproxy-envelope/v1", decision: "allow" };
                }
            "#,
            "sandbox:\n  budget_ms: 1000\n",
            "",
        );
        let (_, first_blocker) = prepare_program(
            fixture.hook(),
            BundleHookKind::Policy,
            json!({"hold_ms": 250}),
        )
        .unwrap();
        let (_, second_blocker) = prepare_program(
            fixture.hook(),
            BundleHookKind::Policy,
            json!({"hold_ms": 250}),
        )
        .unwrap();
        let (_, mut waiting) = prepare_program(
            fixture.hook(),
            BundleHookKind::Policy,
            json!({"hold_ms": 0}),
        )
        .unwrap();
        waiting.limits.budget_ms = 50;
        let first_input = invocation_input(&first_blocker);
        let second_input = invocation_input(&second_blocker);
        let waiting_input = invocation_input(&waiting);
        let executor = Arc::new(JavascriptExecutor::start(1, 1));

        let first_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(first_blocker, first_input).await }
        });
        wait_until("running JavaScript blocker", || {
            executor.available_admission() == 1 && executor.available_queue() == 1
        })
        .await;
        let second_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(second_blocker, second_input).await }
        });
        wait_until("full JavaScript admission", || {
            executor.available_admission() == 0 && executor.available_queue() == 0
        })
        .await;

        let started = Instant::now();
        assert_eq!(
            executor.execute(waiting, waiting_input).await,
            Err(super::RuntimeFailure::Timeout)
        );
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "admission waiter should time out before a slot opens"
        );
        assert!(first_call.await.unwrap().is_ok());
        assert!(second_call.await.unwrap().is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_does_not_carry_globals_between_requests() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                let calls = 0;
                export function run() {
                    calls += 1;
                    return calls === 1
                        ? { version: "sbproxy-envelope/v1", decision: "allow" }
                        : { version: "sbproxy-envelope/v1", decision: "deny", status: 500, message: "state leaked" };
                }
            "#,
            "",
            "",
        );
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        let mut context = ();
        for _ in 0..2 {
            assert_eq!(
                adapter.enforce(&request(b""), &mut context).await.unwrap(),
                PolicyDecision::Allow
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn javascript_pool_saturation_does_not_block_a_tokio_worker() {
        let fixture = fixture(
            BundleHookKind::Policy,
            "entry.js",
            r#"
                export function run() {
                    const until = Date.now() + 40;
                    while (Date.now() < until) {}
                    return { version: "sbproxy-envelope/v1", decision: "allow" };
                }
            "#,
            "sandbox:\n  budget_ms: 200\n",
            "",
        );
        let executor = Arc::new(JavascriptExecutor::start(2, 4));
        let mut adapter =
            build_javascript_policy(fixture.hook(), Value::Object(Default::default())).unwrap();
        adapter.program.executor = Arc::clone(&executor);
        let adapter = Arc::new(adapter);
        let admission_capacity = executor.available_admission();
        let ticker = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Instant::now()
        });
        let mut calls = Vec::new();
        for _ in 0..32 {
            let adapter = Arc::clone(&adapter);
            calls.push(tokio::spawn(async move {
                let mut context = ();
                adapter.enforce(&request(b""), &mut context).await
            }));
        }
        let ticked_at = tokio::time::timeout(Duration::from_millis(150), ticker)
            .await
            .expect("Tokio timer should run while JavaScript admission waits")
            .unwrap();
        assert!(ticked_at.elapsed() < Duration::from_secs(1));
        let mut timeout_count = 0;
        for call in calls {
            match call.await.unwrap() {
                Ok(PolicyDecision::Allow) => {}
                Err(sbproxy_plugin::PluginError::Timeout) => timeout_count += 1,
                result => panic!("unexpected saturated JavaScript result: {result:?}"),
            }
        }
        assert!(
            timeout_count > 0,
            "saturated calls should consume their budget while waiting"
        );
        wait_until("saturated JavaScript cleanup", || {
            executor.available_admission() == admission_capacity
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "local benchmark"]
    async fn javascript_bundle_benchmark() {
        let mut cold_load_us = Vec::new();
        for _ in 0..20 {
            let started = Instant::now();
            let fixture = fixture(BundleHookKind::Policy, "entry.js", allow_source(), "", "");
            let _adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
            cold_load_us.push(started.elapsed().as_micros());
        }

        let fixture = fixture(BundleHookKind::Policy, "entry.js", allow_source(), "", "");
        let adapter = build_javascript_policy(fixture.hook(), json!({})).unwrap();
        let mut context = ();
        for _ in 0..50 {
            adapter.enforce(&request(b""), &mut context).await.unwrap();
        }
        let mut warm_us = Vec::new();
        for _ in 0..500 {
            let started = Instant::now();
            adapter.enforce(&request(b""), &mut context).await.unwrap();
            warm_us.push(started.elapsed().as_micros());
        }
        cold_load_us.sort_unstable();
        warm_us.sort_unstable();
        let cold_median = cold_load_us[cold_load_us.len() / 2];
        let warm_p50 = warm_us[warm_us.len() / 2];
        let warm_p99 = warm_us[(warm_us.len() * 99 / 100).min(warm_us.len() - 1)];
        println!(
            "javascript benchmark: cold_load_median_us={cold_median} warm_p50_us={warm_p50} warm_p99_us={warm_p99} warm_samples={}",
            warm_us.len()
        );
    }
}
