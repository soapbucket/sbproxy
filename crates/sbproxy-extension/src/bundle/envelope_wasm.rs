use std::io;
use std::pin::Pin;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use sbproxy_config::{BundleHookKind, BundleRuntime};
use sbproxy_plugin::{
    ActionHandler, ActionOutcome, PluginError, PluginResult, PolicyDecision, PolicyEnforcer,
    TransformContext, TransformHandler,
};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

use super::envelope::{self, EnvelopeError};
use super::{BundleLoadError, LoadedBundleHook};
use crate::wasm::{WasmCallFailure, WasmExecutionControl, WasmRuntime};

const MAX_WASM_WORKERS: usize = 4;
const QUEUE_SLOTS_PER_WORKER: usize = 2;
const WASM_WORKER_STACK_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct EnvelopeWasmProgram {
    runtime: Arc<WasmRuntime>,
    /// Bundle the module came from. Used to attribute captured guest
    /// stderr (WOR-2364 §1); one runtime is shared by every hook in a
    /// bundle, so the identity has to travel with the call.
    bundle_name: Arc<str>,
    hook_kind: &'static str,
    type_name: Arc<str>,
    config: Arc<Value>,
    /// `secret_vars ∪ masked_vars` var names from this hook's manifest
    /// (WOR-2289). Never printed as-is; `Debug` masks exactly these
    /// vars so a resolved secret or a masked literal never reaches a
    /// log or panic message.
    masked_names: Arc<Vec<String>>,
    max_input_bytes: usize,
    max_output_bytes: usize,
    budget: std::time::Duration,
    #[cfg(test)]
    metrics_engine: &'static str,
    #[cfg(test)]
    execution_started: Arc<AtomicBool>,
    #[cfg(test)]
    execution_finished: Arc<AtomicBool>,
}

impl std::fmt::Debug for EnvelopeWasmProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvelopeWasmProgram")
            .field("bundle_name", &self.bundle_name)
            .field("hook_kind", &self.hook_kind)
            .field("type_name", &self.type_name)
            .field(
                "config",
                &envelope::mask_declared_vars(&self.config, &self.masked_names),
            )
            .field("max_input_bytes", &self.max_input_bytes)
            .field("max_output_bytes", &self.max_output_bytes)
            .field("budget_ms", &self.budget.as_millis())
            .finish_non_exhaustive()
    }
}

impl EnvelopeWasmProgram {
    pub(crate) async fn invoke(
        &self,
        payload_name: &str,
        payload: Value,
    ) -> Result<Vec<u8>, PluginError> {
        let envelope = envelope::hook_envelope(
            payload_name,
            self.hook_kind,
            self.type_name.as_ref(),
            self.config.as_ref(),
            payload,
        );
        let input = envelope::serialize_envelope(&envelope, self.max_input_bytes)
            .map_err(envelope_plugin_error)?;
        WASM_EXECUTOR
            .as_ref()
            .ok_or_else(|| wasm_plugin_error(WasmCallFailure::HostFailure))?
            .execute(self.clone(), input)
            .await
            .map_err(wasm_plugin_error)
    }

    #[cfg(test)]
    fn for_test(runtime: Arc<WasmRuntime>) -> Self {
        Self::for_test_with_budget(runtime, std::time::Duration::from_millis(50))
    }

    #[cfg(test)]
    fn for_test_with_budget(runtime: Arc<WasmRuntime>, budget: std::time::Duration) -> Self {
        Self {
            runtime,
            bundle_name: Arc::from("test-bundle"),
            hook_kind: "policy",
            type_name: Arc::from("test"),
            config: Arc::new(json!({})),
            masked_names: Arc::new(Vec::new()),
            max_input_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            budget,
            metrics_engine: "wasm",
            execution_started: Arc::new(AtomicBool::new(false)),
            execution_finished: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    fn with_metrics_engine(mut self, metrics_engine: &'static str) -> Self {
        self.metrics_engine = metrics_engine;
        self
    }

    fn metrics_engine(&self) -> &'static str {
        #[cfg(test)]
        {
            self.metrics_engine
        }
        #[cfg(not(test))]
        {
            "wasm"
        }
    }

    #[cfg(test)]
    fn execution_started(&self) -> bool {
        self.execution_started.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn execution_finished(&self) -> bool {
        self.execution_finished.load(Ordering::Relaxed)
    }

    fn mark_execution_started(&self) {
        #[cfg(test)]
        self.execution_started.store(true, Ordering::Relaxed);
    }

    fn mark_execution_finished(&self) {
        #[cfg(test)]
        self.execution_finished.store(true, Ordering::Relaxed);
    }
}

struct WasmJob {
    program: EnvelopeWasmProgram,
    input: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, WasmCallFailure>>,
    invocation: Arc<WasmInvocation>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum WasmInvocationStage {
    Admission = 0,
    Queue = 1,
    Running = 2,
}

struct WasmInvocation {
    execution: Arc<WasmExecutionControl>,
    stage: AtomicU8,
}

impl WasmInvocation {
    fn new(deadline: std::time::Instant) -> Self {
        Self {
            execution: Arc::new(WasmExecutionControl::new(deadline)),
            stage: AtomicU8::new(WasmInvocationStage::Admission as u8),
        }
    }

    fn set_stage(&self, stage: WasmInvocationStage) {
        self.stage.store(stage as u8, Ordering::Release);
    }

    fn stage(&self) -> WasmInvocationStage {
        match self.stage.load(Ordering::Acquire) {
            value if value == WasmInvocationStage::Queue as u8 => WasmInvocationStage::Queue,
            value if value == WasmInvocationStage::Running as u8 => WasmInvocationStage::Running,
            _ => WasmInvocationStage::Admission,
        }
    }
}

struct WasmInvocationGuard {
    invocation: Arc<WasmInvocation>,
    started: std::time::Instant,
    metrics_engine: &'static str,
    admission_permit: Option<OwnedSemaphorePermit>,
    recorded: bool,
}

impl WasmInvocationGuard {
    fn new(
        invocation: Arc<WasmInvocation>,
        started: std::time::Instant,
        metrics_engine: &'static str,
    ) -> Self {
        Self {
            invocation,
            started,
            metrics_engine,
            admission_permit: None,
            recorded: false,
        }
    }

    fn admit(&mut self, permit: OwnedSemaphorePermit) {
        self.admission_permit = Some(permit);
    }

    fn finish(&mut self, outcome: &'static str) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        sbproxy_observe::metrics::record_script_duration(
            self.metrics_engine,
            self.started.elapsed().as_secs_f64(),
        );
        sbproxy_observe::metrics::record_script_invocation(self.metrics_engine, outcome);
    }
}

impl Drop for WasmInvocationGuard {
    fn drop(&mut self) {
        if !self.recorded {
            self.invocation.execution.cancel();
            self.finish("cancelled");
        }
    }
}

struct WasmExecutor {
    sender: mpsc::Sender<WasmJob>,
    admission: Arc<Semaphore>,
}

type WasmReceiver = Arc<Mutex<mpsc::Receiver<WasmJob>>>;

impl WasmExecutor {
    fn start(worker_count: usize, queue_capacity: usize) -> Result<Self, WasmCallFailure> {
        Self::start_with_spawner(worker_count, queue_capacity, |worker_index, receiver| {
            std::thread::Builder::new()
                .name(format!("sbproxy-wasm-worker-{worker_index}"))
                .stack_size(WASM_WORKER_STACK_BYTES)
                .spawn(move || wasm_worker(receiver))
                .map(|_| ())
        })
    }

    fn start_with_spawner(
        worker_count: usize,
        queue_capacity: usize,
        mut spawn: impl FnMut(usize, WasmReceiver) -> io::Result<()>,
    ) -> Result<Self, WasmCallFailure> {
        let worker_count = worker_count.max(1);
        let queue_capacity = queue_capacity.max(1);
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_index in 0..worker_count {
            spawn(worker_index, Arc::clone(&receiver)).map_err(|_| WasmCallFailure::HostFailure)?;
        }
        Ok(Self {
            sender,
            admission: Arc::new(Semaphore::new(worker_count + queue_capacity)),
        })
    }

    async fn execute(
        &self,
        program: EnvelopeWasmProgram,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, WasmCallFailure> {
        let budget = program.budget;
        let started = std::time::Instant::now();
        let deadline = started
            .checked_add(budget)
            .ok_or(WasmCallFailure::HostFailure)?;
        let invocation = Arc::new(WasmInvocation::new(deadline));
        let mut guard =
            WasmInvocationGuard::new(Arc::clone(&invocation), started, program.metrics_engine());
        let timed_result =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
                let permit = Arc::clone(&self.admission)
                    .acquire_owned()
                    .await
                    .map_err(|_| WasmCallFailure::HostFailure)?;
                guard.admit(permit);
                invocation.set_stage(WasmInvocationStage::Queue);
                let (reply, response) = oneshot::channel();
                self.sender
                    .send(WasmJob {
                        program,
                        input,
                        reply,
                        invocation: Arc::clone(&invocation),
                    })
                    .await
                    .map_err(|_| WasmCallFailure::HostFailure)?;
                response.await.map_err(|_| WasmCallFailure::HostFailure)?
            })
            .await;
        let result = timed_result.unwrap_or(Err(WasmCallFailure::Timeout));
        guard.finish(wasm_invocation_outcome(&result, invocation.stage()));
        result
    }

    #[cfg(test)]
    fn available_admission(&self) -> usize {
        self.admission.available_permits()
    }
}

fn default_executor() -> Option<WasmExecutor> {
    let worker_count = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(2)
        .clamp(1, MAX_WASM_WORKERS);
    WasmExecutor::start(worker_count, worker_count * QUEUE_SLOTS_PER_WORKER).ok()
}

static WASM_EXECUTOR: LazyLock<Option<WasmExecutor>> = LazyLock::new(default_executor);

fn wasm_worker(receiver: Arc<Mutex<mpsc::Receiver<WasmJob>>>) {
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
        let result = match job.invocation.execution.stop_reason() {
            None => {
                job.invocation.set_stage(WasmInvocationStage::Running);
                if let Some(reason) = job.invocation.execution.stop_reason() {
                    Err(reason)
                } else {
                    let execution = Arc::clone(&job.invocation.execution);
                    job.program.mark_execution_started();
                    job.program.runtime.execute_bounded_until(
                        &job.input,
                        execution,
                        crate::wasm::WasmGuestIdentity {
                            bundle: &job.program.bundle_name,
                            hook_kind: job.program.hook_kind,
                            type_name: &job.program.type_name,
                        },
                    )
                }
            }
            Some(reason) => Err(reason),
        };
        job.program.mark_execution_finished();
        let _ = job.reply.send(result);
    }
}

fn wasm_invocation_outcome(
    result: &Result<Vec<u8>, WasmCallFailure>,
    stage: WasmInvocationStage,
) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(WasmCallFailure::InputLimit) => "input_limit",
        Err(WasmCallFailure::Cancelled) => "cancelled",
        Err(WasmCallFailure::Timeout) => match stage {
            WasmInvocationStage::Admission => "admission_timeout",
            WasmInvocationStage::Queue => "queue_timeout",
            WasmInvocationStage::Running => "timeout",
        },
        Err(WasmCallFailure::FuelLimit) => "instruction_cap",
        Err(WasmCallFailure::MemoryLimit) => "memory_cap",
        Err(WasmCallFailure::TableLimit) => "table_cap",
        Err(WasmCallFailure::StackLimit) => "stack_cap",
        Err(WasmCallFailure::OutputLimit) => "output_limit",
        Err(WasmCallFailure::GuestTrap) => "guest_exception",
        Err(WasmCallFailure::HostFailure) => "runtime_unavailable",
    }
}

pub(crate) fn prepare_wasm_program(
    hook: &LoadedBundleHook,
    expected_kind: BundleHookKind,
    config: Value,
) -> Result<(String, EnvelopeWasmProgram), BundleLoadError> {
    if hook.manifest().runtime != BundleRuntime::Wasm || hook.hook().kind != expected_kind {
        return Err(BundleLoadError::new(
            "wasm",
            "hook kind does not match the requested WASM adapter",
        ));
    }
    // Defaults, secret resolution, and schema validation, in that
    // order and in one place: `prepare_hook_config` is also where a
    // value the bundle's own manifest authored is refused a host-backed
    // secret (WOR-2433).
    let config = envelope::prepare_hook_config(hook, config)?;
    let runtime = hook
        .prepared_wasm_runtime()
        .ok_or_else(|| BundleLoadError::new("wasm", "bundle has no prepared WASM runtime"))?;
    let budget = runtime
        .bundle_budget()
        .ok_or_else(|| BundleLoadError::new("wasm", "bundle has no WASM execution budget"))?;
    let max_input_bytes = usize::try_from(hook.manifest().sandbox.max_buffer_bytes)
        .map_err(|_| BundleLoadError::new("wasm", "input limit is unsupported"))?;
    let max_output_bytes = usize::try_from(hook.manifest().sandbox.max_output_bytes)
        .map_err(|_| BundleLoadError::new("wasm", "output limit is unsupported"))?;
    let type_name = hook.hook().type_name.clone();
    let masked_names: Vec<String> = hook
        .hook()
        .secret_vars
        .iter()
        .chain(&hook.hook().masked_vars)
        .cloned()
        .collect();
    Ok((
        type_name.clone(),
        EnvelopeWasmProgram {
            runtime: Arc::clone(runtime),
            bundle_name: Arc::from(hook.manifest().name.as_str()),
            hook_kind: envelope::hook_kind_label(expected_kind),
            type_name: Arc::from(type_name),
            config: Arc::new(config),
            masked_names: Arc::new(masked_names),
            max_input_bytes,
            max_output_bytes,
            budget,
            #[cfg(test)]
            metrics_engine: "wasm",
            #[cfg(test)]
            execution_started: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            execution_finished: Arc::new(AtomicBool::new(false)),
        },
    ))
}

fn envelope_plugin_error(error: EnvelopeError) -> PluginError {
    PluginError::Internal(anyhow::anyhow!("wasm bundle hook failed: {}", error.code()))
}

fn wasm_plugin_error(error: WasmCallFailure) -> PluginError {
    if matches!(error, WasmCallFailure::Timeout | WasmCallFailure::Cancelled) {
        PluginError::Timeout
    } else {
        PluginError::Internal(anyhow::anyhow!("wasm bundle hook failed: {}", error.code()))
    }
}

/// Buffered policy adapter backed by one prepared envelope WASM runtime.
pub struct WasmPolicyAdapter {
    type_name: String,
    program: EnvelopeWasmProgram,
}

impl std::fmt::Debug for WasmPolicyAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmPolicyAdapter")
            .field("type_name", &self.type_name)
            .field("program", &self.program)
            .finish()
    }
}

/// Build a policy adapter from a validated envelope WASM hook.
pub fn build_wasm_policy(
    hook: &LoadedBundleHook,
    config: Value,
) -> Result<WasmPolicyAdapter, BundleLoadError> {
    let (type_name, program) = prepare_wasm_program(hook, BundleHookKind::Policy, config)?;
    Ok(WasmPolicyAdapter { type_name, program })
}

impl PolicyEnforcer for WasmPolicyAdapter {
    fn policy_type(&self) -> &str {
        &self.type_name
    }

    fn enforce(
        &self,
        request: &http::Request<Bytes>,
        _context: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn std::future::Future<Output = PluginResult<PolicyDecision>> + Send + '_>> {
        let request = envelope::request_value(request, self.program.max_input_bytes);
        Box::pin(async move {
            let request = request.map_err(envelope_plugin_error)?;
            let output = self.program.invoke("request", request).await?;
            envelope::decode_policy(&output).map_err(envelope_plugin_error)
        })
    }
}

/// Buffered body-transform adapter backed by one prepared WASM runtime.
pub struct WasmTransformAdapter {
    type_name: String,
    program: EnvelopeWasmProgram,
}

impl std::fmt::Debug for WasmTransformAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmTransformAdapter")
            .field("type_name", &self.type_name)
            .field("program", &self.program)
            .finish()
    }
}

/// Build a transform adapter from a validated envelope WASM hook.
pub fn build_wasm_transform(
    hook: &LoadedBundleHook,
    config: Value,
) -> Result<WasmTransformAdapter, BundleLoadError> {
    let (type_name, program) = prepare_wasm_program(hook, BundleHookKind::Transform, config)?;
    Ok(WasmTransformAdapter { type_name, program })
}

impl TransformHandler for WasmTransformAdapter {
    fn transform_type(&self) -> &str {
        &self.type_name
    }

    fn apply<'a>(
        &'a self,
        body: &'a mut BytesMut,
        content_type: Option<&'a str>,
        context: &'a TransformContext<'a>,
    ) -> Pin<Box<dyn std::future::Future<Output = PluginResult<()>> + Send + 'a>> {
        let input = if body.len() > self.program.max_input_bytes {
            Err(EnvelopeError::new("input_limit"))
        } else {
            Ok(json!({
                "body_base64": base64::engine::general_purpose::STANDARD.encode(&body[..]),
                "content_type": content_type,
                "origin": context.origin,
            }))
        };
        Box::pin(async move {
            let input = input.map_err(envelope_plugin_error)?;
            let output = self.program.invoke("body", input).await?;
            let replacement = envelope::decode_body(&output, self.program.max_output_bytes)
                .map_err(envelope_plugin_error)?;
            body.clear();
            body.extend_from_slice(&replacement);
            Ok(())
        })
    }
}

/// Buffered action adapter backed by one prepared envelope WASM runtime.
pub struct WasmActionAdapter {
    type_name: String,
    program: EnvelopeWasmProgram,
}

impl std::fmt::Debug for WasmActionAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmActionAdapter")
            .field("type_name", &self.type_name)
            .field("program", &self.program)
            .finish()
    }
}

/// Build an action adapter from a validated envelope WASM hook.
pub fn build_wasm_action(
    hook: &LoadedBundleHook,
    config: Value,
) -> Result<WasmActionAdapter, BundleLoadError> {
    let (type_name, program) = prepare_wasm_program(hook, BundleHookKind::Action, config)?;
    Ok(WasmActionAdapter { type_name, program })
}

impl ActionHandler for WasmActionAdapter {
    fn handler_type(&self) -> &str {
        &self.type_name
    }

    fn handle(
        &self,
        request: &mut http::Request<Bytes>,
        _context: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn std::future::Future<Output = PluginResult<ActionOutcome>> + Send + '_>> {
        let request = envelope::request_value(request, self.program.max_input_bytes);
        Box::pin(async move {
            let request = request.map_err(envelope_plugin_error)?;
            let output = self.program.invoke("request", request).await?;
            envelope::decode_action(&output, self.program.max_output_bytes)
                .map_err(envelope_plugin_error)
        })
    }
}

/// AI routing program backed by one prepared envelope WASM runtime.
///
/// Built from a bundle hook of kind `ai_routing` (WOR-2366). The
/// compiled routing policy in sbproxy-ai holds one of these and calls
/// [`WasmAiRoutingProgram::plan`] with the `ai` decision document,
/// the same vocabulary the inline engines read.
pub struct WasmAiRoutingProgram {
    type_name: String,
    program: EnvelopeWasmProgram,
}

impl std::fmt::Debug for WasmAiRoutingProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasmAiRoutingProgram")
            .field("type_name", &self.type_name)
            .field("program", &self.program)
            .finish()
    }
}

/// Build an AI routing program from a validated envelope WASM hook.
///
/// Runs the same prepare path as every other envelope adapter: the
/// hook's `config_schema` defaults are applied to `vars`, declared
/// `secret_vars` are resolved, the resolved config is validated
/// against the hook's own schema, and the bundle's sandbox budget and
/// buffer limits are attached to the program.
pub fn build_wasm_ai_routing(
    hook: &LoadedBundleHook,
    vars: Value,
) -> Result<WasmAiRoutingProgram, BundleLoadError> {
    let (type_name, program) = prepare_wasm_program(hook, BundleHookKind::AiRouting, vars)?;
    Ok(WasmAiRoutingProgram { type_name, program })
}

impl WasmAiRoutingProgram {
    /// The hook's `type:` name, echoed for labels and error messages.
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// Invoke the guest with the `ai` decision document and return the
    /// raw plan JSON from its response envelope.
    ///
    /// `Value::Null` is a legitimate decline; any other value is
    /// handed to sbproxy-ai's plan decoder untouched, so this crate
    /// never learns the routing-plan schema. Faults (timeout, guest
    /// trap, resource caps, malformed envelope) map to [`PluginError`]
    /// exactly like the policy adapter's.
    pub async fn plan(&self, ai_document: Value) -> Result<Value, PluginError> {
        let output = self.program.invoke("ai", ai_document).await?;
        envelope::decode_route_document(&output).map_err(envelope_plugin_error)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::{Bytes, BytesMut};
    use sbproxy_config::{BundleHookKind, ExtensionBundlesConfig};
    use sbproxy_plugin::{
        ActionHandler, ActionOutcome, PolicyDecision, PolicyEnforcer, TransformContext,
        TransformHandler,
    };
    use serde_json::json;
    use tempfile::TempDir;

    use super::{
        build_wasm_action, build_wasm_ai_routing, build_wasm_policy, build_wasm_transform,
        EnvelopeWasmProgram, WasmExecutor,
    };
    use crate::bundle::{BundleRegistry, DynamicBundleRegistry, LoadedBundleHook};
    use crate::wasm::{WasmBundleLimits, WasmCallFailure, WasmRuntime};

    struct BundleFixture {
        _directory: TempDir,
        registry: Arc<DynamicBundleRegistry>,
    }

    impl BundleFixture {
        fn hook(&self, kind: BundleHookKind, type_name: &str) -> &LoadedBundleHook {
            match kind {
                BundleHookKind::Policy => self.registry.policy(type_name),
                BundleHookKind::Transform => self.registry.transform(type_name),
                BundleHookKind::Action => self.registry.action(type_name),
                BundleHookKind::AiRouting => self.registry.ai_routing(type_name),
                _ => None,
            }
            .expect("fixture hook should load")
        }
    }

    fn fixture(entry: &str, hooks: &str, sandbox: &str) -> BundleFixture {
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/bundle/testdata/wasm")
                .join(entry),
            bundle.join("entry.wasm"),
        )
        .unwrap();
        std::fs::write(
            bundle.join("bundle.yaml"),
            format!(
                "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: wasm-fixture\nversion: 1.0.0\nruntime: wasm\nabi: sbproxy-envelope/v1\nentry: entry.wasm\nhooks:\n{hooks}{sandbox}"
            ),
        )
        .unwrap();
        let config = ExtensionBundlesConfig {
            bundles_dir: Some(directory.path().display().to_string()),
            sources: Vec::new(),
            grants: Default::default(),
        };
        let registry = DynamicBundleRegistry::load(&config, directory.path(), &BTreeSet::new())
            .expect("WASM fixture should load");
        BundleFixture {
            _directory: directory,
            registry,
        }
    }

    fn request(body: &'static [u8]) -> http::Request<Bytes> {
        http::Request::builder()
            .method("POST")
            .uri("https://test.sbproxy.dev/widgets")
            .header("x-plan", "free")
            .body(Bytes::from_static(body))
            .unwrap()
    }

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

    fn runtime(entry: &str, limits: WasmBundleLimits) -> Arc<WasmRuntime> {
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/bundle/testdata/wasm")
                .join(entry),
        )
        .unwrap();
        Arc::new(WasmRuntime::from_bundle_bytes(&bytes, limits).unwrap())
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

    fn metric_value(name: &str, labels: &[(&str, &str)]) -> f64 {
        sbproxy_observe::metrics::metrics()
            .render()
            .lines()
            .find_map(|line| {
                if !line.starts_with(name)
                    || labels
                        .iter()
                        .any(|(key, value)| !line.contains(&format!("{key}=\"{value}\"")))
                {
                    return None;
                }
                line.split_whitespace().nth(1)?.parse().ok()
            })
            .unwrap_or(0.0)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn envelope_wasm_one_module_serves_policy_and_transform() {
        let fixture = fixture(
            "dispatch.wasm",
            "  - kind: policy\n    type: wasm_policy_fixture\n  - kind: transform\n    type: wasm_transform_fixture\n",
            "",
        );
        let policy_hook = fixture.hook(BundleHookKind::Policy, "wasm_policy_fixture");
        let transform_hook = fixture.hook(BundleHookKind::Transform, "wasm_transform_fixture");
        assert!(Arc::ptr_eq(
            policy_hook.prepared_wasm_runtime().unwrap(),
            transform_hook.prepared_wasm_runtime().unwrap()
        ));

        let policy = build_wasm_policy(policy_hook, json!({})).unwrap();
        let transform = build_wasm_transform(transform_hook, json!({})).unwrap();
        let mut context = ();
        assert_eq!(
            policy
                .enforce(&request(b"hello"), &mut context)
                .await
                .unwrap(),
            PolicyDecision::Deny {
                status: 403,
                message: "upgrade required".to_owned(),
            }
        );
        let mut body = BytesMut::from(&b"original"[..]);
        transform
            .apply(
                &mut body,
                Some("text/plain"),
                &TransformContext::new("fixture"),
            )
            .await
            .unwrap();
        assert_eq!(&body[..], b"replaced");
    }

    // WOR-2289: bundle config var secret resolution + masking. The
    // resolution and masking logic itself is exercised exhaustively in
    // `envelope`'s own tests (env:, ${VAR}, file:, and a provider-URI
    // form, plus a literal-passthrough case); this test only proves the
    // WASM build path is wired to it and never echoes a resolved value.
    #[test]
    fn wasm_policy_debug_never_echoes_a_resolved_bundle_secret() {
        let secret_dir = TempDir::new().unwrap();
        let secret_path = secret_dir.path().join("token");
        std::fs::write(&secret_path, "DISTINCTIVE_WASM_SECRET_c92e").unwrap();

        let fixture = fixture(
            "dispatch.wasm",
            "  - kind: policy\n    type: wasm_policy_fixture\n    config_schema:\n      type: object\n      properties:\n        token:\n          type: string\n    secret_vars: [token]\n  - kind: transform\n    type: wasm_transform_fixture\n",
            "",
        );
        let hook = fixture.hook(BundleHookKind::Policy, "wasm_policy_fixture");
        let policy = build_wasm_policy(
            hook,
            json!({ "token": format!("file:{}", secret_path.display()) }),
        )
        .unwrap();

        let rendered = format!("{policy:?}");
        assert!(
            !rendered.contains("DISTINCTIVE_WASM_SECRET_c92e"),
            "{rendered}"
        );
        assert!(rendered.contains("REDACTED:token"), "{rendered}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn envelope_wasm_action_returns_a_validated_response() {
        let fixture = fixture(
            "action.wasm",
            "  - kind: action\n    type: wasm_action_fixture\n",
            "",
        );
        let adapter = build_wasm_action(
            fixture.hook(BundleHookKind::Action, "wasm_action_fixture"),
            json!({}),
        )
        .unwrap();
        let mut input = request(b"");
        let mut context = ();
        assert_eq!(
            adapter.handle(&mut input, &mut context).await.unwrap(),
            ActionOutcome::Response {
                status: 202,
                headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
                body: Bytes::from_static(b"queued"),
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn envelope_wasm_ai_routing_round_trips_a_plan_envelope() {
        let fixture = fixture(
            "ai-routing-plan.wasm",
            "  - kind: ai_routing\n    type: wasm_ai_routing_fixture\n    execution:\n      body_mode: none\n",
            "",
        );
        let program = build_wasm_ai_routing(
            fixture.hook(BundleHookKind::AiRouting, "wasm_ai_routing_fixture"),
            json!({}),
        )
        .unwrap();
        assert_eq!(program.type_name(), "wasm_ai_routing_fixture");
        let plan = program
            .plan(json!({ "model": "gpt-4o", "intent": "chat" }))
            .await
            .unwrap();
        assert_eq!(
            plan,
            json!({
                "candidates": [{ "provider_id": "frontier", "model": "gpt-4o" }],
                "reason": "from wasm",
            })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn envelope_wasm_ai_routing_null_plan_is_a_decline() {
        // The guest declines when the `ai` document carries the bytes
        // "decline"; the adapter must surface that as `Value::Null`,
        // not an error, so the caller can fall through to its own
        // routing.
        let fixture = fixture(
            "ai-routing-plan.wasm",
            "  - kind: ai_routing\n    type: wasm_ai_routing_fixture\n    execution:\n      body_mode: none\n",
            "",
        );
        let program = build_wasm_ai_routing(
            fixture.hook(BundleHookKind::AiRouting, "wasm_ai_routing_fixture"),
            json!({}),
        )
        .unwrap();
        let plan = program.plan(json!({ "intent": "decline" })).await.unwrap();
        assert!(plan.is_null(), "{plan}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn envelope_wasm_rejects_bad_responses() {
        for (entry, code) in [
            ("malformed.wasm", "invalid_envelope"),
            ("wrong-version.wasm", "invalid_version"),
        ] {
            let fixture = fixture(
                entry,
                "  - kind: policy\n    type: wasm_policy_fixture\n",
                "",
            );
            let adapter = build_wasm_policy(
                fixture.hook(BundleHookKind::Policy, "wasm_policy_fixture"),
                json!({}),
            )
            .unwrap();
            let mut context = ();
            let error = adapter
                .enforce(&request(b""), &mut context)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("wasm bundle hook failed: {code}")
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn envelope_wasm_enforces_input_and_stdout_caps() {
        let fixture = fixture(
            "dispatch.wasm",
            "  - kind: policy\n    type: wasm_policy_fixture\n",
            "sandbox:\n  max_buffer_bytes: 256\n",
        );
        let adapter = build_wasm_policy(
            fixture.hook(BundleHookKind::Policy, "wasm_policy_fixture"),
            json!({}),
        )
        .unwrap();
        let mut context = ();
        let error = adapter
            .enforce(&request(&[b'x'; 300]), &mut context)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "wasm bundle hook failed: input_limit");

        let mut cap_limits = limits();
        cap_limits.max_output_bytes = 256;
        let oversized = runtime("oversized.wasm", cap_limits);
        let invocation_runtime = Arc::clone(&oversized);
        assert_eq!(
            tokio::task::spawn_blocking(move || invocation_runtime.execute_bounded(b"{}"))
                .await
                .unwrap(),
            Err(WasmCallFailure::OutputLimit)
        );
        assert!(oversized.last_retained_stdout_bytes() <= 257);
    }

    #[test]
    fn envelope_wasm_classifies_fuel_timeout_memory_and_stack_limits() {
        let mut fuel_limits = limits();
        fuel_limits.fuel = 1;
        assert_eq!(
            runtime("loop.wasm", fuel_limits).execute_bounded(b"{}"),
            Err(WasmCallFailure::FuelLimit)
        );

        let mut timeout_limits = limits();
        timeout_limits.budget = Duration::from_millis(2);
        assert_eq!(
            runtime("loop.wasm", timeout_limits).execute_bounded(b"{}"),
            Err(WasmCallFailure::Timeout)
        );

        let mut memory_limits = limits();
        memory_limits.memory_bytes = 1024 * 1024;
        let memory = runtime("memory.wasm", memory_limits);
        assert_eq!(
            memory.execute_bounded(b"{}"),
            Err(WasmCallFailure::MemoryLimit)
        );
        assert_eq!(
            memory.execute_bounded(b"{}"),
            Err(WasmCallFailure::MemoryLimit),
            "a failed call must not poison the compiled runtime"
        );

        let mut stack_limits = limits();
        stack_limits.stack_bytes = 64 * 1024;
        assert_eq!(
            runtime("stack.wasm", stack_limits).execute_bounded(b"{}"),
            Err(WasmCallFailure::StackLimit)
        );
    }

    #[test]
    fn envelope_wasm_classifies_table_growth_limit() {
        assert_eq!(
            runtime("table-grow.wasm", limits()).execute_bounded(b"{}"),
            Err(WasmCallFailure::TableLimit)
        );
    }

    #[test]
    fn envelope_wasm_uses_a_fresh_instance_for_every_call() {
        let runtime = runtime("fresh-global.wasm", limits());
        let expected = br#"{"version":"sbproxy-envelope/v1","decision":"allow"}"#;
        assert_eq!(runtime.execute_bounded(b"{}").unwrap(), expected);
        assert_eq!(runtime.execute_bounded(b"{}").unwrap(), expected);
    }

    #[test]
    fn envelope_wasm_captures_guest_stderr_instead_of_sinking_it() {
        // WOR-2364 §1: the envelope path handed the guest a
        // `SinkOutputStream`, so a hook that refused a request could
        // not say why. The legacy module path kept its diagnostics the
        // whole time, which made the bundle path, the one operators
        // actually author against, the one that dropped them.
        let runtime = runtime("stderr-diagnostic.wasm", limits());
        let output = runtime.execute_bounded(b"{}").unwrap();
        assert_eq!(
            output, br#"{"version":"sbproxy-envelope/v1","decision":"release"}"#,
            "the decision itself must be unaffected by capturing stderr"
        );
        assert_eq!(
            runtime.last_guest_stderr_lines(),
            2,
            "both diagnostic lines the guest wrote must reach the host"
        );
    }

    #[test]
    fn envelope_wasm_reports_no_stderr_for_a_silent_guest() {
        // The counter has to distinguish "nothing written" from
        // "written and dropped", otherwise it cannot be used to tell an
        // operator whether the guest said anything at all.
        let runtime = runtime("fresh-global.wasm", limits());
        runtime.execute_bounded(b"{}").unwrap();
        assert_eq!(runtime.last_guest_stderr_lines(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn envelope_wasm_pool_is_bounded_and_keeps_tokio_responsive() {
        let mut call_limits = limits();
        call_limits.budget = Duration::from_millis(40);
        call_limits.fuel = 1_000_000_000;
        let runtime = runtime("loop.wasm", call_limits);
        let program = EnvelopeWasmProgram::for_test(runtime);
        let execution_observer = program.clone();
        let executor = Arc::new(WasmExecutor::start(1, 1).unwrap());

        let first = tokio::spawn({
            let executor = Arc::clone(&executor);
            let program = program.clone();
            async move { executor.execute(program, b"{}".to_vec()).await }
        });
        let second = tokio::spawn({
            let executor = Arc::clone(&executor);
            let program = program.clone();
            async move { executor.execute(program, b"{}".to_vec()).await }
        });
        wait_until("bounded executor admission", || {
            executor.available_admission() == 0
        })
        .await;
        wait_until("first Wasmtime execution", || {
            execution_observer.execution_started()
        })
        .await;
        assert_eq!(executor.available_admission(), 0);

        let (responsive, observed) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = responsive.send(());
        });
        tokio::time::timeout(Duration::from_millis(30), observed)
            .await
            .expect("Tokio task must run while Wasmtime occupies its OS worker")
            .expect("responsiveness sender must complete");
        let third = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(program, b"{}".to_vec()).await }
        });
        tokio::task::yield_now().await;
        assert!(
            !third.is_finished(),
            "third call should wait for bounded admission"
        );

        assert_eq!(first.await.unwrap(), Err(WasmCallFailure::Timeout));
        assert_eq!(second.await.unwrap(), Err(WasmCallFailure::Timeout));
        assert_eq!(third.await.unwrap(), Err(WasmCallFailure::Timeout));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn envelope_wasm_expired_queued_work_never_starts() {
        let mut slow_limits = limits();
        slow_limits.budget = Duration::from_millis(80);
        slow_limits.fuel = 1_000_000_000;
        let slow = EnvelopeWasmProgram::for_test_with_budget(
            runtime("loop.wasm", slow_limits),
            Duration::from_millis(80),
        );
        let slow_observer = slow.clone();
        let mut abandoned_limits = limits();
        abandoned_limits.budget = Duration::from_millis(50);
        abandoned_limits.fuel = 1_000_000_000;
        let abandoned = EnvelopeWasmProgram::for_test_with_budget(
            runtime("loop.wasm", abandoned_limits),
            Duration::from_millis(20),
        );
        let abandoned_observer = abandoned.clone();
        let healthy = EnvelopeWasmProgram::for_test_with_budget(
            runtime("fresh-global.wasm", limits()),
            Duration::from_millis(500),
        );
        let executor = Arc::new(WasmExecutor::start(1, 2).unwrap());

        let first = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(slow, b"{}".to_vec()).await }
        });
        wait_until("slow Wasmtime execution", || {
            slow_observer.execution_started()
        })
        .await;
        assert_eq!(
            executor.execute(abandoned, b"{}".to_vec()).await,
            Err(WasmCallFailure::Timeout)
        );
        let healthy_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(healthy, b"{}".to_vec()).await }
        });

        assert_eq!(first.await.unwrap(), Err(WasmCallFailure::Timeout));
        assert!(healthy_call.await.unwrap().is_ok());
        assert!(
            !abandoned_observer.execution_started(),
            "an expired queued guest must not consume the worker"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canceled_queued_wasm_is_removed_before_execution() {
        const METRICS_ENGINE: &str = "wasm_test_cancelled_queued";
        let mut blocker_limits = limits();
        blocker_limits.budget = Duration::from_millis(100);
        blocker_limits.fuel = 1_000_000_000;
        let blocker = EnvelopeWasmProgram::for_test_with_budget(
            runtime("loop.wasm", blocker_limits),
            Duration::from_millis(100),
        )
        .with_metrics_engine(METRICS_ENGINE);
        let blocker_observer = blocker.clone();
        let mut canceled_limits = limits();
        canceled_limits.budget = Duration::from_millis(300);
        canceled_limits.fuel = 1_000_000_000;
        let canceled = EnvelopeWasmProgram::for_test_with_budget(
            runtime("loop.wasm", canceled_limits),
            Duration::from_millis(300),
        )
        .with_metrics_engine(METRICS_ENGINE);
        let canceled_observer = canceled.clone();
        let healthy = EnvelopeWasmProgram::for_test_with_budget(
            runtime("fresh-global.wasm", limits()),
            Duration::from_millis(500),
        )
        .with_metrics_engine(METRICS_ENGINE);
        let executor = Arc::new(WasmExecutor::start(1, 2).unwrap());
        let before = metric_value(
            "sbproxy_script_invocations_total",
            &[("engine", METRICS_ENGINE), ("result", "cancelled")],
        );

        let blocker_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(blocker, b"{}".to_vec()).await }
        });
        wait_until("blocker execution", || blocker_observer.execution_started()).await;
        let canceled_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(canceled, b"{}".to_vec()).await }
        });
        wait_until("canceled call queue admission", || {
            executor.available_admission() == 1
        })
        .await;
        canceled_call.abort();
        assert!(canceled_call.await.unwrap_err().is_cancelled());
        assert_eq!(
            executor.available_admission(),
            2,
            "canceling a queued call must release its admission permit immediately"
        );

        let healthy_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(healthy, b"{}".to_vec()).await }
        });
        assert_eq!(blocker_call.await.unwrap(), Err(WasmCallFailure::Timeout));
        assert!(healthy_call.await.unwrap().is_ok());
        assert!(canceled_observer.execution_finished());
        assert!(
            !canceled_observer.execution_started(),
            "a canceled queued call must never enter Wasmtime"
        );
        assert_eq!(
            metric_value(
                "sbproxy_script_invocations_total",
                &[("engine", METRICS_ENGINE), ("result", "cancelled")],
            ) - before,
            1.0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canceled_running_wasm_releases_its_worker() {
        const METRICS_ENGINE: &str = "wasm_test_cancelled_running";
        let mut runaway_limits = limits();
        runaway_limits.budget = Duration::from_millis(500);
        runaway_limits.fuel = 1_000_000_000;
        let runaway = EnvelopeWasmProgram::for_test_with_budget(
            runtime("loop.wasm", runaway_limits),
            Duration::from_millis(500),
        )
        .with_metrics_engine(METRICS_ENGINE);
        let runaway_observer = runaway.clone();
        let healthy = EnvelopeWasmProgram::for_test_with_budget(
            runtime("fresh-global.wasm", limits()),
            Duration::from_millis(100),
        )
        .with_metrics_engine(METRICS_ENGINE);
        let executor = Arc::new(WasmExecutor::start(1, 1).unwrap());
        let before = metric_value(
            "sbproxy_script_invocations_total",
            &[("engine", METRICS_ENGINE), ("result", "cancelled")],
        );

        let runaway_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(runaway, b"{}".to_vec()).await }
        });
        wait_until("runaway execution", || runaway_observer.execution_started()).await;
        runaway_call.abort();
        assert!(runaway_call.await.unwrap_err().is_cancelled());

        assert!(executor.execute(healthy, b"{}".to_vec()).await.is_ok());
        wait_until("canceled Wasmtime execution to stop", || {
            runaway_observer.execution_finished()
        })
        .await;
        assert_eq!(
            metric_value(
                "sbproxy_script_invocations_total",
                &[("engine", METRICS_ENGINE), ("result", "cancelled")],
            ) - before,
            1.0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_timeout_records_one_invocation_and_total_duration() {
        const METRICS_ENGINE: &str = "wasm_test_queue_timeout";
        let before_timeout = metric_value(
            "sbproxy_script_invocations_total",
            &[("engine", METRICS_ENGINE), ("result", "queue_timeout")],
        );
        let before_duration = metric_value(
            "sbproxy_script_duration_seconds_count",
            &[("engine", METRICS_ENGINE)],
        );
        let mut blocker_limits = limits();
        blocker_limits.budget = Duration::from_millis(100);
        blocker_limits.fuel = 1_000_000_000;
        let blocker = EnvelopeWasmProgram::for_test_with_budget(
            runtime("loop.wasm", blocker_limits),
            Duration::from_millis(100),
        )
        .with_metrics_engine(METRICS_ENGINE);
        let blocker_observer = blocker.clone();
        let queued = EnvelopeWasmProgram::for_test_with_budget(
            runtime("loop.wasm", limits()),
            Duration::from_millis(20),
        )
        .with_metrics_engine(METRICS_ENGINE);
        let executor = Arc::new(WasmExecutor::start(1, 1).unwrap());

        let blocker_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(blocker, b"{}".to_vec()).await }
        });
        wait_until("blocker execution", || blocker_observer.execution_started()).await;
        assert_eq!(
            executor.execute(queued, b"{}".to_vec()).await,
            Err(WasmCallFailure::Timeout)
        );
        assert_eq!(blocker_call.await.unwrap(), Err(WasmCallFailure::Timeout));

        assert_eq!(
            metric_value(
                "sbproxy_script_invocations_total",
                &[("engine", METRICS_ENGINE), ("result", "queue_timeout")],
            ) - before_timeout,
            1.0
        );
        assert_eq!(
            metric_value(
                "sbproxy_script_duration_seconds_count",
                &[("engine", METRICS_ENGINE)],
            ) - before_duration,
            2.0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admission_timeout_records_one_invocation_and_total_duration() {
        const METRICS_ENGINE: &str = "wasm_test_admission_timeout";
        let before_timeout = metric_value(
            "sbproxy_script_invocations_total",
            &[("engine", METRICS_ENGINE), ("result", "admission_timeout")],
        );
        let before_duration = metric_value(
            "sbproxy_script_duration_seconds_count",
            &[("engine", METRICS_ENGINE)],
        );
        let mut running_limits = limits();
        running_limits.budget = Duration::from_millis(100);
        running_limits.fuel = 1_000_000_000;
        let running = EnvelopeWasmProgram::for_test_with_budget(
            runtime("loop.wasm", running_limits),
            Duration::from_millis(100),
        )
        .with_metrics_engine(METRICS_ENGINE);
        let running_observer = running.clone();
        let mut queued_limits = limits();
        queued_limits.budget = Duration::from_millis(300);
        queued_limits.fuel = 1_000_000_000;
        let queued = EnvelopeWasmProgram::for_test_with_budget(
            runtime("loop.wasm", queued_limits),
            Duration::from_millis(300),
        )
        .with_metrics_engine(METRICS_ENGINE);
        let waiting_for_admission = EnvelopeWasmProgram::for_test_with_budget(
            runtime("fresh-global.wasm", limits()),
            Duration::from_millis(20),
        )
        .with_metrics_engine(METRICS_ENGINE);
        let executor = Arc::new(WasmExecutor::start(1, 1).unwrap());

        let running_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(running, b"{}".to_vec()).await }
        });
        wait_until("running call", || running_observer.execution_started()).await;
        let queued_call = tokio::spawn({
            let executor = Arc::clone(&executor);
            async move { executor.execute(queued, b"{}".to_vec()).await }
        });
        wait_until("full executor admission", || {
            executor.available_admission() == 0
        })
        .await;
        assert_eq!(
            executor
                .execute(waiting_for_admission, b"{}".to_vec())
                .await,
            Err(WasmCallFailure::Timeout)
        );
        assert_eq!(running_call.await.unwrap(), Err(WasmCallFailure::Timeout));
        assert_eq!(queued_call.await.unwrap(), Err(WasmCallFailure::Timeout));

        assert_eq!(
            metric_value(
                "sbproxy_script_invocations_total",
                &[("engine", METRICS_ENGINE), ("result", "admission_timeout")],
            ) - before_timeout,
            1.0
        );
        assert_eq!(
            metric_value(
                "sbproxy_script_duration_seconds_count",
                &[("engine", METRICS_ENGINE)],
            ) - before_duration,
            3.0
        );
    }

    #[test]
    fn envelope_wasm_worker_spawn_failure_is_a_safe_runtime_error() {
        let result = WasmExecutor::start_with_spawner(1, 1, |_worker_index, _receiver| {
            Err(io::Error::other("synthetic thread failure"))
        });
        assert!(matches!(result, Err(WasmCallFailure::HostFailure)));
    }
}
