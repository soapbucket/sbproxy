use std::io;
use std::pin::Pin;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
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
use crate::wasm::{WasmCallFailure, WasmRuntime};

const MAX_WASM_WORKERS: usize = 4;
const QUEUE_SLOTS_PER_WORKER: usize = 2;
const WASM_WORKER_STACK_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct EnvelopeWasmProgram {
    runtime: Arc<WasmRuntime>,
    hook_kind: &'static str,
    type_name: Arc<str>,
    config: Arc<Value>,
    max_input_bytes: usize,
    max_output_bytes: usize,
    budget: std::time::Duration,
    #[cfg(test)]
    execution_started: Arc<AtomicBool>,
}

impl std::fmt::Debug for EnvelopeWasmProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvelopeWasmProgram")
            .field("hook_kind", &self.hook_kind)
            .field("type_name", &self.type_name)
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
            hook_kind: "policy",
            type_name: Arc::from("test"),
            config: Arc::new(json!({})),
            max_input_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            budget,
            execution_started: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    fn execution_started(&self) -> bool {
        self.execution_started.load(Ordering::Relaxed)
    }

    fn mark_execution_started(&self) {
        #[cfg(test)]
        self.execution_started.store(true, Ordering::Relaxed);
    }
}

struct WasmJob {
    program: EnvelopeWasmProgram,
    input: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, WasmCallFailure>>,
    deadline: std::time::Instant,
    _permit: OwnedSemaphorePermit,
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
        let deadline = std::time::Instant::now() + budget;
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let permit = Arc::clone(&self.admission)
                .acquire_owned()
                .await
                .map_err(|_| WasmCallFailure::HostFailure)?;
            let (reply, response) = oneshot::channel();
            self.sender
                .send(WasmJob {
                    program,
                    input,
                    reply,
                    deadline,
                    _permit: permit,
                })
                .await
                .map_err(|_| WasmCallFailure::HostFailure)?;
            response.await.map_err(|_| WasmCallFailure::HostFailure)?
        })
        .await
        .unwrap_or(Err(WasmCallFailure::Timeout))
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
        let result = match job
            .deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
        {
            Some(remaining) => {
                job.program.mark_execution_started();
                job.program
                    .runtime
                    .execute_bounded_with_budget(&job.input, remaining)
            }
            None => Err(WasmCallFailure::Timeout),
        };
        let _ = job.reply.send(result);
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
    let mut config = config;
    if let Some(schema) = hook.hook().config_schema.as_ref() {
        envelope::apply_schema_defaults(&mut config, schema);
    }
    hook.validate_config(&config)
        .map_err(|error| BundleLoadError::new("config", error.to_string()))?;
    let runtime = hook
        .prepared_wasm_runtime()
        .ok_or_else(|| BundleLoadError::new("wasm", "bundle has no prepared WASM runtime"))?;
    let max_input_bytes = usize::try_from(hook.manifest().sandbox.max_buffer_bytes)
        .map_err(|_| BundleLoadError::new("wasm", "input limit is unsupported"))?;
    let max_output_bytes = usize::try_from(hook.manifest().sandbox.max_output_bytes)
        .map_err(|_| BundleLoadError::new("wasm", "output limit is unsupported"))?;
    let type_name = hook.hook().type_name.clone();
    Ok((
        type_name.clone(),
        EnvelopeWasmProgram {
            runtime: Arc::clone(runtime),
            hook_kind: envelope::hook_kind_label(expected_kind),
            type_name: Arc::from(type_name),
            config: Arc::new(config),
            max_input_bytes,
            max_output_bytes,
            budget: std::time::Duration::from_millis(hook.manifest().sandbox.budget_ms),
            #[cfg(test)]
            execution_started: Arc::new(AtomicBool::new(false)),
        },
    ))
}

fn envelope_plugin_error(error: EnvelopeError) -> PluginError {
    PluginError::Internal(anyhow::anyhow!("wasm bundle hook failed: {}", error.code()))
}

fn wasm_plugin_error(error: WasmCallFailure) -> PluginError {
    if error == WasmCallFailure::Timeout {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::{Bytes, BytesMut};
    use sbproxy_config::{BundleHookKind, ExtensionBundlesConfig};
    use sbproxy_plugin::{
        ActionHandler, ActionOutcome, PolicyDecision, PolicyEnforcer, TransformContext,
        TransformHandler,
    };
    use serde_json::json;
    use tempfile::TempDir;

    use super::{
        build_wasm_action, build_wasm_policy, build_wasm_transform, EnvelopeWasmProgram,
        WasmExecutor,
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
    fn envelope_wasm_uses_a_fresh_instance_for_every_call() {
        let runtime = runtime("fresh-global.wasm", limits());
        let expected = br#"{"version":"sbproxy-envelope/v1","decision":"allow"}"#;
        assert_eq!(runtime.execute_bounded(b"{}").unwrap(), expected);
        assert_eq!(runtime.execute_bounded(b"{}").unwrap(), expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn envelope_wasm_pool_is_bounded_and_keeps_tokio_responsive() {
        let mut call_limits = limits();
        call_limits.budget = Duration::from_millis(40);
        call_limits.fuel = 1_000_000_000;
        let runtime = runtime("loop.wasm", call_limits);
        let program = EnvelopeWasmProgram::for_test(runtime);
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
        let admission_deadline = Instant::now() + Duration::from_millis(100);
        while executor.available_admission() != 0 && Instant::now() < admission_deadline {
            tokio::task::yield_now().await;
        }
        assert_eq!(executor.available_admission(), 0);

        let started = Instant::now();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(started.elapsed() < Duration::from_millis(30));
        let third_started = Instant::now();
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
        assert!(
            third_started.elapsed() < Duration::from_millis(70),
            "queue time must count against the hook budget"
        );
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
        tokio::time::sleep(Duration::from_millis(5)).await;
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

    #[test]
    fn envelope_wasm_worker_spawn_failure_is_a_safe_runtime_error() {
        let result = WasmExecutor::start_with_spawner(1, 1, |_worker_index, _receiver| {
            Err(io::Error::other("synthetic thread failure"))
        });
        assert!(matches!(result, Err(WasmCallFailure::HostFailure)));
    }
}
