use std::sync::Arc;

use bytes::Bytes;
use sbproxy_config::{
    BundleExecutionMode, BundleHookKind, BundleRuntime, EnforcementMode, FailureMode,
};
use sbproxy_observe::metrics::record_channel_drop;
use sbproxy_plugin::{
    collect_linked_ai_extension_hooks, AiExtensionDecision, AiExtensionEnforcement,
    AiExtensionEvent, AiExtensionEventPayload, AiExtensionHook, ExtensionHookKind, PluginError,
    PluginResult, AI_EXTENSION_EVENT_SCHEMA_VERSION,
};
use tokio::sync::mpsc;

use super::envelope::decode_ai_decision;
use super::events::EnvelopeEventProgram;
use super::proxy_wasm::{
    build_proxy_wasm_filter_for_kind, ProxyWasmAction, ProxyWasmFilter, ProxyWasmLocalResponse,
    ProxyWasmSession,
};
use super::{BundleLoadError, BundleRegistry, LoadedBundleHook};

const OBSERVATION_QUEUE_CAPACITY: usize = 64;
const MAX_PROXY_WASM_BLOCK_MESSAGE_BYTES: usize = 4 * 1024;

const AI_HOOK_KINDS: [(BundleHookKind, ExtensionHookKind); 6] = [
    (
        BundleHookKind::AiGuardrailInput,
        ExtensionHookKind::AiGuardrailInput,
    ),
    (
        BundleHookKind::AiGuardrailOutput,
        ExtensionHookKind::AiGuardrailOutput,
    ),
    (BundleHookKind::AiToolCall, ExtensionHookKind::AiToolCall),
    (
        BundleHookKind::AiStreamEvent,
        ExtensionHookKind::AiStreamEvent,
    ),
    (BundleHookKind::AiClose, ExtensionHookKind::AiClose),
    (BundleHookKind::AiFailure, ExtensionHookKind::AiFailure),
];

#[derive(Clone)]
enum PreparedAiRunner {
    Linked(Arc<dyn AiExtensionHook>),
    Envelope(EnvelopeEventProgram),
    ProxyWasm(ProxyWasmFilter),
}

#[derive(Clone)]
struct PreparedAiHook {
    id: String,
    /// Inventory lookup key, so a reported chain position can be matched
    /// back to the hook record the operator sees (WOR-2272).
    match_key: String,
    kind: ExtensionHookKind,
    enforcement: AiExtensionEnforcement,
    failure_posture: FailureMode,
    /// Whether the manifest declared this hook may return `Mutate`.
    mutates: bool,
    /// Cap on a mutate body, from the manifest sandbox.
    max_buffer_bytes: usize,
    /// Inspect-only input hook that runs alongside the upstream call.
    parallel: bool,
    runner: PreparedAiRunner,
}

/// Immutable AI hook chain pinned to one compiled pipeline generation.
pub struct AiExtensionChain {
    hooks: Arc<[PreparedAiHook]>,
}

impl std::fmt::Debug for AiExtensionChain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AiExtensionChain")
            .field("hooks", &self.hooks.len())
            .finish()
    }
}

impl AiExtensionChain {
    /// Prepare linked and dynamic hooks in deterministic dispatch order.
    ///
    /// # Errors
    ///
    /// Returns a load error when registrations collide or one dynamic hook
    /// cannot be prepared from its validated bundle.
    pub fn from_registry(registry: &dyn BundleRegistry) -> Result<Self, BundleLoadError> {
        let mut hooks = Vec::new();
        for (bundle_kind, public_kind) in AI_HOOK_KINDS {
            let linked = collect_linked_ai_extension_hooks(public_kind)
                .map_err(|error| BundleLoadError::new("ai", error.to_string()))?;
            hooks.extend(linked.into_iter().map(|registration| PreparedAiHook {
                id: registration.id.to_owned(),
                match_key: registration.id.to_owned(),
                kind: public_kind,
                enforcement: registration.enforcement,
                failure_posture: FailureMode::Closed,
                // Linked registrations do not declare mutation yet, so a
                // linked hook returning `Mutate` is an engine fault under
                // its (closed) posture until the public registration
                // grows the flag. Inspect-only is the safe default.
                mutates: false,
                max_buffer_bytes: 0,
                parallel: false,
                runner: PreparedAiRunner::Linked((registration.factory)()),
            }));

            for hook in registry.ai_hooks(bundle_kind) {
                hooks.push(prepare_dynamic_hook(hook, bundle_kind, public_kind)?);
            }
        }
        Ok(Self {
            hooks: Arc::from(hooks),
        })
    }

    /// True when no linked or dynamic AI hooks were prepared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Return every prepared hook's kind and lookup key in dispatch order.
    ///
    /// Inventory used to re-derive a chain position by sorting hook
    /// identities alphabetically, which reported an order the pipeline
    /// never runs. This is the real one (WOR-2272).
    #[must_use]
    pub fn dispatch_order(&self) -> Vec<(ExtensionHookKind, String)> {
        self.hooks
            .iter()
            .map(|hook| (hook.kind, hook.match_key.clone()))
            .collect()
    }

    /// True when at least one hook receives this event kind.
    #[must_use]
    pub fn has_kind(&self, kind: ExtensionHookKind) -> bool {
        self.hooks.iter().any(|hook| hook.kind == kind)
    }

    /// True when at least one inline enforcing hook receives this event kind.
    #[must_use]
    pub fn has_enforcing(&self, kind: ExtensionHookKind) -> bool {
        self.hooks
            .iter()
            .any(|hook| hook.kind == kind && hook.enforcement == AiExtensionEnforcement::Block)
    }

    /// True when a sequential (pre-dispatch) hook receives this event kind.
    ///
    /// Parallel inspect-only input hooks are excluded: they run alongside
    /// the upstream call, not on the session [`Self::start_session`] builds.
    #[cfg(test)]
    #[must_use]
    fn has_sequential_kind(&self, kind: ExtensionHookKind) -> bool {
        self.hooks
            .iter()
            .any(|hook| hook.kind == kind && !hook.parallel)
    }

    /// True when a sequential enforcing hook receives this event kind.
    #[cfg(test)]
    #[must_use]
    fn has_sequential_enforcing(&self, kind: ExtensionHookKind) -> bool {
        self.hooks.iter().any(|hook| {
            hook.kind == kind && !hook.parallel && hook.enforcement == AiExtensionEnforcement::Block
        })
    }

    /// True when at least one inspect-only input hook runs alongside dispatch.
    #[cfg(test)]
    #[must_use]
    fn has_parallel_input(&self) -> bool {
        self.hooks.iter().any(|hook| hook.parallel)
    }

    /// Start request-local runtime state and a bounded observation drain.
    ///
    /// # Panics
    ///
    /// Panics when observe hooks exist and this method is called outside a
    /// Tokio runtime.
    #[must_use]
    pub fn start_session(&self) -> AiExtensionSession {
        let mut enforcing = Vec::new();
        let mut observing = Vec::new();
        let mut parallel = Vec::new();
        for hook in self.hooks.iter().cloned() {
            if hook.enforcement == AiExtensionEnforcement::Observe {
                observing.push(ActiveAiHook::from(hook));
            } else if hook.parallel {
                parallel.push(hook);
            } else {
                enforcing.push(ActiveAiHook::from(hook));
            }
        }

        let observer = if observing.is_empty() {
            None
        } else {
            let (sender, receiver) = observation_channel(OBSERVATION_QUEUE_CAPACITY);
            tokio::spawn(drain_observations(observing, receiver));
            Some(sender)
        };
        AiExtensionSession {
            enforcing,
            parallel,
            parallel_task: None,
            observer,
            last_sequence: None,
            finished: false,
        }
    }
}

fn prepare_dynamic_hook(
    hook: &LoadedBundleHook,
    bundle_kind: BundleHookKind,
    public_kind: ExtensionHookKind,
) -> Result<PreparedAiHook, BundleLoadError> {
    let runner = match hook.manifest().runtime {
        BundleRuntime::Javascript | BundleRuntime::Wasm => PreparedAiRunner::Envelope(
            EnvelopeEventProgram::prepare(hook, bundle_kind, serde_json::json!({}))?,
        ),
        BundleRuntime::ProxyWasm if bundle_kind == BundleHookKind::AiStreamEvent => {
            PreparedAiRunner::ProxyWasm(build_proxy_wasm_filter_for_kind(
                hook,
                BundleHookKind::AiStreamEvent,
                serde_json::json!({}),
            )?)
        }
        BundleRuntime::ProxyWasm => {
            return Err(BundleLoadError::new(
                "ai",
                "Proxy-Wasm supports only streamed AI extension events",
            ));
        }
        // WOR-2482: a Rego bundle hook is `kind: policy` or
        // `kind: transform` only (anything else is refused earlier at
        // manifest validation), so this arm is a defensive backstop
        // rather than a reachable path.
        BundleRuntime::Rego => {
            return Err(BundleLoadError::new(
                "ai",
                "runtime rego does not support AI extension events",
            ));
        }
    };
    let enforcement = match hook.hook().enforcement_mode {
        EnforcementMode::Block => AiExtensionEnforcement::Block,
        EnforcementMode::Observe => AiExtensionEnforcement::Observe,
    };
    Ok(PreparedAiHook {
        id: format!("{}:{}", hook.manifest().name, hook.hook().type_name),
        match_key: hook.hook().type_name.clone(),
        kind: public_kind,
        enforcement,
        failure_posture: hook.manifest().failure_posture,
        mutates: hook.hook().execution.mutates,
        max_buffer_bytes: usize::try_from(hook.manifest().sandbox.max_buffer_bytes)
            .unwrap_or(usize::MAX),
        parallel: hook.hook().execution.mode == BundleExecutionMode::Parallel,
        runner,
    })
}

enum ActiveAiRunner {
    Linked(Arc<dyn AiExtensionHook>),
    Envelope(EnvelopeEventProgram),
    ProxyWasm {
        filter: ProxyWasmFilter,
        session: Option<ProxyWasmSession>,
    },
}

struct ActiveAiHook {
    id: String,
    kind: ExtensionHookKind,
    failure_posture: FailureMode,
    /// Whether the manifest declared this hook may return `Mutate`. A
    /// linked Rust hook declares through its registration; a hook that
    /// returns `Mutate` without declaring is an engine fault under its
    /// posture, so the cheap inspect-only path is a manifest fact
    /// rather than an inference from what came back.
    mutates: bool,
    /// Cap on a mutate body. The envelope decoder caps bundle output at
    /// decode; this cap also covers linked hooks, which return the
    /// variant directly with no envelope in between.
    max_buffer_bytes: usize,
    runner: ActiveAiRunner,
}

impl From<PreparedAiHook> for ActiveAiHook {
    fn from(hook: PreparedAiHook) -> Self {
        let mutates = hook.mutates;
        let max_buffer_bytes = hook.max_buffer_bytes;
        let runner = match hook.runner {
            PreparedAiRunner::Linked(runner) => ActiveAiRunner::Linked(runner),
            PreparedAiRunner::Envelope(runner) => ActiveAiRunner::Envelope(runner),
            PreparedAiRunner::ProxyWasm(filter) => ActiveAiRunner::ProxyWasm {
                filter,
                session: None,
            },
        };
        Self {
            id: hook.id,
            kind: hook.kind,
            mutates,
            max_buffer_bytes,
            failure_posture: hook.failure_posture,
            runner,
        }
    }
}

impl ActiveAiHook {
    async fn invoke(&mut self, event: &AiExtensionEvent) -> PluginResult<AiExtensionDecision> {
        match &mut self.runner {
            ActiveAiRunner::Linked(hook) => hook.handle(event).await,
            ActiveAiRunner::Envelope(program) => {
                let output = program.invoke("event", event).await?;
                // The manifest's sandbox buffer cap bounds a mutate
                // body at decode, before the base64 payload becomes a
                // held allocation; dispatch re-checks it for runners
                // that have no envelope.
                decode_ai_decision(&output, self.max_buffer_bytes).map_err(|error| {
                    PluginError::Internal(anyhow::anyhow!(
                        "AI bundle hook returned {}",
                        error.code()
                    ))
                })
            }
            ActiveAiRunner::ProxyWasm { filter, session } => {
                invoke_proxy_wasm(filter, session, event)
            }
        }
    }

    fn finish(&mut self) -> PluginResult<()> {
        let ActiveAiRunner::ProxyWasm { session, .. } = &mut self.runner else {
            return Ok(());
        };
        if let Some(mut session) = session.take() {
            session.finish().map_err(proxy_wasm_error)?;
        }
        Ok(())
    }
}

/// Chain verdict for one dispatched event.
///
/// Distinct from [`AiExtensionDecision`], which is one hook's answer:
/// this is the whole enforcing chain's. `Mutated` carries no payload
/// because the applied content lives on the event the caller handed
/// in; there is exactly one copy of the truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiChainVerdict {
    /// Every enforcing hook released the event as delivered.
    Release,
    /// At least one hook rewrote the payload in place; read the event
    /// back rather than assuming it is what was sent.
    Mutated,
    /// A hook refused the event.
    Block {
        /// Client-safe refusal status.
        status: u16,
        /// Stable machine-readable refusal code.
        code: String,
        /// Client-safe refusal message.
        message: String,
    },
}

/// Request-local AI extension state.
pub struct AiExtensionSession {
    enforcing: Vec<ActiveAiHook>,
    parallel: Vec<PreparedAiHook>,
    parallel_task: Option<tokio::task::JoinHandle<PluginResult<AiChainVerdict>>>,
    observer: Option<mpsc::Sender<AiExtensionEvent>>,
    last_sequence: Option<u64>,
    finished: bool,
}

impl std::fmt::Debug for AiExtensionSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AiExtensionSession")
            .field("enforcing_hooks", &self.enforcing.len())
            .field("parallel_hooks", &self.parallel.len())
            .field("observing", &self.observer.is_some())
            .field("last_sequence", &self.last_sequence)
            .field("finished", &self.finished)
            .finish()
    }
}

impl AiExtensionSession {
    /// Deliver an event to observation hooks and await every enforcing hook.
    ///
    /// Events must have schema version 1 and strictly increasing sequence
    /// values. The first block verdict stops the chain. The observation
    /// lane receives the event as submitted, before any enforcing hook
    /// mutates it; mutations are attributed on the enforcing lane's log
    /// records.
    ///
    /// # Errors
    ///
    /// Returns a plugin error for an invalid event, an enforcing hook failure
    /// under closed posture, or use after [`Self::finish`].
    pub async fn dispatch(&mut self, event: &mut AiExtensionEvent) -> PluginResult<AiChainVerdict> {
        if self.finished {
            return Err(PluginError::Config(
                "AI extension session has already finished".to_owned(),
            ));
        }
        if event.schema_version != AI_EXTENSION_EVENT_SCHEMA_VERSION {
            return Err(PluginError::Config(
                "AI extension event uses an unsupported schema version".to_owned(),
            ));
        }
        if self
            .last_sequence
            .is_some_and(|sequence| event.sequence <= sequence)
        {
            return Err(PluginError::Config(
                "AI extension events must have increasing sequence values".to_owned(),
            ));
        }
        self.last_sequence = Some(event.sequence);

        if let Some(observer) = &self.observer {
            if let Err(error) = observer.try_send(event.clone()) {
                let reason = match error {
                    mpsc::error::TrySendError::Full(_) => "channel_full",
                    mpsc::error::TrySendError::Closed(_) => "receiver_closed",
                };
                record_channel_drop("hooks", reason);
            }
        }

        let kind = event.hook_kind();
        let mut mutated = false;
        for hook in self.enforcing.iter_mut().filter(|hook| hook.kind == kind) {
            // Hooks run in chain dispatch order (the order
            // `dispatch_order` reports: linked registrations first,
            // then bundle hooks sorted by type name) and each sees the
            // previous hook's output: the event is mutated in place,
            // so a redactor followed by a classifier classifies the
            // redacted payload rather than one that will never be
            // sent.
            match hook.invoke(event).await {
                Ok(AiExtensionDecision::Block {
                    status,
                    code,
                    message,
                }) => {
                    return Ok(AiChainVerdict::Block {
                        status,
                        code,
                        message,
                    });
                }
                Ok(AiExtensionDecision::Flag { code, message }) => {
                    tracing::info!(hook = %hook.id, %code, %message, "AI extension hook flagged an event");
                }
                Ok(AiExtensionDecision::Release) => {}
                Ok(AiExtensionDecision::Mutate { body, code }) => {
                    match Self::apply_hook_mutation(hook, event, &body) {
                        Ok(()) => {
                            mutated = true;
                            tracing::info!(
                                hook = %hook.id,
                                %code,
                                bytes = body.len(),
                                "AI extension hook mutated the event payload"
                            );
                        }
                        Err(reason) if hook.failure_posture.admits() => {
                            // The mutation is refused but the posture
                            // admits: the event continues UNMODIFIED,
                            // which is the same reading as a hook that
                            // errored. A half-applied mutation is not a
                            // state this chain can be in.
                            tracing::warn!(
                                hook = %hook.id,
                                posture = hook.failure_posture.as_label(),
                                %reason,
                                "AI extension hook mutation refused under an admitting posture"
                            );
                        }
                        Err(reason) => {
                            return Err(PluginError::Config(format!(
                                "AI extension hook `{}` returned an invalid mutation: {reason}",
                                hook.id
                            )));
                        }
                    }
                }
                // The enum is non_exhaustive for out-of-tree matchers;
                // in-tree, a variant this host does not know is a build
                // error upstream, so this arm is unreachable today and
                // deliberately conservative if that ever changes.
                Ok(_) => {
                    return Err(PluginError::Config(format!(
                        "AI extension hook `{}` returned a decision this host does not support",
                        hook.id
                    )));
                }
                Err(error) if hook.failure_posture.admits() => {
                    tracing::warn!(
                        hook = %hook.id,
                        posture = hook.failure_posture.as_label(),
                        error = %error,
                        "AI extension hook failed under an admitting posture"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        if mutated {
            self.arm_parallel_input(event);
            return Ok(AiChainVerdict::Mutated);
        }
        self.arm_parallel_input(event);
        Ok(AiChainVerdict::Release)
    }

    /// Start inspect-only input hooks alongside the rest of dispatch.
    ///
    /// Serial enforcing hooks have already run. A later `guard_input`
    /// (RAG's second scan) aborts the previous task so the last
    /// pre-dispatch body is the one that is judged.
    fn arm_parallel_input(&mut self, event: &AiExtensionEvent) {
        if event.hook_kind() != ExtensionHookKind::AiGuardrailInput || self.parallel.is_empty() {
            return;
        }
        self.abort_parallel();
        let hooks = self.parallel.clone();
        let event = event.clone();
        self.parallel_task = Some(tokio::spawn(run_parallel_input(hooks, event)));
    }

    fn abort_parallel(&mut self) {
        if let Some(task) = self.parallel_task.take() {
            task.abort();
        }
    }

    /// Take the in-flight parallel input task so the provider path can race it.
    ///
    /// Tokio's [`tokio::task::JoinHandle`] does not abort on drop. The caller must
    /// abort the task (or wrap the handle so drop does) or the inspect
    /// work keeps the prompt-bearing event until sandbox budget.
    #[must_use]
    pub fn take_parallel_task(
        &mut self,
    ) -> Option<tokio::task::JoinHandle<PluginResult<AiChainVerdict>>> {
        self.parallel_task.take()
    }

    /// Await the parallel input task, if one is armed.
    ///
    /// # Errors
    ///
    /// Returns a plugin error when the task was cancelled or a closed-posture
    /// hook failed.
    #[cfg(test)]
    async fn wait_parallel(&mut self) -> PluginResult<AiChainVerdict> {
        let Some(task) = self.take_parallel_task() else {
            return Ok(AiChainVerdict::Release);
        };
        match task.await {
            Ok(result) => result,
            Err(_) => Err(PluginError::Config(
                "parallel AI input hook task was cancelled".to_owned(),
            )),
        }
    }

    /// Validate and apply one hook's mutation to the event in place.
    ///
    /// Refusals are stable labels the posture logic maps like any other
    /// engine fault: an undeclared mutation (the manifest said
    /// inspect-only), an oversized body, a payload kind that does not
    /// accept mutation, or a body that does not parse as the kind's
    /// content shape.
    fn apply_hook_mutation(
        hook: &ActiveAiHook,
        event: &mut AiExtensionEvent,
        body: &[u8],
    ) -> Result<(), &'static str> {
        if !hook.mutates {
            return Err("mutation_not_declared");
        }
        if !event.payload.accepts_mutation() {
            return Err("event_not_mutable");
        }
        if hook.max_buffer_bytes != 0 && body.len() > hook.max_buffer_bytes {
            return Err("mutate_body_over_buffer_cap");
        }
        event.payload.apply_mutation(body)
    }

    /// Finish request-local Proxy-Wasm contexts and close the observation lane.
    ///
    /// # Errors
    ///
    /// Returns the first closed-posture cleanup failure.
    pub fn finish(&mut self) -> PluginResult<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        self.abort_parallel();
        self.observer.take();
        for hook in &mut self.enforcing {
            if let Err(error) = hook.finish() {
                if hook.failure_posture.admits() {
                    tracing::warn!(
                        hook = %hook.id,
                        posture = hook.failure_posture.as_label(),
                        error = %error,
                        "AI extension hook cleanup failed under an admitting posture"
                    );
                } else {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

impl Drop for AiExtensionSession {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

async fn run_parallel_input(
    hooks: Vec<PreparedAiHook>,
    event: AiExtensionEvent,
) -> PluginResult<AiChainVerdict> {
    let mut hooks: Vec<ActiveAiHook> = hooks.into_iter().map(ActiveAiHook::from).collect();
    let mut verdict = AiChainVerdict::Release;
    for hook in &mut hooks {
        match hook.invoke(&event).await {
            Ok(AiExtensionDecision::Block {
                status,
                code,
                message,
            }) => {
                verdict = AiChainVerdict::Block {
                    status,
                    code,
                    message,
                };
                break;
            }
            Ok(AiExtensionDecision::Flag { code, message }) => {
                tracing::info!(hook = %hook.id, %code, %message, "AI extension hook flagged an event");
            }
            Ok(AiExtensionDecision::Release) => {}
            Ok(AiExtensionDecision::Mutate { .. }) => {
                if hook.failure_posture.admits() {
                    tracing::warn!(
                        hook = %hook.id,
                        posture = hook.failure_posture.as_label(),
                        "parallel AI input hook returned mutate under an admitting posture"
                    );
                } else {
                    let id = hook.id.clone();
                    finish_parallel_hooks(&mut hooks);
                    return Err(PluginError::Config(format!(
                        "parallel AI input hook `{id}` returned mutate, which parallel mode cannot apply",
                    )));
                }
            }
            Ok(_) => {
                let id = hook.id.clone();
                finish_parallel_hooks(&mut hooks);
                return Err(PluginError::Config(format!(
                    "AI extension hook `{id}` returned a decision this host does not support",
                )));
            }
            Err(error) if hook.failure_posture.admits() => {
                tracing::warn!(
                    hook = %hook.id,
                    posture = hook.failure_posture.as_label(),
                    error = %error,
                    "AI extension hook failed under an admitting posture"
                );
            }
            Err(error) => {
                finish_parallel_hooks(&mut hooks);
                return Err(error);
            }
        }
    }
    finish_parallel_hooks(&mut hooks);
    Ok(verdict)
}

fn finish_parallel_hooks(hooks: &mut [ActiveAiHook]) {
    for hook in hooks {
        if let Err(error) = hook.finish() {
            tracing::warn!(
                hook = %hook.id,
                error = %error,
                "parallel AI input hook cleanup failed"
            );
        }
    }
}

fn observation_channel(
    capacity: usize,
) -> (
    mpsc::Sender<AiExtensionEvent>,
    mpsc::Receiver<AiExtensionEvent>,
) {
    mpsc::channel(capacity)
}

async fn drain_observations(
    mut hooks: Vec<ActiveAiHook>,
    mut receiver: mpsc::Receiver<AiExtensionEvent>,
) {
    while let Some(event) = receiver.recv().await {
        let kind = event.hook_kind();
        for hook in hooks.iter_mut().filter(|hook| hook.kind == kind) {
            if let Err(error) = hook.invoke(&event).await {
                tracing::warn!(hook = %hook.id, error = %error, "AI observation hook failed");
            }
        }
    }
    for hook in &mut hooks {
        if let Err(error) = hook.finish() {
            tracing::warn!(hook = %hook.id, error = %error, "AI observation hook cleanup failed");
        }
    }
}

fn invoke_proxy_wasm(
    filter: &ProxyWasmFilter,
    session: &mut Option<ProxyWasmSession>,
    event: &AiExtensionEvent,
) -> PluginResult<AiExtensionDecision> {
    if session.is_none() {
        let mut started = filter.start_session().map_err(proxy_wasm_error)?;
        let headers = started
            .on_request_headers(
                vec![
                    (":method".to_owned(), "POST".to_owned()),
                    (":path".to_owned(), "/_sbproxy/events/ai".to_owned()),
                    ("content-type".to_owned(), "application/x-ndjson".to_owned()),
                    (
                        "x-sbproxy-event-schema".to_owned(),
                        AI_EXTENSION_EVENT_SCHEMA_VERSION.to_string(),
                    ),
                ],
                false,
            )
            .map_err(proxy_wasm_error)?;
        if let Some(decision) =
            proxy_wasm_decision(headers.action, headers.local_response.as_ref())?
        {
            *session = Some(started);
            return Ok(decision);
        }
        *session = Some(started);
    }

    let mut bytes = serde_json::to_vec(event).map_err(|_| {
        PluginError::Internal(anyhow::anyhow!("AI stream event could not be encoded"))
    })?;
    bytes.push(b'\n');
    let end_of_stream = matches!(
        event.payload,
        AiExtensionEventPayload::Stream {
            chunk: sbproxy_plugin::AiExtensionStreamChunk::MessageStop { .. }
        }
    );
    let active = session
        .as_mut()
        .ok_or_else(|| PluginError::Internal(anyhow::anyhow!("Proxy-Wasm session is missing")))?;
    let result = active
        .on_request_body(Bytes::from(bytes), end_of_stream)
        .map_err(proxy_wasm_error)?;
    let decision = proxy_wasm_decision(result.action, result.local_response.as_ref())?
        .unwrap_or(AiExtensionDecision::Release);
    if end_of_stream {
        active.finish().map_err(proxy_wasm_error)?;
        *session = None;
    }
    Ok(decision)
}

fn proxy_wasm_decision(
    action: ProxyWasmAction,
    local_response: Option<&ProxyWasmLocalResponse>,
) -> PluginResult<Option<AiExtensionDecision>> {
    if let Some(response) = local_response {
        let status = if (400..=599).contains(&response.status) {
            response.status
        } else {
            403
        };
        let message = std::str::from_utf8(&response.body)
            .ok()
            .filter(|message| {
                !message.is_empty() && message.len() <= MAX_PROXY_WASM_BLOCK_MESSAGE_BYTES
            })
            .unwrap_or("Proxy-Wasm AI hook blocked the event")
            .to_owned();
        return Ok(Some(AiExtensionDecision::Block {
            status,
            code: "proxy_wasm_block".to_owned(),
            message,
        }));
    }
    match action {
        ProxyWasmAction::Continue => Ok(None),
        ProxyWasmAction::Close => Ok(Some(AiExtensionDecision::Block {
            status: 403,
            code: "proxy_wasm_close".to_owned(),
            message: "Proxy-Wasm AI hook closed the event stream".to_owned(),
        })),
        ProxyWasmAction::Pause => Err(PluginError::Internal(anyhow::anyhow!(
            "Proxy-Wasm AI hook paused without resuming"
        ))),
    }
}

fn proxy_wasm_error(error: super::ProxyWasmCallFailure) -> PluginError {
    PluginError::Internal(anyhow::anyhow!(
        "Proxy-Wasm AI hook failed: {}",
        error.code()
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sbproxy_config::ExtensionBundlesConfig;
    use sbproxy_plugin::{AiExtensionStreamChunk, ExtensionHookKind};
    use tempfile::TempDir;

    use super::*;
    use crate::bundle::DynamicBundleRegistry;

    fn event(sequence: u64, payload: AiExtensionEventPayload) -> AiExtensionEvent {
        AiExtensionEvent {
            schema_version: AI_EXTENSION_EVENT_SCHEMA_VERSION,
            sequence,
            request_id: Some("request-fixture".to_owned()),
            model: Some("model-fixture".to_owned()),
            payload,
        }
    }

    fn load_bundle(manifest: &str, artifact_name: &str, artifact: &[u8]) -> DynamicBundleRegistry {
        let directory = TempDir::new().unwrap();
        let bundle = directory.path().join("fixture");
        std::fs::create_dir(&bundle).unwrap();
        std::fs::write(bundle.join("bundle.yaml"), manifest).unwrap();
        std::fs::write(bundle.join(artifact_name), artifact).unwrap();
        let registry = DynamicBundleRegistry::load(
            &ExtensionBundlesConfig {
                bundles_dir: Some(directory.path().display().to_string()),
                sources: Vec::new(),
                grants: Default::default(),
            },
            directory.path(),
            &BTreeSet::new(),
        )
        .unwrap();
        std::mem::forget(directory);
        Arc::try_unwrap(registry).unwrap()
    }

    #[tokio::test]
    async fn javascript_block_is_awaited_and_sequence_is_strict() {
        let registry = load_bundle(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: ai-block\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: ai_guardrail_output\n    type: block_output\n    export: inspect\n",
            "entry.js",
            br#"export function inspect(input) { if (input.event.event !== "guardrail_output") throw new Error("wrong event"); return {version:"sbproxy-envelope/v1",decision:"block",status:451,code:"fixture_block",message:"blocked by fixture"}; }"#,
        );
        let chain = AiExtensionChain::from_registry(&registry).unwrap();
        assert!(chain.has_enforcing(ExtensionHookKind::AiGuardrailOutput));
        let mut session = chain.start_session();
        let mut output = event(
            1,
            AiExtensionEventPayload::GuardrailOutput {
                content: "blocked text".to_owned(),
            },
        );
        assert_eq!(
            session.dispatch(&mut output).await.unwrap(),
            AiChainVerdict::Block {
                status: 451,
                code: "fixture_block".to_owned(),
                message: "blocked by fixture".to_owned(),
            }
        );
        assert!(session.dispatch(&mut output).await.is_err());
    }

    #[tokio::test]
    async fn envelope_wasm_ai_decision_is_awaited() {
        let registry = load_bundle(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: ai-wasm\nversion: 1.0.0\nruntime: wasm\nabi: sbproxy-envelope/v1\nentry: entry.wasm\nhooks:\n  - kind: ai_guardrail_input\n    type: inspect_input\n",
            "entry.wasm",
            include_bytes!("testdata/wasm/ai-event-release.wasm"),
        );
        let chain = AiExtensionChain::from_registry(&registry).unwrap();
        let mut session = chain.start_session();

        assert_eq!(
            session
                .dispatch(&mut event(
                    1,
                    AiExtensionEventPayload::GuardrailInput {
                        stage: "original".to_owned(),
                        messages: Vec::new(),
                    },
                ))
                .await
                .unwrap(),
            AiChainVerdict::Release
        );
    }

    #[tokio::test]
    async fn proxy_wasm_receives_normalized_stream_events() {
        let registry = load_bundle(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: ai-stream\nversion: 1.0.0\nruntime: proxy_wasm\nabi: 0.2.1\nentry: filter.wasm\nhooks:\n  - kind: ai_stream_event\n    type: stream_filter\n    execution:\n      body_mode: streamed\n",
            "filter.wasm",
            include_bytes!("testdata/proxy_wasm/minimal.wasm"),
        );
        let chain = AiExtensionChain::from_registry(&registry).unwrap();
        assert!(chain.has_kind(ExtensionHookKind::AiStreamEvent));
        let mut session = chain.start_session();
        assert_eq!(
            session
                .dispatch(&mut event(
                    1,
                    AiExtensionEventPayload::Stream {
                        chunk: AiExtensionStreamChunk::ContentDelta {
                            index: 0,
                            text: "hello".to_owned(),
                        },
                    },
                ))
                .await
                .unwrap(),
            AiChainVerdict::Release
        );
        session.finish().unwrap();
    }

    #[tokio::test]
    async fn two_mutating_hooks_compose_in_chain_order() {
        // Hook one rewrites the content; hook two refuses unless it
        // sees hook one's output, proving each hook receives the
        // previous hook's rewrite rather than the original. Bundle
        // hooks dispatch sorted by type name (WOR-2272), so the type
        // names carry an explicit a_/b_ prefix to pin the order the
        // test depends on.
        let registry = load_bundle(
            concat!(
                "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: ai-mutate\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n",
                "  - kind: ai_guardrail_output\n    type: a_redact_output\n    export: redact\n    execution:\n      mutates: true\n",
                "  - kind: ai_guardrail_output\n    type: b_polish_output\n    export: polish\n    execution:\n      mutates: true\n",
            ),
            "entry.js",
            concat!(
                r#"export function redact(input) { if (input.event.content !== "raw text") throw new Error("first hook saw " + input.event.content); return {version:"sbproxy-envelope/v1",decision:"mutate",code:"redacted",body_base64:"Y2xlYW4gdGV4dA=="}; }"#,
                "\n",
                r#"export function polish(input) { if (input.event.content !== "clean text") throw new Error("second hook saw " + input.event.content); return {version:"sbproxy-envelope/v1",decision:"mutate",code:"polished",body_base64:"Y2xlYW5lciB0ZXh0"}; }"#,
            )
            .as_bytes(),
        );
        let chain = AiExtensionChain::from_registry(&registry).unwrap();
        let mut session = chain.start_session();
        let mut output = event(
            1,
            AiExtensionEventPayload::GuardrailOutput {
                content: "raw text".to_owned(),
            },
        );
        assert_eq!(
            session.dispatch(&mut output).await.unwrap(),
            AiChainVerdict::Mutated
        );
        // The caller reads the final content off the event; identity
        // fields are host-owned and unchanged.
        assert_eq!(
            output.payload,
            AiExtensionEventPayload::GuardrailOutput {
                content: "cleaner text".to_owned(),
            }
        );
        assert_eq!(output.sequence, 1);
        assert_eq!(output.request_id.as_deref(), Some("request-fixture"));
    }

    #[tokio::test]
    async fn block_after_mutate_short_circuits_and_keeps_the_rewrite() {
        let registry = load_bundle(
            concat!(
                "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: ai-mutate-block\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n",
                "  - kind: ai_guardrail_output\n    type: a_redact_output\n    export: redact\n    execution:\n      mutates: true\n",
                "  - kind: ai_guardrail_output\n    type: b_block_output\n    export: block\n",
            ),
            "entry.js",
            concat!(
                r#"export function redact(input) { return {version:"sbproxy-envelope/v1",decision:"mutate",code:"redacted",body_base64:"Y2xlYW4gdGV4dA=="}; }"#,
                "\n",
                r#"export function block(input) { if (input.event.content !== "clean text") throw new Error("block hook saw " + input.event.content); return {version:"sbproxy-envelope/v1",decision:"block",status:451,code:"still_bad",message:"refused after rewrite"}; }"#,
            )
            .as_bytes(),
        );
        let chain = AiExtensionChain::from_registry(&registry).unwrap();
        let mut session = chain.start_session();
        let mut output = event(
            1,
            AiExtensionEventPayload::GuardrailOutput {
                content: "raw text".to_owned(),
            },
        );
        assert_eq!(
            session.dispatch(&mut output).await.unwrap(),
            AiChainVerdict::Block {
                status: 451,
                code: "still_bad".to_owned(),
                message: "refused after rewrite".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn undeclared_mutation_is_an_engine_fault_under_closed_posture() {
        // The manifest says inspect-only (no `mutates: true`), so a
        // mutate decision is the engine misbehaving, not a feature.
        let registry = load_bundle(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: ai-undeclared\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: ai_guardrail_output\n    type: sneaky_output\n    export: sneak\n",
            "entry.js",
            br#"export function sneak(input) { return {version:"sbproxy-envelope/v1",decision:"mutate",code:"sneaky",body_base64:"Y2xlYW4gdGV4dA=="}; }"#,
        );
        let chain = AiExtensionChain::from_registry(&registry).unwrap();
        let mut session = chain.start_session();
        let mut output = event(
            1,
            AiExtensionEventPayload::GuardrailOutput {
                content: "raw text".to_owned(),
            },
        );
        assert!(session.dispatch(&mut output).await.is_err());
        // The refused mutation was not half-applied.
        assert_eq!(
            output.payload,
            AiExtensionEventPayload::GuardrailOutput {
                content: "raw text".to_owned(),
            },
        );
    }

    #[tokio::test]
    async fn undeclared_mutation_under_an_admitting_posture_continues_unmodified() {
        let registry = load_bundle(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: ai-undeclared-open\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nfailure_posture: open\nhooks:\n  - kind: ai_guardrail_output\n    type: sneaky_output\n    export: sneak\n",
            "entry.js",
            br#"export function sneak(input) { return {version:"sbproxy-envelope/v1",decision:"mutate",code:"sneaky",body_base64:"Y2xlYW4gdGV4dA=="}; }"#,
        );
        let chain = AiExtensionChain::from_registry(&registry).unwrap();
        let mut session = chain.start_session();
        let mut output = event(
            1,
            AiExtensionEventPayload::GuardrailOutput {
                content: "raw text".to_owned(),
            },
        );
        assert_eq!(
            session.dispatch(&mut output).await.unwrap(),
            AiChainVerdict::Release
        );
        assert_eq!(
            output.payload,
            AiExtensionEventPayload::GuardrailOutput {
                content: "raw text".to_owned(),
            },
        );
    }

    struct NoopLinkedHook;

    impl sbproxy_plugin::AiExtensionHook for NoopLinkedHook {
        fn handle<'a>(
            &'a self,
            _event: &'a AiExtensionEvent,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = PluginResult<AiExtensionDecision>> + Send + 'a>,
        > {
            Box::pin(async { Ok(AiExtensionDecision::Release) })
        }
    }

    #[test]
    fn hook_mutation_guard_refuses_before_touching_the_event() {
        let hook = ActiveAiHook {
            id: "fixture".to_owned(),
            kind: ExtensionHookKind::AiGuardrailOutput,
            failure_posture: FailureMode::Closed,
            mutates: false,
            max_buffer_bytes: 4,
            runner: ActiveAiRunner::Linked(Arc::new(NoopLinkedHook)),
        };
        let mut output = event(
            1,
            AiExtensionEventPayload::GuardrailOutput {
                content: "raw".to_owned(),
            },
        );
        assert_eq!(
            AiExtensionSession::apply_hook_mutation(&hook, &mut output, b"new"),
            Err("mutation_not_declared")
        );
        let hook = ActiveAiHook {
            mutates: true,
            ..hook
        };
        assert_eq!(
            AiExtensionSession::apply_hook_mutation(&hook, &mut output, b"12345"),
            Err("mutate_body_over_buffer_cap")
        );
        // A non-content event refuses regardless of declaration.
        let mut close = event(
            2,
            AiExtensionEventPayload::Close {
                finish_reason: None,
                content_bytes: 0,
                content_delta_count: 0,
                tool_call_count: 0,
                prompt_tokens: None,
                completion_tokens: None,
            },
        );
        assert_eq!(
            AiExtensionSession::apply_hook_mutation(&hook, &mut close, b"new"),
            Err("event_not_mutable")
        );
        // Every refusal above left the original payload in place.
        assert_eq!(
            output.payload,
            AiExtensionEventPayload::GuardrailOutput {
                content: "raw".to_owned(),
            },
        );
    }

    #[test]
    fn observation_queue_is_bounded_and_preserves_the_first_event() {
        let (sender, mut receiver) = observation_channel(1);
        let first = event(
            1,
            AiExtensionEventPayload::Close {
                finish_reason: None,
                content_bytes: 0,
                content_delta_count: 0,
                tool_call_count: 0,
                prompt_tokens: None,
                completion_tokens: None,
            },
        );
        sender.try_send(first.clone()).unwrap();
        assert!(matches!(
            sender.try_send(event(
                2,
                AiExtensionEventPayload::Close {
                    finish_reason: None,
                    content_bytes: 0,
                    content_delta_count: 0,
                    tool_call_count: 0,
                    prompt_tokens: None,
                    completion_tokens: None,
                },
            )),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert_eq!(receiver.try_recv().unwrap(), first);
    }

    #[tokio::test]
    async fn parallel_input_is_not_awaited_by_serial_dispatch() {
        let registry = load_bundle(
            "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: parallel-input\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: ai_guardrail_input\n    type: inspect_input\n    export: inspect\n    execution:\n      mode: parallel\n",
            "entry.js",
            br#"export function inspect(input) { if (input.event.event !== "guardrail_input") throw new Error("wrong event"); return {version:"sbproxy-envelope/v1",decision:"block",status:451,code:"fixture_parallel",message:"blocked in parallel"}; }"#,
        );
        let chain = AiExtensionChain::from_registry(&registry).unwrap();
        assert!(chain.has_enforcing(ExtensionHookKind::AiGuardrailInput));
        assert!(chain.has_parallel_input());
        assert!(
            !chain.has_sequential_kind(ExtensionHookKind::AiGuardrailInput),
            "parallel input must not occupy the sequential session"
        );
        assert!(!chain.has_sequential_enforcing(ExtensionHookKind::AiGuardrailInput));
        let mut session = chain.start_session();
        let mut input = event(
            1,
            AiExtensionEventPayload::GuardrailInput {
                stage: "original".to_owned(),
                messages: Vec::new(),
            },
        );
        assert_eq!(
            session.dispatch(&mut input).await.unwrap(),
            AiChainVerdict::Release,
            "parallel input must not block serial dispatch"
        );
        assert_eq!(
            session.wait_parallel().await.unwrap(),
            AiChainVerdict::Block {
                status: 451,
                code: "fixture_parallel".to_owned(),
                message: "blocked in parallel".to_owned(),
            }
        );
    }
}
