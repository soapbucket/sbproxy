use std::sync::Arc;

use bytes::Bytes;
use sbproxy_config::{BundleHookKind, BundleRuntime, EnforcementMode, FailureMode};
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

const AI_HOOK_KINDS: [(BundleHookKind, ExtensionHookKind); 5] = [
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
    kind: ExtensionHookKind,
    enforcement: AiExtensionEnforcement,
    failure_posture: FailureMode,
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
                kind: public_kind,
                enforcement: registration.enforcement,
                failure_posture: FailureMode::Closed,
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
        for hook in self.hooks.iter().cloned() {
            let active = ActiveAiHook::from(hook);
            if active.enforcement == AiExtensionEnforcement::Observe {
                observing.push(active);
            } else {
                enforcing.push(active);
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
    };
    let enforcement = match hook.hook().enforcement_mode {
        EnforcementMode::Block => AiExtensionEnforcement::Block,
        EnforcementMode::Observe => AiExtensionEnforcement::Observe,
    };
    Ok(PreparedAiHook {
        id: format!("{}:{}", hook.manifest().name, hook.hook().type_name),
        kind: public_kind,
        enforcement,
        failure_posture: hook.manifest().failure_posture,
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
    enforcement: AiExtensionEnforcement,
    failure_posture: FailureMode,
    runner: ActiveAiRunner,
}

impl From<PreparedAiHook> for ActiveAiHook {
    fn from(hook: PreparedAiHook) -> Self {
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
            enforcement: hook.enforcement,
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
                decode_ai_decision(&output).map_err(|error| {
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

/// Request-local AI extension state.
pub struct AiExtensionSession {
    enforcing: Vec<ActiveAiHook>,
    observer: Option<mpsc::Sender<AiExtensionEvent>>,
    last_sequence: Option<u64>,
    finished: bool,
}

impl std::fmt::Debug for AiExtensionSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AiExtensionSession")
            .field("enforcing_hooks", &self.enforcing.len())
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
    /// values. The first block verdict stops the chain.
    ///
    /// # Errors
    ///
    /// Returns a plugin error for an invalid event, an enforcing hook failure
    /// under closed posture, or use after [`Self::finish`].
    pub async fn dispatch(
        &mut self,
        event: &AiExtensionEvent,
    ) -> PluginResult<AiExtensionDecision> {
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
        for hook in self.enforcing.iter_mut().filter(|hook| hook.kind == kind) {
            match hook.invoke(event).await {
                Ok(AiExtensionDecision::Block {
                    status,
                    code,
                    message,
                }) => {
                    return Ok(AiExtensionDecision::Block {
                        status,
                        code,
                        message,
                    });
                }
                Ok(AiExtensionDecision::Flag { code, message }) => {
                    tracing::info!(hook = %hook.id, %code, %message, "AI extension hook flagged an event");
                }
                Ok(AiExtensionDecision::Release) => {}
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
        Ok(AiExtensionDecision::Release)
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
        let output = event(
            1,
            AiExtensionEventPayload::GuardrailOutput {
                content: "blocked text".to_owned(),
            },
        );
        assert_eq!(
            session.dispatch(&output).await.unwrap(),
            AiExtensionDecision::Block {
                status: 451,
                code: "fixture_block".to_owned(),
                message: "blocked by fixture".to_owned(),
            }
        );
        assert!(session.dispatch(&output).await.is_err());
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
                .dispatch(&event(
                    1,
                    AiExtensionEventPayload::GuardrailInput {
                        stage: "original".to_owned(),
                        messages: Vec::new(),
                    },
                ))
                .await
                .unwrap(),
            AiExtensionDecision::Release
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
                .dispatch(&event(
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
            AiExtensionDecision::Release
        );
        session.finish().unwrap();
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
}
