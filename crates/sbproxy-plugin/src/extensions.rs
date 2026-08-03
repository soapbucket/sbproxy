//! Public declarations and inventory records for extension bundles.
//!
//! Link-time declarations borrow static strings so plugin crates can submit
//! them through [`inventory`]. Runtime inventory records own their strings so
//! a pipeline generation can describe dynamically loaded bundles without
//! borrowing loader state.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{PluginError, PluginResult};

/// Schema version emitted by [`ExtensionInventorySnapshot`].
pub const EXTENSION_INVENTORY_SCHEMA_VERSION: u16 = 1;

/// Schema version emitted by [`PaymentExtensionEvent`].
pub const PAYMENT_EXTENSION_SCHEMA_VERSION: u16 = 1;

/// Maximum UTF-8 byte length for a payment rail or method label.
pub const PAYMENT_EXTENSION_MAX_LABEL_BYTES: usize = 64;

/// Maximum UTF-8 byte length for a payment network, asset, or identifier.
pub const PAYMENT_EXTENSION_MAX_VALUE_BYTES: usize = 128;

/// Stage of the payment lifecycle represented by an extension event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentExtensionPhase {
    /// A payment challenge is being prepared.
    Challenge,
    /// Payment evidence is being verified.
    Verify,
    /// A verified payment is being settled.
    Settle,
    /// An uncertain payment attempt is being reconciled.
    Reconcile,
}

/// Bounded outcome reported for a payment lifecycle stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentExtensionOutcome {
    /// The operation has not performed a provider write or released access.
    Started,
    /// The operation completed successfully.
    Succeeded,
    /// The operation was conclusively rejected.
    Rejected,
    /// The operation failed before an irreversible provider write.
    Failed,
    /// The operation may have performed an irreversible provider write.
    Ambiguous,
    /// The payment rail does not support the requested operation.
    Unsupported,
}

/// Decision returned by a payment extension for a `started` event.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentExtensionDecision {
    /// Continue the payment operation.
    #[default]
    Continue,
    /// Reject the payment operation before it can perform a provider write.
    Reject,
}

/// Bounded monetary amount exposed to a payment extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaymentExtensionAmount {
    amount_micros: u64,
    currency: String,
}

/// Credential-free payment lifecycle event exposed to extensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaymentExtensionEvent {
    schema_version: u16,
    phase: PaymentExtensionPhase,
    outcome: PaymentExtensionOutcome,
    rail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asset: Option<String>,
    amount: PaymentExtensionAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    intent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_reference: Option<String>,
}

impl PaymentExtensionEvent {
    /// Start building a payment event from its required bounded fields.
    pub fn builder(
        phase: PaymentExtensionPhase,
        outcome: PaymentExtensionOutcome,
        rail: impl Into<String>,
        amount_micros: u64,
        currency: impl Into<String>,
    ) -> PaymentExtensionEventBuilder {
        PaymentExtensionEventBuilder {
            phase,
            outcome,
            rail: rail.into(),
            method: None,
            network: None,
            asset: None,
            amount_micros,
            currency: currency.into(),
            intent_id: None,
            request_id: None,
            provider_reference: None,
        }
    }
}

/// Builder that validates payment metadata before creating an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentExtensionEventBuilder {
    phase: PaymentExtensionPhase,
    outcome: PaymentExtensionOutcome,
    rail: String,
    method: Option<String>,
    network: Option<String>,
    asset: Option<String>,
    amount_micros: u64,
    currency: String,
    intent_id: Option<String>,
    request_id: Option<String>,
    provider_reference: Option<String>,
}

impl PaymentExtensionEventBuilder {
    /// Attach a payment method or scheme.
    #[must_use]
    pub fn method(mut self, value: impl Into<String>) -> Self {
        self.method = Some(value.into());
        self
    }

    /// Attach the payment network.
    #[must_use]
    pub fn network(mut self, value: impl Into<String>) -> Self {
        self.network = Some(value.into());
        self
    }

    /// Attach the payment asset.
    #[must_use]
    pub fn asset(mut self, value: impl Into<String>) -> Self {
        self.asset = Some(value.into());
        self
    }

    /// Attach the stable payment intent identifier.
    #[must_use]
    pub fn intent_id(mut self, value: impl Into<String>) -> Self {
        self.intent_id = Some(value.into());
        self
    }

    /// Attach the stable request identifier.
    #[must_use]
    pub fn request_id(mut self, value: impl Into<String>) -> Self {
        self.request_id = Some(value.into());
        self
    }

    /// Attach a sanitized provider reference for a successful operation.
    #[must_use]
    pub fn provider_reference(mut self, value: impl Into<String>) -> Self {
        self.provider_reference = Some(value.into());
        self
    }

    /// Validate all fields and create the payment event.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Config`] when any field is outside the payment
    /// event contract.
    pub fn build(self) -> PluginResult<PaymentExtensionEvent> {
        validate_payment_label("rail", &self.rail)?;
        if let Some(method) = &self.method {
            validate_payment_label("method", method)?;
        }
        for (field, value) in [
            ("network", self.network.as_deref()),
            ("asset", self.asset.as_deref()),
            ("intent_id", self.intent_id.as_deref()),
            ("request_id", self.request_id.as_deref()),
            ("provider_reference", self.provider_reference.as_deref()),
        ] {
            if let Some(value) = value {
                validate_payment_value(field, value)?;
            }
        }
        if self.amount_micros == 0 || self.amount_micros > i64::MAX as u64 {
            return Err(PluginError::Config(
                "payment extension amount is outside the supported range".to_owned(),
            ));
        }
        if self.currency.len() != 3 || !self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(PluginError::Config(
                "payment extension currency must be three uppercase ASCII letters".to_owned(),
            ));
        }
        if self.provider_reference.is_some() && self.outcome != PaymentExtensionOutcome::Succeeded {
            return Err(PluginError::Config(
                "payment extension provider reference requires a succeeded outcome".to_owned(),
            ));
        }

        Ok(PaymentExtensionEvent {
            schema_version: PAYMENT_EXTENSION_SCHEMA_VERSION,
            phase: self.phase,
            outcome: self.outcome,
            rail: self.rail,
            method: self.method,
            network: self.network,
            asset: self.asset,
            amount: PaymentExtensionAmount {
                amount_micros: self.amount_micros,
                currency: self.currency,
            },
            intent_id: self.intent_id,
            request_id: self.request_id,
            provider_reference: self.provider_reference,
        })
    }
}

fn validate_payment_label(field: &str, value: &str) -> PluginResult<()> {
    if value.is_empty()
        || value.len() > PAYMENT_EXTENSION_MAX_LABEL_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(PluginError::Config(format!(
            "payment extension {field} is not a bounded label"
        )));
    }
    Ok(())
}

fn validate_payment_value(field: &str, value: &str) -> PluginResult<()> {
    if value.is_empty()
        || value.len() > PAYMENT_EXTENSION_MAX_VALUE_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(PluginError::Config(format!(
            "payment extension {field} is not a bounded value"
        )));
    }
    Ok(())
}

/// Schema version carried by every provider-neutral AI extension event.
pub const AI_EXTENSION_EVENT_SCHEMA_VERSION: u16 = 1;

/// Runtime used to execute an extension bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRuntime {
    /// Native Rust code linked into the proxy binary.
    Rust,
    /// JavaScript or load-time-transpiled TypeScript.
    Javascript,
    /// Native bundle using the versioned envelope WebAssembly ABI.
    Wasm,
    /// HTTP filter using the Proxy-Wasm ABI.
    ProxyWasm,
}

/// Kind of hook exported by an extension bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionHookKind {
    /// Request action hook.
    Action,
    /// Authentication provider hook.
    Auth,
    /// Request or response policy hook.
    Policy,
    /// Body transform hook.
    Transform,
    /// Request enrichment hook.
    Enricher,
    /// Process or pipeline startup hook.
    Startup,
    /// Identity resolution hook.
    Identity,
    /// Machine-learning classification hook.
    MlClassifier,
    /// Anomaly detection hook.
    AnomalyDetector,
    /// Model Context Protocol policy hook.
    Mcp,
    /// Proxy-Wasm HTTP filter.
    ProxyWasmFilter,
    /// AI tool-call event hook.
    AiToolCall,
    /// AI guardrail-input event hook.
    AiGuardrailInput,
    /// AI guardrail-output event hook.
    AiGuardrailOutput,
    /// AI streaming event hook.
    AiStreamEvent,
    /// AI stream-close event hook.
    AiClose,
    /// Payment lifecycle event hook.
    Payment,
}

/// Whether a successful AI hook verdict can stop the current operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiExtensionEnforcement {
    /// Await the hook and apply a block verdict before releasing bytes.
    Block,
    /// Deliver the event through the bounded observation lane.
    Observe,
}

/// Provider-neutral role attached to an AI extension message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiExtensionRole {
    /// System instruction.
    System,
    /// End-user input.
    User,
    /// Model output carried into a later turn.
    Assistant,
    /// Tool result carried into a later turn.
    Tool,
}

/// Bounded text view of one canonical AI message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiExtensionMessage {
    /// Canonical speaker role.
    pub role: AiExtensionRole,
    /// Text content after provider-format normalization.
    pub content: String,
    /// Optional speaker name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tool call satisfied by a tool-result message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// One complete model-emitted tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiExtensionToolCall {
    /// Stable position in the model response.
    pub index: usize,
    /// Provider-issued call identifier, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Tool name.
    pub name: String,
    /// Complete raw JSON arguments assembled from every streamed fragment.
    pub arguments_json: String,
}

/// Selected normalized chunks available to streamed AI hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AiExtensionStreamChunk {
    /// Start of one model response.
    MessageStart,
    /// One text delta in response order.
    ContentDelta {
        /// Canonical content-block index.
        index: usize,
        /// Decoded text for this delta.
        text: String,
    },
    /// Provider-normalized token usage.
    Usage {
        /// Prompt tokens, when the provider reported them.
        prompt_tokens: u64,
        /// Completion tokens, when the provider reported them.
        completion_tokens: u64,
        /// Total tokens, when the provider reported them.
        total_tokens: u64,
    },
    /// Terminal model event.
    MessageStop {
        /// Provider-neutral finish reason.
        finish_reason: String,
    },
}

/// Event payload delivered to an AI extension hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AiExtensionEventPayload {
    /// Canonical request messages before upstream model dispatch.
    GuardrailInput {
        /// Evaluation stage, such as `original` or `rag_augmented`.
        stage: String,
        /// Messages in canonical arrival order.
        messages: Vec<AiExtensionMessage>,
    },
    /// Canonical assistant text from a buffered response.
    GuardrailOutput {
        /// Provider-normalized assistant text.
        content: String,
    },
    /// One complete tool call, assembled before evaluation.
    ToolCall {
        /// Complete tool-call facts.
        call: AiExtensionToolCall,
    },
    /// One selected normalized stream chunk.
    Stream {
        /// Provider-neutral chunk.
        chunk: AiExtensionStreamChunk,
    },
    /// Aggregate metadata emitted exactly once when a stream closes.
    Close {
        /// Provider-neutral terminal reason, when observed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        finish_reason: Option<String>,
        /// Total decoded content bytes seen by the host.
        content_bytes: u64,
        /// Number of decoded content deltas seen by the host.
        content_delta_count: u64,
        /// Number of complete tool calls seen by the host.
        tool_call_count: u64,
        /// Prompt tokens, when reported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt_tokens: Option<u64>,
        /// Completion tokens, when reported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        completion_tokens: Option<u64>,
    },
}

/// Versioned provider-neutral event shared by linked and bundled AI hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiExtensionEvent {
    /// Event schema version.
    pub schema_version: u16,
    /// Monotonic sequence within one request.
    pub sequence: u64,
    /// Safe request correlation identifier, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Resolved model identifier, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Event-specific payload.
    #[serde(flatten)]
    pub payload: AiExtensionEventPayload,
}

impl AiExtensionEvent {
    /// Return the hook kind that receives this event.
    #[must_use]
    pub const fn hook_kind(&self) -> ExtensionHookKind {
        match self.payload {
            AiExtensionEventPayload::GuardrailInput { .. } => ExtensionHookKind::AiGuardrailInput,
            AiExtensionEventPayload::GuardrailOutput { .. } => ExtensionHookKind::AiGuardrailOutput,
            AiExtensionEventPayload::ToolCall { .. } => ExtensionHookKind::AiToolCall,
            AiExtensionEventPayload::Stream { .. } => ExtensionHookKind::AiStreamEvent,
            AiExtensionEventPayload::Close { .. } => ExtensionHookKind::AiClose,
        }
    }
}

/// Verdict returned by an awaited AI extension hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AiExtensionDecision {
    /// Release the operation or stream bytes.
    Release,
    /// Refuse the operation before the corresponding bytes leave the proxy.
    Block {
        /// HTTP status used when the call site has a response surface.
        status: u16,
        /// Stable bounded reason code for metrics and logs.
        code: String,
        /// Bounded client-safe message.
        message: String,
    },
    /// Record a match without refusing the operation.
    Flag {
        /// Stable bounded reason code for metrics and logs.
        code: String,
        /// Bounded diagnostic message.
        message: String,
    },
}

/// Awaited link-time Rust hook for provider-neutral AI events.
pub trait AiExtensionHook: Send + Sync + 'static {
    /// Inspect one event and return a release, block, or flag decision.
    fn handle<'a>(
        &'a self,
        event: &'a AiExtensionEvent,
    ) -> Pin<Box<dyn Future<Output = PluginResult<AiExtensionDecision>> + Send + 'a>>;
}

/// Link-time registration for one executable AI hook.
pub struct AiExtensionHookRegistration {
    /// Stable hook identifier matching its declaration inventory record.
    pub id: &'static str,
    /// AI event kind accepted by the hook.
    pub kind: ExtensionHookKind,
    /// Whether the hook enforces inline or observes through a bounded queue.
    pub enforcement: AiExtensionEnforcement,
    /// Factory for the linked hook implementation.
    pub factory: fn() -> Arc<dyn AiExtensionHook>,
}

inventory::collect!(AiExtensionHookRegistration);

/// Collect linked AI hook registrations of one kind in stable ID order.
///
/// ## Errors
///
/// Returns [`PluginError::Config`] when two registrations of the selected
/// kind share an ID.
pub fn collect_linked_ai_extension_hooks(
    kind: ExtensionHookKind,
) -> PluginResult<Vec<&'static AiExtensionHookRegistration>> {
    let mut registrations = inventory::iter::<AiExtensionHookRegistration>
        .into_iter()
        .filter(|registration| registration.kind == kind)
        .collect::<Vec<_>>();
    registrations.sort_by_key(|registration| registration.id);
    if let Some(duplicate) = registrations
        .windows(2)
        .find(|pair| pair[0].id == pair[1].id)
    {
        return Err(PluginError::Config(format!(
            "duplicate AI extension hook id: {}",
            duplicate[0].id
        )));
    }
    Ok(registrations)
}

/// How hooks sharing a match key participate in dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionDispatch {
    /// Exactly one registration may own the match key.
    Exclusive,
    /// Every registration runs in deterministic order.
    Chain,
}

/// Body access required by an extension hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionBodyMode {
    /// The hook does not inspect or change a body.
    None,
    /// The hook requires the complete buffered body.
    Buffered,
    /// The hook can process body chunks as they arrive.
    Streamed,
}

/// Execution limits and phase for an extension hook.
///
/// Link-time declarations use the default `&'static str` phase. Owned
/// inventory records use `ExtensionExecution<String>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionExecution<P = &'static str> {
    /// Pipeline phase in which the hook runs.
    pub phase: P,
    /// Body access mode required by the hook.
    pub body_mode: ExtensionBodyMode,
    /// Hook timeout in milliseconds, when independently bounded.
    pub timeout_ms: Option<u64>,
    /// Maximum buffered body size, when the hook buffers a body.
    pub max_buffer_bytes: Option<u64>,
}

impl ExtensionExecution<&'static str> {
    /// Convert a static declaration into an owned inventory value.
    pub fn to_owned(&self) -> ExtensionExecution<String> {
        ExtensionExecution {
            phase: self.phase.to_owned(),
            body_mode: self.body_mode,
            timeout_ms: self.timeout_ms,
            max_buffer_bytes: self.max_buffer_bytes,
        }
    }
}

/// One hook exported by a link-time extension bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ExtensionHookDeclaration {
    /// Stable hook identifier, unique within the linked binary.
    pub id: &'static str,
    /// Dispatch interface implemented by the hook.
    pub kind: ExtensionHookKind,
    /// Whether the hook is exclusive or participates in a chain.
    pub dispatch: ExtensionDispatch,
    /// Stable lookup key used to attach or invoke the hook.
    pub match_key: &'static str,
    /// Hook phase and resource limits.
    pub execution: ExtensionExecution,
    /// Declared host capabilities required by the hook.
    pub capabilities: &'static [&'static str],
}

/// Link-time declaration for one extension bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ExtensionBundleDeclaration {
    /// Stable bundle identifier.
    pub id: &'static str,
    /// Human-readable bundle name.
    pub name: &'static str,
    /// Bundle version.
    pub version: &'static str,
    /// Package or crate name, when it differs from the bundle identifier.
    pub package: Option<&'static str>,
    /// Runtime used by the bundle.
    pub runtime: ExtensionRuntime,
    /// Hooks exported by the bundle.
    pub hooks: &'static [ExtensionHookDeclaration],
}

inventory::collect!(ExtensionBundleDeclaration);

fn sort_and_validate_extension_declarations(
    mut declarations: Vec<&'static ExtensionBundleDeclaration>,
) -> PluginResult<Vec<&'static ExtensionBundleDeclaration>> {
    declarations.sort();
    if let Some(duplicate) = declarations
        .windows(2)
        .find(|pair| pair[0].id == pair[1].id)
    {
        return Err(PluginError::Config(format!(
            "duplicate extension bundle id: {}",
            duplicate[0].id
        )));
    }
    Ok(declarations)
}

/// Return link-time extension declarations in deterministic order.
///
/// ## Errors
///
/// Returns [`PluginError::Config`] when more than one linked declaration
/// uses the same stable bundle ID.
pub fn collect_linked_extension_declarations(
) -> PluginResult<Vec<&'static ExtensionBundleDeclaration>> {
    let declarations = inventory::iter::<ExtensionBundleDeclaration>
        .into_iter()
        .collect::<Vec<_>>();
    sort_and_validate_extension_declarations(declarations)
}

/// Where a bundle or hook registration came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRegistrationSource {
    /// Registration linked into the proxy binary.
    LinkTime,
    /// Bundle loaded from a configured directory.
    Directory,
    /// Bundle loaded from a pinned Git source.
    Git,
}

/// Lifecycle state reported for a bundle or hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionState {
    /// Present in the binary or configured source.
    Installed,
    /// Loaded and available for attachment.
    Available,
    /// Selected and wired in the snapshot's pipeline perspective.
    ///
    /// In a doctor snapshot, this is a stopped candidate attachment. In a
    /// running snapshot, it is attached to the serving generation.
    Active,
    /// Failed to load, validate, or initialize.
    Failed,
    /// Hidden by a higher-precedence registration.
    Shadowed,
    /// Discovered by doctor before candidate attachment could be evaluated.
    NotEvaluated,
    /// Loaded successfully but not attached by the configuration.
    Unconsumed,
}

/// Perspective represented by an extension inventory snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionScopeMode {
    /// Snapshot of the pipeline generation serving traffic.
    Running,
    /// Snapshot of a stopped candidate or a loader-level doctor diagnostic.
    Doctor,
}

/// Metadata describing the perspective of an inventory snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionInventoryScope {
    /// Whether the snapshot describes a running generation or doctor result.
    pub mode: ExtensionScopeMode,
    /// Version of the proxy that produced the snapshot.
    pub proxy_version: String,
    /// Active or inspected configuration revision, when known.
    pub config_revision: Option<String>,
}

/// Aggregate counts for an extension inventory snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionInventorySummary {
    /// Number of bundles in the snapshot.
    pub bundles: u32,
    /// Number of hooks in the snapshot.
    pub hooks: u32,
    /// Number of active hooks.
    pub active: u32,
    /// Number of available hooks.
    pub available: u32,
    /// Number of failed bundles or hooks.
    pub failed: u32,
    /// Number of registration collisions.
    pub collisions: u32,
}

/// Load result attached to a bundle inventory record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionLoadRecord {
    /// Load or validation phase that produced the result.
    pub phase: String,
    /// Stable status label for the result.
    pub status: String,
    /// Sanitized bounded detail, when additional context is safe to expose.
    pub detail: Option<String>,
}

/// Owned inventory record for one extension bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionBundleRecord {
    /// Stable bundle identifier.
    pub id: String,
    /// Human-readable bundle name.
    pub name: String,
    /// Bundle version.
    pub version: String,
    /// Package or artifact name, when present.
    pub package: Option<String>,
    /// Bundle source.
    pub source: ExtensionRegistrationSource,
    /// Runtime used by the bundle.
    pub runtime: ExtensionRuntime,
    /// Current bundle state.
    pub state: ExtensionState,
    /// Stable IDs of hooks exported by this bundle.
    pub hook_ids: Vec<String>,
    /// Bundle load result.
    pub load: ExtensionLoadRecord,
}

/// Owned inventory record for one extension hook.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionHookRecord {
    /// Stable hook identifier.
    pub id: String,
    /// Stable identifier of the containing bundle.
    pub bundle_id: String,
    /// Dispatch interface implemented by the hook.
    pub kind: ExtensionHookKind,
    /// Registration source for the hook.
    pub registration: ExtensionRegistrationSource,
    /// Whether the hook is exclusive or chained.
    pub dispatch: ExtensionDispatch,
    /// Lookup key used to attach or invoke the hook.
    pub match_key: String,
    /// Position in the resolved chain, when attached.
    pub position: Option<u32>,
    /// Current hook state.
    pub state: ExtensionState,
    /// Sanitized bounded detail about the current state.
    pub detail: Option<String>,
    /// Runtime used by the hook.
    pub runtime: ExtensionRuntime,
    /// Owned execution phase and limits.
    pub execution: ExtensionExecution<String>,
    /// Declared host capabilities required by the hook.
    pub capabilities: Vec<String>,
}

/// One collision between registrations sharing a match key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExtensionCollision {
    /// Lookup key claimed by multiple registrations.
    pub match_key: String,
    /// Stable IDs of the registrations that claimed the key.
    pub registrations: Vec<String>,
    /// Winning registration ID, when the collision was resolved.
    pub winner: Option<String>,
    /// Stable explanation of the resolution or rejection.
    pub resolution: String,
}

/// Versioned extension inventory shared by admin and doctor surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionInventorySnapshot {
    /// Inventory schema version.
    pub schema_version: u16,
    /// Perspective and proxy metadata for this snapshot.
    pub scope: ExtensionInventoryScope,
    /// Aggregate inventory counts.
    pub summary: ExtensionInventorySummary,
    /// Bundle records sorted by stable bundle ID.
    pub bundles: Vec<ExtensionBundleRecord>,
    /// Hook records sorted by stable hook ID.
    pub hooks: Vec<ExtensionHookRecord>,
    /// Collision records sorted by match key.
    pub collisions: Vec<ExtensionCollision>,
}

impl ExtensionInventorySnapshot {
    /// Sort every inventory vector deterministically and validate stable IDs.
    ///
    /// ## Errors
    ///
    /// Returns [`PluginError::Config`] when two bundle records share an ID or
    /// two hook records share an ID.
    pub fn sort_stably(&mut self) -> PluginResult<()> {
        for bundle in &mut self.bundles {
            bundle.hook_ids.sort();
        }
        for hook in &mut self.hooks {
            hook.capabilities.sort();
        }
        for collision in &mut self.collisions {
            collision.registrations.sort();
        }
        self.bundles.sort();
        self.hooks.sort();
        self.collisions.sort();

        if let Some(duplicate) = self
            .bundles
            .windows(2)
            .find(|pair| pair[0].id == pair[1].id)
        {
            return Err(PluginError::Config(format!(
                "duplicate extension bundle id: {}",
                duplicate[0].id
            )));
        }
        if let Some(duplicate) = self.hooks.windows(2).find(|pair| pair[0].id == pair[1].id) {
            return Err(PluginError::Config(format!(
                "duplicate extension hook id: {}",
                duplicate[0].id
            )));
        }
        Ok(())
    }
}

/// Runtime observation used to assemble bundle and hook inventory state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionObservation {
    /// Stable bundle identifier associated with the observation.
    pub bundle_id: String,
    /// Stable hook identifier, absent for bundle-level observations.
    pub hook_id: Option<String>,
    /// State observed for the bundle or hook.
    pub state: ExtensionState,
    /// Position in a resolved hook chain, when attached.
    pub position: Option<u32>,
    /// Lifecycle or execution phase that produced the observation.
    pub phase: String,
    /// Stable status label for the observation.
    pub status: String,
    /// Sanitized bounded detail, when available.
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    static DUPLICATE_BUNDLE_A: ExtensionBundleDeclaration = ExtensionBundleDeclaration {
        id: "duplicate-fixture-bundle",
        name: "Duplicate fixture A",
        version: "1.0.0",
        package: None,
        runtime: ExtensionRuntime::Rust,
        hooks: &[],
    };

    static DUPLICATE_BUNDLE_B: ExtensionBundleDeclaration = ExtensionBundleDeclaration {
        id: "duplicate-fixture-bundle",
        name: "Duplicate fixture B",
        version: "2.0.0",
        package: None,
        runtime: ExtensionRuntime::Javascript,
        hooks: &[],
    };

    fn bundle(id: &str, hook_ids: &[&str]) -> ExtensionBundleRecord {
        ExtensionBundleRecord {
            id: id.to_owned(),
            name: id.to_owned(),
            version: "1.0.0".to_owned(),
            package: None,
            source: ExtensionRegistrationSource::LinkTime,
            runtime: ExtensionRuntime::Rust,
            state: ExtensionState::Installed,
            hook_ids: hook_ids.iter().map(|value| (*value).to_owned()).collect(),
            load: ExtensionLoadRecord {
                phase: "link".to_owned(),
                status: "ok".to_owned(),
                detail: None,
            },
        }
    }

    fn hook(id: &str, capabilities: &[&str]) -> ExtensionHookRecord {
        ExtensionHookRecord {
            id: id.to_owned(),
            bundle_id: "bundle".to_owned(),
            kind: ExtensionHookKind::Policy,
            registration: ExtensionRegistrationSource::LinkTime,
            dispatch: ExtensionDispatch::Exclusive,
            match_key: id.to_owned(),
            position: None,
            state: ExtensionState::Installed,
            detail: None,
            runtime: ExtensionRuntime::Rust,
            execution: ExtensionExecution {
                phase: "request".to_owned(),
                body_mode: ExtensionBodyMode::None,
                timeout_ms: None,
                max_buffer_bytes: None,
            },
            capabilities: capabilities
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }

    #[test]
    fn inventory_snapshot_sorts_stable_id_vectors() {
        let mut snapshot = ExtensionInventorySnapshot {
            schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
            scope: ExtensionInventoryScope {
                mode: ExtensionScopeMode::Running,
                proxy_version: "1.0.0".to_owned(),
                config_revision: None,
            },
            summary: ExtensionInventorySummary::default(),
            bundles: vec![bundle("z", &["z-hook", "a-hook"]), bundle("a", &[])],
            hooks: vec![hook("z-hook", &["write", "read"]), hook("a-hook", &[])],
            collisions: vec![
                ExtensionCollision {
                    match_key: "z-key".to_owned(),
                    registrations: vec!["z".to_owned(), "a".to_owned()],
                    winner: None,
                    resolution: "rejected".to_owned(),
                },
                ExtensionCollision {
                    match_key: "a-key".to_owned(),
                    registrations: vec!["z".to_owned()],
                    winner: None,
                    resolution: "z-resolution".to_owned(),
                },
                ExtensionCollision {
                    match_key: "a-key".to_owned(),
                    registrations: vec!["a".to_owned()],
                    winner: None,
                    resolution: "a-resolution".to_owned(),
                },
            ],
        };

        snapshot.sort_stably().unwrap();

        assert_eq!(
            snapshot
                .bundles
                .iter()
                .map(|bundle| bundle.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "z"]
        );
        assert_eq!(snapshot.bundles[1].hook_ids, ["a-hook", "z-hook"]);
        assert_eq!(
            snapshot
                .hooks
                .iter()
                .map(|hook| hook.id.as_str())
                .collect::<Vec<_>>(),
            ["a-hook", "z-hook"]
        );
        assert_eq!(snapshot.hooks[1].capabilities, ["read", "write"]);
        assert_eq!(
            snapshot
                .collisions
                .iter()
                .map(|collision| collision.match_key.as_str())
                .collect::<Vec<_>>(),
            ["a-key", "a-key", "z-key"]
        );
        assert_eq!(snapshot.collisions[0].registrations, ["a"]);
        assert_eq!(snapshot.collisions[1].registrations, ["z"]);
        assert_eq!(snapshot.collisions[2].registrations, ["a", "z"]);
    }

    #[test]
    fn declaration_collection_rejects_duplicate_bundle_ids() {
        let error = sort_and_validate_extension_declarations(vec![
            &DUPLICATE_BUNDLE_B,
            &DUPLICATE_BUNDLE_A,
        ])
        .unwrap_err();

        assert!(matches!(
            error,
            crate::PluginError::Config(message)
                if message == "duplicate extension bundle id: duplicate-fixture-bundle"
        ));
    }

    #[test]
    fn inventory_snapshot_rejects_duplicate_bundle_and_hook_ids() {
        let mut duplicate_bundles = ExtensionInventorySnapshot {
            schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
            scope: ExtensionInventoryScope {
                mode: ExtensionScopeMode::Doctor,
                proxy_version: "1.0.0".to_owned(),
                config_revision: None,
            },
            summary: ExtensionInventorySummary::default(),
            bundles: vec![bundle("duplicate", &[]), bundle("duplicate", &["hook"])],
            hooks: Vec::new(),
            collisions: Vec::new(),
        };
        let bundle_error = duplicate_bundles.sort_stably().unwrap_err();
        assert!(matches!(
            bundle_error,
            crate::PluginError::Config(message)
                if message == "duplicate extension bundle id: duplicate"
        ));

        let mut duplicate_hooks = ExtensionInventorySnapshot {
            schema_version: EXTENSION_INVENTORY_SCHEMA_VERSION,
            scope: ExtensionInventoryScope {
                mode: ExtensionScopeMode::Doctor,
                proxy_version: "1.0.0".to_owned(),
                config_revision: None,
            },
            summary: ExtensionInventorySummary::default(),
            bundles: Vec::new(),
            hooks: vec![hook("duplicate", &[]), hook("duplicate", &["write"])],
            collisions: Vec::new(),
        };
        let hook_error = duplicate_hooks.sort_stably().unwrap_err();
        assert!(matches!(
            hook_error,
            crate::PluginError::Config(message)
                if message == "duplicate extension hook id: duplicate"
        ));
    }

    #[test]
    fn payment_extension_phases_and_outcomes_serialize_stably() {
        let phases = [
            PaymentExtensionPhase::Challenge,
            PaymentExtensionPhase::Verify,
            PaymentExtensionPhase::Settle,
            PaymentExtensionPhase::Reconcile,
        ];
        let outcomes = [
            PaymentExtensionOutcome::Started,
            PaymentExtensionOutcome::Succeeded,
            PaymentExtensionOutcome::Rejected,
            PaymentExtensionOutcome::Failed,
            PaymentExtensionOutcome::Ambiguous,
            PaymentExtensionOutcome::Unsupported,
        ];

        assert_eq!(
            serde_json::to_value(phases).unwrap(),
            serde_json::json!(["challenge", "verify", "settle", "reconcile"])
        );
        assert_eq!(
            serde_json::to_value(outcomes).unwrap(),
            serde_json::json!([
                "started",
                "succeeded",
                "rejected",
                "failed",
                "ambiguous",
                "unsupported"
            ])
        );
    }

    #[test]
    fn payment_extension_event_serializes_only_bounded_metadata() {
        let event = PaymentExtensionEvent::builder(
            PaymentExtensionPhase::Settle,
            PaymentExtensionOutcome::Succeeded,
            "x402",
            1_250_000,
            "USD",
        )
        .method("exact")
        .network("eip155:8453")
        .asset("eip155:8453/erc20:0x1234")
        .intent_id("sbpi_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .request_id("req_123")
        .provider_reference("0xabc123")
        .build()
        .unwrap();

        assert_eq!(
            serde_json::to_value(event).unwrap(),
            serde_json::json!({
                "schema_version": 1,
                "phase": "settle",
                "outcome": "succeeded",
                "rail": "x402",
                "method": "exact",
                "network": "eip155:8453",
                "asset": "eip155:8453/erc20:0x1234",
                "amount": {
                    "amount_micros": 1_250_000,
                    "currency": "USD"
                },
                "intent_id": "sbpi_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "request_id": "req_123",
                "provider_reference": "0xabc123"
            })
        );
    }

    #[test]
    fn payment_extension_event_rejects_unbounded_or_unsafe_metadata() {
        let event = |rail: &str, amount_micros, currency: &str| {
            PaymentExtensionEvent::builder(
                PaymentExtensionPhase::Settle,
                PaymentExtensionOutcome::Succeeded,
                rail,
                amount_micros,
                currency,
            )
        };

        assert!(event("", 1, "USD").build().is_err());
        assert!(event(&"x".repeat(65), 1, "USD").build().is_err());
        assert!(event("X402", 1, "USD").build().is_err());
        assert!(event("x402", 0, "USD").build().is_err());
        assert!(event("x402", i64::MAX as u64 + 1, "USD").build().is_err());
        assert!(event("x402", 1, "usd").build().is_err());
        assert!(event("x402", 1, "USDC").build().is_err());

        for invalid in ["", "contains a space", &"x".repeat(129)] {
            assert!(event("x402", 1, "USD").network(invalid).build().is_err());
            assert!(event("x402", 1, "USD").asset(invalid).build().is_err());
            assert!(event("x402", 1, "USD").intent_id(invalid).build().is_err());
            assert!(event("x402", 1, "USD").request_id(invalid).build().is_err());
            assert!(event("x402", 1, "USD")
                .provider_reference(invalid)
                .build()
                .is_err());
        }

        assert!(PaymentExtensionEvent::builder(
            PaymentExtensionPhase::Settle,
            PaymentExtensionOutcome::Failed,
            "x402",
            1,
            "USD",
        )
        .provider_reference("0xabc123")
        .build()
        .is_err());
    }

    #[test]
    fn payment_extension_decisions_serialize_stably() {
        assert_eq!(
            serde_json::to_value([
                PaymentExtensionDecision::Continue,
                PaymentExtensionDecision::Reject,
            ])
            .unwrap(),
            serde_json::json!(["continue", "reject"])
        );
    }

    #[test]
    fn payment_extension_hook_kind_serializes_stably() {
        assert_eq!(
            serde_json::to_value(ExtensionHookKind::Payment).unwrap(),
            serde_json::json!("payment")
        );
    }
}
