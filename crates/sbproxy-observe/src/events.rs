use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

/// Policy decision audit event emitted on every policy evaluation.
///
/// Bound to the audit event bus (see
/// `crates/sbproxy-core/src/policy_bus.rs`) and consumed asynchronously
/// per `docs/adr-policy-audit-binding.md`. The OSS substrate ships an
/// in-memory drain stub; the enterprise consumer adds tamper-evident
/// chaining and KMS-signed Merkle root commits downstream of the bus.
///
/// The OSS payload is intentionally a subset of the full ADR shape:
/// it carries the fields a regulator-defensible audit trail can be
/// reconstructed from in the OSS context (request correlation, the
/// stable verdict tag, and a coarse decision latency). Enterprise
/// extends the payload with the rendered rationale, judge call
/// summaries, redacted input contexts, and
/// W3C trace correlation; those fields are out of scope for OSS so
/// they are not declared here. The struct is `#[non_exhaustive]` so
/// adding them later does not break consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PolicyVerdictEvent {
    /// Idempotency key for the consumer; one UUID v4 per policy
    /// decision.
    pub event_id: uuid::Uuid,
    /// Correlates to the access log entry and any traces.
    pub request_id: String,
    /// Tenant identifier the request belongs to. Empty string in the
    /// single-tenant OSS default.
    pub tenant_id: String,
    /// Workspace identifier the request belongs to. Empty string in
    /// the single-tenant OSS default.
    pub workspace_id: String,
    /// Wall-clock instant the verdict was rendered.
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    /// Stable identifier for the policy that fired.
    ///
    /// In OSS scope this is the policy_type string from the policy
    /// (`rate_limit`, `waf`, `ip_filter`, ...).
    pub policy_id: String,
    /// Built-in dispatch path versus dynamic-dispatch plugin path.
    pub surface: PolicySurface,
    /// Which engine actually made this decision.
    ///
    /// Carried beside `surface` rather than derived from it, because a
    /// surface cannot tell a CEL expression from a rate limiter or a
    /// WASM bundle from a linked Rust plugin. Without this the
    /// Prometheus series for a decision said `engine="cel"` while the
    /// audit record for that same decision said `surface: built_in`,
    /// so an operator correlating an alert to the trail found the two
    /// disagreeing about who decided.
    pub engine: crate::decision::DecisionEngine,
    /// Coarse verdict tag suitable for metrics labels.
    ///
    /// The full [`sbproxy_plugin::PolicyDecision`] payload (status
    /// code, message, header list, confirm reason, webhook URL,
    /// expiry) belongs to the enterprise audit envelope and is
    /// captured there. The OSS event keeps only the tag so dashboards
    /// and SIEM rules can break down by verdict shape without
    /// inheriting the cardinality of the full payload.
    pub verdict: VerdictTag,
    /// Wall-clock duration from entering the dispatcher to the
    /// verdict being produced, in milliseconds. Coarse on purpose;
    /// the enterprise event carries a microsecond-resolution
    /// duration and a histogram-friendly seconds-as-f64 sibling.
    pub decision_latency_ms: u32,
}

impl PolicyVerdictEvent {
    /// Construct a [`PolicyVerdictEvent`] with the supplied fields.
    ///
    /// `#[non_exhaustive]` blocks out-of-crate struct-literal
    /// construction so the dispatcher in `sbproxy-core` cannot
    /// build one with `Self { ... }`. This constructor is the
    /// supported entry point; future fields land here with
    /// sensible defaults so existing call sites stay green.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: uuid::Uuid,
        request_id: String,
        tenant_id: String,
        workspace_id: String,
        occurred_at: chrono::DateTime<chrono::Utc>,
        policy_id: String,
        surface: PolicySurface,
        engine: crate::decision::DecisionEngine,
        verdict: VerdictTag,
        decision_latency_ms: u32,
    ) -> Self {
        Self {
            event_id,
            request_id,
            tenant_id,
            workspace_id,
            occurred_at,
            policy_id,
            surface,
            engine,
            verdict,
            decision_latency_ms,
        }
    }
}

/// Surface a policy decision was rendered on.
///
/// `BuiltIn` covers the 21 built-in OSS policy variants that dispatch
/// through the enum-arm path in `check_policies`. `Plugin` covers
/// dynamic-dispatch plugins registered via the
/// [`sbproxy_plugin::PolicyEnforcer`] trait.
///
/// Marked `#[non_exhaustive]` so future surfaces (CEL, Lua, JS, WASM,
/// webhook) the enterprise audit binding distinguishes can
/// extend this enum without breaking external consumers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PolicySurface {
    /// One of the 21 OSS built-in policy enum arms.
    BuiltIn,
    /// A dynamic-dispatch [`sbproxy_plugin::PolicyEnforcer`] impl.
    Plugin,
}

impl PolicySurface {
    /// Stable label suitable for use as a Prometheus metric label.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::BuiltIn => "built_in",
            Self::Plugin => "plugin",
        }
    }
}

/// Coarse verdict tag carried on a [`PolicyVerdictEvent`].
///
/// Mirrors [`sbproxy_plugin::PolicyDecision`] one-to-one for the OSS
/// scope: the full payload is captured by the enterprise audit
/// envelope, the tag here is the dashboard-friendly label.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum VerdictTag {
    /// Allow with no header decoration.
    Allow,
    /// Deny with an HTTP status and message.
    Deny,
    /// Hold pending human approval. Routes through `AllowWithHeaders`
    /// in OSS with `X-Policy-Confirm` stamped on the response.
    Confirm,
    /// Allow with response-header decoration.
    AllowWithHeaders,
}

impl VerdictTag {
    /// Stable label suitable for use as a Prometheus metric label.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Confirm => "confirm",
            Self::AllowWithHeaders => "allow_with_headers",
        }
    }
}

/// A typed proxy event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEvent {
    /// Discriminator identifying which kind of proxy event this is.
    pub event_type: EventType,
    /// Hostname (origin) the event is associated with.
    pub hostname: String,
    /// Tenant the event is attributed to, for per-tenant event
    /// filtering on the bus without parsing `data` (WOR-1098). Empty
    /// when the producing site has no resolved tenant. Defaults to
    /// empty when absent in a serialized event so older payloads still
    /// deserialize.
    #[serde(default)]
    pub tenant_id: String,
    /// Unix epoch timestamp in milliseconds when the event was produced.
    pub timestamp: u64, // Unix millis
    /// Free-form JSON payload carrying event-specific data.
    pub data: serde_json::Value,
}

/// Maximum UTF-8 bytes retained for an AI-toolkit identifier in a typed event.
///
/// The toolkit validates the same ceiling before publication. Applying it a
/// second time at the egress boundary prevents a future producer from turning
/// an operator-controlled identifier into an unbounded webhook payload.
pub(crate) const AI_TOOLKIT_EVENT_ID_MAX_BYTES: usize = 128;

/// Closed terminal outcome vocabulary shared by AI-toolkit event payloads.
///
/// This intentionally matches `sbproxy_ai_toolkit_operations_total` exactly.
/// Adding an operational error detail here would also create a new metric label
/// and a third-party event field, so callers map internal error variants onto
/// this fixed public contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiToolkitEventOutcome {
    /// The operation completed successfully.
    Success,
    /// Input, schema, or immutable-resource state was invalid.
    Invalid,
    /// The caller was not authenticated or authorized.
    Unauthorized,
    /// The requested scoped resource did not exist.
    NotFound,
    /// Purpose-scoped egress governance refused the agent destination.
    EgressRefused,
    /// The operation exceeded its deadline.
    Timeout,
    /// The inbound body exceeded the operation limit.
    BodyTooLarge,
    /// A bounded response could not fit the response limit.
    ResponseTooLarge,
    /// Concurrency admission refused the operation; retry later.
    Busy,
    /// The configured downstream agent failed: a non-success status, or a
    /// governed hop to it that could not complete. Distinct from
    /// `Internal` because the HTTP surface already exposes it as 502
    /// `agent_operation_failed`, so a tenant's broken agent is not a
    /// proxy fault on the SIEM feed.
    AgentFailed,
    /// Any failure that is not safe to expose as a more specific outcome.
    Internal,
}

impl AiToolkitEventOutcome {
    /// Closed event/metric label for this outcome.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Invalid => "invalid",
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::EgressRefused => "egress_refused",
            Self::Timeout => "timeout",
            Self::BodyTooLarge => "body_too_large",
            Self::ResponseTooLarge => "response_too_large",
            Self::Busy => "busy",
            Self::AgentFailed => "agent_failed",
            Self::Internal => "internal",
        }
    }
}

/// A workflow's content-safe terminal event payload.
///
/// The explicit field allowlist is the privacy boundary. It cannot represent
/// agent inputs or outputs, an endpoint, a token, or any secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AiWorkflowOperationData {
    /// Stable compiled-origin identifier owning the workflow.
    pub origin_id: String,
    /// Scoped configured workflow identifier.
    pub workflow_id: String,
    /// Closed terminal outcome.
    pub outcome: AiToolkitEventOutcome,
    /// Number of workflow states invoked.
    pub steps: usize,
    /// Whole-operation wall-clock duration.
    pub duration_ms: u64,
}

impl AiWorkflowOperationData {
    /// Build a bounded workflow payload.
    pub fn new(
        origin_id: &str,
        workflow_id: &str,
        outcome: AiToolkitEventOutcome,
        steps: usize,
        duration_ms: u64,
    ) -> Self {
        Self {
            origin_id: bounded_ai_toolkit_event_id(origin_id),
            workflow_id: bounded_ai_toolkit_event_id(workflow_id),
            outcome,
            steps,
            duration_ms,
        }
    }

    /// Wrap this payload in the exact typed event envelope.
    pub fn into_proxy_event(
        self,
        hostname: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> ProxyEvent {
        let mut data = serde_json::Map::with_capacity(5);
        data.insert("origin_id".to_owned(), self.origin_id.into());
        data.insert("workflow_id".to_owned(), self.workflow_id.into());
        data.insert("outcome".to_owned(), self.outcome.as_str().into());
        data.insert("steps".to_owned(), self.steps.into());
        data.insert("duration_ms".to_owned(), self.duration_ms.into());
        ProxyEvent::new(
            EventType::AiWorkflowOperation,
            hostname.into(),
            tenant_id.into(),
            serde_json::Value::Object(data),
        )
    }
}

/// An offline evaluation's content-safe terminal event payload.
///
/// Dataset entries, candidate and judge responses, prompts, model endpoints,
/// credentials, and free-form error text have no representable field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AiEvaluationOperationData {
    /// Stable compiled-origin identifier owning the evaluation.
    pub origin_id: String,
    /// Scoped immutable dataset name.
    pub dataset: String,
    /// Exact immutable dataset version.
    pub dataset_version: u32,
    /// Scoped operator-supplied experiment identifier.
    pub experiment_id: String,
    /// Closed terminal outcome.
    pub outcome: AiToolkitEventOutcome,
    /// Number of cases evaluated before the terminal outcome.
    pub cases: usize,
    /// Whole-operation wall-clock duration.
    pub duration_ms: u64,
}

impl AiEvaluationOperationData {
    /// Build a bounded evaluation payload.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        origin_id: &str,
        dataset: &str,
        dataset_version: u32,
        experiment_id: &str,
        outcome: AiToolkitEventOutcome,
        cases: usize,
        duration_ms: u64,
    ) -> Self {
        Self {
            origin_id: bounded_ai_toolkit_event_id(origin_id),
            dataset: bounded_ai_toolkit_event_id(dataset),
            dataset_version,
            experiment_id: bounded_ai_toolkit_event_id(experiment_id),
            outcome,
            cases,
            duration_ms,
        }
    }

    /// Wrap this payload in the exact typed event envelope.
    pub fn into_proxy_event(
        self,
        hostname: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> ProxyEvent {
        let mut data = serde_json::Map::with_capacity(7);
        data.insert("origin_id".to_owned(), self.origin_id.into());
        data.insert("dataset".to_owned(), self.dataset.into());
        data.insert("dataset_version".to_owned(), self.dataset_version.into());
        data.insert("experiment_id".to_owned(), self.experiment_id.into());
        data.insert("outcome".to_owned(), self.outcome.as_str().into());
        data.insert("cases".to_owned(), self.cases.into());
        data.insert("duration_ms".to_owned(), self.duration_ms.into());
        ProxyEvent::new(
            EventType::AiEvaluationOperation,
            hostname.into(),
            tenant_id.into(),
            serde_json::Value::Object(data),
        )
    }
}

/// Validation failure while constructing an AI-toolkit event payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AiToolkitEventDataError {
    /// The prompt runtime did not supply exact lowercase SHA-256 hex.
    #[error("AI prompt rollout cohort digest must be 64 lowercase hexadecimal characters")]
    InvalidCohortDigest,
}

/// A weighted prompt selection's content-safe event payload.
///
/// The constructor accepts only a digest already computed by the owning
/// runtime generation. Raw cohort keys, rollout salt, and prompt content cannot
/// be stored in this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AiPromptRolloutSelectedData {
    /// Stable compiled-origin identifier owning the rollout.
    pub origin_id: String,
    /// Scoped prompt-rollout identifier.
    pub prompt: String,
    /// Selected immutable prompt version.
    pub version: u32,
    /// Closed terminal outcome.
    pub outcome: AiToolkitEventOutcome,
    /// Lowercase SHA-256 of the runtime's length-framed scope, name, salt, and
    /// raw cohort key.
    pub cohort_digest: String,
}

impl AiPromptRolloutSelectedData {
    /// Build a bounded prompt-selection payload from a runtime-generated
    /// cohort digest.
    pub fn new(
        origin_id: &str,
        prompt: &str,
        version: u32,
        outcome: AiToolkitEventOutcome,
        cohort_digest: &str,
    ) -> Result<Self, AiToolkitEventDataError> {
        if !is_lowercase_sha256(cohort_digest) {
            return Err(AiToolkitEventDataError::InvalidCohortDigest);
        }
        Ok(Self {
            origin_id: bounded_ai_toolkit_event_id(origin_id),
            prompt: bounded_ai_toolkit_event_id(prompt),
            version,
            outcome,
            cohort_digest: cohort_digest.to_owned(),
        })
    }

    /// Wrap this payload in the exact typed event envelope.
    pub fn into_proxy_event(
        self,
        hostname: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> ProxyEvent {
        let mut data = serde_json::Map::with_capacity(5);
        data.insert("origin_id".to_owned(), self.origin_id.into());
        data.insert("prompt".to_owned(), self.prompt.into());
        data.insert("version".to_owned(), self.version.into());
        data.insert("outcome".to_owned(), self.outcome.as_str().into());
        data.insert("cohort_digest".to_owned(), self.cohort_digest.into());
        ProxyEvent::new(
            EventType::AiPromptRolloutSelected,
            hostname.into(),
            tenant_id.into(),
            serde_json::Value::Object(data),
        )
    }
}

/// The content-safe payload of an `agent_registration_decided` event.
///
/// The explicit field allowlist is the privacy boundary, and it is the whole
/// of it: this type has no field a minted client secret, a registration
/// access token, an Argon2id hash, or a submitter's contact URL could occupy.
/// A queue decision is worth putting on a SIEM feed; the credential material
/// the same call site is holding is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AgentRegistrationDecidedData {
    /// The minted agent slug the decision applies to.
    pub agent_id: String,
    /// What happened: `submitted`, `approve`, `reject`, or `revoke`. The
    /// three decisions carry the verb the admin route was called with, not
    /// the past tense; `state` below carries the result.
    pub decision: String,
    /// The registration's state after the decision.
    pub state: String,
    /// The admin operator that decided, when an admin session resolved one.
    pub decided_by: Option<String>,
}

impl AgentRegistrationDecidedData {
    /// Build a bounded decision payload. Every string is truncated to the
    /// same identifier bound the toolkit events use, so a submitter cannot
    /// widen an event by sending a long vendor name.
    pub fn new(agent_id: &str, decision: &str, state: &str, decided_by: Option<&str>) -> Self {
        Self {
            agent_id: bounded_ai_toolkit_event_id(agent_id),
            decision: bounded_ai_toolkit_event_id(decision),
            state: bounded_ai_toolkit_event_id(state),
            decided_by: decided_by.map(bounded_ai_toolkit_event_id),
        }
    }

    /// Wrap this payload in the exact typed event envelope.
    pub fn into_proxy_event(
        self,
        hostname: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> ProxyEvent {
        let mut data = serde_json::Map::with_capacity(4);
        data.insert("agent_id".to_owned(), self.agent_id.into());
        data.insert("decision".to_owned(), self.decision.into());
        data.insert("state".to_owned(), self.state.into());
        data.insert(
            "decided_by".to_owned(),
            match self.decided_by {
                Some(actor) => actor.into(),
                None => serde_json::Value::Null,
            },
        );
        ProxyEvent::new(
            EventType::AgentRegistrationDecided,
            hostname.into(),
            tenant_id.into(),
            serde_json::Value::Object(data),
        )
    }
}

fn bounded_ai_toolkit_event_id(value: &str) -> String {
    sbproxy_util::truncate_utf8(value, AI_TOOLKIT_EVENT_ID_MAX_BYTES).to_owned()
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Enumeration of proxy event types emitted on the event bus.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Event name `request_started`. A new request has begun processing.
    RequestStarted,
    /// Event name `request_completed`. A request finished successfully.
    RequestCompleted,
    /// Event name `request_error`. A request terminated with an error.
    RequestError,
    /// Event name `auth_denied`. Authentication rejected the request.
    AuthDenied,
    /// Event name `policy_denied`. A policy (rate limit, ACL, WAF) blocked the request.
    PolicyDenied,
    /// Event name `cache_hit`. A response was served from cache.
    CacheHit,
    /// Event name `cache_miss`. The cache lookup did not find a usable entry.
    CacheMiss,
    /// Event name `provider_selected`. An AI provider was chosen for routing.
    ProviderSelected,
    /// Event name `budget_exceeded`. A spending or quota budget was exhausted.
    BudgetExceeded,
    /// Event name `guardrail_triggered`. An AI guardrail flagged or blocked content.
    GuardrailTriggered,
    /// Event name `config_reloaded`. The proxy configuration was reloaded.
    ConfigReloaded,
    /// Event name `egress_refused`. An outbound dial was refused by
    /// purpose-scoped egress authorization (WOR-2486).
    EgressRefused,
    /// Event name `mcp_governance_decision`. An MCP `tools/call` dispatch
    /// was decided (allowed or refused), emitted from the same funnel
    /// every MCP tool dispatch already passes through (WOR-2384).
    McpGovernanceDecision,
    /// Event name `key_minted`. A key or upstream credential record was
    /// created through the admin key plane (WOR-2571).
    KeyMinted,
    /// Event name `key_revoked`. A key or upstream credential was marked
    /// revoked, the terminal state (WOR-2571).
    KeyRevoked,
    /// Event name `key_rotated`. A key's secret was rotated; the prior
    /// secret keeps working for the grace window (WOR-2571).
    KeyRotated,
    /// Event name `key_blocked`. A key or upstream credential was marked
    /// blocked (WOR-2571).
    KeyBlocked,
    /// Event name `credential_resolved`. An upstream credential's
    /// material was resolved into its presentable header form, either
    /// freshly or served stale inside the rotation grace window
    /// (WOR-2571). Fires once per actual resolution, never on the
    /// per-request cache hit.
    CredentialResolved,
    /// Event name `credential_fallback`. An AI provider refused the
    /// provider entry's own key with a `401`/`403` and the request was
    /// retried against the same provider on the operator's
    /// `fallback_credential_id`. Names the provider, the credential id,
    /// and whether the retry was served; never any secret.
    CredentialFallback,
    /// Event name `ai_workflow_operation`. A governed workflow execution
    /// completed or was refused. Its payload is bounded metadata;
    /// agent inputs, outputs, endpoints, tokens, and secrets are excluded.
    AiWorkflowOperation,
    /// Event name `ai_evaluation_operation`. A governed evaluation run
    /// completed or was refused. Its payload excludes model and
    /// judge response content, endpoints, credentials, and secret references.
    AiEvaluationOperation,
    /// Event name `ai_prompt_rollout_selected`. A weighted prompt selection
    /// completed on the admin or live request path. Its payload may identify
    /// the prompt and version and carry a cohort digest, but never prompt
    /// content or the raw cohort key.
    AiPromptRolloutSelected,
    /// Event name `agent_registration_decided`. A self-registered agent
    /// entered the owner-approval queue, or an operator approved, rejected,
    /// or revoked one (WOR-2664). Its payload is the agent id, the decision
    /// (`submitted`, `approve`, `reject`, or `revoke`), the resulting state,
    /// and the acting operator when an admin session resolved one; never a
    /// minted secret, a registration access token, or a credential hash.
    AgentRegistrationDecided,
}

impl ProxyEvent {
    /// Build an event stamped with the current wall clock.
    ///
    /// `data` reaches third-party endpoints verbatim once an `events:`
    /// webhook sink is configured, so what a caller puts in it is a
    /// disclosure decision rather than a formatting one. The bridges in
    /// [`crate::audit`] and [`crate::request_sink`] pass types whose
    /// secret-free property is already documented and tested; a new
    /// publisher owes the same argument before it calls this.
    pub fn new(
        event_type: EventType,
        hostname: String,
        tenant_id: String,
        data: serde_json::Value,
    ) -> Self {
        Self {
            event_type,
            hostname,
            tenant_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_millis() as u64)
                .unwrap_or(0),
            data,
        }
    }
}

/// Every [`EventType`] variant, in declaration order.
///
/// Two consumers need the list rather than one variant at a time: the
/// `events.types:` config validator, which names the accepted values in
/// its refusal message, and [`crate::event_sink::EventTypeMask`], which
/// indexes bits by position here.
///
/// The array length is written out, so a variant added to the enum and
/// not added here fails to compile. That is deliberate. The failure
/// mode this prevents is a twenty-third event type that no `events:` sink
/// can ever be told to deliver, which looks exactly like a working sink
/// to everyone except the operator waiting for the event.
pub const ALL_EVENT_TYPES: [EventType; 23] = [
    EventType::RequestStarted,
    EventType::RequestCompleted,
    EventType::RequestError,
    EventType::AuthDenied,
    EventType::PolicyDenied,
    EventType::CacheHit,
    EventType::CacheMiss,
    EventType::ProviderSelected,
    EventType::BudgetExceeded,
    EventType::GuardrailTriggered,
    EventType::ConfigReloaded,
    EventType::EgressRefused,
    EventType::McpGovernanceDecision,
    EventType::KeyMinted,
    EventType::KeyRevoked,
    EventType::KeyRotated,
    EventType::KeyBlocked,
    EventType::CredentialResolved,
    EventType::CredentialFallback,
    EventType::AiWorkflowOperation,
    EventType::AiEvaluationOperation,
    EventType::AiPromptRolloutSelected,
    EventType::AgentRegistrationDecided,
];

impl EventType {
    /// The wire name, identical to what serde writes.
    ///
    /// Hand written rather than derived from the `serde` rename so it can
    /// be used where a `&'static str` is required (Prometheus labels,
    /// error messages, header values) without serializing to a `String`
    /// and trimming the quotes. `event_type_as_str_matches_serde` pins
    /// the two together.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RequestStarted => "request_started",
            Self::RequestCompleted => "request_completed",
            Self::RequestError => "request_error",
            Self::AuthDenied => "auth_denied",
            Self::PolicyDenied => "policy_denied",
            Self::CacheHit => "cache_hit",
            Self::CacheMiss => "cache_miss",
            Self::ProviderSelected => "provider_selected",
            Self::BudgetExceeded => "budget_exceeded",
            Self::GuardrailTriggered => "guardrail_triggered",
            Self::ConfigReloaded => "config_reloaded",
            Self::EgressRefused => "egress_refused",
            Self::McpGovernanceDecision => "mcp_governance_decision",
            Self::KeyMinted => "key_minted",
            Self::KeyRevoked => "key_revoked",
            Self::KeyRotated => "key_rotated",
            Self::KeyBlocked => "key_blocked",
            Self::CredentialResolved => "credential_resolved",
            Self::CredentialFallback => "credential_fallback",
            Self::AiWorkflowOperation => "ai_workflow_operation",
            Self::AiEvaluationOperation => "ai_evaluation_operation",
            Self::AiPromptRolloutSelected => "ai_prompt_rollout_selected",
            Self::AgentRegistrationDecided => "agent_registration_decided",
        }
    }

    /// Parse a wire name back to a variant. `None` for anything the enum
    /// does not name, which is what lets `events.types:` refuse a typo
    /// instead of quietly delivering nothing.
    pub fn from_name(name: &str) -> Option<Self> {
        ALL_EVENT_TYPES
            .into_iter()
            .find(|candidate| candidate.as_str() == name)
    }

    /// Position of this variant in [`ALL_EVENT_TYPES`], which is the bit
    /// [`crate::event_sink::EventTypeMask`] sets for it.
    pub fn index(&self) -> usize {
        match self {
            Self::RequestStarted => 0,
            Self::RequestCompleted => 1,
            Self::RequestError => 2,
            Self::AuthDenied => 3,
            Self::PolicyDenied => 4,
            Self::CacheHit => 5,
            Self::CacheMiss => 6,
            Self::ProviderSelected => 7,
            Self::BudgetExceeded => 8,
            Self::GuardrailTriggered => 9,
            Self::ConfigReloaded => 10,
            Self::EgressRefused => 11,
            Self::McpGovernanceDecision => 12,
            Self::KeyMinted => 13,
            Self::KeyRevoked => 14,
            Self::KeyRotated => 15,
            Self::KeyBlocked => 16,
            Self::CredentialResolved => 17,
            Self::CredentialFallback => 18,
            Self::AiWorkflowOperation => 19,
            Self::AiEvaluationOperation => 20,
            Self::AiPromptRolloutSelected => 21,
            Self::AgentRegistrationDecided => 22,
        }
    }

    /// Whether this event type has a production call site that
    /// publishes it today (WOR-2486, mirroring
    /// [`crate::decision::DecisionEvent::has_emitter`]).
    ///
    /// `events.types:` accepts every declared variant, including one
    /// with no emitter yet: refusing an unwired name would block
    /// pre-configuring a type a later release wires, and would fail a
    /// correct config over a gap in this crate's own instrumentation.
    /// That leaves the same hole `has_emitter` closes for decision
    /// events: silence from a configured sink reads exactly like a sink
    /// with nothing to report. Boot reads this to warn instead.
    ///
    /// **Hand-maintained, and it will drift if you let it.** Wiring a
    /// new emitter means flipping its arm here in the same change.
    pub const fn has_emitter(self) -> bool {
        matches!(
            self,
            Self::RequestStarted
                | Self::RequestCompleted
                | Self::RequestError
                | Self::AuthDenied
                | Self::PolicyDenied
                | Self::ProviderSelected
                | Self::BudgetExceeded
                | Self::GuardrailTriggered
                | Self::ConfigReloaded
                | Self::EgressRefused
                | Self::McpGovernanceDecision
                // WOR-2571: the four mutation kinds publish from the
                // `KeyAuditEntry::emit` bridge (every admin mint /
                // revoke / rotate / block funnels through it), and
                // `credential_resolved` from
                // `sbproxy_core::key_plane`'s resolution path.
                | Self::KeyMinted
                | Self::KeyRevoked
                | Self::KeyRotated
                | Self::KeyBlocked
                | Self::CredentialResolved
                // The AI provider-key fallback publishes from the one
                // arm in `sbproxy_core::server::ai_dispatch` that swaps
                // the credential mid-request.
                | Self::CredentialFallback
                // Group D's generation-owned toolkit runtime publishes
                // workflow/evaluation operation events, and the live AI
                // request dispatcher publishes the concrete rollout pick.
                | Self::AiWorkflowOperation
                | Self::AiEvaluationOperation
                | Self::AiPromptRolloutSelected
                // The agent registry publishes one per queue decision:
                // submission, approval, rejection, revocation.
                | Self::AgentRegistrationDecided
        )
        // `CacheHit` and `CacheMiss` are deliberately absent: wiring
        // them per-request would put an NDJSON line on every configured
        // webhook sink per cache lookup (WOR-2486 sweep). Their
        // forensic value already lives on `DecisionEvent::CacheAdmit` /
        // `CacheKey` and the access log's `cache_status` column.
    }
}

/// Event subscriber callback type.
pub type EventHandler = Box<dyn Fn(&ProxyEvent) + Send + Sync>;

/// How many nested [`EventBus::publish`] calls one thread may stack
/// before the bus starts dropping events.
///
/// A handler is allowed to publish, and two handlers that publish each
/// other's type are a cycle with no natural end. While the fan-out ran
/// under the handler-map lock the cycle stopped itself by deadlocking on
/// the second publish, which is a hang rather than a bound. With the
/// lock released before handlers run, the same cycle recurses instead,
/// and unbounded recursion on the publisher's thread overflows the stack
/// and aborts the process. The cap turns that into a dropped event and
/// one `warn`.
///
/// Eight is past any fan-out chain a real embedder writes on purpose and
/// far short of the frame budget eight nested handlers could exhaust.
const MAX_PUBLISH_DEPTH: usize = 8;

thread_local! {
    /// Nested [`EventBus::publish`] calls on this thread's stack.
    ///
    /// Counted per thread across every bus rather than per bus: what the
    /// cap protects is one thread's stack, and two buses whose handlers
    /// publish into each other build exactly the stack a single bus
    /// does. Thread-local also keeps a parallel test run from making one
    /// test's depth depend on another's.
    static PUBLISH_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Restores the thread's fan-out depth when a `publish` returns,
/// including when a handler unwinds through it.
///
/// A bare decrement in the happy path would leak depth on every
/// panicking handler until the thread hit the cap permanently and
/// stopped delivering anything.
struct PublishDepthGuard {
    previous: usize,
}

impl Drop for PublishDepthGuard {
    fn drop(&mut self) {
        PUBLISH_DEPTH.with(|depth| depth.set(self.previous));
    }
}

/// Event bus for publishing and subscribing to proxy events.
///
/// # What the lock covers
///
/// The handler map is locked to read or write the subscriber list and
/// unlocked before any handler runs. [`EventBus::publish`] clones the
/// `Arc<EventHandler>` list for one event type, which is a refcount bump
/// per subscriber and not a copy of any closure, drops the guard, and
/// only then calls handlers. Nothing arbitrary runs under the lock, so:
///
/// - A handler that blocks on a socket delays its own publisher and
///   nobody else. Other threads keep publishing, subscribing, and
///   counting while it runs.
/// - A handler that calls back into [`EventBus::subscribe`],
///   [`EventBus::publish`], or [`EventBus::subscriber_count`] returns
///   instead of waiting forever on a lock its own caller is holding.
///   `parking_lot::Mutex` is not reentrant and blocks rather than
///   panicking, so re-entry used to be a permanent hang on a thread with
///   no diagnostic attached to it.
/// - A handler that panics unwinds through `publish` and the handlers
///   after it do not run, but the bus stays usable: `parking_lot` has no
///   poisoning, and the guard is gone before the handler is entered, so
///   the next publish reads the same list and runs it from the start.
pub struct EventBus {
    handlers: Mutex<HashMap<EventType, Vec<Arc<EventHandler>>>>,
}

impl EventBus {
    /// Create a new empty event bus.
    pub fn new() -> Self {
        Self {
            handlers: Mutex::new(HashMap::new()),
        }
    }

    /// Subscribe to events of a specific type.
    ///
    /// Handlers run in registration order, so this appends. Subscribing
    /// from inside a handler is allowed and joins the list for the
    /// *next* [`EventBus::publish`]: the fan-out in flight already took
    /// its snapshot, and the new handler does not run for the event
    /// being delivered.
    pub fn subscribe(&self, event_type: EventType, handler: EventHandler) {
        let mut handlers = self.handlers.lock();
        handlers
            .entry(event_type)
            .or_default()
            .push(Arc::new(handler));
    }

    /// Publish an event to all subscribers.
    ///
    /// Synchronous on the calling thread, in registration order, over the
    /// subscribers registered at the moment this call started. The
    /// handler map is unlocked before the first handler runs; see the
    /// type-level docs for what that buys a slow, re-entrant, or
    /// panicking handler.
    ///
    /// Nested publishes on one thread are capped at `MAX_PUBLISH_DEPTH`.
    /// Past the cap the event is dropped and a `warn` names the type, so
    /// a handler cycle ends in a counted-off event rather than a blown
    /// stack.
    pub fn publish(&self, event: &ProxyEvent) {
        let depth = PUBLISH_DEPTH.with(Cell::get);
        if depth >= MAX_PUBLISH_DEPTH {
            tracing::warn!(
                event_type = event.event_type.as_str(),
                depth,
                max_depth = MAX_PUBLISH_DEPTH,
                "event bus fan-out hit its nesting cap; dropping this event \
                 rather than recursing further. A handler publishes an event \
                 that reaches it again."
            );
            return;
        }

        // The snapshot is the fix. Clone the `Arc` list under the lock,
        // drop the guard at the end of this block, and call handlers
        // with nothing held.
        let subscribers = {
            let handlers = self.handlers.lock();
            let Some(subscribers) = handlers.get(&event.event_type) else {
                return;
            };
            subscribers.clone()
        };

        PUBLISH_DEPTH.with(|current| current.set(depth + 1));
        let _depth_guard = PublishDepthGuard { previous: depth };
        for handler in &subscribers {
            handler(event);
        }
    }

    /// Number of subscribers for an event type.
    ///
    /// Safe to call from inside a handler: a fan-out in flight is not
    /// holding the handler map. The count includes handlers registered
    /// after that fan-out took its snapshot, so a handler that
    /// subscribes and then counts sees its own addition even though the
    /// addition will not run until the next publish.
    pub fn subscriber_count(&self, event_type: &EventType) -> usize {
        let handlers = self.handlers.lock();
        handlers.get(event_type).map(|v| v.len()).unwrap_or(0)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn make_event(event_type: EventType) -> ProxyEvent {
        ProxyEvent {
            event_type,
            hostname: "example.com".to_string(),
            tenant_id: "tenant-a".to_string(),
            timestamp: 1700000000000,
            data: serde_json::json!({"key": "value"}),
        }
    }

    #[test]
    fn test_subscribe_and_publish() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = counter.clone();

        bus.subscribe(
            EventType::RequestStarted,
            Box::new(move |_event| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let event = make_event(EventType::RequestStarted);
        bus.publish(&event);
        bus.publish(&event);

        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_multiple_subscribers() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicU64::new(0));

        for _ in 0..3 {
            let c = counter.clone();
            bus.subscribe(
                EventType::CacheHit,
                Box::new(move |_event| {
                    c.fetch_add(1, Ordering::SeqCst);
                }),
            );
        }

        bus.publish(&make_event(EventType::CacheHit));
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_no_subscriber_no_crash() {
        let bus = EventBus::new();
        // Publishing with no subscribers should not panic.
        bus.publish(&make_event(EventType::AuthDenied));
    }

    #[test]
    fn test_subscriber_count() {
        let bus = EventBus::new();
        assert_eq!(bus.subscriber_count(&EventType::RequestStarted), 0);

        bus.subscribe(EventType::RequestStarted, Box::new(|_| {}));
        assert_eq!(bus.subscriber_count(&EventType::RequestStarted), 1);

        bus.subscribe(EventType::RequestStarted, Box::new(|_| {}));
        assert_eq!(bus.subscriber_count(&EventType::RequestStarted), 2);

        // Different event type is still 0.
        assert_eq!(bus.subscriber_count(&EventType::ConfigReloaded), 0);
    }

    #[test]
    fn test_event_serialization_roundtrip() {
        let event = make_event(EventType::GuardrailTriggered);
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ProxyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hostname, "example.com");
        assert_eq!(deserialized.event_type, EventType::GuardrailTriggered);
        assert_eq!(deserialized.timestamp, 1700000000000);
    }

    #[test]
    fn test_event_type_serialization() {
        let variants = vec![
            (EventType::RequestStarted, "\"request_started\""),
            (EventType::RequestCompleted, "\"request_completed\""),
            (EventType::RequestError, "\"request_error\""),
            (EventType::AuthDenied, "\"auth_denied\""),
            (EventType::PolicyDenied, "\"policy_denied\""),
            (EventType::CacheHit, "\"cache_hit\""),
            (EventType::CacheMiss, "\"cache_miss\""),
            (EventType::ProviderSelected, "\"provider_selected\""),
            (EventType::BudgetExceeded, "\"budget_exceeded\""),
            (EventType::GuardrailTriggered, "\"guardrail_triggered\""),
            (EventType::ConfigReloaded, "\"config_reloaded\""),
            (EventType::EgressRefused, "\"egress_refused\""),
            (
                EventType::McpGovernanceDecision,
                "\"mcp_governance_decision\"",
            ),
            (EventType::KeyMinted, "\"key_minted\""),
            (EventType::KeyRevoked, "\"key_revoked\""),
            (EventType::KeyRotated, "\"key_rotated\""),
            (EventType::KeyBlocked, "\"key_blocked\""),
            (EventType::CredentialResolved, "\"credential_resolved\""),
            (EventType::CredentialFallback, "\"credential_fallback\""),
            (EventType::AiWorkflowOperation, "\"ai_workflow_operation\""),
            (
                EventType::AiEvaluationOperation,
                "\"ai_evaluation_operation\"",
            ),
            (
                EventType::AiPromptRolloutSelected,
                "\"ai_prompt_rollout_selected\"",
            ),
            (
                EventType::AgentRegistrationDecided,
                "\"agent_registration_decided\"",
            ),
        ];

        for (variant, expected) in variants {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, expected, "Failed for {:?}", variant);
            let deserialized: EventType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, variant);
        }
    }

    #[test]
    fn event_type_as_str_matches_serde() {
        // `as_str` is hand written and serde's name is derived from the
        // `rename_all`. Nothing but this test keeps them equal, and an
        // `events.types:` entry an operator copied out of the JSON would
        // stop resolving the moment they diverged.
        for variant in ALL_EVENT_TYPES {
            let serialized = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(
                serialized,
                format!("\"{}\"", variant.as_str()),
                "as_str disagrees with serde for {variant:?}"
            );
        }
    }

    /// WOR-2384: the previous test pins the bare `EventType`'s own
    /// serialization; this pins the same thing one layer up, on the
    /// envelope that actually reaches a file or a webhook. A struct
    /// derive routes a field through that field type's own `Serialize`
    /// impl, so this cannot observably differ from
    /// `event_type_as_str_matches_serde` today, but a future
    /// hand-written `Serialize` on `ProxyEvent` (or a `#[serde(with =
    /// ..)]` on the field) could take a different path for the type
    /// name than `EventType`'s own impl does, and this is the test that
    /// would catch it. The gap this closes is exactly the one that
    /// shipped: `EventType`'s bare serialization matching `as_str()`
    /// was never actually the same question as "what does a SIEM
    /// reading the NDJSON line see", even though for every variant so
    /// far the two have had one answer.
    #[test]
    fn proxy_event_envelope_serializes_the_same_type_name_as_as_str() {
        for variant in ALL_EVENT_TYPES {
            let envelope = make_event(variant);
            let json = serde_json::to_value(&envelope).expect("serialize envelope");
            assert_eq!(
                json["event_type"],
                variant.as_str(),
                "the envelope's event_type field disagrees with as_str() for {variant:?}"
            );
        }
    }

    #[test]
    fn ai_toolkit_payload_builders_are_bounded_and_exclude_content() {
        let long_id = "雪".repeat(80);
        let workflow =
            AiWorkflowOperationData::new(&long_id, &long_id, AiToolkitEventOutcome::Success, 3, 42)
                .into_proxy_event("ai.example", "tenant-a");
        let evaluation = AiEvaluationOperationData::new(
            &long_id,
            &long_id,
            7,
            &long_id,
            AiToolkitEventOutcome::Invalid,
            11,
            84,
        )
        .into_proxy_event("ai.example", "tenant-a");

        assert_eq!(workflow.event_type, EventType::AiWorkflowOperation);
        assert_eq!(evaluation.event_type, EventType::AiEvaluationOperation);
        for event in [&workflow, &evaluation] {
            for field in event.data.as_object().expect("typed object").values() {
                if let Some(value) = field.as_str() {
                    assert!(
                        value.len() <= AI_TOOLKIT_EVENT_ID_MAX_BYTES,
                        "identifier escaped its event byte bound: {value}"
                    );
                    assert!(value.is_char_boundary(value.len()));
                }
            }
        }

        let wire = serde_json::to_string(&[workflow, evaluation]).expect("serialize payloads");
        for forbidden in [
            "prompt",
            "response",
            "endpoint",
            "token",
            "shared_secret",
            "secret_ref",
        ] {
            assert!(
                !wire.contains(forbidden),
                "payload field accidentally opened a sensitive surface: {forbidden}"
            );
        }
    }

    #[test]
    fn prompt_rollout_payload_accepts_only_a_validated_digest() {
        let digest = "a".repeat(64);
        let first = AiPromptRolloutSelectedData::new(
            "origin-a",
            "support-system",
            2,
            AiToolkitEventOutcome::Success,
            &digest,
        )
        .expect("runtime-generated digest")
        .into_proxy_event("ai.example", "tenant-a");
        let same = AiPromptRolloutSelectedData::new(
            "origin-a",
            "support-system",
            2,
            AiToolkitEventOutcome::Success,
            &digest,
        )
        .expect("runtime-generated digest")
        .into_proxy_event("ai.example", "tenant-a");

        assert_eq!(first.event_type, EventType::AiPromptRolloutSelected);
        assert_eq!(first.data["cohort_digest"], same.data["cohort_digest"]);
        let serialized_digest = first.data["cohort_digest"].as_str().expect("digest");
        assert_eq!(serialized_digest, digest);

        let wire = serde_json::to_string(&first).expect("serialize payload");
        assert!(!wire.contains("content"));
        for invalid in [
            "a",
            "A234567890123456789012345678901234567890123456789012345678901234",
            "z234567890123456789012345678901234567890123456789012345678901234",
        ] {
            assert_eq!(
                AiPromptRolloutSelectedData::new(
                    "origin-a",
                    "support-system",
                    2,
                    AiToolkitEventOutcome::Success,
                    invalid,
                )
                .expect_err("only exact lowercase SHA-256 hex is accepted"),
                AiToolkitEventDataError::InvalidCohortDigest
            );
        }
    }

    #[test]
    fn ai_toolkit_event_outcomes_match_the_metric_vocabulary() {
        let outcomes = [
            (AiToolkitEventOutcome::Success, "success"),
            (AiToolkitEventOutcome::Invalid, "invalid"),
            (AiToolkitEventOutcome::Unauthorized, "unauthorized"),
            (AiToolkitEventOutcome::NotFound, "not_found"),
            (AiToolkitEventOutcome::EgressRefused, "egress_refused"),
            (AiToolkitEventOutcome::Timeout, "timeout"),
            (AiToolkitEventOutcome::BodyTooLarge, "body_too_large"),
            (
                AiToolkitEventOutcome::ResponseTooLarge,
                "response_too_large",
            ),
            (AiToolkitEventOutcome::Busy, "busy"),
            (AiToolkitEventOutcome::AgentFailed, "agent_failed"),
            (AiToolkitEventOutcome::Internal, "internal"),
        ];
        for (outcome, expected) in outcomes {
            // Exhaustive on purpose. The list above is hand written, so a
            // new variant would otherwise ship with nothing pinning its
            // wire label; this arm stops compiling instead.
            let wire = match outcome {
                AiToolkitEventOutcome::Success => "success",
                AiToolkitEventOutcome::Invalid => "invalid",
                AiToolkitEventOutcome::Unauthorized => "unauthorized",
                AiToolkitEventOutcome::NotFound => "not_found",
                AiToolkitEventOutcome::EgressRefused => "egress_refused",
                AiToolkitEventOutcome::Timeout => "timeout",
                AiToolkitEventOutcome::BodyTooLarge => "body_too_large",
                AiToolkitEventOutcome::ResponseTooLarge => "response_too_large",
                AiToolkitEventOutcome::Busy => "busy",
                AiToolkitEventOutcome::AgentFailed => "agent_failed",
                AiToolkitEventOutcome::Internal => "internal",
            };
            assert_eq!(wire, expected);
            assert_eq!(outcome.as_str(), expected);
            assert_eq!(serde_json::to_value(outcome).expect("serialize"), expected);
        }
    }

    #[test]
    fn event_type_from_name_round_trips_and_rejects_unknown() {
        for variant in ALL_EVENT_TYPES {
            assert_eq!(EventType::from_name(variant.as_str()), Some(variant));
        }
        assert_eq!(EventType::from_name("policy_denied "), None);
        assert_eq!(EventType::from_name("PolicyDenied"), None);
        assert_eq!(EventType::from_name("kafka"), None);
    }

    #[test]
    fn event_type_index_is_its_position_and_is_unique() {
        for (position, variant) in ALL_EVENT_TYPES.into_iter().enumerate() {
            assert_eq!(
                variant.index(),
                position,
                "{variant:?} indexes off its own position, so the mask would \
                 route it to another type's bit"
            );
        }
    }

    /// WOR-2655: the credential-fallback type, pinned across all four
    /// hand-maintained surfaces at once.
    ///
    /// The array length is compile-checked; `index()`, `as_str()` and
    /// `has_emitter()` are hand-written matches that are not checked
    /// against the array by the compiler. A half-added variant
    /// compiles, resolves from `events.types:`, and then routes to
    /// another type's mask bit, which reads as a working sink to
    /// everyone except the operator waiting for the event.
    #[test]
    fn credential_fallback_is_declared_on_every_hand_maintained_surface() {
        assert_eq!(
            EventType::CredentialFallback.as_str(),
            "credential_fallback"
        );
        assert_eq!(
            EventType::from_name("credential_fallback"),
            Some(EventType::CredentialFallback)
        );
        assert!(
            ALL_EVENT_TYPES.contains(&EventType::CredentialFallback),
            "an events.types: entry can only name a type the array lists"
        );
        assert_eq!(
            EventType::CredentialFallback.index(),
            18,
            "later event additions must not move an existing wire bit"
        );
        assert!(
            EventType::CredentialFallback.has_emitter(),
            "sbproxy_core::server::ai_dispatch publishes it from the \
             provider-key fallback arm"
        );
    }

    #[test]
    fn cache_hit_and_cache_miss_are_the_only_events_with_no_emitter() {
        // WOR-2486: the boot warning in
        // `sbproxy_core::server::lifecycle::warn_unwired_proxy_events`
        // trusts this to name every dead type. Both this test and the
        // ruling it pins are read together: cache_hit/cache_miss stay
        // dead on purpose (cardinality), and everything else declared
        // on the enum must have shipped a real emitter by the time it
        // is added to `ALL_EVENT_TYPES`.
        let unwired: Vec<&str> = ALL_EVENT_TYPES
            .into_iter()
            .filter(|event_type| !event_type.has_emitter())
            .map(|event_type| event_type.as_str())
            .collect();
        assert_eq!(unwired, vec!["cache_hit", "cache_miss"]);
    }

    #[test]
    fn test_different_event_types_isolated() {
        let bus = EventBus::new();
        let started_count = Arc::new(AtomicU64::new(0));
        let error_count = Arc::new(AtomicU64::new(0));

        let sc = started_count.clone();
        bus.subscribe(
            EventType::RequestStarted,
            Box::new(move |_| {
                sc.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let ec = error_count.clone();
        bus.subscribe(
            EventType::RequestError,
            Box::new(move |_| {
                ec.fetch_add(1, Ordering::SeqCst);
            }),
        );

        bus.publish(&make_event(EventType::RequestStarted));
        assert_eq!(started_count.load(Ordering::SeqCst), 1);
        assert_eq!(error_count.load(Ordering::SeqCst), 0);

        bus.publish(&make_event(EventType::RequestError));
        assert_eq!(started_count.load(Ordering::SeqCst), 1);
        assert_eq!(error_count.load(Ordering::SeqCst), 1);
    }

    /// Runs `body` on its own thread and fails the test if it has not
    /// returned inside `DEADLINE`.
    ///
    /// Every re-entrancy test below hangs forever against the pre-fix
    /// bus, because the handler blocks on the handler-map mutex its own
    /// `publish` is still holding and `parking_lot::Mutex` waits rather
    /// than panicking on a same-thread relock. Running the publish on a
    /// borrowed thread converts that hang into a failed assertion: the
    /// test thread stops waiting, reports, and lets the run finish. The
    /// wedged worker stays parked until the process exits, which is the
    /// price of not wedging the runner with it.
    fn run_with_deadline(what: &str, body: impl FnOnce() + Send + 'static) {
        const DEADLINE: Duration = Duration::from_secs(10);

        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            body();
            let _ = done_tx.send(());
        });

        match done_rx.recv_timeout(DEADLINE) {
            Ok(()) => {}
            // The worker unwound before it could send. Fall through to
            // the join, which re-raises its panic with its own message
            // rather than reporting a deadline that was never missed.
            Err(mpsc::RecvTimeoutError::Disconnected) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => panic!(
                "{what} did not finish within {DEADLINE:?}: publish is \
                 holding the handler map while a handler waits for it"
            ),
        }

        if let Err(payload) = worker.join() {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn publish_does_not_deadlock_when_a_handler_reenters_the_bus() {
        // The regression test for WOR-2613. Against the pre-fix
        // `publish`, which held the handler-map guard across the whole
        // fan-out, `subscriber_count` inside the handler blocks forever
        // on that same mutex and this never returns.
        let bus = Arc::new(EventBus::new());
        let weak_bus = Arc::downgrade(&bus);
        // u64::MAX distinguishes "the handler never ran" from a real
        // count of zero.
        let observed = Arc::new(AtomicU64::new(u64::MAX));
        let recorder = observed.clone();

        bus.subscribe(
            EventType::RequestStarted,
            Box::new(move |_event| {
                let Some(bus) = weak_bus.upgrade() else {
                    return;
                };
                let count = bus.subscriber_count(&EventType::RequestStarted);
                recorder.store(count as u64, Ordering::SeqCst);
            }),
        );

        let publisher = bus.clone();
        run_with_deadline("a handler that counts subscribers", move || {
            publisher.publish(&make_event(EventType::RequestStarted));
        });

        assert_eq!(
            observed.load(Ordering::SeqCst),
            1,
            "the re-entrant handler should have read the live subscriber count"
        );
    }

    #[test]
    fn a_handler_that_subscribes_is_delivered_to_from_the_next_publish() {
        // Two contracts at once: subscribing from inside a handler does
        // not deadlock (pre-fix, `subscribe` blocks on the guard
        // `publish` holds), and the fan-out set is frozen at publish
        // entry, so the handler added mid-flight does not see the event
        // in flight.
        let bus = Arc::new(EventBus::new());
        let weak_bus = Arc::downgrade(&bus);
        let late_handler_runs = Arc::new(AtomicU64::new(0));
        let late_counter = late_handler_runs.clone();
        let already_added = Arc::new(AtomicBool::new(false));

        bus.subscribe(
            EventType::CacheHit,
            Box::new(move |_event| {
                if already_added.swap(true, Ordering::SeqCst) {
                    return;
                }
                let Some(bus) = weak_bus.upgrade() else {
                    return;
                };
                let counter = late_counter.clone();
                bus.subscribe(
                    EventType::CacheHit,
                    Box::new(move |_event| {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }),
                );
            }),
        );

        let publisher = bus.clone();
        run_with_deadline("a handler that subscribes another handler", move || {
            publisher.publish(&make_event(EventType::CacheHit));
        });

        assert_eq!(bus.subscriber_count(&EventType::CacheHit), 2);
        assert_eq!(
            late_handler_runs.load(Ordering::SeqCst),
            0,
            "a handler subscribed during a fan-out must not receive the event \
             that fan-out is already delivering"
        );

        let publisher = bus.clone();
        run_with_deadline("the next publish", move || {
            publisher.publish(&make_event(EventType::CacheHit));
        });

        assert_eq!(
            late_handler_runs.load(Ordering::SeqCst),
            1,
            "the late handler should receive every publish after the one it \
             was added during"
        );
    }

    #[test]
    fn a_handler_that_republishes_its_own_type_stops_at_the_depth_cap() {
        // Releasing the lock is what makes this cycle possible: pre-fix
        // it deadlocked on the second publish. The cap is what keeps it
        // from becoming a stack overflow, which aborts the process
        // instead of failing one call.
        let bus = Arc::new(EventBus::new());
        let weak_bus = Arc::downgrade(&bus);
        let invocations = Arc::new(AtomicU64::new(0));
        let counter = invocations.clone();

        bus.subscribe(
            EventType::RequestError,
            Box::new(move |event| {
                counter.fetch_add(1, Ordering::SeqCst);
                if let Some(bus) = weak_bus.upgrade() {
                    bus.publish(event);
                }
            }),
        );

        let publisher = bus.clone();
        run_with_deadline("a self-republishing handler", move || {
            publisher.publish(&make_event(EventType::RequestError));
        });

        // Invocation n runs at depth n, and the publish it makes sees
        // depth n, so the cap refuses the one that would run invocation
        // MAX_PUBLISH_DEPTH + 1.
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            MAX_PUBLISH_DEPTH as u64,
            "the recursion cap should have bounded the cycle"
        );
    }

    #[test]
    fn the_depth_counter_is_restored_after_a_handler_panics() {
        // The cap is per thread and outlives any single publish, so a
        // depth left incremented by an unwinding handler would ratchet
        // the thread shut: after MAX_PUBLISH_DEPTH panics it would
        // silently stop delivering anything.
        let bus = Arc::new(EventBus::new());
        let survivor_runs = Arc::new(AtomicU64::new(0));
        let counter = survivor_runs.clone();

        bus.subscribe(
            EventType::AuthDenied,
            Box::new(|_event| panic!("handler under test")),
        );
        bus.subscribe(
            EventType::PolicyDenied,
            Box::new(move |_event| {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let publisher = bus.clone();
        run_with_deadline("publishes that survive a panicking handler", move || {
            for _ in 0..(MAX_PUBLISH_DEPTH + 2) {
                let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    publisher.publish(&make_event(EventType::AuthDenied));
                }));
                assert!(panicked.is_err(), "the handler was supposed to panic");
                publisher.publish(&make_event(EventType::PolicyDenied));
            }
        });

        assert_eq!(
            survivor_runs.load(Ordering::SeqCst),
            (MAX_PUBLISH_DEPTH + 2) as u64,
            "every publish after a panicking one should still fan out"
        );
    }
}
