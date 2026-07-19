//! Canonical, secret-free policy resolved for an authenticated virtual key.
//!
//! Persistence and configuration records lower into [`EffectiveKeyPolicy`]
//! before request enforcement. Keeping one runtime shape prevents policy
//! fields from drifting between dynamic keys, configured keys, and dispatch.

use crate::identity::{
    InjectMcpRef, KeyPriority, McpToolFormat, PrincipalSelectorConfig, VirtualKeyConfig,
};
use chrono::{DateTime, Utc};
use sbproxy_plugin::Principal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Schema version included in effective-policy previews and digest material.
pub const EFFECTIVE_KEY_POLICY_SCHEMA_VERSION: u16 = 2;

/// Source that produced an effective key policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveKeySource {
    /// A mutable record created or updated through the admin key API.
    Dynamic,
    /// A key lowered from operator configuration.
    Config,
}

/// Lifecycle state used by request-path policy enforcement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveKeyStatus {
    /// The key may be used while it remains unexpired.
    #[default]
    Active,
    /// The key is temporarily disabled and may be unblocked.
    Blocked,
    /// The key is permanently disabled.
    Revoked,
}

/// Version identifying one persisted policy mutation and its effective value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVersion {
    /// Monotonic per-record revision.
    pub revision: u64,
    /// SHA-256 digest of canonical effective policy, prefixed with `sha256:`.
    pub digest: String,
}

/// Per-key budget limits represented in the canonical runtime policy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KeyBudgetPolicy {
    /// Maximum total tokens for this key.
    pub max_tokens: Option<u64>,
    /// Maximum total cost in USD for this key.
    pub max_cost_usd: Option<f64>,
}

/// One typed inbound-principal selector.
///
/// Fields are ORed within a selector and selector rows are ORed together.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSelector {
    /// Glob matched against the inbound virtual-key name.
    pub virtual_key: Option<String>,
    /// Exact inbound team match.
    pub team: Option<String>,
    /// Exact inbound project match.
    pub project: Option<String>,
    /// Exact inbound user match.
    pub user: Option<String>,
    /// Exact match against any inbound role.
    pub role: Option<String>,
    /// Exact claim key/value matches.
    #[serde(default)]
    pub claim: BTreeMap<String, String>,
}

/// Provider shape used for tools resolved from an MCP gateway.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMcpToolFormat {
    /// OpenAI function-tool JSON.
    #[default]
    Openai,
    /// Anthropic tool JSON.
    Anthropic,
}

/// Effective reference to a federated MCP tool catalogue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMcpRef {
    /// Registered MCP gateway name.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Provider tool-JSON format to emit.
    #[serde(default)]
    pub format: PolicyMcpToolFormat,
    /// Optional exact or trailing-wildcard tool-name filters.
    #[serde(default)]
    pub filter: Vec<String>,
}

/// Request-path subsystem that proves an exposed policy field is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEnforcementProof {
    /// Status and expiry gate key use.
    LifecycleGate,
    /// Tenant policy is checked against the origin tenant boundary.
    TenantBoundary,
    /// Attribution is propagated to safe usage, audit, and trace dimensions.
    Attribution,
    /// Requested models pass through the effective model predicate.
    ModelGate,
    /// Candidate providers pass through the effective provider predicate.
    ProviderGate,
    /// The effective route override is applied before model enforcement.
    RouteOverride,
    /// Request dispatch resolves the key's compression selector by precedence.
    CompressionSelection,
    /// Inbound principal attributes pass through the selector gate.
    PrincipalGate,
    /// Required PII rules are checked before upstream dispatch.
    PiiGuardrail,
    /// Caller-supplied tools pass through the effective allowlist.
    ToolGate,
    /// Static or MCP-backed tools are injected from effective policy.
    ToolInjection,
    /// Prompt-injection evaluation receives the effective bypass bit.
    PromptInjection,
    /// Per-key request and token windows are enforced.
    RateLimit,
    /// Per-key token and cost budgets are enforced.
    Budget,
    /// Served-model admission uses the key's priority lane.
    AdmissionPriority,
}

impl PolicyEnforcementProof {
    /// Stable identifier used by generated policy-contract tests.
    pub const fn id(self) -> &'static str {
        match self {
            Self::LifecycleGate => "lifecycle_gate",
            Self::TenantBoundary => "tenant_boundary",
            Self::Attribution => "attribution",
            Self::ModelGate => "model_gate",
            Self::ProviderGate => "provider_gate",
            Self::RouteOverride => "route_override",
            Self::CompressionSelection => "compression_selection",
            Self::PrincipalGate => "principal_gate",
            Self::PiiGuardrail => "pii_guardrail",
            Self::ToolGate => "tool_gate",
            Self::ToolInjection => "tool_injection",
            Self::PromptInjection => "prompt_injection",
            Self::RateLimit => "rate_limit",
            Self::Budget => "budget",
            Self::AdmissionPriority => "admission_priority",
        }
    }
}

/// How an admin client mutates one effective-policy field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMutationKind {
    /// The named fields are members of the flat key PATCH body.
    Patch,
    /// The named values are lifecycle action subroutes.
    Action,
}

/// Wire mapping from an effective-policy field to its admin mutation surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PolicyMutationDescriptor {
    /// Mutation transport used for this field.
    pub kind: PolicyMutationKind,
    /// PATCH member names or action names, depending on [`Self::kind`].
    pub fields: &'static [&'static str],
}

/// Server-recommended editor for one policy field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEditor {
    /// Lifecycle action controls.
    Lifecycle,
    /// Nullable single-line text.
    Text,
    /// RFC 3339 date-time input.
    DateTime,
    /// List of opaque strings.
    StringList,
    /// String-to-string map.
    StringMap,
    /// Model-name list.
    ModelList,
    /// Provider-name list.
    ProviderList,
    /// Typed inbound-principal selector rows.
    PrincipalSelectors,
    /// Required guardrail-name list.
    GuardrailList,
    /// Optional tool-name allowlist.
    ToolAllowlist,
    /// List of provider-shaped JSON values.
    JsonList,
    /// Federated MCP reference object.
    McpReference,
    /// Boolean toggle.
    Boolean,
    /// Nullable non-negative integer.
    PositiveInteger,
    /// Token and monetary budget pair.
    Budget,
    /// Served-model priority lane.
    Priority,
}

/// Exact value an admin client sends to clear a policy field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyClearSemantics {
    /// Lifecycle is changed only through an explicit action.
    ActionOnly,
    /// JSON `null` removes the value.
    Null,
    /// An empty JSON array removes every entry.
    EmptyList,
    /// An empty JSON object removes every entry.
    EmptyObject,
    /// JSON `false` disables the behavior.
    False,
    /// JSON `null` removes the tool restriction; `[]` denies every tool.
    NullMeansUnrestricted,
    /// JSON `null` restores the standard priority lane.
    NullMeansStandard,
    /// Setting both budget mutation fields to JSON `null` removes the budget.
    AllBudgetFieldsNull,
}

/// One complete, server-driven policy field contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PolicyFieldDescriptor {
    /// Field name in [`EffectiveKeyPolicy`] JSON.
    pub wire_name: &'static str,
    /// Mapping onto the admin mutation API.
    pub mutation: PolicyMutationDescriptor,
    /// Server-recommended editor.
    pub editor: PolicyEditor,
    /// Exact clearing behavior.
    pub clear_semantics: PolicyClearSemantics,
    /// Field name in the effective-policy preview object.
    pub preview_field: &'static str,
    /// Request-path subsystem that consumes this field.
    pub enforcement_proof: &'static str,
}

macro_rules! declare_policy_fields {
    (
        $(
            $(#[$meta:meta])*
            $variant:ident => (
                $wire_name:literal,
                $proof:ident,
                $mutation_kind:ident,
                [$($mutation_field:literal),+ $(,)?],
                $editor:ident,
                $clear:ident
            )
        ),+ $(,)?
    ) => {
        /// Fields exposed by the effective key-policy contract.
        ///
        /// This enum, [`Self::ALL`], wire names, and enforcement-proof mapping
        /// are generated from one declaration so a new exposed field cannot be
        /// added without registering its request-path consumer.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum PolicyField {
            $(
                $(#[$meta])*
                $variant,
            )+
        }

        impl PolicyField {
            /// Every field in stable server-schema order.
            pub const ALL: &'static [Self] = &[
                $(Self::$variant,)+
            ];

            /// Stable JSON field name.
            pub const fn wire_name(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire_name,)+
                }
            }

            /// Request-path subsystem responsible for this field.
            pub const fn enforcement_proof(self) -> PolicyEnforcementProof {
                match self {
                    $(Self::$variant => PolicyEnforcementProof::$proof,)+
                }
            }

            /// Complete descriptor registry in the same stable order as
            /// [`Self::ALL`].
            pub const DESCRIPTORS: &'static [PolicyFieldDescriptor] = &[
                    $(
                        PolicyFieldDescriptor {
                            wire_name: $wire_name,
                            mutation: PolicyMutationDescriptor {
                                kind: PolicyMutationKind::$mutation_kind,
                                fields: &[$($mutation_field,)+],
                            },
                            editor: PolicyEditor::$editor,
                            clear_semantics: PolicyClearSemantics::$clear,
                            preview_field: $wire_name,
                            enforcement_proof: PolicyEnforcementProof::$proof.id(),
                        },
                    )+
                ];

            /// Return the complete server-driven descriptor registry.
            pub const fn descriptors() -> &'static [PolicyFieldDescriptor] {
                Self::DESCRIPTORS
            }
        }
    };
}

declare_policy_fields! {
    /// Mutable display name used for safe attribution.
    DisplayName => ("display_name", Attribution, Patch, ["name"], Text, Null),
    /// Lifecycle status.
    Status => (
        "status",
        LifecycleGate,
        Action,
        ["block", "unblock", "revoke"],
        Lifecycle,
        ActionOnly
    ),
    /// Expiry timestamp.
    ExpiresAt => ("expires_at", LifecycleGate, Patch, ["expires_at"], DateTime, Null),
    /// Effective tenant boundary.
    TenantId => ("tenant_id", TenantBoundary, Patch, ["tenant"], Text, Null),
    /// Project attribution.
    Project => ("project", Attribution, Patch, ["project"], Text, Null),
    /// User attribution.
    User => ("user", Attribution, Patch, ["user"], Text, Null),
    /// Grouping tags.
    Tags => ("tags", Attribution, Patch, ["tags"], StringList, EmptyList),
    /// Safe string metadata.
    Metadata => ("metadata", Attribution, Patch, ["metadata"], StringMap, EmptyObject),
    /// Model allowlist.
    AllowedModels => (
        "allowed_models",
        ModelGate,
        Patch,
        ["allowed_models"],
        ModelList,
        EmptyList
    ),
    /// Model blocklist.
    BlockedModels => (
        "blocked_models",
        ModelGate,
        Patch,
        ["blocked_models"],
        ModelList,
        EmptyList
    ),
    /// Provider allowlist.
    AllowedProviders => (
        "allowed_providers",
        ProviderGate,
        Patch,
        ["allowed_providers"],
        ProviderList,
        EmptyList
    ),
    /// Provider blocklist.
    BlockedProviders => (
        "blocked_providers",
        ProviderGate,
        Patch,
        ["blocked_providers"],
        ProviderList,
        EmptyList
    ),
    /// Model route override.
    RouteToModel => ("route_to_model", RouteOverride, Patch, ["route_to_model"], Text, Null),
    /// Route-local compression selector.
    CompressionProfile => (
        "compression_profile",
        CompressionSelection,
        Patch,
        ["compression_profile"],
        Text,
        Null
    ),
    /// Inbound principal selectors.
    PrincipalSelectors => (
        "principal_selectors",
        PrincipalGate,
        Patch,
        ["principal_selectors"],
        PrincipalSelectors,
        EmptyList
    ),
    /// Required PII-redaction rules.
    RequirePiiRedaction => (
        "require_pii_redaction",
        PiiGuardrail,
        Patch,
        ["require_pii_redaction"],
        GuardrailList,
        EmptyList
    ),
    /// Caller tool allowlist.
    AllowedTools => (
        "allowed_tools",
        ToolGate,
        Patch,
        ["allowed_tools"],
        ToolAllowlist,
        NullMeansUnrestricted
    ),
    /// Static injected tools.
    InjectTools => (
        "inject_tools",
        ToolInjection,
        Patch,
        ["inject_tools"],
        JsonList,
        EmptyList
    ),
    /// MCP catalogue injection.
    InjectMcp => ("inject_mcp", ToolInjection, Patch, ["inject_mcp"], McpReference, Null),
    /// Prompt-injection bypass bit.
    BypassPromptInjection => (
        "bypass_prompt_injection",
        PromptInjection,
        Patch,
        ["bypass_prompt_injection"],
        Boolean,
        False
    ),
    /// Per-minute request cap.
    MaxRequestsPerMinute => (
        "max_requests_per_minute",
        RateLimit,
        Patch,
        ["max_requests_per_minute"],
        PositiveInteger,
        Null
    ),
    /// Per-minute token cap.
    MaxTokensPerMinute => (
        "max_tokens_per_minute",
        RateLimit,
        Patch,
        ["max_tokens_per_minute"],
        PositiveInteger,
        Null
    ),
    /// Token and cost budget.
    Budget => (
        "budget",
        Budget,
        Patch,
        ["max_budget_tokens", "max_budget_usd"],
        Budget,
        AllBudgetFieldsNull
    ),
    /// Served-model admission priority.
    Priority => (
        "priority",
        AdmissionPriority,
        Patch,
        ["priority"],
        Priority,
        NullMeansStandard
    ),
}

/// Fully resolved, secret-free policy consumed by request dispatch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveKeyPolicy {
    /// Effective-policy schema version.
    pub schema_version: u16,
    /// Immutable, non-secret key identifier used for attribution and limits.
    pub key_id: String,
    /// Mutable operator-facing display name. Never used as key identity.
    pub display_name: Option<String>,
    /// Source that produced this policy.
    pub source: EffectiveKeySource,
    /// Monotonic revision of the persisted record.
    pub policy_revision: u64,
    /// Lifecycle status.
    pub status: EffectiveKeyStatus,
    /// Optional expiry. An instant equal to `now` is already expired.
    pub expires_at: Option<DateTime<Utc>>,
    /// Tenant accepted at the origin boundary.
    pub tenant_id: String,
    /// Project attribution.
    pub project: Option<String>,
    /// User attribution.
    pub user: Option<String>,
    /// Free-form grouping tags.
    pub tags: Vec<String>,
    /// Operator-supplied string metadata retained by usage and access-log
    /// sinks. Security audits, traces, and metric labels omit it.
    pub metadata: BTreeMap<String, String>,
    /// Models this key may use. Empty permits all non-blocked models.
    pub allowed_models: Vec<String>,
    /// Models this key may not use. Blocks override allows.
    pub blocked_models: Vec<String>,
    /// Providers this key may use. Empty permits all non-blocked providers.
    pub allowed_providers: Vec<String>,
    /// Providers this key may not use. Blocks override allows.
    pub blocked_providers: Vec<String>,
    /// Optional model override applied before model enforcement.
    pub route_to_model: Option<String>,
    /// Route-local compression selector applied before cache lookup.
    pub compression_profile: Option<String>,
    /// Typed inbound-principal selectors. Empty permits any principal.
    pub principal_selectors: Vec<PrincipalSelector>,
    /// PII redaction rules required before upstream dispatch.
    pub require_pii_redaction: Vec<String>,
    /// Caller tool names permitted by this key. `None` means unrestricted.
    pub allowed_tools: Option<Vec<String>>,
    /// Static provider-shaped tool definitions injected into the request.
    pub inject_tools: Vec<Value>,
    /// Optional federated MCP tool-catalogue injection.
    pub inject_mcp: Option<PolicyMcpRef>,
    /// Whether body-aware prompt-injection evaluation is bypassed.
    pub bypass_prompt_injection: bool,
    /// Maximum requests per minute.
    pub max_requests_per_minute: Option<u64>,
    /// Maximum completed tokens per minute.
    pub max_tokens_per_minute: Option<u64>,
    /// Optional token and cost budget.
    pub budget: Option<KeyBudgetPolicy>,
    /// Served-model admission priority.
    pub priority: KeyPriority,
}

impl EffectiveKeyPolicy {
    /// Lower a typed configured key into the canonical governed policy.
    ///
    /// Legacy configured keys without a non-empty public `key_id` return
    /// `None`. Their bearer material is deliberately not copied into this
    /// secret-free shape.
    pub fn from_configured_key(key: &VirtualKeyConfig, origin_tenant_id: &str) -> Option<Self> {
        let key_id = key
            .key_id
            .as_deref()
            .filter(|key_id| !key_id.trim().is_empty())?;
        Some(Self {
            schema_version: EFFECTIVE_KEY_POLICY_SCHEMA_VERSION,
            key_id: key_id.to_owned(),
            display_name: key.name.clone(),
            source: EffectiveKeySource::Config,
            policy_revision: 1,
            status: EffectiveKeyStatus::Active,
            expires_at: None,
            tenant_id: origin_tenant_id.to_owned(),
            project: key.project.clone(),
            user: key.user.clone(),
            tags: key.tags.clone(),
            metadata: key
                .metadata
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            allowed_models: key.allowed_models.clone(),
            blocked_models: key.blocked_models.clone(),
            allowed_providers: key.allowed_providers.clone(),
            blocked_providers: key.blocked_providers.clone(),
            route_to_model: key.route_to_model.clone(),
            compression_profile: key.compression_profile.clone(),
            principal_selectors: key
                .principal_selectors
                .iter()
                .map(PrincipalSelector::from)
                .collect(),
            require_pii_redaction: key.require_pii_redaction.clone(),
            allowed_tools: key.allowed_tools.clone(),
            inject_tools: key.inject_tools.clone(),
            inject_mcp: key.inject_mcp.as_ref().map(PolicyMcpRef::from),
            bypass_prompt_injection: key.bypass_prompt_injection,
            max_requests_per_minute: key.max_requests_per_minute,
            max_tokens_per_minute: key.max_tokens_per_minute,
            budget: key.budget.as_ref().map(|budget| KeyBudgetPolicy {
                max_tokens: budget.max_tokens,
                max_cost_usd: budget.max_cost_usd,
            }),
            priority: key.priority.unwrap_or(KeyPriority::Standard),
        })
    }

    /// Whether this policy is active and unexpired at `now`.
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.status == EffectiveKeyStatus::Active
            && self.expires_at.is_none_or(|expires_at| expires_at > now)
    }

    /// Whether `model` passes the effective model allow and block lists.
    pub fn is_model_allowed(&self, model: &str) -> bool {
        is_allowed(model, &self.allowed_models, &self.blocked_models)
    }

    /// Whether `provider` passes the effective provider allow and block lists.
    pub fn is_provider_allowed(&self, provider: &str) -> bool {
        is_allowed(provider, &self.allowed_providers, &self.blocked_providers)
    }

    /// Whether the authenticated inbound principal passes this policy.
    pub fn matches_principal(&self, principal: &Principal) -> bool {
        self.principal_selectors.is_empty()
            || self
                .principal_selectors
                .iter()
                .any(|selector| selector.matches(principal))
    }

    /// Whether a caller-supplied tool name passes the effective allowlist.
    pub fn is_tool_allowed(&self, tool: &str) -> bool {
        self.allowed_tools
            .as_ref()
            .is_none_or(|allowed| allowed.iter().any(|candidate| candidate == tool))
    }

    /// Compute a stable SHA-256 digest of effective behavior and attribution.
    ///
    /// The mutation revision is excluded because it is already represented by
    /// [`PolicyVersion::revision`]. Set-like collections are sorted and
    /// deduplicated before hashing so semantically equivalent ordering produces
    /// the same digest. Injected tool order remains significant.
    pub fn policy_digest(&self) -> Result<String, serde_json::Error> {
        let mut normalized = self.clone();
        normalize_set(&mut normalized.tags);
        normalize_set(&mut normalized.allowed_models);
        normalize_set(&mut normalized.blocked_models);
        normalize_set(&mut normalized.allowed_providers);
        normalize_set(&mut normalized.blocked_providers);
        normalize_set(&mut normalized.require_pii_redaction);
        if let Some(allowed_tools) = normalized.allowed_tools.as_mut() {
            normalize_set(allowed_tools);
        }
        normalized.principal_selectors.sort();
        normalized.principal_selectors.dedup();
        if let Some(inject_mcp) = normalized.inject_mcp.as_mut() {
            normalize_set(&mut inject_mcp.filter);
        }

        let mut value = serde_json::to_value(normalized)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("policy_revision");
        }
        let mut canonical = String::new();
        write_canonical_json(&value, &mut canonical);
        let digest = Sha256::digest(canonical.as_bytes());
        Ok(format!("sha256:{}", hex::encode(digest)))
    }

    /// Pair the persisted revision with the canonical effective-policy digest.
    pub fn policy_version(&self) -> Result<PolicyVersion, serde_json::Error> {
        Ok(PolicyVersion {
            revision: self.policy_revision,
            digest: self.policy_digest()?,
        })
    }
}

impl From<&PrincipalSelectorConfig> for PrincipalSelector {
    fn from(selector: &PrincipalSelectorConfig) -> Self {
        Self {
            virtual_key: selector.virtual_key.clone(),
            team: selector.team.clone(),
            project: selector.project.clone(),
            user: selector.user.clone(),
            role: selector.role.clone(),
            claim: selector.claim.clone(),
        }
    }
}

impl From<&InjectMcpRef> for PolicyMcpRef {
    fn from(reference: &InjectMcpRef) -> Self {
        Self {
            reference: reference.reference.clone(),
            format: match reference.format {
                McpToolFormat::Openai => PolicyMcpToolFormat::Openai,
                McpToolFormat::Anthropic => PolicyMcpToolFormat::Anthropic,
            },
            filter: reference.filter.clone(),
        }
    }
}

impl PrincipalSelector {
    fn is_empty(&self) -> bool {
        self.virtual_key.is_none()
            && self.team.is_none()
            && self.project.is_none()
            && self.user.is_none()
            && self.role.is_none()
            && self.claim.is_empty()
    }

    fn matches(&self, principal: &Principal) -> bool {
        if self.is_empty() {
            return false;
        }
        if let Some(pattern) = self.virtual_key.as_deref() {
            if principal
                .virtual_key
                .as_ref()
                .is_some_and(|key| sbproxy_util::prefix_glob_match(pattern, &key.name))
            {
                return true;
            }
        }
        if self
            .team
            .as_deref()
            .is_some_and(|team| principal.attrs.team.as_deref() == Some(team))
        {
            return true;
        }
        if self
            .project
            .as_deref()
            .is_some_and(|project| principal.attrs.project.as_deref() == Some(project))
        {
            return true;
        }
        if self
            .user
            .as_deref()
            .is_some_and(|user| principal.attrs.user.as_deref() == Some(user))
        {
            return true;
        }
        if self.role.as_deref().is_some_and(|role| {
            principal
                .attrs
                .roles
                .iter()
                .any(|candidate| candidate == role)
        }) {
            return true;
        }
        principal.attrs.claims.as_ref().is_some_and(|claims| {
            self.claim.iter().any(|(key, expected)| {
                claims
                    .get(key)
                    .is_some_and(|actual| claim_value_matches(actual, expected))
            })
        })
    }
}

fn claim_value_matches(actual: &Value, expected: &str) -> bool {
    if let Some(actual) = actual.as_str() {
        return actual == expected;
    }
    serde_json::from_str::<Value>(expected).is_ok_and(|expected| *actual == expected)
}

fn is_allowed(value: &str, allowed: &[String], blocked: &[String]) -> bool {
    if blocked.iter().any(|candidate| candidate == value) {
        return false;
    }
    allowed.is_empty() || allowed.iter().any(|candidate| candidate == value)
}

fn normalize_set(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn write_canonical_json(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => {
            output
                .push_str(&serde_json::to_string(value).expect("serializing a string cannot fail"));
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(value, output);
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).expect("serializing an object key cannot fail"),
                );
                output.push(':');
                write_canonical_json(&values[key], output);
            }
            output.push('}');
        }
    }
}

/// Error returned when a key record attempts to cross an origin tenant boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TenantResolutionError {
    /// The record tenant differs from the origin tenant.
    #[error("key tenant '{key_tenant_id}' does not match origin tenant '{origin_tenant_id}'")]
    Mismatch {
        /// Tenant configured on the origin handling the request.
        origin_tenant_id: String,
        /// Tenant attached to the authenticated key record.
        key_tenant_id: String,
    },
}

/// Resolve the effective tenant without allowing a key to cross its origin.
///
/// A key without an explicit tenant inherits the origin tenant. An explicit
/// tenant must match exactly or resolution fails closed.
pub fn resolve_effective_tenant(
    origin_tenant_id: &str,
    key_tenant_id: Option<&str>,
) -> Result<String, TenantResolutionError> {
    match key_tenant_id {
        None => Ok(origin_tenant_id.to_owned()),
        Some(key_tenant_id) if key_tenant_id == origin_tenant_id => Ok(key_tenant_id.to_owned()),
        Some(key_tenant_id) => Err(TenantResolutionError::Mismatch {
            origin_tenant_id: origin_tenant_id.to_owned(),
            key_tenant_id: key_tenant_id.to_owned(),
        }),
    }
}
