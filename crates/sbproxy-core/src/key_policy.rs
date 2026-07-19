//! Shared lowering from stored key records into the canonical runtime policy.
//!
//! Both request dispatch and admin preview use this seam so malformed stored
//! policy fails closed in exactly one place. Errors retain only a bounded kind;
//! they never retain record values, verifier hashes, or deserializer payloads.

use sbproxy_ai::effective_key_policy::{
    resolve_effective_tenant, EffectiveKeyPolicy, EffectiveKeySource, EffectiveKeyStatus,
    KeyBudgetPolicy, PolicyMcpRef, PrincipalSelector, EFFECTIVE_KEY_POLICY_SCHEMA_VERSION,
};
use sbproxy_keystore::record::{KeyRecord, RecordSource, RecordStatus};

/// Bounded reason a stored key record could not become an effective policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredPolicyErrorKind {
    /// The immutable public key identifier is empty.
    EmptyKeyId,
    /// The monotonic policy revision is zero.
    InvalidRevision,
    /// The stored tenant crosses the request origin tenant boundary.
    TenantMismatch,
    /// A stored principal selector is malformed or contains unknown fields.
    PrincipalSelector,
    /// The stored MCP reference is malformed or has an empty reference.
    McpReference,
    /// The stored served-model priority lane is not recognized.
    InvalidPriority,
    /// The stored monetary budget is negative, non-finite, or unrepresentable.
    InvalidBudget,
}

/// Secret-free stored-policy lowering error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredPolicyError {
    kind: StoredPolicyErrorKind,
}

impl StoredPolicyError {
    fn new(kind: StoredPolicyErrorKind) -> Self {
        Self { kind }
    }

    /// Bounded error category suitable for tests and programmatic handling.
    pub const fn kind(self) -> StoredPolicyErrorKind {
        self.kind
    }

    /// Stable, payload-free reason suitable for audit logs.
    pub const fn safe_reason(self) -> &'static str {
        match self.kind {
            StoredPolicyErrorKind::EmptyKeyId => "empty_key_id",
            StoredPolicyErrorKind::InvalidRevision => "invalid_policy_revision",
            StoredPolicyErrorKind::TenantMismatch => "tenant_mismatch",
            StoredPolicyErrorKind::PrincipalSelector => "invalid_principal_selector",
            StoredPolicyErrorKind::McpReference => "invalid_mcp_reference",
            StoredPolicyErrorKind::InvalidPriority => "invalid_priority",
            StoredPolicyErrorKind::InvalidBudget => "invalid_budget",
        }
    }
}

impl std::fmt::Display for StoredPolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.safe_reason())
    }
}

impl std::error::Error for StoredPolicyError {}

/// Lower one authenticated stored record into the canonical secret-free policy.
pub fn key_record_to_effective_policy(
    record: &KeyRecord,
    origin_tenant_id: &str,
) -> Result<EffectiveKeyPolicy, StoredPolicyError> {
    if record.key_id.trim().is_empty() {
        return Err(StoredPolicyError::new(StoredPolicyErrorKind::EmptyKeyId));
    }
    if record.policy_revision == 0 {
        return Err(StoredPolicyError::new(
            StoredPolicyErrorKind::InvalidRevision,
        ));
    }
    let tenant_id = resolve_effective_tenant(origin_tenant_id, record.tenant_id.as_deref())
        .map_err(|_| StoredPolicyError::new(StoredPolicyErrorKind::TenantMismatch))?;
    let principal_selectors = record
        .principal_selectors
        .iter()
        .map(|value| {
            serde_json::from_value::<PrincipalSelector>(value.clone())
                .map_err(|_| StoredPolicyError::new(StoredPolicyErrorKind::PrincipalSelector))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inject_mcp = record
        .inject_mcp
        .as_ref()
        .map(|value| {
            serde_json::from_value::<PolicyMcpRef>(value.clone())
                .map_err(|_| StoredPolicyError::new(StoredPolicyErrorKind::McpReference))
        })
        .transpose()?;
    if inject_mcp
        .as_ref()
        .is_some_and(|reference| reference.reference.trim().is_empty())
    {
        return Err(StoredPolicyError::new(StoredPolicyErrorKind::McpReference));
    }
    let priority = match record.priority.as_deref() {
        None => sbproxy_ai::identity::KeyPriority::Standard,
        Some(priority) => sbproxy_ai::identity::KeyPriority::parse(priority).ok_or(
            StoredPolicyError::new(StoredPolicyErrorKind::InvalidPriority),
        )?,
    };
    if record
        .budget
        .as_ref()
        .and_then(|budget| budget.max_cost_usd)
        .is_some_and(|value| {
            const MICRO_USD_PER_USD: f64 = 1_000_000.0;
            let micro_usd = value * MICRO_USD_PER_USD;
            !value.is_finite()
                || value < 0.0
                || !micro_usd.is_finite()
                || micro_usd >= u64::MAX as f64
        })
    {
        return Err(StoredPolicyError::new(StoredPolicyErrorKind::InvalidBudget));
    }

    Ok(EffectiveKeyPolicy {
        schema_version: EFFECTIVE_KEY_POLICY_SCHEMA_VERSION,
        key_id: record.key_id.clone(),
        display_name: record.name.clone(),
        source: match record.source {
            RecordSource::Api => EffectiveKeySource::Dynamic,
            RecordSource::Config => EffectiveKeySource::Config,
        },
        policy_revision: record.policy_revision,
        status: match record.status {
            RecordStatus::Active => EffectiveKeyStatus::Active,
            RecordStatus::Blocked => EffectiveKeyStatus::Blocked,
            RecordStatus::Revoked => EffectiveKeyStatus::Revoked,
        },
        expires_at: record.expires_at,
        tenant_id,
        project: record.project.clone(),
        user: record.user.clone(),
        tags: record.tags.clone(),
        metadata: record.metadata.clone(),
        allowed_models: record.allowed_models.clone(),
        blocked_models: record.blocked_models.clone(),
        allowed_providers: record.allowed_providers.clone(),
        blocked_providers: record.blocked_providers.clone(),
        route_to_model: record.route_to_model.clone(),
        compression_profile: record.compression_profile.clone(),
        principal_selectors,
        require_pii_redaction: record.require_pii_redaction.clone(),
        allowed_tools: record.allowed_tools.clone(),
        inject_tools: record.inject_tools.clone(),
        inject_mcp,
        bypass_prompt_injection: record.bypass_prompt_injection,
        max_requests_per_minute: record.max_requests_per_minute,
        max_tokens_per_minute: record.max_tokens_per_minute,
        budget: record.budget.as_ref().map(|budget| KeyBudgetPolicy {
            max_tokens: budget.max_tokens,
            max_cost_usd: budget.max_cost_usd,
        }),
        priority,
    })
}
