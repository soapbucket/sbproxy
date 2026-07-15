//! WOR-1553: the admin key/credential lifecycle REST API.
//!
//! Mounted in the existing `/admin` server (shared bind + basic auth). Routes:
//!
//! ```text
//! POST   /admin/keys                      mint a key (plaintext token shown once)
//! GET    /admin/keys                      list keys (no secrets)
//! GET    /admin/keys/policy-schema        fetch the server-driven policy contract
//! GET    /admin/keys/{id}                 fetch one key
//! GET    /admin/keys/{id}/usage           fetch governed usage and backend health
//! POST   /admin/keys/{id}/effective-policy/preview
//!                                            evaluate policy without dispatch or reserve
//! PATCH  /admin/keys/{id}                 update policy/attribution
//! DELETE /admin/keys/{id}                 delete a key
//! POST   /admin/keys/{id}/revoke          mark revoked (terminal)
//! POST   /admin/keys/{id}/block           mark blocked
//! POST   /admin/keys/{id}/unblock         mark active
//! POST   /admin/keys/{id}/rotate          rotate (see admin rotation, WOR-1554)
//! POST   /admin/credentials               create an upstream credential
//! GET    /admin/credentials               list credentials (no secrets)
//! GET    /admin/credentials/{id}          fetch one credential
//! PATCH  /admin/credentials/{id}          update credential metadata
//! DELETE /admin/credentials/{id}          delete a credential
//! POST   /admin/credentials/{id}/revoke|block|unblock
//! ```
//!
//! Every mutation goes through the store then invalidates the cache so the
//! change takes effect on the next request without a reload. Responses never
//! carry a hash, an envelope, or plaintext (apart from the one-time minted
//! token on create).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::key_plane::{block_on_keystore, current_key_plane, KeyPlane};
use sbproxy_ai::governance::{GovernanceError, GovernanceLimits, SnapshotKey};
use sbproxy_keystore::record::{
    CredentialMaterial, CredentialRecord, KeyRecord, RecordBudget, RecordStatus,
};
use sbproxy_keystore::KeyPolicyCasResult;

type Resp = (u16, &'static str, String);

/// Route entry point. Returns `Some(response)` for paths this module owns and
/// `None` so the caller can fall through to the rest of the admin dispatcher.
pub fn dispatch(method: &str, path: &str, body: Option<&str>) -> Option<Resp> {
    if path == "/admin/keys" {
        return Some(if method.eq_ignore_ascii_case("GET") {
            list_keys()
        } else if method.eq_ignore_ascii_case("POST") {
            create_key(body)
        } else {
            method_not_allowed()
        });
    }
    if path == "/admin/keys/policy-schema" {
        return Some(if method.eq_ignore_ascii_case("GET") {
            get_key_policy_schema()
        } else {
            method_not_allowed()
        });
    }
    if let Some(rest) = path.strip_prefix("/admin/keys/") {
        return Some(key_subroute(method, rest, body));
    }
    if path == "/admin/credentials" {
        return Some(if method.eq_ignore_ascii_case("GET") {
            list_credentials()
        } else if method.eq_ignore_ascii_case("POST") {
            create_credential(body)
        } else {
            method_not_allowed()
        });
    }
    if let Some(rest) = path.strip_prefix("/admin/credentials/") {
        return Some(credential_subroute(method, rest, body));
    }
    None
}

fn key_subroute(method: &str, rest: &str, body: Option<&str>) -> Resp {
    let mut parts = rest.splitn(2, '/');
    let id = parts.next().unwrap_or("");
    let action = parts.next();
    if id.is_empty() {
        return not_found("missing key id");
    }
    match action {
        None => {
            if method.eq_ignore_ascii_case("GET") {
                get_key(id)
            } else if method.eq_ignore_ascii_case("PATCH") {
                update_key(id, body)
            } else if method.eq_ignore_ascii_case("DELETE") {
                delete_key(id)
            } else {
                method_not_allowed()
            }
        }
        Some("usage") if method.eq_ignore_ascii_case("GET") => get_key_usage(id),
        Some("effective-policy/preview") if method.eq_ignore_ascii_case("POST") => {
            preview_effective_key_policy(id, body)
        }
        Some(action) if method.eq_ignore_ascii_case("POST") => match action {
            "revoke" => set_key_status(id, RecordStatus::Revoked, body),
            "block" => set_key_status(id, RecordStatus::Blocked, body),
            "unblock" => set_key_status(id, RecordStatus::Active, body),
            "rotate" => rotate_key(id, body),
            _ => not_found("unknown key action"),
        },
        Some(_) => method_not_allowed(),
    }
}

fn credential_subroute(method: &str, rest: &str, body: Option<&str>) -> Resp {
    let mut parts = rest.splitn(2, '/');
    let id = parts.next().unwrap_or("");
    let action = parts.next();
    if id.is_empty() {
        return not_found("missing credential id");
    }
    match action {
        None => {
            if method.eq_ignore_ascii_case("GET") {
                get_credential(id)
            } else if method.eq_ignore_ascii_case("PATCH") {
                update_credential(id, body)
            } else if method.eq_ignore_ascii_case("DELETE") {
                delete_credential(id)
            } else {
                method_not_allowed()
            }
        }
        Some(action) if method.eq_ignore_ascii_case("POST") => match action {
            "revoke" => set_credential_status(id, RecordStatus::Revoked),
            "block" => set_credential_status(id, RecordStatus::Blocked),
            "unblock" => set_credential_status(id, RecordStatus::Active),
            _ => not_found("unknown credential action"),
        },
        Some(_) => method_not_allowed(),
    }
}

// --- Key handlers ---

/// Three-way PATCH state: absent leaves a field unchanged, JSON `null` clears
/// a nullable value, and a concrete value replaces it.
#[derive(Debug, Clone, Default)]
enum Patch<T> {
    /// Field was absent.
    #[default]
    Missing,
    /// Field was explicitly JSON `null`.
    Null,
    /// Field carried a concrete replacement value.
    Value(T),
}

impl<'de, T> Deserialize<'de> for Patch<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match Option::<T>::deserialize(deserializer)? {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KeyMutation {
    expected_revision: Option<u64>,
    name: Patch<String>,
    max_requests_per_minute: Patch<u64>,
    max_tokens_per_minute: Patch<u64>,
    /// SLO priority lane: `interactive` | `standard` | `batch`.
    priority: Patch<String>,
    max_budget_tokens: Patch<u64>,
    max_budget_usd: Patch<f64>,
    allowed_models: Patch<Vec<String>>,
    blocked_models: Patch<Vec<String>>,
    allowed_providers: Patch<Vec<String>>,
    blocked_providers: Patch<Vec<String>>,
    require_pii_redaction: Patch<Vec<String>>,
    principal_selectors: Patch<Vec<serde_json::Value>>,
    /// Pin a model for this key. JSON `null` clears the pin.
    route_to_model: Patch<String>,
    allowed_tools: Patch<Vec<String>>,
    inject_tools: Patch<Vec<serde_json::Value>>,
    /// Federated-MCP injection ref. JSON `null` clears it.
    inject_mcp: Patch<serde_json::Value>,
    bypass_prompt_injection: Patch<bool>,
    project: Patch<String>,
    user: Patch<String>,
    tags: Patch<Vec<String>>,
    /// Free-form string metadata; replaces the record's map wholesale.
    metadata: Patch<std::collections::BTreeMap<String, String>>,
    tenant: Patch<String>,
    /// RFC 3339 expiry. JSON `null` clears it.
    expires_at: Patch<DateTime<Utc>>,
}

/// Reject mutation values that would store an invalid policy: an unknown
/// priority lane, or an `inject_mcp` value that is not an object carrying
/// the required `ref` string. Runs before [`apply_key_mutation`] so a bad
/// PATCH is a 400, never a silently-stored record the AI seam later drops.
fn validate_key_mutation(m: &KeyMutation) -> Result<(), String> {
    if let Some(0) = m.expected_revision {
        return Err("expected_revision must be at least 1".to_string());
    }
    if let Patch::Value(p) = &m.priority {
        if sbproxy_ai::identity::KeyPriority::parse(p).is_none() {
            return Err(format!(
                "priority '{p}' is not a lane; use interactive, standard, or batch"
            ));
        }
    }
    if let Patch::Value(v) = &m.inject_mcp {
        let has_ref = v
            .as_object()
            .and_then(|o| o.get("ref"))
            .and_then(|r| r.as_str())
            .is_some_and(|s| !s.is_empty());
        if !has_ref {
            return Err(
                "inject_mcp must be an object with a non-empty `ref` naming a federated \
                 MCP gateway, e.g. {\"ref\": \"toolhub\"}"
                    .to_string(),
            );
        }
    }
    if let Patch::Value(selectors) = &m.principal_selectors {
        for (index, selector) in selectors.iter().enumerate() {
            serde_json::from_value::<sbproxy_ai::identity::PrincipalSelectorConfig>(
                selector.clone(),
            )
            .map_err(|error| format!("principal_selectors[{index}] is invalid: {error}"))?;
        }
    }
    if let Patch::Value(value) = &m.max_budget_usd {
        if !value.is_finite() || *value < 0.0 {
            return Err("max_budget_usd must be a finite non-negative number".to_string());
        }
    }
    for (field, is_null) in [
        ("allowed_models", matches!(&m.allowed_models, Patch::Null)),
        ("blocked_models", matches!(&m.blocked_models, Patch::Null)),
        (
            "allowed_providers",
            matches!(&m.allowed_providers, Patch::Null),
        ),
        (
            "blocked_providers",
            matches!(&m.blocked_providers, Patch::Null),
        ),
        (
            "require_pii_redaction",
            matches!(&m.require_pii_redaction, Patch::Null),
        ),
        (
            "principal_selectors",
            matches!(&m.principal_selectors, Patch::Null),
        ),
        ("inject_tools", matches!(&m.inject_tools, Patch::Null)),
        ("tags", matches!(&m.tags, Patch::Null)),
        ("metadata", matches!(&m.metadata, Patch::Null)),
        (
            "bypass_prompt_injection",
            matches!(&m.bypass_prompt_injection, Patch::Null),
        ),
    ] {
        if is_null {
            return Err(format!(
                "{field} does not accept null; use its explicit empty or false value"
            ));
        }
    }
    Ok(())
}

fn apply_nullable<T: Clone>(target: &mut Option<T>, patch: &Patch<T>) {
    match patch {
        Patch::Missing => {}
        Patch::Null => *target = None,
        Patch::Value(value) => *target = Some(value.clone()),
    }
}

fn apply_replacement<T: Clone>(target: &mut T, patch: &Patch<T>) {
    if let Patch::Value(value) = patch {
        *target = value.clone();
    }
}

/// Apply fields present in a validated mutation onto a record.
fn apply_key_mutation(rec: &mut KeyRecord, m: &KeyMutation) {
    apply_nullable(&mut rec.name, &m.name);
    apply_nullable(&mut rec.max_requests_per_minute, &m.max_requests_per_minute);
    apply_nullable(&mut rec.max_tokens_per_minute, &m.max_tokens_per_minute);
    apply_nullable(&mut rec.priority, &m.priority);
    if !matches!(&m.max_budget_tokens, Patch::Missing)
        || !matches!(&m.max_budget_usd, Patch::Missing)
    {
        let mut b = rec.budget.clone().unwrap_or_default();
        apply_nullable(&mut b.max_tokens, &m.max_budget_tokens);
        apply_nullable(&mut b.max_cost_usd, &m.max_budget_usd);
        rec.budget = if b.max_tokens.is_none() && b.max_cost_usd.is_none() {
            None
        } else {
            Some(b)
        };
    }
    apply_replacement(&mut rec.allowed_models, &m.allowed_models);
    apply_replacement(&mut rec.blocked_models, &m.blocked_models);
    apply_replacement(&mut rec.allowed_providers, &m.allowed_providers);
    apply_replacement(&mut rec.blocked_providers, &m.blocked_providers);
    apply_replacement(&mut rec.require_pii_redaction, &m.require_pii_redaction);
    apply_replacement(&mut rec.principal_selectors, &m.principal_selectors);
    apply_nullable(&mut rec.route_to_model, &m.route_to_model);
    apply_nullable(&mut rec.allowed_tools, &m.allowed_tools);
    apply_replacement(&mut rec.inject_tools, &m.inject_tools);
    apply_nullable(&mut rec.inject_mcp, &m.inject_mcp);
    if let Patch::Value(value) = &m.bypass_prompt_injection {
        rec.bypass_prompt_injection = *value;
    }
    apply_nullable(&mut rec.project, &m.project);
    apply_nullable(&mut rec.user, &m.user);
    apply_replacement(&mut rec.tags, &m.tags);
    apply_replacement(&mut rec.metadata, &m.metadata);
    apply_nullable(&mut rec.tenant_id, &m.tenant);
    apply_nullable(&mut rec.expires_at, &m.expires_at);
}

fn create_key(body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let m: KeyMutation = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Err(e) = validate_key_mutation(&m) {
        return bad_request(&e);
    }
    if m.expected_revision.is_some() {
        return bad_request("expected_revision is only valid for key mutation");
    }
    let minted = plane.crypto().mint_key();
    let now = Utc::now();
    let mut rec = KeyRecord::new(minted.key_id.clone(), minted.secret_hash.clone(), now);
    apply_key_mutation(&mut rec, &m);

    let store = plane.cache().store().clone();
    let put = rec.clone();
    if let Err(e) = block_on_keystore(async move { store.put_key(put).await }) {
        return internal_error(&format!("store key: {e:#}"));
    }
    invalidate(&plane, &minted.key_id);
    audit_mutation("create", "key", &minted.key_id);

    created(json!({
        // The plaintext token is shown exactly once and never stored.
        "token": minted.token,
        "key": KeyView::from(&rec),
    }))
}

fn list_keys() -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let store = plane.cache().store().clone();
    match block_on_keystore(async move { store.list_keys().await }) {
        Ok(keys) => {
            let views: Vec<KeyView> = keys.iter().map(KeyView::from).collect();
            ok(json!({ "keys": views }))
        }
        Err(e) => internal_error(&format!("list keys: {e:#}")),
    }
}

fn get_key(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    match load_key(&plane, id) {
        Ok(Some(rec)) => ok(json!({ "key": KeyView::from(&rec) })),
        Ok(None) => not_found("key not found"),
        Err(e) => internal_error(&e),
    }
}

fn get_key_policy_schema() -> Resp {
    ok(json!({
        "schema_version":
            sbproxy_ai::effective_key_policy::EFFECTIVE_KEY_POLICY_SCHEMA_VERSION,
        "fields": sbproxy_ai::effective_key_policy::PolicyField::descriptors(),
    }))
}

const MAX_POLICY_PREVIEW_BODY_BYTES: usize = 64 * 1024;
const MAX_POLICY_PREVIEW_ITEMS: usize = 128;
const MAX_POLICY_PREVIEW_STRING_BYTES: usize = 512;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyPreviewSample {
    origin_tenant_id: Option<String>,
    at: Option<DateTime<Utc>>,
    model: Option<String>,
    provider: Option<String>,
    tools: Option<Vec<String>>,
    principal: Option<PolicyPreviewPrincipal>,
    active_pii_rules: Option<Vec<String>>,
    prompt_injection_detected: Option<bool>,
    estimated_tokens: Option<u64>,
    estimated_micro_usd: Option<u64>,
    usage: Option<PolicyPreviewUsage>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyPreviewPrincipal {
    virtual_key: Option<String>,
    team: Option<String>,
    project: Option<String>,
    user: Option<String>,
    roles: Vec<String>,
    claims: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyPreviewUsage {
    requests_in_window: u64,
    tokens_in_window: u64,
    total_tokens: u64,
    total_micro_usd: u64,
}

#[derive(Debug, Serialize)]
struct PreviewLifecycleDecision {
    allowed: bool,
    reason_code: &'static str,
    status: sbproxy_ai::effective_key_policy::EffectiveKeyStatus,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct PreviewTenantDecision {
    allowed: bool,
    reason_code: &'static str,
    origin_tenant_id: String,
    effective_tenant_id: String,
}

#[derive(Debug, Serialize)]
struct PreviewModelDecision {
    allowed: bool,
    reason_code: &'static str,
    requested: Option<String>,
    effective: Option<String>,
    routed: bool,
}

#[derive(Debug, Serialize)]
struct PreviewProviderDecision {
    allowed: bool,
    reason_code: &'static str,
    provider: Option<String>,
}

#[derive(Debug, Serialize)]
struct PreviewToolsDecision {
    allowed: bool,
    reason_code: &'static str,
    requested_count: usize,
    denied: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PreviewPrincipalDecision {
    allowed: bool,
    reason_code: &'static str,
}

#[derive(Debug, Serialize)]
struct PreviewCounterDecision {
    allowed: bool,
    limit: Option<u64>,
    current: u64,
    requested: u64,
    projected: Option<u64>,
    reason_code: &'static str,
}

#[derive(Debug, Serialize)]
struct PreviewRateLimitDecision {
    allowed: bool,
    reason_code: &'static str,
    requests_per_minute: PreviewCounterDecision,
    tokens_per_minute: PreviewCounterDecision,
}

#[derive(Debug, Serialize)]
struct PreviewBudgetDecision {
    allowed: bool,
    reason_code: &'static str,
    tokens: PreviewCounterDecision,
    micro_usd: PreviewCounterDecision,
}

#[derive(Debug, Serialize)]
struct PreviewPriorityDecision {
    allowed: bool,
    reason_code: &'static str,
    lane: &'static str,
}

#[derive(Debug, Serialize)]
struct PreviewPiiDecision {
    allowed: bool,
    reason_code: &'static str,
    required: Vec<String>,
    missing: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PreviewPromptInjectionDecision {
    allowed: bool,
    reason_code: &'static str,
    mode: &'static str,
    detected: Option<bool>,
}

#[derive(Debug, Serialize)]
struct PreviewGuardrailDecision {
    allowed: bool,
    reason_code: &'static str,
    pii: PreviewPiiDecision,
    prompt_injection: PreviewPromptInjectionDecision,
}

#[derive(Debug, Serialize)]
struct EffectivePolicyPreviewDecisions {
    allowed: bool,
    lifecycle: PreviewLifecycleDecision,
    tenant: PreviewTenantDecision,
    model: PreviewModelDecision,
    provider: PreviewProviderDecision,
    tools: PreviewToolsDecision,
    principal: PreviewPrincipalDecision,
    rate_limits: PreviewRateLimitDecision,
    budget: PreviewBudgetDecision,
    priority: PreviewPriorityDecision,
    guardrails: PreviewGuardrailDecision,
}

struct PolicyPreviewLimits {
    requests_per_minute: Option<u64>,
    tokens_per_minute: Option<u64>,
    total_tokens: Option<u64>,
    total_micro_usd: Option<u64>,
}

fn preview_effective_key_policy(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(plane) => plane,
        Err(response) => return response,
    };
    let record = match load_key(&plane, id) {
        Ok(Some(record)) => record,
        Ok(None) => return not_found("key not found"),
        Err(error) => return internal_error(&error),
    };
    let sample = match parse_policy_preview_sample(body) {
        Ok(sample) => sample,
        Err(response) => return response,
    };
    let origin_tenant_id = sample
        .origin_tenant_id
        .clone()
        .or_else(|| record.tenant_id.clone())
        .unwrap_or_else(|| "__default__".to_string());
    let (tenant_allowed, tenant_reason_code) = match record.tenant_id.as_deref() {
        None => (true, "inherited"),
        Some(tenant) if tenant == origin_tenant_id => (true, "match"),
        Some(_) => (false, "mismatch"),
    };
    // A cross-tenant sample is a normal deny result. Lower the displayed
    // canonical policy in its owning tenant so the preview can still return
    // the complete secret-free contract without weakening request-path checks.
    let policy_origin = if tenant_allowed {
        origin_tenant_id.as_str()
    } else {
        record
            .tenant_id
            .as_deref()
            .unwrap_or(origin_tenant_id.as_str())
    };
    let policy = match crate::key_policy::key_record_to_effective_policy(&record, policy_origin) {
        Ok(policy) => policy,
        Err(error) => {
            tracing::warn!(
                reason = error.safe_reason(),
                "admin key policy preview: stored policy rejected"
            );
            return internal_error("stored key policy is invalid");
        }
    };
    let policy_version = match policy.policy_version() {
        Ok(version) => version,
        Err(_) => return internal_error("effective policy serialization failed"),
    };
    let decisions = match evaluate_policy_preview(
        &record,
        &policy,
        sample,
        origin_tenant_id,
        tenant_allowed,
        tenant_reason_code,
    ) {
        Ok(decisions) => decisions,
        Err(error) => return internal_error(error),
    };

    ok(json!({
        "effective_policy": policy,
        "policy_version": policy_version,
        "decisions": decisions,
    }))
}

fn parse_policy_preview_sample(body: Option<&str>) -> Result<PolicyPreviewSample, Resp> {
    let body = body.unwrap_or("");
    if body.len() > MAX_POLICY_PREVIEW_BODY_BYTES {
        return Err(bad_request("policy preview sample body is too large"));
    }
    let sample = if body.is_empty() {
        PolicyPreviewSample::default()
    } else {
        serde_json::from_str::<PolicyPreviewSample>(body)
            .map_err(|_| bad_request("invalid policy preview sample"))?
    };
    validate_policy_preview_sample(&sample).map_err(|error| bad_request(error))?;
    Ok(sample)
}

fn validate_policy_preview_sample(sample: &PolicyPreviewSample) -> Result<(), &'static str> {
    for value in [
        sample.origin_tenant_id.as_deref(),
        sample.model.as_deref(),
        sample.provider.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_policy_preview_string(value)?;
    }
    for values in [sample.tools.as_deref(), sample.active_pii_rules.as_deref()]
        .into_iter()
        .flatten()
    {
        validate_policy_preview_strings(values)?;
    }
    if let Some(principal) = sample.principal.as_ref() {
        for value in [
            principal.virtual_key.as_deref(),
            principal.team.as_deref(),
            principal.project.as_deref(),
            principal.user.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_policy_preview_string(value)?;
        }
        validate_policy_preview_strings(&principal.roles)?;
        if principal.claims.len() > MAX_POLICY_PREVIEW_ITEMS {
            return Err("policy preview sample has too many claim fields");
        }
        for name in principal.claims.keys() {
            validate_policy_preview_string(name)?;
        }
    }
    Ok(())
}

fn validate_policy_preview_strings(values: &[String]) -> Result<(), &'static str> {
    if values.len() > MAX_POLICY_PREVIEW_ITEMS {
        return Err("policy preview sample list is too large");
    }
    for value in values {
        validate_policy_preview_string(value)?;
    }
    Ok(())
}

fn validate_policy_preview_string(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > MAX_POLICY_PREVIEW_STRING_BYTES {
        return Err("policy preview sample string has an invalid length");
    }
    Ok(())
}

fn evaluate_policy_preview(
    record: &KeyRecord,
    policy: &sbproxy_ai::effective_key_policy::EffectiveKeyPolicy,
    sample: PolicyPreviewSample,
    origin_tenant_id: String,
    tenant_allowed: bool,
    tenant_reason_code: &'static str,
) -> Result<EffectivePolicyPreviewDecisions, &'static str> {
    use sbproxy_ai::effective_key_policy::EffectiveKeyStatus;

    let at = sample.at.unwrap_or_else(Utc::now);
    let lifecycle_reason_code = match policy.status {
        EffectiveKeyStatus::Revoked => "revoked",
        EffectiveKeyStatus::Blocked => "blocked",
        EffectiveKeyStatus::Active if policy.expires_at.is_some_and(|expires| expires <= at) => {
            "expired"
        }
        EffectiveKeyStatus::Active => "active",
    };
    let lifecycle = PreviewLifecycleDecision {
        allowed: lifecycle_reason_code == "active",
        reason_code: lifecycle_reason_code,
        status: policy.status,
        expires_at: policy.expires_at,
    };
    let tenant = PreviewTenantDecision {
        allowed: tenant_allowed,
        reason_code: tenant_reason_code,
        origin_tenant_id: origin_tenant_id.clone(),
        effective_tenant_id: policy.tenant_id.clone(),
    };

    let requested_model = sample.model.clone();
    let effective_model = policy
        .route_to_model
        .clone()
        .or_else(|| requested_model.clone());
    let routed = policy.route_to_model.is_some();
    let (model_allowed, model_reason_code) = match effective_model.as_deref() {
        None => (true, "not_sampled"),
        Some(model) if policy.blocked_models.iter().any(|blocked| blocked == model) => {
            (false, "blocked")
        }
        Some(model)
            if !policy.allowed_models.is_empty()
                && !policy.allowed_models.iter().any(|allowed| allowed == model) =>
        {
            (false, "not_allowed")
        }
        Some(_) => (true, "allowed"),
    };
    let model = PreviewModelDecision {
        allowed: model_allowed,
        reason_code: model_reason_code,
        requested: requested_model,
        effective: effective_model,
        routed,
    };

    let (provider_allowed, provider_reason_code) = match sample.provider.as_deref() {
        None => (true, "not_sampled"),
        Some(provider)
            if policy
                .blocked_providers
                .iter()
                .any(|blocked| blocked == provider) =>
        {
            (false, "blocked")
        }
        Some(provider)
            if !policy.allowed_providers.is_empty()
                && !policy
                    .allowed_providers
                    .iter()
                    .any(|allowed| allowed == provider) =>
        {
            (false, "not_allowed")
        }
        Some(_) => (true, "allowed"),
    };
    let provider = PreviewProviderDecision {
        allowed: provider_allowed,
        reason_code: provider_reason_code,
        provider: sample.provider,
    };

    let (requested_count, denied, tools_reason_code) = match sample.tools {
        None => (0, Vec::new(), "not_sampled"),
        Some(tools) => {
            let denied = tools
                .iter()
                .filter(|tool| !policy.is_tool_allowed(tool))
                .cloned()
                .collect::<Vec<_>>();
            let reason = if denied.is_empty() {
                if policy.allowed_tools.is_none() {
                    "unrestricted"
                } else {
                    "allowed"
                }
            } else {
                "not_allowed"
            };
            (tools.len(), denied, reason)
        }
    };
    let tools = PreviewToolsDecision {
        allowed: denied.is_empty(),
        reason_code: tools_reason_code,
        requested_count,
        denied,
    };

    let principal = match sample.principal {
        None if policy.principal_selectors.is_empty() => PreviewPrincipalDecision {
            allowed: true,
            reason_code: "unrestricted",
        },
        None => PreviewPrincipalDecision {
            allowed: true,
            reason_code: "not_sampled",
        },
        Some(principal) => {
            let principal = policy_preview_principal(principal, &origin_tenant_id);
            let allowed = policy.matches_principal(&principal);
            PreviewPrincipalDecision {
                allowed,
                reason_code: if allowed { "matched" } else { "not_matched" },
            }
        }
    };

    let usage = sample.usage.unwrap_or_default();
    let estimated_tokens = sample.estimated_tokens.unwrap_or(0);
    let estimated_micro_usd = sample.estimated_micro_usd.unwrap_or(0);
    let limits = policy_preview_limits(record)?;
    let requests_per_minute =
        preview_counter(limits.requests_per_minute, usage.requests_in_window, 1);
    let tokens_per_minute = preview_counter(
        limits.tokens_per_minute,
        usage.tokens_in_window,
        estimated_tokens,
    );
    let rate_limits_allowed = requests_per_minute.allowed && tokens_per_minute.allowed;
    let rate_limits = PreviewRateLimitDecision {
        allowed: rate_limits_allowed,
        reason_code: if rate_limits_allowed {
            "within_limits"
        } else {
            "limit_exceeded"
        },
        requests_per_minute,
        tokens_per_minute,
    };
    let budget_tokens = preview_counter(limits.total_tokens, usage.total_tokens, estimated_tokens);
    let budget_micro_usd = preview_counter(
        limits.total_micro_usd,
        usage.total_micro_usd,
        estimated_micro_usd,
    );
    let budget_allowed = budget_tokens.allowed && budget_micro_usd.allowed;
    let budget = PreviewBudgetDecision {
        allowed: budget_allowed,
        reason_code: if budget_allowed {
            "within_limits"
        } else {
            "limit_exceeded"
        },
        tokens: budget_tokens,
        micro_usd: budget_micro_usd,
    };
    let priority = PreviewPriorityDecision {
        allowed: true,
        reason_code: "selected_lane",
        lane: policy.priority.as_str(),
    };

    let pii = match sample.active_pii_rules {
        None => PreviewPiiDecision {
            allowed: true,
            reason_code: "not_sampled",
            required: policy.require_pii_redaction.clone(),
            missing: Vec::new(),
        },
        Some(active) => {
            let missing = policy
                .require_pii_redaction
                .iter()
                .filter(|required| !active.iter().any(|rule| rule == *required))
                .cloned()
                .collect::<Vec<_>>();
            PreviewPiiDecision {
                allowed: missing.is_empty(),
                reason_code: if missing.is_empty() {
                    "satisfied"
                } else {
                    "missing_required_rules"
                },
                required: policy.require_pii_redaction.clone(),
                missing,
            }
        }
    };
    let prompt_injection = if policy.bypass_prompt_injection {
        PreviewPromptInjectionDecision {
            allowed: true,
            reason_code: "bypassed",
            mode: "bypass",
            detected: sample.prompt_injection_detected,
        }
    } else {
        let detected = sample.prompt_injection_detected;
        PreviewPromptInjectionDecision {
            allowed: detected != Some(true),
            reason_code: match detected {
                Some(true) => "detected",
                Some(false) => "not_detected",
                None => "not_sampled",
            },
            mode: "enforce",
            detected,
        }
    };
    let guardrails_allowed = pii.allowed && prompt_injection.allowed;
    let guardrails = PreviewGuardrailDecision {
        allowed: guardrails_allowed,
        reason_code: if guardrails_allowed {
            "satisfied"
        } else {
            "guardrail_denied"
        },
        pii,
        prompt_injection,
    };

    let allowed = lifecycle.allowed
        && tenant.allowed
        && model.allowed
        && provider.allowed
        && tools.allowed
        && principal.allowed
        && rate_limits.allowed
        && budget.allowed
        && priority.allowed
        && guardrails.allowed;
    Ok(EffectivePolicyPreviewDecisions {
        allowed,
        lifecycle,
        tenant,
        model,
        provider,
        tools,
        principal,
        rate_limits,
        budget,
        priority,
        guardrails,
    })
}

fn policy_preview_limits(record: &KeyRecord) -> Result<PolicyPreviewLimits, &'static str> {
    let total_micro_usd = record
        .budget
        .as_ref()
        .and_then(|budget| budget.max_cost_usd)
        .map(policy_preview_usd_to_micro_usd)
        .transpose()?;
    Ok(PolicyPreviewLimits {
        requests_per_minute: record.max_requests_per_minute,
        tokens_per_minute: record.max_tokens_per_minute,
        total_tokens: record.budget.as_ref().and_then(|budget| budget.max_tokens),
        total_micro_usd,
    })
}

fn policy_preview_usd_to_micro_usd(value: f64) -> Result<u64, &'static str> {
    const MICRO_USD_PER_USD: f64 = 1_000_000.0;

    if !value.is_finite() || value < 0.0 {
        return Err("stored max_budget_usd is not a finite non-negative number");
    }
    let rounded = (value * MICRO_USD_PER_USD).round();
    if !rounded.is_finite() || rounded < 0.0 || rounded >= u64::MAX as f64 {
        return Err("stored max_budget_usd cannot be represented as integer micro-USD");
    }
    Ok(rounded as u64)
}

fn policy_preview_principal(
    sample: PolicyPreviewPrincipal,
    tenant_id: &str,
) -> sbproxy_plugin::Principal {
    let mut principal = sbproxy_plugin::Principal::anonymous_for(tenant_id.into());
    principal.virtual_key = sample
        .virtual_key
        .map(|name| sbproxy_plugin::VirtualKeyRef {
            name,
            allowed_providers: Vec::new(),
        });
    principal.attrs.team = sample.team;
    principal.attrs.project = sample.project;
    principal.attrs.user = sample.user;
    principal.attrs.roles = sample.roles;
    principal.attrs.claims = if sample.claims.is_empty() {
        None
    } else {
        Some(sample.claims)
    };
    principal
}

fn preview_counter(limit: Option<u64>, current: u64, requested: u64) -> PreviewCounterDecision {
    let projected = current.checked_add(requested);
    let allowed = projected.is_some_and(|projected| limit.is_none_or(|limit| projected <= limit));
    let reason_code = match (projected, limit) {
        (None, _) => "overflow",
        (Some(_), None) => "unlimited",
        (Some(projected), Some(limit)) if projected <= limit => "within_limit",
        (Some(_), Some(_)) => "limit_exceeded",
    };
    PreviewCounterDecision {
        allowed,
        limit,
        current,
        requested,
        projected,
        reason_code,
    }
}

fn get_key_usage(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(plane) => plane,
        Err(response) => return response,
    };
    let record = match load_key(&plane, id) {
        Ok(Some(record)) => record,
        Ok(None) => return not_found("key not found"),
        Err(error) => return internal_error(&error),
    };
    let limits = match governance_limits(&record) {
        Ok(limits) => limits,
        Err(error) => return internal_error(error),
    };
    let snapshot_key = SnapshotKey {
        key_id: record.key_id,
        policy_revision: record.policy_revision,
        limits,
    };
    let store = plane.governance_store();
    match block_on_keystore(async move { store.snapshot(snapshot_key).await }) {
        Ok(snapshot) => ok(json!({ "usage": snapshot })),
        Err(GovernanceError::BackendUnavailable { .. }) => governance_backend_unavailable(),
        Err(error) => internal_error(&format!("governance snapshot: {error}")),
    }
}

fn governance_limits(record: &KeyRecord) -> Result<GovernanceLimits, &'static str> {
    let total_micro_usd = record
        .budget
        .as_ref()
        .and_then(|budget| budget.max_cost_usd)
        .map(usd_to_micro_usd)
        .transpose()?;

    Ok(GovernanceLimits {
        requests_per_window: record.max_requests_per_minute,
        tokens_per_window: record.max_tokens_per_minute,
        total_tokens: record.budget.as_ref().and_then(|budget| budget.max_tokens),
        total_micro_usd,
        window_millis: 60_000,
    })
}

fn usd_to_micro_usd(value: f64) -> Result<u64, &'static str> {
    const MICRO_USD_PER_USD: f64 = 1_000_000.0;

    if !value.is_finite() || value < 0.0 {
        return Err("stored max_budget_usd is not a finite non-negative number");
    }
    let rounded = (value * MICRO_USD_PER_USD).round();
    if !rounded.is_finite() || rounded < 0.0 || rounded >= u64::MAX as f64 {
        return Err("stored max_budget_usd cannot be represented as integer micro-USD");
    }
    Ok(rounded as u64)
}

fn update_key(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let m: KeyMutation = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Err(e) = validate_key_mutation(&m) {
        return bad_request(&e);
    }
    let expected_revision = match m.expected_revision {
        Some(revision) => revision,
        None => return bad_request("expected_revision is required"),
    };
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    if rec.policy_revision != expected_revision {
        return revision_conflict(id, expected_revision, rec.policy_revision);
    }
    if rec.status == RecordStatus::Revoked {
        return terminal_key(id, rec.policy_revision);
    }
    apply_key_mutation(&mut rec, &m);
    rec.updated_at = Utc::now();
    let rec = match store_key_if_revision(&plane, rec, expected_revision) {
        Ok(rec) => rec,
        Err(response) => return response,
    };
    invalidate(&plane, id);
    audit_mutation("update", "key", id);
    ok(json!({ "key": KeyView::from(&rec) }))
}

fn delete_key(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let store = plane.cache().store().clone();
    let owned = id.to_string();
    if let Err(e) = block_on_keystore(async move { store.delete_key(&owned).await }) {
        return internal_error(&format!("delete key: {e:#}"));
    }
    invalidate(&plane, id);
    audit_mutation("delete", "key", id);
    ok(json!({ "deleted": true, "key_id": id }))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RevisionRequest {
    expected_revision: Option<u64>,
}

fn set_key_status(id: &str, status: RecordStatus, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let request: RevisionRequest = match parse_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if request.expected_revision == Some(0) {
        return bad_request("expected_revision must be at least 1");
    }
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    let expected_revision = request.expected_revision.unwrap_or(rec.policy_revision);
    if rec.policy_revision != expected_revision {
        return revision_conflict(id, expected_revision, rec.policy_revision);
    }
    if rec.status == RecordStatus::Revoked {
        return terminal_key(id, rec.policy_revision);
    }
    rec.status = status;
    rec.updated_at = Utc::now();
    let rec = match store_key_if_revision(&plane, rec, expected_revision) {
        Ok(rec) => rec,
        Err(response) => return response,
    };
    invalidate(&plane, id);
    audit_mutation(status_verb(status), "key", id);
    ok(json!({ "key": KeyView::from(&rec) }))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RotateRequest {
    /// Optional optimistic revision. Omitted actions use the server-read value.
    expected_revision: Option<u64>,
    /// Seconds the prior secret keeps working alongside the new one.
    grace_secs: Option<i64>,
}

/// Default rotation grace window: one hour. Matches the transition windows used
/// by hosted gateways so a client fleet can pick up the new token before the old
/// one stops working.
const DEFAULT_ROTATE_GRACE_SECS: i64 = 3600;

/// WOR-1554: rotate a key with a grace-period dual-key. Mints a fresh secret for
/// the same key_id, keeps the prior hash valid until the grace window expires,
/// and returns the new plaintext token once. Both tokens authenticate during
/// the window (the resolve path accepts the prior hash while it is unexpired);
/// after it, only the new token works, with no extra cleanup needed.
fn rotate_key(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let req: RotateRequest = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if req.expected_revision == Some(0) {
        return bad_request("expected_revision must be at least 1");
    }
    let grace_secs = req.grace_secs.unwrap_or(DEFAULT_ROTATE_GRACE_SECS).max(0);
    let mut rec = match load_key(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("key not found"),
        Err(e) => return internal_error(&e),
    };
    let expected_revision = req.expected_revision.unwrap_or(rec.policy_revision);
    if rec.policy_revision != expected_revision {
        return revision_conflict(id, expected_revision, rec.policy_revision);
    }
    if rec.status == RecordStatus::Revoked {
        return terminal_key(id, rec.policy_revision);
    }
    let minted = plane.crypto().mint_secret();
    let now = Utc::now();
    // The current secret becomes the graced prior secret.
    rec.prev_secret_hash = Some(rec.secret_hash.clone());
    rec.prev_hash_expires_at = Some(now + chrono::Duration::seconds(grace_secs));
    rec.secret_hash = minted.secret_hash;
    rec.updated_at = now;
    let rec = match store_key_if_revision(&plane, rec, expected_revision) {
        Ok(rec) => rec,
        Err(response) => return response,
    };
    invalidate(&plane, id);
    audit_mutation("rotate", "key", id);

    let token = format!("sk-{}-{}", id, minted.secret);
    ok(json!({
        "token": token,
        "grace_expires_at": rec.prev_hash_expires_at,
        "key": KeyView::from(&rec),
    }))
}

// --- Credential handlers ---

#[derive(Debug, Default, Deserialize)]
struct CredentialCreate {
    /// Optional stable id; generated when omitted.
    id: Option<String>,
    name: Option<String>,
    provider: Option<String>,
    kind: Option<String>,
    /// A secret reference resolved by the vault at use (`vault://`, `awssm://`).
    vault_ref: Option<String>,
    /// A plaintext secret to envelope-encrypt at rest (needs a master key).
    secret: Option<String>,
    tenant: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CredentialUpdate {
    name: Option<String>,
    provider: Option<String>,
    kind: Option<String>,
    vault_ref: Option<String>,
    secret: Option<String>,
    tenant: Option<String>,
}

fn create_credential(body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let c: CredentialCreate = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let id =
        c.id.clone()
            .unwrap_or_else(sbproxy_keystore::crypto::random_id);
    let material = match build_material(&plane, &id, c.vault_ref.as_deref(), c.secret.as_deref()) {
        Ok(m) => m,
        Err(e) => return bad_request(&e),
    };
    let now = Utc::now();
    let rec = CredentialRecord {
        id: id.clone(),
        name: c.name.unwrap_or_else(|| id.clone()),
        provider: c.provider,
        kind: c.kind.unwrap_or_else(|| "ai_provider".to_string()),
        material,
        status: RecordStatus::Active,
        tenant_id: c.tenant,
        metadata: Default::default(),
        created_at: now,
        updated_at: now,
        source: sbproxy_keystore::record::RecordSource::Api,
    };
    if let Err(e) = store_credential(&plane, rec.clone()) {
        return internal_error(&e);
    }
    invalidate(&plane, &id);
    audit_mutation("create", "credential", &id);
    created(json!({ "credential": CredentialView::from(&rec) }))
}

fn list_credentials() -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let store = plane.cache().store().clone();
    match block_on_keystore(async move { store.list_credentials().await }) {
        Ok(creds) => {
            let views: Vec<CredentialView> = creds.iter().map(CredentialView::from).collect();
            ok(json!({ "credentials": views }))
        }
        Err(e) => internal_error(&format!("list credentials: {e:#}")),
    }
}

fn get_credential(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    match load_credential(&plane, id) {
        Ok(Some(rec)) => ok(json!({ "credential": CredentialView::from(&rec) })),
        Ok(None) => not_found("credential not found"),
        Err(e) => internal_error(&e),
    }
}

fn update_credential(id: &str, body: Option<&str>) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let c: CredentialUpdate = match parse_body(body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut rec = match load_credential(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("credential not found"),
        Err(e) => return internal_error(&e),
    };
    if let Some(v) = c.name {
        rec.name = v;
    }
    if c.provider.is_some() {
        rec.provider = c.provider;
    }
    if let Some(v) = c.kind {
        rec.kind = v;
    }
    if c.tenant.is_some() {
        rec.tenant_id = c.tenant;
    }
    if c.vault_ref.is_some() || c.secret.is_some() {
        match build_material(&plane, id, c.vault_ref.as_deref(), c.secret.as_deref()) {
            Ok(m) => rec.material = m,
            Err(e) => return bad_request(&e),
        }
    }
    rec.updated_at = Utc::now();
    if let Err(e) = store_credential(&plane, rec.clone()) {
        return internal_error(&e);
    }
    invalidate(&plane, id);
    audit_mutation("update", "credential", id);
    ok(json!({ "credential": CredentialView::from(&rec) }))
}

fn delete_credential(id: &str) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let store = plane.cache().store().clone();
    let owned = id.to_string();
    if let Err(e) = block_on_keystore(async move { store.delete_credential(&owned).await }) {
        return internal_error(&format!("delete credential: {e:#}"));
    }
    invalidate(&plane, id);
    audit_mutation("delete", "credential", id);
    ok(json!({ "deleted": true, "id": id }))
}

fn set_credential_status(id: &str, status: RecordStatus) -> Resp {
    let plane = match plane_or_err() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut rec = match load_credential(&plane, id) {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("credential not found"),
        Err(e) => return internal_error(&e),
    };
    rec.status = status;
    rec.updated_at = Utc::now();
    if let Err(e) = store_credential(&plane, rec.clone()) {
        return internal_error(&e);
    }
    invalidate(&plane, id);
    audit_mutation(status_verb(status), "credential", id);
    ok(json!({ "credential": CredentialView::from(&rec) }))
}

/// Build credential material from the request, preferring a vault reference.
fn build_material(
    plane: &KeyPlane,
    id: &str,
    vault_ref: Option<&str>,
    secret: Option<&str>,
) -> Result<CredentialMaterial, String> {
    if let Some(reference) = vault_ref {
        Ok(CredentialMaterial::VaultRef {
            reference: reference.to_string(),
        })
    } else if let Some(secret) = secret {
        let envelope = plane
            .crypto()
            .seal(id, secret.as_bytes())
            .map_err(|e| format!("seal credential: {e:#}"))?;
        Ok(CredentialMaterial::Envelope { envelope })
    } else {
        Err("credential requires either vault_ref or secret".to_string())
    }
}

// --- Response DTOs (never carry secrets) ---

#[derive(Serialize)]
struct KeyView {
    key_id: String,
    policy_revision: u64,
    /// Digest of the canonical secret-free effective policy when the record
    /// owns a tenant.
    ///
    /// Tenantless records inherit the request origin, so they have no single
    /// runtime digest. Their origin-scoped digest is available from policy
    /// preview. `None` also keeps malformed legacy records listable without
    /// pretending they have a request-enforceable policy.
    policy_digest: Option<String>,
    name: Option<String>,
    status: RecordStatus,
    max_requests_per_minute: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens_per_minute: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<String>,
    budget: Option<RecordBudget>,
    allowed_models: Vec<String>,
    blocked_models: Vec<String>,
    allowed_providers: Vec<String>,
    blocked_providers: Vec<String>,
    allowed_tools: Option<Vec<String>>,
    require_pii_redaction: Vec<String>,
    principal_selectors: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_to_model: Option<String>,
    inject_tools: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inject_mcp: Option<serde_json::Value>,
    bypass_prompt_injection: bool,
    project: Option<String>,
    user: Option<String>,
    tags: Vec<String>,
    metadata: std::collections::BTreeMap<String, String>,
    tenant_id: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    source: sbproxy_keystore::record::RecordSource,
    /// True while a rotation grace window is open (the prior secret still works).
    rotation_pending: bool,
}

impl From<&KeyRecord> for KeyView {
    fn from(r: &KeyRecord) -> Self {
        Self {
            key_id: r.key_id.clone(),
            policy_revision: r.policy_revision,
            policy_digest: key_record_policy_digest(r),
            name: r.name.clone(),
            status: r.status,
            max_requests_per_minute: r.max_requests_per_minute,
            max_tokens_per_minute: r.max_tokens_per_minute,
            priority: r.priority.clone(),
            budget: r.budget.clone(),
            allowed_models: r.allowed_models.clone(),
            blocked_models: r.blocked_models.clone(),
            allowed_providers: r.allowed_providers.clone(),
            blocked_providers: r.blocked_providers.clone(),
            allowed_tools: r.allowed_tools.clone(),
            require_pii_redaction: r.require_pii_redaction.clone(),
            principal_selectors: r.principal_selectors.clone(),
            route_to_model: r.route_to_model.clone(),
            inject_tools: r.inject_tools.clone(),
            inject_mcp: r.inject_mcp.clone(),
            bypass_prompt_injection: r.bypass_prompt_injection,
            project: r.project.clone(),
            user: r.user.clone(),
            tags: r.tags.clone(),
            metadata: r.metadata.clone(),
            tenant_id: r.tenant_id.clone(),
            expires_at: r.expires_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
            source: r.source,
            rotation_pending: r.prev_secret_hash.is_some(),
        }
    }
}

fn key_record_policy_digest(record: &KeyRecord) -> Option<String> {
    let policy_origin = record.tenant_id.as_deref()?;
    crate::key_policy::key_record_to_effective_policy(record, policy_origin)
        .ok()?
        .policy_digest()
        .ok()
}

#[derive(Serialize)]
struct CredentialView {
    id: String,
    name: String,
    provider: Option<String>,
    kind: String,
    status: RecordStatus,
    tenant_id: Option<String>,
    /// How the secret is held, without revealing it.
    storage: &'static str,
    /// The vault reference (only for vault-ref credentials; never a secret).
    vault_ref: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    source: sbproxy_keystore::record::RecordSource,
}

impl From<&CredentialRecord> for CredentialView {
    fn from(r: &CredentialRecord) -> Self {
        let (storage, vault_ref) = match &r.material {
            CredentialMaterial::VaultRef { reference } => ("vault_ref", Some(reference.clone())),
            CredentialMaterial::Envelope { .. } => ("encrypted", None),
            CredentialMaterial::Plaintext { .. } => ("plaintext", None),
        };
        Self {
            id: r.id.clone(),
            name: r.name.clone(),
            provider: r.provider.clone(),
            kind: r.kind.clone(),
            status: r.status,
            tenant_id: r.tenant_id.clone(),
            storage,
            vault_ref,
            created_at: r.created_at,
            updated_at: r.updated_at,
            source: r.source,
        }
    }
}

// --- Shared helpers ---

fn plane_or_err() -> Result<Arc<KeyPlane>, Resp> {
    current_key_plane().ok_or_else(|| {
        (
            409,
            "application/json",
            r#"{"error":"key_management is not enabled"}"#.to_string(),
        )
    })
}

fn load_key(plane: &KeyPlane, id: &str) -> Result<Option<KeyRecord>, String> {
    let store = plane.cache().store().clone();
    let owned = id.to_string();
    block_on_keystore(async move { store.get_key(&owned).await }).map_err(|e| format!("{e:#}"))
}

fn store_key_if_revision(
    plane: &KeyPlane,
    rec: KeyRecord,
    expected_revision: u64,
) -> Result<KeyRecord, Resp> {
    let store = plane.cache().store().clone();
    let key_id = rec.key_id.clone();
    match block_on_keystore(async move {
        store
            .put_key_if_revision(rec.clone(), expected_revision)
            .await
            .map(|result| (result, rec))
    }) {
        Ok((KeyPolicyCasResult::Applied { policy_revision }, mut stored)) => {
            stored.policy_revision = policy_revision;
            Ok(stored)
        }
        Ok((KeyPolicyCasResult::Conflict { actual_revision }, _)) => Err(revision_conflict(
            &key_id,
            expected_revision,
            actual_revision,
        )),
        Ok((KeyPolicyCasResult::NotFound, _)) => Err(not_found("key not found")),
        Ok((KeyPolicyCasResult::Unsupported, _)) => Err(atomic_mutation_unsupported()),
        Err(error) => Err(internal_error(&format!("store key mutation: {error:#}"))),
    }
}

fn load_credential(plane: &KeyPlane, id: &str) -> Result<Option<CredentialRecord>, String> {
    let store = plane.cache().store().clone();
    let owned = id.to_string();
    block_on_keystore(async move { store.get_credential(&owned).await })
        .map_err(|e| format!("{e:#}"))
}

fn store_credential(plane: &KeyPlane, rec: CredentialRecord) -> Result<(), String> {
    let store = plane.cache().store().clone();
    block_on_keystore(async move { store.put_credential(rec).await }).map_err(|e| format!("{e:#}"))
}

fn invalidate(plane: &KeyPlane, id: &str) {
    let cache = plane.cache().clone();
    let owned = id.to_string();
    block_on_keystore(async move { cache.invalidate(&owned).await });
}

fn status_verb(status: RecordStatus) -> &'static str {
    match status {
        RecordStatus::Active => "unblock",
        RecordStatus::Blocked => "block",
        RecordStatus::Revoked => "revoke",
    }
}

/// Emit an audit record for a key/credential mutation. Wired to the audit sink
/// in WOR-1557; here it stamps the structured event onto the tracing pipeline.
fn audit_mutation(op: &str, kind: &str, id: &str) {
    sbproxy_observe::KeyAuditEntry::new(op, kind, id).emit();
}

fn parse_body<T: for<'de> Deserialize<'de> + Default>(body: Option<&str>) -> Result<T, Resp> {
    match body {
        None | Some("") => Ok(T::default()),
        Some(b) => {
            serde_json::from_str(b).map_err(|e| bad_request(&format!("invalid JSON body: {e}")))
        }
    }
}

fn ok(value: serde_json::Value) -> Resp {
    (200, "application/json", value.to_string())
}

fn created(value: serde_json::Value) -> Resp {
    (201, "application/json", value.to_string())
}

fn bad_request(msg: &str) -> Resp {
    (400, "application/json", json!({ "error": msg }).to_string())
}

fn revision_conflict(key_id: &str, expected_revision: u64, current_revision: u64) -> Resp {
    (
        409,
        "application/json",
        json!({
            "error": "key policy revision conflict",
            "key_id": key_id,
            "expected_revision": expected_revision,
            "current_revision": current_revision,
        })
        .to_string(),
    )
}

fn terminal_key(key_id: &str, current_revision: u64) -> Resp {
    (
        409,
        "application/json",
        json!({
            "error": "revoked key is terminal",
            "key_id": key_id,
            "current_revision": current_revision,
        })
        .to_string(),
    )
}

fn atomic_mutation_unsupported() -> Resp {
    (
        409,
        "application/json",
        json!({
            "error": "configured key store does not support atomic key policy mutation",
        })
        .to_string(),
    )
}

fn not_found(msg: &str) -> Resp {
    (404, "application/json", json!({ "error": msg }).to_string())
}

fn method_not_allowed() -> Resp {
    (
        405,
        "application/json",
        r#"{"error":"method not allowed"}"#.to_string(),
    )
}

fn governance_backend_unavailable() -> Resp {
    (
        503,
        "application/json",
        r#"{"error":"governance backend unavailable"}"#.to_string(),
    )
}

fn internal_error(msg: &str) -> Resp {
    tracing::warn!(error = %msg, "admin key API: internal error");
    (
        500,
        "application/json",
        json!({ "error": "internal error" }).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use sbproxy_ai::governance::{
        CounterSnapshot, GovernanceBackendHealth, GovernanceBackendStatus, GovernanceConsistency,
        GovernanceError, GovernanceSnapshot, GovernanceStore, Release, ReleaseRequest, Reservation,
        ReserveRequest, SettleRequest, Settlement, SnapshotKey,
    };
    use sbproxy_keystore::crypto::KeyCrypto;
    use sbproxy_keystore::{KeyStore, MemoryKeyStore, TtlCache, TtlCacheConfig};

    struct RecordingGovernanceStore {
        snapshots: Mutex<Vec<SnapshotKey>>,
        unavailable: bool,
    }

    impl RecordingGovernanceStore {
        fn healthy() -> Self {
            Self {
                snapshots: Mutex::new(Vec::new()),
                unavailable: false,
            }
        }

        fn unavailable() -> Self {
            Self {
                snapshots: Mutex::new(Vec::new()),
                unavailable: true,
            }
        }

        fn snapshot_requests(&self) -> Vec<SnapshotKey> {
            self.snapshots.lock().clone()
        }

        fn backend_health(&self) -> GovernanceBackendHealth {
            GovernanceBackendHealth {
                backend: "redis".to_string(),
                consistency: GovernanceConsistency::Strict,
                status: if self.unavailable {
                    GovernanceBackendStatus::Unavailable
                } else {
                    GovernanceBackendStatus::Healthy
                },
                checked_at_millis: 1_700_000_000_000,
            }
        }
    }

    fn counter(
        limit: Option<u64>,
        used: u64,
        reserved: u64,
        reset_at_millis: Option<u64>,
    ) -> CounterSnapshot {
        CounterSnapshot {
            limit,
            used,
            reserved,
            remaining: limit.map(|value| value.saturating_sub(used.saturating_add(reserved))),
            reset_at_millis,
        }
    }

    #[async_trait]
    impl GovernanceStore for RecordingGovernanceStore {
        async fn reserve(&self, _request: ReserveRequest) -> Result<Reservation, GovernanceError> {
            Err(GovernanceError::BackendUnavailable { backend: "redis" })
        }

        async fn settle(&self, _request: SettleRequest) -> Result<Settlement, GovernanceError> {
            Err(GovernanceError::BackendUnavailable { backend: "redis" })
        }

        async fn release(&self, _request: ReleaseRequest) -> Result<Release, GovernanceError> {
            Err(GovernanceError::BackendUnavailable { backend: "redis" })
        }

        async fn snapshot(&self, key: SnapshotKey) -> Result<GovernanceSnapshot, GovernanceError> {
            self.snapshots.lock().push(key.clone());
            if self.unavailable {
                return Err(GovernanceError::BackendUnavailable { backend: "redis" });
            }

            Ok(GovernanceSnapshot {
                key_id: key.key_id,
                policy_revision: key.policy_revision,
                requests_per_window: counter(
                    key.limits.requests_per_window,
                    2,
                    1,
                    Some(1_700_000_040_000),
                ),
                tokens_per_window: counter(
                    key.limits.tokens_per_window,
                    100,
                    20,
                    Some(1_700_000_040_000),
                ),
                total_tokens: counter(key.limits.total_tokens, 200, 40, None),
                total_micro_usd: counter(key.limits.total_micro_usd, 3_000_000, 500_000, None),
                backend: self.backend_health(),
            })
        }

        async fn health(&self) -> GovernanceBackendHealth {
            self.backend_health()
        }
    }

    fn install_test_plane_with_governance(
        store: Arc<MemoryKeyStore>,
        governance_store: Arc<dyn GovernanceStore>,
    ) {
        let crypto = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let store: Arc<dyn KeyStore> = store;
        let cache = Arc::new(TtlCache::new(store, TtlCacheConfig::default()));
        let plane = Arc::new(crate::key_plane::KeyPlane::from_parts_with_governance(
            crypto,
            cache,
            false,
            false,
            None,
            sbproxy_config::KeyGovernanceConfig::default(),
            governance_store,
        ));
        crate::key_plane::install_key_plane(plane);
    }

    fn install_test_plane_with_store(store: Arc<MemoryKeyStore>) {
        let crypto = KeyCrypto::new(b"pepper".to_vec(), b"master".to_vec());
        let store: Arc<dyn KeyStore> = store;
        let cache = Arc::new(TtlCache::new(store, TtlCacheConfig::default()));
        let plane = Arc::new(crate::key_plane::KeyPlane::from_parts(
            crypto, cache, false, false, None,
        ));
        crate::key_plane::install_key_plane(plane);
    }

    fn install_test_plane() {
        install_test_plane_with_store(Arc::new(MemoryKeyStore::new()));
    }

    fn parse(resp: &Resp) -> serde_json::Value {
        serde_json::from_str(&resp.2).unwrap()
    }

    #[test]
    fn key_lifecycle_via_dispatch() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        // Create: returns the one-time token and no hash.
        let resp = dispatch(
            "POST",
            "/admin/keys",
            Some(r#"{"name":"ci","max_requests_per_minute":60}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 201);
        let v = parse(&resp);
        let token = v["token"].as_str().unwrap().to_string();
        assert!(token.starts_with("sk-"));
        let key_id = v["key"]["key_id"].as_str().unwrap().to_string();
        assert_eq!(v["key"]["policy_revision"], 1);
        assert!(
            !resp.2.contains("secret_hash"),
            "response must not leak the hash"
        );

        // List + get.
        assert!(dispatch("GET", "/admin/keys", None)
            .unwrap()
            .2
            .contains(&key_id));
        assert_eq!(
            dispatch("GET", &format!("/admin/keys/{key_id}"), None)
                .unwrap()
                .0,
            200
        );

        // Update.
        assert_eq!(
            dispatch(
                "PATCH",
                &format!("/admin/keys/{key_id}"),
                Some(r#"{"expected_revision":1,"max_requests_per_minute":5}"#)
            )
            .unwrap()
            .0,
            200
        );

        // Reversible status transitions and rotation each advance revision.
        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/block"),
            Some(r#"{"expected_revision":2}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200);
        assert_eq!(parse(&resp)["key"]["policy_revision"], 3);
        assert_eq!(
            dispatch(
                "POST",
                &format!("/admin/keys/{key_id}/unblock"),
                Some(r#"{"expected_revision":3}"#),
            )
            .unwrap()
            .0,
            200
        );

        let stale_rotate = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/rotate"),
            Some(r#"{"expected_revision":3,"grace_secs":120}"#),
        )
        .unwrap();
        assert_eq!(stale_rotate.0, 409);
        assert_eq!(parse(&stale_rotate)["current_revision"], 4);
        assert!(!stale_rotate.2.contains("token"));
        assert!(!stale_rotate.2.contains("hash"));

        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/rotate"),
            Some(r#"{"expected_revision":4,"grace_secs":120}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200);
        let v = parse(&resp);
        assert!(v["token"]
            .as_str()
            .unwrap()
            .starts_with(&format!("sk-{key_id}-")));
        assert_eq!(v["key"]["rotation_pending"], true);
        assert_eq!(v["key"]["policy_revision"], 5);

        // Revocation is terminal. Neither unblock nor rotation may change it.
        let resp = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/revoke"),
            Some(r#"{"expected_revision":5}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200);
        assert_eq!(parse(&resp)["key"]["status"], "revoked");
        assert_eq!(parse(&resp)["key"]["policy_revision"], 6);

        for action in ["unblock", "block", "rotate"] {
            let resp = dispatch(
                "POST",
                &format!("/admin/keys/{key_id}/{action}"),
                Some(r#"{"expected_revision":6}"#),
            )
            .unwrap();
            assert_eq!(resp.0, 409, "terminal action {action}: {}", resp.2);
            assert!(!resp.2.contains("token"));
            assert!(!resp.2.contains("hash"));
        }
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":6,"name":"must not change"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 409);

        // Delete -> gone.
        assert_eq!(
            dispatch("DELETE", &format!("/admin/keys/{key_id}"), None)
                .unwrap()
                .0,
            200
        );
        assert_eq!(
            dispatch("GET", &format!("/admin/keys/{key_id}"), None)
                .unwrap()
                .0,
            404
        );
    }

    #[test]
    fn key_views_expose_secret_free_policy_digest_and_patch_changes_it() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"name":"governed","tenant":"tenant-a",
                    "allowed_models":["gpt-4.1"],"allowed_providers":["openai"]}"#,
            ),
        )
        .unwrap();
        assert_eq!(created.0, 201, "create failed: {}", created.2);
        let created_json = parse(&created);
        let key_id = created_json["key"]["key_id"].as_str().unwrap().to_string();
        let token = created_json["token"].as_str().unwrap();
        let created_digest = created_json["key"]["policy_digest"]
            .as_str()
            .expect("create response policy digest")
            .to_string();
        assert!(created_digest.starts_with("sha256:"));
        assert_eq!(created_digest.len(), "sha256:".len() + 64);
        assert!(!created_digest.contains(token));

        let plane = current_key_plane().unwrap();
        let stored = load_key(&plane, &key_id).unwrap().unwrap();
        let expected = crate::key_policy::key_record_to_effective_policy(&stored, "tenant-a")
            .unwrap()
            .policy_digest()
            .unwrap();
        assert_eq!(created_digest, expected);
        assert!(!created.2.contains(&stored.secret_hash));

        let listed = parse(&dispatch("GET", "/admin/keys", None).unwrap());
        let listed_key = listed["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["key_id"] == key_id)
            .expect("created key in list response");
        assert_eq!(listed_key["policy_digest"], created_digest);

        let fetched = parse(&dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap());
        assert_eq!(fetched["key"]["policy_digest"], created_digest);

        let patched = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":1,"blocked_models":["gpt-4o"]}"#),
        )
        .unwrap();
        assert_eq!(patched.0, 200, "patch failed: {}", patched.2);
        let patched_json = parse(&patched);
        let patched_digest = patched_json["key"]["policy_digest"]
            .as_str()
            .expect("patch response policy digest");
        assert_ne!(patched_digest, created_digest);

        let fetched = parse(&dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap());
        assert_eq!(fetched["key"]["policy_digest"], patched_digest);
    }

    #[test]
    fn tenantless_key_digest_is_origin_scoped_to_policy_preview() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(r#"{"name":"shared","allowed_models":["gpt-4.1"]}"#),
        )
        .unwrap();
        assert_eq!(created.0, 201, "create failed: {}", created.2);
        let created_json = parse(&created);
        let key_id = created_json["key"]["key_id"].as_str().unwrap();
        assert!(created_json["key"]["tenant_id"].is_null());
        assert!(
            created_json["key"]["policy_digest"].is_null(),
            "a tenantless record has no single runtime digest"
        );

        let preview = |tenant: &str| {
            let body = json!({"origin_tenant_id": tenant}).to_string();
            parse(
                &dispatch(
                    "POST",
                    &format!("/admin/keys/{key_id}/effective-policy/preview"),
                    Some(&body),
                )
                .unwrap(),
            )
        };
        let tenant_a = preview("tenant-a");
        let tenant_b = preview("tenant-b");

        assert_eq!(tenant_a["effective_policy"]["tenant_id"], "tenant-a");
        assert_eq!(tenant_b["effective_policy"]["tenant_id"], "tenant-b");
        assert_ne!(
            tenant_a["policy_version"]["digest"], tenant_b["policy_version"]["digest"],
            "the inherited tenant participates in the runtime policy digest"
        );
    }

    #[test]
    fn malformed_legacy_policy_has_null_digest_without_breaking_list_or_get() {
        let _g = crate::key_plane::test_plane_guard();
        let store = Arc::new(MemoryKeyStore::new());
        install_test_plane_with_store(store.clone());

        let mut legacy = KeyRecord::new(
            "legacy-malformed".to_string(),
            "sensitive-stored-verifier".to_string(),
            Utc::now(),
        );
        legacy.name = Some("legacy record".to_string());
        legacy.principal_selectors = vec![json!({"unknown": "value"})];
        block_on_keystore(store.put_key(legacy)).unwrap();

        let fetched = dispatch("GET", "/admin/keys/legacy-malformed", None).unwrap();
        assert_eq!(fetched.0, 200, "get failed: {}", fetched.2);
        assert!(parse(&fetched)["key"]["policy_digest"].is_null());
        assert!(!fetched.2.contains("sensitive-stored-verifier"));

        let listed = dispatch("GET", "/admin/keys", None).unwrap();
        assert_eq!(listed.0, 200, "list failed: {}", listed.2);
        let listed_json = parse(&listed);
        let legacy_view = listed_json["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["key_id"] == "legacy-malformed")
            .expect("legacy record in list response");
        assert!(legacy_view["policy_digest"].is_null());
        assert!(!listed.2.contains("sensitive-stored-verifier"));
    }

    #[test]
    fn advanced_policy_fields_validate_and_roundtrip() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        // Valid lane + tpm + inject_mcp + metadata all land on the view.
        let resp = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"name":"lanes","priority":"interactive","max_tokens_per_minute":50000,
                    "inject_mcp":{"ref":"toolhub"},"metadata":{"owner":"platform"}}"#,
            ),
        )
        .unwrap();
        assert_eq!(resp.0, 201, "create failed: {}", resp.2);
        let v = parse(&resp);
        let key_id = v["key"]["key_id"].as_str().unwrap().to_string();
        assert_eq!(v["key"]["priority"], "interactive");
        assert_eq!(v["key"]["max_tokens_per_minute"], 50000);
        assert_eq!(v["key"]["inject_mcp"]["ref"], "toolhub");
        assert_eq!(v["key"]["metadata"]["owner"], "platform");

        // Unknown lane and a ref-less inject_mcp are 400s, not stored.
        assert_eq!(
            dispatch(
                "PATCH",
                &format!("/admin/keys/{key_id}"),
                Some(r#"{"expected_revision":1,"priority":"urgent"}"#)
            )
            .unwrap()
            .0,
            400
        );
        assert_eq!(
            dispatch(
                "PATCH",
                &format!("/admin/keys/{key_id}"),
                Some(r#"{"expected_revision":1,"inject_mcp":{"format":"openai"}}"#)
            )
            .unwrap()
            .0,
            400
        );

        // Explicit null clears nullable values.
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":1,"priority":null,"inject_mcp":null}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200);
        let v = parse(&resp);
        assert_eq!(v["key"]["policy_revision"], 2);
        assert!(v["key"]["priority"].is_null());
        assert!(v["key"]["inject_mcp"].is_null());
    }

    #[test]
    fn key_patch_has_flat_revisioned_tri_state_semantics() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let resp = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"name":"governed","max_requests_per_minute":60,
                    "max_tokens_per_minute":50000,"priority":"interactive",
                    "max_budget_tokens":1000000,"max_budget_usd":25.0,
                    "allowed_models":["gpt-4.1"],"blocked_models":["gpt-4o"],
                    "allowed_providers":["openai"],"blocked_providers":["vertex"],
                    "allowed_tools":["search"],
                    "require_pii_redaction":["email"],
                    "principal_selectors":[{"team":"platform"}],
                    "route_to_model":"gpt-4.1","inject_tools":[{"name":"search"}],
                    "inject_mcp":{"ref":"toolhub"},"bypass_prompt_injection":true,
                    "project":"search","user":"alice","tags":["prod"],
                    "metadata":{"owner":"platform"},"tenant":"tenant-a",
                    "expires_at":"2030-01-01T00:00:00Z"}"#,
            ),
        )
        .unwrap();
        assert_eq!(resp.0, 201, "create failed: {}", resp.2);
        let created = parse(&resp);
        let key_id = created["key"]["key_id"].as_str().unwrap().to_string();
        assert_eq!(created["key"]["policy_revision"], 1);
        assert_eq!(created["key"]["blocked_providers"], json!(["vertex"]));
        assert_eq!(created["key"]["allowed_tools"], json!(["search"]));

        // Absent fields stay unchanged while a concrete value replaces one.
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":1,"project":"recommendations"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "value patch failed: {}", resp.2);
        let updated = parse(&resp);
        assert_eq!(updated["key"]["policy_revision"], 2);
        assert_eq!(updated["key"]["project"], "recommendations");
        assert_eq!(updated["key"]["name"], "governed");
        assert_eq!(updated["key"]["blocked_providers"], json!(["vertex"]));
        assert_eq!(updated["key"]["allowed_tools"], json!(["search"]));

        // An explicit empty tool allowlist is distinct from unrestricted.
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":2,"allowed_tools":[]}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "empty allowlist patch failed: {}", resp.2);
        let deny_all_tools = parse(&resp);
        assert_eq!(deny_all_tools["key"]["policy_revision"], 3);
        assert_eq!(deny_all_tools["key"]["allowed_tools"], json!([]));

        // Null clears nullable scalars, budget members, and the optional tool
        // allowlist. Empty collections replace other collection policy, and
        // false remains an explicit value.
        let resp = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(
                r#"{"expected_revision":3,"name":null,
                    "max_requests_per_minute":null,"max_tokens_per_minute":null,
                    "priority":null,"max_budget_tokens":null,"max_budget_usd":null,
                    "allowed_models":[],"blocked_models":[],"allowed_providers":[],
                    "blocked_providers":[],"allowed_tools":null,"require_pii_redaction":[],
                    "principal_selectors":[],"route_to_model":null,"inject_tools":[],
                    "inject_mcp":null,"bypass_prompt_injection":false,
                    "project":null,"user":null,"tags":[],"metadata":{},
                    "tenant":null,"expires_at":null}"#,
            ),
        )
        .unwrap();
        assert_eq!(resp.0, 200, "clear patch failed: {}", resp.2);
        let cleared = parse(&resp);
        assert_eq!(cleared["key"]["policy_revision"], 4);
        for field in [
            "name",
            "max_requests_per_minute",
            "max_tokens_per_minute",
            "priority",
            "budget",
            "route_to_model",
            "allowed_tools",
            "inject_mcp",
            "project",
            "user",
            "tenant_id",
            "expires_at",
        ] {
            assert!(
                cleared["key"][field].is_null(),
                "field {field} was not cleared"
            );
        }
        for field in [
            "allowed_models",
            "blocked_models",
            "allowed_providers",
            "blocked_providers",
            "require_pii_redaction",
            "principal_selectors",
            "inject_tools",
            "tags",
        ] {
            assert_eq!(cleared["key"][field], json!([]), "field {field}");
        }
        assert_eq!(cleared["key"]["metadata"], json!({}));
        assert_eq!(cleared["key"]["bypass_prompt_injection"], false);

        // A stale writer is denied and learns only the current revision.
        let stale = dispatch(
            "PATCH",
            &format!("/admin/keys/{key_id}"),
            Some(r#"{"expected_revision":3,"name":"stale"}"#),
        )
        .unwrap();
        assert_eq!(stale.0, 409);
        let conflict = parse(&stale);
        assert_eq!(conflict["key_id"], key_id);
        assert_eq!(conflict["expected_revision"], 3);
        assert_eq!(conflict["current_revision"], 4);
        for forbidden in ["token", "secret", "hash", "record"] {
            assert!(!stale.2.contains(forbidden), "conflict leaked {forbidden}");
        }

        let current = dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap();
        assert_eq!(parse(&current)["key"]["policy_revision"], 4);
        assert!(parse(&current)["key"]["name"].is_null());
    }

    #[test]
    fn invalid_key_policy_input_is_rejected_before_write() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        assert_eq!(
            dispatch(
                "POST",
                "/admin/keys",
                Some(r#"{"name":"bad","unknown_policy":true}"#),
            )
            .unwrap()
            .0,
            400
        );
        assert_eq!(
            dispatch(
                "POST",
                "/admin/keys",
                Some(r#"{"expires_at":"not-a-date"}"#),
            )
            .unwrap()
            .0,
            400
        );
        assert_eq!(
            dispatch(
                "POST",
                "/admin/keys",
                Some(r#"{"principal_selectors":[42]}"#),
            )
            .unwrap()
            .0,
            400
        );

        let created = dispatch("POST", "/admin/keys", Some(r#"{"name":"stable"}"#)).unwrap();
        let key_id = parse(&created)["key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string();

        for body in [
            r#"{"expected_revision":1,"unknown_policy":true}"#,
            r#"{"expected_revision":1,"expires_at":"not-a-date"}"#,
            r#"{"name":"missing revision"}"#,
            r#"{"expected_revision":1,"tags":null}"#,
            r#"{"expected_revision":1,"allowed_tools":"search"}"#,
            r#"{"expected_revision":1,"metadata":null}"#,
            r#"{"expected_revision":1,"bypass_prompt_injection":null}"#,
            r#"{"expected_revision":1,"principal_selectors":[42]}"#,
            r#"{"expected_revision":1,"principal_selectors":[{"unknown":"value"}]}"#,
        ] {
            let resp = dispatch("PATCH", &format!("/admin/keys/{key_id}"), Some(body)).unwrap();
            assert_eq!(resp.0, 400, "body {body}: {}", resp.2);
        }

        let invalid_action = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/block"),
            Some(r#"{"expected_revision":1,"unknown_policy":true}"#),
        )
        .unwrap();
        assert_eq!(invalid_action.0, 400);

        let current = dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap();
        assert_eq!(parse(&current)["key"]["policy_revision"], 1);
        assert_eq!(parse(&current)["key"]["name"], "stable");
        assert_eq!(parse(&current)["key"]["status"], "active");
    }

    #[test]
    fn credential_lifecycle_via_dispatch() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        // Encrypted credential: plaintext must not appear in the response.
        let resp = dispatch(
            "POST",
            "/admin/credentials",
            Some(r#"{"id":"openai","provider":"openai","secret":"sk-up"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 201);
        let v = parse(&resp);
        assert_eq!(v["credential"]["storage"], "encrypted");
        assert!(
            !resp.2.contains("sk-up"),
            "plaintext secret leaked into response"
        );

        // Vault-ref credential surfaces the reference (not a secret).
        let resp = dispatch(
            "POST",
            "/admin/credentials",
            Some(r#"{"id":"anthropic","vault_ref":"vault://anthropic"}"#),
        )
        .unwrap();
        assert_eq!(resp.0, 201);
        let v = parse(&resp);
        assert_eq!(v["credential"]["storage"], "vault_ref");
        assert_eq!(v["credential"]["vault_ref"], "vault://anthropic");

        assert_eq!(dispatch("GET", "/admin/credentials", None).unwrap().0, 200);
        assert_eq!(
            dispatch("DELETE", "/admin/credentials/openai", None)
                .unwrap()
                .0,
            200
        );
    }

    #[test]
    fn unowned_paths_fall_through() {
        // dispatch returns None for paths it does not own, so the rest of the
        // admin dispatcher still handles them.
        assert!(dispatch("GET", "/admin/reload", None).is_none());
        assert!(dispatch("GET", "/api/stats", None).is_none());
        assert!(dispatch("POST", "/healthz", None).is_none());
    }

    #[test]
    fn key_policy_schema_is_server_driven_and_does_not_require_a_key_plane() {
        let _g = crate::key_plane::test_plane_guard();

        let response = dispatch("GET", "/admin/keys/policy-schema", None).unwrap();
        assert_eq!(response.0, 200, "schema failed: {}", response.2);
        let schema = parse(&response);
        assert_eq!(
            schema["schema_version"],
            sbproxy_ai::effective_key_policy::EFFECTIVE_KEY_POLICY_SCHEMA_VERSION
        );
        assert_eq!(
            schema["fields"].as_array().unwrap().len(),
            sbproxy_ai::effective_key_policy::PolicyField::ALL.len()
        );

        let field = |name: &str| {
            schema["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|field| field["wire_name"] == name)
                .unwrap_or_else(|| panic!("missing schema field {name}"))
        };
        assert_eq!(field("display_name")["mutation"]["fields"], json!(["name"]));
        assert_eq!(field("display_name")["editor"], "text");
        assert_eq!(field("display_name")["clear_semantics"], "null");
        assert_eq!(field("tenant_id")["mutation"]["fields"], json!(["tenant"]));
        assert_eq!(
            field("status")["mutation"],
            json!({
                "kind": "action",
                "fields": ["block", "unblock", "revoke"]
            })
        );
        assert_eq!(
            field("allowed_tools")["clear_semantics"],
            "null_means_unrestricted"
        );
        assert!(schema["fields"].as_array().unwrap().iter().all(|field| {
            field["wire_name"] == field["preview_field"]
                && field["enforcement_proof"]
                    .as_str()
                    .is_some_and(|proof| !proof.is_empty())
        }));

        assert_eq!(
            dispatch("POST", "/admin/keys/policy-schema", Some("{}"))
                .unwrap()
                .0,
            405
        );
    }

    #[test]
    fn key_policy_preview_returns_canonical_policy_version_and_allow_decisions() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"name":"production chat","tenant":"tenant-a",
                    "expires_at":"2030-01-01T00:00:00Z",
                    "allowed_models":["gpt-4.1"],"blocked_models":["gpt-4o"],
                    "route_to_model":"gpt-4.1","allowed_providers":["openai"],
                    "blocked_providers":["vertex"],"allowed_tools":["search"],
                    "principal_selectors":[{"team":"platform"}],
                    "require_pii_redaction":["email"],
                    "max_requests_per_minute":60,"max_tokens_per_minute":50000,
                    "max_budget_tokens":1000000,"max_budget_usd":25.0,
                    "priority":"interactive"}"#,
            ),
        )
        .unwrap();
        assert_eq!(created.0, 201, "create failed: {}", created.2);
        let created_json = parse(&created);
        let key_id = created_json["key"]["key_id"].as_str().unwrap();
        let token = created_json["token"].as_str().unwrap();

        let sample = json!({
            "origin_tenant_id": "tenant-a",
            "at": "2029-01-01T00:00:00Z",
            "model": "gpt-4o",
            "provider": "openai",
            "tools": ["search"],
            "principal": {
                "virtual_key": "production-chat",
                "team": "platform",
                "project": "search",
                "user": "alice",
                "roles": ["developer"],
                "claims": {"environment": "production"}
            },
            "active_pii_rules": ["email", "phone"],
            "estimated_tokens": 1000,
            "estimated_micro_usd": 2_000_000,
            "usage": {
                "requests_in_window": 2,
                "tokens_in_window": 1000,
                "total_tokens": 100_000,
                "total_micro_usd": 3_000_000
            }
        });
        let body = serde_json::to_string(&sample).unwrap();
        let response = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/effective-policy/preview"),
            Some(&body),
        )
        .unwrap();
        assert_eq!(response.0, 200, "preview failed: {}", response.2);
        let preview = parse(&response);

        assert_eq!(preview["effective_policy"]["key_id"], key_id);
        assert_eq!(
            preview["effective_policy"]["display_name"],
            "production chat"
        );
        assert_eq!(preview["effective_policy"]["tenant_id"], "tenant-a");
        assert_eq!(preview["effective_policy"]["policy_revision"], 1);
        assert_eq!(preview["policy_version"]["revision"], 1);
        assert!(preview["policy_version"]["digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(preview["decisions"]["allowed"], true);
        assert_eq!(preview["decisions"]["lifecycle"]["reason_code"], "active");
        assert_eq!(preview["decisions"]["tenant"]["reason_code"], "match");
        assert_eq!(preview["decisions"]["model"]["requested"], "gpt-4o");
        assert_eq!(preview["decisions"]["model"]["effective"], "gpt-4.1");
        assert_eq!(preview["decisions"]["model"]["routed"], true);
        assert_eq!(preview["decisions"]["provider"]["allowed"], true);
        assert_eq!(preview["decisions"]["tools"]["denied"], json!([]));
        assert_eq!(preview["decisions"]["principal"]["reason_code"], "matched");
        assert_eq!(
            preview["decisions"]["rate_limits"]["requests_per_minute"],
            json!({
                "allowed": true,
                "limit": 60,
                "current": 2,
                "requested": 1,
                "projected": 3,
                "reason_code": "within_limit"
            })
        );
        assert_eq!(
            preview["decisions"]["rate_limits"]["tokens_per_minute"]["projected"],
            2000
        );
        assert_eq!(
            preview["decisions"]["budget"]["tokens"]["projected"],
            101_000
        );
        assert_eq!(
            preview["decisions"]["budget"]["micro_usd"]["projected"],
            5_000_000
        );
        assert_eq!(preview["decisions"]["priority"]["lane"], "interactive");
        assert_eq!(
            preview["decisions"]["guardrails"]["pii"]["missing"],
            json!([])
        );
        assert_eq!(
            preview["decisions"]["guardrails"]["prompt_injection"]["mode"],
            "enforce"
        );
        let unchanged = dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap();
        assert_eq!(
            parse(&unchanged)["key"],
            created_json["key"],
            "preview must not mutate the stored key policy"
        );

        for forbidden in [token, "secret_hash", "prev_secret_hash", "hash_alg"] {
            assert!(
                !response.2.contains(forbidden),
                "preview response leaked {forbidden}"
            );
        }
    }

    #[test]
    fn key_policy_preview_reports_every_denial_in_one_response() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"tenant":"tenant-a","expires_at":"2025-01-01T00:00:00Z",
                    "allowed_models":["gpt-4.1"],"blocked_models":["gpt-4o"],
                    "allowed_providers":["openai"],"blocked_providers":["vertex"],
                    "allowed_tools":["search"],
                    "principal_selectors":[{"team":"platform"}],
                    "require_pii_redaction":["email"],
                    "max_requests_per_minute":3,"max_tokens_per_minute":1000,
                    "max_budget_tokens":5000,"max_budget_usd":2.0,
                    "priority":"batch"}"#,
            ),
        )
        .unwrap();
        let key_id = parse(&created)["key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string();
        let sample = json!({
            "origin_tenant_id": "tenant-b",
            "at": "2029-01-01T00:00:00Z",
            "model": "gpt-4o",
            "provider": "vertex",
            "tools": ["search", "shell"],
            "principal": {"team": "finance"},
            "active_pii_rules": [],
            "estimated_tokens": 500,
            "estimated_micro_usd": 500_000,
            "usage": {
                "requests_in_window": 3,
                "tokens_in_window": 750,
                "total_tokens": 4800,
                "total_micro_usd": 1_750_000
            }
        });
        let body = serde_json::to_string(&sample).unwrap();
        let response = dispatch(
            "POST",
            &format!("/admin/keys/{key_id}/effective-policy/preview"),
            Some(&body),
        )
        .unwrap();
        assert_eq!(response.0, 200, "preview failed: {}", response.2);
        let decisions = &parse(&response)["decisions"];

        assert_eq!(decisions["allowed"], false);
        assert_eq!(decisions["lifecycle"]["reason_code"], "expired");
        assert_eq!(decisions["tenant"]["reason_code"], "mismatch");
        assert_eq!(decisions["model"]["reason_code"], "blocked");
        assert_eq!(decisions["provider"]["reason_code"], "blocked");
        assert_eq!(decisions["tools"]["denied"], json!(["shell"]));
        assert_eq!(decisions["principal"]["reason_code"], "not_matched");
        assert_eq!(decisions["rate_limits"]["allowed"], false);
        assert_eq!(decisions["budget"]["allowed"], false);
        assert_eq!(decisions["priority"]["lane"], "batch");
        assert_eq!(decisions["guardrails"]["pii"]["missing"], json!(["email"]));
        assert_eq!(decisions["guardrails"]["allowed"], false);
        let unchanged = dispatch("GET", &format!("/admin/keys/{key_id}"), None).unwrap();
        assert_eq!(parse(&unchanged)["key"], parse(&created)["key"]);
    }

    #[test]
    fn key_policy_preview_defaults_context_and_rejects_unbounded_or_unknown_samples() {
        let _g = crate::key_plane::test_plane_guard();
        install_test_plane();
        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(r#"{"name":"bounded","tenant":"tenant-a"}"#),
        )
        .unwrap();
        let key_id = parse(&created)["key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string();
        let path = format!("/admin/keys/{key_id}/effective-policy/preview");

        let defaulted = dispatch("POST", &path, Some("{}")).unwrap();
        assert_eq!(defaulted.0, 200, "default preview failed: {}", defaulted.2);
        assert_eq!(
            parse(&defaulted)["decisions"]["tenant"]["origin_tenant_id"],
            "tenant-a"
        );

        for body in [
            r#"{"unknown":true}"#.to_string(),
            r#"{"principal":{"unknown":true}}"#.to_string(),
            serde_json::to_string(&json!({"tools": vec!["tool"; 129]})).unwrap(),
            serde_json::to_string(&json!({"model": "x".repeat(513)})).unwrap(),
            "{".to_string(),
            format!(r#"{{"model":"{}"}}"#, "x".repeat(70_000)),
        ] {
            let response = dispatch("POST", &path, Some(&body)).unwrap();
            assert_eq!(response.0, 400, "body was accepted: {}", response.2);
            assert!(!response.2.contains(&"x".repeat(513)));
        }

        let missing = dispatch(
            "POST",
            "/admin/keys/missing/effective-policy/preview",
            Some("{}"),
        )
        .unwrap();
        assert_eq!(missing.0, 404);
        assert_eq!(parse(&missing), json!({"error": "key not found"}));
        assert_eq!(dispatch("GET", &path, None).unwrap().0, 405);
    }

    #[test]
    fn key_usage_returns_integer_limits_counters_and_safe_backend_health() {
        let _g = crate::key_plane::test_plane_guard();
        let key_store = Arc::new(MemoryKeyStore::new());
        let governance = Arc::new(RecordingGovernanceStore::healthy());
        install_test_plane_with_governance(key_store, governance.clone());

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(
                r#"{"name":"must-not-appear","max_requests_per_minute":60,
                    "max_tokens_per_minute":50000,"max_budget_tokens":1000000,
                    "max_budget_usd":25.1234564,
                    "metadata":{"redis_url":"redis://operator:top-secret@redis.internal",
                    "node_id":"node-secret","artifact":"artifact-secret"}}"#,
            ),
        )
        .unwrap();
        assert_eq!(created.0, 201, "create failed: {}", created.2);
        let created_json = parse(&created);
        let key_id = created_json["key"]["key_id"].as_str().unwrap().to_string();
        let token = created_json["token"].as_str().unwrap().to_string();

        let response = dispatch("GET", &format!("/admin/keys/{key_id}/usage"), None).unwrap();
        assert_eq!(response.0, 200, "usage failed: {}", response.2);
        let usage = &parse(&response)["usage"];
        assert_eq!(usage["key_id"], key_id);
        assert_eq!(usage["policy_revision"], 1);
        assert_eq!(
            usage["requests_per_window"],
            json!({
                "limit": 60,
                "used": 2,
                "reserved": 1,
                "remaining": 57,
                "reset_at_millis": 1_700_000_040_000_u64,
            })
        );
        assert_eq!(usage["tokens_per_window"]["limit"], 50_000);
        assert_eq!(usage["tokens_per_window"]["used"], 100);
        assert_eq!(usage["tokens_per_window"]["reserved"], 20);
        assert_eq!(usage["tokens_per_window"]["remaining"], 49_880);
        assert_eq!(usage["total_tokens"]["limit"], 1_000_000);
        assert_eq!(usage["total_tokens"]["reset_at_millis"], json!(null));
        assert_eq!(usage["total_micro_usd"]["limit"], 25_123_456);
        assert_eq!(usage["total_micro_usd"]["used"], 3_000_000);
        assert_eq!(usage["total_micro_usd"]["reserved"], 500_000);
        assert_eq!(usage["total_micro_usd"]["remaining"], 21_623_456);
        assert_eq!(usage["backend"]["backend"], "redis");
        assert_eq!(usage["backend"]["consistency"], "strict");
        assert_eq!(usage["backend"]["status"], "healthy");
        assert_eq!(usage["backend"]["checked_at_millis"], 1_700_000_000_000_u64);

        let snapshots = governance.snapshot_requests();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].key_id, key_id);
        assert_eq!(snapshots[0].policy_revision, 1);
        assert_eq!(snapshots[0].limits.window_millis, 60_000);
        assert_eq!(snapshots[0].limits.total_micro_usd, Some(25_123_456));

        for forbidden in [
            token.as_str(),
            "must-not-appear",
            "top-secret",
            "redis.internal",
            "node-secret",
            "artifact-secret",
            "secret_hash",
        ] {
            assert!(
                !response.2.contains(forbidden),
                "usage response leaked {forbidden}"
            );
        }
    }

    #[test]
    fn key_usage_returns_not_found_without_calling_governance_storage() {
        let _g = crate::key_plane::test_plane_guard();
        let key_store = Arc::new(MemoryKeyStore::new());
        let governance = Arc::new(RecordingGovernanceStore::unavailable());
        install_test_plane_with_governance(key_store, governance.clone());

        let missing = dispatch("GET", "/admin/keys/missing/usage", None).unwrap();
        assert_eq!(missing.0, 404);
        assert_eq!(parse(&missing), json!({ "error": "key not found" }));
        assert!(governance.snapshot_requests().is_empty());
    }

    #[test]
    fn key_usage_returns_generic_secret_free_service_unavailable_for_backend_errors() {
        let _g = crate::key_plane::test_plane_guard();
        let key_store = Arc::new(MemoryKeyStore::new());
        let governance = Arc::new(RecordingGovernanceStore::unavailable());
        install_test_plane_with_governance(key_store, governance.clone());

        let created = dispatch(
            "POST",
            "/admin/keys",
            Some(r#"{"name":"unavailable-key","max_requests_per_minute":5}"#),
        )
        .unwrap();
        let key_id = parse(&created)["key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string();
        let response = dispatch("GET", &format!("/admin/keys/{key_id}/usage"), None).unwrap();
        assert_eq!(response.0, 503);
        assert_eq!(
            parse(&response),
            json!({ "error": "governance backend unavailable" })
        );
        for forbidden in ["redis", "unavailable-key", &key_id] {
            assert!(
                !response.2.contains(forbidden),
                "backend error leaked {forbidden}"
            );
        }
    }

    #[test]
    fn key_usage_rejects_malformed_legacy_monetary_limits_before_snapshot() {
        let _g = crate::key_plane::test_plane_guard();
        let key_store = Arc::new(MemoryKeyStore::new());
        let governance = Arc::new(RecordingGovernanceStore::healthy());
        install_test_plane_with_governance(key_store.clone(), governance.clone());

        for (index, value) in [-1.0, f64::NAN, f64::INFINITY, f64::MAX]
            .into_iter()
            .enumerate()
        {
            let key_id = format!("legacy-{index}");
            let mut record =
                KeyRecord::new(key_id.clone(), "hash-must-not-leak".to_string(), Utc::now());
            record.budget = Some(RecordBudget {
                max_tokens: Some(100),
                max_cost_usd: Some(value),
            });
            let store = key_store.clone();
            block_on_keystore(async move { store.put_key(record).await }).unwrap();

            let response = dispatch("GET", &format!("/admin/keys/{key_id}/usage"), None).unwrap();
            assert_eq!(response.0, 500, "value {value:?}: {}", response.2);
            assert_eq!(parse(&response), json!({ "error": "internal error" }));
            assert!(!response.2.contains("hash-must-not-leak"));
            assert!(!response.2.contains(&key_id));
        }

        assert!(
            governance.snapshot_requests().is_empty(),
            "malformed monetary policies must not reach governance storage"
        );
    }
}
