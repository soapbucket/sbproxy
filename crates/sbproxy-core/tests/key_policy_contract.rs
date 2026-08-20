use chrono::{DateTime, Duration, Utc};
use sbproxy_ai::effective_key_policy::{EffectiveKeySource, EffectiveKeyStatus};
use sbproxy_ai::identity::KeyPriority;
use sbproxy_core::key_policy::{
    key_record_to_effective_policy, key_record_to_effective_policy_at, StoredPolicyErrorKind,
};
use sbproxy_keystore::record::{
    BudgetOverride, KeyRecord, RecordBudget, RecordSource, RecordStatus,
};
use serde_json::json;

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

fn record() -> KeyRecord {
    let mut record = KeyRecord::new("key_01", "hash-must-not-escape", now());
    record.policy_revision = 7;
    record.name = Some("production chat".into());
    record.status = RecordStatus::Blocked;
    record.source = RecordSource::Config;
    record.tenant_id = Some("tenant-a".into());
    record.project = Some("search".into());
    record.allowed_models = vec!["gpt-4.1".into()];
    record.blocked_providers = vec!["vertex".into()];
    record.principal_selectors = vec![json!({"team": "platform"})];
    record.allowed_tools = Some(vec!["search".into()]);
    record.inject_mcp = Some(json!({"ref": "toolhub", "filter": ["search*"]}));
    record.max_requests_per_minute = Some(60);
    record.max_tokens_per_minute = Some(50_000);
    record.budget = Some(RecordBudget {
        max_tokens: Some(1_000_000),
        max_cost_usd: Some(25.0),
    });
    record.priority = Some("interactive".into());
    record
}

#[test]
fn key_policy_stored_record_lowers_to_the_canonical_secret_free_policy() {
    let policy = key_record_to_effective_policy(&record(), "tenant-a").unwrap();

    assert_eq!(policy.key_id, "key_01");
    assert_eq!(policy.policy_revision, 7);
    assert_eq!(policy.display_name.as_deref(), Some("production chat"));
    assert_eq!(policy.source, EffectiveKeySource::Config);
    assert_eq!(policy.status, EffectiveKeyStatus::Blocked);
    assert_eq!(policy.tenant_id, "tenant-a");
    assert_eq!(policy.allowed_models, ["gpt-4.1"]);
    assert_eq!(policy.blocked_providers, ["vertex"]);
    assert_eq!(policy.priority, KeyPriority::Interactive);
    assert_eq!(policy.budget.as_ref().unwrap().max_tokens, Some(1_000_000));

    let serialized = serde_json::to_string(&policy).unwrap();
    assert!(!serialized.contains("hash-must-not-escape"));
    assert!(!serialized.contains("secret_hash"));
}

#[test]
fn key_policy_lowering_inherits_tenant_but_rejects_a_cross_tenant_record() {
    let mut inherited = record();
    inherited.tenant_id = None;
    assert_eq!(
        key_record_to_effective_policy(&inherited, "tenant-b")
            .unwrap()
            .tenant_id,
        "tenant-b"
    );

    let error = key_record_to_effective_policy(&record(), "tenant-b").unwrap_err();
    assert_eq!(error.kind(), StoredPolicyErrorKind::TenantMismatch);
    assert_eq!(error.safe_reason(), "tenant_mismatch");
    assert!(!format!("{error:?}").contains("tenant-a"));
}

#[test]
fn key_policy_malformed_stored_selectors_and_mcp_references_fail_closed() {
    let mut selector = record();
    selector.principal_selectors = vec![json!({"unknown": "must-not-escape"})];
    let error = key_record_to_effective_policy(&selector, "tenant-a").unwrap_err();
    assert_eq!(error.kind(), StoredPolicyErrorKind::PrincipalSelector);
    assert_eq!(error.safe_reason(), "invalid_principal_selector");
    assert!(!format!("{error:?}").contains("must-not-escape"));

    let mut mcp = record();
    mcp.inject_mcp = Some(json!({"ref": ""}));
    let error = key_record_to_effective_policy(&mcp, "tenant-a").unwrap_err();
    assert_eq!(error.kind(), StoredPolicyErrorKind::McpReference);
    assert_eq!(error.safe_reason(), "invalid_mcp_reference");
}

/// WOR-2561: the lowering seam is where every request-path budget read
/// happens, so an override that is active at the evaluation instant must
/// raise the lowered budget, and one past its expiry must not. The instant
/// is injected: no sleeping, no sweeper.
#[test]
fn key_policy_lowering_applies_an_unexpired_override_and_ignores_an_expired_one() {
    let mut with_override = record();
    with_override.budget_override = Some(BudgetOverride {
        max_tokens_increase: Some(500_000),
        max_cost_usd_increase: Some(75.0),
        expires_at: now() + Duration::seconds(300),
        granted_by: "casey".into(),
        granted_at: now(),
        reason: None,
    });

    // Inside the window the effective policy carries the raised caps.
    let raised = key_record_to_effective_policy_at(&with_override, "tenant-a", now()).unwrap();
    let budget = raised.budget.as_ref().unwrap();
    assert_eq!(budget.max_tokens, Some(1_500_000));
    assert_eq!(budget.max_cost_usd, Some(100.0));

    // Past expiry the same stored record lowers to the base caps: the
    // grant needs no revert and no operator action to stop applying.
    let lapsed = key_record_to_effective_policy_at(
        &with_override,
        "tenant-a",
        now() + Duration::seconds(300),
    )
    .unwrap();
    let budget = lapsed.budget.as_ref().unwrap();
    assert_eq!(budget.max_tokens, Some(1_000_000));
    assert_eq!(budget.max_cost_usd, Some(25.0));
}

/// WOR-2561: a stored override whose applied cost arithmetic is not
/// representable fails closed exactly like a bad base budget, but only
/// while it is active; once expired it is inert and the base governs.
#[test]
fn key_policy_lowering_rejects_an_active_override_with_invalid_cost_arithmetic() {
    let mut poisoned = record();
    poisoned.budget_override = Some(BudgetOverride {
        max_tokens_increase: None,
        max_cost_usd_increase: Some(f64::MAX),
        expires_at: now() + Duration::seconds(300),
        granted_by: "casey".into(),
        granted_at: now(),
        reason: None,
    });
    let error = key_record_to_effective_policy_at(&poisoned, "tenant-a", now()).unwrap_err();
    assert_eq!(error.kind(), StoredPolicyErrorKind::InvalidBudget);

    let after_expiry =
        key_record_to_effective_policy_at(&poisoned, "tenant-a", now() + Duration::seconds(301))
            .unwrap();
    assert_eq!(
        after_expiry.budget.as_ref().unwrap().max_cost_usd,
        Some(25.0)
    );
}

#[test]
fn key_policy_invalid_revision_priority_and_budget_fail_closed() {
    let mut revision = record();
    revision.policy_revision = 0;
    let error = key_record_to_effective_policy(&revision, "tenant-a").unwrap_err();
    assert_eq!(error.kind(), StoredPolicyErrorKind::InvalidRevision);
    assert_eq!(error.safe_reason(), "invalid_policy_revision");

    let mut priority = record();
    priority.priority = Some("root-secret-lane".into());
    let error = key_record_to_effective_policy(&priority, "tenant-a").unwrap_err();
    assert_eq!(error.kind(), StoredPolicyErrorKind::InvalidPriority);
    assert_eq!(error.safe_reason(), "invalid_priority");
    assert!(!format!("{error:?}").contains("root-secret-lane"));

    for value in [-1.0, f64::NAN, f64::INFINITY, f64::MAX] {
        let mut budget = record();
        budget.budget.as_mut().unwrap().max_cost_usd = Some(value);
        let error = key_record_to_effective_policy(&budget, "tenant-a").unwrap_err();
        assert_eq!(error.kind(), StoredPolicyErrorKind::InvalidBudget);
        assert_eq!(error.safe_reason(), "invalid_budget");
        assert!(!format!("{error:?}").contains(&format!("{value:?}")));
    }
}
