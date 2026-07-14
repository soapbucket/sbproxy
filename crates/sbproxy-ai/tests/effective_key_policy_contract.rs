use chrono::{DateTime, Duration, Utc};
use sbproxy_ai::effective_key_policy::{
    resolve_effective_tenant, EffectiveKeyPolicy, EffectiveKeySource, EffectiveKeyStatus,
    KeyBudgetPolicy, PolicyEnforcementProof, PolicyField, PolicyMcpRef, PolicyMcpToolFormat,
    PrincipalSelector, TenantResolutionError, EFFECTIVE_KEY_POLICY_SCHEMA_VERSION,
};
use sbproxy_ai::identity::{KeyPriority, VirtualKeyConfig};
use serde_json::json;
use std::collections::BTreeMap;

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

fn policy() -> EffectiveKeyPolicy {
    EffectiveKeyPolicy {
        schema_version: EFFECTIVE_KEY_POLICY_SCHEMA_VERSION,
        key_id: "key_01".into(),
        display_name: Some("production chat".into()),
        source: EffectiveKeySource::Dynamic,
        policy_revision: 7,
        status: EffectiveKeyStatus::Active,
        expires_at: Some(now() + Duration::hours(1)),
        tenant_id: "tenant-a".into(),
        project: Some("search".into()),
        user: Some("alice".into()),
        tags: vec!["production".into(), "chat".into()],
        metadata: BTreeMap::from([("cost_center".into(), "cc-42".into())]),
        allowed_models: vec!["gpt-4.1".into(), "gpt-4o".into()],
        blocked_models: vec!["gpt-4o".into()],
        allowed_providers: vec!["openai".into(), "vertex".into()],
        blocked_providers: vec!["vertex".into()],
        route_to_model: Some("gpt-4.1".into()),
        principal_selectors: vec![PrincipalSelector {
            team: Some("platform".into()),
            ..PrincipalSelector::default()
        }],
        require_pii_redaction: vec!["email".into()],
        allowed_tools: Some(vec!["search".into(), "calculator".into()]),
        inject_tools: vec![json!({
            "type": "function",
            "function": {"name": "search", "description": "Search the index"}
        })],
        inject_mcp: Some(PolicyMcpRef {
            reference: "internal-tools".into(),
            format: PolicyMcpToolFormat::Openai,
            filter: vec!["search*".into()],
        }),
        bypass_prompt_injection: false,
        max_requests_per_minute: Some(60),
        max_tokens_per_minute: Some(100_000),
        budget: Some(KeyBudgetPolicy {
            max_tokens: Some(1_000_000),
            max_cost_usd: Some(25.0),
        }),
        priority: KeyPriority::Interactive,
    }
}

type EnforcementAssertion = fn(&EffectiveKeyPolicy);

const GOVERNED_KEY_E2E_SOURCE_PATH: &str = "e2e/tests/governed_key_policy.rs";
const GOVERNED_KEY_E2E_SOURCE: &str = include_str!("../../../e2e/tests/governed_key_policy.rs");
const AI_DISPATCH_SOURCE_PATH: &str = "crates/sbproxy-core/src/server/ai_dispatch.rs";
const AI_DISPATCH_SOURCE: &str = include_str!("../../sbproxy-core/src/server/ai_dispatch.rs");

#[derive(Clone, Copy)]
struct EnforcementTestRegistration {
    source_path: &'static str,
    source: &'static str,
    test_name: &'static str,
    behavior_markers: &'static [&'static str],
    assertion: EnforcementAssertion,
}

impl EnforcementTestRegistration {
    fn test_id(self) -> String {
        format!("{}::{}", self.source_path, self.test_name)
    }

    fn named_test_source(self) -> &'static str {
        let needle = format!("fn {}(", self.test_name);
        let mut matches = self.source.match_indices(&needle);
        let (function_start, _) = matches.next().unwrap_or_else(|| {
            panic!(
                "{} does not contain test function {}",
                self.source_path, self.test_name
            )
        });
        assert!(
            matches.next().is_none(),
            "{} contains multiple functions named {}",
            self.source_path,
            self.test_name
        );

        let function_line_start = self.source[..function_start]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
        let before_function = self.source[..function_line_start].trim_end();
        let attribute_line = before_function
            .rsplit_once('\n')
            .map_or(before_function, |(_, line)| line)
            .trim();
        assert!(
            attribute_line == "#[test]" || attribute_line.starts_with("#[tokio::test"),
            "{}::{} is not directly marked as a test",
            self.source_path,
            self.test_name
        );

        let opening_brace = self.source[function_start..]
            .find('{')
            .map(|offset| function_start + offset)
            .unwrap_or_else(|| {
                panic!(
                    "{}::{} has no function body",
                    self.source_path, self.test_name
                )
            });
        let mut depth = 0_u32;
        for (offset, character) in self.source[opening_brace..].char_indices() {
            match character {
                '{' => depth += 1,
                '}' => {
                    depth = depth.checked_sub(1).unwrap_or_else(|| {
                        panic!(
                            "{}::{} has an unbalanced function body",
                            self.source_path, self.test_name
                        )
                    });
                    if depth == 0 {
                        let function_end = opening_brace + offset + character.len_utf8();
                        return &self.source[function_start..function_end];
                    }
                }
                _ => {}
            }
        }
        panic!(
            "{}::{} has an unterminated function body",
            self.source_path, self.test_name
        );
    }
}

fn governed_key_e2e_test(
    test_name: &'static str,
    behavior_markers: &'static [&'static str],
    assertion: EnforcementAssertion,
) -> EnforcementTestRegistration {
    EnforcementTestRegistration {
        source_path: GOVERNED_KEY_E2E_SOURCE_PATH,
        source: GOVERNED_KEY_E2E_SOURCE,
        test_name,
        behavior_markers,
        assertion,
    }
}

fn ai_dispatch_test(
    test_name: &'static str,
    behavior_markers: &'static [&'static str],
    assertion: EnforcementAssertion,
) -> EnforcementTestRegistration {
    EnforcementTestRegistration {
        source_path: AI_DISPATCH_SOURCE_PATH,
        source: AI_DISPATCH_SOURCE,
        test_name,
        behavior_markers,
        assertion,
    }
}

fn registered_enforcement_test(proof: PolicyEnforcementProof) -> EnforcementTestRegistration {
    match proof {
        PolicyEnforcementProof::LifecycleGate => governed_key_e2e_test(
            "governed_key_requirement_is_origin_scoped_and_tenant_safe",
            &[
                "key_action(&world, &lifecycle, \"block\")",
                "key_action(&world, &lifecycle, \"revoke\")",
                "\"expires_at\": \"2020-01-01T00:00:00Z\"",
                "a blocked governed key must be denied immediately",
                "an expired governed key must be denied",
            ],
            |policy| assert!(policy.is_usable(now())),
        ),
        PolicyEnforcementProof::TenantBoundary => governed_key_e2e_test(
            "governed_key_requirement_is_origin_scoped_and_tenant_safe",
            &[
                "&chat(&world, STRICT_A_HOST, Some(&tenant_b.token), &body)",
                "&chat(&world, STRICT_B_HOST, Some(&tenant_b.token), &body)",
                "a stored tenant must not cross an origin tenant boundary",
                "the same governed key must work inside its matching tenant boundary",
            ],
            |policy| assert_eq!(policy.tenant_id, "tenant-a"),
        ),
        PolicyEnforcementProof::Attribution => governed_key_e2e_test(
            "dynamic_record_enforces_prompt_rates_budget_and_safe_attribution",
            &[
                "assert_eq!(usage[\"key_id\"], attributed.key_id)",
                "assert_eq!(usage[\"tenant_id\"], \"tenant-a\")",
                "assert_eq!(usage[\"project\"], \"recommendations\")",
                "assert_eq!(usage[\"user\"], \"alice\")",
                "assert_eq!(usage[\"tags\"], json!([\"production\", \"trusted\"]))",
                "usage[\"metadata\"]",
                "bounded security audit must not persist attribution canary",
                "attributed_line.contains(\"tenant_id=\\\"tenant-a\\\"\")",
                "high-cardinality user and metadata values must stay out of metric labels",
            ],
            |policy| {
                assert_eq!(policy.display_name.as_deref(), Some("production chat"));
                assert_eq!(policy.tenant_id, "tenant-a");
                assert_eq!(policy.project.as_deref(), Some("search"));
                assert_eq!(policy.user.as_deref(), Some("alice"));
                assert_eq!(policy.tags, ["production", "chat"]);
                assert_eq!(
                    policy.metadata.get("cost_center").map(String::as_str),
                    Some("cc-42")
                );
            },
        ),
        PolicyEnforcementProof::ModelGate => governed_key_e2e_test(
            "dynamic_record_enforces_model_provider_route_and_caller_tool_policy",
            &[
                "\"allowed_models\": [\"gpt-allowed\", \"gpt-blocked\"]",
                "\"blocked_models\": [\"gpt-blocked\"]",
                "model denials must happen before provider dispatch",
                "an allowed model must dispatch",
            ],
            |policy| {
                assert!(policy.is_model_allowed("gpt-4.1"));
                assert!(!policy.is_model_allowed("gpt-4o"));
            },
        ),
        PolicyEnforcementProof::ProviderGate => governed_key_e2e_test(
            "dynamic_record_enforces_model_provider_route_and_caller_tool_policy",
            &[
                "\"allowed_providers\": [\"openai\"]",
                "\"blocked_providers\": [\"openai\"]",
                "provider blocklist must take precedence over the allowlist",
                "world.vertex.captured().len(), before.1 + 1",
            ],
            |policy| {
                assert!(policy.is_provider_allowed("openai"));
                assert!(!policy.is_provider_allowed("vertex"));
            },
        ),
        PolicyEnforcementProof::RouteOverride => governed_key_e2e_test(
            "dynamic_record_enforces_model_provider_route_and_caller_tool_policy",
            &[
                "\"route_to_model\": \"gpt-route\"",
                "capture_json(&only_new_capture(&world, before))[\"model\"]",
                "provider must receive the effective routed model",
                "multipart provider body must contain the effective routed model",
            ],
            |policy| assert_eq!(policy.route_to_model.as_deref(), Some("gpt-4.1")),
        ),
        PolicyEnforcementProof::PrincipalGate => ai_dispatch_test(
            "dynamic_principal_selectors_gate_the_request_principal",
            &[
                "record.principal_selectors",
                "assert!(resolved.matches_principal(&matching))",
                "assert!(!resolved.matches_principal(&denied))",
            ],
            |policy| {
                let principal = sbproxy_plugin::Principal {
                    attrs: sbproxy_plugin::PrincipalAttrs {
                        team: Some("platform".into()),
                        ..Default::default()
                    },
                    ..sbproxy_plugin::Principal::anonymous()
                };
                assert!(policy.matches_principal(&principal));
            },
        ),
        PolicyEnforcementProof::PiiGuardrail => governed_key_e2e_test(
            "dynamic_record_enforces_model_provider_route_and_caller_tool_policy",
            &[
                "\"require_pii_redaction\": [\"email\"]",
                "assert!(forwarded.contains(\"[REDACTED:EMAIL]\")",
                "a key requiring an inactive PII rule must fail closed",
                "an inactive required PII rule must deny before dispatch",
            ],
            |policy| assert_eq!(policy.require_pii_redaction, ["email"]),
        ),
        PolicyEnforcementProof::ToolGate => governed_key_e2e_test(
            "dynamic_record_enforces_model_provider_route_and_caller_tool_policy",
            &[
                "\"allowed_tools\": [\"search\"]",
                "a caller tool outside the allowlist must be denied",
                "a malformed caller tool declaration must fail closed",
                "denied and malformed tool bodies must not reach a provider",
            ],
            |policy| {
                assert!(policy.is_tool_allowed("search"));
                assert!(!policy.is_tool_allowed("shell"));
            },
        ),
        PolicyEnforcementProof::ToolInjection => governed_key_e2e_test(
            "dynamic_record_enforces_model_provider_route_and_caller_tool_policy",
            &[
                "\"inject_tools\": [injected_tool.clone()]",
                "stored tool definitions must replace caller-supplied tools",
                "\"inject_mcp\": {",
                "assert_eq!(injected_names, [\"search\"])",
            ],
            |policy| {
                assert!(!policy.inject_tools.is_empty());
                assert_eq!(
                    policy.inject_mcp.as_ref().map(|mcp| mcp.reference.as_str()),
                    Some("internal-tools")
                );
            },
        ),
        PolicyEnforcementProof::PromptInjection => governed_key_e2e_test(
            "dynamic_record_enforces_prompt_rates_budget_and_safe_attribution",
            &[
                "body-aware prompt injection must block by default",
                "\"bypass_prompt_injection\": true",
                "the stored bypass bit must reach the body-aware evaluator",
                "a blocked prompt must not reach a provider body",
            ],
            |policy| assert!(!policy.bypass_prompt_injection),
        ),
        PolicyEnforcementProof::RateLimit => governed_key_e2e_test(
            "dynamic_record_enforces_prompt_rates_budget_and_safe_attribution",
            &[
                "\"max_requests_per_minute\": 1",
                "the dynamic RPM cap must block the second request",
                "\"max_tokens_per_minute\": 100",
                "recorded provider usage must exhaust the dynamic TPM cap",
            ],
            |policy| {
                assert_eq!(policy.max_requests_per_minute, Some(60));
                assert_eq!(policy.max_tokens_per_minute, Some(100_000));
            },
        ),
        PolicyEnforcementProof::Budget => governed_key_e2e_test(
            "dynamic_record_enforces_prompt_rates_budget_and_safe_attribution",
            &[
                "\"max_budget_tokens\": 100",
                "provider usage must exhaust the dynamic record budget",
                "\"max_budget_usd\": 0.000001",
                "recorded provider cost must exhaust the dynamic USD budget",
            ],
            |policy| {
                let budget = policy.budget.as_ref().unwrap();
                assert_eq!(budget.max_tokens, Some(1_000_000));
                assert_eq!(budget.max_cost_usd, Some(25.0));
            },
        ),
        PolicyEnforcementProof::AdmissionPriority => ai_dispatch_test(
            "dynamic_stored_key_priority_reaches_managed_model_admission",
            &[
                "record.priority = Some(\"interactive\".into())",
                "apply_resolved_key_lane(&mut context, &resolved)",
                "lane_class_for(context.ai_lane_priority)",
                "assert_eq!(admission, sbproxy_model_host::PriorityClass::Interactive)",
            ],
            |policy| assert_eq!(policy.priority, KeyPriority::Interactive),
        ),
    }
}

#[test]
fn every_policy_field_registers_a_concrete_enforcement_test() {
    let names = PolicyField::ALL
        .iter()
        .map(|field| field.wire_name())
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        [
            "display_name",
            "status",
            "expires_at",
            "tenant_id",
            "project",
            "user",
            "tags",
            "metadata",
            "allowed_models",
            "blocked_models",
            "allowed_providers",
            "blocked_providers",
            "route_to_model",
            "principal_selectors",
            "require_pii_redaction",
            "allowed_tools",
            "inject_tools",
            "inject_mcp",
            "bypass_prompt_injection",
            "max_requests_per_minute",
            "max_tokens_per_minute",
            "budget",
            "priority",
        ]
    );
    let policy = policy();
    let mut registered_assertions = std::collections::BTreeMap::new();
    for field in PolicyField::ALL {
        let proof = field.enforcement_proof();
        let registration = registered_enforcement_test(proof);
        let test_id = registration.test_id();
        (registration.assertion)(&policy);
        if let Some(existing) = registered_assertions.insert(proof.id(), test_id.clone()) {
            assert_eq!(
                existing,
                test_id,
                "proof {} has conflicting tests",
                proof.id()
            );
        }
    }
    assert_eq!(registered_assertions.len(), 14);
}

#[test]
fn registered_enforcement_tests_resolve_to_named_source_tests() {
    for field in PolicyField::ALL {
        let registration = registered_enforcement_test(field.enforcement_proof());
        let test_source = registration.named_test_source();
        assert!(
            ["assert!(", "assert_eq!(", "assert_ne!(", "assert_status("]
                .iter()
                .any(|marker| test_source.contains(marker)),
            "{} resolves to {} without an enforcement assertion",
            field.wire_name(),
            registration.test_id()
        );
        assert!(
            !registration.behavior_markers.is_empty(),
            "{} has no source behavior markers",
            field.wire_name()
        );
        for marker in registration.behavior_markers {
            assert!(
                test_source.contains(marker),
                "{} expects missing behavior marker {marker:?} in {}",
                field.wire_name(),
                registration.test_id()
            );
        }
    }
}

#[test]
fn descriptor_registry_matches_every_serialized_effective_policy_field() {
    let serialized = serde_json::to_value(policy()).unwrap();
    let mut serialized_policy_fields = serialized
        .as_object()
        .unwrap()
        .keys()
        .filter(|field| {
            !["schema_version", "key_id", "source", "policy_revision"].contains(&field.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    serialized_policy_fields.sort();

    let descriptors = PolicyField::descriptors();
    let mut descriptor_fields = descriptors
        .iter()
        .map(|descriptor| descriptor.wire_name.to_string())
        .collect::<Vec<_>>();
    descriptor_fields.sort();

    assert_eq!(descriptor_fields, serialized_policy_fields);
    assert_eq!(descriptors.len(), PolicyField::ALL.len());
    for (field, descriptor) in PolicyField::ALL.iter().zip(descriptors) {
        assert_eq!(descriptor.wire_name, field.wire_name());
        assert_eq!(descriptor.preview_field, field.wire_name());
        assert_eq!(descriptor.enforcement_proof, field.enforcement_proof().id());
        assert!(!descriptor.mutation.fields.is_empty());
    }
}

#[test]
fn descriptor_registry_encodes_non_obvious_mutation_and_clear_semantics() {
    let descriptors = PolicyField::descriptors();
    let descriptor = |wire_name: &str| {
        descriptors
            .iter()
            .find(|descriptor| descriptor.wire_name == wire_name)
            .unwrap_or_else(|| panic!("missing descriptor for {wire_name}"))
    };

    assert_eq!(
        serde_json::to_value(descriptor("display_name")).unwrap(),
        json!({
            "wire_name": "display_name",
            "mutation": {"kind": "patch", "fields": ["name"]},
            "editor": "text",
            "clear_semantics": "null",
            "preview_field": "display_name",
            "enforcement_proof": "attribution",
        })
    );
    assert_eq!(
        serde_json::to_value(descriptor("status")).unwrap(),
        json!({
            "wire_name": "status",
            "mutation": {
                "kind": "action",
                "fields": ["block", "unblock", "revoke"]
            },
            "editor": "lifecycle",
            "clear_semantics": "action_only",
            "preview_field": "status",
            "enforcement_proof": "lifecycle_gate",
        })
    );
    assert_eq!(descriptor("tenant_id").mutation.fields, ["tenant"]);
    assert_eq!(
        descriptor("budget").mutation.fields,
        ["max_budget_tokens", "max_budget_usd"]
    );
    assert_eq!(
        serde_json::to_value(descriptor("allowed_tools").clear_semantics).unwrap(),
        json!("null_means_unrestricted")
    );
    assert_eq!(
        serde_json::to_value(descriptor("priority").clear_semantics).unwrap(),
        json!("null_means_standard")
    );
}

#[test]
fn digest_is_stable_for_semantically_equivalent_set_order() {
    let first = policy();
    let mut reordered = first.clone();
    reordered.tags.reverse();
    reordered.allowed_models.reverse();
    reordered.allowed_providers.reverse();
    reordered.allowed_tools.as_mut().unwrap().reverse();

    assert_eq!(
        first.policy_digest().unwrap(),
        reordered.policy_digest().unwrap()
    );
    assert!(first.policy_digest().unwrap().starts_with("sha256:"));
}

#[test]
fn digest_changes_with_effective_behavior_but_not_revision() {
    let first = policy();
    let mut revision_only = first.clone();
    revision_only.policy_revision += 1;
    assert_eq!(
        first.policy_digest().unwrap(),
        revision_only.policy_digest().unwrap()
    );

    let mut changed = first.clone();
    changed.blocked_providers.push("openai".into());
    assert_ne!(
        first.policy_digest().unwrap(),
        changed.policy_digest().unwrap()
    );
}

#[test]
fn version_pairs_record_revision_with_the_effective_digest() {
    let policy = policy();
    let version = policy.policy_version().unwrap();

    assert_eq!(version.revision, 7);
    assert_eq!(version.digest, policy.policy_digest().unwrap());
}

#[test]
fn block_lists_take_precedence_over_allow_lists() {
    let policy = policy();

    assert!(policy.is_model_allowed("gpt-4.1"));
    assert!(!policy.is_model_allowed("gpt-4o"));
    assert!(!policy.is_model_allowed("claude-3.7"));
    assert!(policy.is_provider_allowed("openai"));
    assert!(!policy.is_provider_allowed("vertex"));
    assert!(!policy.is_provider_allowed("anthropic"));
}

#[test]
fn empty_allow_lists_allow_values_not_explicitly_blocked() {
    let mut policy = policy();
    policy.allowed_models.clear();
    policy.allowed_providers.clear();

    assert!(policy.is_model_allowed("claude-3.7"));
    assert!(policy.is_provider_allowed("anthropic"));
    assert!(!policy.is_model_allowed("gpt-4o"));
    assert!(!policy.is_provider_allowed("vertex"));
}

#[test]
fn tenant_resolution_inherits_or_accepts_the_origin_boundary() {
    assert_eq!(
        resolve_effective_tenant("tenant-a", None).unwrap(),
        "tenant-a"
    );
    assert_eq!(
        resolve_effective_tenant("tenant-a", Some("tenant-a")).unwrap(),
        "tenant-a"
    );
}

#[test]
fn tenant_resolution_rejects_cross_tenant_policy() {
    assert_eq!(
        resolve_effective_tenant("tenant-a", Some("tenant-b")),
        Err(TenantResolutionError::Mismatch {
            origin_tenant_id: "tenant-a".into(),
            key_tenant_id: "tenant-b".into(),
        })
    );
}

#[test]
fn lifecycle_status_and_expiry_determine_usability() {
    let mut policy = policy();
    assert!(policy.is_usable(now()));

    policy.status = EffectiveKeyStatus::Blocked;
    assert!(!policy.is_usable(now()));

    policy.status = EffectiveKeyStatus::Active;
    policy.expires_at = Some(now());
    assert!(!policy.is_usable(now()));
}

#[test]
fn serialized_effective_policy_has_no_secret_or_hash_fields() {
    let value = serde_json::to_value(policy()).unwrap();
    let object = value.as_object().unwrap();

    for forbidden in [
        "key",
        "token",
        "secret",
        "secret_hash",
        "prev_secret_hash",
        "hash_alg",
    ] {
        assert!(!object.contains_key(forbidden), "found {forbidden}");
    }
    assert_eq!(object.get("key_id"), Some(&json!("key_01")));
}

#[test]
fn configured_key_with_public_id_lowers_without_bearer_material() {
    let key: VirtualKeyConfig = serde_json::from_value(json!({
        "key": "sk-live-bearer-material",
        "key_id": "cfg:tenant-a:ai.local:production",
        "name": "production",
        "allowed_models": ["gpt-4.1"],
        "blocked_providers": ["vertex"],
        "allowed_tools": [],
        "max_requests_per_minute": 60,
        "priority": "interactive",
        "project": "search",
        "inject_mcp": {"ref": "internal-tools", "filter": ["search*"]}
    }))
    .expect("configured virtual key");

    let effective = EffectiveKeyPolicy::from_configured_key(&key, "tenant-a")
        .expect("public key id is governed");

    assert_eq!(effective.source, EffectiveKeySource::Config);
    assert_eq!(effective.policy_revision, 1);
    assert_eq!(effective.status, EffectiveKeyStatus::Active);
    assert_eq!(effective.tenant_id, "tenant-a");
    assert_eq!(effective.allowed_tools, Some(Vec::new()));
    assert_eq!(effective.priority, KeyPriority::Interactive);
    assert_eq!(
        effective
            .inject_mcp
            .as_ref()
            .map(|mcp| mcp.reference.as_str()),
        Some("internal-tools")
    );

    let serialized = serde_json::to_string(&effective).expect("effective policy JSON");
    assert!(!serialized.contains("sk-live-bearer-material"));
}

#[test]
fn configured_key_without_public_id_remains_legacy_and_ungoverned() {
    let key: VirtualKeyConfig = serde_json::from_value(json!({
        "key": "legacy-bearer",
        "name": "legacy"
    }))
    .expect("legacy virtual key");

    assert!(EffectiveKeyPolicy::from_configured_key(&key, "tenant-a").is_none());
}

#[test]
fn effective_principal_and_tool_predicates_preserve_policy_semantics() {
    let mut effective = policy();
    effective.principal_selectors = vec![PrincipalSelector {
        team: Some("platform".into()),
        ..PrincipalSelector::default()
    }];
    effective.allowed_tools = Some(vec!["search".into()]);
    let matching = sbproxy_plugin::Principal {
        attrs: sbproxy_plugin::PrincipalAttrs {
            team: Some("platform".into()),
            ..Default::default()
        },
        ..sbproxy_plugin::Principal::anonymous()
    };
    let other = sbproxy_plugin::Principal {
        attrs: sbproxy_plugin::PrincipalAttrs {
            team: Some("finance".into()),
            ..Default::default()
        },
        ..sbproxy_plugin::Principal::anonymous()
    };

    assert!(effective.matches_principal(&matching));
    assert!(!effective.matches_principal(&other));
    assert!(effective.is_tool_allowed("search"));
    assert!(!effective.is_tool_allowed("shell"));

    effective.allowed_tools = None;
    assert!(effective.is_tool_allowed("shell"));
}
