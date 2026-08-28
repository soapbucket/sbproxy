// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The composition resolver against the real module parsers (WOR-2434).
//!
//! `sbproxy-config` cannot depend on `sbproxy-modules`, so the claim
//! that composition strips its bookkeeping keys can only be proved from
//! a crate that sees both. It matters because the modules the four
//! merged lists feed are `#[serde(deny_unknown_fields)]`: a surviving
//! `name:` on a composed `rate_limit_budget` policy is not a cosmetic
//! wart, it is a boot failure on every node, long after the compose that
//! put it there.

use std::collections::BTreeSet;

use sbproxy_config::origin_profile::{resolve_origins, ProfileBinding};
use sbproxy_config::types::OriginSourceEntry;
use sbproxy_core::rate_limit_budget::RateLimitBudgetPolicy;

const ENTRY: &str = r#"
name: checkout
repo: https://git.test/acme/checkout
revision: refs/tags/v1.4.2
path: sbproxy/origin.yaml
hosts:
  api: ["checkout.acme.test"]
"#;

/// A platform floor that names the policy and locks nothing, so the
/// project may override it.
const FLOOR: &str = r#"
policies:
  - name: budget
    type: rate_limit_budget
    headers:
      enabled: true
      include_retry_after: true
      include_ratelimit_policy: true
"#;

/// The project changes one header preference and nothing else.
const PROFILE: &str = r#"
name: checkout
spec:
  api:
    base:
      action:
        type: proxy
        url: https://checkout.internal
      policies:
        - name: budget
          headers:
            include_retry_after: false
"#;

#[test]
fn a_composed_rate_limit_budget_policy_parses_through_the_real_module() {
    let entry: OriginSourceEntry = serde_yaml::from_str(ENTRY).expect("entry parses");
    let floor: serde_yaml::Mapping = serde_yaml::from_str(FLOOR).expect("floor parses");
    let resolution = resolve_origins(
        Some(&floor),
        &[ProfileBinding {
            entry: &entry,
            document: PROFILE,
            commit: None,
        }],
        &BTreeSet::new(),
    )
    .expect("composition succeeds");

    let origin = resolution
        .origins
        .get("checkout.acme.test")
        .expect("the origin composed");
    assert_eq!(origin.policies.len(), 1, "merged by name, not appended");

    // The claim under test. `RateLimitBudgetPolicy::from_config` is
    // `deny_unknown_fields`, so a surviving `name:` fails here.
    let policy = RateLimitBudgetPolicy::from_config(origin.policies[0].clone())
        .expect("the composed policy must parse through the module that owns it");
    assert!(
        policy.headers_enabled(),
        "the floor's field the project never mentioned survived"
    );
    assert!(!policy.include_retry_after(), "the project's field won");
    assert!(
        policy.include_ratelimit_policy(),
        "the floor's other field survived"
    );
}

/// The same policy with the bookkeeping keys left in, to show the module
/// really would have refused it. Without this the test above could pass
/// because `from_config` is lenient rather than because the strip works.
#[test]
fn the_same_policy_with_its_bookkeeping_left_in_is_refused_by_the_module() {
    for key in ["name", "locked", "disabled"] {
        let mut value = serde_json::json!({
            "type": "rate_limit_budget",
            "headers": {"enabled": true}
        });
        value[key] = serde_json::json!("anything");
        assert!(
            RateLimitBudgetPolicy::from_config(value).is_err(),
            "`{key}` must be refused by the module, or the strip proves nothing"
        );
    }
}

/// The gauge is written for every tier every time a pipeline is applied,
/// including the apply where the block is gone.
///
/// The reading the dashboard panel and `docs/configuration.md` both tell
/// an operator to alert on is "the total dropped to zero", and the one
/// after it is "a non-zero `pinned=false` under `tier=production`". Both
/// are transitions *out* of a state, so a gauge only written for the tier
/// in force could never produce either.
///
/// Driven through `load_pipeline`, not `compile_config`, and that is the
/// point. `compile_config` also validates candidate documents:
/// `ConfigAuthority::publish` runs it on a payload, and a payload can
/// never carry `origin_sources` because the path is denied to an
/// authority. Writing there meant every publish zeroed all four series,
/// which is precisely the page this metric exists to raise
/// (WOR-2432 re-review N1). The second half of this test is that
/// regression: compile a payload-shaped document and assert the live
/// series are untouched.
#[test]
fn the_entry_gauge_follows_the_applied_pipeline_and_not_a_candidate_compile() {
    fn series() -> std::collections::BTreeMap<(String, String), i64> {
        let mut out = std::collections::BTreeMap::new();
        for family in prometheus::gather() {
            if family.name() != "sbproxy_origin_source_entries" {
                continue;
            }
            for metric in family.get_metric() {
                let mut tier = String::new();
                let mut pinned = String::new();
                for label in metric.get_label() {
                    match label.name() {
                        "tier" => tier = label.value().to_string(),
                        "pinned" => pinned = label.value().to_string(),
                        _ => {}
                    }
                }
                out.insert(
                    (tier, pinned),
                    metric.get_gauge().value.unwrap_or_default() as i64,
                );
            }
        }
        out
    }

    fn apply(yaml: &str) {
        let compiled = sbproxy_config::compile_config(yaml).expect("the document compiles");
        let pipeline =
            sbproxy_core::pipeline::CompiledPipeline::from_config_for_validation(compiled)
                .expect("the document constructs");
        sbproxy_core::reload::load_pipeline(pipeline);
    }

    let with_block = "origins: {}\norigin_sources:\n  tier: production\n  entries:\n    \
                      - name: checkout\n      repo: https://git.test/acme/checkout\n      \
                      revision: refs/tags/v1.4.2\n      path: sbproxy/origin.yaml\n";
    apply(with_block);
    let after_declaration = series();
    assert_eq!(
        after_declaration.get(&("production".to_string(), "true".to_string())),
        Some(&1),
        "{after_declaration:?}"
    );
    // Every other series exists and reads zero, so an alert on
    // `pinned="false"` has something to be false about.
    for key in [
        ("production", "false"),
        ("development", "true"),
        ("development", "false"),
    ] {
        assert_eq!(
            after_declaration.get(&(key.0.to_string(), key.1.to_string())),
            Some(&0),
            "{key:?} missing from {after_declaration:?}"
        );
    }

    // A candidate compile must not touch the live series. This is the
    // exact shape an authority payload has: no `origin_sources`, because
    // the path is denied to it.
    sbproxy_config::compile_config("origins: {}\n").expect("a candidate compiles");
    assert_eq!(
        series(),
        after_declaration,
        "compiling a candidate document moved the live series"
    );

    // Applying a document with the block deleted is the transition the
    // panel description names, and every series has to fall to zero.
    apply("origins: {}\n");
    let after_removal = series();
    assert!(!after_removal.is_empty(), "the series must still exist");
    for (key, value) in &after_removal {
        assert_eq!(
            *value, 0,
            "`{key:?}` kept a stale reading after the block was removed: {after_removal:?}"
        );
    }
}
