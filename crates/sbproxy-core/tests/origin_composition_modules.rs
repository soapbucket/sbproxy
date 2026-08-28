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
        upstream: https://checkout.internal
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
