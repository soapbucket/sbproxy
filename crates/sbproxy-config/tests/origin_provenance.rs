// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Composition provenance (WOR-2440): which layer and which entry set
//! each leaf of a composed origin.
//!
//! The question this answers is "why is this policy here", once an
//! origin is the product of four layers and two repositories. The answer
//! decides who a security engineer talks to, so getting the layer wrong
//! is worse than having no answer at all.
//!
//! Pure, like the resolver it tests: no git, no network, no filesystem.

use std::collections::BTreeSet;

use sbproxy_config::config_merge::Provenance;
use sbproxy_config::origin_profile::{
    resolve_origins, CompositionLayer, CompositionProvenance, ProfileBinding,
};
use sbproxy_config::types::OriginSourceEntry;

// --- fixtures ---------------------------------------------------------

const FLOOR: &str = r#"
policies:
  - name: waf
    type: waf
    locked: true
    owasp_crs:
      enabled: true
    action_on_match: block
  - name: rate_limit
    type: rate_limiting
    requests_per_minute: 100
    burst: 20
  - name: legacy_body_cap
    type: request_limit
    max_body_size: 1024
"#;

const PROFILE: &str = r#"
name: checkout
spec:
  api:
    base:
      action:
        type: proxy
        url: https://checkout.internal
      policies:
        - name: rate_limit
          requests_per_minute: 600
        - name: legacy_body_cap
          disabled: true
        - name: project_concurrency
          type: concurrent_limit
          max_concurrent: 32
    environments:
      prod:
        action:
          host_override: checkout.prod.internal
"#;

const ENTRY: &str = r#"
name: checkout
repo: https://git.test/acme/checkout
revision: refs/tags/v1.4.2
path: sbproxy/origin.yaml
environment: prod
hosts:
  api: ["checkout.acme.test"]
overrides:
  policies:
    - name: rate_limit
      burst: 999
"#;

fn entry(yaml: &str) -> OriginSourceEntry {
    serde_yaml::from_str(yaml).expect("entry fixture parses")
}

fn defaults(yaml: &str) -> serde_yaml::Mapping {
    serde_yaml::from_str(yaml).expect("defaults fixture parses")
}

/// Compose the four-layer fixture and hand back the host's provenance.
fn compose(commit: Option<&str>) -> (sbproxy_config::OriginResolution, CompositionProvenance) {
    let entry = entry(ENTRY);
    let floor = defaults(FLOOR);
    let resolution = resolve_origins(
        Some(&floor),
        &[ProfileBinding {
            entry: &entry,
            document: PROFILE,
            commit,
        }],
        &BTreeSet::new(),
    )
    .expect("composition succeeds");
    let provenance = resolution
        .provenance
        .get("checkout.acme.test")
        .expect("every composed host carries provenance")
        .clone();
    (resolution, provenance)
}

// --- the acceptance lines ---------------------------------------------

#[test]
fn every_leaf_of_a_composed_origin_names_the_layer_that_set_it() {
    let (_, provenance) = compose(Some("abc123def456abc123def456abc123def456abcd"));
    assert!(
        provenance.unattributed().is_empty(),
        "a composed leaf no layer claims means the derivation and the merge have diverged: {:?}",
        provenance.unattributed()
    );

    // One leaf per layer, so all four are proved rather than the two a
    // simple fixture would reach.
    let waf = provenance
        .get("policies[waf].action_on_match")
        .expect("the floor's WAF is attributed");
    assert_eq!(waf.layer, CompositionLayer::OriginDefaults);
    assert_eq!(waf.entry, None, "no entry owns the platform floor");
    assert_eq!(waf.source, None, "and it came from no project repository");

    let url = provenance
        .get("action.url")
        .expect("the project's action is attributed");
    assert_eq!(url.layer, CompositionLayer::ProfileBase);
    assert_eq!(url.entry.as_deref(), Some("checkout"));
    assert_eq!(url.profile.as_deref(), Some("checkout"));
    assert_eq!(
        url.source,
        Some(Provenance::Git {
            repo: "https://git.test/acme/checkout".to_string(),
            reference: "refs/tags/v1.4.2".to_string(),
            commit: "abc123def456abc123def456abc123def456abcd".to_string(),
        }),
        "the repository and the resolved sha are on the leaf"
    );

    let host_override = provenance
        .get("action.host_override")
        .expect("the environment layer is attributed");
    assert_eq!(
        host_override.layer,
        CompositionLayer::ProfileEnvironment {
            environment: "prod".to_string()
        }
    );

    let burst = provenance
        .get("policies[rate_limit].burst")
        .expect("the entry override is attributed");
    assert_eq!(burst.layer, CompositionLayer::EntryOverride);
    assert_eq!(burst.entry.as_deref(), Some("checkout"));
    assert_eq!(
        burst.profile, None,
        "an overrides block is runtime YAML, so crediting the profile would blame a repository \
         for a line the platform wrote"
    );
}

#[test]
fn provenance_covers_exactly_the_leaves_the_composed_origin_carries() {
    // The guard on the whole approach: attribution is derived from the
    // layers rather than stamped as the merge runs, so the check that
    // the two agree is that the path set is exactly the composed
    // document's own, both directions.
    //
    // `resolution.composed` is what an aggregator publishes, so this is
    // a claim about the document a node receives and not about an
    // in-memory struct. The typed `origins` half is deliberately not
    // used: `RawOriginConfig` serializes all fifty-two of its fields,
    // and the forty-odd nobody authored have no layer to attribute.
    let (resolution, provenance) = compose(None);
    let composed = resolution
        .composed
        .get("checkout.acme.test")
        .expect("composed");
    let composed_leaves = count_leaves(&serde_yaml::Value::Mapping(composed.clone()));
    assert!(
        composed_leaves > 10,
        "the fixture has to be rich enough for this to mean anything; got {composed_leaves}"
    );
    assert_eq!(
        provenance.len(),
        composed_leaves,
        "every composed leaf is attributed and nothing else is; paths were {:?}",
        provenance.paths().collect::<Vec<_>>()
    );
    assert_eq!(
        provenance.paths().collect::<Vec<_>>(),
        vec![
            "action.host_override",
            "action.type",
            "action.url",
            "policies[project_concurrency].max_concurrent",
            "policies[project_concurrency].type",
            "policies[rate_limit].burst",
            "policies[rate_limit].requests_per_minute",
            "policies[rate_limit].type",
            "policies[waf].action_on_match",
            "policies[waf].owasp_crs.enabled",
            "policies[waf].type",
        ],
        "the merged lists are keyed by `name:` rather than by index, because an index moves \
         whenever an earlier entry is dropped and an audit trail that renumbered itself between \
         two composes would be worse than none"
    );
}

/// Count the leaves of a composed origin mapping under the same rule the
/// provenance walk uses: a non-empty mapping recurses, everything else
/// is a leaf, and the four merged lists have their elements walked.
fn count_leaves(value: &serde_yaml::Value) -> usize {
    match value {
        serde_yaml::Value::Mapping(map) if !map.is_empty() => {
            map.iter().map(|(_, child)| count_leaves(child)).sum()
        }
        // Only the four merged lists have walked elements; the composed
        // origin's other sequences are leaves. Both shapes reduce to the
        // same arithmetic here because a merged list's elements are
        // mappings and an ordinary sequence's are not.
        serde_yaml::Value::Sequence(items)
            if !items.is_empty() && items.iter().all(serde_yaml::Value::is_mapping) =>
        {
            items.iter().map(count_leaves).sum()
        }
        _ => 1,
    }
}

#[test]
fn a_dropped_default_records_the_layer_that_dropped_it_and_the_one_that_introduced_it() {
    let (resolution, provenance) = compose(None);
    assert_eq!(resolution.drops.len(), 1, "one default was switched off");
    let drop = &resolution.drops[0];
    assert_eq!(drop.name, "legacy_body_cap");
    assert_eq!(drop.list, "policies");
    assert_eq!(
        drop.dropped_by,
        CompositionLayer::ProfileBase,
        "the project's base layer is what carried `disabled: true`"
    );
    assert_eq!(
        drop.introduced_by,
        Some(CompositionLayer::OriginDefaults),
        "and an absence explains nothing on its own, so the layer that had it is recorded too"
    );
    assert_eq!(
        provenance.drops(),
        resolution.drops.as_slice(),
        "the per-host provenance carries the same record the resolution does"
    );
    assert!(
        provenance
            .get("policies[legacy_body_cap].max_body_size")
            .is_none(),
        "a dropped policy has no surviving leaves"
    );
}

#[test]
fn a_field_level_override_reports_per_field_so_surviving_defaults_are_attributable() {
    let (_, provenance) = compose(None);
    // The floor set both fields; the project rewrote one and the entry
    // rewrote the other. Reporting per policy would credit one layer
    // with all three and lose exactly the fact somebody needs.
    assert_eq!(
        provenance
            .get("policies[rate_limit].requests_per_minute")
            .map(|leaf| leaf.layer.clone()),
        Some(CompositionLayer::ProfileBase),
        "the project overrode this field"
    );
    assert_eq!(
        provenance
            .get("policies[rate_limit].burst")
            .map(|leaf| leaf.layer.clone()),
        Some(CompositionLayer::EntryOverride),
        "and the runtime overrode that one"
    );
    assert_eq!(
        provenance
            .get("policies[rate_limit].type")
            .map(|leaf| leaf.layer.clone()),
        Some(CompositionLayer::OriginDefaults),
        "while the field nobody touched still names the floor"
    );
}

#[test]
fn provenance_renders_for_a_human_without_a_json_tool() {
    let (_, provenance) = compose(Some("abc123def456abc123def456abc123def456abcd"));
    let rendered = provenance.render("checkout.acme.test");
    assert!(rendered.starts_with("checkout.acme.test\n"));
    assert!(
        rendered.contains("action.url") && rendered.contains("spec.base"),
        "a leaf and its layer are on one line: {rendered}"
    );
    assert!(
        rendered.contains("entry checkout"),
        "and so is the entry that deployed it"
    );
    assert!(
        rendered.contains("https://git.test/acme/checkout@abc123def456"),
        "and the repository at its shortened resolved sha: {rendered}"
    );
    assert!(
        rendered.contains("dropped policies[legacy_body_cap]")
            && rendered.contains("introduced by origin_defaults"),
        "the drop reads as a sentence rather than as an absence: {rendered}"
    );
    assert!(
        rendered.contains("spec.environments[prod]"),
        "the environment layer names which environment: {rendered}"
    );
}

#[test]
fn provenance_carries_no_value_only_a_path_and_a_layer() {
    // The acceptance line asks that a leaf whose value is a resolved
    // secret reference never reports the resolved material. This carries
    // no values at all, which is the stronger claim, so the assertion is
    // that the reference itself is absent from every rendering.
    let profile = r#"
name: checkout
inputs:
  - name: api_key
    description: the key callers present
spec:
  api:
    base:
      action:
        type: proxy
        url: https://checkout.internal
      authentication:
        type: api_key
        api_keys:
          - "{{vars.api_key}}"
"#;
    let entry_yaml = r#"
name: checkout
repo: https://git.test/acme/checkout
path: sbproxy/origin.yaml
inputs:
  api_key: "secret://vault/checkout-api-key"
hosts:
  api: ["checkout.acme.test"]
"#;
    let entry = entry(entry_yaml);
    let resolution = resolve_origins(
        None,
        &[ProfileBinding {
            entry: &entry,
            document: profile,
            commit: Some("abc123def456abc123def456abc123def456abcd"),
        }],
        &BTreeSet::new(),
    )
    .expect("composes");
    let provenance = resolution
        .provenance
        .get("checkout.acme.test")
        .expect("composed");
    // The value really is in the composed origin, so this is not passing
    // because the fixture never carried one.
    let origin = serde_yaml::to_string(
        resolution
            .origins
            .get("checkout.acme.test")
            .expect("composed"),
    )
    .expect("serializes");
    assert!(
        origin.contains("secret://vault/checkout-api-key"),
        "the composed origin carries the reference: {origin}"
    );

    let rendered = provenance.render("checkout.acme.test");
    let json = serde_json::to_string(provenance).expect("provenance serializes");
    for surface in [&rendered, &json] {
        assert!(
            !surface.contains("secret://vault/checkout-api-key"),
            "provenance must carry no leaf value: {surface}"
        );
    }
    assert!(
        rendered.contains("authentication.api_keys"),
        "the path is still reported, which is what makes the absence a design and not a gap: \
         {rendered}"
    );
}

#[test]
fn provenance_is_identical_whether_a_commit_was_resolved_or_not() {
    // The offline path composes documents read off disk and the publish
    // path composes documents read from a repository. Everything but the
    // commit has to agree, or `--out` and publish would disagree about
    // who owns a policy.
    let (_, resolved) = compose(Some("abc123def456abc123def456abc123def456abcd"));
    let (_, offline) = compose(None);
    let with_commit: Vec<(&str, CompositionLayer)> = resolved
        .iter()
        .map(|(path, leaf)| (path.as_str(), leaf.layer.clone()))
        .collect();
    let without: Vec<(&str, CompositionLayer)> = offline
        .iter()
        .map(|(path, leaf)| (path.as_str(), leaf.layer.clone()))
        .collect();
    assert_eq!(with_commit, without, "the layers agree path for path");
    assert_eq!(
        offline
            .get("action.url")
            .and_then(|leaf| leaf.source.clone()),
        Some(Provenance::Git {
            repo: "https://git.test/acme/checkout".to_string(),
            reference: "refs/tags/v1.4.2".to_string(),
            commit: "(unresolved)".to_string(),
        }),
        "and an unresolved commit says so rather than reporting an empty string"
    );
}

#[test]
fn an_unnamed_list_entry_is_attributed_to_the_layer_that_wrote_it() {
    // Unnamed entries are always appended and never merged, so their
    // index in the composed list is a position the merge produced rather
    // than one any layer wrote. They are matched by value instead, and
    // this is the test that keeps that path honest.
    // The floor's entry is named, because `validate_origin_defaults`
    // refuses an unnamed one: a default has to be addressable to be
    // overridable. Only a project layer can append an unnamed entry.
    let floor = r#"
response_modifiers:
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
      action:
        type: proxy
        url: https://checkout.internal
      response_modifiers:
        - headers:
            set:
              X-Service: checkout
"#;
    let entry = entry(
        r#"
name: checkout
repo: https://git.test/acme/checkout
path: sbproxy/origin.yaml
hosts:
  api: ["checkout.acme.test"]
"#,
    );
    let floor = defaults(floor);
    let resolution = resolve_origins(
        Some(&floor),
        &[ProfileBinding {
            entry: &entry,
            document: profile,
            commit: None,
        }],
        &BTreeSet::new(),
    )
    .expect("composes");
    let provenance = resolution
        .provenance
        .get("checkout.acme.test")
        .expect("composed");
    assert!(
        provenance.unattributed().is_empty(),
        "an unnamed entry is still attributed: {:?}",
        provenance.unattributed()
    );
    let platform = provenance
        .iter()
        .find(|(path, _)| path.contains("X-Platform"))
        .map(|(_, leaf)| leaf.layer.clone());
    let service = provenance
        .iter()
        .find(|(path, _)| path.contains("X-Service"))
        .map(|(_, leaf)| leaf.layer.clone());
    assert_eq!(platform, Some(CompositionLayer::OriginDefaults));
    assert_eq!(service, Some(CompositionLayer::ProfileBase));
}
