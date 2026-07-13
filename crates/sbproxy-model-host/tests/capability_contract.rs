// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::collections::BTreeSet;

use sbproxy_model_host::{
    capability_registry, CapabilityDomain, ModelHostConfig, SupportLevel,
    CAPABILITY_REGISTRY_VERSION,
};

#[test]
fn registry_covers_every_domain_and_validates() {
    let registry = capability_registry();

    assert_eq!(registry.version(), CAPABILITY_REGISTRY_VERSION);
    registry
        .validate()
        .expect("the built-in capability registry must be internally consistent");

    let actual: BTreeSet<_> = registry
        .entries()
        .iter()
        .map(|entry| entry.domain)
        .collect();
    let expected = BTreeSet::from([
        CapabilityDomain::Manifest,
        CapabilityDomain::Artifact,
        CapabilityDomain::Engine,
        CapabilityDomain::Lifecycle,
        CapabilityDomain::Cluster,
        CapabilityDomain::Policy,
        CapabilityDomain::Admin,
        CapabilityDomain::Platform,
    ]);
    assert_eq!(actual, expected);
}

#[test]
fn model_host_capabilities_match_the_cluster_control_plane_boundary() {
    let registry = capability_registry();
    let status = |id: &str| {
        registry
            .entries()
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("missing capability {id}"))
            .status
    };

    for id in [
        "manifest.canonical_desired_state",
        "artifact.exact_removal",
        "engine.typed_managed_drivers",
        "lifecycle.atomic_reconciliation",
        "lifecycle.keep_alive",
        "lifecycle.priority_admission",
        "lifecycle.model_cli",
        "cluster.managed_replicas",
        "admin.model_status",
        "admin.model_management",
        "platform.apple_metal",
    ] {
        assert_eq!(status(id), SupportLevel::Stable, "{id}");
    }
    for id in [
        "engine.vllm_uv",
        "engine.vllm_container",
        "platform.nvidia_cuda",
    ] {
        assert_eq!(status(id), SupportLevel::Preview, "{id}");
    }
    for id in ["cluster.remote_dispatch"] {
        assert_eq!(status(id), SupportLevel::Unsupported, "{id}");
    }
}

#[test]
fn every_stable_claim_has_executable_evidence() {
    let registry = capability_registry();

    for entry in registry
        .entries()
        .iter()
        .filter(|entry| entry.status == SupportLevel::Stable)
    {
        let consumer = entry.consumer.unwrap_or_else(|| {
            panic!(
                "stable capability {} must own an executable consumer contract",
                entry.id
            )
        });
        assert!(
            entry.evidence.contains(&consumer.id()),
            "stable capability {} must name its consumer {} as evidence",
            entry.id,
            consumer.id()
        );
        consumer
            .assert_behavior()
            .unwrap_or_else(|error| panic!("{} ({}): {error}", entry.id, consumer.id()));
    }

    for field in registry
        .config_fields()
        .iter()
        .filter(|field| field.status == SupportLevel::Stable)
    {
        let capability = registry
            .entries()
            .iter()
            .find(|entry| entry.id == field.capability_id)
            .expect("validated field capability exists");
        assert_eq!(
            capability.status,
            SupportLevel::Stable,
            "stable field {} cannot belong to non-stable capability {}",
            field.path,
            field.capability_id
        );
        let consumer = field.consumer.unwrap_or_else(|| {
            panic!(
                "stable config field {} must name a consumer contract",
                field.path
            )
        });
        consumer
            .assert_behavior()
            .unwrap_or_else(|error| panic!("{} ({}): {error}", field.path, consumer.id()));
    }
}

#[test]
fn configured_preview_fields_are_reported_by_validation() {
    let config: ModelHostConfig = serde_yaml::from_str(
        "\
engines:
  vllm:
    launch: container
    image: vllm/vllm-openai:v0.24.0
models:
  - model: qwen3-8b
    keep_alive: 30m
",
    )
    .expect("fixture parses");

    let findings = capability_registry().validate_config(&config);
    assert!(findings.iter().any(|finding| {
        finding.path == "serve.engines" && finding.status == SupportLevel::Preview
    }));
    assert!(!findings
        .iter()
        .any(|finding| finding.path == "serve.models[].keep_alive"));
    assert!(findings
        .iter()
        .all(|finding| finding.message.contains(finding.status.as_str())));
}

#[test]
fn model_host_config_exposes_the_same_capability_findings() {
    let config: ModelHostConfig =
        serde_yaml::from_str("models:\n  - model: qwen3-8b\n    keep_alive: 30m\n")
            .expect("fixture parses");

    assert_eq!(
        config.capability_findings(),
        capability_registry().validate_config(&config)
    );
}

#[test]
fn minimal_stable_config_has_no_capability_findings() {
    let config: ModelHostConfig =
        serde_yaml::from_str("models:\n  - model: qwen3-8b\n").expect("fixture parses");

    assert!(capability_registry().validate_config(&config).is_empty());
}

#[test]
fn markdown_is_deterministic_and_exposes_all_support_levels() {
    let first = capability_registry().render_markdown();
    let second = capability_registry().render_markdown();

    assert_eq!(first, second);
    assert!(first.starts_with("# Model-host capability matrix\n*Last modified: 2026-07-12*\n"));
    assert!(first.contains("Registry version: `1`"));
    for status in ["stable", "preview", "config_only", "unsupported"] {
        assert!(first.contains(&format!("`{status}`")), "missing {status}");
    }
    assert!(
        !first.contains('\u{2014}'),
        "generated docs must not use em dashes"
    );
}

#[test]
fn generated_schema_labels_every_nonstable_field() {
    capability_registry()
        .validate_schema_descriptions()
        .expect("preview, config-only, and unsupported fields must be labeled in JSON Schema");
}

#[test]
fn generator_binary_prints_the_registry_markdown_exactly() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_generate-model-host-capabilities"))
        .output()
        .expect("run capability generator");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).expect("generator output is UTF-8"),
        capability_registry().render_markdown()
    );
}
