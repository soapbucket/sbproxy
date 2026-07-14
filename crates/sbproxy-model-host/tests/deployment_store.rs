// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::collections::BTreeMap;
use std::fs;

use sbproxy_model_host::{
    DeploymentRevisionDraft, DeploymentSourceMode, DeploymentStoreError, EngineChoice,
    FileDeploymentRevisionStore, ModelDeployment, PullPolicy, RolloutPolicy,
    DEPLOYMENT_SCHEMA_VERSION,
};
use tempfile::tempdir;

fn deployment(model: &str) -> ModelDeployment {
    ModelDeployment {
        model: model.to_string(),
        variant: Some("q4_k_m".to_string()),
        heterogeneous_variants: false,
        replicas: 1,
        required_labels: BTreeMap::new(),
        spread_by: Vec::new(),
        pull: PullPolicy::OnDemand,
        warm: false,
        cold_start: sbproxy_model_host::ColdStartPolicy::Wait,
        keep_alive_secs: None,
        max_concurrency: Some(8),
        max_queue_depth: 128,
        queue_timeout_ms: 30_000,
        engine: EngineChoice::Auto,
        rollout: RolloutPolicy::Rolling,
    }
}

fn draft(mode: DeploymentSourceMode) -> DeploymentRevisionDraft {
    DeploymentRevisionDraft {
        source_mode: mode,
        source_revision: "operator-change-1".to_string(),
        catalog_revision: "builtin-2026-07-10".to_string(),
        deployments: BTreeMap::from([(
            "assistant".to_string(),
            deployment("qwen2.5-0.5b-instruct"),
        )]),
    }
}

#[test]
fn all_authority_modes_share_one_canonical_revision_contract() {
    for mode in [
        DeploymentSourceMode::AdminManaged,
        DeploymentSourceMode::FileManaged,
        DeploymentSourceMode::ClusterAuthority,
    ] {
        let revision = draft(mode)
            .into_revision(7)
            .expect("valid authority revision");
        assert_eq!(revision.schema_version, DEPLOYMENT_SCHEMA_VERSION);
        assert_eq!(revision.revision, 7);
        assert_eq!(revision.source_mode, mode);
        assert_eq!(revision.content_digest.len(), 64);
        revision.validate().expect("stored revision validates");
    }
}

#[test]
fn content_digest_is_stable_across_map_insertion_order_and_reload() {
    let first = DeploymentRevisionDraft {
        deployments: BTreeMap::from([
            ("alpha".to_string(), deployment("model-a")),
            ("beta".to_string(), deployment("model-b")),
        ]),
        ..draft(DeploymentSourceMode::FileManaged)
    }
    .into_revision(12)
    .expect("first revision");

    let mut reverse = BTreeMap::new();
    reverse.insert("beta".to_string(), deployment("model-b"));
    reverse.insert("alpha".to_string(), deployment("model-a"));
    let second = DeploymentRevisionDraft {
        deployments: reverse,
        ..draft(DeploymentSourceMode::FileManaged)
    }
    .into_revision(12)
    .expect("second revision");

    assert_eq!(first.content_digest, second.content_digest);
    let encoded = serde_json::to_vec(&first).expect("serialize revision");
    let decoded = serde_json::from_slice::<sbproxy_model_host::DeploymentRevision>(&encoded)
        .expect("deserialize revision");
    assert_eq!(decoded, first);
    decoded.validate().expect("reloaded digest matches");
}

#[test]
fn invalid_deployments_and_unpinned_replicas_are_rejected() {
    let cases = [
        ("empty source revision", {
            let mut value = draft(DeploymentSourceMode::AdminManaged);
            value.source_revision.clear();
            value
        }),
        ("empty catalog revision", {
            let mut value = draft(DeploymentSourceMode::AdminManaged);
            value.catalog_revision.clear();
            value
        }),
        ("invalid deployment id", {
            let mut value = draft(DeploymentSourceMode::AdminManaged);
            value.deployments = BTreeMap::from([(
                "../assistant".to_string(),
                deployment("qwen2.5-0.5b-instruct"),
            )]);
            value
        }),
        ("empty model", {
            let mut value = draft(DeploymentSourceMode::AdminManaged);
            value
                .deployments
                .get_mut("assistant")
                .unwrap()
                .model
                .clear();
            value
        }),
        ("zero replicas", {
            let mut value = draft(DeploymentSourceMode::AdminManaged);
            value.deployments.get_mut("assistant").unwrap().replicas = 0;
            value
        }),
        ("zero concurrency", {
            let mut value = draft(DeploymentSourceMode::AdminManaged);
            value
                .deployments
                .get_mut("assistant")
                .unwrap()
                .max_concurrency = Some(0);
            value
        }),
        ("blank variant", {
            let mut value = draft(DeploymentSourceMode::AdminManaged);
            value.deployments.get_mut("assistant").unwrap().variant = Some(" ".to_string());
            value
        }),
        ("duplicate spread label", {
            let mut value = draft(DeploymentSourceMode::AdminManaged);
            value.deployments.get_mut("assistant").unwrap().spread_by =
                vec!["zone".to_string(), "zone".to_string()];
            value
        }),
        ("unpinned replicas", {
            let mut value = draft(DeploymentSourceMode::AdminManaged);
            let deployment = value.deployments.get_mut("assistant").unwrap();
            deployment.replicas = 2;
            deployment.variant = None;
            value
        }),
    ];

    for (name, value) in cases {
        let error = value.into_revision(1).expect_err(name);
        assert!(error.to_string().contains("deployment") || error.to_string().contains("revision"));
    }

    let mut heterogeneous = draft(DeploymentSourceMode::ClusterAuthority);
    let deployment = heterogeneous.deployments.get_mut("assistant").unwrap();
    deployment.replicas = 3;
    deployment.variant = None;
    deployment.heterogeneous_variants = true;
    heterogeneous
        .into_revision(1)
        .expect("heterogeneous replicas may resolve per worker");
}

#[test]
fn duplicate_yaml_deployment_ids_are_rejected() {
    let yaml = "source_mode: file_managed\nsource_revision: git:abc\ncatalog_revision: cat-1\ndeployments:\n  assistant:\n    model: model-a\n  assistant:\n    model: model-b\n";
    let error = serde_yaml::from_str::<DeploymentRevisionDraft>(yaml)
        .expect_err("duplicate map keys cannot silently replace desired state");
    assert!(error.to_string().contains("duplicate"));
}

#[test]
fn admin_store_is_atomic_restart_safe_and_never_rewrites_sb_yml() {
    let directory = tempdir().expect("temp dir");
    let config_path = directory.path().join("sb.yml");
    let store_path = directory.path().join("model-deployments.json");
    let config_bytes = b"proxy:\n  listeners: []\n";
    fs::write(&config_path, config_bytes).expect("write neighboring config");

    let store = FileDeploymentRevisionStore::open(&store_path).expect("open store");
    assert!(store.load().expect("empty load").is_none());
    let first = store
        .compare_and_swap(None, draft(DeploymentSourceMode::AdminManaged))
        .expect("create revision");
    assert_eq!(first.revision, 1);
    assert_eq!(fs::read(&config_path).unwrap(), config_bytes);

    let reopened = FileDeploymentRevisionStore::open(&store_path).expect("reopen store");
    assert_eq!(
        reopened.load().expect("restart hydration"),
        Some(first.clone())
    );

    let mut update = draft(DeploymentSourceMode::AdminManaged);
    update.source_revision = "operator-change-2".to_string();
    update
        .deployments
        .insert("coder".to_string(), deployment("model-coder"));
    let second = reopened
        .compare_and_swap(Some(first.revision), update)
        .expect("update revision");
    assert_eq!(second.revision, 2);
    assert_ne!(second.content_digest, first.content_digest);
    assert_eq!(fs::read(&config_path).unwrap(), config_bytes);
    assert_eq!(reopened.load().unwrap(), Some(second));
}

#[test]
fn stale_or_invalid_updates_preserve_last_good_bytes() {
    let directory = tempdir().expect("temp dir");
    let store_path = directory.path().join("deployments.json");
    let store = FileDeploymentRevisionStore::open(&store_path).expect("open store");
    let active = store
        .compare_and_swap(None, draft(DeploymentSourceMode::AdminManaged))
        .expect("create active revision");
    let before = fs::read(&store_path).expect("stored bytes");

    let conflict = store
        .compare_and_swap(Some(0), draft(DeploymentSourceMode::AdminManaged))
        .expect_err("stale expected revision conflicts");
    assert!(matches!(
        conflict,
        DeploymentStoreError::Conflict {
            expected: Some(0),
            actual: Some(1)
        }
    ));
    assert_eq!(fs::read(&store_path).unwrap(), before);

    let mut invalid = draft(DeploymentSourceMode::AdminManaged);
    invalid.deployments.get_mut("assistant").unwrap().replicas = 0;
    store
        .compare_and_swap(Some(active.revision), invalid)
        .expect_err("invalid candidate is rejected before persistence");
    assert_eq!(fs::read(&store_path).unwrap(), before);

    let wrong_authority = draft(DeploymentSourceMode::FileManaged);
    store
        .compare_and_swap(Some(active.revision), wrong_authority)
        .expect_err("admin store cannot persist file-managed authority");
    assert_eq!(fs::read(&store_path).unwrap(), before);
    assert_eq!(store.load().unwrap(), Some(active));
}
