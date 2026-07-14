// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::collections::BTreeMap;

use sbproxy_model_host::cluster_authority::{
    DeploymentBundleCursor, DeploymentSigningKey, FileDeploymentBundleCursorStore,
    RestrictedDeploymentBundle, SignedDeploymentBundle,
};
use sbproxy_model_host::{
    DeploymentRevisionDraft, DeploymentSourceMode, EngineChoice, ModelDeployment, PullPolicy,
    RolloutPolicy,
};

fn deployment(model: &str) -> ModelDeployment {
    ModelDeployment {
        model: model.to_string(),
        variant: Some("q4_k_m".to_string()),
        heterogeneous_variants: false,
        replicas: 1,
        required_labels: BTreeMap::from([("pool".to_string(), "gpu".to_string())]),
        spread_by: vec!["zone".to_string()],
        pull: PullPolicy::OnDemand,
        warm: true,
        cold_start: sbproxy_model_host::ColdStartPolicy::Wait,
        keep_alive_secs: Some(300),
        max_concurrency: Some(8),
        max_queue_depth: 128,
        queue_timeout_ms: 30_000,
        engine: EngineChoice::Auto,
        rollout: RolloutPolicy::Rolling,
    }
}

fn bundle(revision: u64) -> RestrictedDeploymentBundle {
    RestrictedDeploymentBundle::new(
        "catalog-v1",
        revision,
        BTreeMap::from([("coder".to_string(), deployment("coder-model"))]),
    )
    .unwrap()
}

#[test]
fn strict_bundle_rejects_unknown_privileged_fields_and_duplicate_deployments() {
    let valid: serde_json::Value = serde_json::from_slice(&bundle(1).to_json().unwrap()).unwrap();
    let mut missing_cold_start = valid.clone();
    missing_cold_start["deployments"]["coder"]
        .as_object_mut()
        .unwrap()
        .remove("cold_start");
    RestrictedDeploymentBundle::from_json(&serde_json::to_vec(&missing_cold_start).unwrap())
        .expect_err("cluster-authority deployments require explicit cold_start");
    for field in ["secrets", "proxy", "private_key"] {
        let mut malicious = valid.clone();
        malicious
            .as_object_mut()
            .unwrap()
            .insert(field.to_string(), serde_json::json!({"value": "forbidden"}));
        let bytes = serde_json::to_vec(&malicious).unwrap();
        let error = RestrictedDeploymentBundle::from_json(&bytes).expect_err(field);
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    let mut nested = valid.clone();
    nested["deployments"]["coder"]["secret_ref"] = serde_json::json!("env:TOKEN");
    let error = RestrictedDeploymentBundle::from_json(&serde_json::to_vec(&nested).unwrap())
        .expect_err("nested unknown field");
    assert!(error.to_string().contains("unknown field"), "{error}");

    let duplicate = format!(
        r#"{{"schema_version":1,"catalog_revision":"catalog-v1","revision":1,"deployments":{{"coder":{},"coder":{}}},"content_digest":"{}"}}"#,
        serde_json::to_string(&deployment("coder-model")).unwrap(),
        serde_json::to_string(&deployment("other-model")).unwrap(),
        "a".repeat(64),
    );
    let error = RestrictedDeploymentBundle::from_json(duplicate.as_bytes())
        .expect_err("duplicate deployment key");
    assert!(error.to_string().contains("duplicate"), "{error}");

    let mut oversized = deployment("coder-model");
    oversized.replicas = 1_025;
    let error = RestrictedDeploymentBundle::new(
        "catalog-v1",
        1,
        BTreeMap::from([("coder".to_string(), oversized)]),
    )
    .expect_err("replica bound");
    assert!(error.to_string().contains("1024"), "{error}");
}

#[test]
fn content_address_and_signature_are_canonical_and_tamper_evident() {
    let key = DeploymentSigningKey::from_seed([7; 32]);
    let verifying = key.verifying_key();
    let first = bundle(7);
    let mut reverse = BTreeMap::new();
    reverse.insert("zeta".to_string(), deployment("zeta-model"));
    reverse.insert("alpha".to_string(), deployment("alpha-model"));
    let ordered = RestrictedDeploymentBundle::new("catalog-v1", 7, reverse).unwrap();
    let reordered = RestrictedDeploymentBundle::new(
        "catalog-v1",
        7,
        BTreeMap::from([
            ("alpha".to_string(), deployment("alpha-model")),
            ("zeta".to_string(), deployment("zeta-model")),
        ]),
    )
    .unwrap();
    assert_eq!(ordered.content_digest, reordered.content_digest);
    assert_eq!(ordered.content_key(), ordered.content_digest);

    let signed = SignedDeploymentBundle::sign(first.clone(), "authority-a", &key).unwrap();
    let verified = signed.verify(&verifying, None).unwrap();
    assert_eq!(verified.bundle(), &first);
    assert_eq!(verified.revision_draft().deployments, first.deployments());

    let mut bad_digest = first;
    bad_digest.content_digest = "f".repeat(64);
    assert!(SignedDeploymentBundle::sign(bad_digest, "authority-a", &key).is_err());

    let mut tampered: serde_json::Value =
        serde_json::from_slice(&signed.to_json().unwrap()).unwrap();
    tampered["signature"] = serde_json::json!("AAAAAAAA");
    let tampered = SignedDeploymentBundle::from_json(&serde_json::to_vec(&tampered).unwrap())
        .expect("strict envelope");
    assert!(tampered.verify(&verifying, None).is_err());
}

#[test]
fn verified_cursor_rejects_older_or_conflicting_authority_revisions() {
    let key = DeploymentSigningKey::from_seed([9; 32]);
    let verifying = key.verifying_key();
    let signed = SignedDeploymentBundle::sign(bundle(7), "authority-a", &key).unwrap();
    let stale = DeploymentBundleCursor {
        revision: 8,
        content_digest: "a".repeat(64),
    };
    assert!(signed.verify(&verifying, Some(&stale)).is_err());

    let conflict = DeploymentBundleCursor {
        revision: 7,
        content_digest: "b".repeat(64),
    };
    assert!(signed.verify(&verifying, Some(&conflict)).is_err());

    let idempotent = DeploymentBundleCursor {
        revision: 7,
        content_digest: signed.bundle.content_digest.clone(),
    };
    signed.verify(&verifying, Some(&idempotent)).unwrap();
}

#[test]
fn file_and_verified_authority_sources_normalize_to_identical_placement_data() {
    let deployments = BTreeMap::from([("coder".to_string(), deployment("coder-model"))]);
    let file = DeploymentRevisionDraft {
        source_mode: DeploymentSourceMode::FileManaged,
        source_revision: "git:abc".to_string(),
        catalog_revision: "catalog-v1".to_string(),
        deployments: deployments.clone(),
    };
    let key = DeploymentSigningKey::from_seed([11; 32]);
    let verified = SignedDeploymentBundle::sign(
        RestrictedDeploymentBundle::new("catalog-v1", 12, deployments).unwrap(),
        "authority-a",
        &key,
    )
    .unwrap()
    .verify(&key.verifying_key(), None)
    .unwrap();
    let authority = verified.revision_draft();

    assert_eq!(file.catalog_revision, authority.catalog_revision);
    assert_eq!(file.deployments, authority.deployments);
    assert_eq!(
        authority.source_mode,
        DeploymentSourceMode::ClusterAuthority
    );
}

#[test]
fn durable_cursor_survives_restart_and_rejects_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("deployment-cursor.json");
    let store = FileDeploymentBundleCursorStore::open(&path).unwrap();
    let current = DeploymentBundleCursor {
        revision: 9,
        content_digest: "a".repeat(64),
    };
    store.commit(&current).unwrap();
    let reopened = FileDeploymentBundleCursorStore::open(&path).unwrap();
    assert_eq!(reopened.load().unwrap(), Some(current.clone()));
    reopened.commit(&current).expect("idempotent commit");
    assert!(reopened
        .commit(&DeploymentBundleCursor {
            revision: 8,
            content_digest: "b".repeat(64),
        })
        .is_err());
    assert!(reopened
        .commit(&DeploymentBundleCursor {
            revision: 9,
            content_digest: "c".repeat(64),
        })
        .is_err());
}
