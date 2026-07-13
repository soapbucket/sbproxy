// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sbproxy_core::model_runtime::model_runtime_manager;
use sbproxy_mesh::enrollment::{AuthorityInit, EnrollmentAuthority};
use sbproxy_mesh::ClusterNodeRole;

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(
    state: &Path,
    signing_key: &Path,
    verifying_key: &Path,
    gossip_port: u16,
    transport_port: u16,
) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  cluster:
    cluster_id: authority-runtime
    node_id: authority-a
    roles: [gateway, authority]
    gossip_port: {gossip_port}
    transport_port: {transport_port}
    state_dir: {state}
    security:
      mode: shared_key
      development: true
      shared_key: local-development-secret
    deployment_authority:
      signing_key_file: {signing_key}
      verifying_key_file: {verifying_key}
  model_host:
    authority: cluster_authority
origins:
  "health.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#,
        state = state.display(),
        signing_key = signing_key.display(),
        verifying_key = verifying_key.display(),
    )
}

fn deployments() -> BTreeMap<String, sbproxy_model_host::ModelDeployment> {
    BTreeMap::from([(
        "coder".to_string(),
        serde_yaml::from_str("model: qwen2.5-0.5b-instruct\nvariant: q4_k_m\nreplicas: 1\n")
            .unwrap(),
    )])
}

#[tokio::test(flavor = "multi_thread")]
async fn verified_authority_revision_commits_atomically_and_bad_catalog_retains_last_good() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority_dir = temp.path().join("authority");
    EnrollmentAuthority::initialize(
        &authority_dir,
        AuthorityInit {
            cluster_id: "authority-runtime".to_string(),
            node_id: "authority-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Gateway, ClusterNodeRole::Authority]),
            labels: BTreeMap::new(),
            server_name: "sbproxy-mesh".to_string(),
        },
    )
    .expect("authority material");
    let config_path = temp.path().join("sb.yml");
    let base_config = config(
        &temp.path().join("state"),
        &authority_dir.join("authority-signing.key"),
        &authority_dir.join("authority-verifying.key"),
        free_udp_port(),
        free_tcp_port(),
    );
    std::fs::write(&config_path, &base_config).expect("write config");
    sbproxy_core::server::reload_from_config_path(config_path.to_str().unwrap())
        .expect("initialize cluster authority runtime");
    let runtime = model_runtime_manager();
    assert!(runtime
        .cluster_placement_state()
        .expect("cluster controller")
        .global()
        .deployments
        .is_empty());
    let authority =
        sbproxy_core::cluster::current_deployment_authority().expect("deployment authority");
    let request = serde_json::to_string(&sbproxy_model_host::RestrictedDeploymentBundleDraft::new(
        "builtin-2026-07-10",
        7,
        deployments(),
    ))
    .unwrap();
    let (status, _, response) = sbproxy_core::admin_cluster::dispatch(
        "POST",
        sbproxy_core::admin_cluster::DEPLOYMENTS_PATH,
        Some(&request),
    )
    .expect("deployment admin route");
    assert_eq!(status, 202, "{response}");
    if let Some(verified) = authority.read_candidate().await.expect("read revision 7") {
        runtime
            .apply_cluster_authority_bundle(&verified)
            .await
            .expect("apply revision 7");
        authority.commit(verified).expect("commit authority cursor");
    }
    let active = authority.active().expect("active authority cursor");
    assert_eq!(active.bundle().revision, 7);
    let (status, _, body) = sbproxy_core::admin_cluster::dispatch(
        "GET",
        sbproxy_core::admin_cluster::DEPLOYMENTS_PATH,
        None,
    )
    .unwrap();
    assert_eq!(status, 200, "{body}");
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["bundle"]["revision"], 7);
    assert_eq!(body["read_only"], false);
    let (_, _, status_body) = sbproxy_core::admin_cluster::dispatch(
        "GET",
        sbproxy_core::admin_cluster::STATUS_PATH,
        None,
    )
    .unwrap();
    let status_body: serde_json::Value = serde_json::from_str(&status_body).unwrap();
    assert_eq!(status_body["deployment_authority"]["configured"], true);
    assert_eq!(status_body["deployment_authority"]["active_revision"], 7);
    let placement = runtime
        .cluster_placement_state()
        .expect("committed placement");
    assert!(placement.global().deployments.contains_key("coder"));
    assert!(runtime.current_desired().deployments.is_empty());
    let routed_config = base_config.replace(
        r#"      type: static
      status_code: 200
      content_type: text/plain
      body: ok"#,
        r#"      type: ai_proxy
      providers:
        - name: cluster-models
          provider_type: managed_model
          deployment: coder
          models: [coder]"#,
    );
    std::fs::write(&config_path, routed_config).expect("write routed config");
    sbproxy_core::server::reload_from_config_path(config_path.to_str().unwrap())
        .expect("reload consumes committed signed bundle");
    assert_eq!(
        runtime
            .cluster_placement_state()
            .unwrap()
            .global()
            .revision
            .source_revision,
        active.revision_draft().source_revision
    );
    assert!(runtime
        .cluster_placement_state()
        .unwrap()
        .global()
        .route_for("health.test", "cluster-models", "coder")
        .is_some());

    authority
        .publish(
            sbproxy_model_host::RestrictedDeploymentBundle::new("wrong-catalog", 8, deployments())
                .unwrap(),
        )
        .await
        .expect("publish signed but incompatible revision");
    let incompatible = authority
        .read_candidate()
        .await
        .expect("read incompatible candidate")
        .expect("candidate remains unapplied");
    let error = runtime
        .apply_cluster_authority_bundle(&incompatible)
        .await
        .expect_err("catalog mismatch must preserve last good");
    assert!(error.to_string().contains("catalog revision"), "{error:#}");
    assert_eq!(authority.active().unwrap().bundle().revision, 7);
    assert_eq!(
        runtime
            .cluster_placement_state()
            .unwrap()
            .global()
            .revision
            .source_revision,
        active.revision_draft().source_revision
    );
}
