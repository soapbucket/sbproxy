use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sbproxy_config::ProxyServerConfig;
use sbproxy_core::cluster::{ClusterBootstrap, ClusterOwner, SystemClusterBootstrap};
use sbproxy_mesh::{
    enrollment::{AuthorityInit, EnrollmentAuthority},
    ClusterNodeRole,
};
use sbproxy_mesh::{ClusterHandle, ClusterIdentity, ClusterMode, ClusterStateRead, MeshNode};
use std::collections::{BTreeMap, BTreeSet};

fn parse(yaml: &str) -> ProxyServerConfig {
    serde_yaml::from_str(yaml).expect("proxy config")
}

fn canonical() -> ProxyServerConfig {
    parse(
        r#"
cluster:
  cluster_id: cluster-a
  node_id: worker-a
  roles: [gateway, worker]
  labels: {zone: a}
  gossip_port: 17946
  transport_port: 18946
  state_dir: target/test-cluster-control-state
  security:
    mode: mtls
    shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
    cert_file: node.pem
    key_file: node-key.pem
    ca_file: ca.pem
  snapshot_ttl_secs: 30
  publish_interval_secs: 5
"#,
    )
}

#[derive(Default)]
struct FakeBootstrap {
    calls: AtomicUsize,
    fail: bool,
}

impl ClusterBootstrap for FakeBootstrap {
    fn bootstrap(
        &self,
        identity: ClusterIdentity,
        _config: &sbproxy_config::EffectiveClusterConfig,
    ) -> anyhow::Result<ClusterHandle> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            anyhow::bail!("injected bootstrap failure");
        }
        let node_id = identity.node_id.clone();
        ClusterHandle::distributed(identity, Arc::new(MeshNode::new(node_id, Vec::new(), 32)))
            .map_err(anyhow::Error::from)
    }
}

#[test]
fn absent_cluster_installs_one_zero_network_local_handle() {
    let bootstrap = Arc::new(FakeBootstrap::default());
    let owner = ClusterOwner::new(bootstrap.clone());
    let first = owner
        .reconcile(&ProxyServerConfig::default())
        .expect("local handle");
    let again = owner
        .reconcile(&ProxyServerConfig::default())
        .expect("same local handle");

    assert_eq!(first.mode(), ClusterMode::Local);
    assert!(ClusterHandle::ptr_eq(&first, &again));
    assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 0);
    assert_eq!(owner.settings().expect("settings").snapshot_ttl_secs, 30);
}

#[tokio::test]
async fn canonical_worker_publishes_one_fenced_snapshot_and_honors_cadence() {
    use sbproxy_model_host::node_snapshot::{
        NodeHealthSnapshot, NodeHealthState, NodeIdentitySnapshot, NodeModelSnapshot, NodeRole,
        NODE_MODEL_SNAPSHOT_NAMESPACE, NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
    };

    let temp = tempfile::tempdir().expect("snapshot state");
    let server = parse(&format!(
        r#"
cluster:
  cluster_id: cluster-a
  node_id: worker-a
  roles: [worker]
  labels: {{zone: a}}
  model_endpoint: http://127.0.0.1:9443
  state_dir: {}
  security:
    mode: shared_key
    development: true
    shared_key: local-development-secret
  snapshot_ttl_secs: 30
  publish_interval_secs: 5
"#,
        temp.path().display()
    ));
    let owner = ClusterOwner::new(Arc::new(FakeBootstrap::default()));
    let handle = owner.reconcile(&server).expect("cluster handle");
    let publication = owner
        .begin_node_snapshot_publication(true)
        .await
        .expect("publication reservation")
        .expect("worker publication enabled");
    let snapshot = NodeModelSnapshot {
        schema_version: NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
        node: NodeIdentitySnapshot {
            node_id: publication.identity().node_id.clone(),
            roles: BTreeSet::from([NodeRole::Worker]),
            labels: publication.identity().labels.clone(),
            model_endpoint: publication.identity().model_endpoint.clone(),
        },
        health: NodeHealthSnapshot {
            state: NodeHealthState::Unhealthy,
            reason_codes: vec!["fixture_unhealthy".to_string()],
            model_plane: sbproxy_model_host::node_snapshot::ModelPlaneHealth::Unavailable,
        },
        engines: Vec::new(),
        devices: Vec::new(),
        artifacts: Vec::new(),
        replicas: Vec::new(),
        placement_weight: 0,
        active_deployment_digest: None,
        generation: publication.generation(),
        published_at_unix_ms: publication.published_at_unix_ms(),
        expires_at_unix_ms: publication.expires_at_unix_ms(),
    };
    let generation = snapshot.generation;
    publication
        .publish(snapshot.clone())
        .await
        .expect("publish");

    let ClusterStateRead::Present(record) = handle
        .read_state::<NodeModelSnapshot>(
            NODE_MODEL_SNAPSHOT_NAMESPACE,
            "worker-a",
            NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
        )
        .await
    else {
        panic!("published node snapshot is absent");
    };
    assert_eq!(record.generation, generation);
    assert_eq!(record.payload, snapshot);
    let directory = owner
        .collect_model_directory(true)
        .await
        .expect("collect directory")
        .expect("canonical directory enabled");
    assert_eq!(directory.nodes.len(), 1);
    assert_eq!(directory.summary.unhealthy_nodes, 1);
    assert_eq!(directory.nodes[0].node_id, "worker-a");
    assert_eq!(
        directory.nodes[0].unhealthy_reasons,
        vec!["fixture_unhealthy".to_string()]
    );
    assert!(owner
        .begin_node_snapshot_publication(false)
        .await
        .expect("cadence check")
        .is_none());

    let restarted = ClusterOwner::new(Arc::new(FakeBootstrap::default()));
    restarted.reconcile(&server).expect("restarted cluster");
    let restarted_publication = restarted
        .begin_node_snapshot_publication(true)
        .await
        .expect("restarted publication")
        .expect("restarted worker publication enabled");
    assert!(restarted_publication.generation() > generation);

    let local = ClusterOwner::new(Arc::new(FakeBootstrap::default()));
    local
        .reconcile(&ProxyServerConfig::default())
        .expect("local handle");
    assert!(local
        .begin_node_snapshot_publication(true)
        .await
        .expect("local publication check")
        .is_none());
}

#[test]
fn canonical_cluster_bootstraps_once_without_key_management() {
    let bootstrap = Arc::new(FakeBootstrap::default());
    let owner = ClusterOwner::new(bootstrap.clone());
    let server = canonical();
    assert!(server.key_management.is_none());

    let first = owner.reconcile(&server).expect("distributed handle");
    let again = owner.reconcile(&server).expect("same distributed handle");
    assert_eq!(first.mode(), ClusterMode::Distributed);
    assert!(ClusterHandle::ptr_eq(&first, &again));
    assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.identity().cluster_id, "cluster-a");
    assert_eq!(first.identity().node_id, "worker-a");
}

#[test]
fn canonical_cluster_rejects_an_unwritable_generation_path_before_installing() {
    let temp = tempfile::tempdir().expect("temp dir");
    let not_a_directory = temp.path().join("generation-state");
    std::fs::write(&not_a_directory, b"not a directory").expect("state fixture");
    let server = parse(&format!(
        r#"
cluster:
  cluster_id: cluster-a
  node_id: worker-a
  roles: [worker]
  state_dir: {}
  security:
    mode: shared_key
    development: true
    shared_key: local-development-secret
"#,
        not_a_directory.display()
    ));
    let owner = ClusterOwner::new(Arc::new(FakeBootstrap::default()));

    let error = owner
        .reconcile(&server)
        .expect_err("generation state must be writable at startup");

    assert!(format!("{error:#}").contains("snapshot generation"));
    assert!(owner.current().is_none());
}

#[test]
fn snapshot_cadence_reloads_but_identity_change_requires_restart() {
    let bootstrap = Arc::new(FakeBootstrap::default());
    let owner = ClusterOwner::new(bootstrap.clone());
    let server = canonical();
    let handle = owner.reconcile(&server).expect("initial handle");

    let mut cadence = server.clone();
    let cluster = cadence.cluster.as_mut().expect("cluster");
    cluster.snapshot_ttl_secs = 60;
    cluster.publish_interval_secs = 10;
    let reloaded = owner.reconcile(&cadence).expect("cadence reload");
    assert!(ClusterHandle::ptr_eq(&handle, &reloaded));
    let settings = owner.settings().expect("settings");
    assert_eq!(settings.snapshot_ttl_secs, 60);
    assert_eq!(settings.publish_interval_secs, 10);

    let mut identity = cadence;
    identity
        .cluster
        .as_mut()
        .expect("cluster")
        .labels
        .insert("zone".to_string(), "b".to_string());
    let error = owner
        .reconcile(&identity)
        .expect_err("identity reload must fail");
    assert!(error.to_string().contains("restart"));
    assert!(ClusterHandle::ptr_eq(
        &handle,
        &owner.current().expect("last good handle")
    ));
    assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn enabling_cluster_after_local_start_requires_restart() {
    let bootstrap = Arc::new(FakeBootstrap::default());
    let owner = ClusterOwner::new(bootstrap.clone());
    let local = owner
        .reconcile(&ProxyServerConfig::default())
        .expect("local start");
    let error = owner
        .reconcile(&canonical())
        .expect_err("enable requires restart");
    assert!(error.to_string().contains("restart"));
    assert!(ClusterHandle::ptr_eq(
        &local,
        &owner.current().expect("local remains")
    ));
    assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn legacy_mesh_uses_shared_owner_and_retains_local_fallback() {
    let legacy = parse(
        r#"
key_management:
  enabled: true
  cache:
    tier: mesh
    mesh_node_id: legacy-a
    mesh:
      gossip_port: 17947
      transport_port: 18947
      shared_key: local-development-secret
"#,
    );
    let successful = Arc::new(FakeBootstrap::default());
    let owner = ClusterOwner::new(successful.clone());
    assert_eq!(
        owner.reconcile(&legacy).expect("legacy distributed").mode(),
        ClusterMode::Distributed
    );
    assert_eq!(successful.calls.load(Ordering::SeqCst), 1);

    let failing = Arc::new(FakeBootstrap {
        calls: AtomicUsize::new(0),
        fail: true,
    });
    let owner = ClusterOwner::new(failing.clone());
    let fallback = owner.reconcile(&legacy).expect("legacy fallback");
    assert_eq!(fallback.mode(), ClusterMode::Local);
    assert_eq!(fallback.identity().node_id, "legacy-a");
    assert_eq!(failing.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn canonical_bootstrap_failure_is_fatal_and_not_installed() {
    let bootstrap = Arc::new(FakeBootstrap {
        calls: AtomicUsize::new(0),
        fail: true,
    });
    let owner = ClusterOwner::new(bootstrap.clone());
    let error = owner
        .reconcile(&canonical())
        .expect_err("canonical bootstrap fails closed");
    assert!(error.to_string().contains("injected bootstrap failure"));
    assert!(owner.current().is_none());
    assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn production_bootstrap_rejects_missing_mtls_material_before_network_start() {
    let owner = ClusterOwner::new(Arc::new(SystemClusterBootstrap));
    let mut server = canonical();
    let security = &mut server.cluster.as_mut().expect("cluster").security;
    security.shared_key = Some("local-development-secret".to_string());
    security.cert_file = Some("/missing/sbproxy-node.pem".to_string());
    security.key_file = Some("/missing/sbproxy-node-key.pem".to_string());
    security.ca_file = Some("/missing/sbproxy-ca.pem".to_string());

    let error = owner
        .reconcile(&server)
        .expect_err("missing mTLS files must fail closed");
    let message = format!("{error:#}");
    assert!(message.contains("read cluster certificate"), "{message}");
    assert!(owner.current().is_none());
}

#[test]
fn canonical_listener_bind_failure_is_fatal_and_uninstalled() {
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").expect("occupy UDP port");
    let gossip_port = occupied.local_addr().expect("occupied address").port();
    let transport_port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve TCP port")
        .local_addr()
        .expect("TCP address")
        .port();
    let server = parse(&format!(
        r#"
cluster:
  cluster_id: cluster-a
  node_id: worker-a
  roles: [worker]
  gossip_port: {gossip_port}
  transport_port: {transport_port}
  advertise_addr: 127.0.0.1:{gossip_port}
  transport_advertise_addr: 127.0.0.1:{transport_port}
  state_dir: target/test-cluster-listener-state
  security:
    mode: shared_key
    development: true
    shared_key: local-development-secret
"#
    ));
    let owner = ClusterOwner::new(Arc::new(SystemClusterBootstrap));

    let error = owner
        .reconcile(&server)
        .expect_err("occupied gossip port must fail closed");
    let message = format!("{error:#}");
    assert!(
        message.contains("gossip listener failed to bind"),
        "{message}"
    );
    assert!(owner.current().is_none());
}

#[test]
fn configured_authority_is_loaded_before_bootstrap_and_must_match_identity() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority_dir = temp.path().join("authority");
    EnrollmentAuthority::initialize(
        &authority_dir,
        AuthorityInit {
            cluster_id: "dev-a".to_string(),
            node_id: "authority-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Gateway, ClusterNodeRole::Authority]),
            labels: BTreeMap::from([("zone".to_string(), "a".to_string())]),
            server_name: "sbproxy-mesh".to_string(),
        },
    )
    .expect("authority");
    let server = parse(&format!(
        r#"
admin:
  enabled: true
cluster:
  cluster_id: dev-a
  node_id: authority-a
  roles: [gateway, authority]
  labels: {{zone: a}}
  state_dir: {}
  enrollment:
    authority_dir: {}
    allow_insecure_http: true
  security:
    mode: shared_key
    development: true
    shared_key: local-development-secret
"#,
        authority_dir.display(),
        authority_dir.display()
    ));
    let bootstrap = Arc::new(FakeBootstrap::default());
    let owner = ClusterOwner::new(bootstrap.clone());
    owner.reconcile(&server).expect("matching authority");
    assert!(owner.enrollment_authority().is_some());
    assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 1);

    let mut mismatch = server;
    mismatch
        .cluster
        .as_mut()
        .expect("cluster")
        .labels
        .insert("zone".to_string(), "b".to_string());
    let bootstrap = Arc::new(FakeBootstrap::default());
    let owner = ClusterOwner::new(bootstrap.clone());
    let error = owner
        .reconcile(&mismatch)
        .expect_err("signed identity mismatch");
    assert!(error.to_string().contains("signed enrollment authority"));
    assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 0);

    let mismatched_transport_identity = parse(&format!(
        r#"
admin:
  enabled: true
  tls:
    cert: admin.pem
    key: admin-key.pem
cluster:
  cluster_id: dev-a
  node_id: authority-a
  roles: [gateway, authority]
  labels: {{zone: a}}
  state_dir: {}
  enrollment:
    authority_dir: {}
  security:
    mode: mtls
    shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
    cert_file: {}/node.pem
    key_file: {}/node-key.pem
    ca_file: {}/ca.pem
    server_name: wrong-mesh-name
"#,
        authority_dir.display(),
        authority_dir.display(),
        authority_dir.display(),
        authority_dir.display(),
        authority_dir.display()
    ));
    let bootstrap = Arc::new(FakeBootstrap::default());
    let owner = ClusterOwner::new(bootstrap.clone());
    let error = owner
        .reconcile(&mismatched_transport_identity)
        .expect_err("transport identity mismatch");
    assert!(error.to_string().contains("server name"), "{error:#}");
    assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 0);

    let mismatched_transport_certificate = parse(&format!(
        r#"
admin:
  enabled: true
  tls:
    cert: admin.pem
    key: admin-key.pem
cluster:
  cluster_id: dev-a
  node_id: authority-a
  roles: [gateway, authority]
  labels: {{zone: a}}
  state_dir: {}
  enrollment:
    authority_dir: {}
  security:
    mode: mtls
    shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
    cert_file: {}/ca.pem
    key_file: {}/node-key.pem
    ca_file: {}/ca.pem
    server_name: sbproxy-mesh
"#,
        authority_dir.display(),
        authority_dir.display(),
        authority_dir.display(),
        authority_dir.display(),
        authority_dir.display()
    ));
    let bootstrap = Arc::new(FakeBootstrap::default());
    let owner = ClusterOwner::new(bootstrap.clone());
    let error = owner
        .reconcile(&mismatched_transport_certificate)
        .expect_err("transport certificate mismatch");
    assert!(error.to_string().contains("certificate"), "{error:#}");
    assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn deployment_authority_signs_content_addressed_state_and_workers_are_read_only() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority_dir = temp.path().join("authority");
    EnrollmentAuthority::initialize(
        &authority_dir,
        sbproxy_mesh::enrollment::AuthorityInit {
            cluster_id: "cluster-a".to_string(),
            node_id: "authority-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Authority, ClusterNodeRole::Worker]),
            labels: BTreeMap::new(),
            server_name: "sbproxy-mesh".to_string(),
        },
    )
    .expect("authority keys");
    let signing_key = authority_dir.join("authority-signing.key");
    let verifying_key = authority_dir.join("authority-verifying.key");
    let server = parse(&format!(
        r#"
cluster:
  cluster_id: cluster-a
  node_id: authority-a
  roles: [authority, worker]
  state_dir: {}
  security:
    mode: shared_key
    development: true
    shared_key: local-development-secret
  deployment_authority:
    signing_key_file: {}
    verifying_key_file: {}
"#,
        temp.path().join("authority-state").display(),
        signing_key.display(),
        verifying_key.display(),
    ));
    let owner = ClusterOwner::new(Arc::new(FakeBootstrap::default()));
    owner.reconcile(&server).expect("authority cluster");
    let authority = owner.deployment_authority().expect("deployment authority");
    assert!(authority.can_publish());
    let bundle = sbproxy_model_host::RestrictedDeploymentBundle::new(
        "builtin-2026-07-10",
        7,
        BTreeMap::from([(
            "coder".to_string(),
            serde_yaml::from_str("model: qwen2.5-0.5b-instruct\nvariant: q4_k_m\nreplicas: 1\n")
                .expect("deployment"),
        )]),
    )
    .expect("bundle");
    let signed = authority
        .publish(bundle)
        .await
        .expect("publish signed bundle");
    assert_eq!(signed.bundle.revision, 7);
    let verified = authority
        .read_candidate()
        .await
        .expect("read candidate")
        .expect("new candidate");
    assert_eq!(
        verified.bundle().content_digest,
        signed.bundle.content_digest
    );
    authority.commit(verified).expect("commit authority cursor");
    assert!(authority
        .read_candidate()
        .await
        .expect("idempotent current read")
        .is_none());
    let restarted_owner = ClusterOwner::new(Arc::new(FakeBootstrap::default()));
    restarted_owner
        .reconcile(&server)
        .expect("restart loads durable cursor");
    let rollback = restarted_owner
        .deployment_authority()
        .unwrap()
        .publish(
            sbproxy_model_host::RestrictedDeploymentBundle::new(
                "builtin-2026-07-10",
                6,
                BTreeMap::new(),
            )
            .unwrap(),
        )
        .await
        .expect_err("durable cursor rejects rollback after restart");
    assert!(rollback.to_string().contains("stale"), "{rollback}");

    let worker = parse(&format!(
        r#"
cluster:
  cluster_id: cluster-a
  node_id: worker-a
  roles: [worker]
  state_dir: {}
  security:
    mode: shared_key
    development: true
    shared_key: local-development-secret
  deployment_authority:
    verifying_key_file: {}
"#,
        temp.path().join("worker-state").display(),
        verifying_key.display(),
    ));
    let worker_owner = ClusterOwner::new(Arc::new(FakeBootstrap::default()));
    worker_owner.reconcile(&worker).expect("worker cluster");
    let worker_authority = worker_owner
        .deployment_authority()
        .expect("worker verifier");
    assert!(!worker_authority.can_publish());
    let error = worker_authority
        .publish(
            sbproxy_model_host::RestrictedDeploymentBundle::new(
                "builtin-2026-07-10",
                8,
                BTreeMap::new(),
            )
            .unwrap(),
        )
        .await
        .expect_err("worker cannot publish");
    assert!(matches!(
        error,
        sbproxy_core::cluster::ClusterDeploymentAuthorityError::ReadOnly
    ));
}

#[tokio::test]
async fn failed_authority_cursor_write_does_not_activate_or_suppress_retry() {
    let temp = tempfile::tempdir().expect("temp dir");
    let authority_dir = temp.path().join("authority");
    EnrollmentAuthority::initialize(
        &authority_dir,
        sbproxy_mesh::enrollment::AuthorityInit {
            cluster_id: "cluster-a".to_string(),
            node_id: "authority-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Authority]),
            labels: BTreeMap::new(),
            server_name: "sbproxy-mesh".to_string(),
        },
    )
    .expect("authority keys");
    let state_dir = temp.path().join("state");
    let server = parse(&format!(
        r#"
cluster:
  cluster_id: cluster-a
  node_id: authority-a
  roles: [authority]
  state_dir: {}
  security:
    mode: shared_key
    development: true
    shared_key: local-development-secret
  deployment_authority:
    signing_key_file: {}
    verifying_key_file: {}
"#,
        state_dir.display(),
        authority_dir.join("authority-signing.key").display(),
        authority_dir.join("authority-verifying.key").display(),
    ));
    let owner = ClusterOwner::new(Arc::new(FakeBootstrap::default()));
    owner.reconcile(&server).expect("authority cluster");
    let authority = owner.deployment_authority().expect("deployment authority");
    let signed = authority
        .publish(
            sbproxy_model_host::RestrictedDeploymentBundle::new(
                "builtin-2026-07-10",
                7,
                BTreeMap::new(),
            )
            .expect("bundle"),
        )
        .await
        .expect("publish");
    let verified = authority
        .read_candidate()
        .await
        .expect("candidate read")
        .expect("candidate");
    std::fs::create_dir(state_dir.join("deployment-authority-cursor.json"))
        .expect("block cursor file creation");

    authority
        .commit(verified)
        .expect_err("durability failure must abort activation");

    assert!(authority.active().is_none());
    let retry = authority
        .read_candidate()
        .await
        .expect("retry read")
        .expect("failed cursor write must not suppress retry");
    assert_eq!(retry.bundle().content_digest, signed.bundle.content_digest);
}
