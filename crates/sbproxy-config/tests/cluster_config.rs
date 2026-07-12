use sbproxy_config::{
    compile_config, resolve_effective_cluster, ClusterConfigSource, ClusterRole,
    EffectiveClusterSecurity, EffectiveClusterSecurityMode, ProxyServerConfig,
};

fn parse(yaml: &str) -> ProxyServerConfig {
    serde_yaml::from_str(yaml).expect("cluster config parses")
}

#[test]
fn canonical_mtls_cluster_round_trips_and_resolves() {
    let proxy = parse(
        r#"
cluster:
  cluster_id: prod-a
  node_id: worker-a
  roles: [gateway, worker]
  labels:
    zone: us-central1-a
    accelerator: l4
  seeds: [10.0.0.11:7946]
  gossip_port: 7946
  transport_port: 8946
  advertise_addr: 10.0.0.12:7946
  transport_advertise_addr: 10.0.0.12:8946
  model_endpoint: https://10.0.0.12:9443
  state_dir: /var/lib/sbproxy/cluster
  security:
    mode: mtls
    shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
    cert_file: /var/lib/sbproxy/cluster/node.pem
    key_file: /var/lib/sbproxy/cluster/node-key.pem
    ca_file: /var/lib/sbproxy/cluster/ca.pem
    server_name: sbproxy-mesh
  snapshot_ttl_secs: 30
  publish_interval_secs: 5
"#,
    );

    let configured = proxy.cluster.as_ref().expect("typed cluster block");
    configured.validate().expect("valid canonical cluster");
    assert!(configured.roles.contains(&ClusterRole::Gateway));
    assert!(configured.roles.contains(&ClusterRole::Worker));
    assert_eq!(
        configured.state_dir.as_deref(),
        Some("/var/lib/sbproxy/cluster")
    );

    let effective = resolve_effective_cluster(&proxy)
        .expect("effective cluster")
        .expect("cluster enabled");
    assert_eq!(effective.source, ClusterConfigSource::Canonical);
    assert_eq!(effective.cluster_id, "prod-a");
    assert_eq!(effective.node_id.as_deref(), Some("worker-a"));
    assert_eq!(
        effective.transport_advertise_addr.as_deref(),
        Some("10.0.0.12:8946")
    );
    assert_eq!(
        effective.security.mode(),
        EffectiveClusterSecurityMode::Mtls
    );
    assert!(effective.diagnostics.is_empty());

    let round_trip = serde_yaml::to_string(&proxy).expect("serialize cluster config");
    let decoded: ProxyServerConfig = serde_yaml::from_str(&round_trip).expect("round trip");
    assert_eq!(decoded.cluster, proxy.cluster);
}

#[test]
fn generated_proxy_schema_exposes_cluster_contract() {
    let schema = schemars::schema_for!(ProxyServerConfig);
    let json = serde_json::to_string(&schema).expect("serialize schema");
    for field in [
        "cluster",
        "cluster_id",
        "node_id",
        "roles",
        "labels",
        "transport_advertise_addr",
        "state_dir",
        "security",
        "snapshot_ttl_secs",
        "publish_interval_secs",
        "deployment_authority",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing {field}");
    }
}

#[test]
fn canonical_cluster_validation_rejects_unsafe_or_unbounded_inputs() {
    let invalid = [
        (
            "missing node id",
            r#"
cluster_id: prod-a
roles: [worker]
security:
  mode: mtls
  shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
  cert_file: node.pem
  key_file: node-key.pem
  ca_file: ca.pem
"#,
        ),
        (
            "missing roles",
            r#"
cluster_id: prod-a
node_id: worker-a
security:
  mode: mtls
  cert_file: node.pem
  key_file: node-key.pem
  ca_file: ca.pem
"#,
        ),
        (
            "shared key not marked development",
            r#"
cluster_id: dev-a
node_id: worker-a
roles: [worker]
security:
  mode: shared_key
  shared_key: env:SBPROXY_CLUSTER_KEY
"#,
        ),
        (
            "incomplete mtls",
            r#"
cluster_id: prod-a
node_id: worker-a
roles: [worker]
security:
  mode: mtls
  cert_file: node.pem
  key_file: node-key.pem
"#,
        ),
        (
            "mtls without authenticated gossip",
            r#"
cluster_id: prod-a
node_id: worker-a
roles: [worker]
security:
  mode: mtls
  cert_file: node.pem
  key_file: node-key.pem
  ca_file: ca.pem
"#,
        ),
        (
            "invalid model endpoint",
            r#"
cluster_id: prod-a
node_id: worker-a
roles: [worker]
model_endpoint: file:///tmp/engine.sock
security:
  mode: mtls
  cert_file: node.pem
  key_file: node-key.pem
  ca_file: ca.pem
"#,
        ),
        (
            "invalid transport advertise address",
            r#"
cluster_id: prod-a
node_id: worker-a
roles: [worker]
transport_advertise_addr: missing-port
security:
  mode: mtls
  shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
  cert_file: node.pem
  key_file: node-key.pem
  ca_file: ca.pem
"#,
        ),
        (
            "expiry shorter than two publishes",
            r#"
cluster_id: prod-a
node_id: worker-a
roles: [worker]
snapshot_ttl_secs: 5
publish_interval_secs: 3
security:
  mode: mtls
  cert_file: node.pem
  key_file: node-key.pem
  ca_file: ca.pem
"#,
        ),
        (
            "ephemeral transport port",
            r#"
cluster_id: prod-a
node_id: worker-a
roles: [worker]
transport_port: 0
security:
  mode: mtls
  cert_file: node.pem
  key_file: node-key.pem
  ca_file: ca.pem
"#,
        ),
        (
            "short inline shared key",
            r#"
cluster_id: dev-a
node_id: worker-a
roles: [worker]
security:
  mode: shared_key
  development: true
  shared_key: too-short
"#,
        ),
        (
            "unresolved vault shared key",
            r#"
cluster_id: dev-a
node_id: worker-a
roles: [worker]
security:
  mode: shared_key
  development: true
  shared_key: vault://secret/data/sbproxy#cluster
"#,
        ),
    ];

    for (case, yaml) in invalid {
        let cluster: sbproxy_config::ClusterConfig =
            serde_yaml::from_str(yaml).unwrap_or_else(|error| panic!("{case}: parse: {error}"));
        assert!(cluster.validate().is_err(), "{case} unexpectedly validated");
    }

    let mut cluster: sbproxy_config::ClusterConfig = serde_yaml::from_str(
        r#"
cluster_id: prod-a
node_id: worker-a
roles: [worker]
security:
  mode: mtls
  shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
  cert_file: node.pem
  key_file: node-key.pem
  ca_file: ca.pem
"#,
    )
    .expect("base config");
    for index in 0..65 {
        cluster
            .labels
            .insert(format!("label-{index}"), "value".to_string());
    }
    assert!(cluster.validate().is_err(), "too many labels validated");
}

#[test]
fn development_shared_key_is_explicit_and_valid() {
    let cluster: sbproxy_config::ClusterConfig = serde_yaml::from_str(
        r#"
cluster_id: dev-a
node_id: dev-worker
roles: [gateway, worker]
security:
  mode: shared_key
  development: true
  shared_key: env:SBPROXY_CLUSTER_KEY
"#,
    )
    .expect("development config");
    cluster.validate().expect("explicit development mode");
}

#[test]
fn enrollment_requires_enabled_https_admin_except_explicit_development() {
    let production = parse(
        r#"
cluster:
  cluster_id: prod-a
  node_id: authority-a
  roles: [authority]
  enrollment:
    authority_dir: /var/lib/sbproxy/cluster
  security:
    mode: mtls
    shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
    cert_file: node.pem
    key_file: node-key.pem
    ca_file: ca.pem
"#,
    );
    let error = resolve_effective_cluster(&production).expect_err("admin is required");
    assert!(error.to_string().contains("proxy.admin.enabled"));

    let production_https = parse(
        r#"
admin:
  enabled: true
  tls:
    cert: admin.pem
    key: admin-key.pem
cluster:
  cluster_id: prod-a
  node_id: authority-a
  roles: [authority]
  enrollment:
    authority_dir: /var/lib/sbproxy/cluster
  security:
    mode: mtls
    shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
    cert_file: node.pem
    key_file: node-key.pem
    ca_file: ca.pem
"#,
    );
    resolve_effective_cluster(&production_https).expect("HTTPS enrollment");

    let development = parse(
        r#"
admin:
  enabled: true
cluster:
  cluster_id: dev-a
  node_id: authority-a
  roles: [authority]
  enrollment:
    authority_dir: ./cluster
    allow_insecure_http: true
  security:
    mode: shared_key
    development: true
    shared_key: local-development-secret
"#,
    );
    resolve_effective_cluster(&development).expect("explicit insecure development");

    let mut unsafe_production = production_https;
    unsafe_production
        .cluster
        .as_mut()
        .expect("cluster")
        .enrollment
        .as_mut()
        .expect("enrollment")
        .allow_insecure_http = true;
    let error = resolve_effective_cluster(&unsafe_production)
        .expect_err("production insecure enrollment denied");
    assert!(error.to_string().contains("development shared_key"));
}

#[test]
fn legacy_key_cache_mesh_lowers_to_the_shared_cluster() {
    let proxy = parse(
        r#"
key_management:
  enabled: true
  cache:
    tier: mesh
    mesh_node_id: legacy-worker
    mesh:
      seeds: [10.0.0.11:7946]
      gossip_port: 7947
      transport_port: 8947
      advertise_addr: 10.0.0.12:7947
      transport_advertise_addr: 10.0.0.12:8947
      shared_key: env:SBPROXY_CLUSTER_KEY
"#,
    );

    let effective = resolve_effective_cluster(&proxy)
        .expect("legacy lowering")
        .expect("cluster enabled");
    assert_eq!(effective.source, ClusterConfigSource::LegacyMesh);
    assert_eq!(effective.node_id.as_deref(), Some("legacy-worker"));
    assert_eq!(effective.gossip_port, 7947);
    assert_eq!(effective.transport_port, 8947);
    assert_eq!(
        effective.transport_advertise_addr.as_deref(),
        Some("10.0.0.12:8947")
    );
    assert_eq!(
        effective.security,
        EffectiveClusterSecurity::SharedKey {
            reference: "env:SBPROXY_CLUSTER_KEY".to_string(),
            development: true,
        }
    );
    assert_eq!(effective.diagnostics.len(), 1);
    assert_eq!(effective.diagnostics[0].code, "legacy_mesh_config");
    assert!(effective.diagnostics[0].message.contains("proxy.cluster"));
}

#[test]
fn matching_canonical_and_legacy_mesh_share_one_effective_handle() {
    let proxy = parse(
        r#"
cluster:
  cluster_id: dev-a
  node_id: worker-a
  roles: [gateway, worker]
  seeds: [10.0.0.11:7946]
  gossip_port: 7947
  transport_port: 8947
  advertise_addr: 10.0.0.12:7947
  transport_advertise_addr: 10.0.0.12:8947
  security:
    mode: shared_key
    development: true
    shared_key: env:SBPROXY_CLUSTER_KEY
key_management:
  enabled: true
  cache:
    tier: mesh
    mesh_node_id: worker-a
    mesh:
      seeds: [10.0.0.11:7946]
      gossip_port: 7947
      transport_port: 8947
      advertise_addr: 10.0.0.12:7947
      transport_advertise_addr: 10.0.0.12:8947
      shared_key: env:SBPROXY_CLUSTER_KEY
"#,
    );

    let effective = resolve_effective_cluster(&proxy)
        .expect("matching configs")
        .expect("cluster enabled");
    assert_eq!(effective.source, ClusterConfigSource::CanonicalWithLegacy);
    assert_eq!(effective.node_id.as_deref(), Some("worker-a"));
    assert_eq!(effective.diagnostics.len(), 1);
}

#[test]
fn conflicting_canonical_and_legacy_mesh_are_rejected() {
    let proxy = parse(
        r#"
cluster:
  cluster_id: dev-a
  node_id: worker-a
  roles: [worker]
  gossip_port: 7946
  security:
    mode: shared_key
    development: true
    shared_key: env:SBPROXY_CLUSTER_KEY
key_management:
  enabled: true
  cache:
    tier: mesh
    mesh_node_id: worker-b
    mesh:
      gossip_port: 7999
      shared_key: env:SBPROXY_CLUSTER_KEY
"#,
    );

    let error = resolve_effective_cluster(&proxy).expect_err("conflict must fail");
    let message = error.to_string();
    assert!(message.contains("node_id") || message.contains("gossip_port"));
    assert!(message.contains("proxy.cluster"));
    assert!(message.contains("key_management.cache.mesh"));
}

#[test]
fn restart_fingerprint_excludes_only_snapshot_cadence() {
    let base = parse(
        r#"
cluster:
  cluster_id: prod-a
  node_id: worker-a
  roles: [worker]
  labels: {zone: a}
  security:
    mode: mtls
    shared_key: env:SBPROXY_CLUSTER_GOSSIP_KEY
    cert_file: node.pem
    key_file: node-key.pem
    ca_file: ca.pem
"#,
    );
    let mut cadence = base.clone();
    let cadence_cluster = cadence.cluster.as_mut().expect("cluster");
    cadence_cluster.snapshot_ttl_secs = 60;
    cadence_cluster.publish_interval_secs = 10;

    let base_effective = resolve_effective_cluster(&base)
        .expect("base")
        .expect("enabled");
    let cadence_effective = resolve_effective_cluster(&cadence)
        .expect("cadence")
        .expect("enabled");
    assert_eq!(
        base_effective.restart_fingerprint(),
        cadence_effective.restart_fingerprint()
    );

    let mut identity = cadence;
    identity
        .cluster
        .as_mut()
        .expect("cluster")
        .labels
        .insert("zone".to_string(), "b".to_string());
    let identity_effective = resolve_effective_cluster(&identity)
        .expect("identity")
        .expect("enabled");
    assert_ne!(
        base_effective.restart_fingerprint(),
        identity_effective.restart_fingerprint()
    );

    let mut routing = base;
    routing
        .cluster
        .as_mut()
        .expect("cluster")
        .transport_advertise_addr = Some("10.0.0.12:8946".to_string());
    let routing_effective = resolve_effective_cluster(&routing)
        .expect("routing")
        .expect("enabled");
    assert_ne!(
        base_effective.restart_fingerprint(),
        routing_effective.restart_fingerprint()
    );

    let mut state = base_effective.clone();
    state.state_dir = Some("/var/lib/sbproxy/other-cluster".to_string());
    assert_ne!(
        base_effective.restart_fingerprint(),
        state.restart_fingerprint()
    );
}

#[test]
fn compile_path_enforces_cluster_validation_and_compatibility() {
    let invalid = r#"
proxy:
  cluster:
    cluster_id: prod-a
    node_id: worker-a
    roles: [worker]
    security:
      mode: shared_key
      shared_key: unsafe-inline
origins:
  test.local:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#;
    let error = compile_config(invalid)
        .err()
        .expect("compile rejects unsafe cluster");
    assert!(format!("{error:#}").contains("development: true"));

    let conflict = r#"
proxy:
  cluster:
    cluster_id: dev-a
    node_id: worker-a
    roles: [worker]
    gossip_port: 7946
    security:
      mode: shared_key
      development: true
      shared_key: local-development-secret
  key_management:
    enabled: true
    cache:
      tier: mesh
      mesh_node_id: worker-a
      mesh:
        gossip_port: 7999
        shared_key: local-development-secret
origins:
  test.local:
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#;
    let error = compile_config(conflict)
        .err()
        .expect("compile rejects split cluster bootstrap");
    assert!(format!("{error:#}").contains("gossip_port"));
}
