// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Local multi-process proof for the managed-model cluster control plane.
//!
//! Four real `sbproxy` children share one encrypted gossip and mTLS transport
//! mesh. The test waits for their authenticated admin views to converge on the
//! same model placement, then removes one worker and proves every surviving
//! view retains the full roster while calling out the unhealthy node.

use std::collections::BTreeSet;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use sbproxy_e2e::ProxyHarness;
use serde_json::Value;
use sha2::{Digest, Sha256};

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "cluster-test-secret";
const CLUSTER_ID: &str = "model-control-e2e";

#[derive(Debug, Clone)]
struct NodeSpec {
    node_id: &'static str,
    role: &'static str,
    zone: &'static str,
    gossip_port: u16,
    transport_port: u16,
    admin_port: u16,
    certificate: PathBuf,
    private_key: PathBuf,
    state_dir: PathBuf,
    cache_dir: PathBuf,
    keystore: PathBuf,
}

fn reserve_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve TCP port")
        .local_addr()
        .expect("reserved TCP address")
        .port()
}

fn reserve_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("reserve UDP port")
        .local_addr()
        .expect("reserved UDP address")
        .port()
}

fn write_test_pki(root: &Path, node_ids: &[&str]) -> Result<(PathBuf, PathBuf)> {
    let ca_key = KeyPair::generate().context("generate cluster CA key")?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params
        .self_signed(&ca_key)
        .context("self-sign cluster CA")?;
    let ca_path = root.join("ca.pem");
    fs::write(&ca_path, ca.pem()).context("write cluster CA")?;

    let gossip_key_path = root.join("gossip.key");
    fs::write(&gossip_key_path, "model-control-e2e-gossip-key-32-bytes")
        .context("write gossip key")?;

    for node_id in node_ids {
        let node_dir = root.join(node_id);
        fs::create_dir_all(&node_dir).context("create node identity directory")?;
        let key = KeyPair::generate().context("generate node key")?;
        let mut params =
            CertificateParams::new(vec!["sbproxy-mesh".to_string(), (*node_id).to_string()])?;
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = params
            .signed_by(&key, &ca, &ca_key)
            .context("sign node certificate")?;
        fs::write(node_dir.join("node.pem"), certificate.pem())
            .context("write node certificate")?;
        fs::write(node_dir.join("node-key.pem"), key.serialize_pem())
            .context("write node private key")?;
    }

    Ok((ca_path, gossip_key_path))
}

fn write_model_fixture(root: &Path) -> Result<PathBuf> {
    let source = root.join("fixture-model");
    fs::create_dir_all(&source).context("create fixture model source")?;
    let config = br#"{"hidden_size":16,"num_hidden_layers":2,"num_attention_heads":2,"num_key_value_heads":2,"max_position_embeddings":128}"#;
    let weights = b"GGUF deterministic cluster control fixture";
    fs::write(source.join("config.json"), config).context("write fixture model config")?;
    fs::write(source.join("weights.gguf"), weights).context("write fixture model weights")?;
    let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let catalog = format!(
        r#"schema_version: 2
catalog_revision: model-control-e2e-v1
models:
  fixture-model:
    params: 0.001B
    license: apache-2.0
    family: fixture
    context_length: 128
    pull: on_demand
    variants:
      - id: q4
        format: gguf
        quant: Q4
        engines: [llama_cpp]
        source: "file:{source}"
        revision: 1111111111111111111111111111111111111111
        files:
          - path: config.json
            sha256: {config_digest}
            size_bytes: {config_size}
          - path: weights.gguf
            sha256: {weights_digest}
            size_bytes: {weights_size}
        requirements:
          accelerators: [cpu, metal, cuda]
          min_memory_bytes: 1
        stability: preview
        certification: local-multi-process-fixture
"#,
        source = source.display(),
        config_digest = digest(config),
        config_size = config.len(),
        weights_digest = digest(weights),
        weights_size = weights.len(),
    );
    let catalog_path = root.join("models.yaml");
    fs::write(&catalog_path, catalog).context("write fixture model catalog")?;
    Ok(catalog_path)
}

fn node_spec(
    root: &Path,
    node_id: &'static str,
    role: &'static str,
    zone: &'static str,
) -> NodeSpec {
    let identity = root.join(node_id);
    NodeSpec {
        node_id,
        role,
        zone,
        gossip_port: reserve_udp_port(),
        transport_port: reserve_tcp_port(),
        admin_port: reserve_tcp_port(),
        certificate: identity.join("node.pem"),
        private_key: identity.join("node-key.pem"),
        state_dir: identity.join("state"),
        cache_dir: identity.join("models"),
        keystore: identity.join("keys.redb"),
    }
}

fn node_config(
    node: &NodeSpec,
    authority_gossip_port: u16,
    ca_path: &Path,
    gossip_key_path: &Path,
    catalog_path: &Path,
    fake_engine_path: &Path,
) -> String {
    let seeds = if node.node_id == "authority-a" {
        "[]".to_string()
    } else {
        format!("[127.0.0.1:{authority_gossip_port}]")
    };
    let model_endpoint = if node.role == "worker" {
        format!(
            "\n    model_endpoint: https://{}.model.internal:9443",
            node.node_id
        )
    } else {
        String::new()
    };
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    bind: 127.0.0.1
    port: {admin_port}
    username: {ADMIN_USER}
    password: {ADMIN_PASSWORD}
  cluster:
    cluster_id: {CLUSTER_ID}
    node_id: {node_id}
    roles: [{role}]
    labels: {{zone: {zone}}}
    seeds: {seeds}
    gossip_port: {gossip_port}
    transport_port: {transport_port}
    advertise_addr: 127.0.0.1:{gossip_port}
    transport_advertise_addr: 127.0.0.1:{transport_port}{model_endpoint}
    state_dir: "{state_dir}"
    security:
      mode: mtls
      shared_key: "file:{gossip_key}"
      cert_file: "{certificate}"
      key_file: "{private_key}"
      ca_file: "{ca_path}"
      server_name: sbproxy-mesh
    snapshot_ttl_secs: 10
    publish_interval_secs: 1
  key_management:
    enabled: true
    store:
      backend: embedded
      path: "{keystore}"
    cache:
      tier: mesh
      mesh_node_id: {node_id}
      mesh:
        seeds: {seeds}
        gossip_port: {gossip_port}
        transport_port: {transport_port}
        advertise_addr: 127.0.0.1:{gossip_port}
        transport_advertise_addr: 127.0.0.1:{transport_port}
        shared_key: "file:{gossip_key}"
        peer_tls:
          cert_file: "{certificate}"
          key_file: "{private_key}"
          ca_file: "{ca_path}"
          server_name: sbproxy-mesh
    crypto:
      pepper: model-control-e2e-pepper
      master_key: model-control-e2e-master-key
origins:
  "cluster.test":
    action:
      type: ai_proxy
      providers:
        - name: local
          default_model: fixture-model
          models: [fixture-model]
          serve:
            catalog_file: "{catalog_path}"
            cache_dir: "{cache_dir}"
            engines:
              llama_cpp:
                launch: binary
                acquire:
                  source: path
                  path: "{fake_engine_path}"
            models:
              - model: fixture-model
                variant: q4
                engine: llama_cpp
"#,
        admin_port = node.admin_port,
        node_id = node.node_id,
        role = node.role,
        zone = node.zone,
        gossip_port = node.gossip_port,
        transport_port = node.transport_port,
        state_dir = node.state_dir.display(),
        gossip_key = gossip_key_path.display(),
        certificate = node.certificate.display(),
        private_key = node.private_key.display(),
        ca_path = ca_path.display(),
        keystore = node.keystore.display(),
        cache_dir = node.cache_dir.display(),
        catalog_path = catalog_path.display(),
        fake_engine_path = fake_engine_path.display(),
    )
}

fn read_status(client: &reqwest::blocking::Client, admin_port: u16) -> Result<Value> {
    let response = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/admin/cluster/status"
        ))
        .basic_auth(ADMIN_USER, Some(ADMIN_PASSWORD))
        .send()
        .context("request cluster status")?;
    let status = response.status();
    let body = response.text().context("read cluster status")?;
    anyhow::ensure!(status.is_success(), "cluster status {status}: {body}");
    serde_json::from_str(&body).context("decode cluster status")
}

fn validate_config(root: &Path, index: usize, config: &str) -> Result<()> {
    let path = root.join(format!("node-{index}.yml"));
    fs::write(&path, config).context("write validation config")?;
    let output = Command::new(sbproxy_e2e::proxy_binary_path())
        .arg("validate")
        .arg(&path)
        .output()
        .context("run sbproxy validate")?;
    anyhow::ensure!(
        output.status.success(),
        "sbproxy validate failed for node {index}:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn wait_for_statuses<F>(
    client: &reqwest::blocking::Client,
    admin_ports: &[u16],
    timeout: Duration,
    predicate: F,
) -> Vec<Value>
where
    F: Fn(&[Value]) -> bool,
{
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    while Instant::now() < deadline {
        match admin_ports
            .iter()
            .map(|port| read_status(client, *port))
            .collect::<Result<Vec<_>>>()
        {
            Ok(statuses) if predicate(&statuses) => return statuses,
            Ok(statuses) => {
                last = serde_json::to_string_pretty(&statuses)
                    .unwrap_or_else(|error| format!("status serialization failed: {error}"));
            }
            Err(error) if last.is_empty() => last = format!("{error:#}"),
            Err(_) => {}
        }
        // The production admin listener permits 60 requests per minute per
        // client IP. One request per second keeps the fixture below that guard
        // even when both the convergence and failure windows run to timeout.
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("cluster status did not converge within {timeout:?}; last observation:\n{last}");
}

fn assignment_nodes(status: &Value) -> BTreeSet<String> {
    status["deployments"][0]["assignments"]
        .as_array()
        .expect("deployment assignments")
        .iter()
        .map(|assignment| {
            assignment["node_id"]
                .as_str()
                .expect("assignment node ID")
                .to_string()
        })
        .collect()
}

fn converged(statuses: &[Value]) -> bool {
    if statuses.len() != 4 {
        return false;
    }
    let first_assignments = &statuses[0]["deployments"][0]["assignments"];
    statuses.iter().all(|status| {
        status["configured"] == true
            && status["mode"] == "distributed"
            && status["summary"]["total_nodes"] == 4
            && status["summary"]["eligible_workers"] == 2
            && status["summary"]["unhealthy_nodes"] == 0
            && status["summary"]["deployment_digest_mismatch"] == false
            && status["summary"]["unplaced_replicas"] == 0
            && status["nodes"]
                .as_array()
                .is_some_and(|nodes| nodes.len() == 4)
            && status["deployments"]
                .as_array()
                .is_some_and(|items| items.len() == 1)
            && status["deployments"][0]["assignments"]
                .as_array()
                .is_some_and(|assignments| assignments.len() == 1)
            && status["deployments"][0]["target_ready"] == true
            && status["deployments"][0]["assignments"] == *first_assignments
    })
}

fn failed_worker_is_called_out(statuses: &[Value], failed_node_id: &str) -> bool {
    let first_assignments = &statuses[0]["deployments"][0]["assignments"];
    statuses.iter().all(|status| {
        let nodes = status["nodes"].as_array().cloned().unwrap_or_default();
        let alerts = status["unhealthy_nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        status["summary"]["total_nodes"] == 4
            && status["summary"]["eligible_workers"] == 1
            && nodes.iter().any(|node| {
                node["node_id"] == failed_node_id
                    && node["unhealthy"] == true
                    && node["model_eligible"] == false
            })
            && alerts.iter().any(|alert| {
                alert["node_id"] == failed_node_id
                    && alert["reasons"]
                        .as_array()
                        .is_some_and(|reasons| !reasons.is_empty())
            })
            && status["summary"]["unplaced_replicas"] == 0
            && status["deployments"][0]["target_ready"] == true
            && status["deployments"][0]["assignments"] == *first_assignments
            && status["deployments"][0]["assignments"]
                .as_array()
                .is_some_and(|assignments| assignments.len() == 1)
    })
}

fn wait_for_ports_to_release(nodes: &[NodeSpec]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let released = nodes.iter().all(|node| {
            UdpSocket::bind(("127.0.0.1", node.gossip_port)).is_ok()
                && TcpListener::bind(("127.0.0.1", node.transport_port)).is_ok()
                && TcpListener::bind(("127.0.0.1", node.admin_port)).is_ok()
        });
        if released {
            return;
        }
        assert!(Instant::now() < deadline, "cluster ports did not release");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn cluster_converges_and_admin_calls_out_an_unhealthy_worker() -> Result<()> {
    let root = tempfile::tempdir().context("create cluster fixture")?;
    let node_ids = ["authority-a", "gateway-a", "worker-a", "worker-b"];
    let (ca_path, gossip_key_path) = write_test_pki(root.path(), &node_ids)?;
    let catalog_path = write_model_fixture(root.path())?;
    let fake_engine_path = Path::new(env!("CARGO_BIN_EXE_fake_model_engine"));
    let nodes = vec![
        node_spec(root.path(), "authority-a", "authority", "control"),
        node_spec(root.path(), "gateway-a", "gateway", "edge"),
        node_spec(root.path(), "worker-a", "worker", "zone-a"),
        node_spec(root.path(), "worker-b", "worker", "zone-b"),
    ];
    let authority_gossip_port = nodes[0].gossip_port;
    let configs = nodes
        .iter()
        .map(|node| {
            node_config(
                node,
                authority_gossip_port,
                &ca_path,
                &gossip_key_path,
                &catalog_path,
                fake_engine_path,
            )
        })
        .collect::<Vec<_>>();
    for (index, config) in configs.iter().enumerate() {
        validate_config(root.path(), index, config)?;
    }

    let authority = ProxyHarness::start_with_yaml(&configs[0]).context("start authority")?;
    let gateway = ProxyHarness::start_with_yaml(&configs[1]).context("start gateway")?;
    let mut worker_a = Some(ProxyHarness::start_with_yaml(&configs[2]).context("start worker A")?);
    let mut worker_b = Some(ProxyHarness::start_with_yaml(&configs[3]).context("start worker B")?);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build admin client")?;
    let all_admin_ports = nodes.iter().map(|node| node.admin_port).collect::<Vec<_>>();
    let statuses = wait_for_statuses(
        &client,
        &all_admin_ports,
        Duration::from_secs(30),
        converged,
    );
    let initial_assignments = assignment_nodes(&statuses[0]);
    assert_eq!(initial_assignments.len(), 1);
    let failed_node_id = initial_assignments
        .first()
        .expect("one initial assignment")
        .clone();

    match failed_node_id.as_str() {
        "worker-a" => drop(worker_a.take()),
        "worker-b" => drop(worker_b.take()),
        other => panic!("placement selected non-worker {other:?}"),
    }
    let surviving_admin_ports = nodes
        .iter()
        .filter(|node| node.node_id != failed_node_id)
        .map(|node| node.admin_port)
        .collect::<Vec<_>>();
    let degraded = wait_for_statuses(
        &client,
        &surviving_admin_ports,
        Duration::from_secs(20),
        |statuses| failed_worker_is_called_out(statuses, &failed_node_id),
    );
    let surviving_assignments = assignment_nodes(&degraded[0]);
    assert_eq!(surviving_assignments.len(), 1);
    assert!(!surviving_assignments.contains(&failed_node_id));

    drop(worker_a);
    drop(worker_b);
    drop(gateway);
    drop(authority);
    wait_for_ports_to_release(&nodes);
    Ok(())
}
