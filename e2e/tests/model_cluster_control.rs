// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Local multi-process proof for the managed-model cluster control plane.
//!
//! Four real `sbproxy` children share one encrypted gossip and mTLS transport
//! mesh. The test waits for their authenticated admin views to converge on the
//! same model placement, then removes one worker and proves every surviving
//! view retains the full roster while calling out the unhealthy node.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sbproxy_e2e::ProxyHarness;
use sbproxy_mesh::enrollment::{
    install_worker_enrollment, AuthorityInit, EnrollmentAuthority, EnrollmentTokenConstraints,
    WorkerEnrollment,
};
use sbproxy_mesh::ClusterNodeRole;
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

/// A picked port whose socket stays bound until just before the node
/// that will re-bind it is spawned. Dropping the reservation at the
/// last moment shrinks the WOR-2295 window in which a concurrently
/// starting process can be handed the same number while this test is
/// still provisioning identities and validating configs.
struct PortLease {
    _tcp: Option<TcpListener>,
    _udp: Option<UdpSocket>,
}

fn reserve_tcp_port(leases: &mut Vec<PortLease>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve TCP port");
    let port = listener.local_addr().expect("reserved TCP address").port();
    leases.push(PortLease {
        _tcp: Some(listener),
        _udp: None,
    });
    port
}

fn reserve_udp_port(leases: &mut Vec<PortLease>) -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("reserve UDP port");
    let port = socket.local_addr().expect("reserved UDP address").port();
    leases.push(PortLease {
        _tcp: None,
        _udp: Some(socket),
    });
    port
}

fn provision_test_identities(nodes: &[NodeSpec]) -> Result<()> {
    let authority_node = &nodes[0];
    let authority = EnrollmentAuthority::initialize(
        &authority_node.state_dir,
        AuthorityInit {
            cluster_id: CLUSTER_ID.to_string(),
            node_id: authority_node.node_id.to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Authority]),
            labels: BTreeMap::from([("zone".to_string(), authority_node.zone.to_string())]),
            server_name: "sbproxy-mesh".to_string(),
        },
    )
    .context("initialize test enrollment authority")?;
    for node in &nodes[1..] {
        let role = match node.role {
            "gateway" => ClusterNodeRole::Gateway,
            "worker" => ClusterNodeRole::Worker,
            other => anyhow::bail!("unsupported test cluster role {other:?}"),
        };
        let roles = BTreeSet::from([role]);
        let labels = BTreeMap::from([("zone".to_string(), node.zone.to_string())]);
        let token = authority
            .create_token(
                EnrollmentTokenConstraints {
                    allowed_roles: roles.clone(),
                    labels: labels.clone(),
                },
                Duration::from_secs(60),
            )
            .context("create test enrollment token")?;
        let worker = WorkerEnrollment::generate(node.node_id, "sbproxy-mesh")
            .context("generate test enrollment CSR")?;
        let response = authority
            .enroll(worker.request(token.into_token(), roles, labels))
            .context("enroll test cluster node")?;
        install_worker_enrollment(&node.state_dir, worker, response)
            .context("install test cluster identity")?;
    }
    Ok(())
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
    leases: &mut BTreeMap<&'static str, Vec<PortLease>>,
) -> NodeSpec {
    let identity = root.join(node_id);
    let state_dir = identity.join("state");
    let node_leases = leases.entry(node_id).or_default();
    NodeSpec {
        node_id,
        role,
        zone,
        gossip_port: reserve_udp_port(node_leases),
        transport_port: reserve_tcp_port(node_leases),
        admin_port: reserve_tcp_port(node_leases),
        certificate: state_dir.join("node.pem"),
        private_key: state_dir.join("node-key.pem"),
        state_dir,
        cache_dir: identity.join("models"),
        keystore: identity.join("keys.redb"),
    }
}

#[derive(Clone, Copy)]
struct NodeConfigScenario<'a> {
    max_concurrency: u32,
    required_zone: &'a str,
    rollout: &'a str,
    advertised_gossip_port: Option<u16>,
}

fn node_config(
    node: &NodeSpec,
    authority_gossip_port: u16,
    catalog_path: &Path,
    fake_engine_path: &Path,
    scenario: NodeConfigScenario<'_>,
) -> String {
    let NodeConfigScenario {
        max_concurrency,
        required_zone,
        rollout,
        advertised_gossip_port,
    } = scenario;
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
    let advertised_gossip_port = advertised_gossip_port.unwrap_or(node.gossip_port);
    let required_labels = if required_zone.is_empty() {
        "{}".to_string()
    } else {
        format!("{{zone: {required_zone}}}")
    };
    let ca_path = node.state_dir.join("ca.pem");
    let gossip_key_path = node.state_dir.join("gossip.key");
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
    advertise_addr: 127.0.0.1:{advertised_gossip_port}
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
    dead_peer_gc_secs: 2
  model_host:
    authority: file_managed
    catalog_file: "{catalog_path}"
    handoff_timeout_ms: 10000
    cache:
      directory: "{cache_dir}"
    engines:
      llama_cpp:
        launch: binary
        path: "{fake_engine_path}"
    deployments:
      fixture:
        model: fixture-model
        variant: q4
        replicas: 1
        required_labels: {required_labels}
        pull: on_demand
        warm: true
        max_concurrency: {max_concurrency}
        engine: llama_cpp
        rollout: {rollout}
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
        advertise_addr: 127.0.0.1:{advertised_gossip_port}
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
          provider_type: managed_model
          deployment: fixture
          default_model: fixture-model
          models: [fixture-model]
"#,
        admin_port = node.admin_port,
        node_id = node.node_id,
        role = node.role,
        zone = node.zone,
        gossip_port = node.gossip_port,
        advertised_gossip_port = advertised_gossip_port,
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
        max_concurrency = max_concurrency,
        required_labels = required_labels,
        rollout = rollout,
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

fn read_model_host_status(client: &reqwest::blocking::Client, admin_port: u16) -> Result<Value> {
    let response = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/admin/model-host/status"
        ))
        .basic_auth(ADMIN_USER, Some(ADMIN_PASSWORD))
        .send()
        .context("request model-host status")?;
    let status = response.status();
    let body = response.text().context("read model-host status")?;
    anyhow::ensure!(status.is_success(), "model-host status {status}: {body}");
    serde_json::from_str(&body).context("decode model-host status")
}

fn ready_engine_port(client: &reqwest::blocking::Client, node: &NodeSpec) -> Result<u16> {
    let status = read_model_host_status(client, node.admin_port)?;
    let port = status["deployments"]
        .as_array()
        .and_then(|deployments| deployments.iter().find_map(|item| item["port"].as_u64()))
        .context("assigned worker has no ready engine port")?;
    u16::try_from(port).context("engine port exceeds u16")
}

/// Keep an admission-owned request active so recreate's drain phase cannot
/// disappear before the admin assertion observes it.
fn retain_managed_stream(
    client: &reqwest::blocking::Client,
    node: &NodeSpec,
    process: &ProxyHarness,
) -> Result<reqwest::blocking::Response> {
    let engine_port = ready_engine_port(client, node)?;
    client
        .post(format!(
            "http://127.0.0.1:{engine_port}/__control/mode/stream_until_cancelled"
        ))
        .send()
        .context("configure retained model stream")?
        .error_for_status()
        .context("fake engine refused streaming mode")?;
    let streaming_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .context("build retained-stream client")?;
    let mut response = streaming_client
        .post(format!("{}/v1/chat/completions", process.base_url()))
        .header("host", "cluster.test")
        .json(&serde_json::json!({
            "model": "fixture-model",
            "messages": [{"role": "user", "content": "hold this request during recreate"}],
            "stream": true,
        }))
        .send()
        .context("start admission-owned model stream")?;
    anyhow::ensure!(
        response.status().is_success(),
        "retained model stream returned {}: {}",
        response.status(),
        response.text().unwrap_or_default()
    );
    let mut first = [0u8; 6];
    response
        .read_exact(&mut first)
        .context("read first retained stream frame")?;
    anyhow::ensure!(
        &first == b"data: ",
        "retained request did not stream model output"
    );
    Ok(response)
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

/// Convergence budget for every status wait in this file. Sized for a
/// loaded CI runner, not a quiet laptop: the 2026-08-18 release
/// certification run lost a 60s deadline to runner load on a tree that
/// had passed hours earlier. The poll returns as soon as the predicate
/// holds, so a healthy cluster never spends the full budget.
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);

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
        // client IP. One request per second sits exactly at that guard, so
        // clock jitter on a loaded runner can trip it and turn every later
        // poll into a refusal the predicate never sees. 1.5s keeps the
        // fixture at 40 requests per minute per listener with margin.
        std::thread::sleep(Duration::from_millis(1500));
    }
    panic!("cluster status did not converge within {timeout:?}; last observation:\n{last}");
}

fn wait_for_one_status<F>(
    client: &reqwest::blocking::Client,
    admin_port: u16,
    timeout: Duration,
    predicate: F,
) -> Value
where
    F: Fn(&Value) -> bool,
{
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    while Instant::now() < deadline {
        match read_status(client, admin_port) {
            Ok(status) if predicate(&status) => return status,
            Ok(status) => {
                last = serde_json::to_string_pretty(&status)
                    .unwrap_or_else(|error| format!("status serialization failed: {error}"));
            }
            Err(error) => last = format!("{error:#}"),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("cluster status did not reach the expected transition within {timeout:?}; last observation:\n{last}");
}

fn reload_cluster_configs(
    client: &reqwest::blocking::Client,
    nodes: &[NodeSpec],
    processes: &BTreeMap<&'static str, ProxyHarness>,
    configs: &[String],
) -> Result<()> {
    for (node, config) in nodes.iter().zip(configs) {
        let process = processes
            .get(node.node_id)
            .unwrap_or_else(|| panic!("missing process {}", node.node_id));
        process
            .rewrite_config(config)
            .with_context(|| format!("rewrite {} config", node.node_id))?;
        let response = client
            .post(format!("http://127.0.0.1:{}/admin/reload", node.admin_port))
            .basic_auth(ADMIN_USER, Some(ADMIN_PASSWORD))
            .send()
            .with_context(|| format!("reload {}", node.node_id))?;
        anyhow::ensure!(
            response.status().is_success(),
            "reload {} returned {}: {}",
            node.node_id,
            response.status(),
            response.text().unwrap_or_default()
        );
    }
    Ok(())
}

fn deployment_generation(status: &Value) -> u64 {
    status["deployments"][0]["generation"]
        .as_u64()
        .expect("deployment generation")
}

fn versioned_assignment_nodes(status: &Value, field: &str) -> BTreeSet<String> {
    status["deployments"][0][field]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|assignment| assignment["assignment"]["node_id"].as_str())
        .map(str::to_string)
        .collect()
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
    let first_generation = &statuses[0]["deployments"][0]["generation"];
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
            && status["deployments"][0]["phase"] == "stable"
            && status["deployments"][0]["generation"] == *first_generation
            && status["deployments"][0]["assignments"] == *first_assignments
    })
}

fn rolling_handoff_is_waiting(
    status: &Value,
    generation: u64,
    prior_node: &str,
    target_node: &str,
) -> bool {
    deployment_generation(status) == generation
        && status["deployments"][0]["phase"] == "waiting_for_readiness"
        && assignment_nodes(status) == BTreeSet::from([target_node.to_string()])
        && versioned_assignment_nodes(status, "retained")
            == BTreeSet::from([prior_node.to_string()])
        && status["nodes"].as_array().is_some_and(|nodes| {
            nodes.iter().any(|node| {
                node["node_id"] == prior_node
                    && node["replicas"].as_array().is_some_and(|replicas| {
                        replicas.iter().any(|replica| {
                            replica["deployment_generation"] == generation.saturating_sub(1)
                                && replica["state"] == "ready"
                        })
                    })
            })
        })
}

fn recreate_is_draining_before_start(
    status: &Value,
    generation: u64,
    prior_node: &str,
    target_node: &str,
) -> bool {
    deployment_generation(status) == generation
        && status["deployments"][0]["phase"] == "draining_prior"
        && assignment_nodes(status) == BTreeSet::from([target_node.to_string()])
        && versioned_assignment_nodes(status, "draining")
            == BTreeSet::from([prior_node.to_string()])
        && status["nodes"].as_array().is_some_and(|nodes| {
            nodes
                .iter()
                .find(|node| node["node_id"] == target_node)
                .and_then(|node| node["replicas"].as_array())
                .is_none_or(|replicas| {
                    replicas
                        .iter()
                        .all(|replica| replica["deployment_generation"] != generation)
                })
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

fn deployment_digest_mismatch_is_called_out(statuses: &[Value]) -> bool {
    !statuses.is_empty()
        && statuses.iter().all(|status| {
            status["summary"]["total_nodes"] == 4
                && status["summary"]["deployment_digest_mismatch"] == true
                && status["summary"]["unhealthy_nodes"]
                    .as_u64()
                    .is_some_and(|count| count >= 1)
                && status["unhealthy_nodes"]
                    .as_array()
                    .is_some_and(|nodes| !nodes.is_empty())
        })
}

fn partitioned_worker_is_called_out(
    statuses: &[Value],
    node_id: &str,
    advertised_port: u16,
) -> bool {
    let advertised = format!("127.0.0.1:{advertised_port}");
    !statuses.is_empty()
        && statuses.iter().all(|status| {
            status["nodes"].as_array().is_some_and(|nodes| {
                nodes.iter().any(|node| {
                    node["node_id"] == node_id
                        && node["address"] == advertised
                        && node["unhealthy"] == true
                })
            }) && status["unhealthy_nodes"]
                .as_array()
                .is_some_and(|nodes| nodes.iter().any(|node| node["node_id"] == node_id))
        })
}

fn wait_for_tcp_port_to_release(port: u16, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{label} TCP port {port} did not release"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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

/// Environment for every spawned cluster node: the fake engine
/// (spawned by the node's model host) reads
/// `SBPROXY_FAKE_ENGINE_READY_AFTER_PROBES` from its inherited process
/// environment. Passed per child instead of exported from this test
/// runner's own environment (WOR-646).
const NODE_ENV: &[(&str, &str)] = &[("SBPROXY_FAKE_ENGINE_READY_AFTER_PROBES", "20")];

/// Start a cluster node with the fixture's shutdown budget and the
/// fake-engine environment on the child.
fn start_node(config: &str) -> Result<ProxyHarness> {
    ProxyHarness::start_with_workspace_shutdown_grace_and_env(config, &[], 1_000, NODE_ENV)
}

#[test]
fn cluster_converges_and_admin_calls_out_an_unhealthy_worker() -> Result<()> {
    let root = tempfile::tempdir().context("create cluster fixture")?;
    let catalog_path = write_model_fixture(root.path())?;
    let fake_engine_path = Path::new(env!("CARGO_BIN_EXE_fake_model_engine"));
    let mut node_leases: BTreeMap<&'static str, Vec<PortLease>> = BTreeMap::new();
    let nodes = vec![
        node_spec(
            root.path(),
            "authority-a",
            "authority",
            "control",
            &mut node_leases,
        ),
        node_spec(
            root.path(),
            "gateway-a",
            "gateway",
            "edge",
            &mut node_leases,
        ),
        node_spec(
            root.path(),
            "worker-a",
            "worker",
            "zone-a",
            &mut node_leases,
        ),
        node_spec(
            root.path(),
            "worker-b",
            "worker",
            "zone-b",
            &mut node_leases,
        ),
    ];
    provision_test_identities(&nodes)?;
    let authority_gossip_port = nodes[0].gossip_port;
    let configs = nodes
        .iter()
        .map(|node| {
            node_config(
                node,
                authority_gossip_port,
                &catalog_path,
                fake_engine_path,
                NodeConfigScenario {
                    max_concurrency: 1,
                    required_zone: "zone-a",
                    rollout: "rolling",
                    advertised_gossip_port: None,
                },
            )
        })
        .collect::<Vec<_>>();
    for (index, config) in configs.iter().enumerate() {
        validate_config(root.path(), index, config)?;
    }

    let mut processes = BTreeMap::new();
    for (node, config) in nodes.iter().zip(&configs) {
        // Release this node's port reservations only now, so the
        // WOR-2295 window is the spawn itself rather than the identity
        // provisioning and config validation above.
        drop(node_leases.remove(node.node_id));
        processes.insert(
            node.node_id,
            start_node(config).with_context(|| format!("start {}", node.node_id))?,
        );
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build admin client")?;
    let all_admin_ports = nodes.iter().map(|node| node.admin_port).collect::<Vec<_>>();
    let initial_convergence = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_for_statuses(&client, &all_admin_ports, CONVERGENCE_TIMEOUT, converged)
    }));
    let mut statuses = match initial_convergence {
        Ok(statuses) => statuses,
        Err(panic) => {
            for (node_id, process) in &processes {
                eprintln!("\n--- {node_id} stdout ---\n{}", process.stdout_contents());
                eprintln!("\n--- {node_id} stderr ---\n{}", process.stderr_contents());
            }
            for process in processes.values_mut() {
                let _ = process.terminate_gracefully(Duration::from_secs(5));
            }
            std::panic::resume_unwind(panic);
        }
    };
    let initial_generation = deployment_generation(&statuses[0]);
    assert_eq!(
        assignment_nodes(&statuses[0]),
        BTreeSet::from(["worker-a".to_string()])
    );

    // Restart one controller without changing desired state. It must recover
    // generation and assignment identity from authenticated replica fences,
    // rather than incrementing away from the still-live controllers.
    let mut gateway = processes
        .remove("gateway-a")
        .context("gateway process is absent")?;
    gateway
        .terminate_gracefully(Duration::from_secs(5))
        .context("stop gateway controller")?;
    drop(gateway);
    let restarted_gateway = start_node(&configs[1]).context("restart gateway controller")?;
    processes.insert("gateway-a", restarted_gateway);
    statuses = wait_for_statuses(&client, &all_admin_ports, CONVERGENCE_TIMEOUT, converged);
    let restarted_gateway_status = statuses
        .iter()
        .find(|status| status["local_node_id"] == "gateway-a")
        .expect("restarted gateway status");
    assert_eq!(
        deployment_generation(restarted_gateway_status),
        initial_generation
    );
    assert_eq!(
        assignment_nodes(&statuses[0]),
        BTreeSet::from(["worker-a".to_string()])
    );

    // Rolling moves the replica to worker-b. The replacement is started and
    // observed before worker-a is removed from the retained set.
    let rolling_configs = nodes
        .iter()
        .map(|node| {
            node_config(
                node,
                authority_gossip_port,
                &catalog_path,
                fake_engine_path,
                NodeConfigScenario {
                    max_concurrency: 1,
                    required_zone: "zone-b",
                    rollout: "rolling",
                    advertised_gossip_port: None,
                },
            )
        })
        .collect::<Vec<_>>();
    reload_cluster_configs(&client, &nodes, &processes, &rolling_configs)?;
    let rolling_generation = initial_generation + 1;
    wait_for_one_status(
        &client,
        nodes[1].admin_port,
        Duration::from_secs(15),
        |status| rolling_handoff_is_waiting(status, rolling_generation, "worker-a", "worker-b"),
    );
    statuses = wait_for_statuses(&client, &all_admin_ports, CONVERGENCE_TIMEOUT, converged);
    assert_eq!(deployment_generation(&statuses[0]), rolling_generation);
    assert_eq!(
        assignment_nodes(&statuses[0]),
        BTreeSet::from(["worker-b".to_string()])
    );

    // Recreate moves back to worker-a, but first emits a drain-only phase in
    // which the target generation is absent from worker-a's replica truth.
    let recreate_configs = nodes
        .iter()
        .map(|node| {
            node_config(
                node,
                authority_gossip_port,
                &catalog_path,
                fake_engine_path,
                NodeConfigScenario {
                    max_concurrency: 1,
                    required_zone: "zone-a",
                    rollout: "recreate",
                    advertised_gossip_port: None,
                },
            )
        })
        .collect::<Vec<_>>();
    let retained_stream = retain_managed_stream(&client, &nodes[3], &processes["worker-b"])?;
    let reload_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(45))
        .build()
        .context("build recreate reload client")?;
    let recreate_generation = rolling_generation + 1;
    std::thread::scope(|scope| -> Result<()> {
        // Keep the stream inside the scope so a failed assertion releases
        // its admission before the reload thread is joined during unwinding.
        let draining_request = retained_stream;
        let reload = scope.spawn(|| {
            reload_cluster_configs(&reload_client, &nodes, &processes, &recreate_configs)
        });
        wait_for_one_status(
            &client,
            nodes[1].admin_port,
            Duration::from_secs(15),
            |status| {
                recreate_is_draining_before_start(
                    status,
                    recreate_generation,
                    "worker-b",
                    "worker-a",
                )
            },
        );
        drop(draining_request);
        reload.join().expect("recreate reload thread")?;
        Ok(())
    })?;
    statuses = wait_for_statuses(&client, &all_admin_ports, CONVERGENCE_TIMEOUT, converged);
    assert_eq!(deployment_generation(&statuses[0]), recreate_generation);
    assert_eq!(
        assignment_nodes(&statuses[0]),
        BTreeSet::from(["worker-a".to_string()])
    );

    // Return to an unconstrained steady policy so the subsequent worker loss
    // can prove deterministic failover to the remaining worker.
    let steady_configs = nodes
        .iter()
        .map(|node| {
            node_config(
                node,
                authority_gossip_port,
                &catalog_path,
                fake_engine_path,
                NodeConfigScenario {
                    max_concurrency: 1,
                    required_zone: "",
                    rollout: "rolling",
                    advertised_gossip_port: None,
                },
            )
        })
        .collect::<Vec<_>>();
    reload_cluster_configs(&client, &nodes, &processes, &steady_configs)?;
    statuses = wait_for_statuses(&client, &all_admin_ports, CONVERGENCE_TIMEOUT, converged);

    let initial_assignments = assignment_nodes(&statuses[0]);
    assert_eq!(initial_assignments.len(), 1);
    let failed_node_id = initial_assignments
        .first()
        .expect("one initial assignment")
        .clone();
    let failed_index = nodes
        .iter()
        .position(|node| node.node_id == failed_node_id)
        .context("placement selected an unknown node")?;
    anyhow::ensure!(
        nodes[failed_index].role == "worker",
        "placement selected non-worker"
    );
    let engine_port = ready_engine_port(&client, &nodes[failed_index])?;
    let mut failed_process = processes
        .remove(failed_node_id.as_str())
        .context("failed worker process is absent")?;
    failed_process
        .terminate_gracefully(Duration::from_secs(5))
        .context("gracefully stop assigned worker")?;
    drop(failed_process);
    wait_for_tcp_port_to_release(engine_port, "managed engine child");
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

    // Routing membership GCs the dead peer after two seconds, while every
    // admin directory must retain its tombstone and operator callout.
    std::thread::sleep(Duration::from_secs(3));
    let retained = wait_for_statuses(
        &client,
        &surviving_admin_ports,
        Duration::from_secs(10),
        |statuses| failed_worker_is_called_out(statuses, &failed_node_id),
    );
    assert!(retained.iter().all(|status| {
        status["nodes"]
            .as_array()
            .is_some_and(|nodes| nodes.iter().any(|node| node["node_id"] == failed_node_id))
    }));

    // Rejoin with a signed but unreachable gossip advertisement. Peers retain
    // the same enrolled identity yet must call out the partitioned node.
    // The lease stays held on purpose: nothing may answer on this port,
    // and keeping our own silent socket bound guarantees no concurrent
    // test's process is handed the same number.
    let mut bad_gossip_lease = Vec::new();
    let bad_gossip_port = reserve_udp_port(&mut bad_gossip_lease);
    let partitioned_config = node_config(
        &nodes[failed_index],
        authority_gossip_port,
        &catalog_path,
        fake_engine_path,
        NodeConfigScenario {
            max_concurrency: 1,
            required_zone: "",
            rollout: "rolling",
            advertised_gossip_port: Some(bad_gossip_port),
        },
    );
    validate_config(root.path(), 100, &partitioned_config)?;
    let mut partitioned = start_node(&partitioned_config).context("start partitioned worker")?;
    wait_for_statuses(
        &client,
        &surviving_admin_ports,
        Duration::from_secs(20),
        |statuses| partitioned_worker_is_called_out(statuses, &failed_node_id, bad_gossip_port),
    );
    partitioned
        .terminate_gracefully(Duration::from_secs(5))
        .context("stop partitioned worker")?;
    drop(partitioned);

    // A different concurrency policy changes the deployment digest. Every
    // surviving admin view must surface the mismatch, then clear it after the
    // node returns to the fleet's rolling policy.
    let mismatch_config = node_config(
        &nodes[failed_index],
        authority_gossip_port,
        &catalog_path,
        fake_engine_path,
        NodeConfigScenario {
            max_concurrency: 2,
            required_zone: "",
            rollout: "rolling",
            advertised_gossip_port: None,
        },
    );
    validate_config(root.path(), 101, &mismatch_config)?;
    let mut mismatched = start_node(&mismatch_config).context("start digest-mismatched worker")?;
    let mismatch_ports = nodes
        .iter()
        .filter(|node| node.node_id != failed_node_id)
        .map(|node| node.admin_port)
        .collect::<Vec<_>>();
    wait_for_statuses(
        &client,
        &mismatch_ports,
        Duration::from_secs(20),
        deployment_digest_mismatch_is_called_out,
    );
    mismatched
        .terminate_gracefully(Duration::from_secs(5))
        .context("stop digest-mismatched worker")?;
    drop(mismatched);

    let recovered = start_node(&steady_configs[failed_index])
        .context("restart worker with matching deployment policy")?;
    processes.insert(nodes[failed_index].node_id, recovered);
    let recovery = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_for_statuses(&client, &all_admin_ports, CONVERGENCE_TIMEOUT, converged)
    }));
    if let Err(panic) = recovery {
        for (node_id, process) in &processes {
            eprintln!("\n--- {node_id} stdout ---\n{}", process.stdout_contents());
            eprintln!("\n--- {node_id} stderr ---\n{}", process.stderr_contents());
        }
        for process in processes.values_mut() {
            let _ = process.terminate_gracefully(Duration::from_secs(5));
        }
        std::panic::resume_unwind(panic);
    }

    for process in processes.values_mut() {
        process
            .terminate_gracefully(Duration::from_secs(5))
            .context("gracefully stop cluster process")?;
    }
    drop(processes);
    wait_for_ports_to_release(&nodes);
    Ok(())
}
