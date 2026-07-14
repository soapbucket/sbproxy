// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Local three-process proof for the authenticated managed-model data plane.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Read;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "model-dispatch-admin";
const CLUSTER_ID: &str = "model-dispatch-e2e";
const CLUSTER_SECRET: &str = "model-dispatch-development-secret-123456";
const HOST: &str = "cluster.test";
const DEPLOYMENT: &str = "fixture";
const LOGICAL_MODEL: &str = "fixture-model";
const PUBLIC_KEY: &str = "public-model-key-must-not-reach-workers";

#[derive(Debug, Clone)]
struct NodeSpec {
    node_id: &'static str,
    role: &'static str,
    zone: &'static str,
    gossip_port: u16,
    transport_port: u16,
    admin_port: u16,
    model_port: Option<u16>,
    state_dir: PathBuf,
    cache_dir: PathBuf,
}

#[derive(Debug)]
struct ChatResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Clone, Copy)]
struct NodeConfigPolicy<'a> {
    cold_start: &'a str,
    routing: &'a str,
    fallback_url: Option<&'a str>,
    placeable: bool,
}

struct ThreeNodeCluster {
    _root: tempfile::TempDir,
    nodes: Vec<NodeSpec>,
    processes: BTreeMap<&'static str, ProxyHarness>,
    expanded_configs: Vec<String>,
    client: reqwest::blocking::Client,
    engine_ports: BTreeMap<&'static str, u16>,
    primary_worker: Option<&'static str>,
    failover_prompt: Option<String>,
    fallback_upstream: Option<MockUpstream>,
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

fn node_spec(
    root: &Path,
    node_id: &'static str,
    role: &'static str,
    zone: &'static str,
) -> NodeSpec {
    let node_root = root.join(node_id);
    NodeSpec {
        node_id,
        role,
        zone,
        gossip_port: reserve_udp_port(),
        transport_port: reserve_tcp_port(),
        admin_port: reserve_tcp_port(),
        model_port: (role == "worker").then(reserve_tcp_port),
        state_dir: node_root.join("state"),
        cache_dir: node_root.join("models"),
    }
}

fn write_model_fixture(root: &Path) -> Result<PathBuf> {
    let source = root.join("fixture-model");
    fs::create_dir_all(&source).context("create fixture model source")?;
    let config = br#"{"hidden_size":16,"num_hidden_layers":2,"num_attention_heads":2,"num_key_value_heads":2,"max_position_embeddings":128}"#;
    let weights = b"GGUF deterministic model dispatch fixture";
    fs::write(source.join("config.json"), config).context("write fixture model config")?;
    fs::write(source.join("weights.gguf"), weights).context("write fixture model weights")?;
    let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let catalog = format!(
        r#"schema_version: 2
catalog_revision: model-dispatch-e2e-v1
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
        certification: local-three-process-data-plane
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

fn node_config(
    node: &NodeSpec,
    gateway_gossip_port: u16,
    catalog_path: &Path,
    fake_engine_path: &Path,
    replicas: u32,
    policy: NodeConfigPolicy<'_>,
) -> String {
    let seeds = if node.role == "gateway" {
        "[]".to_string()
    } else {
        format!("[127.0.0.1:{gateway_gossip_port}]")
    };
    let model_plane = node.model_port.map_or_else(String::new, |port| {
        format!("\n    model_bind: 127.0.0.1:{port}\n    model_endpoint: http://127.0.0.1:{port}")
    });
    let fallback_provider = policy.fallback_url.map_or_else(String::new, |base_url| {
        format!(
            r#"
        - name: external
          provider_type: openai
          api_key: fixture
          base_url: "{base_url}"
          allow_private_base_url: true
          models: [{LOGICAL_MODEL}]"#
        )
    });
    let required_labels = if policy.placeable {
        "{}"
    } else {
        "{accelerator: unavailable}"
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
    transport_advertise_addr: 127.0.0.1:{transport_port}{model_plane}
    state_dir: "{state_dir}"
    security:
      mode: shared_key
      development: true
      shared_key: {CLUSTER_SECRET}
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
      {DEPLOYMENT}:
        model: {LOGICAL_MODEL}
        variant: q4
        replicas: {replicas}
        required_labels: {required_labels}
        spread_by: [zone]
        pull: on_demand
        warm: false
        cold_start: {cold_start}
        max_concurrency: 1
        max_queue_depth: 8
        queue_timeout_ms: 3000
        engine: llama_cpp
        rollout: rolling
origins:
  "{HOST}":
    action:
      type: ai_proxy
      routing: {routing}
      providers:
        - name: managed
          provider_type: managed_model
          deployment: {DEPLOYMENT}
          models: [{LOGICAL_MODEL}]
          default_model: {LOGICAL_MODEL}
{fallback_provider}
"#,
        admin_port = node.admin_port,
        node_id = node.node_id,
        role = node.role,
        zone = node.zone,
        gossip_port = node.gossip_port,
        transport_port = node.transport_port,
        state_dir = node.state_dir.display(),
        catalog_path = catalog_path.display(),
        cache_dir = node.cache_dir.display(),
        fake_engine_path = fake_engine_path.display(),
        replicas = replicas,
        cold_start = policy.cold_start,
        routing = policy.routing,
        fallback_provider = fallback_provider,
        required_labels = required_labels,
    )
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

impl ThreeNodeCluster {
    fn start() -> Result<Self> {
        Self::start_with_policy("wait", "fallback_chain", None, true)
    }

    fn start_with_policy(
        cold_start: &str,
        routing: &str,
        fallback_upstream: Option<MockUpstream>,
        placeable: bool,
    ) -> Result<Self> {
        let root = tempfile::tempdir().context("create model dispatch fixture")?;
        let catalog_path = write_model_fixture(root.path())?;
        let fake_engine_path = Path::new(env!("CARGO_BIN_EXE_fake_model_engine"));
        let nodes = vec![
            node_spec(root.path(), "gateway-a", "gateway", "edge"),
            node_spec(root.path(), "worker-a", "worker", "zone-a"),
            node_spec(root.path(), "worker-b", "worker", "zone-b"),
        ];
        let gateway_gossip_port = nodes[0].gossip_port;
        let fallback_url = fallback_upstream.as_ref().map(MockUpstream::base_url);
        let policy = NodeConfigPolicy {
            cold_start,
            routing,
            fallback_url: fallback_url.as_deref(),
            placeable,
        };
        let configs = nodes
            .iter()
            .map(|node| {
                node_config(
                    node,
                    gateway_gossip_port,
                    &catalog_path,
                    fake_engine_path,
                    1,
                    policy,
                )
            })
            .collect::<Vec<_>>();
        let expanded_configs = nodes
            .iter()
            .map(|node| {
                node_config(
                    node,
                    gateway_gossip_port,
                    &catalog_path,
                    fake_engine_path,
                    2,
                    policy,
                )
            })
            .collect::<Vec<_>>();
        for (index, config) in configs.iter().enumerate() {
            validate_config(root.path(), index, config)?;
        }
        for (index, config) in expanded_configs.iter().enumerate() {
            validate_config(root.path(), index + configs.len(), config)?;
        }

        let mut processes = BTreeMap::new();
        for (node, config) in nodes.iter().zip(&configs) {
            processes.insert(
                node.node_id,
                ProxyHarness::start_with_workspace_and_shutdown_grace(config, &[], 1_000)
                    .with_context(|| format!("start {}", node.node_id))?,
            );
            ProxyHarness::wait_for_port(node.admin_port, Duration::from_secs(10))
                .with_context(|| format!("wait for {} admin", node.node_id))?;
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("build model dispatch client")?;
        let cluster = Self {
            _root: root,
            nodes,
            processes,
            expanded_configs,
            client,
            engine_ports: BTreeMap::new(),
            primary_worker: None,
            failover_prompt: None,
            fallback_upstream,
        };
        cluster.wait_for_assignments(usize::from(placeable), Duration::from_secs(40))?;
        Ok(cluster)
    }

    fn gateway(&self) -> &ProxyHarness {
        self.processes.get("gateway-a").expect("gateway process")
    }

    fn worker(&self, node_id: &str) -> &NodeSpec {
        self.nodes
            .iter()
            .find(|node| node.node_id == node_id)
            .unwrap_or_else(|| panic!("missing worker {node_id}"))
    }

    fn worker_ids(&self) -> [&'static str; 2] {
        ["worker-a", "worker-b"]
    }

    fn read_cluster_status(&self) -> Result<Value> {
        let gateway = self.worker("gateway-a");
        let response = self
            .client
            .get(format!(
                "http://127.0.0.1:{}/admin/cluster/status",
                gateway.admin_port
            ))
            .basic_auth(ADMIN_USER, Some(ADMIN_PASSWORD))
            .send()
            .context("request cluster status")?;
        let status = response.status();
        let body = response.text().context("read cluster status")?;
        anyhow::ensure!(status.is_success(), "cluster status {status}: {body}");
        serde_json::from_str(&body).context("decode cluster status")
    }

    fn read_model_status(&self, node_id: &str) -> Result<Value> {
        let node = self.worker(node_id);
        let response = self
            .client
            .get(format!(
                "http://127.0.0.1:{}/admin/model-host/status",
                node.admin_port
            ))
            .basic_auth(ADMIN_USER, Some(ADMIN_PASSWORD))
            .send()
            .with_context(|| format!("request {node_id} model status"))?;
        let status = response.status();
        let body = response.text().context("read model status")?;
        anyhow::ensure!(
            status.is_success(),
            "{node_id} model status {status}: {body}"
        );
        serde_json::from_str(&body).context("decode model status")
    }

    fn wait_for_assignments(&self, expected_replicas: usize, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut last = String::new();
        while Instant::now() < deadline {
            match self.read_cluster_status() {
                Ok(status) => {
                    let workers_with_replicas = status["nodes"]
                        .as_array()
                        .map(|nodes| {
                            self.worker_ids()
                                .iter()
                                .filter(|node_id| {
                                    nodes.iter().any(|node| {
                                        node["node_id"] == **node_id
                                            && node["replicas"]
                                                .as_array()
                                                .is_some_and(|replicas| !replicas.is_empty())
                                    })
                                })
                                .count()
                        })
                        .unwrap_or_default();
                    if status["summary"]["total_nodes"] == 3
                        && status["summary"]["eligible_workers"] == 2
                        && status["deployments"][0]["assignments"]
                            .as_array()
                            .is_some_and(|assignments| assignments.len() == expected_replicas)
                        && workers_with_replicas == expected_replicas
                    {
                        return Ok(());
                    }
                    last = serde_json::to_string_pretty(&status).unwrap_or_default();
                }
                Err(error) => last = format!("{error:#}"),
            }
            thread::sleep(Duration::from_secs(1));
        }
        anyhow::bail!("cluster did not publish {expected_replicas} cold assignments: {last}")
    }

    fn send_chat(&self, prompt: &str, stream: bool) -> Result<ChatResponse> {
        send_chat(&self.client, &self.gateway().base_url(), prompt, stream)
    }

    fn assert_models_lists_logical_fixture_only(&self) -> Result<()> {
        let response = self.gateway().get("/v1/models", HOST)?;
        anyhow::ensure!(response.status == 200, "models status {}", response.status);
        let body = response.json()?;
        let data = body["data"].as_array().context("models data")?;
        anyhow::ensure!(data.len() == 1, "unexpected model list: {body}");
        anyhow::ensure!(data[0]["id"] == LOGICAL_MODEL, "logical model absent");
        anyhow::ensure!(
            matches!(
                data[0]["availability"]["state"].as_str(),
                Some("cold" | "ready")
            ),
            "managed availability absent: {body}"
        );
        let encoded = body.to_string();
        for private in ["worker-a", "worker-b", "model_endpoint", "127.0.0.1"] {
            anyhow::ensure!(
                !encoded.contains(private),
                "models leaked {private}: {body}"
            );
        }
        Ok(())
    }

    fn assert_concurrent_cold_start_launches_once(&mut self) -> Result<()> {
        let barrier = Arc::new(Barrier::new(3));
        let mut joins = Vec::new();
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let client = self.client.clone();
            let base_url = self.gateway().base_url();
            joins.push(thread::spawn(move || {
                barrier.wait();
                send_chat(&client, &base_url, "shared-cold-prefix", false)
            }));
        }
        barrier.wait();
        for join in joins {
            let response = join.join().expect("cold request thread")?;
            assert_successful_completion(&response)?;
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            self.refresh_engine_ports()?;
            if self.engine_ports.len() == 1 {
                break;
            }
            anyhow::ensure!(
                self.engine_ports.is_empty(),
                "concurrent cold requests launched distinct workers: {:?}",
                self.engine_ports
            );
            thread::sleep(Duration::from_secs(1));
        }
        anyhow::ensure!(
            self.engine_ports.len() == 1,
            "concurrent cold requests launched distinct workers: {:?}",
            self.engine_ports
        );
        let (&primary, &port) = self.engine_ports.iter().next().expect("one engine");
        self.primary_worker = Some(primary);
        let control = self.control_state(port)?;
        anyhow::ensure!(
            control["completion_requests"] == 2,
            "cold requests did not share one engine: {control}"
        );

        self.expand_to_two_replicas()?;
        let secondary = self
            .worker_ids()
            .into_iter()
            .find(|worker| *worker != primary)
            .expect("secondary worker");
        self.load_worker(secondary)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            self.refresh_engine_ports()?;
            if self.engine_ports.len() == 2 {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(1));
        }
        anyhow::bail!("secondary worker did not load: {:?}", self.engine_ports)
    }

    fn expand_to_two_replicas(&self) -> Result<()> {
        for ((node, process), config) in self
            .nodes
            .iter()
            .map(|node| {
                (
                    node,
                    self.processes
                        .get(node.node_id)
                        .expect("node process for config reload"),
                )
            })
            .zip(&self.expanded_configs)
        {
            process
                .rewrite_config(config)
                .with_context(|| format!("rewrite {} config", node.node_id))?;
            let response = self
                .client
                .post(format!("http://127.0.0.1:{}/admin/reload", node.admin_port))
                .basic_auth(ADMIN_USER, Some(ADMIN_PASSWORD))
                .send()
                .with_context(|| format!("reload {} config", node.node_id))?;
            let status = response.status();
            let body = response.text().context("read reload response")?;
            anyhow::ensure!(
                status.is_success(),
                "reload {} returned {status}: {body}",
                node.node_id
            );
        }
        self.wait_for_assignments(2, Duration::from_secs(40))
    }

    fn assert_remote_unary_completion(&self) -> Result<()> {
        self.set_all_modes("normal")?;
        let response = self.send_chat("remote-unary", false)?;
        assert_successful_completion(&response)?;
        assert_safe_route_headers(&response)?;
        let body: Value = serde_json::from_slice(&response.body).context("unary JSON")?;
        anyhow::ensure!(body["model"] == LOGICAL_MODEL, "logical model not echoed");
        anyhow::ensure!(
            body["choices"][0]["message"]["content"] == "fixture-ready",
            "unexpected completion: {body}"
        );
        Ok(())
    }

    fn assert_remote_sse_usage(&self) -> Result<()> {
        self.set_all_modes("normal")?;
        let response = self.send_chat("remote-sse", true)?;
        anyhow::ensure!(response.status == 200, "SSE status {}", response.status);
        assert_safe_route_headers(&response)?;
        let body = String::from_utf8(response.body).context("SSE UTF-8")?;
        anyhow::ensure!(
            body.contains("fixture-ready"),
            "missing SSE content: {body}"
        );
        anyhow::ensure!(body.contains("total_tokens"), "missing SSE usage: {body}");
        anyhow::ensure!(
            body.contains("data: [DONE]"),
            "missing SSE terminator: {body}"
        );
        Ok(())
    }

    fn assert_pre_output_worker_failure_fails_over(&mut self) -> Result<()> {
        let primary = self.primary_worker.context("primary worker")?;
        let secondary = self
            .worker_ids()
            .into_iter()
            .find(|worker| *worker != primary)
            .context("secondary worker")?;
        self.set_mode(primary, "pre_output_error")?;
        self.set_mode(secondary, "normal")?;

        for index in 0..64 {
            self.reset_controls()?;
            let prompt = format!("failover-prefix-{index}");
            let response = self.send_chat(&prompt, false)?;
            let primary_count = self.completion_count(primary)?;
            let secondary_count = self.completion_count(secondary)?;
            if primary_count == 1 && secondary_count == 1 {
                assert_successful_completion(&response)?;
                assert_safe_route_headers(&response)?;
                self.failover_prompt = Some(prompt);
                return Ok(());
            }
        }
        anyhow::bail!("could not select the failing worker first within bounded prompts")
    }

    fn assert_mid_stream_failure_does_not_replay(&self) -> Result<()> {
        let primary = self.primary_worker.context("primary worker")?;
        let secondary = self
            .worker_ids()
            .into_iter()
            .find(|worker| *worker != primary)
            .context("secondary worker")?;
        let prompt = self.failover_prompt.as_deref().context("failover prompt")?;
        self.reset_controls()?;
        self.set_mode(primary, "mid_stream_error")?;
        self.set_mode(secondary, "normal")?;

        let mut response = self
            .client
            .post(format!("{}/v1/chat/completions", self.gateway().base_url()))
            .header("host", HOST)
            .header("authorization", format!("Bearer {PUBLIC_KEY}"))
            .json(&serde_json::json!({
                "model": LOGICAL_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "stream": true
            }))
            .send()
            .context("mid-stream request")?;
        anyhow::ensure!(response.status().is_success(), "mid-stream status");
        let mut body = Vec::new();
        let _ = response.read_to_end(&mut body);
        anyhow::ensure!(
            String::from_utf8_lossy(&body).contains("partial"),
            "first stream frame was not relayed"
        );
        anyhow::ensure!(
            !String::from_utf8_lossy(&body).contains("data: [DONE]"),
            "truncated upstream stream emitted a successful terminator"
        );
        anyhow::ensure!(self.completion_count(primary)? == 1, "primary not invoked");
        anyhow::ensure!(
            self.completion_count(secondary)? == 0,
            "mid-stream failure replayed on secondary"
        );
        Ok(())
    }

    fn assert_client_cancel_reaches_engine_and_releases_permit(&self) -> Result<()> {
        let primary = self.primary_worker.context("primary worker")?;
        let secondary = self
            .worker_ids()
            .into_iter()
            .find(|worker| *worker != primary)
            .context("secondary worker")?;
        let prompt = self.failover_prompt.as_deref().context("failover prompt")?;
        self.reset_controls()?;
        self.set_mode(primary, "stream_until_cancelled")?;
        self.set_mode(secondary, "normal")?;

        let mut response = self
            .client
            .post(format!("{}/v1/chat/completions", self.gateway().base_url()))
            .header("host", HOST)
            .header("authorization", format!("Bearer {PUBLIC_KEY}"))
            .json(&serde_json::json!({
                "model": LOGICAL_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "stream": true
            }))
            .send()
            .context("cancellable stream request")?;
        anyhow::ensure!(response.status().is_success(), "cancel stream status");
        let mut first = [0u8; 128];
        let count = response.read(&mut first).context("first cancel frame")?;
        anyhow::ensure!(
            String::from_utf8_lossy(&first[..count]).starts_with("data: {"),
            "cancel stream had no first frame"
        );
        drop(response);

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let state = self.control_for_worker(primary)?;
            if state["cancelled_requests"].as_u64().unwrap_or(0) >= 1
                && state["active_requests"] == 0
            {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let state = self.control_for_worker(primary)?;
        anyhow::ensure!(
            state["cancelled_requests"].as_u64().unwrap_or(0) >= 1,
            "engine did not observe cancellation: {state}"
        );
        anyhow::ensure!(
            state["active_requests"] == 0,
            "engine request remained active"
        );
        anyhow::ensure!(
            self.completion_count(secondary)? == 0,
            "cancelled stream replayed on secondary"
        );

        self.set_mode(primary, "normal")?;
        let response = self.send_chat(prompt, false)?;
        assert_successful_completion(&response)
            .context("admission permit was not released after cancellation")
    }

    fn assert_raw_public_key_absent_from_worker_logs(&self) -> Result<()> {
        for worker in self.worker_ids() {
            let process = self.processes.get(worker).context("worker process")?;
            let logs = format!(
                "{}\n{}",
                process.stdout_contents(),
                process.stderr_contents()
            );
            anyhow::ensure!(
                !logs.contains(PUBLIC_KEY),
                "{worker} logs exposed the public bearer key"
            );
        }
        Ok(())
    }

    fn load_worker(&self, node_id: &str) -> Result<()> {
        let node = self.worker(node_id);
        let response = self
            .client
            .post(format!(
                "http://127.0.0.1:{}/admin/model-host/load",
                node.admin_port
            ))
            .basic_auth(ADMIN_USER, Some(ADMIN_PASSWORD))
            .json(&serde_json::json!({"deployment": DEPLOYMENT}))
            .send()
            .with_context(|| format!("load {node_id} deployment"))?;
        let status = response.status();
        let body = response.text().context("read load response")?;
        anyhow::ensure!(
            status.is_success(),
            "load {node_id} returned {status}: {body}"
        );
        Ok(())
    }

    fn refresh_engine_ports(&mut self) -> Result<()> {
        let mut ports = BTreeMap::new();
        for worker in self.worker_ids() {
            let status = self.read_model_status(worker)?;
            if let Some(port) = status["deployments"]
                .as_array()
                .and_then(|deployments| deployments.iter().find_map(|item| item["port"].as_u64()))
            {
                ports.insert(worker, u16::try_from(port).context("engine port overflow")?);
            }
        }
        self.engine_ports = ports;
        Ok(())
    }

    fn set_all_modes(&self, mode: &str) -> Result<()> {
        for worker in self.worker_ids() {
            self.set_mode(worker, mode)?;
        }
        Ok(())
    }

    fn set_mode(&self, worker: &str, mode: &str) -> Result<()> {
        let port = *self
            .engine_ports
            .get(worker)
            .with_context(|| format!("missing {worker} engine port"))?;
        let response = self
            .client
            .post(format!("http://127.0.0.1:{port}/__control/mode/{mode}"))
            .send()
            .with_context(|| format!("set {worker} mode {mode}"))?;
        anyhow::ensure!(response.status().is_success(), "set mode failed");
        Ok(())
    }

    fn reset_controls(&self) -> Result<()> {
        for (&worker, &port) in &self.engine_ports {
            let response = self
                .client
                .post(format!("http://127.0.0.1:{port}/__control/reset"))
                .send()
                .with_context(|| format!("reset {worker} engine"))?;
            anyhow::ensure!(response.status().is_success(), "reset {worker} failed");
        }
        Ok(())
    }

    fn control_state(&self, port: u16) -> Result<Value> {
        let response = self
            .client
            .get(format!("http://127.0.0.1:{port}/__control"))
            .send()
            .context("read engine control")?;
        let status = response.status();
        let body = response.text().context("read engine control body")?;
        anyhow::ensure!(status.is_success(), "engine control {status}: {body}");
        serde_json::from_str(&body).context("decode engine control")
    }

    fn control_for_worker(&self, worker: &str) -> Result<Value> {
        let port = *self
            .engine_ports
            .get(worker)
            .with_context(|| format!("missing {worker} engine port"))?;
        self.control_state(port)
    }

    fn completion_count(&self, worker: &str) -> Result<u64> {
        Ok(self.control_for_worker(worker)?["completion_requests"]
            .as_u64()
            .unwrap_or(0))
    }

    fn dump_logs(&self) {
        for (node_id, process) in &self.processes {
            eprintln!("\n--- {node_id} stdout ---\n{}", process.stdout_contents());
            eprintln!("\n--- {node_id} stderr ---\n{}", process.stderr_contents());
        }
    }
}

fn external_chat_reply() -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-external",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": LOGICAL_MODEL,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "external-ready"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

impl Drop for ThreeNodeCluster {
    fn drop(&mut self) {
        for process in self.processes.values_mut() {
            let _ = process.terminate_gracefully(Duration::from_secs(5));
        }
    }
}

fn send_chat(
    client: &reqwest::blocking::Client,
    base_url: &str,
    prompt: &str,
    stream: bool,
) -> Result<ChatResponse> {
    let response = client
        .post(format!("{base_url}/v1/chat/completions"))
        .header("host", HOST)
        .header("authorization", format!("Bearer {PUBLIC_KEY}"))
        .json(&serde_json::json!({
            "model": LOGICAL_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream": stream
        }))
        .send()
        .context("send gateway completion")?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect();
    let body = response
        .bytes()
        .context("read gateway completion")?
        .to_vec();
    Ok(ChatResponse {
        status,
        headers,
        body,
    })
}

fn assert_successful_completion(response: &ChatResponse) -> Result<()> {
    anyhow::ensure!(
        response.status == 200,
        "completion status {}: {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    let body: Value = serde_json::from_slice(&response.body).context("completion JSON")?;
    anyhow::ensure!(
        body["choices"][0]["message"]["content"] == "fixture-ready",
        "unexpected completion: {body}"
    );
    Ok(())
}

fn assert_safe_route_headers(response: &ChatResponse) -> Result<()> {
    anyhow::ensure!(
        response
            .headers
            .get("x-sbproxy-logical-model")
            .is_some_and(|value| value == LOGICAL_MODEL),
        "logical model header absent: {:?}",
        response.headers
    );
    anyhow::ensure!(
        response
            .headers
            .get("x-sbproxy-route-class")
            .is_some_and(|value| value == "peer"),
        "peer route header absent: {:?}",
        response.headers
    );
    anyhow::ensure!(
        !response.headers.contains_key("x-sbproxy-worker"),
        "worker identity header exposed"
    );
    let encoded = format!(
        "{} {:?}",
        String::from_utf8_lossy(&response.body),
        response.headers
    );
    for private in ["worker-a", "worker-b", "model_endpoint", ":9443"] {
        anyhow::ensure!(!encoded.contains(private), "response leaked {private}");
    }
    Ok(())
}

#[test]
fn remote_stream_failover_and_cancel_are_safe() -> Result<()> {
    let mut cluster = ThreeNodeCluster::start()?;
    let result = (|| {
        cluster.assert_models_lists_logical_fixture_only()?;
        cluster.assert_concurrent_cold_start_launches_once()?;
        cluster.assert_remote_unary_completion()?;
        cluster.assert_remote_sse_usage()?;
        cluster.assert_pre_output_worker_failure_fails_over()?;
        cluster.assert_mid_stream_failure_does_not_replay()?;
        cluster.assert_client_cancel_reaches_engine_and_releases_permit()?;
        cluster.assert_raw_public_key_absent_from_worker_logs()?;
        Ok(())
    })();
    if result.is_err() {
        cluster.dump_logs();
    }
    result
}

#[test]
fn managed_cold_fallback_advances_a_non_fallback_router() -> Result<()> {
    let upstream = MockUpstream::start(external_chat_reply()).context("fallback upstream")?;
    let cluster =
        ThreeNodeCluster::start_with_policy("fallback", "round_robin", Some(upstream), false)?;

    let response = cluster.send_chat("cold-fallback", false)?;
    anyhow::ensure!(
        response.status == 200,
        "fallback status {}",
        response.status
    );
    let body: Value = serde_json::from_slice(&response.body).context("fallback response JSON")?;
    anyhow::ensure!(
        body["choices"][0]["message"]["content"] == "external-ready",
        "managed cold fallback did not reach the external provider: {body}"
    );
    let upstream = cluster
        .fallback_upstream
        .as_ref()
        .context("fallback upstream retained")?;
    anyhow::ensure!(
        !upstream.captured().is_empty(),
        "external fallback provider was not called"
    );
    Ok(())
}

#[test]
fn multipart_managed_cold_fallback_advances_provider() -> Result<()> {
    let upstream = MockUpstream::start(external_chat_reply()).context("fallback upstream")?;
    let cluster =
        ThreeNodeCluster::start_with_policy("fallback", "fallback_chain", Some(upstream), false)?;

    let boundary = "sbproxy-cold-fallback";
    let multipart = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{LOGICAL_MODEL}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.wav\"\r\nContent-Type: audio/wav\r\n\r\nfixture\r\n--{boundary}--\r\n"
    );
    let response = cluster
        .client
        .post(format!(
            "{}/v1/chat/completions",
            cluster.gateway().base_url()
        ))
        .header("host", HOST)
        .header("authorization", format!("Bearer {PUBLIC_KEY}"))
        .header(
            reqwest::header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(multipart)
        .send()
        .context("multipart cold fallback")?;
    anyhow::ensure!(
        response.status().is_success(),
        "multipart fallback status {}",
        response.status()
    );
    let upstream = cluster
        .fallback_upstream
        .as_ref()
        .context("fallback upstream retained")?;
    anyhow::ensure!(
        !upstream.captured().is_empty(),
        "multipart managed fallback did not advance to the external provider"
    );
    Ok(())
}
