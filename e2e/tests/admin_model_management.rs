// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Real-process proof for local admin-managed model desired state.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "model-management-test-secret";

fn reserve_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve admin port")
        .local_addr()
        .expect("reserved admin address")
        .port()
}

fn write_model_fixture(root: &Path) -> Result<PathBuf> {
    let source = root.join("fixture-model");
    fs::create_dir_all(&source).context("create model source")?;
    let weights = b"GGUF deterministic admin model management fixture";
    fs::write(source.join("weights.gguf"), weights).context("write fixture weights")?;
    let weights_digest = hex::encode(Sha256::digest(weights));
    let catalog = format!(
        r#"schema_version: 2
catalog_revision: admin-model-management-e2e-v1
models:
  fixture-model:
    params: 0.001B
    license: apache-2.0
    family: fixture
    context_length: 128
    variants:
      - id: q4
        format: gguf
        quant: Q4
        engines: [llama_cpp]
        source: "file:{source}"
        revision: 1111111111111111111111111111111111111111
        files:
          - path: weights.gguf
            sha256: {weights_digest}
            size_bytes: {weights_size}
        requirements:
          accelerators: [cpu, metal, cuda]
          min_memory_bytes: 1
        stability: preview
        certification: local-admin-management-fixture
"#,
        source = source.display(),
        weights_size = weights.len(),
    );
    let catalog_path = root.join("models.yaml");
    fs::write(&catalog_path, catalog).context("write model catalog")?;
    Ok(catalog_path)
}

fn config(
    admin_port: u16,
    catalog_path: &Path,
    store_path: &Path,
    cache_path: &Path,
    fake_engine_path: &Path,
) -> String {
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
  model_host:
    authority: admin_managed
    store_path: "{store_path}"
    catalog_file: "{catalog_path}"
    cache:
      directory: "{cache_path}"
    engines:
      llama_cpp:
        launch: binary
        path: "{fake_engine_path}"
origins:
  "admin-model-management.test":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: ok
"#,
        store_path = store_path.display(),
        catalog_path = catalog_path.display(),
        cache_path = cache_path.display(),
        fake_engine_path = fake_engine_path.display(),
    )
}

fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build admin client")
}

fn get_deployments(client: &Client, admin_port: u16) -> Result<(u16, Value)> {
    let response = client
        .get(format!(
            "http://127.0.0.1:{admin_port}/admin/model-host/deployments"
        ))
        .basic_auth(ADMIN_USER, Some(ADMIN_PASSWORD))
        .send()
        .context("get model deployments")?;
    let status = response.status().as_u16();
    let body = response.text().context("read deployment response")?;
    let value = serde_json::from_str(&body)
        .with_context(|| format!("decode deployment response {status}: {body}"))?;
    Ok((status, value))
}

fn put_deployments(
    client: &Client,
    admin_port: u16,
    expected_revision: Value,
) -> Result<(u16, Value)> {
    let response = client
        .put(format!(
            "http://127.0.0.1:{admin_port}/admin/model-host/deployments"
        ))
        .basic_auth(ADMIN_USER, Some(ADMIN_PASSWORD))
        .json(&json!({
            "expected_revision": expected_revision,
            "deployments": {
                "local-fixture": {
                    "model": "fixture-model",
                    "variant": "q4",
                    "replicas": 1,
                    "pull": "on_demand",
                    "warm": false,
                    "engine": "llama_cpp",
                    "rollout": "rolling"
                }
            }
        }))
        .send()
        .context("put model deployments")?;
    let status = response.status().as_u16();
    let body = response.text().context("read mutation response")?;
    let value = serde_json::from_str(&body)
        .with_context(|| format!("decode mutation response {status}: {body}"))?;
    Ok((status, value))
}

#[test]
fn admin_revision_survives_conflict_and_process_restart() -> Result<()> {
    let root = tempfile::tempdir().context("create admin model management fixture")?;
    let catalog_path = write_model_fixture(root.path())?;
    let store_path = root.path().join("deployments.json");
    let cache_path = root.path().join("cache");
    let fake_engine_path = Path::new(env!("CARGO_BIN_EXE_fake_model_engine"));
    let admin_port = reserve_port();
    let proxy = ProxyHarness::start_with_yaml(&config(
        admin_port,
        &catalog_path,
        &store_path,
        &cache_path,
        fake_engine_path,
    ))
    .context("start first proxy")?;
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(10))
        .context("wait for first admin server")?;
    let client = client()?;

    let (status, created) = put_deployments(&client, admin_port, Value::Null)?;
    assert_eq!(status, 200, "create deployment: {created}");
    assert_eq!(created["revision"], 1);
    assert_eq!(created["plan"]["added"], json!(["local-fixture"]));
    let digest = created["content_digest"]
        .as_str()
        .context("create response content digest")?
        .to_string();

    let (status, current) = get_deployments(&client, admin_port)?;
    assert_eq!(status, 200, "read deployment: {current}");
    assert_eq!(current["authority"], "admin_managed");
    assert_eq!(current["read_only"], false);
    assert_eq!(current["revision"], 1);
    assert_eq!(current["content_digest"], digest);
    assert_eq!(
        current["deployments"]["local-fixture"]["model"],
        "fixture-model"
    );

    let (status, conflict) = put_deployments(&client, admin_port, Value::Null)?;
    assert_eq!(status, 409, "stale mutation: {conflict}");
    assert_eq!(conflict["code"], "revision_conflict");
    assert_eq!(conflict["actual_revision"], 1);

    drop(proxy);

    let restarted_admin_port = reserve_port();
    let _restarted = ProxyHarness::start_with_yaml(&config(
        restarted_admin_port,
        &catalog_path,
        &store_path,
        &cache_path,
        fake_engine_path,
    ))
    .context("restart proxy against durable model store")?;
    ProxyHarness::wait_for_port(restarted_admin_port, Duration::from_secs(10))
        .context("wait for restarted admin server")?;
    let (status, restarted) = get_deployments(&client, restarted_admin_port)?;
    assert_eq!(status, 200, "read restarted deployment: {restarted}");
    assert_eq!(restarted["revision"], 1);
    assert_eq!(restarted["content_digest"], digest);
    assert_eq!(restarted["deployments"]["local-fixture"]["variant"], "q4");

    Ok(())
}
