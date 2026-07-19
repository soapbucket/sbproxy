// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ADMIN_FIXTURE_TIMEOUT: Duration = Duration::from_secs(30);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

fn temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sbproxy-models-cli-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .output()
        .expect("run sbproxy")
}

fn json_stdout(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(!output.stdout.contains(&b'\r'));
    assert!(!output.stdout.contains(&0x1b));
    serde_json::from_slice(&output.stdout).expect("JSON stdout")
}

#[test]
fn models_list_and_show_use_versioned_json_envelopes() {
    let list = json_stdout(&run(&["models", "list", "--format", "json"]));
    assert_eq!(list["schema_version"], 1);
    assert_eq!(list["command"], "models.list");
    assert!(list["models"]
        .as_array()
        .is_some_and(|models| !models.is_empty()));

    let show = json_stdout(&run(&[
        "models",
        "show",
        "qwen2.5-0.5b-instruct",
        "--format",
        "json",
    ]));
    assert_eq!(show["schema_version"], 1);
    assert_eq!(show["command"], "models.show");
    assert_eq!(show["id"], "qwen2.5-0.5b-instruct");
}

fn fixture_admin(
    expected_prefix: &'static str,
    body: &'static str,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + ADMIN_FIXTURE_TIMEOUT;
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for admin request"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept admin request: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(ADMIN_FIXTURE_TIMEOUT))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with(expected_prefix), "{request}");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: basic ywrtaw46c2vjcmv0"),
            "{request}",
        );
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body,
        )
        .expect("write response");
    });
    (format!("http://{address}"), handle)
}

#[test]
fn models_ps_and_stop_use_authenticated_admin_and_stable_json() {
    let (url, server) = fixture_admin(
        "GET /admin/model-host/status ",
        r#"{"serving":true,"runtime_revision":7,"deployments":[{"deployment":"coder","state":"ready","port":41000}],"models":[]}"#,
    );
    let ps = run(&[
        "models",
        "ps",
        "--admin-url",
        &url,
        "--username",
        "admin",
        "--password",
        "secret",
        "--format",
        "json",
    ]);
    server.join().unwrap();
    let ps_json = json_stdout(&ps);
    assert_eq!(ps_json["schema_version"], 1);
    assert_eq!(ps_json["command"], "models.ps");
    assert_eq!(ps_json["deployments"][0]["deployment"], "coder");
    assert!(!String::from_utf8_lossy(&ps.stderr).contains("secret"));

    let (url, server) = fixture_admin(
        "POST /admin/model-host/stop ",
        r#"{"deployment":"coder","state":"stopped","job_id":"01FIXTURE"}"#,
    );
    let stop = run(&[
        "models",
        "stop",
        "coder",
        "--admin-url",
        &url,
        "--username",
        "admin",
        "--password",
        "secret",
        "--format",
        "json",
    ]);
    server.join().unwrap();
    let stop_json = json_stdout(&stop);
    assert_eq!(stop_json["schema_version"], 1);
    assert_eq!(stop_json["command"], "models.stop");
    assert_eq!(stop_json["job_id"], "01FIXTURE");
    assert!(!String::from_utf8_lossy(&stop.stderr).contains("secret"));
}

fn write_artifact_fixture(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let source = root.join("model.gguf");
    let catalog = root.join("models.yaml");
    let cache = root.join("cache");
    std::fs::write(&source, "demo weights\n").unwrap();
    std::fs::write(
        &catalog,
        format!(
            "schema_version: 2\ncatalog_revision: cli-remove-fixture\nmodels:\n  offline:\n    params: 0.000000013B\n    license: apache-2.0\n    family: fixture\n    context_length: 1024\n    pull: manual\n    variants:\n      - id: demo\n        format: gguf\n        quant: Q4_K_M\n        engines: [llama_cpp]\n        source: file:{}\n        revision: local-v1\n        files:\n          - path: model.gguf\n            sha256: 729590a45b549db7a1631f3d220b794a8cd7c9042a43064dd0dcc80c7cb98b5e\n            size_bytes: 13\n        requirements:\n          accelerators: [cpu, metal, cuda]\n          min_memory_bytes: 1\n        stability: preview\n        certification: cli-offline-fixture\n",
            source.display(),
        ),
    )
    .unwrap();
    (source, catalog, cache)
}

#[test]
fn models_remove_rejects_configured_then_removes_exact_cached_artifact() {
    let root = temp_dir("remove");
    let (_source, catalog, cache) = write_artifact_fixture(&root);
    let catalog_text = catalog.to_string_lossy();
    let cache_text = cache.to_string_lossy();
    let pull = run(&[
        "models",
        "pull",
        "offline",
        "--variant",
        "demo",
        "--catalog-file",
        &catalog_text,
        "--cache-dir",
        &cache_text,
        "--offline",
        "--format",
        "json",
    ]);
    let pull_json = json_stdout(&pull);
    assert_eq!(pull_json["schema_version"], 1);
    assert_eq!(pull_json["command"], "models.pull");

    let config = root.join("sb.yml");
    std::fs::write(
        &config,
        format!(
            "proxy:\n  model_host:\n    cache:\n      directory: {}\n    deployments:\n      offline:\n        model: offline\n        variant: demo\norigins:\n  ai.local:\n    action:\n      type: ai_proxy\n      providers:\n        - name: local\n          provider_type: managed_model\n          deployment: offline\n          models: [offline]\n",
            cache.display(),
        ),
    )
    .unwrap();
    let config_text = config.to_string_lossy();
    let blocked = run(&[
        "models",
        "remove",
        "offline",
        "-f",
        &config_text,
        "--catalog-file",
        &catalog_text,
        "--cache-dir",
        &cache_text,
        "--format",
        "json",
    ]);
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("configured"),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr),
    );

    let removed = run(&[
        "models",
        "remove",
        "offline",
        "--variant",
        "demo",
        "--catalog-file",
        &catalog_text,
        "--cache-dir",
        &cache_text,
        "--format",
        "json",
    ]);
    let removed_json = json_stdout(&removed);
    assert_eq!(removed_json["schema_version"], 1);
    assert_eq!(removed_json["command"], "models.remove");
    assert_eq!(removed_json["removed"], true);
    assert!(removed_json["job_id"].as_str().is_some());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn run_dry_run_uses_canonical_warm_runtime_and_generated_admin_auth() {
    let root = temp_dir("run");
    let cache = root.join("cache");
    let output = run(&[
        "run",
        "qwen2.5-0.5b-instruct",
        "--variant",
        "q4_k_m",
        "--port",
        "48123",
        "--admin-port",
        "48124",
        "--cache-dir",
        cache.to_str().unwrap(),
        "--dry-run",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("model_host:"), "{stdout}");
    assert!(stdout.contains("provider_type: managed_model"), "{stdout}");
    assert!(stdout.contains("warm: true"), "{stdout}");
    assert!(stdout.contains("enabled: true"), "{stdout}");
    assert!(!stdout.contains("changeme"), "{stdout}");
    assert!(!stdout.contains("serve:"), "{stdout}");
    std::fs::remove_dir_all(root).unwrap();
}
