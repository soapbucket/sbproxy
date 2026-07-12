// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sbproxy_mesh::enrollment::{EnrollmentAuthority, EnrollmentRequest};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

fn temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sbproxy-cluster-cli-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create test directory");
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
    serde_json::from_slice(&output.stdout).expect("JSON stdout")
}

fn enrollment_fixture(
    authority: Arc<EnrollmentAuthority>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
    let address = listener.local_addr().expect("fixture address");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept enrollment");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("read timeout");
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        let mut expected_len = None;
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            assert!(read > 0, "client closed before request completed");
            request.extend_from_slice(&buffer[..read]);
            if expected_len.is_none() {
                if let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers.lines().find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    });
                    expected_len = content_length.map(|length| header_end + 4 + length);
                }
            }
            if expected_len.is_some_and(|length| request.len() >= length) {
                break;
            }
        }
        let header_end = request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .expect("headers");
        let headers = String::from_utf8_lossy(&request[..header_end]);
        assert!(
            headers.starts_with("POST /admin/cluster/enroll "),
            "{headers}"
        );
        let body = &request[header_end + 4..expected_len.expect("request length")];
        assert!(!body.windows(11).any(|bytes| bytes == b"PRIVATE KEY"));
        let request: EnrollmentRequest = serde_json::from_slice(body).expect("enrollment JSON");
        let response = authority.enroll(request).expect("authority enrollment");
        let body = serde_json::to_vec(&response).expect("response JSON");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .expect("response headers");
        stream.write_all(&body).expect("response body");
    });
    (format!("http://{address}"), handle)
}

fn status_fixture() -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("fixture listener");
    let address = listener.local_addr().expect("fixture address");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept status");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("read timeout");
        let mut request = [0u8; 8192];
        let read = stream.read(&mut request).expect("read status request");
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(
            request.starts_with("GET /admin/cluster/status "),
            "{request}"
        );
        assert!(
            request
                .lines()
                .any(|line| line.eq_ignore_ascii_case("authorization: Basic YWRtaW46c2VjcmV0")),
            "{request}"
        );
        let body = serde_json::json!({
            "schema_version": 1,
            "configured": true,
            "mode": "distributed",
            "cluster_id": "prod-a",
            "local_node_id": "gateway-a",
            "summary": {
                "total_nodes": 2,
                "healthy_nodes": 1,
                "degraded_nodes": 0,
                "unhealthy_nodes": 1,
                "eligible_workers": 1
            },
            "nodes": [{
                "node_id": "worker-b",
                "health": "unhealthy",
                "membership_state": "suspect",
                "model_eligible": false,
                "unhealthy_reasons": ["membership_suspect"]
            }],
            "unhealthy_nodes": [{
                "node_id": "worker-b",
                "reasons": ["membership_suspect"]
            }]
        })
        .to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .expect("status response");
    });
    (format!("http://{address}"), handle)
}

#[test]
fn cluster_init_token_and_http_development_enroll_work_end_to_end() {
    let root = temp_dir("enroll");
    let authority_dir = root.join("authority");
    let worker_dir = root.join("worker");
    let authority_path = authority_dir.to_string_lossy().into_owned();
    let worker_path = worker_dir.to_string_lossy().into_owned();

    let initialized = run(&[
        "cluster",
        "init",
        "--dir",
        &authority_path,
        "--cluster-id",
        "dev-a",
        "--node-id",
        "authority-a",
        "--label",
        "zone=a",
        "--format",
        "json",
    ]);
    let initialized = json_stdout(&initialized);
    assert_eq!(initialized["command"], "cluster.init");
    assert_eq!(initialized["cluster_id"], "dev-a");

    let token_output = run(&[
        "cluster",
        "token",
        "create",
        "--dir",
        &authority_path,
        "--label",
        "zone=b",
        "--ttl-secs",
        "300",
        "--format",
        "json",
    ]);
    let token_json = json_stdout(&token_output);
    let token = token_json["token"]
        .as_str()
        .expect("clear token")
        .to_string();
    assert!(token.starts_with("sbce1."));

    let authority = Arc::new(EnrollmentAuthority::open(&authority_dir).expect("open authority"));
    let (url, server) = enrollment_fixture(authority);
    let enrolled = run(&[
        "cluster",
        "enroll",
        "--url",
        &url,
        "--token",
        &token,
        "--node-id",
        "worker-b",
        "--label",
        "zone=b",
        "--out",
        &worker_path,
        "--allow-insecure-http",
        "--format",
        "json",
    ]);
    server.join().expect("enrollment fixture");
    let enrolled_json = json_stdout(&enrolled);
    assert_eq!(enrolled_json["command"], "cluster.enroll");
    assert_eq!(enrolled_json["node_id"], "worker-b");
    assert!(worker_dir.join("node.pem").is_file());
    assert!(worker_dir.join("node-key.pem").is_file());
    assert!(worker_dir.join("identity.json").is_file());
    assert!(!String::from_utf8_lossy(&enrolled.stderr).contains(&token));
}

#[test]
fn cluster_enroll_rejects_plaintext_without_explicit_development_flag() {
    let root = temp_dir("http-reject");
    let output = run(&[
        "cluster",
        "enroll",
        "--url",
        "http://127.0.0.1:1",
        "--token",
        "not-a-real-token",
        "--node-id",
        "worker-a",
        "--out",
        &root.join("worker").to_string_lossy(),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--allow-insecure-http"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("not-a-real-token"));
}

#[test]
fn cluster_status_prints_the_authenticated_admin_contract() {
    let (url, server) = status_fixture();
    let output = run(&[
        "cluster",
        "status",
        "--admin-url",
        &url,
        "--username",
        "admin",
        "--password",
        "secret",
        "--format",
        "json",
    ]);
    server.join().expect("status fixture");
    let status = json_stdout(&output);
    assert_eq!(status["cluster_id"], "prod-a");
    assert_eq!(status["summary"]["unhealthy_nodes"], 1);
    assert_eq!(status["unhealthy_nodes"][0]["node_id"], "worker-b");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret"));
}
