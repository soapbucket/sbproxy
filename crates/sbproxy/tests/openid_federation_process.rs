// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Process-level OpenID Federation reachability.
//!
//! The library crate's router tests cannot prove the released `sbproxy`
//! binary mounts that router or reads its configuration. This test boots
//! the real binary from `sb.yml` and reaches the well-known endpoint over
//! the public listener.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Decode one base64url segment of a compact JWS.
fn base64_url_decode(segment: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("compact JWS segment is base64url")
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

fn temp_dir() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sbproxy-openid-federation-process-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create test directory");
    path
}

fn get(port: u16, path: &str) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: federation.test\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    Some(response)
}

fn start_proxy(root: &Path, config: &Path, port: u16) -> Child {
    let mut child = Command::new(binary())
        .arg("serve")
        .arg(config)
        .env_remove("SB_CONFIG_FILE")
        .env("SBPROXY_ENGINE_OWNERSHIP_DIR", root.join("ownership"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start sbproxy");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait().expect("poll sbproxy").is_some() {
            let output = child.wait_with_output().expect("collect sbproxy output");
            panic!(
                "sbproxy exited before serving OpenID Federation: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if get(port, "/.well-known/openid-federation").is_some() {
            return child;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect timed-out sbproxy");
            panic!(
                "sbproxy did not serve OpenID Federation: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn security_boundary_single_process_serves_its_configured_entity_statement() {
    let root = temp_dir();
    let key_path = root.join("federation-signing-key.pem");
    std::fs::write(
        &key_path,
        include_str!("../../sbproxy-modules/src/auth/dpop_test_ec_p256.pem"),
    )
    .expect("write signing-key fixture");
    let reserved = TcpListener::bind("127.0.0.1:0").expect("reserve ephemeral port");
    let port = reserved.local_addr().expect("reserved address").port();
    drop(reserved);
    let config = root.join("sb.yml");
    std::fs::write(
        &config,
        format!(
            r#"proxy:
  http_bind_port: {port}
  bind_address: 127.0.0.1
  federation:
    enabled: true
    entity_id: https://federation.test
    signing_key:
      pem_file: "{}"
      algorithm: ES256
      kid: process-test-key
    published_jwks:
      keys:
        - kty: EC
          crv: P-256
          x: DpZdjog3y9hgIyKgEPltBi5ptXKUeuRwVOAPSmoQAu4
          y: bfVVYV9slbMcg4dvtvYbeekYtpFXsYCWcIa9RCrBmTc
          kid: process-test-key
          alg: ES256
          use: sig
    lifetime_secs: 3600
    refresh_margin_secs: 300
    authority_hints:
      - https://anchor.test
origins:
  "federation.test":
    action:
      type: static
      status_code: 418
      content_type: text/plain
      body: origin-fallback-must-not-answer
"#,
            key_path.display()
        ),
    )
    .expect("write process config");

    let mut child = start_proxy(&root, &config, port);
    let response = get(port, "/.well-known/openid-federation").expect("well-known response");
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("content-type: application/entity-statement+jwt"),
        "{response}"
    );
    let lowered = response.to_ascii_lowercase();
    // The proxy serves this through the crate's own handler body, so
    // the cache directive and the two well-known metric writers come
    // from one place. A hand-rolled response left peers and CDNs with
    // no directive at all and every `sbproxy_federation_*` family flat.
    assert!(
        lowered.contains("cache-control: public, max-age="),
        "the served configuration must carry its remaining lifetime: {response}"
    );
    assert!(lowered.contains("vary: accept"), "{response}");
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert_eq!(body.split('.').count(), 3, "body must be a compact JWS");

    // `authority_hints` is what a peer's resolver walks. Without it the
    // statement is anchor-shaped and no peer can chain this entity.
    let claims = body.split('.').nth(1).expect("compact JWS has a payload");
    let claims = base64_url_decode(claims);
    let claims: serde_json::Value = serde_json::from_slice(&claims).expect("payload is JSON");
    assert_eq!(
        claims["authority_hints"],
        serde_json::json!(["https://anchor.test"]),
        "{claims}"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(root);
}
