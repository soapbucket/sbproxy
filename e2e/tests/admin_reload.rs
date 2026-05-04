//! End-to-end coverage for `POST /admin/reload`.
//!
//! Boots the proxy with one config, mutates the file on disk, hits
//! the admin reload endpoint, and verifies the live pipeline now
//! serves the new config. The test exercises Prereq.B: the K8s
//! operator's hot-reload path collapses to this same endpoint.

use std::net::TcpListener;
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

fn pick_admin_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn config_v1(admin_port: u16) -> String {
    // Two routes:
    //   - "old.localhost"  -> static "v1-old"
    //   - "shared.localhost" -> static "v1-shared"
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
origins:
  "old.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "v1-old"
  "shared.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "v1-shared"
"#
    )
}

fn config_v2(admin_port: u16) -> String {
    // After reload:
    //   - "old.localhost" is removed (should now miss).
    //   - "new.localhost" appears with body "v2-new".
    //   - "shared.localhost" still serves but with body "v2-shared".
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
origins:
  "new.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "v2-new"
  "shared.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "v2-shared"
"#
    )
}

fn admin_post(port: u16, path: &str, auth: &str) -> (u16, String) {
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
        .post(format!("http://127.0.0.1:{}{}", port, path))
        .header("authorization", auth)
        .send()
        .expect("admin POST");
    let status = resp.status().as_u16();
    let body = resp.text().unwrap_or_default();
    (status, body)
}

#[test]
fn admin_reload_swaps_pipeline_in_place() {
    // --- Arrange: boot the proxy with v1 config ---
    let admin_port = pick_admin_port();
    let proxy = ProxyHarness::start_with_yaml(&config_v1(admin_port)).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port to bind");

    // Sanity-check v1: known route serves expected body.
    let resp = proxy
        .get("/", "shared.localhost")
        .expect("GET shared.localhost (v1)");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text().unwrap(), "v1-shared");

    let resp = proxy
        .get("/", "old.localhost")
        .expect("GET old.localhost (v1)");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text().unwrap(), "v1-old");

    // --- Act: rewrite the config on disk + POST /admin/reload ---
    proxy
        .rewrite_config(&config_v2(admin_port))
        .expect("rewrite config");

    let auth = format!("Basic {}", base64_encode("admin:secret"));
    let (status, body) = admin_post(admin_port, "/admin/reload", &auth);
    assert_eq!(status, 200, "reload body: {body}");

    let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    let revision = parsed
        .get("config_revision")
        .and_then(|v| v.as_str())
        .expect("config_revision present");
    assert!(!revision.is_empty(), "config_revision empty: {body}");
    assert!(
        parsed.get("loaded_at").and_then(|v| v.as_str()).is_some(),
        "loaded_at present: {body}"
    );

    // --- Assert: new route serves, old route is gone ---
    let resp = proxy
        .get("/", "new.localhost")
        .expect("GET new.localhost (v2)");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text().unwrap(), "v2-new");

    let resp = proxy
        .get("/", "shared.localhost")
        .expect("GET shared.localhost (v2)");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text().unwrap(), "v2-shared");

    // The removed origin: the proxy returns the "no origin matches"
    // response (404 in OSS). We just assert it is no longer the v1
    // body.
    let resp = proxy
        .get("/", "old.localhost")
        .expect("GET old.localhost (post-reload)");
    assert_ne!(
        resp.text().unwrap_or_default(),
        "v1-old",
        "old route should be gone after reload, but still serves v1-old"
    );
    assert!(
        resp.status >= 400,
        "expected 4xx for removed origin, got {}",
        resp.status
    );
}

#[test]
fn admin_reload_requires_auth() {
    let admin_port = pick_admin_port();
    let _proxy = ProxyHarness::start_with_yaml(&config_v1(admin_port)).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port to bind");

    // No auth header at all.
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .post(format!("http://127.0.0.1:{}/admin/reload", admin_port))
        .send()
        .expect("POST");
    assert_eq!(resp.status().as_u16(), 401);

    // Wrong password.
    let bad = format!("Basic {}", base64_encode("admin:wrong"));
    let (status, _) = admin_post(admin_port, "/admin/reload", &bad);
    assert_eq!(status, 401);
}

/// Tiny base64 encoder so the test stays single-purpose without
/// pulling in another dep. Standard alphabet, padded.
fn base64_encode(input: &str) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() {
            bytes[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            bytes[i + 2] as u32
        } else {
            0
        };
        out.push(ALPH[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(ALPH[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(ALPH[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(ALPH[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}
