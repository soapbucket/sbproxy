//! End-to-end coverage for the admin endpoint surface.
//!
//! Builds a small config with `proxy.admin.enabled: true` on a
//! free port and exercises every admin route documented in
//! `sbproxy-core/src/admin.rs::handle_admin_request`.

use std::net::TcpListener;

use sbproxy_e2e::ProxyHarness;

fn config_yaml(admin_port: u16) -> String {
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
  "demo.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "demo"
"#
    )
}

fn pick_admin_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn admin_get(port: u16, path: &str, auth: Option<&str>) -> (u16, String) {
    let mut req = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{}{}", port, path));
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let resp = req.send().expect("admin GET");
    (resp.status().as_u16(), resp.text().unwrap_or_default())
}

#[test]
fn admin_endpoints_require_basic_auth() {
    let admin_port = pick_admin_port();
    let _proxy = ProxyHarness::start_with_yaml(&config_yaml(admin_port)).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, std::time::Duration::from_secs(5))
        .expect("admin port to bind");
    let (status, _) = admin_get(admin_port, "/api/health", None);
    assert_eq!(
        status, 401,
        "admin endpoint should reject unauthenticated requests"
    );
}

#[test]
fn admin_health_returns_ok_with_valid_auth() {
    let admin_port = pick_admin_port();
    let _proxy = ProxyHarness::start_with_yaml(&config_yaml(admin_port)).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, std::time::Duration::from_secs(5))
        .expect("admin port to bind");
    let auth = format!("Basic {}", base64_encode("admin:secret"));
    let (status, body) = admin_get(admin_port, "/api/health", Some(&auth));
    assert_eq!(status, 200);
    assert!(
        body.contains("status"),
        "expected status field in health body: {body}"
    );
}

#[test]
fn admin_openapi_endpoint_returns_emitted_spec() {
    let admin_port = pick_admin_port();
    let _proxy = ProxyHarness::start_with_yaml(&config_yaml(admin_port)).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, std::time::Duration::from_secs(5))
        .expect("admin port to bind");
    let auth = format!("Basic {}", base64_encode("admin:secret"));
    let (status, body) = admin_get(admin_port, "/api/openapi.json", Some(&auth));
    assert_eq!(status, 200);
    assert!(
        body.contains("\"openapi\""),
        "expected openapi.json body: {body}"
    );
}

/// Tiny base64 encoder so the test stays single-purpose without
/// pulling in another dep. Standard alphabet, no padding logic
/// needed for the short strings we encode.
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
