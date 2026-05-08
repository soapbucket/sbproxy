//! End-to-end coverage for the WOR-27 synthetic-transaction probe.
//!
//! Boots the proxy with `proxy.synthetic_probe.enabled: true` plus a
//! `__synthetic.local` origin that serves a static 200, then waits
//! for the driver loop to record an outcome and hits `/readyz` to
//! verify the synthetic_pipeline component shows up healthy.

use std::net::TcpListener;

use sbproxy_e2e::ProxyHarness;

fn config_with_synthetic(admin_port: u16) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
  synthetic_probe:
    enabled: true
    hostname: __synthetic.local
    path: /readyz/synthetic
    interval_secs: 1
    timeout_ms: 500
    stale_after_secs: 30
origins:
  "demo.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "demo"
  "__synthetic.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "synthetic ok"
"#
    )
}

fn config_without_synthetic(admin_port: u16) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
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

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn http_get(port: u16, path: &str) -> (u16, String) {
    let resp = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{}{}", port, path))
        .send()
        .expect("admin GET");
    (resp.status().as_u16(), resp.text().unwrap_or_default())
}

#[test]
fn readyz_omits_synthetic_pipeline_when_disabled() {
    let admin_port = pick_port();
    let _proxy =
        ProxyHarness::start_with_yaml(&config_without_synthetic(admin_port)).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, std::time::Duration::from_secs(5))
        .expect("admin port to bind");
    let (status, body) = http_get(admin_port, "/readyz");
    assert_eq!(status, 200, "readyz should be 200 by default: {body}");
    assert!(
        !body.contains("synthetic_pipeline"),
        "synthetic_pipeline must not appear when disabled: {body}"
    );
}

#[test]
fn readyz_includes_healthy_synthetic_pipeline_when_enabled() {
    let admin_port = pick_port();
    let _proxy =
        ProxyHarness::start_with_yaml(&config_with_synthetic(admin_port)).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, std::time::Duration::from_secs(5))
        .expect("admin port to bind");

    // The driver runs every second, so wait up to ~6s for the first
    // outcome to land. The probe initially reports unhealthy
    // (no_outcome_yet) until the first synthetic round trip succeeds.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut last_body = String::new();
    while std::time::Instant::now() < deadline {
        let (status, body) = http_get(admin_port, "/readyz");
        last_body = body.clone();
        if status == 200 && body.contains("\"name\":\"synthetic_pipeline\"") {
            assert!(
                body.contains("\"status\":\"healthy\""),
                "synthetic_pipeline component must report healthy: {body}"
            );
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    panic!(
        "synthetic_pipeline never reported healthy on /readyz within deadline. \
         last body: {last_body}"
    );
}
