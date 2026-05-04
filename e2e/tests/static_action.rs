//! End-to-end test for the `static` action.
//!
//! `static` is the simplest action: returns a fixed status, body,
//! and content-type. Worth covering as a smoke test for the
//! ProxyHarness itself - if this fails everything else is suspect.

use sbproxy_e2e::ProxyHarness;

#[test]
fn static_action_returns_configured_body() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "demo.localhost":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        ok: true
        message: hello
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    let resp = proxy.get("/", "demo.localhost").expect("GET /");
    assert_eq!(resp.status, 200);
    let json = resp.json().expect("decode body as JSON");
    assert_eq!(json["ok"], true);
    assert_eq!(json["message"], "hello");
    assert_eq!(
        resp.headers.get("content-type").map(|s| s.as_str()),
        Some("application/json")
    );
}

#[test]
fn unknown_host_returns_404() {
    // No origins defined for "unknown.localhost"; the host-router
    // should reject before reaching any action.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "demo.localhost":
    action: { type: static, status_code: 200, content_type: text/plain, body: "demo" }
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "unknown.localhost").expect("GET unknown");
    assert_eq!(resp.status, 404);
}
