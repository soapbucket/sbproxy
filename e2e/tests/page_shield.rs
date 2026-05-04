//! Page Shield CSP injection + report intake (F2.10).

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn yaml_with_upstream(upstream_base: &str, mode: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "app.localhost":
    action:
      type: proxy
      url: "{base}"
    policies:
      - type: page_shield
        mode: {mode}
        directives:
          - "default-src 'self'"
          - "script-src 'self' https://cdn.example"
"#,
        base = upstream_base,
        mode = mode,
    )
}

#[test]
fn report_only_response_carries_csp_report_only_header() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&yaml_with_upstream(&upstream.base_url(), "report-only"))
            .expect("start proxy");
    let resp = harness.get("/page", "app.localhost").expect("send");
    assert_eq!(resp.status, 200);
    let csp = resp
        .headers
        .get("content-security-policy-report-only")
        .expect("CSP-report-only header");
    assert!(csp.starts_with("default-src 'self'"));
    assert!(csp.contains("script-src 'self' https://cdn.example"));
    assert!(csp.contains("report-uri /__sbproxy/csp-report"));
    // Enforce-mode header must NOT also be present in report-only mode.
    assert!(!resp.headers.contains_key("content-security-policy"));
}

#[test]
fn enforce_mode_emits_csp_header() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&yaml_with_upstream(&upstream.base_url(), "enforce"))
            .expect("start proxy");
    let resp = harness.get("/page", "app.localhost").expect("send");
    assert_eq!(resp.status, 200);
    assert!(resp.headers.contains_key("content-security-policy"));
    // Report-only header must NOT also be present.
    assert!(!resp
        .headers
        .contains_key("content-security-policy-report-only"));
}

#[test]
fn intake_endpoint_returns_204_for_post() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let harness =
        ProxyHarness::start_with_yaml(&yaml_with_upstream(&upstream.base_url(), "report-only"))
            .expect("start proxy");
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/__sbproxy/csp-report", harness.base_url()))
        .header("content-type", "application/csp-report")
        .body(
            r#"{"csp-report":{"document-uri":"http://app.localhost/","violated-directive":"script-src","blocked-uri":"https://evil.example/x.js"}}"#,
        )
        .send()
        .expect("send report");
    assert_eq!(resp.status().as_u16(), 204);
}

#[test]
fn intake_endpoint_only_matches_post() {
    // A GET on the intake path is not the report submission; the
    // intake handler ignores the request and the rest of the
    // pipeline runs normally. With this config the path proxies
    // upstream and returns 200.
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let harness =
        ProxyHarness::start_with_yaml(&yaml_with_upstream(&upstream.base_url(), "report-only"))
            .expect("start proxy");
    let resp = harness
        .get("/__sbproxy/csp-report", "app.localhost")
        .expect("send");
    assert_ne!(resp.status, 204);
}
