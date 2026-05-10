//! WOR-201 PR 1b: end-to-end coverage for policy verdict
//! observability.
//!
//! Drives the proxy with two fixtures: an Allow path that returns
//! 200 cleanly, and a Deny path triggered by the existing
//! `ip_filter` built-in. The audit emission (PolicyVerdictEvent +
//! sbproxy_policy_audit_events_total) fires on both paths through
//! the new wiring in `server.rs`; the metric and event payloads
//! are exercised by the unit + integration tests in
//! `crates/sbproxy-core/`.
//!
//! The third spec fixture (Plugin policy returning Confirm and
//! reaching the response as `X-Policy-Confirm`) requires a
//! `Policy::Plugin` constructor in the YAML compiler. PR 1c
//! ports the 21 built-in policies to the trait surface and then
//! the Plugin variant becomes constructible from config; for
//! PR 1b the Confirm bridge is covered by the unit tests in
//! `crates/sbproxy-core/tests/confirm_oss_bridge.rs`.

use sbproxy_e2e::ProxyHarness;

const ALLOW_CONFIG: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "verdict-allow.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: rate_limiting
        requests_per_second: 1000
        burst: 1000
"#;

const DENY_CONFIG: &str = r#"
proxy:
  http_bind_port: 0
  trusted_proxies:
    - 127.0.0.1/32
origins:
  "verdict-deny.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: ip_filter
        blacklist:
          - 203.0.113.0/24
"#;

#[test]
fn allow_path_returns_upstream_response() {
    let harness = ProxyHarness::start_with_yaml(ALLOW_CONFIG).expect("start proxy");
    let resp = harness.get("/", "verdict-allow.localhost").expect("send");
    assert_eq!(
        resp.status, 200,
        "request that passes every policy must reach the upstream and yield 200; got {}",
        resp.status,
    );
}

#[test]
fn deny_path_returns_policy_status_unchanged() {
    let harness = ProxyHarness::start_with_yaml(DENY_CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "verdict-deny.localhost",
            &[("x-forwarded-for", "203.0.113.42")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 403,
        "blacklisted IP must produce 403; got {}",
        resp.status,
    );
}
