//! End-to-end coverage for path-, header-, and query-based `forward_rules`.
//!
//! `examples/62-forward-rules/sb.yml` documents the contract: a
//! parent origin defines an ordered list of `forward_rules`, each
//! with one or more matcher entries (path / header / query) and an
//! inline child `origin` that takes over when an entry hits. Anything
//! that does not match falls through to the parent origin's own action.
//! Within a single entry the present matchers are ANDed; across
//! entries in the same rule they are ORed.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

#[test]
fn path_prefix_routes_to_inline_child_origin() {
    let api = MockUpstream::start(json!({"target": "api"})).expect("api upstream");
    let stat = MockUpstream::start(json!({"target": "static"})).expect("static upstream");

    // Parent origin uses a static action so unmatched paths return a
    // deterministic body without a third upstream. Sole purpose of
    // this test is to confirm that /api/* and /static/* dispatch to
    // their inline child origins.
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "gw.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "default-action"

    forward_rules:
      - rules:
          - path:
              prefix: /api/
        origin:
          id: api-backend
          action:
            type: proxy
            url: "{}"

      - rules:
          - path:
              prefix: /static/
        origin:
          id: static-backend
          action:
            type: proxy
            url: "{}"
"#,
        api.base_url(),
        stat.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let api_resp = proxy.get("/api/users", "gw.localhost").expect("api req");
    assert_eq!(api_resp.status, 200);
    let stat_resp = proxy
        .get("/static/logo.png", "gw.localhost")
        .expect("static req");
    assert_eq!(stat_resp.status, 200);
    let default_resp = proxy.get("/page", "gw.localhost").expect("default req");
    assert_eq!(default_resp.status, 200);
    assert_eq!(default_resp.text().unwrap(), "default-action");

    assert_eq!(api.captured().len(), 1, "/api/* must hit api upstream");
    assert_eq!(
        stat.captured().len(),
        1,
        "/static/* must hit static upstream"
    );
}

#[test]
fn forward_rule_inline_static_origin_serves_without_upstream() {
    // Inline child origin uses a static action; no upstream needed.
    // Mirrors the /admin/* branch in examples/62-forward-rules.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "gw.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "default"

    forward_rules:
      - rules:
          - path:
              prefix: /admin/
        origin:
          id: admin-stub
          action:
            type: static
            status_code: 200
            content_type: application/json
            json_body:
              section: admin
              authenticated: false
"#;

    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    let admin_resp = proxy
        .get("/admin/dashboard", "gw.localhost")
        .expect("admin GET");
    assert_eq!(admin_resp.status, 200);
    let body = admin_resp.json().expect("admin body json");
    assert_eq!(body["section"], "admin");
    assert_eq!(body["authenticated"], false);

    let other_resp = proxy.get("/", "gw.localhost").expect("default GET");
    assert_eq!(other_resp.status, 200);
    assert_eq!(other_resp.text().unwrap(), "default");
}

#[test]
fn forward_rule_evaluates_in_declaration_order() {
    // Two rules with overlapping prefixes; the first wins.
    let first = MockUpstream::start(json!({"target": "first"})).expect("first upstream");
    let second = MockUpstream::start(json!({"target": "second"})).expect("second upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ord.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "fallback"

    forward_rules:
      - rules:
          - path:
              prefix: /api/
        origin:
          id: first
          action:
            type: proxy
            url: "{}"

      - rules:
          - path:
              prefix: /api/
        origin:
          id: second
          action:
            type: proxy
            url: "{}"
"#,
        first.base_url(),
        second.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    for _ in 0..3 {
        let _ = proxy.get("/api/x", "ord.localhost").expect("send");
    }

    assert_eq!(first.captured().len(), 3, "first matching rule must win");
    assert_eq!(second.captured().len(), 0, "later rule must never fire");
}

#[test]
fn header_based_dispatch_routes_to_tenant_upstream() {
    let tenant = MockUpstream::start(json!({"target": "tenant"})).expect("tenant upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "hgw.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "default-action"

    forward_rules:
      - rules:
          - header:
              name: X-Tenant
              value: foo
        origin:
          id: tenant-foo
          action:
            type: proxy
            url: "{}"
"#,
        tenant.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let matched = proxy
        .get_with_headers("/anything", "hgw.localhost", &[("X-Tenant", "foo")])
        .expect("tenant req");
    assert_eq!(matched.status, 200);
    assert_eq!(tenant.captured().len(), 1, "X-Tenant: foo must dispatch");

    let other = proxy
        .get_with_headers("/anything", "hgw.localhost", &[("X-Tenant", "bar")])
        .expect("other tenant req");
    assert_eq!(other.status, 200);
    assert_eq!(other.text().unwrap(), "default-action");
    assert_eq!(
        tenant.captured().len(),
        1,
        "non-foo tenants must fall through"
    );

    let no_header = proxy.get("/anything", "hgw.localhost").expect("no header");
    assert_eq!(no_header.status, 200);
    assert_eq!(no_header.text().unwrap(), "default-action");
    assert_eq!(tenant.captured().len(), 1, "missing header falls through");
}

#[test]
fn query_based_dispatch_routes_to_staging_upstream() {
    let staging = MockUpstream::start(json!({"target": "staging"})).expect("staging upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "qgw.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "default-action"

    forward_rules:
      - rules:
          - query:
              name: env
              value: staging
        origin:
          id: staging-backend
          action:
            type: proxy
            url: "{}"
"#,
        staging.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let matched = proxy
        .get("/anything?env=staging", "qgw.localhost")
        .expect("staging req");
    assert_eq!(matched.status, 200);
    assert_eq!(staging.captured().len(), 1, "env=staging must dispatch");

    let other = proxy
        .get("/anything?env=prod", "qgw.localhost")
        .expect("prod req");
    assert_eq!(other.status, 200);
    assert_eq!(other.text().unwrap(), "default-action");
    assert_eq!(staging.captured().len(), 1, "env=prod must fall through");
}
