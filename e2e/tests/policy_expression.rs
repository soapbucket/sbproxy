//! End-to-end coverage for the `expression` policy (CEL-based gating).
//!
//! Exercises the documented behaviour from `examples/35-cel-policy/sb.yml`:
//! the request is allowed only when the configured CEL expression
//! evaluates to `true`. CEL header keys are normalized to lowercase,
//! so `request.headers["x-role"]` reads the value of any incoming
//! `X-Role` / `x-role` header. A failed evaluation returns the
//! configured `deny_status` (default 403) with `deny_message` as
//! the body.
//!
//! The CEL request context exposes `request.method`, `request.path`,
//! `request.host`, `request.headers`, `request.query`,
//! `request.time` (Unix epoch seconds), `request.unix_nanos`, and
//! `connection.remote_ip`.

use sbproxy_e2e::ProxyHarness;

#[test]
fn header_based_allow_lets_admin_through() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "cel.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: 'request.headers["x-role"] == "admin"'
        deny_status: 403
        deny_message: "role not permitted"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    // The role header satisfies the CEL guard.
    let allowed = harness
        .get_with_headers("/secret", "cel.localhost", &[("x-role", "admin")])
        .expect("allowed");
    assert_eq!(
        allowed.status, 200,
        "request with x-role: admin must be allowed; got {}",
        allowed.status
    );
}

#[test]
fn header_based_allow_blocks_other_roles() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "cel.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: 'request.headers["x-role"] == "admin"'
        deny_status: 403
        deny_message: "role not permitted"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    // No header at all.
    let missing = harness.get("/secret", "cel.localhost").expect("missing");
    assert_eq!(missing.status, 403, "missing x-role must be denied");

    // Wrong role.
    let wrong = harness
        .get_with_headers("/secret", "cel.localhost", &[("x-role", "guest")])
        .expect("wrong");
    assert_eq!(wrong.status, 403, "x-role: guest must be denied");
    let body = wrong.text().unwrap_or_default();
    assert!(
        body.contains("role not permitted"),
        "deny_message must surface in the response body; got: {body}"
    );
}

#[test]
fn path_prefix_block_rejects_admin_routes() {
    // Allow everything except `/admin/*`.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "cel.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: '!request.path.startsWith("/admin")'
        deny_status: 403
        deny_message: "admin routes locked"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    let public = harness
        .get("/public/page", "cel.localhost")
        .expect("public");
    assert_eq!(public.status, 200, "non-admin path must be allowed");

    let admin = harness.get("/admin/users", "cel.localhost").expect("admin");
    assert_eq!(admin.status, 403, "/admin prefix must be blocked by CEL");
}

#[test]
fn request_time_namespace_is_evaluable_in_expression_policy() {
    // The CEL request context exposes `request.time` (Unix epoch
    // seconds) and `request.unix_nanos`. A rule that requires the
    // request time to be after 2020-01-01 (epoch 1577836800) must
    // pass for any present-day traffic, proving the namespace is
    // actually populated and usable from an expression policy.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "cel.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: 'request.time > 1577836800'
        deny_status: 403
        deny_message: "time-gate failed"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");

    let resp = harness.get("/health", "cel.localhost").expect("send");
    assert_eq!(
        resp.status, 200,
        "request.time must be exposed as Unix epoch seconds and pass the post-2020 gate"
    );
}
