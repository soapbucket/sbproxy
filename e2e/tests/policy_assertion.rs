//! End-to-end coverage for the response-side `assertion` policy.
//!
//! `AssertionPolicy` evaluates a CEL expression against the response
//! context (`response.status`, `response.headers`, `response.body_size`)
//! and is **non-blocking by design**: a failed assertion is logged
//! but does NOT alter the response sent to the client. See
//! `crates/sbproxy-modules/src/policy/mod.rs` (`AssertionPolicy::evaluate`)
//! and `crates/sbproxy-core/src/server.rs` ("Assertions are
//! informational" comment in the response phase).
//!
//! The contract surfaced to operators is therefore narrow:
//!
//! 1. A passing assertion does not change the response.
//! 2. A failing assertion does not change the response.
//! 3. Mis-typed CEL fails open and never blocks traffic.

use sbproxy_e2e::ProxyHarness;

const STATIC_OK: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "assert.localhost":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        ok: true
"#;

#[test]
fn passing_assertion_leaves_response_unchanged() {
    // Assertion that should pass: response.status == 200.
    let yaml = format!(
        "{STATIC_OK}    policies:\n      - type: assertion\n        expression: 'response.status == 200'\n        name: status-check\n",
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness.get("/", "assert.localhost").expect("send");

    assert_eq!(resp.status, 200, "passing assertion must not alter status");
    let body: serde_json::Value = resp.json().expect("json body");
    assert_eq!(body["ok"], true, "passing assertion must not alter body");
}

#[test]
fn failing_assertion_does_not_block_traffic() {
    // Assertion that should fail: claims status is 500. Since
    // assertions are non-blocking the client still sees the
    // upstream-style 200.
    let yaml = format!(
        "{STATIC_OK}    policies:\n      - type: assertion\n        expression: 'response.status == 500'\n        name: should-fail\n",
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness.get("/", "assert.localhost").expect("send");

    assert_eq!(
        resp.status, 200,
        "failing assertion must NOT translate into a 5xx; assertion is informational"
    );
    let body: serde_json::Value = resp.json().expect("json body");
    assert_eq!(
        body["ok"], true,
        "failing assertion must not modify the response body"
    );
}

#[test]
fn malformed_assertion_fails_open_and_proxy_stays_up() {
    // A garbled CEL expression should not crash the proxy or cause
    // a 5xx. AssertionPolicy::evaluate fails open on compile error.
    let yaml = format!(
        "{STATIC_OK}    policies:\n      - type: assertion\n        expression: 'this is not valid CEL @@@'\n        name: garbled\n",
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness.get("/", "assert.localhost").expect("send");

    assert_eq!(
        resp.status, 200,
        "malformed CEL must fail open; proxy must keep serving traffic"
    );
}

#[test]
fn go_compat_assertions_list_format_loads_cleanly() {
    // The Go-compat shape uses an `assertions:` list under
    // `response_assertion`. AssertionPolicy::from_config accepts
    // both shapes, so the proxy must boot and serve traffic with
    // either schema. This protects against schema drift between
    // the two implementations.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "assert.localhost":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        ok: true
    policies:
      - type: response_assertion
        assertions:
          - name: status-check
            cel_expr: |
              response.status == 200
            action: pass
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "assert.localhost").expect("send");
    assert_eq!(
        resp.status, 200,
        "Go-compat assertion list must load cleanly and preserve response"
    );
}
