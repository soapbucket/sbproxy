//! OpenAPI 3.0 schema validation policy (F1.2).
//!
//! Spins up the proxy in front of a mock upstream and confirms that
//! valid bodies pass through, invalid bodies are rejected with the
//! configured status, out-of-scope routes are forwarded unchanged,
//! and `mode: log` warns instead of blocking.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn enforce_yaml(upstream: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{upstream}"
    policies:
      - type: openapi_validation
        mode: enforce
        status: 422
        spec:
          openapi: "3.0.3"
          info: {{title: t, version: "1"}}
          paths:
            "/users/{{id}}":
              post:
                requestBody:
                  required: true
                  content:
                    application/json:
                      schema:
                        type: object
                        required: [name]
                        additionalProperties: false
                        properties:
                          name: {{type: string, minLength: 1}}
                          age:  {{type: integer, minimum: 0, maximum: 150}}
"#
    )
}

fn log_yaml(upstream: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{upstream}"
    policies:
      - type: openapi_validation
        mode: log
        spec:
          openapi: "3.0.3"
          info: {{title: t, version: "1"}}
          paths:
            "/users/{{id}}":
              post:
                requestBody:
                  required: true
                  content:
                    application/json:
                      schema:
                        type: object
                        required: [name]
                        properties:
                          name: {{type: string}}
"#
    )
}

#[test]
fn valid_body_passes_through() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&enforce_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json(
            "/users/42",
            "api.localhost",
            &json!({"name": "alice", "age": 30}),
            &[],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1, "upstream should see exactly one request");
}

#[test]
fn missing_required_field_is_rejected() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&enforce_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json("/users/42", "api.localhost", &json!({"age": 30}), &[])
        .expect("send");
    assert_eq!(resp.status, 422);
    let text = resp.text().expect("utf-8");
    assert!(
        text.contains("openapi validation failed"),
        "expected validation error body, got: {text}"
    );
    // The proxy connects to the upstream before validation finishes,
    // so the upstream may see the request line + headers. What we
    // care about is that the rejected body is not forwarded.
    let captured = upstream.captured();
    if let Some(req) = captured.first() {
        assert!(
            req.body.is_empty() || !std::str::from_utf8(&req.body).unwrap_or("").contains("age"),
            "rejected body must not be forwarded upstream, got: {:?}",
            std::str::from_utf8(&req.body).unwrap_or("<bytes>")
        );
    }
}

#[test]
fn additional_property_is_rejected() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&enforce_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json(
            "/users/42",
            "api.localhost",
            &json!({"name": "alice", "rogue": "field"}),
            &[],
        )
        .expect("send");
    assert_eq!(resp.status, 422);
}

#[test]
fn out_of_scope_path_passes() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&enforce_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json(
            "/widgets/42",
            "api.localhost",
            &json!({"anything": "goes"}),
            &[],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn log_mode_does_not_block_invalid_bodies() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&log_yaml(&upstream.base_url())).expect("start proxy");
    let resp = harness
        .post_json("/users/42", "api.localhost", &json!({"age": 30}), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    let captured = upstream.captured();
    assert_eq!(
        captured.len(),
        1,
        "log mode must forward invalid bodies upstream"
    );
}
