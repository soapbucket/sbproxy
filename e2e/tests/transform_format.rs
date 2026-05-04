//! End-to-end coverage for text-shaping response transforms.
//!
//! Covers:
//! * `format_convert`  - JSON <-> YAML round-tripping.
//! * `replace_strings` - literal and regex find-and-replace.
//! * `template`        - render a minijinja template against a JSON body.
//! * `encoding`        - base64-encode the response body.
//! * `payload_limit`   - truncate vs reject oversize bodies.
//!
//! Most tests use a self-contained `static` action so the suite
//! does not depend on any external upstream. The `fail_on_error`
//! tests use a MockUpstream because the body-buffering pipeline
//! that honours that flag only runs on the proxy-action path.

use sbproxy_e2e::{MockUpstream, ProxyHarness};

// --- format_convert: JSON to YAML and YAML to JSON ---

#[test]
fn format_convert_json_to_yaml() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "fmt.local":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        name: Alice
        age: 30
        roles:
          - admin
          - user
    transforms:
      - type: format_convert
        from: json
        to: yaml
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "fmt.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");

    // YAML output uses key: value lines.
    assert!(
        body.contains("name: Alice"),
        "expected YAML key line: {}",
        body
    );
    assert!(body.contains("age: 30"));
    assert!(body.contains("- admin"));
    assert!(body.contains("- user"));
}

#[test]
fn format_convert_yaml_to_json() {
    // We feed the body through a static action where `body` is a
    // raw YAML string and `content_type` advertises text/yaml. The
    // transform parses it as YAML and emits JSON.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "yaml.local":
    action:
      type: static
      status_code: 200
      content_type: text/yaml
      body: |
        name: Bob
        age: 42
    transforms:
      - type: format_convert
        from: yaml
        to: json
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "yaml.local").expect("GET");
    assert_eq!(resp.status, 200);
    let json: serde_json::Value = resp.json().expect("body should now be JSON");
    assert_eq!(json["name"], "Bob");
    assert_eq!(json["age"], 42);
}

// --- replace_strings: literal + regex ---

#[test]
fn replace_strings_handles_literal_and_regex_replacements() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "replace.local":
    action:
      type: static
      status_code: 200
      content_type: application/json
      body: |
        {
          "endpoint": "https://internal.example.com/v1/charges",
          "card": "4242424242424242",
          "note": "internal.example.com is the source of truth"
        }
    transforms:
      - type: replace_strings
        replacements:
          - find: "internal.example.com"
            replace: "public.example.com"
          - find: '\d{16}'
            replace: "[REDACTED]"
            regex: true
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "replace.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");

    assert!(
        !body.contains("internal.example.com"),
        "literal replacement should remove internal hostname: {}",
        body
    );
    assert!(
        body.contains("public.example.com"),
        "literal replacement should insert public hostname: {}",
        body
    );
    assert!(
        !body.contains("4242424242424242"),
        "regex replacement should redact the card: {}",
        body
    );
    assert!(
        body.contains("[REDACTED]"),
        "redaction sentinel should be present: {}",
        body
    );
}

// --- template: render minijinja against the response body ---

#[test]
fn template_transform_renders_minijinja_against_json_body() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "tmpl.local":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        order_id: ORD-1042
        customer: Ada Lovelace
        total: 10042.50
    transforms:
      - type: template
        template: "Order {{ order_id }} for {{ customer }} -> ${{ total }}"
    response_modifiers:
      - headers:
          set:
            Content-Type: text/plain; charset=utf-8
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "tmpl.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");
    assert_eq!(body, "Order ORD-1042 for Ada Lovelace -> $10042.5");
}

#[test]
fn payload_limit_via_proxy_action_replaces_body_with_generic_error() {
    // Hits the `proxy` action body-buffering pipeline (which honors
    // `fail_on_error: true` by replacing the body with a generic
    // error envelope). The mock returns a body that is larger than
    // `max_size`, so the transform errors and the buffered response
    // gets the error envelope instead of the upstream payload.
    let upstream = MockUpstream::start(serde_json::json!({
        "data": "this body will exceed the four byte cap"
    }))
    .expect("start mock upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cap-proxy.local":
    action:
      type: proxy
      url: "{}"
    transforms:
      - type: payload_limit
        max_size: 4
        truncate: false
        fail_on_error: true
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = proxy.get("/", "cap-proxy.local").expect("GET");
    let body = resp.text().unwrap_or_default();
    assert!(
        body.contains("\"error\""),
        "expected generic error envelope when payload exceeds limit on proxy action, got: {}",
        body
    );
    assert!(
        !body.contains("exceed"),
        "upstream payload must not leak through: {}",
        body
    );
}

// --- encoding: base64 encode ---

#[test]
fn encoding_transform_base64_encodes_the_body() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "enc.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "Hello, World!"
    transforms:
      - type: encoding
        encoding: base64_encode
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "enc.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");
    assert_eq!(body, "SGVsbG8sIFdvcmxkIQ==");
}

// --- payload_limit: truncate vs reject ---

#[test]
fn payload_limit_truncate_clips_oversize_body_to_max_size() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "cap-trunc.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "abcdefghijklmnopqrstuvwxyz0123456789"
    transforms:
      - type: payload_limit
        max_size: 8
        truncate: true
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "cap-trunc.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.body;
    assert_eq!(body.len(), 8, "body should be clipped to max_size");
    assert_eq!(&body[..], b"abcdefgh");
}

#[test]
fn payload_limit_reject_on_static_action_passes_through_after_warn() {
    // The static-action transform pipeline logs and continues when a
    // transform errors (fail_on_error is honoured only on the
    // proxy-action body-buffering pipeline; see
    // `payload_limit_via_proxy_action_replaces_body_with_generic_error`).
    // We document the static-action behaviour: the original body is
    // returned unchanged after the failed transform.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "cap-reject.local":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "abcdefghijklmnop"
    transforms:
      - type: payload_limit
        max_size: 4
        truncate: false
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "cap-reject.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().unwrap_or_default();
    // Static-action transforms warn-and-continue on error; original
    // body passes through.
    assert_eq!(body, "abcdefghijklmnop");
}
