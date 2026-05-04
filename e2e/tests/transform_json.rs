//! End-to-end coverage for JSON-family response transforms.
//!
//! Three transforms are exercised against a self-contained `static`
//! action so the suite stays offline:
//!
//! * `json` - set/remove/rename top-level fields.
//! * `json_projection` - include or exclude a fixed list of fields.
//! * `json_schema` - validate the upstream body, fail loud when
//!   `fail_on_error: true` and the body violates the schema.
//!
//! Each test follows the same harness pattern: spin the proxy with
//! an inline YAML config, fetch the proxied response, and compare
//! the downstream body against the documented contract.

use sbproxy_e2e::{MockUpstream, ProxyHarness};

// --- json: set / remove / rename ---

#[test]
fn json_transform_renames_removes_and_sets_fields() {
    // Mirrors examples/40-transform-json/sb.yml.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "json.local":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        userId: 1
        id: 1
        title: "first post"
        body: "this body field is removed by the transform"
    transforms:
      - type: json
        rename:
          userId: author_id
        remove:
          - body
        set:
          source: sbproxy
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/posts/1", "json.local").expect("GET");
    assert_eq!(resp.status, 200);

    let json = resp.json().expect("response body must be JSON");
    assert!(
        json.get("userId").is_none(),
        "userId should have been renamed away"
    );
    assert!(
        json.get("body").is_none(),
        "body field should have been removed"
    );
    assert_eq!(json["author_id"], 1, "renamed userId -> author_id");
    assert_eq!(json["id"], 1, "id passes through untouched");
    assert_eq!(json["title"], "first post", "title passes through");
    assert_eq!(json["source"], "sbproxy", "set field is injected");
}

// --- json_projection: include / exclude ---

#[test]
fn json_projection_include_keeps_only_listed_fields() {
    // Mirrors examples/41-transform-json-projection/sb.yml.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "project.local":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        userId: 1
        id: 1
        title: "first post"
        body: "the body is dropped by the projection"
    transforms:
      - type: json_projection
        fields:
          - id
          - title
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/posts/1", "project.local").expect("GET");
    assert_eq!(resp.status, 200);

    let json = resp.json().expect("body must be JSON");
    assert_eq!(json["id"], 1);
    assert_eq!(json["title"], "first post");
    assert!(json.get("userId").is_none(), "userId not in fields list");
    assert!(json.get("body").is_none(), "body not in fields list");
}

#[test]
fn json_projection_exclude_drops_listed_fields() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "exclude.local":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        id: 7
        secret: "do not leak"
        internal: true
        public: "ok"
    transforms:
      - type: json_projection
        fields:
          - secret
          - internal
        exclude: true
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "exclude.local").expect("GET");
    assert_eq!(resp.status, 200);

    let json = resp.json().expect("body must be JSON");
    assert_eq!(json["id"], 7);
    assert_eq!(json["public"], "ok");
    assert!(json.get("secret").is_none(), "secret excluded");
    assert!(json.get("internal").is_none(), "internal excluded");
}

// --- json_schema: validate / pass / fail ---

#[test]
fn json_schema_passes_valid_body() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "schema-ok.local":
    action:
      type: static
      status_code: 200
      content_type: application/json
      json_body:
        id: 1
        title: "valid post"
        userId: 1
    transforms:
      - type: json_schema
        fail_on_error: true
        schema:
          type: object
          required: [id, title, userId]
          properties:
            id: { type: integer }
            title: { type: string }
            userId: { type: integer }
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "schema-ok.local").expect("GET");
    assert_eq!(resp.status, 200);
    let json = resp.json().expect("body must be JSON");
    assert_eq!(json["id"], 1);
    assert_eq!(json["title"], "valid post");
    assert_eq!(json["userId"], 1);
}

#[test]
fn json_schema_fails_when_body_violates_schema() {
    // The upstream body deliberately mismatches the schema: id is a
    // string instead of an integer and userId is missing. With
    // `fail_on_error: true` and a proxy-action origin, the body
    // buffering pipeline replaces the response with a generic error
    // envelope (so the offending payload cannot leak).
    let upstream = MockUpstream::start(serde_json::json!({
        "id": "should-be-int-but-is-string",
        "title": 42
    }))
    .expect("start mock upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "schema-bad.local":
    action:
      type: proxy
      url: "{}"
    transforms:
      - type: json_schema
        fail_on_error: true
        schema:
          type: object
          required: [id, title, userId]
          properties:
            id: {{ type: integer }}
            title: {{ type: string }}
            userId: {{ type: integer }}
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = proxy.get("/", "schema-bad.local").expect("GET");
    let body = resp.text().unwrap_or_default();
    assert!(
        body.contains("\"error\""),
        "expected generic error envelope when schema validation fails, got: {}",
        body
    );
    assert!(
        !body.contains("should-be-int-but-is-string"),
        "offending payload should not be echoed back: {}",
        body
    );
}
