//! End-to-end test for OpenAPI emission.
//!
//! Confirms that the per-host `/.well-known/openapi.json` and
//! `/.well-known/openapi.yaml` endpoints described in
//! `examples/96-openapi-emission/sb.yml` actually emit a valid
//! OpenAPI 3.0 document at runtime.

use sbproxy_e2e::ProxyHarness;

fn config_yaml() -> &'static str {
    r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "api.localhost":
    expose_openapi: true
    action:
      type: proxy
      url: https://httpbin.org
    allowed_methods: ["GET", "POST"]
    forward_rules:
      - rules:
          - path:
              template: /users/{id:[0-9]+}/posts/{post_id}
        parameters:
          - name: id
            in: path
            required: true
            schema:
              type: integer
        origin:
          id: user-posts
          action:
            type: proxy
            url: https://httpbin.org/anything
"#
}

#[test]
fn well_known_openapi_json_is_emitted() {
    let proxy = ProxyHarness::start_with_yaml(config_yaml()).expect("start proxy");
    let resp = proxy
        .get("/.well-known/openapi.json", "api.localhost")
        .expect("GET openapi.json");
    assert_eq!(resp.status, 200);
    let spec = resp.json().expect("parse JSON spec");
    assert_eq!(spec["openapi"], "3.0.3");
    let paths = spec["paths"].as_object().expect("paths object");
    assert!(
        paths.contains_key("/users/{id:[0-9]+}/posts/{post_id}"),
        "template path missing from emitted spec: {:?}",
        paths.keys().collect::<Vec<_>>()
    );
}

#[test]
fn well_known_openapi_yaml_is_emitted() {
    let proxy = ProxyHarness::start_with_yaml(config_yaml()).expect("start proxy");
    let resp = proxy
        .get("/.well-known/openapi.yaml", "api.localhost")
        .expect("GET openapi.yaml");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("decode body");
    assert!(body.contains("openapi"), "yaml missing openapi key: {body}");
    assert!(body.contains("3.0.3"), "yaml missing version");
}

#[test]
fn parameters_block_round_trips_into_emitted_spec() {
    let proxy = ProxyHarness::start_with_yaml(config_yaml()).expect("start proxy");
    let resp = proxy
        .get("/.well-known/openapi.json", "api.localhost")
        .expect("GET openapi.json");
    let spec = resp.json().expect("parse JSON spec");
    let path = &spec["paths"]["/users/{id:[0-9]+}/posts/{post_id}"];
    let params = path["get"]["parameters"]
        .as_array()
        .expect("parameters array");
    assert_eq!(params.len(), 1);
    assert_eq!(params[0]["name"], "id");
    assert_eq!(params[0]["in"], "path");
    assert_eq!(params[0]["schema"]["type"], "integer");
}
