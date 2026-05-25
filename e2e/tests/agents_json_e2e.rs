//! agents.json emission (WOR-820).
//!
//! Verifies the proxy serves a schema-valid agents.json v0.1 manifest
//! at `/.well-known/agents.json` from per-origin config (operator
//! `info` + `flows`, `sources` defaulting to the origin OpenAPI), and
//! that an origin without the config falls through to the upstream.

use sbproxy_e2e::ProxyHarness;

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>api</h1>"
    agents_json:
      info:
        title: "Shop API"
        version: "1.0.0"
        description: "Outcome-based order flows"
      flows:
        - id: place_order
          title: "Place an order"
          description: "Create then confirm an order"
          actions:
            - id: create_order
              sourceId: openapi
              operationId: createOrder
          fields:
            parameters: []
            responses: {}
  "bare.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>bare</h1>"
"#;

#[test]
fn serves_schema_valid_agents_json() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get("/.well-known/agents.json", "api.localhost")
        .expect("send");
    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(ct.contains("application/json"), "unexpected ct: {ct}");

    let doc: serde_json::Value = serde_json::from_slice(&resp.body).expect("valid JSON");
    // Required top-level fields of the agents.json v0.1 spec.
    assert_eq!(doc["agentsJson"], "0.1.0");
    assert_eq!(doc["info"]["title"], "Shop API");
    assert_eq!(doc["info"]["version"], "1.0.0");
    assert!(doc["info"]["description"].is_string());
    assert!(doc["sources"].is_array());
    assert!(doc["flows"].is_array());
}

#[test]
fn sources_default_to_origin_openapi() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get("/.well-known/agents.json", "api.localhost")
        .expect("send");
    let doc: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(doc["sources"][0]["id"], "openapi");
    assert_eq!(
        doc["sources"][0]["path"],
        "https://api.localhost/.well-known/openapi.json"
    );
}

#[test]
fn operator_flow_appears_in_manifest() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get("/.well-known/agents.json", "api.localhost")
        .expect("send");
    let doc: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    let flow = &doc["flows"][0];
    assert_eq!(flow["id"], "place_order");
    assert_eq!(flow["actions"][0]["operationId"], "createOrder");
    // Required flow fields present (schema validity).
    assert!(flow["fields"]["parameters"].is_array());
    assert!(flow["fields"].get("responses").is_some());
}

#[test]
fn unconfigured_origin_falls_through() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get("/.well-known/agents.json", "bare.localhost")
        .expect("send");
    let body = String::from_utf8(resp.body).unwrap_or_default();
    assert!(
        !body.contains("agentsJson"),
        "origin without agents_json must not emit a manifest; got:\n{body}"
    );
}
