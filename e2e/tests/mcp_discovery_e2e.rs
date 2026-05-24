//! MCP discovery manifest (WOR-806).
//!
//! Verifies SBproxy serves a discovery manifest at
//! `/.well-known/mcp-server` and the Cloudflare Agent-Readiness variant
//! `/.well-known/mcp/server-card.json` for an MCP gateway origin, so an
//! agent can discover the endpoint + protocol + tool catalogue without
//! opening a JSON-RPC session.

use sbproxy_e2e::ProxyHarness;

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: sbproxy-gateway
        version: "1.0.0"
      federated_servers:
        - origin: "http://127.0.0.1:9/mcp"
          prefix: x
  "static.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>not mcp</h1>"
"#;

fn assert_valid_manifest(body: &[u8]) {
    let doc: serde_json::Value = serde_json::from_slice(body).expect("manifest is JSON");
    assert_eq!(doc["name"], "sbproxy-gateway");
    assert_eq!(doc["version"], "1.0.0");
    assert_eq!(doc["protocolVersion"], "2025-06-18");
    assert_eq!(doc["transport"], "streamable-http");
    assert!(
        doc["endpoint"].as_str().unwrap().ends_with("/"),
        "endpoint should be the gateway root URL"
    );
    assert!(doc["capabilities"]["tools"].is_object());
    assert!(doc["tools"].is_array());
}

#[test]
fn serves_discovery_manifest_at_mcp_server() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get("/.well-known/mcp-server", "mcp.localhost")
        .expect("send");
    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(ct.contains("application/json"), "unexpected ct: {ct}");
    assert_valid_manifest(&resp.body);
}

#[test]
fn serves_cloudflare_server_card_variant() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get("/.well-known/mcp/server-card.json", "mcp.localhost")
        .expect("send");
    assert_eq!(resp.status, 200);
    assert_valid_manifest(&resp.body);
}

#[test]
fn non_mcp_origin_does_not_serve_manifest() {
    // A static origin is not an MCP gateway: the well-known path is not
    // intercepted and falls through to the origin action.
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get("/.well-known/mcp-server", "static.localhost")
        .expect("send");
    let body = String::from_utf8(resp.body).unwrap_or_default();
    assert!(
        !body.contains("\"transport\""),
        "static origin must not emit an MCP manifest; got:\n{body}"
    );
}
