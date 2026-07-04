//! MCP OAuth auth discovery, RFC 9728 (WOR-806).
//!
//! When the MCP gateway declares `oauth:`, it serves RFC 9728 OAuth
//! Protected Resource Metadata at `/.well-known/oauth-protected-resource`
//! and advertises a pointer to it in the discovery manifest, so an agent
//! can find the authorization server before opening a session.

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
      oauth:
        authorization_servers: ["https://issuer.example.com"]
        scopes_supported: ["mcp.read", "mcp.call"]
      federated_servers:
        - origin: "http://127.0.0.1:9/mcp"
          prefix: x
  "plain.localhost":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: plain-gateway
        version: "1.0.0"
      federated_servers:
        - origin: "http://127.0.0.1:9/mcp"
          prefix: x
"#;

#[test]
fn serves_rfc9728_protected_resource_metadata() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get("/.well-known/oauth-protected-resource", "mcp.localhost")
        .expect("send");
    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(ct.contains("application/json"), "ct: {ct}");

    let doc: serde_json::Value = serde_json::from_slice(&resp.body).expect("json");
    assert!(
        doc["resource"].as_str().unwrap().ends_with("/"),
        "resource should be the gateway URL"
    );
    assert_eq!(
        doc["authorization_servers"][0],
        "https://issuer.example.com"
    );
    assert_eq!(doc["bearer_methods_supported"][0], "header");
    assert!(
        doc["scopes_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "mcp.read"),
        "scopes should include mcp.read"
    );
}

#[test]
fn discovery_manifest_advertises_authorization_pointer() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get("/.well-known/mcp-server", "mcp.localhost")
        .expect("send");
    assert_eq!(resp.status, 200);
    let doc: serde_json::Value = serde_json::from_slice(&resp.body).expect("json");
    assert_eq!(doc["authorization"]["type"], "oauth2");
    assert!(
        doc["authorization"]["resourceMetadata"]
            .as_str()
            .unwrap()
            .ends_with("/.well-known/oauth-protected-resource"),
        "manifest must point at the RFC 9728 metadata; got {:?}",
        doc["authorization"]
    );
}

#[test]
fn non_oauth_gateway_omits_auth_discovery() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    // The plain gateway does not serve the RFC 9728 document...
    let resp = harness
        .get("/.well-known/oauth-protected-resource", "plain.localhost")
        .expect("send");
    let body = String::from_utf8(resp.body).unwrap_or_default();
    assert!(
        !body.contains("authorization_servers"),
        "plain gateway must not serve RFC 9728 metadata; got: {body}"
    );
    // ...and its discovery manifest carries no authorization block.
    let m = harness
        .get("/.well-known/mcp-server", "plain.localhost")
        .expect("send");
    let doc: serde_json::Value = serde_json::from_slice(&m.body).expect("json");
    assert!(doc.get("authorization").is_none());
}

/// WOR-1643: the discovery flow starts from a 401 challenge. A
/// credential-less MCP POST against an `oauth:`-configured gateway
/// must return 401 with a `WWW-Authenticate` header pointing at the
/// protected-resource metadata this gateway serves.
#[test]
fn credential_less_post_gets_rfc9728_challenge() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let resp = harness
        .post_json("/", "mcp.localhost", &body, &[])
        .expect("send");
    assert_eq!(resp.status, 401, "credential-less POST must be challenged");
    let challenge = resp
        .headers
        .get("www-authenticate")
        .cloned()
        .unwrap_or_default();
    assert!(
        challenge.starts_with("Bearer "),
        "challenge must be a Bearer scheme, got: {challenge}"
    );
    assert!(
        challenge.contains("resource_metadata=\"")
            && challenge.contains("/.well-known/oauth-protected-resource"),
        "challenge must point at the protected-resource metadata, got: {challenge}"
    );

    // Drive the flow the challenge advertises: the metadata URL it
    // names must serve the RFC 9728 document.
    let meta = harness
        .get("/.well-known/oauth-protected-resource", "mcp.localhost")
        .expect("fetch metadata");
    assert_eq!(meta.status, 200);
    let doc: serde_json::Value = serde_json::from_slice(&meta.body).expect("json");
    assert_eq!(
        doc["authorization_servers"][0],
        "https://issuer.example.com"
    );
}

/// WOR-1643: a request that carries credentials is never
/// re-challenged by the MCP layer (token validation belongs to the
/// generic auth layer, not this gate).
#[test]
fn authorized_post_is_not_challenged() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "ping"});
    let resp = harness
        .post_json(
            "/",
            "mcp.localhost",
            &body,
            &[("Authorization", "Bearer test-token")],
        )
        .expect("send");
    assert_eq!(resp.status, 200, "authorized POST must reach the handler");
    let parsed: serde_json::Value = serde_json::from_slice(&resp.body).expect("json");
    assert_eq!(parsed["result"], "pong");
}

/// WOR-1643: a gateway without `oauth:` keeps its open behaviour;
/// no challenge is emitted for credential-less POSTs.
#[test]
fn non_oauth_gateway_does_not_challenge() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "ping"});
    let resp = harness
        .post_json("/", "plain.localhost", &body, &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    let parsed: serde_json::Value = serde_json::from_slice(&resp.body).expect("json");
    assert_eq!(parsed["result"], "pong");
}
