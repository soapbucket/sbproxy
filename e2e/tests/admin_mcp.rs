//! WOR-2314 - the gateway's own admin API served as MCP tools.
//!
//! One proxy process serves both surfaces: the admin API on a local
//! port, and an `mcp` origin whose `type: openapi` federated server
//! points back at that admin port with the admin Basic credential in
//! a static `headers:` entry. The tests prove:
//!
//! 1. `tools/list` advertises the admin-derived read tools, and the
//!    declared mutating tool is filtered out by the default gates.
//! 2. A `tools/call` round-trips against the real admin API: the
//!    REST dispatch carries the Basic credential (a 401 would come
//!    back as `isError: true`) and the admin JSON body returns as
//!    MCP tool-result content.
//! 3. A direct `tools/call` for the mutating tool is refused without
//!    reaching the admin API.
//!
//! Mirrors `examples/admin-mcp/`, which is the documented shape.

use std::net::TcpListener;

use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};

fn pick_admin_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Same shape as examples/admin-mcp/sb.yml, shrunk to three declared
/// operations. `YWRtaW46c2VjcmV0` is base64("admin:secret"), pairing
/// with the admin credentials below.
fn config(admin_port: u16) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: sbproxy-admin
        version: "1.0.0"
      rbac_policies:
        admin_read_only:
          default_allow: false
          tool_access:
            - principals: []
              allowed:
                - sbproxy.get_health
                - sbproxy.get_stats
      federated_servers:
        - type: openapi
          origin: "http://127.0.0.1:{admin_port}"
          prefix: sbproxy
          namespace: always
          rbac: admin_read_only
          timeout: 10s
          egress:
            mode: deny_by_default
            hosts: ["127.0.0.1"]
            allow_private: true
          headers:
            authorization: "Basic YWRtaW46c2VjcmV0"
          spec:
            openapi: "3.0.0"
            info:
              title: SBproxy admin API (curated subset)
              version: "1.0"
            paths:
              "/api/health":
                get:
                  operationId: get_health
                  summary: "Aggregate proxy liveness summary."
              "/api/stats":
                get:
                  operationId: get_stats
                  summary: "Request-log statistics summary."
              "/admin/reload":
                post:
                  operationId: reload_config
                  summary: "Hot-reload the config from disk."
      guardrails:
        - type: tool_allowlist
          allow:
            - sbproxy.get_health
            - sbproxy.get_stats
"#
    )
}

fn tools_list_names(harness: &ProxyHarness) -> Vec<String> {
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let resp = harness
        .post_json("/", "mcp.localhost", &list, &[])
        .expect("tools/list");
    assert_eq!(resp.status, 200);
    let parsed: Value = serde_json::from_slice(&resp.body).expect("tools/list json");
    parsed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect()
}

/// tools/list advertises the admin-derived read tools and a
/// tools/call round-trips against the proxy's own admin API through
/// the static Basic credential.
#[test]
fn admin_tools_listed_and_call_round_trips() {
    let admin_port = pick_admin_port();
    let harness = match ProxyHarness::start_with_yaml(&config(admin_port)) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping admin_tools_listed_and_call_round_trips: {e}");
            return;
        }
    };
    ProxyHarness::wait_for_port(admin_port, std::time::Duration::from_secs(5))
        .expect("admin port to bind");

    // The read tools are advertised under the sbproxy. prefix.
    let names = tools_list_names(&harness);
    assert!(
        names.iter().any(|n| n == "sbproxy.get_health"),
        "admin-derived get_health must be listed, got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "sbproxy.get_stats"),
        "admin-derived get_stats must be listed, got {names:?}"
    );

    // tools/call dispatches GET /api/health to the admin port with
    // the Basic credential attached. Without the credential the
    // admin API answers 401, which would surface as isError: true.
    let call = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "sbproxy.get_health", "arguments": {}}
    });
    let resp = harness
        .post_json("/", "mcp.localhost", &call, &[])
        .expect("tools/call");
    assert_eq!(resp.status, 200);
    let parsed: Value = serde_json::from_slice(&resp.body).expect("tools/call json");
    assert!(parsed.get("error").is_none(), "call must succeed: {parsed}");
    assert_eq!(
        parsed.pointer("/result/isError").and_then(Value::as_bool),
        Some(false),
        "authenticated admin call must not be a tool error: {parsed}"
    );
    let text = parsed
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        text.contains("\"status\""),
        "admin /api/health body must round-trip as tool content, got {parsed}"
    );
}

/// The declared mutating tool is filtered out of tools/list and a
/// direct tools/call for it is refused before the admin API sees a
/// request.
#[test]
fn mutating_admin_tool_is_denied_by_default() {
    let admin_port = pick_admin_port();
    let harness = match ProxyHarness::start_with_yaml(&config(admin_port)) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping mutating_admin_tool_is_denied_by_default: {e}");
            return;
        }
    };
    ProxyHarness::wait_for_port(admin_port, std::time::Duration::from_secs(5))
        .expect("admin port to bind");

    // Declared in the spec, absent from both gates: not advertised.
    let names = tools_list_names(&harness);
    assert!(
        !names.iter().any(|n| n == "sbproxy.reload_config"),
        "mutating tool must be filtered from tools/list, got {names:?}"
    );

    // Calling it anyway is refused with a JSON-RPC error naming the
    // guardrail; the upstream admin API is never contacted.
    let call = json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "sbproxy.reload_config", "arguments": {}}
    });
    let resp = harness
        .post_json("/", "mcp.localhost", &call, &[])
        .expect("tools/call");
    assert_eq!(resp.status, 200, "JSON-RPC errors carry HTTP 200");
    let parsed: Value = serde_json::from_slice(&resp.body).expect("tools/call json");
    let err = parsed.get("error").expect("error envelope present on deny");
    let msg = err["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("blocked") || msg.contains("denied"),
        "error must explain the deny, got: {msg}"
    );
}
