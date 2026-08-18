//! WOR-2489: end-to-end proof for `type: local` MCP servers -- a
//! static tool, a two-step composed DAG against a real HTTP stub with
//! a JS-shaped response, egress enforcement on a DAG step, draft-server
//! invisibility, and the governance-evidence feed. Runs the release
//! binary through [`ProxyHarness`], not a unit seam.
//!
//! Not wired into CI (repo rule: e2e runs locally against the release
//! binary, never in the required PR lane).
//!
//! Claim-to-test mapping:
//!
//! - The static call -> [`static_local_tool_call_succeeds`].
//! - The composed call (dependency order + JS-shaped response) ->
//!   [`composed_two_step_dag_dials_the_stub_in_dependency_order_and_shapes_the_response`].
//! - An egress-denied step host refused before connect ->
//!   [`egress_denied_step_host_is_refused_before_connect`].
//! - A draft local server invisible and refused ->
//!   [`draft_local_server_is_invisible_and_refused`].
//! - Evidence lines on the file sink with a gapless seq ->
//!   [`governance_evidence_carries_a_gapless_seq_for_local_dispatch`].

use std::path::Path;
use std::time::{Duration, Instant};

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::{json, Value};

const HOST: &str = "mcp.local-tools.localhost";

/// One origin carrying two `type: local` federated servers:
///
/// - `compose`: a static tool (`ping`), a two-step composed DAG
///   (`workflow`) whose steps dial `stub_base` and whose response is
///   JS-shaped, and a one-step DAG (`exfiltrate`) whose step's host is
///   outside `compose`'s egress allowlist.
/// - `draft`: `status: draft`, one tool (`secret_tool`), never
///   reachable.
///
/// `events_path` of `None` omits the `events:` block entirely (no
/// sink); `Some(path)` wires a file sink for
/// `mcp_governance_decision`.
fn config_yaml(stub_base: &str, events_path: Option<&Path>) -> String {
    let events_block = match events_path {
        Some(path) => format!(
            "events:\n  sink: file\n  path: '{}'\n  types:\n    - mcp_governance_decision\n",
            path.display()
        ),
        None => String::new(),
    };

    let template = r#"
proxy:
  http_bind_port: 0
__EVENTS_BLOCK__origins:
  "__HOST__":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: local-tools-gateway
        version: "1.0.0"
      federated_servers:
        - origin: compose
          type: local
          prefix: compose
          egress:
            mode: enforce
            hosts: ["127.0.0.1"]
            allow_private: true
          tools:
            - name: ping
              description: "a static tool"
              input_schema:
                type: object
                properties: {}
              static:
                message: pong

            - name: workflow
              description: "a two-step composed http DAG"
              input_schema:
                type: object
                properties: {}
              steps:
                steps:
                  - name: first
                    http:
                      method: GET
                      url: "__STUB_BASE__/first"
                      timeout: 10s

                  - name: second
                    depends_on: [first]
                    http:
                      method: GET
                      url: "__STUB_BASE__/second?got=${steps.first.body.greeting}"
                      timeout: 10s

                response:
                  js: "({greeting: ctx.steps.first.body.greeting, echoed: ctx.steps.second.body.echoed, status: ctx.steps.first.status})"

            - name: exfiltrate
              description: "a one-step DAG whose step host is outside the egress allowlist"
              input_schema:
                type: object
                properties: {}
              steps:
                steps:
                  - name: attempt
                    http:
                      method: GET
                      url: "http://mcp-local-tools-e2e-denied.invalid/steal"
                      timeout: 10s

        - origin: draft
          type: local
          prefix: draft
          status: draft
          tools:
            - name: secret_tool
              description: "hidden behind a draft server"
              input_schema:
                type: object
                properties: {}
              static:
                message: shh
"#;

    template
        .replace("__EVENTS_BLOCK__", &events_block)
        .replace("__HOST__", HOST)
        .replace("__STUB_BASE__", stub_base)
}

// --- Request helpers ---

fn call_tool(harness: &ProxyHarness, id: i64, tool: &str, arguments: Value) -> Value {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}
    });
    let resp = harness
        .post_json("/", HOST, &body, &[])
        .expect("tools/call");
    assert_eq!(
        resp.status,
        200,
        "JSON-RPC responses (including errors) carry HTTP 200: {:?}",
        resp.text()
    );
    resp.json().expect("tools/call response is json")
}

fn list_tools(harness: &ProxyHarness) -> Vec<String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let resp = harness
        .post_json("/", HOST, &body, &[])
        .expect("tools/list");
    assert_eq!(
        resp.status,
        200,
        "tools/list must succeed: {:?}",
        resp.text()
    );
    let parsed: Value = resp.json().expect("tools/list response is json");
    parsed["result"]["tools"]
        .as_array()
        .expect("tools/list result carries an array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect()
}

fn error_message(resp: &Value) -> &str {
    resp["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a JSON-RPC error envelope, got: {resp}"))
}

/// Poll the events file until it has at least `min_lines` complete
/// JSON lines, or give up.
fn read_ndjson_lines(path: &Path, min_lines: usize, timeout: Duration) -> Vec<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<Value> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        if lines.len() >= min_lines || Instant::now() >= deadline {
            return lines;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// --- Tests ---

/// A `static` local tool's `tools/call` returns its configured value
/// through the real dispatch chain, end to end.
#[test]
fn static_local_tool_call_succeeds() {
    let stub = MockUpstream::start(json!({})).expect("start stub upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&stub.base_url(), None)).expect("start proxy");

    let resp = call_tool(&harness, 1, "ping", json!({}));
    assert!(resp.get("error").is_none(), "got: {resp}");
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("tool result text");
    assert_eq!(text, r#"{"message":"pong"}"#, "got: {text}");
}

/// The `workflow` tool's two-step DAG dials the stub in dependency
/// order: `second`'s URL interpolates `${steps.first.body.greeting}`,
/// which fails closed if the executor ever ran the steps out of order,
/// so a passing call is itself part of the ordering proof. The final
/// result is the JS-shaped object `response.js` builds, not either
/// step's raw `{status, headers, body}` document.
#[test]
fn composed_two_step_dag_dials_the_stub_in_dependency_order_and_shapes_the_response() {
    let stub = MockUpstream::start_sequence(vec![
        (200, json!({"greeting": "hello"})),
        (200, json!({"echoed": "hello-again"})),
    ])
    .expect("start stub upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&stub.base_url(), None)).expect("start proxy");

    let resp = call_tool(&harness, 1, "workflow", json!({}));
    assert!(resp.get("error").is_none(), "got: {resp}");

    let captured = stub.captured();
    assert_eq!(
        captured.len(),
        2,
        "both steps must have dialed the stub, got: {captured:?}"
    );
    assert!(
        captured[0].path.starts_with("/first"),
        "'first' must dial before 'second', got: {captured:?}"
    );
    assert!(
        captured[1].path.contains("got=hello"),
        "'second' must carry 'first''s real body value through steps.*, got: {captured:?}"
    );

    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("tool result text");
    let shaped: Value = serde_json::from_str(text).expect("shaped result is JSON");
    assert_eq!(
        shaped,
        json!({"greeting": "hello", "echoed": "hello-again", "status": 200}),
        "the response must be the JS-shaped object, not a raw step document: {shaped}"
    );
}

/// The `exfiltrate` tool's single step dials a host outside its
/// server's egress allowlist. The call is refused, and the refusal is
/// recorded on `sbproxy_egress_refused_total` under the local tool's
/// `openapi_tool` purpose (WOR-2489 Task 3's reuse of that label) --
/// proof the dial itself was refused by egress, not merely that the
/// step failed for some other reason. The stub, the only host the
/// server's egress allowlist actually permits, never sees a
/// connection for this call either.
#[test]
fn egress_denied_step_host_is_refused_before_connect() {
    let stub = MockUpstream::start(json!({"ok": true})).expect("start stub upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&stub.base_url(), None)).expect("start proxy");
    let before = stub.captured().len();

    let resp = call_tool(&harness, 1, "exfiltrate", json!({}));
    assert!(
        resp.get("error").is_some(),
        "an egress-denied step must refuse the call, got: {resp}"
    );
    assert_eq!(
        stub.captured().len(),
        before,
        "an egress-denied step must never dial any host, including the allowed stub"
    );

    let metrics = harness.get("/metrics", HOST).expect("metrics");
    assert_eq!(metrics.status, 200);
    let body = metrics.text().unwrap_or_default();
    let refused = body.lines().any(|line| {
        line.starts_with("sbproxy_egress_refused_total")
            && line.contains("purpose=\"openapi_tool\"")
            && line.contains("origin=\"compose\"")
    });
    assert!(
        refused,
        "expected sbproxy_egress_refused_total{{purpose=\"openapi_tool\",...,origin=\"compose\"}} \
         in metrics, got:\n{body}"
    );
}

/// `draft`'s tool is hidden from `tools/list` and refused by name,
/// naming the draft status, exactly like a draft federated server's
/// would be.
#[test]
fn draft_local_server_is_invisible_and_refused() {
    let stub = MockUpstream::start(json!({})).expect("start stub upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&stub.base_url(), None)).expect("start proxy");

    let names = list_tools(&harness);
    assert!(
        !names.iter().any(|n| n == "secret_tool"),
        "a draft local server's tool must be hidden from tools/list, got: {names:?}"
    );

    let resp = call_tool(&harness, 1, "secret_tool", json!({}));
    let message = error_message(&resp);
    assert!(
        message.contains("status 'draft'"),
        "expected a draft-status refusal, got: {message}"
    );
}

/// An allowed local dispatch (`ping`) and a refused one (`secret_tool`,
/// draft-refused) both land on the file sink, with
/// `sbproxy.evidence.seq` gapless starting at 1.
#[test]
fn governance_evidence_carries_a_gapless_seq_for_local_dispatch() {
    let stub = MockUpstream::start(json!({})).expect("start stub upstream");
    let dir = tempfile::tempdir().expect("temp dir");
    let events = dir.path().join("wor2489-local-tools-events.ndjson");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&stub.base_url(), Some(&events)))
        .expect("start proxy");

    let allowed = call_tool(&harness, 1, "ping", json!({}));
    assert!(allowed.get("error").is_none(), "got: {allowed}");

    let refused = call_tool(&harness, 2, "secret_tool", json!({}));
    assert!(
        error_message(&refused).contains("status 'draft'"),
        "got: {refused}"
    );

    let lines = read_ndjson_lines(&events, 2, Duration::from_secs(10));
    let mut seqs: Vec<u64> = lines
        .iter()
        .filter(|line| line["event_type"] == "mcp_governance_decision")
        .filter_map(|line| line["data"]["sbproxy.evidence.seq"].as_u64())
        .collect();
    seqs.sort_unstable();
    assert!(
        seqs.len() >= 2,
        "expected at least 2 governance-decision records, got {}: {lines:?}",
        seqs.len()
    );
    let expected: Vec<u64> = (1..=seqs.len() as u64).collect();
    assert_eq!(
        seqs, expected,
        "evidence sequence must be gapless starting at 1, got: {seqs:?}"
    );
}
