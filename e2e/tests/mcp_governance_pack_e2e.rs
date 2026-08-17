//! WOR-2384: end-to-end proof for the MCP governance pack, the whole
//! stack `examples/mcp-governance/sb.yml` turns on at once. Each test
//! maps to one enforcement claim the pack's coverage table makes, and
//! runs the release binary through [`ProxyHarness`], not a unit seam.
//!
//! Config here mirrors `examples/mcp-governance/sb.yml` (bearer auth,
//! sessions, default-deny RBAC, a checked-in tool-versioning lockfile,
//! per-upstream egress, registry approval status, dual-engine argument
//! policies, deterministic session-flow enforcement, response-side
//! content filtering, and a fail-closed governance-evidence feed), with
//! one deliberate shape change: the real example pairs the CEL rule and
//! its Rego twin on the *same* tool (`crm.echo`), so config order alone
//! decides which one a denial names. This file instead scopes the CEL
//! rule to `crm.echo` and the Rego rule to a second tool, `crm.notes`,
//! so each engine's block is independently observable rather than one
//! masking the other.
//!
//! Claim-to-test mapping:
//!
//! - Unauthenticated call refused ->
//!   [`unauthenticated_call_is_refused_before_any_governance_check`].
//! - Un-granted tool refused (RBAC) -> [`ungranted_tool_is_refused_by_rbac`].
//! - Unlocked tool blocked (`block_unlocked`) ->
//!   [`unlocked_tool_is_blocked_by_the_version_gate`].
//! - Draft server invisible and refused ->
//!   [`draft_server_tools_are_hidden_and_refused`].
//! - Egress-denied upstream refused ->
//!   [`egress_denied_upstream_is_never_dialed`].
//! - Argument policy blocks the injection-shaped call, CEL ->
//!   [`argument_policy_cel_blocks_the_injection_shaped_call`].
//! - The Rego variant blocks equally ->
//!   [`argument_policy_rego_blocks_the_injection_shaped_call`].
//! - Taint-then-outbound refused (session flow) ->
//!   [`taint_then_outbound_is_refused_by_the_flow_guardrail`].
//! - Planted secret redacted in the result ->
//!   [`planted_secret_is_redacted_before_dispatch`].
//! - Governance evidence observed on the file sink with a gapless seq ->
//!   [`governance_evidence_carries_a_gapless_per_tenant_sequence`].
//! - Fail-closed refusal when the sink is unwritable ->
//!   [`fail_closed_refuses_the_call_when_the_sink_cannot_accept_the_record`].

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sbproxy_e2e::ProxyHarness;
use sbproxy_extension::mcp::compat::{contract_digest_v2, Lockfile, ToolLock};
use serde_json::{json, Value};

const HOST: &str = "mcp.governance.localhost";
const AUTH: (&str, &str) = ("authorization", "Bearer governance-demo-token");

// --- Mock federated MCP upstream ---
//
// A single shared upstream stands in for `examples/mcp-governance`'s
// `test.sbproxy.dev`: the `reports`, `crm`, and `legacy` federated
// servers below all point at it, exactly like the real example points
// three prefixes at one real host. It exposes three tools -- `hello`,
// `echo`, `notes` -- regardless of which prefix dialled it, since the
// upstream itself has no notion of the gateway's namespacing.
//
// WOR-2384: this mock used to strip whatever prefix a `tools/call`
// name carried before matching it, which is generous in a way a real
// upstream never is -- test.sbproxy.dev serves bare `hello`/`echo` and
// refuses a prefixed name outright. That generosity is what let 10
// tests here pass while `federation.rs`'s
// `call_tool_with_policy_cause_and_headers_from_held_tool` sent the
// *advertised* (namespaced) name in `tools/call` params instead of
// `FederatedTool::upstream_name`, the name this upstream actually
// advertised. The mock now matches the real one: only the bare name
// dispatches, so a regression here fails these tests again instead of
// hiding behind the stub.

struct MockMcpUpstream {
    port: u16,
    tool_calls: Arc<AtomicUsize>,
    captured_tool_call_args: Arc<Mutex<Vec<Value>>>,
    shutdown: Arc<Mutex<bool>>,
}

impl MockMcpUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock mcp upstream");
        let port = listener.local_addr().expect("mock listener address").port();
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let captured_tool_call_args = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));
        let tool_calls_bg = tool_calls.clone();
        let captured_bg = captured_tool_call_args.clone();
        let shutdown_bg = shutdown.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_bg.lock().expect("shutdown lock") {
                    break;
                }
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let tool_calls = tool_calls_bg.clone();
                let captured = captured_bg.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(&mut stream, &tool_calls, &captured);
                });
            }
        });
        Self {
            port,
            tool_calls,
            captured_tool_call_args,
            shutdown,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }

    fn tool_calls(&self) -> usize {
        self.tool_calls.load(Ordering::SeqCst)
    }

    fn captured_tool_call_args(&self) -> Vec<Value> {
        self.captured_tool_call_args
            .lock()
            .expect("captured args lock")
            .clone()
    }
}

impl Drop for MockMcpUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().expect("shutdown lock") = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(headers).ok()?;
    for line in s.split("\r\n") {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn handle_conn(
    stream: &mut std::net::TcpStream,
    tool_calls: &Arc<AtomicUsize>,
    captured_tool_call_args: &Arc<Mutex<Vec<Value>>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut buf = [0u8; 4096];
    let mut total = Vec::new();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total.extend_from_slice(&buf[..n]);
        if let Some(idx) = find_double_crlf(&total) {
            let headers = &total[..idx];
            let len = parse_content_length(headers).unwrap_or(0);
            if total.len() >= idx + 4 + len {
                break;
            }
        }
    }
    let body_start = find_double_crlf(&total)
        .map(|i| i + 4)
        .unwrap_or(total.len());
    let body = &total[body_start..];
    let req: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = req.get("id").cloned().unwrap_or(Value::Null);

    let response_body = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-governance-upstream", "version": "1.0.0"}
            }
        }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"tools": [hello_def(), echo_def(), notes_def()]}
        }),
        "tools/call" => {
            tool_calls.fetch_add(1, Ordering::SeqCst);
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let raw_name = params
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_default();
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            captured_tool_call_args
                .lock()
                .expect("captured args lock")
                .push(arguments.clone());
            // WOR-2384: match the bare name only, exactly like the
            // real test.sbproxy.dev upstream this mock stands in for.
            // A prefixed name (what the gateway sent before it
            // forwarded `FederatedTool::upstream_name`) falls through
            // to the "unknown tool" arm below instead of dispatching.
            match raw_name {
                "hello" => {
                    let name = arguments
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("world");
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {"content": [{"type": "text", "text": format!("Hello, {name}!")}]}
                    })
                }
                "echo" | "notes" => {
                    let message = arguments
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("");
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {"content": [{"type": "text", "text": message}]}
                    })
                }
                _ => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32601, "message": format!("Unknown tool: {raw_name}")}
                }),
            }
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": "method not found"}
        }),
    };
    let body_bytes = serde_json::to_vec(&response_body).unwrap_or_default();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(&body_bytes)?;
    stream.flush()
}

// --- Tool contracts + lockfile ---

fn tool_def(name: &str, description: &str, arg: &str) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": {arg: {"type": "string"}},
            "required": [arg]
        }
    })
}

fn hello_def() -> Value {
    tool_def("hello", "Returns a greeting", "name")
}

fn echo_def() -> Value {
    tool_def("echo", "Echoes back the input", "message")
}

fn notes_def() -> Value {
    tool_def("notes", "Echoes back the input", "message")
}

/// The advertised (namespaced) projection of `def`, matching what
/// `FederatedTool::advertise_as` rewrites the tool's `name` to once
/// `namespace: always` forces every tool under `prefix` to carry it.
fn advertised(prefix: &str, def: &Value) -> Value {
    let mut doc = def.clone();
    let base = def["name"].as_str().expect("tool def has a name");
    doc["name"] = Value::String(format!("{prefix}.{base}"));
    doc
}

/// Write a lockfile pinning `reports.hello`, `reports.echo`,
/// `crm.echo`, `crm.notes`, and `legacy.echo` at their real contract
/// digests. `crm.hello` is deliberately left out, matching the real
/// example's own unlocked-tool escape hatch
/// (`examples/mcp-governance/tool-versions.lock.yaml`), so
/// `block_unlocked: true` blocks it outright rather than merely
/// reporting it.
fn write_lockfile(tag: &str) -> PathBuf {
    let mut tools = BTreeMap::new();
    for (prefix, def) in [
        ("reports", hello_def()),
        ("reports", echo_def()),
        ("crm", echo_def()),
        ("crm", notes_def()),
        ("legacy", echo_def()),
    ] {
        let doc = advertised(prefix, &def);
        let name = doc["name"].as_str().expect("advertised name").to_string();
        tools.insert(
            name,
            ToolLock {
                semver: "1.0.0".parse().expect("semver"),
                contract_digest: contract_digest_v2(&doc),
                contract: Some(doc),
            },
        );
    }
    let lockfile = Lockfile {
        version: 1,
        generated_for: HOST.to_string(),
        tools,
    };
    let path = std::env::temp_dir().join(format!(
        "sbproxy-mcp-governance-lock-{tag}-{}.lock.yaml",
        std::process::id()
    ));
    std::fs::write(&path, lockfile.to_yaml().expect("serialize lockfile")).expect("write lockfile");
    path
}

fn events_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sbproxy-mcp-governance-events-{tag}-{}.ndjson",
        std::process::id()
    ))
}

// --- Config ---
//
// One origin carrying the whole pack: bearer auth, sessions, a
// default-deny `analyst` RBAC policy, a lockfile-backed version gate
// with `block_unlocked: true`, four federated servers (`reports`
// trusted/approved, `crm` untrusted+sensitive, `legacy` draft,
// `denied` egress-blocked), dual-engine argument policies scoped to
// different tools, `two_of_three` session-flow enforcement, and
// secret/PII content filtering. `events_path` of `None` configures
// `fail_closed` with no sink able to accept it, for the fail-closed
// test; `Some(path)` wires the real file sink every other test reads
// back.
fn config_yaml(upstream_url: &str, lockfile_path: &Path, events_path: Option<&Path>) -> String {
    let events_block = match events_path {
        Some(path) => format!(
            "events:\n  sink: file\n  path: '{}'\n  types:\n    - mcp_governance_decision\n  fail_closed:\n    - mcp_governance_decision\n",
            path.display()
        ),
        None => "events:\n  fail_closed:\n    - mcp_governance_decision\n".to_string(),
    };
    format!(
        r#"
proxy:
  http_bind_port: 0
{events_block}origins:
  "{HOST}":
    authentication:
      type: bearer
      tokens:
        - governance-demo-token
    action:
      type: mcp
      mode: gateway
      server_info:
        name: governed-mcp
        version: "1.0.0"
      sessions:
        enabled: true
        ttl: "30m"
      rbac_policies:
        analyst:
          default_allow: false
          tool_access:
            - principals: []
              allowed:
                - "reports.hello"
                - "crm.hello"
                - "crm.echo"
                - "crm.notes"
                - "legacy.echo"
      tool_versioning:
        lockfile: '{lockfile}'
        mode: block
        block_unlocked: true
      federated_servers:
        - origin: "{upstream_url}"
          prefix: reports
          namespace: always
          rbac: analyst
          timeout: 10s
          status: approved
          egress:
            mode: deny_by_default
            hosts: ["127.0.0.1"]
            allow_private: true
        - origin: "{upstream_url}"
          prefix: crm
          namespace: always
          rbac: analyst
          timeout: 10s
          egress:
            mode: deny_by_default
            hosts: ["127.0.0.1"]
            allow_private: true
        - origin: "{upstream_url}"
          prefix: legacy
          namespace: always
          rbac: analyst
          timeout: 10s
          status: draft
          egress:
            mode: deny_by_default
            hosts: ["127.0.0.1"]
            allow_private: true
        - origin: "{upstream_url}"
          prefix: denied
          namespace: always
          rbac: analyst
          timeout: 10s
          egress:
            mode: deny_by_default
            hosts: []
      argument_policies:
        - name: no-path-traversal-in-message
          when: mcp.tool.name == "crm.echo"
          engine: cel
          source: '!mcp.arguments.message.contains("../")'
          mode: block
        - name: no-path-traversal-in-message-rego
          when: mcp.tool.name == "crm.notes"
          engine: rego
          source: |
            package sbproxy

            default allow := false

            allow if {{
                not contains(input.mcp.arguments.message, "../")
            }}
          mode: block
      flow:
        mode: block
        rule: two_of_three
        trusted_servers: [reports]
        sensitive_servers: [crm]
        outbound_tools: ["reports.*"]
      content_filters:
        secrets: redact
        pii: warn
"#,
        lockfile = lockfile_path.display(),
    )
}

// --- Request helpers ---

fn mint_session(harness: &ProxyHarness) -> String {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "e2e-governance", "version": "1.0.0"}
        }
    });
    let resp = harness
        .post_json("/", HOST, &body, &[AUTH])
        .expect("initialize session");
    assert_eq!(
        resp.status,
        200,
        "initialize must succeed: {:?}",
        resp.text()
    );
    resp.headers
        .get("mcp-session-id")
        .expect("initialize issues a session id")
        .clone()
}

/// Prime the federation catalogue. `resolve_tool` reads a lazily
/// refreshed cache; without a `tools/list` first, every `tools/call`
/// below would short-circuit to "unknown tool" before the gate under
/// test ever ran (mirrors `mcp_rbac_timeout_e2e.rs`'s
/// `prime_tools_list`).
fn prime(harness: &ProxyHarness, session: &str) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let resp = harness
        .post_json("/", HOST, &body, &[AUTH, ("mcp-session-id", session)])
        .expect("tools/list");
    assert_eq!(
        resp.status,
        200,
        "tools/list must succeed: {:?}",
        resp.text()
    );
    resp.json().expect("tools/list response is json")
}

fn call_tool(
    harness: &ProxyHarness,
    session: &str,
    id: i64,
    tool: &str,
    arguments: Value,
) -> Value {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}
    });
    let resp = harness
        .post_json("/", HOST, &body, &[AUTH, ("mcp-session-id", session)])
        .expect("tools/call");
    assert_eq!(
        resp.status,
        200,
        "JSON-RPC responses (including errors) carry HTTP 200: {:?}",
        resp.text()
    );
    resp.json().expect("tools/call response is json")
}

fn error_message(resp: &Value) -> &str {
    resp["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a JSON-RPC error envelope, got: {resp}"))
}

fn tool_names(list_result: &Value) -> Vec<String> {
    list_result["result"]["tools"]
        .as_array()
        .expect("tools/list result carries an array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect()
}

// --- Tests ---

/// A call carrying no `Authorization` header is refused by the bearer
/// auth provider before the MCP action -- and every governance check
/// inside it -- ever runs. The upstream is never dialled.
#[test]
fn unauthenticated_call_is_refused_before_any_governance_check() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("unauth");
    let events = events_path("unauth");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, Some(&events)))
            .expect("start proxy");

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
    });
    let resp = harness
        .post_json("/", HOST, &body, &[])
        .expect("unauthenticated initialize");
    assert_eq!(
        resp.status,
        401,
        "body: {}",
        resp.text().unwrap_or_default()
    );
    assert_eq!(
        upstream.tool_calls(),
        0,
        "an unauthenticated call must never reach the upstream"
    );

    let _ = std::fs::remove_file(&lockfile);
}

/// `reports.echo` is real, on the version lockfile, and served by an
/// approved server, but `analyst`'s `tool_access` never named it.
/// RBAC refuses it before the upstream is contacted.
#[test]
fn ungranted_tool_is_refused_by_rbac() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("rbac");
    let events = events_path("rbac");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, Some(&events)))
            .expect("start proxy");
    let session = mint_session(&harness);
    prime(&harness, &session);
    let before = upstream.tool_calls();

    let resp = call_tool(
        &harness,
        &session,
        10,
        "reports.echo",
        json!({"message": "hi"}),
    );
    let message = error_message(&resp);
    assert!(
        message.contains("denied by RBAC policy"),
        "expected an RBAC denial, got: {message}"
    );
    assert_eq!(
        upstream.tool_calls(),
        before,
        "an RBAC-denied call must never reach the upstream"
    );

    let _ = std::fs::remove_file(&lockfile);
}

/// `crm.hello` is a real, live tool the mock upstream serves, but it
/// has no entry in the lockfile. `block_unlocked: true` blocks it
/// outright -- the escape hatch closing rather than merely reporting.
/// `analyst`'s `allowed` list grants it deliberately: RBAC runs before
/// the version gate, so an ungranted tool would be refused by RBAC
/// first and this test would prove nothing about `block_unlocked`. The
/// grant isolates the version gate as the one deciding refusal here;
/// `ungranted_tool_is_refused_by_rbac` above already covers the RBAC
/// denial this test deliberately routes around.
#[test]
fn unlocked_tool_is_blocked_by_the_version_gate() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("unlocked");
    let events = events_path("unlocked");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, Some(&events)))
            .expect("start proxy");
    let session = mint_session(&harness);
    prime(&harness, &session);
    let before = upstream.tool_calls();

    let resp = call_tool(&harness, &session, 10, "crm.hello", json!({"name": "Ada"}));
    let message = error_message(&resp);
    assert!(
        message.contains("version gate"),
        "expected a version-gate refusal, got: {message}"
    );
    assert_eq!(
        upstream.tool_calls(),
        before,
        "a version-gated call must never reach the upstream"
    );

    let _ = std::fs::remove_file(&lockfile);
}

/// `legacy` is `status: draft`, never approved. Its tools are hidden
/// from `tools/list`, and a call against one is refused naming the
/// draft status rather than pretending the tool does not exist.
#[test]
fn draft_server_tools_are_hidden_and_refused() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("draft");
    let events = events_path("draft");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, Some(&events)))
            .expect("start proxy");
    let session = mint_session(&harness);
    let listed = prime(&harness, &session);

    let names = tool_names(&listed);
    assert!(
        !names.iter().any(|n| n.starts_with("legacy.")),
        "a draft server's tools must be hidden from tools/list, got: {names:?}"
    );

    let before = upstream.tool_calls();
    let resp = call_tool(
        &harness,
        &session,
        10,
        "legacy.echo",
        json!({"message": "hi"}),
    );
    let message = error_message(&resp);
    assert!(
        message.contains("status 'draft'"),
        "expected a draft-status refusal, got: {message}"
    );
    assert_eq!(
        upstream.tool_calls(),
        before,
        "a draft-server call must never reach the upstream"
    );

    let _ = std::fs::remove_file(&lockfile);
}

/// The `denied` federated server's egress policy allows no host at
/// all (`hosts: []` under `deny_by_default`). Its tools never appear
/// in `tools/list`, and the refusal is recorded on
/// `sbproxy_egress_refused_total` under the MCP-upstream purpose --
/// proof the dial itself was refused, not merely that the tool was
/// unknown.
#[test]
fn egress_denied_upstream_is_never_dialed() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("egress");
    let events = events_path("egress");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, Some(&events)))
            .expect("start proxy");
    let session = mint_session(&harness);
    let listed = prime(&harness, &session);

    let names = tool_names(&listed);
    assert!(
        !names.iter().any(|n| n.starts_with("denied.")),
        "an egress-denied server's tools must never be catalogued, got: {names:?}"
    );

    let metrics = harness.get("/metrics", HOST).expect("metrics");
    assert_eq!(metrics.status, 200);
    let body = metrics.text().unwrap_or_default();
    let refused = body.lines().any(|line| {
        line.starts_with("sbproxy_egress_refused_total")
            && line.contains("purpose=\"mcp_upstream\"")
            && line.contains("origin=\"denied\"")
    });
    assert!(
        refused,
        "expected sbproxy_egress_refused_total{{purpose=\"mcp_upstream\",...,origin=\"denied\"}} \
         in metrics, got:\n{body}"
    );

    let _ = std::fs::remove_file(&lockfile);
}

/// `crm.echo`'s message argument contains a path-traversal sequence.
/// The CEL argument policy scoped to it evaluates
/// `mcp.arguments.message` and blocks the call before dispatch.
#[test]
fn argument_policy_cel_blocks_the_injection_shaped_call() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("cel");
    let events = events_path("cel");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, Some(&events)))
            .expect("start proxy");
    let session = mint_session(&harness);
    prime(&harness, &session);
    let before = upstream.tool_calls();

    let resp = call_tool(
        &harness,
        &session,
        10,
        "crm.echo",
        json!({"message": "read ../../etc/passwd"}),
    );
    let message = error_message(&resp);
    assert!(
        message.contains("denied by argument policy 'no-path-traversal-in-message'"),
        "expected the CEL rule to name itself, got: {message}"
    );
    assert_eq!(
        upstream.tool_calls(),
        before,
        "an argument-policy-denied call must never reach the upstream"
    );

    let _ = std::fs::remove_file(&lockfile);
}

/// `crm.notes` is guarded only by the Rego twin of the same
/// predicate. The same injection-shaped message is blocked equally,
/// proving the Rego engine enforces the rule on its own rather than
/// riding along behind the CEL rule above.
#[test]
fn argument_policy_rego_blocks_the_injection_shaped_call() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("rego");
    let events = events_path("rego");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, Some(&events)))
            .expect("start proxy");
    let session = mint_session(&harness);
    prime(&harness, &session);
    let before = upstream.tool_calls();

    let resp = call_tool(
        &harness,
        &session,
        10,
        "crm.notes",
        json!({"message": "read ../../etc/passwd"}),
    );
    let message = error_message(&resp);
    assert!(
        message.contains("denied by argument policy 'no-path-traversal-in-message-rego'"),
        "expected the Rego rule to name itself, got: {message}"
    );
    assert_eq!(
        upstream.tool_calls(),
        before,
        "an argument-policy-denied call must never reach the upstream"
    );

    let _ = std::fs::remove_file(&lockfile);
}

/// Meta's Rule of Two, `rule: two_of_three`. One session reads from
/// `crm` (untrusted, sensitive -- taints the session) and then
/// attempts an outbound call to `reports.*`. The outbound call is
/// refused even though it is the exact call that succeeds on its own
/// in every other test in this file.
#[test]
fn taint_then_outbound_is_refused_by_the_flow_guardrail() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("flow");
    let events = events_path("flow");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, Some(&events)))
            .expect("start proxy");
    let session = mint_session(&harness);
    prime(&harness, &session);

    let tainting_call = call_tool(
        &harness,
        &session,
        10,
        "crm.echo",
        json!({"message": "customer lookup for case 4412"}),
    );
    assert!(
        tainting_call.get("error").is_none(),
        "the tainting call itself must be allowed: {tainting_call}"
    );

    let outbound = call_tool(
        &harness,
        &session,
        11,
        "reports.hello",
        json!({"name": "Ada"}),
    );
    let message = error_message(&outbound);
    assert!(
        message.contains("session-flow guardrail"),
        "expected the flow guardrail to refuse the outbound call, got: {message}"
    );

    let _ = std::fs::remove_file(&lockfile);
}

/// A fake API key planted in a `crm.echo` argument is redacted before
/// the call ever reaches the upstream: the mock's captured argument
/// carries the redacted text, not the secret, and so does the result
/// the caller sees.
#[test]
fn planted_secret_is_redacted_before_dispatch() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("secret");
    let events = events_path("secret");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, Some(&events)))
            .expect("start proxy");
    let session = mint_session(&harness);
    prime(&harness, &session);

    let planted = "my key is sk-FAKEFAKEFAKEFAKEFAKEFAKE, do not share it";
    let resp = call_tool(
        &harness,
        &session,
        10,
        "crm.echo",
        json!({"message": planted}),
    );
    assert!(
        resp.get("error").is_none(),
        "the call itself must dispatch: {resp}"
    );
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("tool result carries text content");
    assert!(
        !text.contains("sk-FAKEFAKEFAKEFAKEFAKEFAKE"),
        "the raw secret must not reach the caller: {text}"
    );
    assert!(
        text.contains("[REDACTED:APIKEY]"),
        "the response must carry the redaction marker: {text}"
    );

    let captured = upstream.captured_tool_call_args();
    assert!(
        captured.iter().any(|args| {
            args["message"].as_str().is_some_and(|m| {
                !m.contains("sk-FAKEFAKEFAKEFAKEFAKEFAKE") && m.contains("[REDACTED:APIKEY]")
            })
        }),
        "the argument the upstream received must already be redacted \
         (content_filters runs before dispatch), got: {captured:?}"
    );

    let _ = std::fs::remove_file(&lockfile);
}

/// Poll the events file until it has at least `min_lines` complete
/// JSON lines, or give up. The delivery worker flushes per drained
/// batch (`event_sink.rs`'s `start_file_worker`), so this is a short
/// wait in practice; the poll only guards against reading the file
/// before that flush lands.
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

/// Every governed decision -- allowed or refused -- carries
/// `sbproxy.evidence.seq`, a per-tenant counter that starts at 1 and
/// never skips. Four decisions of different kinds land on one fresh
/// tenant here (an RBAC deny, an argument-policy deny, a draft-server
/// deny, and a plain allow); their recorded sequence numbers must be
/// exactly `1..=N` with no gaps.
#[test]
fn governance_evidence_carries_a_gapless_per_tenant_sequence() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("evidence");
    let events = events_path("evidence");
    let harness =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, Some(&events)))
            .expect("start proxy");
    let session = mint_session(&harness);
    prime(&harness, &session);

    // RBAC deny.
    let _ = call_tool(
        &harness,
        &session,
        10,
        "reports.echo",
        json!({"message": "hi"}),
    );
    // Argument-policy deny.
    let _ = call_tool(
        &harness,
        &session,
        11,
        "crm.echo",
        json!({"message": "../etc/passwd"}),
    );
    // Draft-server deny.
    let _ = call_tool(
        &harness,
        &session,
        12,
        "legacy.echo",
        json!({"message": "hi"}),
    );
    // Plain allow.
    let allowed = call_tool(
        &harness,
        &session,
        13,
        "reports.hello",
        json!({"name": "Ada"}),
    );
    assert!(
        allowed.get("error").is_none(),
        "the allow leg must dispatch: {allowed}"
    );

    let lines = read_ndjson_lines(&events, 4, Duration::from_secs(10));
    let mut seqs: Vec<u64> = lines
        .iter()
        .filter(|line| line["event_type"] == "mcp_governance_decision")
        .filter_map(|line| line["data"]["sbproxy.evidence.seq"].as_u64())
        .collect();
    seqs.sort_unstable();
    assert!(
        seqs.len() >= 3,
        "expected at least 3 governance-decision records, got {}: {lines:?}",
        seqs.len()
    );
    let expected: Vec<u64> = (1..=seqs.len() as u64).collect();
    assert_eq!(
        seqs, expected,
        "evidence sequence must be gapless starting at 1, got: {seqs:?}"
    );

    let _ = std::fs::remove_file(&lockfile);
    let _ = std::fs::remove_file(&events);
}

/// `events.fail_closed` names `mcp_governance_decision`, but no sink
/// is configured to accept it (`events:` carries `fail_closed` alone,
/// no `sink:`) -- functionally identical to a sink that opened at
/// boot and later became unwritable: nothing can deliver the record.
/// The call that would have produced that record is refused instead
/// of served un-evidenced.
#[test]
fn fail_closed_refuses_the_call_when_the_sink_cannot_accept_the_record() {
    let upstream = MockMcpUpstream::start();
    let lockfile = write_lockfile("failclosed");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.url(), &lockfile, None))
        .expect("start proxy");
    let session = mint_session(&harness);
    prime(&harness, &session);
    let before = upstream.tool_calls();

    // This would ordinarily be an RBAC denial (see
    // `ungranted_tool_is_refused_by_rbac`), but with no sink able to
    // accept the governance record, fail-closed delivery intercepts
    // first and the caller sees the evidence-unavailable refusal
    // instead of the RBAC-specific message.
    let resp = call_tool(
        &harness,
        &session,
        10,
        "reports.echo",
        json!({"message": "hi"}),
    );
    let message = error_message(&resp);
    assert!(
        message.contains("evidence_unavailable"),
        "expected a fail-closed evidence refusal, got: {message}"
    );
    assert_eq!(
        upstream.tool_calls(),
        before,
        "a fail-closed-refused call must never reach the upstream"
    );

    let _ = std::fs::remove_file(&lockfile);
}
