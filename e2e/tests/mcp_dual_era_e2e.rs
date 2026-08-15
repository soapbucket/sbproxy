//! MCP 2025 and 2026 wire-era boundary coverage.
//!
//! The upstream deliberately speaks the established legacy transport. The
//! gateway is responsible for keeping that peer contract isolated from a
//! strict modern caller on the same inbound endpoint.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sbproxy_e2e::{MockUpstream, ProxyHarness, Response};
use sbproxy_extension::mcp::compat::{contract_digest, Lockfile, ToolLock};
use serde_json::{json, Value};

#[derive(Clone, Copy)]
enum MockFlavor {
    Legacy,
    Modern,
    ModernError,
    SecretCallError,
    MissingStructuredContent,
    InvalidStructuredContent,
}

#[derive(Debug, Clone)]
struct CapturedRequest {
    method: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

struct MockState {
    initializes: AtomicUsize,
    discoveries: AtomicUsize,
    tool_calls: AtomicUsize,
    captured: Mutex<Vec<CapturedRequest>>,
    catalog_generation: AtomicUsize,
    call_gate: Mutex<ToolCallGate>,
    call_gate_changed: Condvar,
}

#[derive(Debug, Default)]
struct ToolCallGate {
    block_next: bool,
    blocked: bool,
    released: bool,
}

/// A bounded loopback MCP server with enough fidelity to observe whether the
/// gateway incorrectly dispatches a rejected modern request upstream.
struct MockMcpUpstream {
    port: u16,
    state: Arc<MockState>,
    shutdown: Arc<AtomicBool>,
}

impl MockMcpUpstream {
    fn legacy() -> Self {
        Self::start(MockFlavor::Legacy)
    }

    fn modern() -> Self {
        Self::start(MockFlavor::Modern)
    }

    #[allow(dead_code)]
    fn modern_error() -> Self {
        Self::start(MockFlavor::ModernError)
    }

    fn secret_call_error() -> Self {
        Self::start(MockFlavor::SecretCallError)
    }

    fn missing_structured_content() -> Self {
        Self::start(MockFlavor::MissingStructuredContent)
    }

    fn invalid_structured_content() -> Self {
        Self::start(MockFlavor::InvalidStructuredContent)
    }

    fn start(flavor: MockFlavor) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock MCP upstream");
        let port = listener.local_addr().expect("mock listener address").port();
        let state = Arc::new(MockState {
            initializes: AtomicUsize::new(0),
            discoveries: AtomicUsize::new(0),
            tool_calls: AtomicUsize::new(0),
            captured: Mutex::new(Vec::new()),
            catalog_generation: AtomicUsize::new(0),
            call_gate: Mutex::new(ToolCallGate::default()),
            call_gate_changed: Condvar::new(),
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let state_for_thread = Arc::clone(&state);
        let shutdown_for_thread = Arc::clone(&shutdown);
        thread::spawn(move || {
            for accepted in listener.incoming() {
                if shutdown_for_thread.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = accepted else {
                    continue;
                };
                let state = Arc::clone(&state_for_thread);
                thread::spawn(move || {
                    let _ = handle_upstream_connection(&mut stream, flavor, &state);
                });
            }
        });
        Self {
            port,
            state,
            shutdown,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }

    fn tool_calls(&self) -> usize {
        self.state.tool_calls.load(Ordering::SeqCst)
    }

    fn discoveries(&self) -> usize {
        self.state.discoveries.load(Ordering::SeqCst)
    }

    fn mutate_catalog(&self) {
        self.state.catalog_generation.store(1, Ordering::SeqCst);
    }

    fn block_next_tool_call(&self) {
        let mut gate = self.state.call_gate.lock().expect("tool call gate lock");
        gate.block_next = true;
        gate.blocked = false;
        gate.released = false;
    }

    fn wait_for_blocked_tool_call(&self, timeout: Duration) -> bool {
        let gate = self.state.call_gate.lock().expect("tool call gate lock");
        let (gate, _) = self
            .state
            .call_gate_changed
            .wait_timeout_while(gate, timeout, |gate| !gate.blocked)
            .expect("wait for blocked tool call");
        gate.blocked
    }

    fn release_tool_call(&self) {
        let mut gate = self.state.call_gate.lock().expect("tool call gate lock");
        gate.released = true;
        self.state.call_gate_changed.notify_all();
    }

    fn captured_requests(&self) -> Vec<CapturedRequest> {
        self.state
            .captured
            .lock()
            .expect("captured requests lock")
            .clone()
    }
}

impl Drop for MockMcpUpstream {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_upstream_connection(
    stream: &mut TcpStream,
    flavor: MockFlavor,
    state: &MockState,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = find_double_crlf(&bytes) {
            let content_length = parse_content_length(&bytes[..header_end]).unwrap_or(0);
            if bytes.len() >= header_end + 4 + content_length {
                break;
            }
        }
    }

    let header_end = find_double_crlf(&bytes).unwrap_or(bytes.len());
    let headers = parse_headers(&bytes[..header_end]);
    let body = bytes
        .get(header_end.saturating_add(4)..)
        .and_then(|body| serde_json::from_slice(body).ok())
        .unwrap_or(Value::Null);
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    state
        .captured
        .lock()
        .expect("captured requests lock")
        .push(CapturedRequest {
            method: method.clone(),
            headers,
            body: body.clone(),
        });

    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let response = match method.as_str() {
        "initialize" => {
            state.initializes.fetch_add(1, Ordering::SeqCst);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                    "serverInfo": {"name": "mock", "version": "1.0.0"}
                }
            })
        }
        "tools/list" => {
            state.discoveries.fetch_add(1, Ordering::SeqCst);
            match flavor {
                MockFlavor::ModernError => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32603, "message": "mock modern upstream error"}
                }),
                MockFlavor::Legacy
                | MockFlavor::Modern
                | MockFlavor::SecretCallError
                | MockFlavor::MissingStructuredContent
                | MockFlavor::InvalidStructuredContent => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": complete_tools_in_reverse_order(
                            state.catalog_generation.load(Ordering::SeqCst)
                        )
                    }
                }),
            }
        }
        "resources/list" => {
            state.discoveries.fetch_add(1, Ordering::SeqCst);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"resources": [
                    {"uri": "file:///z-last", "name": "Z last", "description": "second"},
                    {"uri": "file:///a-first", "name": "A first", "description": "first"}
                ]}
            })
        }
        "prompts/list" => {
            state.discoveries.fetch_add(1, Ordering::SeqCst);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"prompts": [
                    {"name": "zeta_prompt", "description": "second"},
                    {"name": "alpha_prompt", "description": "first"}
                ]}
            })
        }
        "tools/call" => {
            state.tool_calls.fetch_add(1, Ordering::SeqCst);
            let call_generation = state.catalog_generation.load(Ordering::SeqCst);
            {
                let mut gate = state.call_gate.lock().expect("tool call gate lock");
                if gate.block_next {
                    gate.block_next = false;
                    gate.blocked = true;
                    state.call_gate_changed.notify_all();
                    while !gate.released {
                        gate = state
                            .call_gate_changed
                            .wait(gate)
                            .expect("wait to release tool call");
                    }
                }
            }
            let result = match flavor {
                MockFlavor::SecretCallError => {
                    return write_upstream_response(
                        stream,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32000,
                                "message": "private-api-key=do-not-reflect"
                            }
                        }),
                    );
                }
                MockFlavor::MissingStructuredContent => json!({
                    "content": [{"type": "text", "text": "missing-structured-leak"}]
                }),
                MockFlavor::InvalidStructuredContent => json!({
                    "content": [{"type": "text", "text": "invalid-structured-leak"}],
                    "structuredContent": "not-an-object"
                }),
                MockFlavor::Legacy | MockFlavor::Modern | MockFlavor::ModernError => json!({
                    "content": [{"type": "text", "text": "ok"}],
                    "structuredContent": {
                        "generation": catalog_generation_name(call_generation),
                        "items": []
                    }
                }),
            };
            json!({"jsonrpc": "2.0", "id": id, "result": result})
        }
        "server/discover" => {
            state.discoveries.fetch_add(1, Ordering::SeqCst);
            json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}})
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": "method not found"}
        }),
    };
    write_upstream_response(stream, &response)
}

fn write_upstream_response(stream: &mut TcpStream, response: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(response).expect("serialize mock response");
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()
}

fn catalog_generation_name(generation: usize) -> &'static str {
    if generation == 0 {
        "old"
    } else {
        "new"
    }
}

fn complete_tools_in_reverse_order(generation: usize) -> Vec<Value> {
    vec![
        complete_tool("zeta", "Zeta", generation),
        json!({
            "name": "search",
            "title": "Search",
            "description": "Search repositories",
            "icons": [{"src": "data:image/png;base64,AA==", "mimeType": "image/png"}],
            "inputSchema": {
                "type": "object",
                "properties": {
                    "region": {"type": "string", "x-mcp-header": "Region"},
                    "limit": {"type": "integer", "minimum": 1}
                },
                "required": ["region", "limit"]
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "generation": {"const": catalog_generation_name(generation)},
                    "items": {"type": "array"}
                },
                "required": ["generation", "items"]
            },
            "annotations": {"readOnlyHint": true, "destructiveHint": false},
            "_meta": {"vendor.example/ui": "search-card"},
            "vendor.example/security": {"audience": "repos"}
        }),
    ]
}

fn complete_tool(name: &str, title: &str, generation: usize) -> Value {
    json!({
        "name": name,
        "title": title,
        "description": format!("{title} tool"),
        "icons": [{"src": "data:image/png;base64,AA==", "mimeType": "image/png"}],
        "inputSchema": {
            "type": "object",
            "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"}
            },
            "required": ["region"]
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "generation": {"const": catalog_generation_name(generation)},
                "items": {"type": "array"}
            },
            "required": ["generation", "items"]
        },
        "annotations": {"readOnlyHint": true},
        "_meta": {"vendor.example/ui": "tool-card"},
        "vendor.example/security": {"audience": "repos"}
    })
}

fn find_double_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

fn parse_headers(headers: &[u8]) -> BTreeMap<String, String> {
    std::str::from_utf8(headers)
        .ok()
        .into_iter()
        .flat_map(str::lines)
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect()
}

fn gateway_yaml(
    origin_key: &str,
    upstream: &MockMcpUpstream,
    sessions: bool,
    refresh_interval: &str,
) -> String {
    let sessions = sessions.then_some(
        r#"
      sessions:
        enabled: true
        ttl: "5m""#,
    );
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "{origin_key}":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: gateway
        version: "1.0.0"
      refresh_interval: "{refresh_interval}"{sessions}
      federated_servers:
        - origin: "{origin}"
          prefix: legacy
"#,
        origin_key = origin_key,
        refresh_interval = refresh_interval,
        sessions = sessions.unwrap_or_default(),
        origin = upstream.url(),
    )
}

fn start_gateway(upstream: &MockMcpUpstream, sessions: bool) -> ProxyHarness {
    ProxyHarness::start_with_yaml(&gateway_yaml("mcp.localhost", upstream, sessions, "1h"))
        .expect("start dual-era gateway")
}

fn start_refreshing_gateway(upstream: &MockMcpUpstream) -> ProxyHarness {
    ProxyHarness::start_with_yaml(&gateway_yaml("mcp.localhost", upstream, false, "1s"))
        .expect("start refreshing dual-era gateway")
}

fn start_wildcard_gateway_without_trust_anchor(upstream: &MockMcpUpstream) -> ProxyHarness {
    ProxyHarness::start_with_yaml(&gateway_yaml("*.localhost", upstream, false, "1h"))
        .expect("start wildcard dual-era gateway")
}

fn start_progressive_gateway(upstream: &MockMcpUpstream) -> ProxyHarness {
    let yaml = gateway_yaml("mcp.localhost", upstream, false, "1h").replacen(
        "      mode: gateway\n",
        "      mode: gateway\n      progressive_discovery: true\n",
        1,
    );
    ProxyHarness::start_with_yaml(&yaml).expect("start progressive dual-era gateway")
}

fn start_gateway_with_allowed_origin(upstream: &MockMcpUpstream) -> ProxyHarness {
    let yaml = gateway_yaml("mcp.localhost", upstream, false, "1h").replacen(
        "      mode: gateway\n",
        r#"      mode: gateway
      modern_http:
        public_origin: "http://mcp.localhost"
        allowed_origins:
          - "https://console.example"
        strict_parameter_headers: true
"#,
        1,
    );
    ProxyHarness::start_with_yaml(&yaml).expect("start allowlisted dual-era gateway")
}

fn start_oauth_gateway_with_trusted_modern_http(upstream: &MockMcpUpstream) -> ProxyHarness {
    let yaml = gateway_yaml("mcp.localhost", upstream, false, "1h").replacen(
        "      mode: gateway\n",
        r#"      mode: gateway
      oauth:
        authorization_servers:
          - "https://issuer.example"
        scopes_supported:
          - "mcp.read"
      modern_http:
        public_origin: "http://mcp.localhost"
"#,
        1,
    );
    ProxyHarness::start_with_yaml(&yaml).expect("start OAuth-protected modern gateway")
}

fn start_forward_auth_gateway(upstream: &MockMcpUpstream, auth: &MockUpstream) -> ProxyHarness {
    let yaml = gateway_yaml("mcp.localhost", upstream, false, "1h").replacen(
        "    action:\n",
        &format!(
            r#"    authentication:
      type: forward_auth
      url: "{}"
      method: GET
      timeout: 5
      success_status: 200
    action:
"#,
            auth.base_url()
        ),
        1,
    );
    ProxyHarness::start_with_yaml(&yaml).expect("start forward-auth modern gateway")
}

fn start_forwarded_https_gateway(upstream: &MockMcpUpstream, trust_loopback: bool) -> ProxyHarness {
    let trusted_proxy = if trust_loopback {
        "127.0.0.1/32"
    } else {
        "192.0.2.0/24"
    };
    let yaml = gateway_yaml("mcp.localhost", upstream, false, "1h")
        .replacen(
            "proxy:\n  http_bind_port: 0\n",
            &format!("proxy:\n  http_bind_port: 0\n  trusted_proxies:\n    - {trusted_proxy}\n"),
            1,
        )
        .replacen(
            "      mode: gateway\n",
            r#"      mode: gateway
      modern_http:
        public_origin: "https://mcp.localhost"
"#,
            1,
        );
    ProxyHarness::start_with_yaml(&yaml).expect("start forwarded-HTTPS modern gateway")
}

fn start_mixed_gateway(legacy: &MockMcpUpstream, modern: &MockMcpUpstream) -> ProxyHarness {
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: gateway
        version: "1.0.0"
      refresh_interval: "1h"
      federated_servers:
        - origin: "{legacy_origin}"
          prefix: zpeer
          namespace: always
        - origin: "{modern_origin}"
          prefix: apeer
          namespace: always
"#,
        legacy_origin = legacy.url(),
        modern_origin = modern.url(),
    );
    ProxyHarness::start_with_yaml(&yaml).expect("start mixed dual-era gateway")
}

fn start_rollout_gateway(upstream: &MockMcpUpstream) -> ProxyHarness {
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: gateway
        version: "1.0.0"
      tool_versioning:
        rollout:
          tools:
            search:
              versions:
                - version: "1.4.0"
                  server: legacy-api
                - version: "2.0.0"
                  server: new-api
      federated_servers:
        - type: openapi
          origin: "{origin}"
          prefix: legacy-api
          spec:
            openapi: "3.0.0"
            info: {{title: Legacy, version: "1.0"}}
            paths:
              "/search":
                get:
                  operationId: search
        - type: openapi
          origin: "{origin}"
          prefix: new-api
          spec:
            openapi: "3.0.0"
            info: {{title: Modern, version: "2.0"}}
            paths:
              "/search":
                get:
                  operationId: search
"#,
        origin = upstream.url(),
    );
    ProxyHarness::start_with_yaml(&yaml).expect("start rollout dual-era gateway")
}

fn write_version_baseline_lockfile() -> String {
    let search = complete_tools_in_reverse_order(0)
        .into_iter()
        .find(|tool| tool["name"] == "search")
        .expect("search baseline contract");
    // The version gate digests the same three-field projection it always has
    // (`name`, `description`, `inputSchema`), not the complete advertised
    // document, so a baseline built from the full tool would never match the
    // live digest and every run would open with `search` already blocked.
    let gate_contract = json!({
        "name": search["name"],
        "description": search["description"],
        "inputSchema": search["inputSchema"],
    });
    let mut tools = BTreeMap::new();
    tools.insert(
        "search".to_string(),
        ToolLock {
            semver: "1.0.0".parse().expect("baseline semver"),
            contract_digest: contract_digest(&gate_contract),
            contract: Some(search),
        },
    );
    let lockfile = Lockfile {
        version: 1,
        generated_for: "mcp.localhost".to_string(),
        tools,
    };
    let path = std::env::temp_dir().join(format!(
        "sbproxy-modern-version-block-{}.lock.yaml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        lockfile.to_yaml().expect("serialize baseline lockfile"),
    )
    .expect("write baseline lockfile");
    path.to_string_lossy().into_owned()
}

fn start_version_blocking_gateway(upstream: &MockMcpUpstream, lockfile: &str) -> ProxyHarness {
    let yaml = gateway_yaml("mcp.localhost", upstream, false, "1s").replacen(
        "      federated_servers:\n",
        &format!(
            r#"      tool_versioning:
        lockfile: "{lockfile}"
        mode: block
      federated_servers:
"#
        ),
        1,
    );
    ProxyHarness::start_with_yaml(&yaml).expect("start version-blocking dual-era gateway")
}

fn modern_request(method: &str, params: Value) -> Value {
    let mut params = params
        .as_object()
        .cloned()
        .expect("modern test parameters are objects");
    params.insert(
        "_meta".to_string(),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "e2e-client", "version": "1.0.0"},
            "io.modelcontextprotocol/clientCapabilities": {}
        }),
    );
    json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
}

fn modern_headers(method: &str, name: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "Accept".to_string(),
            "application/json, text/event-stream".to_string(),
        ),
        ("Mcp-Protocol-Version".to_string(), "2026-07-28".to_string()),
        ("Mcp-Method".to_string(), method.to_string()),
    ];
    if let Some(name) = name {
        headers.push(("Mcp-Name".to_string(), name.to_string()));
    }
    headers
}

/// Construct one strict-modern request. Caller headers replace the generated
/// carrier with the same name case-insensitively, rather than appending a
/// duplicate that would test a different protocol failure.
fn modern_rpc(
    harness: &ProxyHarness,
    method: &str,
    params: Value,
    caller_headers: &[(&str, &str)],
) -> Response {
    let name = params.get("name").and_then(Value::as_str);
    let mut headers = modern_headers(method, name);
    for (name, value) in caller_headers {
        if let Some(existing) = headers
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
        {
            *existing = ((*name).to_string(), (*value).to_string());
        } else {
            headers.push(((*name).to_string(), (*value).to_string()));
        }
    }
    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    harness
        .post_json(
            "/",
            "mcp.localhost",
            &modern_request(method, params),
            &header_refs,
        )
        .expect("post modern MCP request")
}

type RawHeader = (Vec<u8>, Vec<u8>);

#[derive(Debug)]
struct RawHttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl RawHttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("raw gateway response JSON")
    }
}

fn raw_header(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> RawHeader {
    (name.as_ref().to_vec(), value.as_ref().to_vec())
}

fn modern_wire_headers(method: &str, name: Option<&str>) -> Vec<RawHeader> {
    let mut headers = vec![
        raw_header("Host", "mcp.localhost"),
        raw_header("Content-Type", "application/json"),
        raw_header("Accept", "application/json, text/event-stream"),
        raw_header("Mcp-Protocol-Version", "2026-07-28"),
        raw_header("Mcp-Method", method),
    ];
    if let Some(name) = name {
        headers.push(raw_header("Mcp-Name", name));
    }
    headers
}

fn base_json_headers() -> Vec<RawHeader> {
    vec![
        raw_header("Host", "mcp.localhost"),
        raw_header("Content-Type", "application/json"),
        raw_header("Accept", "application/json, text/event-stream"),
    ]
}

fn replace_raw_header(headers: &mut [RawHeader], name: &[u8], value: impl AsRef<[u8]>) {
    let (_, existing) = headers
        .iter_mut()
        .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
        .expect("replace existing raw header");
    *existing = value.as_ref().to_vec();
}

fn remove_raw_header(headers: &mut Vec<RawHeader>, name: &[u8]) {
    headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
}

fn modern_wire_body(method: &str, id_json: Option<&str>, params_members: &str) -> Vec<u8> {
    let id = id_json.map_or_else(String::new, |id| format!(r#","id":{id}"#));
    let separator = if params_members.is_empty() { "" } else { "," };
    format!(
        r#"{{"jsonrpc":"2.0"{id},"method":"{method}","params":{{{params_members}{separator}"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{{"name":"e2e-client","version":"1.0.0"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#
    )
    .into_bytes()
}

fn raw_http_request(
    port: u16,
    method: &str,
    target: &str,
    headers: &[RawHeader],
    body: &[u8],
) -> RawHttpResponse {
    let mut request = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
    for (name, value) in headers {
        request.extend_from_slice(name);
        request.extend_from_slice(b": ");
        request.extend_from_slice(value);
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    request.extend_from_slice(b"Connection: close\r\n\r\n");
    request.extend_from_slice(body);

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to gateway");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set gateway read timeout");
    stream.write_all(&request).expect("write gateway request");
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => output.extend_from_slice(&buffer[..read]),
            Err(_) => break,
        }
    }
    let header_end = find_double_crlf(&output).expect("raw gateway response headers");
    let header_bytes = &output[..header_end];
    let status = String::from_utf8_lossy(header_bytes)
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .expect("raw gateway response status");
    RawHttpResponse {
        status,
        headers: parse_headers(header_bytes),
        body: output[header_end + 4..].to_vec(),
    }
}

fn raw_modern_request(port: u16, method: &str, path: &str, session_id: &str) -> RawHttpResponse {
    let mut headers = modern_wire_headers("tools/list", None);
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case(b"content-type"));
    if !session_id.is_empty() {
        headers.push(raw_header("Mcp-Session-Id", session_id));
    }
    raw_http_request(port, method, path, &headers, b"")
}

fn raw_modern_post(port: u16, headers: Vec<RawHeader>, body: impl AsRef<[u8]>) -> RawHttpResponse {
    raw_http_request(port, "POST", "/", &headers, body.as_ref())
}

fn assert_jsonrpc_error(response: &RawHttpResponse, status: u16, code: i64) -> Value {
    assert_eq!(response.status, status, "raw response: {response:?}");
    let body = response.json();
    assert_eq!(body["error"]["code"], code, "raw response: {response:?}");
    body
}

fn assert_id_absent(body: &Value) {
    assert!(
        !body
            .as_object()
            .expect("JSON-RPC response object")
            .contains_key("id"),
        "response must omit id: {body}"
    );
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

fn assert_sorted_by(entries: &Value, field: &str) {
    let values: Vec<&str> = entries
        .as_array()
        .expect("catalogue is an array")
        .iter()
        .map(|entry| entry[field].as_str().expect("catalogue key is a string"))
        .collect();
    let mut sorted = values.clone();
    sorted.sort_unstable();
    assert_eq!(
        values, sorted,
        "{field} catalogue order must be deterministic"
    );
}

#[test]
fn legacy_and_modern_requests_are_isolated_on_one_endpoint() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, true);

    let legacy = harness
        .post_json(
            "/",
            "mcp.localhost",
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
            }),
            &[],
        )
        .expect("initialize legacy session");
    assert_eq!(legacy.status, 200);
    assert!(legacy.headers.contains_key("mcp-session-id"));

    let discover = modern_rpc(&harness, "server/discover", json!({}), &[]);
    assert_eq!(discover.status, 200);
    let body: Value = serde_json::from_slice(&discover.body).expect("modern discover JSON");
    assert_eq!(body["result"]["resultType"], "complete");
    assert_eq!(
        body["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    assert!(!discover.headers.contains_key("mcp-session-id"));

    let list = modern_rpc(&harness, "tools/list", json!({}), &[]);
    assert_eq!(list.status, 200);
    let body: Value = serde_json::from_slice(&list.body).expect("modern tools JSON");
    assert_eq!(body["result"]["ttlMs"], 0);
    assert_eq!(body["result"]["tools"][0]["title"], "Search");
    assert_eq!(
        body["result"]["tools"][0]["icons"][0]["mimeType"],
        "image/png"
    );
    assert_eq!(body["result"]["tools"][0]["outputSchema"]["type"], "object");
    assert_eq!(
        body["result"]["tools"][0]["annotations"]["readOnlyHint"],
        true
    );
    assert_eq!(
        body["result"]["tools"][0]["_meta"]["vendor.example/ui"],
        "search-card"
    );
    assert_eq!(
        body["result"]["tools"][0]["vendor.example/security"]["audience"],
        "repos"
    );
}

#[test]
fn modern_request_never_enters_legacy_session_or_stream_paths() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, true);
    let init = harness
        .post_json(
            "/",
            "mcp.localhost",
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
            }),
            &[],
        )
        .expect("initialize legacy session");
    let session_id = init
        .headers
        .get("mcp-session-id")
        .expect("legacy initialize issues a session")
        .to_string();

    let list = modern_rpc(
        &harness,
        "tools/list",
        json!({}),
        &[("mCp-SeSsIoN-Id", session_id.as_str())],
    );
    assert_eq!(list.status, 200);
    assert!(!list.headers.contains_key("mcp-session-id"));

    let get = raw_modern_request(harness.port(), "GET", "/", &session_id);
    assert_eq!(get.status, 405, "modern GET response: {get:?}");
    let delete = raw_modern_request(harness.port(), "DELETE", "/", &session_id);
    assert_eq!(delete.status, 405, "modern DELETE response: {delete:?}");

    let legacy_list = harness
        .post_json(
            "/",
            "mcp.localhost",
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            &[("Mcp-Session-Id", session_id.as_str())],
        )
        .expect("reuse legacy session after modern requests");
    assert_eq!(legacy_list.status, 200);
}

#[test]
fn modern_custom_header_mismatch_fails_before_upstream_dispatch() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let before = upstream.tool_calls();
    let response = modern_rpc(
        &harness,
        "tools/call",
        json!({"name": "search", "arguments": {"region": "us-west1"}}),
        &[("Mcp-Name", "search"), ("Mcp-Param-Region", "eu-west1")],
    );
    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_slice(&response.body).expect("modern error JSON");
    assert_eq!(body["error"]["code"], -32020);
    assert_eq!(upstream.tool_calls(), before);

    let captured = upstream.captured_requests();
    assert!(captured
        .iter()
        .all(|request| request.method != "tools/call"));
    assert!(captured.iter().all(|request| {
        request.headers.contains_key("content-type") && request.body.is_object()
    }));
}

#[test]
fn modern_catalogues_are_deterministic_and_unimplemented_methods_are_404() {
    let legacy = MockMcpUpstream::legacy();
    let modern = MockMcpUpstream::modern();
    let harness = start_mixed_gateway(&legacy, &modern);

    let tools = modern_rpc(&harness, "tools/list", json!({}), &[]);
    assert_eq!(tools.status, 200);
    let tools: Value = serde_json::from_slice(&tools.body).expect("modern tools JSON");
    assert_sorted_by(&tools["result"]["tools"], "name");

    let resources = modern_rpc(&harness, "resources/list", json!({}), &[]);
    assert_eq!(resources.status, 200);
    let resources: Value = serde_json::from_slice(&resources.body).expect("modern resources JSON");
    assert_sorted_by(&resources["result"]["resources"], "uri");

    let prompts = modern_rpc(&harness, "prompts/list", json!({}), &[]);
    assert_eq!(prompts.status, 200);
    let prompts: Value = serde_json::from_slice(&prompts.body).expect("modern prompts JSON");
    assert_sorted_by(&prompts["result"]["prompts"], "name");

    for method in [
        "initialize",
        "ping",
        "subscriptions/listen",
        "unknown/method",
    ] {
        let response = modern_rpc(&harness, method, json!({}), &[]);
        assert_eq!(response.status, 404, "{method}");
        let body: Value = serde_json::from_slice(&response.body).expect("modern error JSON");
        assert_eq!(body["error"]["code"], -32601, "{method}");
    }

    let legacy_ping = harness
        .post_json(
            "/",
            "mcp.localhost",
            &json!({"jsonrpc": "2.0", "id": 8, "method": "ping"}),
            &[],
        )
        .expect("legacy ping");
    assert_eq!(legacy_ping.status, 200);
    let body: Value = serde_json::from_slice(&legacy_ping.body).expect("legacy ping JSON");
    assert_eq!(body["result"], "pong");
}

#[test]
fn modern_catalogue_skips_progressive_meta_tools_and_keeps_direct_contracts() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_progressive_gateway(&upstream);

    let response = modern_rpc(&harness, "tools/list", json!({}), &[]);

    assert_eq!(response.status, 200);
    let body: Value =
        serde_json::from_slice(&response.body).expect("modern progressive tools JSON");
    let tools = body["result"]["tools"]
        .as_array()
        .expect("modern tools array");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(names.contains(&"search"), "direct search contract missing");
    assert!(names.contains(&"zeta"), "direct zeta contract missing");
    assert!(
        !names.contains(&"execute"),
        "legacy execute meta-tool leaked"
    );
    let search = tools
        .iter()
        .find(|tool| tool["name"] == "search")
        .expect("direct search contract");
    assert_eq!(search["title"], "Search");
    assert_eq!(
        search["inputSchema"]["properties"]["limit"]["type"],
        "integer"
    );
    assert_eq!(
        search["outputSchema"]["required"],
        json!(["generation", "items"])
    );
    assert_eq!(search["_meta"]["vendor.example/ui"], "search-card");
    assert_eq!(search["vendor.example/security"]["audience"], "repos");
}

#[test]
fn modern_catalogue_and_calls_exclude_rollout_managed_names() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_rollout_gateway(&upstream);

    let response = modern_rpc(&harness, "tools/list", json!({}), &[]);
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body).expect("modern rollout tools JSON");
    let names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .expect("modern rollout tools array")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for managed in ["search", "search_v1", "search_v2"] {
        assert!(
            !names.contains(&managed),
            "rollout-managed {managed} leaked into modern list: {names:?}"
        );
    }

    let captured_before = upstream.captured_requests().len();
    for managed in ["search", "search_v1", "search_v2"] {
        let response = modern_rpc(
            &harness,
            "tools/call",
            json!({"name": managed, "arguments": {}}),
            &[],
        );
        assert_ne!(response.status, 200, "managed modern call {managed}");
        let body: Value =
            serde_json::from_slice(&response.body).expect("managed modern call error JSON");
        assert!(
            body["error"].is_object(),
            "managed modern call must fail: {body}"
        );
    }
    assert_eq!(
        upstream.captured_requests().len(),
        captured_before,
        "modern rollout names must fail before adapter or upstream dispatch"
    );
}

#[test]
fn modern_catalogue_and_calls_use_the_matching_version_block_verdict() {
    let upstream = MockMcpUpstream::legacy();
    let lockfile = write_version_baseline_lockfile();
    let harness = start_version_blocking_gateway(&upstream, &lockfile);

    let initial = modern_rpc(&harness, "tools/list", json!({}), &[]);
    assert_eq!(initial.status, 200);
    let initial: Value =
        serde_json::from_slice(&initial.body).expect("initial versioned tools JSON");
    assert!(initial["result"]["tools"]
        .as_array()
        .expect("initial versioned tools")
        .iter()
        .any(|tool| tool["name"] == "search"));

    upstream.mutate_catalog();
    let blocked = wait_until(Duration::from_secs(10), || {
        let response = modern_rpc(&harness, "tools/list", json!({}), &[]);
        if response.status != 200 {
            return false;
        }
        let Ok(body) = serde_json::from_slice::<Value>(&response.body) else {
            return false;
        };
        body["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.iter().any(|tool| tool["name"] == "search"))
    });
    assert!(
        blocked,
        "version-blocked search remained in modern tools/list"
    );

    let before = upstream.tool_calls();
    let response = modern_rpc(
        &harness,
        "tools/call",
        json!({
            "name": "search",
            "arguments": {"region": "us-west1", "limit": 1}
        }),
        &[("Mcp-Param-Region", "us-west1")],
    );
    let body: Value = serde_json::from_slice(&response.body).expect("version-block error JSON");
    assert!(
        body["error"].is_object(),
        "blocked modern call succeeded: {body}"
    );
    assert_eq!(upstream.tool_calls(), before);

    let _ = std::fs::remove_file(lockfile);
}

#[test]
fn modern_same_origin_is_accepted_against_the_compiled_authority() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("tools/list", Some("41"), "");
    let mut headers = modern_wire_headers("tools/list", None);
    headers.push(raw_header("Origin", "http://mcp.localhost"));

    let response = raw_modern_post(harness.port(), headers, body);

    assert_eq!(response.status, 200, "same-origin response: {response:?}");
    assert_eq!(response.json()["id"], 41);
}

#[test]
fn modern_explicitly_allowlisted_cross_origin_is_accepted() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway_with_allowed_origin(&upstream);
    let body = modern_wire_body("tools/list", Some("410"), "");
    let mut headers = modern_wire_headers("tools/list", None);
    headers.push(raw_header("Origin", "https://console.example"));

    let response = raw_modern_post(harness.port(), headers, body);

    assert_eq!(response.status, 200, "allowlisted Origin: {response:?}");
    assert_eq!(response.json()["id"], 410);
}

#[test]
fn modern_strict_parameter_headers_reject_unknown_projection_names() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway_with_allowed_origin(&upstream);
    let body = modern_wire_body("tools/list", Some("409"), "");
    let mut headers = modern_wire_headers("tools/list", None);
    headers.push(raw_header("Mcp-Param-Vendor", "opaque"));

    let response = raw_modern_post(harness.port(), headers, body);

    let error = assert_jsonrpc_error(&response, 400, -32020);
    assert_eq!(error["id"], 409);
    assert!(upstream.captured_requests().is_empty());
}

#[test]
fn modern_origin_and_authority_compare_effective_ports() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("tools/list", Some("411"), "");
    let mut default_port = modern_wire_headers("tools/list", None);
    replace_raw_header(&mut default_port, b"host", "mcp.localhost:80");
    default_port.push(raw_header("Origin", "http://mcp.localhost:80"));

    let response = raw_modern_post(harness.port(), default_port, &body);
    assert_eq!(response.status, 200, "effective default port: {response:?}");

    let mut wrong_port = modern_wire_headers("tools/list", None);
    replace_raw_header(&mut wrong_port, b"host", "mcp.localhost:81");
    wrong_port.push(raw_header("Origin", "http://mcp.localhost:81"));
    let response = raw_modern_post(harness.port(), wrong_port, body);
    assert_eq!(response.status, 421);
    assert!(response.body.is_empty());
}

#[test]
fn modern_disallowed_origin_is_403_empty_before_priming() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("tools/list", Some("42"), "");
    let mut headers = modern_wire_headers("tools/list", None);
    headers.push(raw_header("Origin", "https://evil.example"));

    let response = raw_modern_post(harness.port(), headers, body);

    assert_eq!(response.status, 403);
    assert!(
        response.body.is_empty(),
        "Origin rejection body: {response:?}"
    );
    assert!(
        upstream.captured_requests().is_empty(),
        "Origin rejection must not prime or dispatch"
    );
}

#[test]
fn modern_disallowed_origin_is_403_empty_before_oauth_challenge_and_federation_priming() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_oauth_gateway_with_trusted_modern_http(&upstream);
    let body = modern_wire_body("tools/list", Some("420"), "");
    let mut rejected_headers = modern_wire_headers("tools/list", None);
    rejected_headers.push(raw_header("Origin", "https://evil.example"));

    let rejected = raw_modern_post(harness.port(), rejected_headers, &body);

    assert_eq!(rejected.status, 403, "Origin rejection: {rejected:?}");
    assert!(rejected.body.is_empty(), "Origin rejection: {rejected:?}");
    assert!(
        !rejected.headers.contains_key("www-authenticate"),
        "Origin rejection must precede the OAuth challenge: {rejected:?}"
    );
    assert!(
        upstream.captured_requests().is_empty(),
        "Origin rejection must precede federation priming"
    );

    let mut same_origin_headers = modern_wire_headers("tools/list", None);
    same_origin_headers.push(raw_header("Origin", "http://mcp.localhost"));
    let challenge = raw_modern_post(harness.port(), same_origin_headers, body);

    assert_eq!(challenge.status, 401, "OAuth control: {challenge:?}");
    assert!(challenge.body.is_empty(), "OAuth control: {challenge:?}");
    assert!(
        challenge
            .headers
            .get("www-authenticate")
            .is_some_and(|value| value.starts_with("Bearer ")
                && value.contains("/.well-known/oauth-protected-resource")),
        "trusted same-origin request must reach the configured OAuth challenge: {challenge:?}"
    );
    assert!(
        upstream.captured_requests().is_empty(),
        "OAuth challenge must not prime federation"
    );
}

#[test]
fn body_selected_modern_origin_rejection_precedes_forward_auth_and_priming() {
    let upstream = MockMcpUpstream::legacy();
    let auth = MockUpstream::start(json!({"ok": true})).expect("start forward-auth fixture");
    let harness = start_forward_auth_gateway(&upstream, &auth);
    let auth_before = auth.captured().len();
    let discoveries_before = upstream.discoveries();
    let body = modern_wire_body("tools/list", Some("422"), "");
    let mut headers = base_json_headers();
    headers.push(raw_header("Origin", "https://evil.example"));

    let response = raw_modern_post(harness.port(), headers, body);

    assert_eq!(response.status, 403, "Origin rejection: {response:?}");
    assert!(response.body.is_empty(), "Origin rejection: {response:?}");
    assert!(
        !response.headers.contains_key("www-authenticate"),
        "transport trust must run before every authentication challenge: {response:?}"
    );
    assert_eq!(
        auth.captured().len(),
        auth_before,
        "a body-only modern marker must be classified before forward auth"
    );
    assert_eq!(
        upstream.discoveries(),
        discoveries_before,
        "transport rejection must not prime federation"
    );
}

#[test]
fn header_selected_modern_well_known_rejection_precedes_catalog_priming() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let mut headers = modern_wire_headers("tools/list", None);
    remove_raw_header(&mut headers, b"content-type");
    headers.push(raw_header("Origin", "https://evil.example"));

    let response = raw_http_request(
        harness.port(),
        "GET",
        "/.well-known/mcp/codemode.ts",
        &headers,
        &[],
    );

    assert_eq!(response.status, 403, "well-known rejection: {response:?}");
    assert!(
        response.body.is_empty(),
        "well-known rejection: {response:?}"
    );
    assert!(
        upstream.captured_requests().is_empty(),
        "modern transport trust must precede well-known catalogue priming"
    );
}

#[test]
fn modern_transport_scheme_uses_only_trust_bounded_forwarded_tls() {
    for (trust_loopback, expected_status) in [(true, 200), (false, 421)] {
        let upstream = MockMcpUpstream::legacy();
        let harness = start_forwarded_https_gateway(&upstream, trust_loopback);
        let body = modern_wire_body("tools/list", Some("423"), "");
        let mut headers = modern_wire_headers("tools/list", None);
        headers.push(raw_header("Origin", "https://mcp.localhost"));
        headers.push(raw_header("X-Forwarded-Proto", "https"));

        let response = raw_modern_post(harness.port(), headers, body);

        assert_eq!(
            response.status, expected_status,
            "trusted_proxy={trust_loopback}: {response:?}"
        );
        if expected_status == 421 {
            assert!(response.body.is_empty(), "untrusted XFP: {response:?}");
        }
    }
}

#[test]
fn mcp_manifest_uses_only_trust_bounded_forwarded_tls() {
    for (trust_loopback, expected_scheme) in [(true, "https"), (false, "http")] {
        let upstream = MockMcpUpstream::legacy();
        let harness = start_forwarded_https_gateway(&upstream, trust_loopback);
        let headers = vec![
            raw_header("Host", "mcp.localhost"),
            raw_header("X-Forwarded-Proto", "https"),
        ];

        let response = raw_http_request(
            harness.port(),
            "GET",
            "/.well-known/mcp-server",
            &headers,
            &[],
        );

        assert_eq!(response.status, 200, "manifest response: {response:?}");
        assert_eq!(
            response.json()["endpoint"],
            format!("{expected_scheme}://mcp.localhost/"),
            "trusted_proxy={trust_loopback}"
        );
    }
}

#[test]
fn modern_malformed_or_non_http_origins_are_403_empty() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("tools/list", Some("421"), "");

    for origin in [
        "null",
        "ftp://mcp.localhost",
        "http://user@mcp.localhost",
        "http://mcp.localhost/path",
        "not an origin",
    ] {
        let mut headers = modern_wire_headers("tools/list", None);
        headers.push(raw_header("Origin", origin));
        let response = raw_modern_post(harness.port(), headers, &body);
        assert_eq!(response.status, 403, "Origin {origin:?}: {response:?}");
        assert!(response.body.is_empty(), "Origin {origin:?}");
    }
    assert!(upstream.captured_requests().is_empty());
}

#[test]
fn modern_get_validates_origin_before_method_not_allowed() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let mut headers = modern_wire_headers("tools/list", None);
    remove_raw_header(&mut headers, b"content-type");
    headers.push(raw_header("Origin", "https://evil.example"));

    let response = raw_http_request(harness.port(), "GET", "/", &headers, b"");

    assert_eq!(response.status, 403);
    assert!(response.body.is_empty());
    assert!(upstream.captured_requests().is_empty());
}

#[test]
fn modern_duplicate_origin_is_403_empty() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("tools/list", Some("43"), "");
    let mut headers = modern_wire_headers("tools/list", None);
    headers.push(raw_header("Origin", "http://mcp.localhost"));
    headers.push(raw_header("oRiGiN", "https://evil.example"));

    let response = raw_modern_post(harness.port(), headers, body);

    assert_eq!(response.status, 403);
    assert!(response.body.is_empty());
    assert!(upstream.captured_requests().is_empty());
}

#[test]
fn modern_duplicate_host_is_421_empty() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("tools/list", Some("44"), "");
    let mut headers = modern_wire_headers("tools/list", None);
    headers.push(raw_header("hOsT", "evil.example"));

    let response = raw_modern_post(harness.port(), headers, body);

    assert_eq!(response.status, 421);
    assert!(response.body.is_empty());
    assert!(upstream.captured_requests().is_empty());
}

#[test]
fn modern_absolute_target_and_host_conflict_is_421_empty() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("tools/list", Some("45"), "");
    let mut headers = modern_wire_headers("tools/list", None);
    headers.push(raw_header("Origin", "http://evil.example"));

    let response = raw_http_request(
        harness.port(),
        "POST",
        "http://evil.example/",
        &headers,
        &body,
    );

    assert_eq!(response.status, 421);
    assert!(response.body.is_empty());
    assert!(upstream.captured_requests().is_empty());
}

#[test]
fn modern_wildcard_route_without_trusted_authority_is_421_empty() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_wildcard_gateway_without_trust_anchor(&upstream);
    let body = modern_wire_body("tools/list", Some("46"), "");
    let mut headers = modern_wire_headers("tools/list", None);
    replace_raw_header(&mut headers, b"host", "tenant.localhost");

    let response = raw_modern_post(harness.port(), headers, body);

    assert_eq!(response.status, 421);
    assert!(response.body.is_empty());
    assert!(upstream.captured_requests().is_empty());
}

#[test]
fn every_reserved_marker_independently_prevents_legacy_downgrade() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, true);
    let marker_free_body = br#"{"jsonrpc":"2.0","id":51,"method":"tools/list","params":{}}"#;

    let mut method_only = base_json_headers();
    method_only.push(raw_header("Mcp-Method", "tools/list"));
    let mut name_only = base_json_headers();
    name_only.push(raw_header("Mcp-Name", "search"));
    let mut param_only = base_json_headers();
    param_only.push(raw_header("Mcp-Param-Region", "us-west1"));
    let mut version_only = base_json_headers();
    version_only.push(raw_header("Mcp-Protocol-Version", "1900-01-01"));

    let cases = [
        ("Mcp-Method", method_only, marker_free_body.as_slice()),
        ("Mcp-Name", name_only, marker_free_body.as_slice()),
        ("Mcp-Param", param_only, marker_free_body.as_slice()),
        ("modern version", version_only, marker_free_body.as_slice()),
    ];
    for (name, headers, body) in cases {
        let response = raw_modern_post(harness.port(), headers, body);
        assert_eq!(response.status, 400, "{name}: {response:?}");
        assert!(
            !response.headers.contains_key("mcp-session-id"),
            "{name} entered legacy session handling"
        );
    }

    let body_markers = [
        (
            "metadata only",
            br#"{"jsonrpc":"2.0","id":52,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#.as_slice(),
        ),
        (
            "escaped metadata key",
            br#"{"jsonrpc":"2.0","id":53,"method":"tools/list","params":{"_meta":{"\u0069o.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#.as_slice(),
        ),
        (
            "malformed metadata value",
            br#"{"jsonrpc":"2.0","id":54,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":null}}}"#.as_slice(),
        ),
    ];
    for (name, body) in body_markers {
        let response = raw_modern_post(harness.port(), base_json_headers(), body);
        assert_eq!(response.status, 400, "{name}: {response:?}");
        assert!(
            !response.headers.contains_key("mcp-session-id"),
            "{name} entered legacy session handling"
        );
    }
}

#[test]
fn namespaced_metadata_nested_inside_arguments_does_not_select_modern() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = br#"{"jsonrpc":"2.0","id":56,"method":"ping","params":{"arguments":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}}"#;

    let response = raw_modern_post(harness.port(), base_json_headers(), body);

    assert_eq!(response.status, 200);
    let response = response.json();
    assert_eq!(response["id"], 56);
    assert_eq!(response["result"], "pong");
}

#[test]
fn malformed_protocol_headers_select_modern_and_are_rejected() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, true);
    let body = modern_wire_body("tools/list", Some("55"), "");
    for (name, value) in [("empty", Vec::new()), ("non-UTF-8", vec![0xff])] {
        let mut headers = modern_wire_headers("tools/list", None);
        replace_raw_header(&mut headers, b"mcp-protocol-version", value);

        let response = raw_modern_post(harness.port(), headers, &body);

        let error = assert_jsonrpc_error(&response, 400, -32022);
        assert_eq!(error["id"], 55, "{name}");
        assert!(
            !response.headers.contains_key("mcp-session-id"),
            "{name} header entered legacy handling"
        );
    }
}

#[test]
fn modern_duplicate_protected_json_members_are_invalid_request() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let headers = modern_wire_headers("tools/call", Some("search"));
    let valid = String::from_utf8(modern_wire_body(
        "tools/call",
        Some("61"),
        r#""name":"search","arguments":{"region":"us-west1","limit":1}"#,
    ))
    .expect("valid modern request text");

    let cases = [
        (
            "duplicate jsonrpc",
            valid.replacen(
                r#""jsonrpc":"2.0"#,
                r#""jsonrpc":"2.0","jsonrpc":"2.0"#,
                1,
            ),
            Some(61),
        ),
        (
            "duplicate request id",
            valid.replacen(r#""id":61"#, r#""id":61,"id":62"#, 1),
            None,
        ),
        (
            "escaped-equivalent request method",
            valid.replacen(
                r#""method":"tools/call"#,
                r#""method":"tools/call","\u006dethod":"tools/list"#,
                1,
            ),
            Some(61),
        ),
        (
            "duplicate request params",
            valid.replacen(r#""params":{"# , r#""params":{},"params":{"#, 1),
            Some(61),
        ),
        (
            "duplicate routing name",
            valid.replacen(
                r#""name":"search"#,
                r#""name":"search","name":"zeta"#,
                1,
            ),
            Some(61),
        ),
        (
            "duplicate routing arguments",
            valid.replacen(
                r#""arguments":{"region":"us-west1","limit":1}"#,
                r#""arguments":{},"arguments":{"region":"us-west1","limit":1}"#,
                1,
            ),
            Some(61),
        ),
        (
            "duplicate params metadata",
            valid.replacen(
                r#""_meta":{"io.modelcontextprotocol/protocolVersion"#,
                r#""_meta":{},"_meta":{"io.modelcontextprotocol/protocolVersion"#,
                1,
            ),
            Some(61),
        ),
        (
            "escaped-equivalent reserved metadata",
            valid.replacen(
                r#""io.modelcontextprotocol/protocolVersion":"2026-07-28"#,
                r#""io.modelcontextprotocol/protocolVersion":"2026-07-28","\u0069o.modelcontextprotocol/protocolVersion":"2026-07-28"#,
                1,
            ),
            Some(61),
        ),
    ];

    for (name, body, expected_id) in cases {
        let before = upstream.tool_calls();
        let response = raw_modern_post(harness.port(), headers.clone(), body);
        let error = assert_jsonrpc_error(&response, 400, -32600);
        if let Some(expected_id) = expected_id {
            assert_eq!(error["id"], expected_id, "{name}");
        } else {
            assert_id_absent(&error);
        }
        assert_eq!(upstream.tool_calls(), before, "{name} reached upstream");
    }
}

#[test]
fn modern_duplicate_cursor_is_rejected_before_catalogue_resolution() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body(
        "tools/list",
        Some("63"),
        r#""cursor":"first","cursor":"second""#,
    );

    let response = raw_modern_post(
        harness.port(),
        modern_wire_headers("tools/list", None),
        body,
    );

    let error = assert_jsonrpc_error(&response, 400, -32600);
    assert_eq!(error["id"], 63);
    assert!(upstream.captured_requests().is_empty());
}

#[test]
fn modern_duplicate_single_valued_routing_headers_are_header_mismatch() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body(
        "tools/call",
        Some("64"),
        r#""name":"search","arguments":{"region":"us-west1","limit":1}"#,
    );
    let duplicates = [
        ("Content-Type", "application/json"),
        ("Mcp-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "search"),
        ("Mcp-Param-Region", "us-west1"),
    ];

    for (name, value) in duplicates {
        let before = upstream.tool_calls();
        let mut headers = modern_wire_headers("tools/call", Some("search"));
        if name.eq_ignore_ascii_case("Mcp-Param-Region") {
            headers.push(raw_header(name, "us-west1"));
        }
        headers.push(raw_header(name.to_ascii_uppercase(), value));
        let response = raw_modern_post(harness.port(), headers, &body);
        let error = assert_jsonrpc_error(&response, 400, -32020);
        assert_eq!(error["id"], 64, "{name}");
        assert_eq!(upstream.tool_calls(), before, "{name} reached upstream");
    }
}

#[test]
fn repeated_accept_lines_are_combined_in_received_order() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("tools/list", Some("65"), "");
    let mut headers = modern_wire_headers("tools/list", None);
    remove_raw_header(&mut headers, b"accept");
    headers.push(raw_header("Accept", "application/json; charset=utf-8"));
    headers.push(raw_header("aCcEpT", "text/event-stream; q=0.5"));

    let response = raw_modern_post(harness.port(), headers, body);

    assert_eq!(response.status, 200, "repeated Accept: {response:?}");
    assert_eq!(response.json()["id"], 65);
}

#[test]
fn modern_media_types_accept_parameters_and_ascii_case() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("tools/list", Some("66"), "");
    let mut headers = modern_wire_headers("tools/list", None);
    replace_raw_header(
        &mut headers,
        b"content-type",
        "Application/JSON; Charset=utf-8",
    );
    replace_raw_header(
        &mut headers,
        b"accept",
        "application/json; profile=modern, text/event-stream; q=0.5",
    );

    let response = raw_modern_post(harness.port(), headers, body);

    assert_eq!(response.status, 200, "parameterized media: {response:?}");
    assert_eq!(response.json()["id"], 66);
}

#[test]
fn modern_media_validation_rejects_q_zero_wildcards_and_wrong_content_type() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("tools/list", Some("67"), "");
    let mut q_zero = modern_wire_headers("tools/list", None);
    replace_raw_header(
        &mut q_zero,
        b"accept",
        "application/json; q=0, text/event-stream; q=0",
    );
    let mut wildcard = modern_wire_headers("tools/list", None);
    replace_raw_header(&mut wildcard, b"accept", "application/json, text/*");

    for (name, headers) in [("q=0", q_zero), ("wildcard", wildcard)] {
        let response = raw_modern_post(harness.port(), headers, &body);
        let error = assert_jsonrpc_error(&response, 406, -32600);
        assert_eq!(error["id"], 67, "{name}");
    }

    let mut wrong_content_type = modern_wire_headers("tools/list", None);
    replace_raw_header(&mut wrong_content_type, b"content-type", "text/plain");
    let response = raw_modern_post(harness.port(), wrong_content_type, body);
    let error = assert_jsonrpc_error(&response, 415, -32600);
    assert_eq!(error["id"], 67);
}

#[test]
fn modern_request_ids_accept_only_strings_and_bounded_lexical_integers() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let valid = vec![
        ("0", json!(0)),
        ("-7", json!(-7)),
        ("-9223372036854775808", json!(i64::MIN)),
        ("18446744073709551615", json!(u64::MAX)),
        (r#""request-東京""#, json!("request-\u{6771}\u{4eac}")),
    ];

    for (id_json, expected_id) in valid {
        let body = modern_wire_body("server/discover", Some(id_json), "");
        let response = raw_modern_post(
            harness.port(),
            modern_wire_headers("server/discover", None),
            body,
        );
        assert_eq!(response.status, 200, "valid ID {id_json}: {response:?}");
        assert_eq!(response.json()["id"], expected_id, "valid ID {id_json}");
    }

    let invalid = [
        "null",
        "true",
        r#"{}"#,
        r#"[]"#,
        "1.5",
        "1e3",
        "1e400",
        "-9223372036854775809",
        "18446744073709551616",
    ];
    for id_json in invalid {
        let body = modern_wire_body("server/discover", Some(id_json), "");
        let response = raw_modern_post(
            harness.port(),
            modern_wire_headers("server/discover", None),
            body,
        );
        let error = assert_jsonrpc_error(&response, 400, -32600);
        assert_id_absent(&error);
    }
}

#[test]
fn recognized_request_method_without_id_is_invalid_and_never_dispatches() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body(
        "tools/call",
        None,
        r#""name":"search","arguments":{"region":"us-west1","limit":1}"#,
    );

    let response = raw_modern_post(
        harness.port(),
        modern_wire_headers("tools/call", Some("search")),
        body,
    );

    let error = assert_jsonrpc_error(&response, 400, -32600);
    assert_id_absent(&error);
    assert_eq!(upstream.tool_calls(), 0);
}

#[test]
fn unknown_method_without_id_is_404_and_omits_id() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body("unknown/method", None, "");

    let response = raw_modern_post(
        harness.port(),
        modern_wire_headers("unknown/method", None),
        body,
    );

    let error = assert_jsonrpc_error(&response, 404, -32601);
    assert_id_absent(&error);
    assert_eq!(upstream.tool_calls(), 0);
}

#[test]
fn modern_envelope_errors_precede_media_validation() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let valid = String::from_utf8(modern_wire_body("tools/list", Some("71"), ""))
        .expect("modern list request text");
    let batch = format!("[{valid}]");
    let mut headers = modern_wire_headers("tools/list", None);
    remove_raw_header(&mut headers, b"content-type");

    let response = raw_modern_post(harness.port(), headers, batch);

    let error = assert_jsonrpc_error(&response, 400, -32600);
    assert_id_absent(&error);
}

#[test]
fn modern_marked_json_syntax_error_is_parse_error_and_omits_id() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let malformed = br#"{"jsonrpc":"2.0","id":72,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}"#;

    let response = raw_modern_post(
        harness.port(),
        modern_wire_headers("tools/list", None),
        malformed,
    );

    let error = assert_jsonrpc_error(&response, 400, -32700);
    assert_id_absent(&error);
}

#[test]
fn mirrored_header_mismatch_precedes_input_schema_validation() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let response = modern_rpc(
        &harness,
        "tools/call",
        json!({
            "name": "search",
            "arguments": {"region": "us-west1", "limit": "not-an-integer"}
        }),
        &[("Mcp-Param-Region", "eu-west1")],
    );

    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_slice(&response.body).expect("header mismatch JSON");
    assert_eq!(body["error"]["code"], -32020);
    assert_eq!(body["id"], 7);
    assert_eq!(upstream.tool_calls(), 0);
}

#[test]
fn modern_standard_routing_headers_are_bound_to_the_body() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let body = modern_wire_body(
        "tools/call",
        Some("73"),
        r#""name":"search","arguments":{"region":"us-west1","limit":1}"#,
    );
    let mut missing_protocol = modern_wire_headers("tools/call", Some("search"));
    remove_raw_header(&mut missing_protocol, b"mcp-protocol-version");
    let mut mismatched_protocol = modern_wire_headers("tools/call", Some("search"));
    replace_raw_header(
        &mut mismatched_protocol,
        b"mcp-protocol-version",
        "2025-06-18",
    );
    let mut missing_method = modern_wire_headers("tools/call", Some("search"));
    remove_raw_header(&mut missing_method, b"mcp-method");
    let mut mismatched_method = modern_wire_headers("tools/call", Some("search"));
    replace_raw_header(&mut mismatched_method, b"mcp-method", "tools/list");
    let mut missing_name = modern_wire_headers("tools/call", Some("search"));
    remove_raw_header(&mut missing_name, b"mcp-name");
    let mut mismatched_name = modern_wire_headers("tools/call", Some("search"));
    replace_raw_header(&mut mismatched_name, b"mcp-name", "zeta");

    let cases = [
        ("missing protocol", missing_protocol),
        ("mismatched protocol", mismatched_protocol),
        ("missing method", missing_method),
        ("mismatched method", mismatched_method),
        ("missing name", missing_name),
        ("mismatched name", mismatched_name),
    ];
    for (name, headers) in cases {
        let response = raw_modern_post(harness.port(), headers, &body);
        let error = assert_jsonrpc_error(&response, 400, -32020);
        assert_eq!(error["id"], 73, "{name}");
        assert_eq!(upstream.tool_calls(), 0, "{name}");
    }
}

#[test]
fn modern_input_schema_failure_is_invalid_params_with_zero_dispatch() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let response = modern_rpc(
        &harness,
        "tools/call",
        json!({
            "name": "search",
            "arguments": {"region": "us-west1", "limit": "not-an-integer"}
        }),
        &[("Mcp-Param-Region", "us-west1")],
    );

    assert_eq!(response.status, 400);
    let body: Value = serde_json::from_slice(&response.body).expect("schema error JSON");
    assert_eq!(body["error"]["code"], -32602);
    assert_eq!(body["id"], 7);
    assert_eq!(upstream.tool_calls(), 0);
}

#[test]
fn modern_missing_or_invalid_structured_content_is_withheld() {
    let cases = [
        (
            "missing structuredContent",
            MockMcpUpstream::missing_structured_content as fn() -> MockMcpUpstream,
            "missing-structured-leak",
        ),
        (
            "invalid structuredContent",
            MockMcpUpstream::invalid_structured_content as fn() -> MockMcpUpstream,
            "invalid-structured-leak",
        ),
    ];

    for (name, start, leak) in cases {
        let upstream = start();
        let harness = start_gateway(&upstream, false);
        let response = modern_rpc(
            &harness,
            "tools/call",
            json!({
                "name": "search",
                "arguments": {"region": "us-west1", "limit": 1}
            }),
            &[("Mcp-Param-Region", "us-west1")],
        );

        assert_eq!(response.status, 200, "{name}");
        let body: Value = serde_json::from_slice(&response.body).expect("output schema error JSON");
        assert_eq!(body["id"], 7, "{name}");
        assert_eq!(body["error"]["code"], -32603, "{name}");
        assert_eq!(
            body["error"]["message"],
            "upstream tool result does not conform to the advertised output schema",
            "{name}"
        );
        assert!(body["error"].get("data").is_none(), "{name}: {body}");
        assert!(!String::from_utf8_lossy(&response.body).contains(leak));
        assert_eq!(upstream.tool_calls(), 1, "{name}");
    }
}

#[test]
fn modern_upstream_error_detail_is_not_reflected() {
    let upstream = MockMcpUpstream::secret_call_error();
    let harness = start_gateway(&upstream, false);
    let response = modern_rpc(
        &harness,
        "tools/call",
        json!({
            "name": "search",
            "arguments": {"region": "us-west1", "limit": 1}
        }),
        &[("Mcp-Param-Region", "us-west1")],
    );

    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body).expect("upstream error JSON");
    assert_eq!(body["id"], 7);
    assert_eq!(body["error"]["code"], -32603);
    assert_eq!(body["error"]["message"], "upstream tool call failed");
    assert!(body["error"].get("data").is_none(), "{body}");
    assert!(!String::from_utf8_lossy(&response.body).contains("private-api-key"));
    assert_eq!(upstream.tool_calls(), 1);
}

#[test]
fn modern_call_uses_held_output_schema_across_catalog_refresh() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_refreshing_gateway(&upstream);

    let initial = modern_rpc(&harness, "tools/list", json!({}), &[]);
    assert_eq!(initial.status, 200);
    let initial: Value = serde_json::from_slice(&initial.body).expect("initial modern tools JSON");
    assert_eq!(
        initial["result"]["tools"][0]["outputSchema"]["properties"]["generation"]["const"],
        "old"
    );

    upstream.block_next_tool_call();
    let port = harness.port();
    let body = modern_wire_body(
        "tools/call",
        Some("81"),
        r#""name":"search","arguments":{"region":"us-west1","limit":1}"#,
    );
    let mut headers = modern_wire_headers("tools/call", Some("search"));
    headers.push(raw_header("Mcp-Param-Region", "us-west1"));
    let call = thread::spawn(move || raw_modern_post(port, headers, body));

    let blocked = upstream.wait_for_blocked_tool_call(Duration::from_secs(5));
    if !blocked {
        upstream.release_tool_call();
        let _ = call.join();
        panic!("modern call never reached the old held upstream entry");
    }
    let discoveries_before_mutation = upstream.discoveries();
    upstream.mutate_catalog();
    let published = wait_until(Duration::from_secs(10), || {
        if upstream.discoveries() <= discoveries_before_mutation {
            return false;
        }
        let response = modern_rpc(&harness, "tools/list", json!({}), &[]);
        if response.status != 200 {
            return false;
        }
        let Ok(body) = serde_json::from_slice::<Value>(&response.body) else {
            return false;
        };
        body["result"]["tools"]
            .as_array()
            .and_then(|tools| tools.iter().find(|tool| tool["title"] == "Search"))
            .is_some_and(|tool| tool["outputSchema"]["properties"]["generation"]["const"] == "new")
    });
    upstream.release_tool_call();
    let response = call.join().expect("join held-snapshot tools/call");
    assert!(published, "mutated modern catalog was not published");
    assert_eq!(response.status, 200, "held-snapshot response: {response:?}");
    let body = response.json();
    assert_eq!(body["id"], 81);
    assert_eq!(body["result"]["structuredContent"]["generation"], "old");
    assert!(
        body.get("error").is_none(),
        "old held schema rejected: {body}"
    );
}

#[test]
fn marker_free_legacy_malformed_envelopes_keep_literal_wire_bytes() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let cases = [
        (
            "batch",
            br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#.as_slice(),
            br#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"JSON-RPC batching is not supported (removed in MCP 2025-06-18); send one request per POST"},"id":null}"#.as_slice(),
        ),
        (
            "syntax",
            br#"{"jsonrpc":"2.0","id":1"#.as_slice(),
            br#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"invalid JSON-RPC body"},"id":null}"#.as_slice(),
        ),
        (
            "wrong jsonrpc",
            br#"{"jsonrpc":"1.0","id":9,"method":"tools/list"}"#.as_slice(),
            br#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"jsonrpc field must be \"2.0\""},"id":9}"#.as_slice(),
        ),
    ];

    for (name, request, expected) in cases {
        let response = raw_modern_post(harness.port(), base_json_headers(), request);
        assert_eq!(response.status, 200, "{name}");
        assert_eq!(response.body, expected, "{name}");
    }
}

#[test]
fn marker_free_legacy_nonstandard_ids_remain_frozen() {
    let upstream = MockMcpUpstream::legacy();
    let harness = start_gateway(&upstream, false);
    let null_response = raw_modern_post(
        harness.port(),
        base_json_headers(),
        br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
    );
    assert_eq!(null_response.status, 202, "legacy null ID");
    assert!(null_response.body.is_empty(), "legacy null ID");

    let cases = [
        ("true", json!(true)),
        ("1.5", json!(1.5)),
        (r#"{"legacy":true}"#, json!({"legacy": true})),
    ];

    for (id_json, expected_id) in cases {
        let body = format!(r#"{{"jsonrpc":"2.0","id":{id_json},"method":"ping"}}"#);
        let response = raw_modern_post(harness.port(), base_json_headers(), body);
        assert_eq!(response.status, 200, "legacy ID {id_json}");
        assert_eq!(response.json()["id"], expected_id, "legacy ID {id_json}");
    }
}
