//! MCP prompt federation end to end.
//!
//! Three mock upstreams behind one gateway: two that declare the
//! `prompts` capability and publish a colliding prompt name, and one
//! that declares tools only. Through the real proxy binary this pins
//! the four behaviors the dispatch-level tests can only pin in
//! pieces: the catalog aggregates across upstreams, a name collision
//! namespaces the way a tool collision does, `prompts/get` routes the
//! namespaced name back to its owner with the name that owner
//! published, and `initialize` advertises the capability only where
//! an upstream actually backs it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};

// --- Mock MCP upstream ---

/// A mock upstream that answers `initialize`, `tools/list`,
/// `resources/list`, `prompts/list`, and `prompts/get`. Prompts are
/// only advertised (and only answered) when `prompt_names` is
/// non-empty, so the same type covers the "declares prompts" and
/// "declares tools only" cases.
struct MockMcpUpstream {
    port: u16,
    prompt_gets: Arc<AtomicUsize>,
    shutdown: Arc<Mutex<bool>>,
}

impl MockMcpUpstream {
    fn start(name: &'static str, prompt_names: Vec<&'static str>) -> Self {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("mock mcp upstream: bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let prompt_gets = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(Mutex::new(false));
        let gets = prompt_gets.clone();
        let shutdown_clone = shutdown.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_clone.lock().unwrap() {
                    break;
                }
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let gets = gets.clone();
                let prompts = prompt_names.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(&mut stream, name, &prompts, gets);
                });
            }
        });
        Self {
            port,
            prompt_gets,
            shutdown,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }

    fn prompt_gets(&self) -> usize {
        self.prompt_gets.load(Ordering::SeqCst)
    }
}

impl Drop for MockMcpUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_conn(
    stream: &mut std::net::TcpStream,
    name: &str,
    prompt_names: &[&str],
    prompt_gets: Arc<AtomicUsize>,
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
    let req: Value = serde_json::from_slice(&total[body_start..]).unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let has_prompts = !prompt_names.is_empty();

    let response_body = match method {
        "initialize" => {
            let mut capabilities = json!({ "tools": {}, "resources": {} });
            if has_prompts {
                capabilities["prompts"] = json!({ "listChanged": false });
            }
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": capabilities,
                    "serverInfo": {"name": name, "version": "1.0.0"}
                }
            })
        }
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [
                    {
                        "name": format!("{name}_search"),
                        "description": "search tool",
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        }),
        "resources/list" => json!({"jsonrpc": "2.0", "id": id, "result": {"resources": []}}),
        "prompts/list" if has_prompts => {
            let prompts: Vec<Value> = prompt_names
                .iter()
                .map(|p| {
                    json!({
                        "name": p,
                        "description": format!("{p} on {name}"),
                        "arguments": [{"name": "subject", "required": true}]
                    })
                })
                .collect();
            json!({"jsonrpc": "2.0", "id": id, "result": {"prompts": prompts}})
        }
        "prompts/get" if has_prompts => {
            prompt_gets.fetch_add(1, Ordering::SeqCst);
            // Echo back which upstream answered and exactly which
            // name it was asked for, so the test can prove the
            // gateway routed to the right server and un-namespaced
            // the name on the way out.
            let asked = req
                .pointer("/params/name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "description": format!("served by {name}"),
                    "messages": [{
                        "role": "user",
                        "content": {"type": "text", "text": format!("{name}:{asked}")}
                    }]
                }
            })
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": "method not found"}
        }),
    };
    let body_bytes = serde_json::to_vec(&response_body).unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(&body_bytes)?;
    stream.flush()?;
    Ok(())
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

/// Two origins on one proxy: `mcp.localhost` federates the two
/// prompt-serving upstreams plus the tools-only one, and
/// `plain.localhost` federates the tools-only upstream by itself.
fn config_yaml(gh: &str, gl: &str, plain: &str) -> String {
    format!(
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
        - origin: "{gh}"
          prefix: gh
        - origin: "{gl}"
          prefix: gl
        - origin: "{plain}"
          prefix: plain
  "plain.localhost":
    action:
      type: mcp
      mode: gateway
      server_info:
        name: plain-gateway
        version: "1.0.0"
      refresh_interval: "1h"
      federated_servers:
        - origin: "{plain}"
          prefix: plain
"#
    )
}

fn rpc(harness: &ProxyHarness, host: &str, id: i64, method: &str, params: Value) -> Value {
    let mut body = json!({"jsonrpc": "2.0", "id": id, "method": method});
    if !params.is_null() {
        body["params"] = params;
    }
    let resp = harness
        .post_json("/", host, &body, &[])
        .unwrap_or_else(|e| panic!("post {method}: {e}"));
    assert_eq!(resp.status, 200, "{method} must answer 200");
    serde_json::from_slice(&resp.body).unwrap_or_else(|e| panic!("{method} json: {e}"))
}

#[test]
fn prompts_federate_namespace_and_route_to_their_owning_upstream() {
    let gh = MockMcpUpstream::start("gh", vec!["code_review", "triage"]);
    let gl = MockMcpUpstream::start("gl", vec!["code_review"]);
    let plain = MockMcpUpstream::start("plain", vec![]);
    let yaml = config_yaml(&gh.url(), &gl.url(), &plain.url());
    let harness = match ProxyHarness::start_with_yaml(&yaml) {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "skipping prompts_federate_namespace_and_route_to_their_owning_upstream: {e}"
            );
            return;
        }
    };

    // An upstream declares prompts, so the gateway advertises them,
    // and it advertises listChanged: false because it pushes no
    // prompt list notifications.
    let init = rpc(
        &harness,
        "mcp.localhost",
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}}),
    );
    assert_eq!(
        init["result"]["capabilities"]["prompts"],
        json!({"listChanged": false}),
        "initialize must advertise the prompts capability an upstream backs"
    );

    // The catalog aggregates across both prompt-serving upstreams.
    // gh is configured first so it keeps the bare `code_review`; gl's
    // collides and is advertised server-qualified. The tools-only
    // upstream contributes nothing at all.
    let listed = rpc(&harness, "mcp.localhost", 2, "prompts/list", Value::Null);
    let prompts = listed["result"]["prompts"]
        .as_array()
        .expect("prompts array present");
    let names: Vec<&str> = prompts.iter().filter_map(|p| p["name"].as_str()).collect();
    assert_eq!(
        names,
        vec!["code_review", "gl.code_review", "triage"],
        "prompt catalog must aggregate and namespace on collision"
    );
    // Pass-through fields survive the merge.
    let collided = prompts
        .iter()
        .find(|p| p["name"] == "gl.code_review")
        .expect("namespaced entry present");
    assert_eq!(collided["description"], "code_review on gl");
    assert_eq!(collided["arguments"][0]["name"], "subject");

    // The namespaced name routes to gl, and gl is asked for the bare
    // name it published.
    let got = rpc(
        &harness,
        "mcp.localhost",
        3,
        "prompts/get",
        json!({"name": "gl.code_review", "arguments": {"subject": "auth"}}),
    );
    assert_eq!(
        got["result"]["messages"][0]["content"]["text"], "gl:code_review",
        "prompts/get must reach gl with the name gl published"
    );
    assert_eq!(gl.prompt_gets(), 1, "gl served the namespaced prompt");
    assert_eq!(
        gh.prompt_gets(),
        0,
        "gh must not see a prompt that belongs to gl"
    );

    // The bare name still belongs to gh.
    let got = rpc(
        &harness,
        "mcp.localhost",
        4,
        "prompts/get",
        json!({"name": "code_review"}),
    );
    assert_eq!(
        got["result"]["messages"][0]["content"]["text"],
        "gh:code_review"
    );

    // A name that is in no catalog is invalid params, not an
    // upstream error, and never reaches an upstream.
    let missing = rpc(
        &harness,
        "mcp.localhost",
        5,
        "prompts/get",
        json!({"name": "no_such_prompt"}),
    );
    assert_eq!(missing["error"]["code"], -32602);
    assert!(missing["result"].is_null());
    assert_eq!(
        gh.prompt_gets() + gl.prompt_gets(),
        2,
        "no extra upstream calls"
    );

    // The origin federating only the tools-only upstream must not
    // advertise a capability nothing backs, and its catalog is empty
    // rather than an error.
    let init = rpc(
        &harness,
        "plain.localhost",
        6,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}}),
    );
    assert!(
        init["result"]["capabilities"].get("prompts").is_none(),
        "no upstream declares prompts, so none may be advertised: {}",
        init["result"]["capabilities"]
    );
    let listed = rpc(&harness, "plain.localhost", 7, "prompts/list", Value::Null);
    assert_eq!(
        listed["result"]["prompts"],
        json!([]),
        "an upstream without prompts contributes nothing and errors nothing"
    );
}
