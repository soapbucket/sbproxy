//! Progressive tool discovery for the MCP gateway (WOR-806).
//!
//! With `progressive_discovery: true`, `tools/list` advertises only the
//! `search` and `execute` meta-tools instead of the full federated
//! catalogue. `search` returns matching catalogue entries; `execute`
//! unwraps to the real tool and dispatches it. This keeps a large tool
//! set out of the model's context window.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};

struct MockMcp {
    port: u16,
    calls: Arc<AtomicUsize>,
    shutdown: Arc<Mutex<bool>>,
}

impl MockMcp {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let calls = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(Mutex::new(false));
        let calls_c = calls.clone();
        let shutdown_c = shutdown.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_c.lock().unwrap() {
                    break;
                }
                if let Ok(mut s) = stream {
                    let calls = calls_c.clone();
                    std::thread::spawn(move || {
                        let _ = handle(&mut s, calls);
                    });
                }
            }
        });
        Self {
            port,
            calls,
            shutdown,
        }
    }
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for MockMcp {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle(stream: &mut std::net::TcpStream, calls: Arc<AtomicUsize>) -> std::io::Result<()> {
    let mut total = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total.extend_from_slice(&buf[..n]);
        if let Some(idx) = total.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&total[..idx]).to_ascii_lowercase();
            let len = headers
                .split("\r\n")
                .find_map(|l| {
                    l.strip_prefix("content-length:")
                        .and_then(|r| r.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if total.len() >= idx + 4 + len {
                break;
            }
        }
    }
    let body_start = total
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(total.len());
    let req: Value = serde_json::from_slice(&total[body_start..]).unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => {
            json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"1.0.0"}}})
        }
        "tools/list" => json!({"jsonrpc":"2.0","id":id,"result":{"tools":[
            {"name":"get_weather","description":"Look up the current weather for a city","inputSchema":{"type":"object"}},
            {"name":"get_stock_price","description":"Fetch a stock quote","inputSchema":{"type":"object"}},
            {"name":"send_email","description":"Send an email message","inputSchema":{"type":"object"}}
        ]}}),
        "tools/call" => {
            calls.fetch_add(1, Ordering::SeqCst);
            let name = req
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            json!({"jsonrpc":"2.0","id":id,"result":{"ok":true,"tool":name}})
        }
        _ => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}}),
    };
    let bytes = serde_json::to_vec(&result).unwrap();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn config(upstream: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      progressive_discovery: true
      server_info:
        name: sbproxy-gateway
        version: "1.0.0"
      federated_servers:
        - origin: "{upstream}"
"#
    )
}

fn rpc(harness: &ProxyHarness, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let resp = harness
        .post_json("/", "mcp.localhost", &body, &[])
        .expect("rpc");
    assert_eq!(resp.status, 200, "rpc {method} -> {}", resp.status);
    serde_json::from_slice(&resp.body).expect("json-rpc response")
}

#[test]
fn tools_list_advertises_only_meta_tools() {
    let upstream = MockMcp::start();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.url())).expect("proxy");

    let resp = rpc(&harness, "tools/list", Value::Null);
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(
        names,
        vec!["search", "execute"],
        "expected only the meta-tools, got {names:?}"
    );
    // The upstream catalogue must NOT be dumped.
    assert!(!names.contains(&"get_weather"));
}

#[test]
fn search_returns_matching_catalogue_entries() {
    let upstream = MockMcp::start();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.url())).expect("proxy");

    // Prime the federation catalogue (a client calls tools/list first).
    let _ = rpc(&harness, "tools/list", Value::Null);

    let resp = rpc(
        &harness,
        "tools/call",
        json!({"name": "search", "arguments": {"query": "weather"}}),
    );
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("search text");
    assert!(
        text.contains("get_weather"),
        "search should find get_weather; got: {text}"
    );
    assert!(
        !text.contains("send_email"),
        "search should not return unrelated tools; got: {text}"
    );
}

#[test]
fn execute_dispatches_to_the_real_tool() {
    let upstream = MockMcp::start();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.url())).expect("proxy");

    let _ = rpc(&harness, "tools/list", Value::Null);
    assert_eq!(upstream.calls(), 0, "tools/list must not call a tool");

    let resp = rpc(
        &harness,
        "tools/call",
        json!({"name": "execute", "arguments": {"name": "get_weather", "arguments": {"city": "Paris"}}}),
    );
    assert_eq!(
        resp["result"]["tool"].as_str(),
        Some("get_weather"),
        "execute should dispatch to the named tool; got: {resp}"
    );
    assert_eq!(
        upstream.calls(),
        1,
        "execute must reach the upstream exactly once"
    );
}
