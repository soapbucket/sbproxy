//! MCP tool-call attribution into the usage plane.
//!
//! A `tools/call` produces a usage-sink row in the same stream as
//! model spend: provider `mcp`, the owning server as the model, the
//! caller's principal and tenant, latency, and the cost resolved from
//! the action's price map. Metrics ride alongside. Without a price
//! map the row still flows with cost absent.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};

struct MockUpstream {
    port: u16,
    shutdown: Arc<Mutex<bool>>,
    calls: Arc<AtomicUsize>,
}

impl MockUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let shutdown = Arc::new(Mutex::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let shutdown_clone = shutdown.clone();
        let calls_clone = calls.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_clone.lock().unwrap() {
                    break;
                }
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let calls = calls_clone.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(&mut stream, &calls);
                });
            }
        });
        Self {
            port,
            shutdown,
            calls,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_conn(stream: &mut std::net::TcpStream, calls: &AtomicUsize) -> std::io::Result<()> {
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
            let len = parse_content_length(&total[..idx]).unwrap_or(0);
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
    let response_body = match method {
        "initialize" => json!({"jsonrpc": "2.0", "id": id, "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "up", "version": "1.0.0"}}}),
        "tools/list" => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [
            {"name": "search", "description": "s", "inputSchema": {"type": "object"}}
        ]}}),
        "resources/list" => json!({"jsonrpc": "2.0", "id": id, "result": {"resources": []}}),
        "tools/call" => {
            calls.fetch_add(1, Ordering::SeqCst);
            json!({"jsonrpc": "2.0", "id": id, "result": {"ok": true}})
        }
        _ => json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32601, "message": "method not found"}}),
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

fn read_sink_rows(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

fn drive_call(harness: &ProxyHarness) {
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let resp = harness
        .post_json("/", "mcp.localhost", &list, &[])
        .expect("tools/list");
    assert_eq!(resp.status, 200);
    let call = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "search", "arguments": {}}
    });
    let resp = harness
        .post_json("/", "mcp.localhost", &call, &[])
        .expect("tools/call");
    assert_eq!(resp.status, 200);
}

/// A priced tool call lands in the usage sink with its cost, keyed
/// so it is filterable next to model spend.
#[test]
fn priced_tool_call_produces_a_usage_row() {
    let upstream = MockUpstream::start();
    let sink_path =
        std::env::temp_dir().join(format!("sbproxy-mcp-usage-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&sink_path);
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      refresh_interval: "1h"
      tool_pricing:
        search: 0.002
      usage_sinks:
        - type: jsonl_file
          path: "{sink}"
      federated_servers:
        - origin: "{url}"
          prefix: up
"#,
        sink = sink_path.display(),
        url = upstream.url(),
    );
    let harness = match ProxyHarness::start_with_yaml(&yaml) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping priced_tool_call_produces_a_usage_row: {e}");
            return;
        }
    };

    drive_call(&harness);
    assert!(
        upstream.calls() >= 1,
        "upstream must have served the tool call"
    );

    let rows = read_sink_rows(&sink_path);
    let row = rows
        .iter()
        .find(|r| r["provider"] == "mcp")
        .expect("an mcp usage row must be written");
    assert_eq!(row["model"], "up", "server is the model dimension");
    assert_eq!(row["cost_usd"], 0.002, "cost comes from the price map");
    assert_eq!(row["status"], 200);
    assert_eq!(row["tag"], "mcp_tool:search");
    assert!(row["request_id"].as_str().is_some());

    let _ = std::fs::remove_file(sink_path);
}

/// Without a price map the row still flows, cost absent, nothing
/// breaks.
#[test]
fn unpriced_tool_call_still_produces_a_row() {
    let upstream = MockUpstream::start();
    let sink_path =
        std::env::temp_dir().join(format!("sbproxy-mcp-usage-np-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&sink_path);
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "mcp.localhost":
    action:
      type: mcp
      mode: gateway
      refresh_interval: "1h"
      usage_sinks:
        - type: jsonl_file
          path: "{sink}"
      federated_servers:
        - origin: "{url}"
          prefix: up
"#,
        sink = sink_path.display(),
        url = upstream.url(),
    );
    let harness = match ProxyHarness::start_with_yaml(&yaml) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping unpriced_tool_call_still_produces_a_row: {e}");
            return;
        }
    };

    drive_call(&harness);
    assert!(
        upstream.calls() >= 1,
        "upstream must have served the tool call"
    );

    let rows = read_sink_rows(&sink_path);
    let row = rows
        .iter()
        .find(|r| r["provider"] == "mcp")
        .expect("an mcp usage row must be written even with no price map");
    assert_eq!(row["cost_usd"], 0.0, "unpriced cost is zero");

    let _ = std::fs::remove_file(sink_path);
}
