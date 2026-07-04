//! MCP federation upstream deadlines (WOR-1639 behaviour).
//!
//! The federation's HTTP client previously had no timeout, so one
//! hung upstream stalled every catalogue-reading request forever. Now
//! every upstream exchange is bounded by `upstream_timeout` (and
//! `upstream_connect_timeout`), a hung upstream degrades only itself,
//! and the gateway still answers with the healthy upstreams' tools.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};

/// Minimal mock MCP upstream. `delay` is applied before answering any
/// request; a delay far beyond the configured `upstream_timeout`
/// makes the upstream behave as hung.
struct MockUpstream {
    port: u16,
    shutdown: Arc<Mutex<bool>>,
}

impl MockUpstream {
    fn start(tool_name: &'static str, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let shutdown = Arc::new(Mutex::new(false));
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
                std::thread::spawn(move || {
                    let _ = handle_conn(&mut stream, tool_name, delay);
                });
            }
        });
        Self { port, shutdown }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_conn(
    stream: &mut std::net::TcpStream,
    tool_name: &str,
    delay: Duration,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
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
    if !delay.is_zero() {
        std::thread::sleep(delay);
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
                "capabilities": { "tools": {} },
                "serverInfo": {"name": "mock", "version": "1.0.0"}
            }
        }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [
                    {"name": tool_name, "description": "a tool", "inputSchema": {"type": "object"}}
                ]
            }
        }),
        "resources/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "resources": [] }
        }),
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

/// A hung upstream must fail its exchanges at `upstream_timeout`
/// while the healthy upstream's catalogue still comes back.
#[test]
fn hung_upstream_degrades_only_itself() {
    let healthy = MockUpstream::start("alpha", Duration::ZERO);
    // Far beyond the 2s upstream_timeout: behaves as hung.
    let hung = MockUpstream::start("slow_tool", Duration::from_secs(30));

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
      upstream_timeout: "2s"
      upstream_connect_timeout: "1s"
      federated_servers:
        - origin: "{hung_url}"
          prefix: slow
        - origin: "{healthy_url}"
          prefix: fast
"#,
        hung_url = hung.url(),
        healthy_url = healthy.url(),
    );
    let harness = match ProxyHarness::start_with_yaml(&yaml) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping hung_upstream_degrades_only_itself: {e}");
            return;
        }
    };

    let started = Instant::now();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let resp = harness
        .post_json("/", "mcp.localhost", &body, &[])
        .expect("post tools/list");
    let elapsed = started.elapsed();

    assert_eq!(resp.status, 200);
    let parsed: Value = serde_json::from_slice(&resp.body).expect("json");
    let tools = parsed["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(
        names.contains(&"alpha"),
        "healthy upstream's tool must be served, got {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("slow_tool")),
        "hung upstream must contribute nothing, got {names:?}"
    );
    // Cold-start prime: the hung upstream costs at most one
    // upstream_timeout per exchange (tools + initialize probe +
    // resources), serially. Well under a minute proves the deadline
    // fired; without one this request would hang forever.
    assert!(
        elapsed < Duration::from_secs(20),
        "tools/list took {elapsed:?}; upstream deadlines did not fire"
    );
}
