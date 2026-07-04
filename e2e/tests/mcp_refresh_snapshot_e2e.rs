//! MCP federation snapshot serving (background refresh, no inline fan-out).
//!
//! The gateway primes its federated tool and resource catalogue once on
//! the first request (single-flight) and then serves every inbound
//! `tools/list` / `initialize` / `resources/list` from the cached
//! snapshot; a background task is the only steady-state refresher.
//! Before this change every inbound `tools/list` fanned out to every
//! upstream, so upstream load scaled 1:1 with inbound traffic.
//!
//! The mock upstream counts requests per JSON-RPC method. With the
//! refresh interval set far beyond the test duration, the counts must
//! stay flat no matter how many inbound requests the gateway serves.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};

// --- Mock MCP upstream that counts requests per method ---

#[derive(Default)]
struct MethodCounts {
    initialize: AtomicUsize,
    tools_list: AtomicUsize,
    resources_list: AtomicUsize,
}

struct CountingMcpUpstream {
    port: u16,
    counts: Arc<MethodCounts>,
    shutdown: Arc<Mutex<bool>>,
}

impl CountingMcpUpstream {
    fn start() -> Self {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("mock mcp upstream: bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let counts = Arc::new(MethodCounts::default());
        let shutdown = Arc::new(Mutex::new(false));
        let counts_clone = counts.clone();
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
                let counts = counts_clone.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(&mut stream, counts);
                });
            }
        });
        Self {
            port,
            counts,
            shutdown,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }

    fn tools_lists(&self) -> usize {
        self.counts.tools_list.load(Ordering::SeqCst)
    }

    fn resources_lists(&self) -> usize {
        self.counts.resources_list.load(Ordering::SeqCst)
    }

    fn initializes(&self) -> usize {
        self.counts.initialize.load(Ordering::SeqCst)
    }
}

impl Drop for CountingMcpUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_conn(stream: &mut std::net::TcpStream, counts: Arc<MethodCounts>) -> std::io::Result<()> {
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
        "initialize" => {
            counts.initialize.fetch_add(1, Ordering::SeqCst);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {}, "resources": {} },
                    "serverInfo": {"name": "counting-upstream", "version": "1.0.0"}
                }
            })
        }
        "tools/list" => {
            counts.tools_list.fetch_add(1, Ordering::SeqCst);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {"name": "search", "description": "search tool", "inputSchema": {"type": "object"}}
                    ]
                }
            })
        }
        "resources/list" => {
            counts.resources_list.fetch_add(1, Ordering::SeqCst);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "resources": [] }
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

fn config_yaml(upstream_url: &str) -> String {
    // refresh_interval far beyond the test duration: the only
    // upstream fan-out the test can observe is the single-flight
    // cold-start prime.
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
        - origin: "{upstream_url}"
          prefix: gh
"#
    )
}

/// Sustained inbound list/initialize traffic must not scale upstream
/// catalogue fetches: one prime pass, then flat counters.
#[test]
fn upstream_fanout_is_bounded_by_refresh_interval() {
    let upstream = CountingMcpUpstream::start();
    let yaml = config_yaml(&upstream.url());
    let harness = match ProxyHarness::start_with_yaml(&yaml) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping upstream_fanout_is_bounded_by_refresh_interval: {e}");
            return;
        }
    };

    // Drive a burst of inbound traffic across the three registry-read
    // methods.
    for i in 0..10 {
        let body = json!({"jsonrpc": "2.0", "id": i, "method": "tools/list"});
        let resp = harness
            .post_json("/", "mcp.localhost", &body, &[])
            .expect("post tools/list");
        assert_eq!(resp.status, 200);
        let parsed: Value = serde_json::from_slice(&resp.body).expect("json");
        let tools = parsed["result"]["tools"]
            .as_array()
            .expect("tools array present");
        assert_eq!(
            tools.len(),
            1,
            "snapshot must keep serving the primed catalogue"
        );
    }
    for i in 0..5 {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 100 + i,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
        });
        let resp = harness
            .post_json("/", "mcp.localhost", &body, &[])
            .expect("post initialize");
        assert_eq!(resp.status, 200);
    }
    for i in 0..5 {
        let body = json!({"jsonrpc": "2.0", "id": 200 + i, "method": "resources/list"});
        let resp = harness
            .post_json("/", "mcp.localhost", &body, &[])
            .expect("post resources/list");
        assert_eq!(resp.status, 200);
    }

    // 20 inbound requests; the upstream must have seen exactly the
    // cold-start prime: one tools/list, one resources/list, and one
    // initialize (the capability probe inside the resource refresh).
    assert_eq!(
        upstream.tools_lists(),
        1,
        "tools/list fan-out must not scale with inbound requests"
    );
    assert_eq!(
        upstream.resources_lists(),
        1,
        "resources/list fan-out must not scale with inbound requests"
    );
    assert_eq!(
        upstream.initializes(),
        1,
        "initialize probe must run once during the prime"
    );
}
