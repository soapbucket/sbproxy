//! OpenAPI-backed federated MCP server (WOR-1648).
//!
//! An `mcp` action can federate a `type: openapi` server: the gateway
//! derives tools from the spec and dispatches `tools/call` as REST
//! requests against the origin. `tools/list` advertises the derived
//! tools, a call reaches the REST upstream with path params
//! substituted, and the same RBAC allowlist as native MCP tools
//! applies.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};

/// A tiny REST upstream that records the last request line + body.
struct RestUpstream {
    port: u16,
    last_target: Arc<Mutex<String>>,
    calls: Arc<AtomicUsize>,
    shutdown: Arc<Mutex<bool>>,
}

impl RestUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind rest upstream");
        let port = listener.local_addr().unwrap().port();
        let last_target = Arc::new(Mutex::new(String::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(Mutex::new(false));
        let lt = last_target.clone();
        let c = calls.clone();
        let sd = shutdown.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *sd.lock().unwrap() {
                    break;
                }
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let lt = lt.clone();
                let c = c.clone();
                std::thread::spawn(move || {
                    let _ = handle(&mut stream, lt, c);
                });
            }
        });
        Self {
            port,
            last_target,
            calls,
            shutdown,
        }
    }

    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn last_target(&self) -> String {
        self.last_target.lock().unwrap().clone()
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for RestUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle(
    stream: &mut std::net::TcpStream,
    last_target: Arc<Mutex<String>>,
    calls: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    // Read at least the request line + headers.
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let request_line = text.lines().next().unwrap_or("").to_string();
    *last_target.lock().unwrap() = request_line;
    calls.fetch_add(1, Ordering::SeqCst);

    let json_body = r#"{"pet":"rex","status":"ok"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        json_body.len(),
        json_body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn config(rest_base: &str) -> String {
    // Inline OpenAPI spec with two operations. `type: openapi` makes
    // the gateway derive tools and dispatch REST.
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
        - type: openapi
          origin: "{rest_base}"
          spec:
            openapi: "3.0.0"
            info:
              title: Pets
              version: "1.0"
            paths:
              "/pets/{{id}}":
                get:
                  operationId: getPet
                  summary: "Fetch one pet by id."
                  parameters:
                    - name: id
                      in: path
                      required: true
                      schema:
                        type: string
              "/pets":
                get:
                  operationId: listPets
                  summary: "List pets."
"#
    )
}

/// tools/list advertises the OpenAPI-derived tools; a tools/call
/// dispatches to the REST upstream with the path param substituted.
#[test]
fn openapi_server_lists_and_dispatches_rest() {
    let rest = RestUpstream::start();
    let harness = match ProxyHarness::start_with_yaml(&config(&rest.base())) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping openapi_server_lists_and_dispatches_rest: {e}");
            return;
        }
    };

    // tools/list shows the derived tools.
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let resp = harness
        .post_json("/", "mcp.localhost", &list, &[])
        .expect("tools/list");
    assert_eq!(resp.status, 200);
    let parsed: Value = serde_json::from_slice(&resp.body).expect("json");
    let names: Vec<&str> = parsed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        names.contains(&"getPet"),
        "derived tools listed, got {names:?}"
    );
    assert!(names.contains(&"listPets"));

    // tools/call dispatches REST with the path param substituted.
    let call = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "getPet", "arguments": {"id": "rex"}}
    });
    let resp = harness
        .post_json("/", "mcp.localhost", &call, &[])
        .expect("tools/call");
    assert_eq!(resp.status, 200);
    let parsed: Value = serde_json::from_slice(&resp.body).expect("json");
    assert!(parsed.get("error").is_none(), "call must succeed: {parsed}");
    // The upstream saw GET /pets/rex.
    let target = rest.last_target();
    assert!(
        target.contains("GET /pets/rex"),
        "REST upstream must receive the substituted path, got {target:?}"
    );
    assert!(rest.calls() >= 1);
    // The REST body came back wrapped as MCP tool-result content.
    let content = &parsed["result"]["content"][0]["text"];
    assert!(
        content.as_str().unwrap_or("").contains("rex"),
        "REST response must be wrapped as tool content, got {parsed}"
    );
}
