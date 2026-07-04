//! Federation-sourced virtual-key tool injection (WOR-1646).
//!
//! A virtual key with `inject_mcp:` referencing a federated MCP
//! gateway injects that gateway's live `tools/list` catalogue as the
//! request's `tools`, RBAC-filtered by the key's principal and
//! converted to the provider shape. After an upstream catalogue
//! change and refresh, the next model request reflects it with no
//! config reload. The mock provider captures the forwarded body so
//! the test asserts what the upstream received.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sbproxy_e2e::ProxyHarness;
use serde_json::{json, Value};

// --- Mock OpenAI-compatible provider that records the forwarded body ---

struct MockProvider {
    port: u16,
    last_body: Arc<Mutex<String>>,
    shutdown: Arc<Mutex<bool>>,
}

impl MockProvider {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind provider");
        let port = listener.local_addr().unwrap().port();
        let last_body = Arc::new(Mutex::new(String::new()));
        let shutdown = Arc::new(Mutex::new(false));
        let body_clone = last_body.clone();
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
                let body = body_clone.clone();
                std::thread::spawn(move || {
                    let _ = handle_provider(&mut stream, body);
                });
            }
        });
        Self {
            port,
            last_body,
            shutdown,
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn last_body(&self) -> String {
        self.last_body.lock().unwrap().clone()
    }
}

impl Drop for MockProvider {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_provider(
    stream: &mut std::net::TcpStream,
    last_body: Arc<Mutex<String>>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(end) = find_crlf(&buf) {
            let len = content_len(&String::from_utf8_lossy(&buf[..end]));
            if buf.len() >= end + 4 + len {
                break;
            }
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let start = find_crlf(&buf).map(|e| e + 4).unwrap_or(buf.len());
    *last_body.lock().unwrap() = String::from_utf8_lossy(&buf[start.min(buf.len())..]).to_string();
    let json_body = r#"{"id":"c1","object":"chat.completion","created":1700000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        json_body.len(),
        json_body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

// --- Mock MCP upstream whose catalogue can grow ---

struct McpUpstream {
    port: u16,
    grown: Arc<AtomicBool>,
    shutdown: Arc<Mutex<bool>>,
}

impl McpUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mcp upstream");
        let port = listener.local_addr().unwrap().port();
        let grown = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(Mutex::new(false));
        let grown_clone = grown.clone();
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
                let grown = grown_clone.clone();
                std::thread::spawn(move || {
                    let _ = handle_mcp(&mut stream, &grown);
                });
            }
        });
        Self {
            port,
            grown,
            shutdown,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.port)
    }

    fn grow(&self) {
        self.grown.store(true, Ordering::SeqCst);
    }
}

impl Drop for McpUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_mcp(stream: &mut std::net::TcpStream, grown: &AtomicBool) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(end) = find_crlf(&buf) {
            let len = content_len(&String::from_utf8_lossy(&buf[..end]));
            if buf.len() >= end + 4 + len {
                break;
            }
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let start = find_crlf(&buf).map(|e| e + 4).unwrap_or(buf.len());
    let req: Value = serde_json::from_slice(&buf[start.min(buf.len())..]).unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let body = match method {
        "initialize" => json!({"jsonrpc":"2.0","id":id,"result":{
            "protocolVersion":"2025-06-18","capabilities":{"tools":{}},
            "serverInfo":{"name":"up","version":"1.0.0"}}}),
        "tools/list" => {
            let mut tools = vec![
                json!({"name":"search","description":"search","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}),
            ];
            if grown.load(Ordering::SeqCst) {
                tools.push(json!({"name":"summarize","description":"late","inputSchema":{"type":"object"}}));
            }
            json!({"jsonrpc":"2.0","id":id,"result":{"tools":tools}})
        }
        "resources/list" => json!({"jsonrpc":"2.0","id":id,"result":{"resources":[]}}),
        _ => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"nope"}}),
    };
    let bytes = serde_json::to_vec(&body).unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn content_len(headers: &str) -> usize {
    for line in headers.lines() {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn config(provider_url: &str, mcp_url: &str) -> String {
    // The mcp origin registers an injectable source under its
    // server_info.name ("toolhub"); the ai origin's credential
    // references it. `mcp.localhost` and `ai.localhost` are separate
    // origins in one proxy.
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
        name: toolhub
        version: "1.0.0"
      refresh_interval: "1s"
      federated_servers:
        - origin: "{mcp_url}"
          prefix: up
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub"
          base_url: "{provider_url}"
          allow_private_base_url: true
          models: [gpt-4o-mini]
    credentials:
      - name: agent-key
        type: ai_provider
        provider: openai
        key: "sk-agent"
        inject_mcp:
          ref: toolhub
          format: openai
"#
    )
}

fn injected_tool_names(provider: &MockProvider) -> Vec<String> {
    let body: Value = serde_json::from_str(&provider.last_body()).unwrap_or(Value::Null);
    body["tools"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t["function"]["name"].as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// A key with inject_mcp injects the live federated catalogue, and a
/// later upstream change is reflected without a config reload.
#[test]
fn inject_mcp_reflects_live_catalogue() {
    let provider = MockProvider::start();
    let mcp = McpUpstream::start();
    let harness = match ProxyHarness::start_with_yaml(&config(&provider.base_url(), &mcp.url())) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping inject_mcp_reflects_live_catalogue: {e}");
            return;
        }
    };

    // Prime the MCP gateway's catalogue.
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let resp = harness
        .post_json("/", "mcp.localhost", &list, &[])
        .expect("prime mcp");
    assert_eq!(resp.status, 200);

    // Drive a model request through the injecting key.
    let chat = json!({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]});
    let resp = harness
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat,
            &[("Authorization", "Bearer sk-agent")],
        )
        .expect("chat");
    assert_eq!(resp.status, 200, "chat request must succeed");

    let names = injected_tool_names(&provider);
    assert!(
        names.contains(&"search".to_string()),
        "the live catalogue must be injected as OpenAI tools, got {names:?}"
    );
    assert!(
        !names.contains(&"summarize".to_string()),
        "summarize is not advertised yet"
    );

    // Grow the upstream catalogue; the 1s background refresh picks it
    // up and the next request reflects it with no config reload.
    mcp.grow();
    let saw_new = {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut seen = false;
        while Instant::now() < deadline {
            let _ = harness.post_json("/", "mcp.localhost", &list, &[]);
            let _ = harness.post_json(
                "/v1/chat/completions",
                "ai.localhost",
                &chat,
                &[("Authorization", "Bearer sk-agent")],
            );
            if injected_tool_names(&provider).contains(&"summarize".to_string()) {
                seen = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        seen
    };
    assert!(
        saw_new,
        "a catalogue change must reflect in the injected tools without a reload"
    );
}
