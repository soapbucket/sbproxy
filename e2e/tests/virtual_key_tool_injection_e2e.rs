//! Per-key MCP tool injection (WOR-893, PR2).
//!
//! A virtual key with `inject_tools:` populated REPLACES any
//! client-supplied `tools` array on the request before it reaches the
//! provider. A plain key (no `inject_tools`) leaves the client's
//! `tools` alone. The mock provider captures the forwarded body so the
//! test asserts what the upstream actually received.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use sbproxy_e2e::ProxyHarness;

struct MockProvider {
    port: u16,
    last_body: Arc<Mutex<String>>,
    shutdown: Arc<Mutex<bool>>,
}

impl MockProvider {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock provider");
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
                    let _ = handle_conn(&mut stream, body);
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

fn handle_conn(
    stream: &mut std::net::TcpStream,
    last_body: Arc<Mutex<String>>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(end) = find_headers_end(&buf) {
            let header_str = String::from_utf8_lossy(&buf[..end]).to_string();
            let content_len = parse_content_length(&header_str);
            if buf.len() >= end + 4 + content_len {
                break;
            }
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body_start = find_headers_end(&buf).map(|e| e + 4).unwrap_or(buf.len());
    let body = String::from_utf8_lossy(&buf[body_start.min(buf.len())..]).to_string();
    *last_body.lock().unwrap() = body;

    let json_body = r#"{"id":"chatcmpl-1","object":"chat.completion","created":1700000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        json_body.len(),
        json_body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> usize {
    for line in headers.lines() {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn config_for(upstream: &str) -> String {
    // Rewritten from the legacy `action.virtual_keys:` shape to the
    // unified `credentials:` block per docs/migration-credentials.md.
    // `inject_tools` lands on the credential directly; the
    // compile-time lowering materialises each ai_provider credential
    // as the same virtual-key entry the AI handler used to consume,
    // so the runtime tool-injection path is unchanged from the
    // pre-credentials wire shape.
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub"
          base_url: "{upstream}"
          allow_private_base_url: true
          models: [gpt-4o, gpt-4o-mini]
    credentials:
      - name: key-with-tools
        type: ai_provider
        provider: openai
        key: "sk-with-tools"
        inject_tools:
          - type: function
            function:
              name: get_weather
              description: "Look up the weather for a city."
              parameters:
                type: object
                properties:
                  city:
                    type: string
                required: [city]
          - type: function
            function:
              name: get_time
              description: "Return the current time in a timezone."
              parameters:
                type: object
                properties:
                  tz:
                    type: string
      - name: plain-key
        type: ai_provider
        provider: openai
        key: "sk-plain"
"#
    )
}

#[test]
fn virtual_key_inject_tools_replaces_request_tools() {
    let upstream = MockProvider::start();
    let proxy = ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start");

    // Client sends its own (different) tool. The key's inject_tools should
    // win and REPLACE the client tool wholesale.
    let req = serde_json::json!({
        "model": "gpt-4o-mini",
        "messages": [{"role":"user","content":"hi"}],
        "tools": [{
            "type": "function",
            "function": {"name": "client_supplied_tool", "parameters": {"type":"object"}}
        }]
    });
    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &req,
            &[("authorization", "Bearer sk-with-tools")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let fwd: serde_json::Value =
        serde_json::from_str(&upstream.last_body()).expect("upstream got JSON");
    let tools = fwd["tools"].as_array().expect("tools array forwarded");
    assert_eq!(
        tools.len(),
        2,
        "key's two tools should be injected; got: {fwd}"
    );
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t["function"]["name"].as_str())
        .collect();
    assert!(
        names.contains(&"get_weather") && names.contains(&"get_time"),
        "expected injected tool names, got {names:?}"
    );
    assert!(
        !names.contains(&"client_supplied_tool"),
        "client-supplied tool must be replaced, not merged; got {names:?}"
    );
}

#[test]
fn plain_key_leaves_client_tools_intact() {
    let upstream = MockProvider::start();
    let proxy = ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start");

    let req = serde_json::json!({
        "model": "gpt-4o-mini",
        "messages": [{"role":"user","content":"hi"}],
        "tools": [{
            "type": "function",
            "function": {"name": "client_supplied_tool", "parameters": {"type":"object"}}
        }]
    });
    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &req,
            &[("authorization", "Bearer sk-plain")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let fwd: serde_json::Value =
        serde_json::from_str(&upstream.last_body()).expect("upstream got JSON");
    let tools = fwd["tools"].as_array().expect("tools array forwarded");
    assert_eq!(
        tools.len(),
        1,
        "client tool should pass through; got: {fwd}"
    );
    assert_eq!(
        tools[0]["function"]["name"], "client_supplied_tool",
        "plain key should not modify the client's tools array; got: {fwd}"
    );
}

#[test]
fn inject_tools_adds_when_client_sent_none() {
    let upstream = MockProvider::start();
    let proxy = ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start");

    // No `tools` field on the client request; the key's tools should still be
    // injected.
    let req = serde_json::json!({
        "model": "gpt-4o-mini",
        "messages": [{"role":"user","content":"hi"}]
    });
    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &req,
            &[("authorization", "Bearer sk-with-tools")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let fwd: serde_json::Value =
        serde_json::from_str(&upstream.last_body()).expect("upstream got JSON");
    let tools = fwd["tools"].as_array().expect("tools array forwarded");
    assert_eq!(
        tools.len(),
        2,
        "key tools injected even with no client tools; got: {fwd}"
    );
}
