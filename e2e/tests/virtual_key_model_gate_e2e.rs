//! Per-key model gate.
//!
//! A virtual key allow-listed to a subset of the gateway's models is
//! rejected with 403 when it asks for a model outside that subset, and
//! served normally for a model on its allow-list. The model gate is
//! scoped to the matched key, independent of the action-level
//! allow/block lists.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use sbproxy_e2e::ProxyHarness;

struct MockProvider {
    port: u16,
    shutdown: Arc<Mutex<bool>>,
}

impl MockProvider {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock provider");
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
                    let _ = handle_conn(&mut stream);
                });
            }
        });
        Self { port, shutdown }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for MockProvider {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_conn(stream: &mut std::net::TcpStream) -> std::io::Result<()> {
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
    // `scoped-key` is allow-listed to `gpt-4o-mini` only, even though
    // the provider serves both models. The per-key model gate must
    // reject `gpt-4o` for this key while letting `gpt-4o-mini` through.
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
      - name: scoped-key
        type: ai_provider
        provider: openai
        key: "sk-scoped"
        models:
          allow: [gpt-4o-mini]
"#
    )
}

#[test]
fn scoped_key_allows_listed_model() {
    let upstream = MockProvider::start();
    let proxy = ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start");

    let req = serde_json::json!({
        "model": "gpt-4o-mini",
        "messages": [{"role":"user","content":"hi"}]
    });
    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &req,
            &[("authorization", "Bearer sk-scoped")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "a model on the key's allow-list is served; got {}",
        resp.status
    );
}

#[test]
fn scoped_key_blocks_unlisted_model() {
    let upstream = MockProvider::start();
    let proxy = ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start");

    // `gpt-4o` is served by the provider but not on this key's
    // allow-list, so the per-key gate must reject it with 403.
    let req = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role":"user","content":"hi"}]
    });
    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &req,
            &[("authorization", "Bearer sk-scoped")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 403,
        "a model off the key's allow-list is rejected; got {}",
        resp.status
    );
}
