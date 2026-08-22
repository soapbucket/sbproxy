//! Versioned prompt store (WOR-800, WOR-2597).
//!
//! Proves the config-declared prompt store end to end: an `ai_proxy`
//! request that references `"prompt": "name@version"` has the stored
//! template rendered (with request variables + partials) and prepended
//! as a `system` message before the request reaches the provider. A bad
//! reference is a 400. The mock provider captures the forwarded request
//! body so the test can assert what the upstream actually received.
//!
//! WOR-2597 adds the native-surface half. `prompt` belongs to no
//! provider wire format, so the Anthropic Messages and OpenAI Responses
//! translators dropped it and the shared resolver, which reads the
//! already-translated canonical body, never saw one. The reference is
//! now lifted before translation and put back afterwards, and a
//! reference no prompt layer holds is a 404 on those surfaces rather
//! than a gateway-only key forwarded upstream.

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

    let json_body = r#"{"id":"chatcmpl-1","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
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
          api_key: "stub-key"
          base_url: "{upstream}"
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: round_robin
      prompts:
        partials:
          tone: "Be concise."
        templates:
          greeting:
            default_version: "2"
            versions:
              "1":
                template: "You are a bot for {{{{ variables.product }}}}."
                variables:
                  product: "Acme"
              "2":
                template: "You are a bot for {{{{ variables.product }}}}. {{% include \"tone\" %}}"
                variables:
                  product: "Acme v2"
"#
    )
}

/// The same origin with no `prompts:` block, for the surfaces that have
/// to behave differently when no prompt layer can hold a reference.
fn config_without_prompts(upstream: &str) -> String {
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
          api_key: "stub-key"
          base_url: "{upstream}"
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: round_robin
"#
    )
}

#[test]
fn referenced_prompt_is_rendered_and_prepended_as_system_message() {
    let upstream = MockProvider::start();
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    let req = serde_json::json!({
        "model": "gpt-4o",
        "prompt": "greeting@1",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &req, &[])
        .expect("send");
    assert_eq!(resp.status, 200);

    // The forwarded body should carry a prepended system message with the
    // rendered template, and must not carry the gateway-only `prompt` key.
    let fwd: serde_json::Value =
        serde_json::from_str(&upstream.last_body()).expect("upstream got JSON");
    let messages = fwd["messages"].as_array().expect("messages array");
    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[0]["content"], "You are a bot for Acme.");
    assert_eq!(messages[1]["role"], "user", "user message preserved");
    assert!(
        fwd.get("prompt").is_none(),
        "gateway-only `prompt` key stripped"
    );
}

#[test]
fn bare_reference_uses_default_version_with_partial() {
    let upstream = MockProvider::start();
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    let req = serde_json::json!({
        "model": "gpt-4o",
        "prompt": "greeting",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &req, &[])
        .expect("send");
    assert_eq!(resp.status, 200);

    let fwd: serde_json::Value =
        serde_json::from_str(&upstream.last_body()).expect("upstream got JSON");
    // default_version is "2", which composes the `tone` partial.
    assert_eq!(
        fwd["messages"][0]["content"],
        "You are a bot for Acme v2. Be concise."
    );
}

#[test]
fn unknown_prompt_reference_is_a_400() {
    let upstream = MockProvider::start();
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    let req = serde_json::json!({
        "model": "gpt-4o",
        "prompt": "does-not-exist",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &req, &[])
        .expect("send");
    assert_eq!(resp.status, 400, "a bad prompt reference is rejected");
    assert!(
        upstream.last_body().is_empty(),
        "a rejected prompt request must not reach the provider"
    );
}

/// WOR-2597: red before the lift.
///
/// The seam is the `AiSurface::Messages` arm of the inbound shim in
/// `handle_ai_proxy`, which called `translate_anthropic_request_to_openai`
/// with no prompt bridge. `prompt` is absent from
/// `REPRESENTED_TOP_LEVEL_KEYS`, so the translator's catch-all noted
/// `anthropic.prompt` and dropped it, and the shared WOR-800 resolver
/// downstream reads `body.get("prompt")` off the ALREADY-TRANSLATED
/// canonical body, where it no longer existed. On main this request
/// reaches the provider with the caller's turn and no system turn at
/// all, so the first content assertion below fails.
#[test]
fn messages_surface_resolves_a_stored_prompt_reference() {
    let upstream = MockProvider::start();
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    let req = serde_json::json!({
        "model": "gpt-4o",
        "max_tokens": 64,
        "prompt": "greeting@1",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let resp = proxy
        .post_json("/v1/messages", "ai.localhost", &req, &[])
        .expect("send");
    assert_eq!(resp.status, 200);

    let fwd: serde_json::Value =
        serde_json::from_str(&upstream.last_body()).expect("upstream got JSON");
    let messages = fwd["messages"].as_array().expect("messages array");
    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[0]["content"], "You are a bot for Acme.");
    assert_eq!(messages[1]["role"], "user", "user message preserved");
    assert!(
        fwd.get("prompt").is_none(),
        "the gateway-only `prompt` key must not reach the provider"
    );
}

/// The same lift on `/v1/responses`, where the string form was noted as
/// `responses.prompt` and dropped for the same reason.
#[test]
fn responses_surface_resolves_a_stored_prompt_reference() {
    let upstream = MockProvider::start();
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    let req = serde_json::json!({
        "model": "gpt-4o",
        "prompt": "greeting@1",
        "input": "hi"
    });
    let resp = proxy
        .post_json("/v1/responses", "ai.localhost", &req, &[])
        .expect("send");
    assert_eq!(resp.status, 200);

    let fwd: serde_json::Value =
        serde_json::from_str(&upstream.last_body()).expect("upstream got JSON");
    assert_eq!(fwd["messages"][0]["role"], "system");
    assert_eq!(fwd["messages"][0]["content"], "You are a bot for Acme.");
    assert!(
        fwd.get("prompt").is_none(),
        "the gateway-only `prompt` key must not reach the provider"
    );
}

/// An unknown reference against a configured store is refused on the
/// native surface too, and the provider is never contacted.
///
/// Red before the lift for a different reason than the pair above: the
/// translator dropped `prompt` before the resolver could refuse it, so
/// this request used to succeed with a 200 and reach the provider
/// carrying the caller's turn and no template.
#[test]
fn an_unknown_reference_on_the_messages_surface_is_refused() {
    let upstream = MockProvider::start();
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    let req = serde_json::json!({
        "model": "gpt-4o",
        "max_tokens": 64,
        "prompt": "does-not-exist",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let resp = proxy
        .post_json("/v1/messages", "ai.localhost", &req, &[])
        .expect("send");
    assert_eq!(
        resp.status, 400,
        "a configured store refuses an unknown reference at render, as on chat completions"
    );
    assert!(
        upstream.last_body().is_empty(),
        "a refused prompt request must not reach the provider"
    );
}

/// The hole the lift would otherwise open. With no `prompts:` block on
/// the origin, no layer holds the reference and the resolver falls
/// through. On chat completions that pass-through is correct: `prompt`
/// is also a legacy completions field a provider may accept. On a
/// native surface it is not a field of the wire format at all, so
/// falling through would ship a gateway-only key upstream while running
/// the request without the template it named. It is a 404 instead.
#[test]
fn a_reference_with_no_prompt_store_is_refused_on_the_messages_surface() {
    let upstream = MockProvider::start();
    let proxy = ProxyHarness::start_with_yaml(&config_without_prompts(&upstream.base_url()))
        .expect("start proxy");

    let req = serde_json::json!({
        "model": "gpt-4o",
        "max_tokens": 64,
        "prompt": "greeting@1",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let resp = proxy
        .post_json("/v1/messages", "ai.localhost", &req, &[])
        .expect("send");
    assert_eq!(
        resp.status, 404,
        "an origin with no prompt store cannot honor the reference"
    );
    assert!(
        upstream.last_body().is_empty(),
        "the gateway-only key must never reach the provider"
    );
}

/// The same origin still serves the canonical chat path unchanged: a
/// `prompt` no layer holds passes through, because there it is a legacy
/// completions field rather than a gateway-only reference. Pins the
/// boundary the 404 above must not cross.
#[test]
fn a_reference_with_no_prompt_store_still_passes_through_on_chat_completions() {
    let upstream = MockProvider::start();
    let proxy = ProxyHarness::start_with_yaml(&config_without_prompts(&upstream.base_url()))
        .expect("start proxy");

    let req = serde_json::json!({
        "model": "gpt-4o",
        "prompt": "greeting@1",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &req, &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    let fwd: serde_json::Value =
        serde_json::from_str(&upstream.last_body()).expect("upstream got JSON");
    assert_eq!(
        fwd.get("prompt").and_then(serde_json::Value::as_str),
        Some("greeting@1"),
        "the chat path's pass-through behavior is unchanged"
    );
}
