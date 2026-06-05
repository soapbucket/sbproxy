//! Embedding semantic cache (WOR-796).
//!
//! Proves the OSS embedding-similarity cache end to end: a paraphrased
//! prompt (different text, similar embedding) is served from cache with
//! `x-semcache: HIT` and never reaches the upstream, while an unrelated
//! prompt misses and is forwarded.
//!
//! The mock upstream routes by path: `/v1/embeddings` returns a vector
//! keyed on whether the prompt mentions "france" (so the two France
//! prompts are identical vectors and the math prompt is orthogonal),
//! and `/v1/chat/completions` returns a reply whose body changes on
//! every call (a counter) so a cache hit is observable by body.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sbproxy_e2e::ProxyHarness;

struct MockProvider {
    port: u16,
    chat_calls: Arc<AtomicUsize>,
    shutdown: Arc<Mutex<bool>>,
}

impl MockProvider {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock provider");
        let port = listener.local_addr().unwrap().port();
        let chat_calls = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(Mutex::new(false));
        let chat_clone = chat_calls.clone();
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
                let chat = chat_clone.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(&mut stream, chat);
                });
            }
        });
        Self {
            port,
            chat_calls,
            shutdown,
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn chat_calls(&self) -> usize {
        self.chat_calls.load(Ordering::SeqCst)
    }
}

impl Drop for MockProvider {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        // Nudge the accept loop so it observes the shutdown flag.
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn handle_conn(
    stream: &mut std::net::TcpStream,
    chat_calls: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    // Read the full request (headers + body by Content-Length).
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let headers_end = find_headers_end(&buf);
        if let Some(end) = headers_end {
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
    let text = String::from_utf8_lossy(&buf).to_string();
    let request_line = text.lines().next().unwrap_or("");
    let body_start = find_headers_end(&buf).map(|e| e + 4).unwrap_or(buf.len());
    let body = String::from_utf8_lossy(&buf[body_start.min(buf.len())..]).to_lowercase();

    let json_body = if request_line.contains("/v1/embeddings") {
        // Vector keyed on the prompt mentioning "france": both France
        // prompts collide (cosine 1.0); the math prompt is orthogonal.
        let vec = if body.contains("france") {
            "[1.0, 0.0, 0.0]"
        } else {
            "[0.0, 1.0, 0.0]"
        };
        format!(
            r#"{{"object":"list","model":"text-embedding-3-small","data":[{{"object":"embedding","index":0,"embedding":{vec}}}],"usage":{{"prompt_tokens":1,"completion_tokens":0,"total_tokens":1}}}}"#
        )
    } else {
        // Chat: unique content per call so a cache hit is observable.
        let n = chat_calls.fetch_add(1, Ordering::SeqCst) + 1;
        format!(
            r#"{{"id":"chatcmpl-{n}","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{{"index":0,"message":{{"role":"assistant","content":"reply-{n}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}}}"#
        )
    };

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
      semantic_cache:
        enabled: true
        threshold: 0.9
        ttl_secs: 60
        max_entries: 64
        embedding:
          provider: openai
          model: text-embedding-3-small
"#
    )
}

fn chat(prompt: &str) -> serde_json::Value {
    serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": prompt}]
    })
}

#[test]
fn paraphrased_prompt_hits_semantic_cache() {
    let upstream = MockProvider::start();
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    // 1. First France prompt: semantic miss -> upstream chat -> reply-1, cached.
    let r1 = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("What is the capital of France?"),
            &[],
        )
        .expect("first call");
    assert_eq!(r1.status, 200);
    let b1 = String::from_utf8(r1.body).unwrap();
    assert!(
        b1.contains("reply-1"),
        "first reply should be reply-1: {b1}"
    );
    assert_ne!(
        r1.headers.get("x-semcache").map(|s| s.as_str()),
        Some("HIT"),
        "first call must be a miss"
    );

    // 2. A different France prompt (same embedding): semantic HIT,
    //    replays reply-1, never hits the upstream.
    let r2 = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("Tell me which city is the capital of France please"),
            &[],
        )
        .expect("second call");
    assert_eq!(r2.status, 200);
    assert_eq!(
        r2.headers.get("x-semcache").map(|s| s.as_str()),
        Some("HIT"),
        "paraphrased prompt must be a semantic cache hit"
    );
    let b2 = String::from_utf8(r2.body).unwrap();
    assert!(
        b2.contains("reply-1"),
        "hit must replay the cached reply-1, got: {b2}"
    );

    // Exactly one chat call reached the upstream (the cache served #2).
    assert_eq!(
        upstream.chat_calls(),
        1,
        "second call must not reach upstream"
    );
}

#[test]
fn unrelated_prompt_misses_and_forwards() {
    let upstream = MockProvider::start();
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    // France prompt -> miss -> cached.
    let _ = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("What is the capital of France?"),
            &[],
        )
        .expect("first call");

    // Unrelated prompt -> orthogonal embedding -> miss -> forwarded.
    let r2 = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("What is two plus two?"),
            &[],
        )
        .expect("second call");
    assert_eq!(r2.status, 200);
    assert_ne!(
        r2.headers.get("x-semcache").map(|s| s.as_str()),
        Some("HIT"),
        "an unrelated prompt must not hit the cache"
    );
    assert_eq!(upstream.chat_calls(), 2, "both prompts must reach upstream");
}

/// WOR-1154: input guardrails must run BEFORE the semantic-cache
/// lookup. A prompt a guardrail would block must be blocked even when a
/// matching cache entry exists, otherwise a cache hit short-circuits the
/// request and serves a response for a prompt that should have been
/// rejected.
fn config_with_input_guardrail(upstream: &str) -> String {
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
      guardrails:
        input:
          - type: regex
            action: block
            patterns:
              - "FORBIDDEN"
      semantic_cache:
        enabled: true
        threshold: 0.9
        ttl_secs: 60
        max_entries: 64
        embedding:
          provider: openai
          model: text-embedding-3-small
"#
    )
}

#[test]
fn input_guardrail_blocks_even_on_cache_hit() {
    let upstream = MockProvider::start();
    let proxy = ProxyHarness::start_with_yaml(&config_with_input_guardrail(&upstream.base_url()))
        .expect("start proxy");

    // 1. Clean France prompt: miss -> upstream -> cached under the
    //    France embedding bucket.
    let r1 = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("What is the capital of France?"),
            &[],
        )
        .expect("first call");
    assert_eq!(r1.status, 200, "clean prompt passes");
    assert_eq!(
        upstream.chat_calls(),
        1,
        "clean prompt reaches upstream once"
    );

    // 2. A France prompt carrying the forbidden token shares the same
    //    embedding bucket, so it WOULD be a semantic cache hit. The
    //    input guardrail must block it (400) before the cache lookup,
    //    rather than replaying the cached reply.
    let r2 = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("Tell me about France and include FORBIDDEN content"),
            &[],
        )
        .expect("second call");
    assert_eq!(
        r2.status,
        400,
        "a guardrail-blocked prompt must be blocked even when a cache entry matches, got {}: {:?}",
        r2.status,
        String::from_utf8_lossy(&r2.body)
    );
    let b2 = String::from_utf8_lossy(&r2.body);
    assert!(
        b2.contains("guardrail_violation"),
        "block body should name the violation: {b2}"
    );
    assert_ne!(
        r2.headers.get("x-semcache").map(|s| s.as_str()),
        Some("HIT"),
        "the blocked request must not be served from cache"
    );
}
