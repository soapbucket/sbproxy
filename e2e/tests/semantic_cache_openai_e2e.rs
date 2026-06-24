//! OpenAI-compatible embedding-source semantic-cache e2e (WOR-1520).
//!
//! Drives the `source: openai` embedding source end to end: the proxy
//! vectorizes prompts by POSTing `/v1/embeddings` to a standalone
//! OpenAI-compatible endpoint (here a local mock), then serves a
//! near-duplicate prompt from the semantic cache without a second
//! upstream chat call. Needs no model, so unlike the sidecar e2e it is
//! not gated on an embedding-model env var.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sbproxy_e2e::ProxyHarness;

const CASE_CONFIG: &str = "e2e/cases/semantic-cache-openai/sb.yml";

/// A minimal HTTP mock that counts requests and replays a canned JSON body.
struct MockServer {
    port: u16,
    calls: Arc<AtomicUsize>,
    last_request: Arc<Mutex<String>>,
    shutdown: Arc<Mutex<bool>>,
}

impl MockServer {
    /// Start a mock that returns `body` (a JSON string) for every request.
    fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().unwrap().port();
        let calls = Arc::new(AtomicUsize::new(0));
        let last_request = Arc::new(Mutex::new(String::new()));
        let shutdown = Arc::new(Mutex::new(false));
        let calls_c = Arc::clone(&calls);
        let last_c = Arc::clone(&last_request);
        let shutdown_c = Arc::clone(&shutdown);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_c.lock().unwrap() {
                    break;
                }
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let calls = Arc::clone(&calls_c);
                let last = Arc::clone(&last_c);
                std::thread::spawn(move || {
                    let req = read_request(&mut stream);
                    *last.lock().unwrap() = req;
                    calls.fetch_add(1, Ordering::SeqCst);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                });
            }
        });

        Self {
            port,
            calls,
            last_request,
            shutdown,
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last_request(&self) -> String {
        self.last_request.lock().unwrap().clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

/// A chat-completions mock that returns a distinct reply per call so a
/// cache hit (replaying the first reply) is distinguishable from a miss.
struct ChatUpstream {
    inner: TcpListener,
    calls: Arc<AtomicUsize>,
    port: u16,
    shutdown: Arc<Mutex<bool>>,
}

impl ChatUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind chat upstream");
        let port = listener.local_addr().unwrap().port();
        let calls = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(Mutex::new(false));
        let listener_clone = listener.try_clone().unwrap();
        let calls_c = Arc::clone(&calls);
        let shutdown_c = Arc::clone(&shutdown);
        std::thread::spawn(move || {
            for stream in listener_clone.incoming() {
                if *shutdown_c.lock().unwrap() {
                    break;
                }
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let n = calls_c.fetch_add(1, Ordering::SeqCst) + 1;
                std::thread::spawn(move || {
                    let _ = read_request(&mut stream);
                    let json = format!(
                        r#"{{"id":"chatcmpl-{n}","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{{"index":0,"message":{{"role":"assistant","content":"reply-{n}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}}}"#
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(),
                        json
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                });
            }
        });
        Self {
            inner: listener,
            calls,
            port,
            shutdown,
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for ChatUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        // Keep the original listener bound until drop so the port stays ours.
        let _ = &self.inner;
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_str = String::from_utf8_lossy(&buf[..end]).to_string();
            let content_len = header_str
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|rest| rest.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + content_len {
                return String::from_utf8_lossy(&buf).to_string();
            }
        }
        match stream.read(&mut tmp) {
            Ok(0) => return String::from_utf8_lossy(&buf).to_string(),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return String::from_utf8_lossy(&buf).to_string(),
        }
    }
}

fn config_for(upstream: &str, embed: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e crate lives under workspace root")
        .join(CASE_CONFIG);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read case config {}: {e}", path.display()));
    raw.replace("__UPSTREAM__", upstream)
        .replace("__EMBED__", embed)
}

fn chat(prompt: &str) -> serde_json::Value {
    serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": prompt}]
    })
}

#[test]
fn near_duplicate_prompt_hits_openai_embedding_cache() {
    let upstream = ChatUpstream::start();
    // A fixed embedding vector for every prompt: two distinct prompts then
    // score cosine 1.0, so the second is a guaranteed semantic-cache hit.
    // This exercises the wiring (embed via the openai source -> cache hit),
    // not the embedding model itself (covered by unit tests).
    let embed = MockServer::start(
        r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3,0.4]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":1,"completion_tokens":0,"total_tokens":1}}"#,
    );

    let proxy = ProxyHarness::start_with_yaml(&config_for(&upstream.base_url(), &embed.base_url()))
        .expect("start proxy");

    let r1 = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("What is the capital city of France?"),
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

    let r2 = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("What is France's capital city?"),
            &[],
        )
        .expect("second call");
    assert_eq!(r2.status, 200);
    assert_eq!(
        r2.headers.get("x-semcache").map(|s| s.as_str()),
        Some("HIT"),
        "second prompt must be served from the semantic cache"
    );
    let b2 = String::from_utf8(r2.body).unwrap();
    assert!(
        b2.contains("reply-1"),
        "hit must replay the cached reply-1, got: {b2}"
    );

    assert_eq!(
        upstream.calls(),
        1,
        "second call must not reach the chat upstream"
    );
    // Both prompts were vectorized via the OpenAI-compatible endpoint, and the
    // configured Bearer key reached it.
    assert!(embed.calls() >= 2, "both prompts should be embedded");
    let embed_req = embed.last_request();
    assert!(
        embed_req.starts_with("POST /v1/embeddings "),
        "embeddings path wrong: {embed_req}"
    );
    assert!(
        embed_req
            .to_lowercase()
            .contains("authorization: bearer embed-secret-key"),
        "configured embedding auth header not sent: {embed_req}"
    );
}
