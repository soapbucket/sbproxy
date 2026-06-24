//! Local sidecar-backed semantic-cache e2e (WOR-1226).
//!
//! The normal e2e suite compiles this test but skips execution unless
//! `SBPROXY_TEST_EMBED_MODEL` and `SBPROXY_TEST_EMBED_TOKENIZER` point at
//! local ONNX/tokenizer artifacts. When enabled, it launches the release
//! classifier sidecar with `--embed-model`, starts the proxy through
//! `ProxyHarness`, then proves a near-duplicate prompt is served from the
//! semantic cache without a second upstream chat call.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sbproxy_e2e::ProxyHarness;

const MODEL_ID: &str = "all-MiniLM-L6-v2";
const CASE_CONFIG: &str = "e2e/cases/semantic-cache-sidecar/sb.yml";
const SIDECAR_BIN_ENV: &str = "SBPROXY_CLASSIFIER_SIDECAR_BIN";
const EMBED_MODEL_ENV: &str = "SBPROXY_TEST_EMBED_MODEL";
const EMBED_TOKENIZER_ENV: &str = "SBPROXY_TEST_EMBED_TOKENIZER";

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
        let chat_clone = Arc::clone(&chat_calls);
        let shutdown_clone = Arc::clone(&shutdown);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_clone.lock().unwrap() {
                    break;
                }
                let mut stream = match stream {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };
                let chat = Arc::clone(&chat_clone);
                std::thread::spawn(move || {
                    let _ = handle_provider_conn(&mut stream, chat);
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
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

struct Sidecar {
    child: Child,
}

impl Sidecar {
    fn start(model: PathBuf, tokenizer: PathBuf) -> anyhow::Result<(Self, String)> {
        let port = pick_free_port()?;
        let endpoint = format!("http://127.0.0.1:{port}");
        let spec = format!("{MODEL_ID}={}:{}", model.display(), tokenizer.display());
        let bin = sidecar_binary_path();
        if !bin.is_file() {
            anyhow::bail!(
                "classifier sidecar binary missing at {}; run `cargo build --release -p sbproxy-classifier-sidecar` or set {SIDECAR_BIN_ENV}",
                bin.display()
            );
        }

        let mut child = Command::new(&bin)
            .arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--embed-model")
            .arg(spec)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow::anyhow!("spawn sidecar {}: {e}", bin.display()))?;

        wait_for_sidecar_tcp(&mut child, port, Duration::from_secs(45))?;
        Ok((Self { child }, endpoint))
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn handle_provider_conn(
    stream: &mut TcpStream,
    chat_calls: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    read_request(stream)?;
    let n = chat_calls.fetch_add(1, Ordering::SeqCst) + 1;
    let json_body = format!(
        r#"{{"id":"chatcmpl-{n}","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{{"index":0,"message":{{"role":"assistant","content":"reply-{n}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}}}"#
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        json_body.len(),
        json_body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(end) = find_headers_end(&buf) {
            let header_str = String::from_utf8_lossy(&buf[..end]);
            let content_len = parse_content_length(&header_str);
            if buf.len() >= end + 4 + content_len {
                return Ok(());
            }
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .and_then(|rest| rest.trim().parse().ok())
        })
        .unwrap_or(0)
}

fn pick_free_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn wait_for_sidecar_tcp(child: &mut Child, port: u16, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("classifier sidecar exited before accepting connections: {status}");
        }
        if Instant::now() >= deadline {
            anyhow::bail!("classifier sidecar did not accept connections within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn sidecar_binary_path() -> PathBuf {
    if let Some(path) = std::env::var_os(SIDECAR_BIN_ENV).filter(|v| !v.is_empty()) {
        return PathBuf::from(path);
    }
    workspace_root().join("target/release/sbproxy-classifier-sidecar")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e crate lives under workspace root")
        .to_path_buf()
}

fn embed_fixture_from_env() -> Option<(PathBuf, PathBuf)> {
    let model = match std::env::var_os(EMBED_MODEL_ENV) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => {
            eprintln!("skipping sidecar semantic-cache e2e: {EMBED_MODEL_ENV} is not set");
            return None;
        }
    };
    let tokenizer = match std::env::var_os(EMBED_TOKENIZER_ENV) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => {
            eprintln!("skipping sidecar semantic-cache e2e: {EMBED_TOKENIZER_ENV} is not set");
            return None;
        }
    };
    assert!(
        model.is_file(),
        "{EMBED_MODEL_ENV} does not point at a file: {}",
        model.display()
    );
    assert!(
        tokenizer.is_file(),
        "{EMBED_TOKENIZER_ENV} does not point at a file: {}",
        tokenizer.display()
    );
    Some((model, tokenizer))
}

fn config_for(upstream: &str, sidecar: &str) -> String {
    let path = workspace_root().join(CASE_CONFIG);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read case config {}: {e}", path.display()));
    raw.replace("__UPSTREAM__", upstream)
        .replace("__SIDECAR__", sidecar)
}

fn chat(prompt: &str) -> serde_json::Value {
    serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": prompt}]
    })
}

#[test]
fn near_duplicate_prompt_hits_sidecar_semantic_cache() {
    let Some((model, tokenizer)) = embed_fixture_from_env() else {
        return;
    };
    let upstream = MockProvider::start();
    let (_sidecar, sidecar_endpoint) =
        Sidecar::start(model, tokenizer).expect("start classifier sidecar");
    let proxy = ProxyHarness::start_with_yaml(&config_for(&upstream.base_url(), &sidecar_endpoint))
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
        "near-duplicate prompt must be a semantic cache hit"
    );
    let b2 = String::from_utf8(r2.body).unwrap();
    assert!(
        b2.contains("reply-1"),
        "hit must replay the cached reply-1, got: {b2}"
    );
    assert_eq!(
        upstream.chat_calls(),
        1,
        "second call must not reach upstream"
    );
}
